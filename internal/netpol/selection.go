// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

type matchResult uint8

const (
	matchNo matchResult = iota
	matchYes
	matchUnknown
)

// podSelection is the per-pod policy selection, computed once per snapshot
// and indexed by direction and policy layer.
type podSelection struct {
	layers [2][2]layerSelection
	// cilium reports whether a Cilium policy selects the pod per direction.
	cilium [2]bool
}

type layerSelection struct {
	// policies are the modeled policies selecting the pod in the direction.
	policies []*normalizedPolicy
	// effectUnknown policies select the pod, but their effect is unknown.
	effectUnknown []*normalizedPolicy
	isolated      bool
	// uncertain explains why every pair of the pod in this direction and
	// layer is partial data.
	uncertain []string
}

func (s *podSelection) layer(direction Direction, layer policyLayer) *layerSelection {
	return &s.layers[direction][layer]
}

// selection returns the pod's policy selection. Cluster-wide and root
// namespace policies are scanned once per pod rather than once per pair.
func (x *snapshotIndex) selection(info *podInfo) *podSelection {
	if info.selection != nil {
		return info.selection
	}
	selection := &podSelection{}
	visit := func(policy *normalizedPolicy) {
		switch policy.State {
		case policyInert:
			return
		case policySelectionUnknown:
			for _, direction := range []Direction{Ingress, Egress} {
				if policy.affects(direction) {
					layer := selection.layer(direction, policy.Layer)
					layer.uncertain = append(layer.uncertain, policy.reasons...)
				}
			}
			return
		}
		if !policySelectsPod(policy, info) {
			return
		}
		for _, direction := range []Direction{Ingress, Egress} {
			if !policy.affects(direction) {
				continue
			}
			if policy.Type == PolicyTypeCiliumNetworkPolicy || policy.Type == PolicyTypeCiliumClusterwideNetworkPolicy {
				selection.cilium[direction] = true
			}
			layer := selection.layer(direction, policy.Layer)
			if policy.State == policyEffectUnknown {
				layer.effectUnknown = append(layer.effectUnknown, policy)
				layer.uncertain = append(layer.uncertain, policy.reasons...)
				continue
			}
			layer.policies = append(layer.policies, policy)
			layer.isolated = layer.isolated || policy.direction(direction).Isolate
		}
	}
	for _, policy := range x.policies[info.pod.Namespace] {
		visit(policy)
	}
	for _, policy := range x.globalPolicies {
		visit(policy)
	}

	authorization := selection.layer(Ingress, policyLayerAuthorization)
	if len(authorization.policies)+len(authorization.effectUnknown)+len(authorization.uncertain) > 0 {
		switch info.mesh.state {
		case meshNotEnrolled:
			// AuthorizationPolicy only applies to workloads in the mesh.
			*authorization = layerSelection{}
		case meshUnknown:
			authorization.uncertain = append(authorization.uncertain, fmt.Sprintf(
				"Istio AuthorizationPolicy enforcement for pod %s is uncertain: %s", info.ref, info.mesh.reason,
			))
		}
	}
	if info.pod.Spec.HostNetwork {
		for _, direction := range []Direction{Ingress, Egress} {
			if selection.cilium[direction] || x.ciliumHostPolicies {
				network := selection.layer(direction, policyLayerNetwork)
				network.uncertain = append(network.uncertain, fmt.Sprintf(
					"pod %s uses hostNetwork; Cilium enforces host policies and host identities for it, not pod endpoint policies",
					info.ref,
				))
			}
		}
	}
	for direction := range selection.layers {
		for layer := range selection.layers[direction] {
			item := &selection.layers[direction][layer]
			item.uncertain = uniqueStrings(item.uncertain)
		}
	}
	info.selection = selection
	return selection
}

func policySelectsPod(policy *normalizedPolicy, info *podInfo) bool {
	if !policy.ClusterScoped && policy.Namespace != info.pod.Namespace {
		return false
	}
	if !selectorMatches(policy.Selector.pod, &policy.Selector.Pod, labels.Set(info.pod.Labels)) {
		return false
	}
	if policy.Selector.Namespace != nil &&
		!selectorMatches(policy.Selector.namespace, policy.Selector.Namespace, info.namespaceLabels) {
		return false
	}
	return policy.Selector.ServiceAccount == nil ||
		selectorMatches(policy.Selector.serviceAccount, policy.Selector.ServiceAccount, info.accountLabels)
}

// selectorMatches uses the compiled selector and only parses the source for
// policies that were built without finalize.
func selectorMatches(compiled labels.Selector, source *metav1.LabelSelector, set labels.Set) bool {
	if compiled != nil {
		return compiled.Matches(set)
	}
	return source != nil && matchesSelector(*source, set)
}

// ruleMatch is the outcome of matching one rule against one peer.
type ruleMatch struct {
	matched   bool
	peerIndex int
	// uncertain explains why the match could not be decided.
	uncertain string
}

// sideMatcher matches rules against the peer of one side of a pair.
type sideMatcher interface {
	match(policy *normalizedPolicy, direction Direction, rule *normalizedRule) ruleMatch
	couldMatch(policy *normalizedPolicy, rule *normalizedRule) bool
	peerUncertainty(layer policyLayer, selection *podSelection, direction Direction) string
}

// podMatcher matches rules against a concrete peer pod.
type podMatcher struct {
	x    *snapshotIndex
	peer *podInfo
}

func (m podMatcher) match(policy *normalizedPolicy, direction Direction, rule *normalizedRule) ruleMatch {
	if rule.Disabled || rule.MatchNone {
		return ruleMatch{peerIndex: -1}
	}
	if len(rule.Peers) == 0 {
		return ruleMatch{matched: true, peerIndex: -1}
	}
	unknown := false
	for index := range rule.Peers {
		switch peerMatchesPod(&rule.Peers[index], policy, m.peer) {
		case matchYes:
			return ruleMatch{matched: true, peerIndex: index}
		case matchUnknown:
			unknown = true
		}
	}
	result := ruleMatch{peerIndex: -1}
	if unknown {
		result.uncertain = policy.qualify(fmt.Sprintf(
			"%s %s rule %d: identity constraints cannot be evaluated because the Istio mesh enrollment of pod %s is unknown",
			strings.ToLower(direction.String()), rule.Action, rule.Index, m.peer.ref,
		))
	}
	return result
}

func (m podMatcher) couldMatch(policy *normalizedPolicy, rule *normalizedRule) bool {
	if rule.UncertainPeers {
		return true
	}
	if rule.MatchNone {
		return false
	}
	if len(rule.Peers) == 0 {
		return true
	}
	for index := range rule.Peers {
		if peerMatchesPod(&rule.Peers[index], policy, m.peer) != matchNo {
			return true
		}
	}
	return false
}

func (m podMatcher) peerUncertainty(layer policyLayer, selection *podSelection, direction Direction) string {
	if layer != policyLayerNetwork || !m.peer.pod.Spec.HostNetwork || !selection.cilium[direction] {
		return ""
	}
	return fmt.Sprintf(
		"peer pod %s uses hostNetwork; Cilium identifies its traffic as host or remote-node rather than by pod labels",
		m.peer.ref,
	)
}

func peerMatchesPod(peer *normalizedPeer, policy *normalizedPolicy, info *podInfo) matchResult {
	pod := info.pod
	if len(peer.IPBlocks) > 0 && (!peer.MatchPodIPs || !info.matchesBlocks(peer)) {
		return matchNo
	}
	if !peer.AllNamespaces && peer.NamespaceSelector == nil && pod.Namespace != policy.Namespace {
		return matchNo
	}
	if peer.NamespaceSelector != nil &&
		!selectorMatches(peer.namespaceSelector, peer.NamespaceSelector, info.namespaceLabels) {
		return matchNo
	}
	if peer.PodSelector != nil && !selectorMatches(peer.podSelector, peer.PodSelector, labels.Set(pod.Labels)) {
		return matchNo
	}
	if peer.ServiceAccountSelector != nil &&
		!selectorMatches(peer.serviceAccountSelector, peer.ServiceAccountSelector, info.accountLabels) {
		return matchNo
	}
	return peer.identityMatch(&info.identity)
}

func (i *podInfo) matchesBlocks(peer *normalizedPeer) bool {
	blocks := peer.blocks
	if blocks == nil && len(peer.IPBlocks) > 0 {
		blocks = compileBlocks(peer.IPBlocks)
	}
	for _, address := range i.addresses {
		for index := range blocks {
			if blocks[index].contains(address) {
				return true
			}
		}
	}
	return false
}

// cidrMatcher matches rules against a CIDR primitive. With partialDeny set,
// explicit denies that only intersect the CIDR still match so the evaluator
// can keep only permissions guaranteed across the whole range.
type cidrMatcher struct {
	ref         *PrimitiveRef
	partialDeny bool
	intersected bool
}

func (m *cidrMatcher) match(policy *normalizedPolicy, direction Direction, rule *normalizedRule) ruleMatch {
	matched, peerIndex := normalizedRuleMatchesCIDR(rule, m.ref)
	result := ruleMatch{matched: matched, peerIndex: peerIndex}
	if rule.Disabled || rule.MatchNone {
		return result
	}
	for index := range rule.Peers {
		peer := &rule.Peers[index]
		if !peer.CIDRMatchUnsupported || !peerBlocksIntersect(peer, m.ref) {
			continue
		}
		result.uncertain = policy.qualify(fmt.Sprintf(
			"%s %s rule %d: CIDR %s cannot prove identity constraints ANDed with ipBlocks",
			strings.ToLower(direction.String()), rule.Action, rule.Index, m.ref.CIDR,
		))
	}
	if matched || !m.partialDeny || rule.Action != PolicyActionDeny {
		return result
	}
	for index := range rule.Peers {
		peer := &rule.Peers[index]
		if !peer.CIDRMatchUnsupported && peerBlocksIntersect(peer, m.ref) {
			m.intersected = true
			result.matched, result.peerIndex = true, index
			return result
		}
	}
	return result
}

func (m *cidrMatcher) couldMatch(_ *normalizedPolicy, rule *normalizedRule) bool {
	if rule.UncertainPeers {
		return true
	}
	if rule.MatchNone {
		return false
	}
	if len(rule.Peers) == 0 {
		return true
	}
	for index := range rule.Peers {
		peer := &rule.Peers[index]
		if len(peer.IPBlocks) > 0 {
			if peerBlocksIntersect(peer, m.ref) {
				return true
			}
			continue
		}
		if peerMatchesAddresses(peer) {
			return true
		}
	}
	return false
}

func (*cidrMatcher) peerUncertainty(policyLayer, *podSelection, Direction) string {
	return ""
}

func peerBlocksIntersect(peer *normalizedPeer, ref *PrimitiveRef) bool {
	for index := range peer.IPBlocks {
		if ipBlockIntersects(&peer.IPBlocks[index], ref) {
			return true
		}
	}
	return false
}

func normalizedRuleMatchesCIDR(rule *normalizedRule, ref *PrimitiveRef) (matched bool, peerIndex int) {
	if rule.Disabled || rule.MatchNone {
		return false, -1
	}
	if len(rule.Peers) == 0 {
		return true, -1
	}
	for index := range rule.Peers {
		if normalizedPeerMatchesCIDR(&rule.Peers[index], ref) {
			return true, index
		}
	}
	return false, -1
}

// normalizedPeerMatchesCIDR treats CIDR primitives as addresses without a pod
// or mesh identity.
func normalizedPeerMatchesCIDR(peer *normalizedPeer, ref *PrimitiveRef) bool {
	if peer.CIDRMatchUnsupported {
		return false
	}
	if len(peer.IPBlocks) > 0 {
		for index := range peer.IPBlocks {
			if ipBlockContains(&peer.IPBlocks[index], ref) {
				return true
			}
		}
		return false
	}
	return peerMatchesAddresses(peer)
}

// peerMatchesAddresses reports whether a peer without IP blocks matches plain
// addresses: selectors never do, and positive identity constraints need an
// mTLS identity that addresses lack. Negative identity constraints cannot
// exclude an address without identity.
func peerMatchesAddresses(peer *normalizedPeer) bool {
	return peer.PodSelector == nil &&
		peer.NamespaceSelector == nil &&
		peer.ServiceAccountSelector == nil &&
		!peer.hasPositiveIdentityConstraints()
}
