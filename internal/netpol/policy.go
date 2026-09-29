// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/yaml"
)

type policyLayer uint8

const (
	policyLayerNetwork policyLayer = iota
	policyLayerAuthorization
)

// policyState records how much of a policy the graph can evaluate.
type policyState uint8

const (
	// policyEnforced policies have modeled selection and effects. Individual
	// rules may still carry their own uncertainty.
	policyEnforced policyState = iota
	// policyEffectUnknown policies select known pods, but their effect cannot
	// be modeled, for example because Cilium rejects the policy.
	policyEffectUnknown
	// policySelectionUnknown policies may select any pod in their scope.
	policySelectionUnknown
	// policyInert policies cannot affect pod-to-pod reachability.
	policyInert
)

const (
	metadataNameLabel     = "kubernetes.io/metadata.name"
	allIPv4               = "0.0.0.0/0"
	allIPv6               = "::/0"
	istioTrustDomain      = "cluster.local"
	defaultServiceAccount = "default"
)

type normalizedSelector struct {
	Pod            metav1.LabelSelector
	Namespace      *metav1.LabelSelector
	ServiceAccount *metav1.LabelSelector

	pod            labels.Selector
	namespace      labels.Selector
	serviceAccount labels.Selector
}

type normalizedPolicy struct {
	metav1.ObjectMeta
	Type      PolicyType
	Version   string
	SpecIndex int
	// SpecPath is the Cilium rule entry, such as spec or specs[0].
	SpecPath      string
	SpecCount     int
	ClusterScoped bool
	Layer         policyLayer
	Selector      normalizedSelector
	Ingress       normalizedDirection
	Egress        normalizedDirection
	PolicyTypes   []netv1.PolicyType
	Notes         []string
	State         policyState
	// Problems are short explanations for effect or selection uncertainty.
	Problems []string
	// AllDirections marks selection-unknown policies whose directions are
	// unknown as well, such as undecodable Cilium resources.
	AllDirections bool
	// HostPolicy marks Cilium nodeSelector policies.
	HostPolicy bool

	reasons []string
}

type normalizedDirection struct {
	Rules   []normalizedRule
	Isolate bool
}

type normalizedRule struct {
	Index       int
	Action      PolicyAction
	Peers       []normalizedPeer
	PeerStrings []string
	Ports       []netv1.NetworkPolicyPort
	// NoPorts marks rules which only permit traffic outside the graph's
	// TCP/UDP/SCTP model, such as ICMP.
	NoPorts   bool
	TCPOnly   bool
	MatchNone bool
	// Disabled rules cannot contribute modeled permissions.
	Disabled bool
	YAML     string
	Notes    []string
	// Warnings are short uncertainty explanations shown in rule details.
	Warnings []string
	// UncertainPeers widens the rule's uncertainty to every peer, because its
	// dynamic or unsupported peers cannot be resolved from the snapshot.
	UncertainPeers bool
	// IdentityConstrained rules match Istio mTLS peer identities.
	IdentityConstrained bool

	uncertain []string
}

type normalizedPeer struct {
	PodSelector            *metav1.LabelSelector
	NamespaceSelector      *metav1.LabelSelector
	ServiceAccountSelector *metav1.LabelSelector
	AllNamespaces          bool
	IPBlocks               []netv1.IPBlock
	MatchPodIPs            bool
	CIDRMatchUnsupported   bool
	Namespaces             []string
	NotNamespaces          []string
	ServiceAccounts        []string
	NotServiceAccounts     []string
	Principals             []string
	NotPrincipals          []string
	TrustDomains           []string
	NotTrustDomains        []string

	podSelector            labels.Selector
	namespaceSelector      labels.Selector
	serviceAccountSelector labels.Selector
	blocks                 []compiledBlock
}

type compiledBlock struct {
	prefix netip.Prefix
	except []netip.Prefix
}

func (p *normalizedPolicy) direction(direction Direction) *normalizedDirection {
	if direction == Egress {
		return &p.Egress
	}
	return &p.Ingress
}

// affects reports whether the policy constrains the direction.
func (p *normalizedPolicy) affects(direction Direction) bool {
	if p.Layer == policyLayerAuthorization && direction == Egress {
		return false
	}
	if p.State == policySelectionUnknown && p.AllDirections {
		return true
	}
	policyDirection := p.direction(direction)
	return policyDirection.Isolate || len(policyDirection.Rules) > 0
}

func (p *normalizedPolicy) ruleID(direction Direction, rule *normalizedRule) RuleID {
	policyType := p.Type
	if policyType == PolicyTypeNetworkPolicy {
		policyType = ""
	}
	return RuleID{
		PolicyNamespace: p.Namespace,
		PolicyName:      p.Name,
		PolicyUID:       p.UID,
		PolicyType:      policyType,
		PolicyVersion:   p.Version,
		PolicySpecIndex: p.SpecIndex,
		Action:          rule.Action,
		Direction:       direction,
		Index:           rule.Index,
	}
}

func (p *normalizedPolicy) reference() string {
	if p.Namespace == "" {
		return p.Name
	}
	return p.Namespace + "/" + p.Name
}

// qualify prefixes a message with the policy identity so pair-level warnings
// name the policy that made them uncertain.
func (p *normalizedPolicy) qualify(message string) string {
	label := p.Type.Kind() + " " + p.reference()
	if p.SpecCount > 1 && p.SpecPath != "" {
		label += " " + p.SpecPath
	}
	return label + ": " + message
}

func (p *normalizedPolicy) selectorString() string {
	parts := []string{"podSelector=" + labelSelectorString(&p.Selector.Pod)}
	if p.Selector.Namespace != nil {
		parts = append(parts, "namespaceSelector="+labelSelectorString(p.Selector.Namespace))
	}
	if p.Selector.ServiceAccount != nil {
		parts = append(parts, "serviceAccountSelector="+labelSelectorString(p.Selector.ServiceAccount))
	}
	if len(parts) == 1 {
		return strings.TrimPrefix(parts[0], "podSelector=")
	}
	return strings.Join(parts, ", ")
}

// finalize qualifies uncertainty and compiles selectors once, so evaluation
// never re-parses selectors or rebuilds warning text per pod pair.
func (p *normalizedPolicy) finalize() {
	p.Notes = uniqueStrings(p.Notes)
	p.Problems = uniqueStrings(p.Problems)
	p.reasons = make([]string, 0, len(p.Problems))
	for _, problem := range p.Problems {
		p.reasons = append(p.reasons, p.qualify(problem))
	}
	p.Selector.compile()
	for _, direction := range []Direction{Ingress, Egress} {
		policyDirection := p.direction(direction)
		for index := range policyDirection.Rules {
			rule := &policyDirection.Rules[index]
			if p.State == policyEffectUnknown {
				rule.Warnings = append(rule.Warnings, p.Problems...)
			}
			rule.Notes = uniqueStrings(rule.Notes)
			rule.Warnings = uniqueStrings(rule.Warnings)
			rule.uncertain = make([]string, 0, len(rule.Warnings))
			for _, warning := range rule.Warnings {
				rule.uncertain = append(rule.uncertain, p.qualify(fmt.Sprintf(
					"%s %s rule %d: %s", strings.ToLower(direction.String()), rule.Action, rule.Index, warning,
				)))
			}
			for peerIndex := range rule.Peers {
				rule.Peers[peerIndex].compile()
			}
		}
	}
}

func (s *normalizedSelector) compile() {
	s.pod = compileSelector(&s.Pod)
	s.namespace = compileSelector(s.Namespace)
	s.serviceAccount = compileSelector(s.ServiceAccount)
}

func (p *normalizedPeer) compile() {
	p.podSelector = compileSelector(p.PodSelector)
	p.namespaceSelector = compileSelector(p.NamespaceSelector)
	p.serviceAccountSelector = compileSelector(p.ServiceAccountSelector)
	p.blocks = compileBlocks(p.IPBlocks)
}

// compileSelector returns nil for an absent selector and labels.Nothing for an
// invalid one, so an invalid selector can never widen a match.
func compileSelector(selector *metav1.LabelSelector) labels.Selector {
	if selector == nil {
		return nil
	}
	compiled, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return labels.Nothing()
	}
	return compiled
}

func compileBlocks(blocks []netv1.IPBlock) []compiledBlock {
	out := make([]compiledBlock, 0, len(blocks))
	for index := range blocks {
		prefix, err := netip.ParsePrefix(blocks[index].CIDR)
		if err != nil {
			continue
		}
		block := compiledBlock{prefix: prefix.Masked()}
		for _, value := range blocks[index].Except {
			if excluded, parseErr := netip.ParsePrefix(value); parseErr == nil {
				block.except = append(block.except, excluded.Masked())
			}
		}
		out = append(out, block)
	}
	return out
}

func (b *compiledBlock) contains(address netip.Addr) bool {
	if !b.prefix.Contains(address) {
		return false
	}
	for _, excluded := range b.except {
		if excluded.Contains(address) {
			return false
		}
	}
	return true
}

// normalizeSnapshotPolicies converts every policy source into the shared
// model. Normalization problems stay attached to their policy or rule so the
// evaluator can scope uncertainty to the pairs they can affect.
func normalizeSnapshotPolicies(snapshot *Snapshot, cache *normalizationCache) []*normalizedPolicy {
	policies := make([]*normalizedPolicy, 0, len(snapshot.NetworkPolicies)+
		len(snapshot.CiliumNetworkPolicies)+len(snapshot.CiliumClusterwideNetworkPolicies)+
		len(snapshot.IstioAuthorizationPolicies))
	for index := range snapshot.NetworkPolicies {
		policy := &snapshot.NetworkPolicies[index]
		policies = append(policies, cache.load(
			nativeCacheKey(policy),
			func() []*normalizedPolicy { return []*normalizedPolicy{normalizeNetworkPolicy(policy)} },
		)...)
	}
	istio := istioRootConfig{
		root:       snapshot.IstioRootNamespace,
		candidates: snapshot.IstioRootNamespaceCandidates,
	}
	appendCustom := func(objects []unstructured.Unstructured, policyType PolicyType) {
		for index := range objects {
			object := &objects[index]
			policies = append(policies, cache.load(
				customCacheKey(object, policyType, &istio),
				func() []*normalizedPolicy {
					normalized, _ := normalizeCustomPolicy(object, policyType, &istio)
					return normalized
				},
			)...)
		}
	}
	appendCustom(snapshot.CiliumNetworkPolicies, PolicyTypeCiliumNetworkPolicy)
	appendCustom(snapshot.CiliumClusterwideNetworkPolicies, PolicyTypeCiliumClusterwideNetworkPolicy)
	appendCustom(snapshot.IstioAuthorizationPolicies, PolicyTypeIstioAuthorizationPolicy)
	return policies
}

func normalizeNetworkPolicy(policy *netv1.NetworkPolicy) *normalizedPolicy {
	normalized := &normalizedPolicy{
		ObjectMeta:  *policy.ObjectMeta.DeepCopy(),
		Type:        PolicyTypeNetworkPolicy,
		Version:     "networking.k8s.io/v1",
		Layer:       policyLayerNetwork,
		Selector:    normalizedSelector{Pod: *policy.Spec.PodSelector.DeepCopy()},
		PolicyTypes: slices.Clone(policy.Spec.PolicyTypes),
	}
	normalized.Ingress.Isolate = policyHasDirection(policy, Ingress)
	normalized.Egress.Isolate = policyHasDirection(policy, Egress)
	for index := range policy.Spec.Ingress {
		rule := &policy.Spec.Ingress[index]
		normalized.Ingress.Rules = append(normalized.Ingress.Rules, normalizedRule{
			Index:       index,
			Action:      PolicyActionAllow,
			Peers:       normalizeNetworkPolicyPeers(rule.From),
			PeerStrings: rulePeerStrings(rule.From),
			Ports:       slices.Clone(rule.Ports),
			YAML:        ruleYAML("ingress", rule.From, rule.Ports),
		})
	}
	for index := range policy.Spec.Egress {
		rule := &policy.Spec.Egress[index]
		normalized.Egress.Rules = append(normalized.Egress.Rules, normalizedRule{
			Index:       index,
			Action:      PolicyActionAllow,
			Peers:       normalizeNetworkPolicyPeers(rule.To),
			PeerStrings: rulePeerStrings(rule.To),
			Ports:       slices.Clone(rule.Ports),
			YAML:        ruleYAML("egress", rule.To, rule.Ports),
		})
	}
	normalized.finalize()
	return normalized
}

func normalizeNetworkPolicyPeers(peers []netv1.NetworkPolicyPeer) []normalizedPeer {
	out := make([]normalizedPeer, 0, len(peers))
	for index := range peers {
		peer := &peers[index]
		normalized := normalizedPeer{
			PodSelector:       peer.PodSelector.DeepCopy(),
			NamespaceSelector: peer.NamespaceSelector.DeepCopy(),
			AllNamespaces:     peer.NamespaceSelector != nil,
		}
		if peer.IPBlock != nil {
			normalized.IPBlocks = []netv1.IPBlock{*peer.IPBlock.DeepCopy()}
		}
		out = append(out, normalized)
	}
	return out
}

// normalizeCustomPolicy returns the normalized policies and every problem
// found while normalizing them. The problems are also attached to the policies.
func normalizeCustomPolicy(
	object *unstructured.Unstructured,
	policyType PolicyType,
	istio *istioRootConfig,
) ([]*normalizedPolicy, []error) {
	switch policyType {
	case PolicyTypeCiliumNetworkPolicy, PolicyTypeCiliumClusterwideNetworkPolicy:
		return normalizeCiliumPolicy(object, policyType)
	case PolicyTypeIstioAuthorizationPolicy:
		return normalizeIstioPolicy(object, istio)
	default:
		err := fmt.Errorf("unsupported policy type %q", policyType)
		return []*normalizedPolicy{selectionUnknownPolicy(object, policyType, err)}, []error{err}
	}
}

// selectionUnknownPolicy represents a resource whose selected pods cannot be
// determined. Namespaced resources only affect pods in their namespace.
func selectionUnknownPolicy(object *unstructured.Unstructured, policyType PolicyType, err error) *normalizedPolicy {
	policy := &normalizedPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: object.GetName(), Namespace: object.GetNamespace(), UID: object.GetUID(),
			ResourceVersion: object.GetResourceVersion(),
		},
		Type:          policyType,
		Version:       object.GetAPIVersion(),
		ClusterScoped: policyType == PolicyTypeCiliumClusterwideNetworkPolicy || object.GetNamespace() == "",
		Layer:         policyLayerNetwork,
		State:         policySelectionUnknown,
		Problems:      []string{err.Error() + "; the pods it selects cannot be determined"},
		AllDirections: true,
	}
	if policyType == PolicyTypeIstioAuthorizationPolicy {
		policy.Layer = policyLayerAuthorization
	}
	policy.finalize()
	return policy
}

func decodeUnstructured(object *unstructured.Unstructured, target any) error {
	raw, err := json.Marshal(object.Object)
	if err != nil {
		return fmt.Errorf("marshal policy resource: %w", err)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("decode policy resource: %w", err)
	}
	return nil
}

func marshalPolicyRule(rule any) string {
	raw, err := yaml.Marshal(rule)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func normalizedPeerStrings(peers []normalizedPeer, matchNone bool) []string {
	if matchNone {
		return []string{"<none>"}
	}
	out := make([]string, 0, len(peers))
	for index := range peers {
		peer := &peers[index]
		var parts []string
		for _, block := range peer.IPBlocks {
			value := "ipBlock=" + block.CIDR
			if len(block.Except) > 0 {
				value += " except " + strings.Join(block.Except, ",")
			}
			parts = append(parts, value)
		}
		if peer.NamespaceSelector != nil {
			parts = append(parts, "namespaceSelector="+labelSelectorString(peer.NamespaceSelector))
		}
		if peer.PodSelector != nil {
			parts = append(parts, "podSelector="+labelSelectorString(peer.PodSelector))
		}
		if peer.ServiceAccountSelector != nil {
			parts = append(parts, "serviceAccountSelector="+labelSelectorString(peer.ServiceAccountSelector))
		}
		appendValues := func(name string, values []string) {
			if len(values) > 0 {
				parts = append(parts, name+"="+strings.Join(values, ","))
			}
		}
		appendValues("namespaces", peer.Namespaces)
		appendValues("notNamespaces", peer.NotNamespaces)
		appendValues("serviceAccounts", peer.ServiceAccounts)
		appendValues("notServiceAccounts", peer.NotServiceAccounts)
		appendValues("principals", peer.Principals)
		appendValues("notPrincipals", peer.NotPrincipals)
		appendValues("trustDomains", peer.TrustDomains)
		appendValues("notTrustDomains", peer.NotTrustDomains)
		if len(parts) == 0 {
			parts = append(parts, "all peers")
		}
		out = append(out, strings.Join(parts, ", "))
	}
	return out
}

func errorStrings(errs []error) []string {
	out := make([]string, 0, len(errs))
	for _, err := range errs {
		out = append(out, err.Error())
	}
	return uniqueStrings(out)
}

func mapsClone(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	out := make(map[string]string, len(source))
	for key, value := range source {
		out[key] = value
	}
	return out
}
