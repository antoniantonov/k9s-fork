// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	istioActionAllow  = "ALLOW"
	istioActionDeny   = "DENY"
	istioActionCustom = "CUSTOM"
	istioActionAudit  = "AUDIT"

	istioIdentityNote = "Istio principal, namespace, service-account and trust-domain matching is derived from " +
		"workload metadata: it assumes mesh mTLS and the cluster.local trust domain, and sources outside the mesh have no identity. " +
		"Sidecars send plaintext, without an identity, to bare pod IPs that no Service selects"
)

// istioRootConfig describes the resolved Istio root namespace. Candidates are
// set when revisions disagree about the root.
type istioRootConfig struct {
	root       string
	candidates []string
}

func (c *istioRootConfig) effectiveRoot() string {
	if c == nil || c.root == "" {
		return DefaultIstioRootNamespace
	}
	return c.root
}

func (c *istioRootConfig) ambiguous(namespace string) bool {
	return c != nil && len(c.candidates) > 1 && slices.Contains(c.candidates, namespace)
}

type istioPolicyResource struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   metav1.ObjectMeta `json:"metadata"`
	Spec       istioPolicySpec   `json:"spec"`
}

type istioPolicySpec struct {
	Selector   *istioWorkloadSelector `json:"selector,omitempty"`
	TargetRef  json.RawMessage        `json:"targetRef,omitempty"`
	TargetRefs []json.RawMessage      `json:"targetRefs,omitempty"`
	Action     string                 `json:"action,omitempty"`
	Provider   json.RawMessage        `json:"provider,omitempty"`
	Rules      []istioRule            `json:"rules,omitempty"`
}

type istioWorkloadSelector struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

type istioRule struct {
	From []istioFrom       `json:"from,omitempty"`
	To   []istioTo         `json:"to,omitempty"`
	When []json.RawMessage `json:"when,omitempty"`
}

type istioFrom struct {
	Source istioSource `json:"source,omitempty"`
}

type istioSource struct {
	Principals           []string `json:"principals,omitempty"`
	NotPrincipals        []string `json:"notPrincipals,omitempty"`
	RequestPrincipals    []string `json:"requestPrincipals,omitempty"`
	NotRequestPrincipals []string `json:"notRequestPrincipals,omitempty"`
	Namespaces           []string `json:"namespaces,omitempty"`
	NotNamespaces        []string `json:"notNamespaces,omitempty"`
	ServiceAccounts      []string `json:"serviceAccounts,omitempty"`
	NotServiceAccounts   []string `json:"notServiceAccounts,omitempty"`
	IPBlocks             []string `json:"ipBlocks,omitempty"`
	NotIPBlocks          []string `json:"notIpBlocks,omitempty"`
	RemoteIPBlocks       []string `json:"remoteIpBlocks,omitempty"`
	NotRemoteIPBlocks    []string `json:"notRemoteIpBlocks,omitempty"`
	TrustDomains         []string `json:"trustDomains,omitempty"`
	NotTrustDomains      []string `json:"notTrustDomains,omitempty"`
}

type istioTo struct {
	Operation istioOperation `json:"operation,omitempty"`
}

type istioOperation struct {
	Hosts      []string `json:"hosts,omitempty"`
	NotHosts   []string `json:"notHosts,omitempty"`
	Ports      []string `json:"ports,omitempty"`
	NotPorts   []string `json:"notPorts,omitempty"`
	Methods    []string `json:"methods,omitempty"`
	NotMethods []string `json:"notMethods,omitempty"`
	Paths      []string `json:"paths,omitempty"`
	NotPaths   []string `json:"notPaths,omitempty"`
}

func normalizeIstioPolicy(object *unstructured.Unstructured, istio *istioRootConfig) ([]*normalizedPolicy, []error) {
	var resource istioPolicyResource
	if err := decodeUnstructured(object, &resource); err != nil {
		policy := selectionUnknownPolicy(object, PolicyTypeIstioAuthorizationPolicy, err)
		policy.ClusterScoped = object.GetNamespace() == istio.effectiveRoot() || istio.ambiguous(object.GetNamespace())
		return []*normalizedPolicy{policy}, []error{err}
	}
	if strings.EqualFold(resource.Metadata.Annotations["istio.io/dry-run"], "true") {
		return nil, nil
	}
	if resource.APIVersion == "" {
		resource.APIVersion = "security.istio.io/v1"
	}
	action := strings.ToUpper(resource.Spec.Action)
	if action == "" {
		action = istioActionAllow
	}
	if action == istioActionAudit {
		return nil, nil
	}

	policy := &normalizedPolicy{
		ObjectMeta: *resource.Metadata.DeepCopy(),
		Type:       PolicyTypeIstioAuthorizationPolicy,
		Version:    resource.APIVersion,
		Layer:      policyLayerAuthorization,
	}
	if resource.Spec.Selector != nil {
		policy.Selector.Pod.MatchLabels = mapsClone(resource.Spec.Selector.MatchLabels)
	}
	root := istio.effectiveRoot()
	switch {
	case istio.ambiguous(policy.Namespace):
		policy.ClusterScoped = true
		policy.State = policySelectionUnknown
		policy.Problems = append(policy.Problems, fmt.Sprintf(
			"Istio revisions use different root namespaces (%s), so whether this policy applies mesh-wide cannot be determined",
			strings.Join(istio.candidates, ", "),
		))
	case policy.Namespace == root:
		policy.ClusterScoped = true
		policy.Notes = append(policy.Notes, fmt.Sprintf(
			"policy is treated as mesh-wide because %s is the resolved Istio root namespace", root,
		))
	}

	var errs []error
	if len(resource.Spec.TargetRef) > 0 || len(resource.Spec.TargetRefs) > 0 {
		policy.State = policySelectionUnknown
		policy.Problems = append(policy.Problems,
			"targetRefs cannot be resolved to pods from the policy snapshot; the pods it selects cannot be determined")
		errs = append(errs, errors.New("targetRefs cannot be resolved to pods from the policy snapshot"))
	}
	ruleAction := PolicyActionAllow
	switch action {
	case istioActionAllow:
	case istioActionDeny:
		ruleAction = PolicyActionDeny
	case istioActionCustom:
		ruleAction = PolicyActionCustom
	default:
		if policy.State == policyEnforced {
			policy.State = policyEffectUnknown
		}
		policy.Problems = append(policy.Problems, fmt.Sprintf("unsupported Istio action %q", action))
		errs = append(errs, fmt.Errorf("unsupported Istio action %q", action))
	}
	policy.Ingress.Isolate = action == istioActionAllow
	for index := range resource.Spec.Rules {
		rule := normalizeIstioRule(policy.Namespace, index, ruleAction, &resource.Spec.Rules[index])
		if action == istioActionCustom {
			// CUSTOM never grants access; an external provider may deny any
			// request the rule matches.
			rule.Disabled = true
			rule.Warnings = append(rule.Warnings, "CUSTOM authorization depends on an external provider")
		}
		for _, warning := range rule.Warnings {
			errs = append(errs, fmt.Errorf("ingress %s rule %d: %s", ruleAction, index, warning))
		}
		policy.Ingress.Rules = append(policy.Ingress.Rules, rule)
	}
	policy.finalize()
	return []*normalizedPolicy{policy}, errs
}

func normalizeIstioRule(policyNamespace string, index int, action PolicyAction, source *istioRule) normalizedRule {
	rule := normalizedRule{
		Index:   index,
		Action:  action,
		TCPOnly: true,
		YAML:    marshalPolicyRule(source),
	}
	for index := range source.From {
		peer, warnings, notes, disabled := normalizeIstioSource(policyNamespace, &source.From[index].Source)
		rule.Peers = append(rule.Peers, peer)
		rule.Warnings = append(rule.Warnings, warnings...)
		rule.Notes = append(rule.Notes, notes...)
		rule.Disabled = rule.Disabled || disabled
		rule.IdentityConstrained = rule.IdentityConstrained || peer.hasIdentityConstraints()
	}
	ports, notes, warnings, disabled := normalizeIstioOperations(source.To)
	rule.Ports = ports
	rule.Notes = append(rule.Notes, notes...)
	rule.Warnings = append(rule.Warnings, warnings...)
	rule.Disabled = rule.Disabled || disabled
	if len(source.When) > 0 {
		rule.Warnings = append(rule.Warnings, "Istio when conditions cannot be evaluated from the policy snapshot")
		rule.Disabled = true
	}
	if action == PolicyActionDeny && istioRuleHasUnmodeledPredicates(source) {
		rule.Warnings = append(rule.Warnings, "DENY has unmodeled L7 predicates; its ports are not subtracted")
		rule.Disabled = true
	}
	if rule.IdentityConstrained {
		rule.Notes = append(rule.Notes, istioIdentityNote)
	}
	rule.PeerStrings = normalizedPeerStrings(rule.Peers, false)
	return rule
}

func istioRuleHasUnmodeledPredicates(rule *istioRule) bool {
	for index := range rule.To {
		if istioOperationHasL7(&rule.To[index].Operation) {
			return true
		}
	}
	return false
}

func istioOperationHasL7(operation *istioOperation) bool {
	return len(operation.Hosts)+len(operation.NotHosts)+len(operation.Methods)+
		len(operation.NotMethods)+len(operation.Paths)+len(operation.NotPaths) > 0
}

// normalizeIstioSource converts a source. Disabled reports constraints the
// graph cannot evaluate, which keep the rule from contributing permissions.
func normalizeIstioSource(policyNamespace string, source *istioSource) (
	peer normalizedPeer,
	warnings, notes []string,
	disabled bool,
) {
	peer = normalizedPeer{
		AllNamespaces:      true,
		Namespaces:         slices.Clone(source.Namespaces),
		NotNamespaces:      slices.Clone(source.NotNamespaces),
		ServiceAccounts:    normalizeServiceAccounts(policyNamespace, source.ServiceAccounts),
		NotServiceAccounts: normalizeServiceAccounts(policyNamespace, source.NotServiceAccounts),
		Principals:         slices.Clone(source.Principals),
		NotPrincipals:      slices.Clone(source.NotPrincipals),
		TrustDomains:       slices.Clone(source.TrustDomains),
		NotTrustDomains:    slices.Clone(source.NotTrustDomains),
		MatchPodIPs:        len(source.IPBlocks) > 0,
	}
	for _, value := range source.IPBlocks {
		block, err := istioIPBlock(value)
		if err != nil {
			warnings = append(warnings, err.Error())
			disabled = true
			continue
		}
		peer.IPBlocks = append(peer.IPBlocks, block)
	}
	if len(source.NotIPBlocks) > 0 {
		warnings = append(warnings, "notIpBlocks cannot be represented without CIDR subtraction")
		disabled = true
	}
	if len(source.RemoteIPBlocks) > 0 || len(source.NotRemoteIPBlocks) > 0 {
		warnings = append(warnings, "remoteIpBlocks depend on proxy forwarding configuration")
		disabled = true
	}
	if len(source.RequestPrincipals) > 0 || len(source.NotRequestPrincipals) > 0 {
		warnings = append(warnings, "requestPrincipals depend on JWT request identity")
		disabled = true
	}
	for _, value := range append(slices.Clone(source.ServiceAccounts), source.NotServiceAccounts...) {
		if strings.Contains(value, "*") {
			warnings = append(warnings, fmt.Sprintf("serviceAccounts value %q uses a wildcard, which Istio does not allow", value))
		}
	}
	if len(source.ServiceAccounts)+len(source.NotServiceAccounts) > 0 &&
		len(source.Principals)+len(source.NotPrincipals)+len(source.Namespaces)+len(source.NotNamespaces) > 0 {
		warnings = append(warnings, "Istio does not allow serviceAccounts together with principals or namespaces")
	}
	for _, value := range append(slices.Clone(source.Principals), source.NotPrincipals...) {
		if len(value) > 2 && strings.Contains(value[1:len(value)-1], "*") {
			notes = append(notes, fmt.Sprintf("Istio matches the inner * of principal %q literally", value))
		}
	}
	if len(peer.IPBlocks) > 0 && peer.hasIdentityConstraints() {
		peer.CIDRMatchUnsupported = true
	}
	return peer, warnings, notes, disabled
}

func (p *normalizedPeer) hasIdentityConstraints() bool {
	return len(p.Principals)+len(p.NotPrincipals)+len(p.Namespaces)+len(p.NotNamespaces)+
		len(p.ServiceAccounts)+len(p.NotServiceAccounts)+len(p.TrustDomains)+len(p.NotTrustDomains) > 0
}

func (p *normalizedPeer) hasPositiveIdentityConstraints() bool {
	return len(p.Principals)+len(p.Namespaces)+len(p.ServiceAccounts)+len(p.TrustDomains) > 0
}

func normalizeServiceAccounts(namespace string, values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.Contains(value, "/") {
			out = append(out, value)
		} else {
			out = append(out, namespace+"/"+value)
		}
	}
	return out
}

// normalizeIstioOperations converts TCP ports. Disabled reports that none of
// the operations could be modeled.
func normalizeIstioOperations(operations []istioTo) (
	ports []netv1.NetworkPolicyPort,
	notes, warnings []string,
	disabled bool,
) {
	if len(operations) == 0 {
		return nil, nil, nil, false
	}
	allPorts, modeled := false, 0
	for index := range operations {
		operation := &operations[index].Operation
		if len(operation.NotPorts) > 0 {
			warnings = append(warnings, "notPorts cannot be represented without port subtraction")
			continue
		}
		if istioOperationHasL7(operation) {
			notes = append(notes, "Istio L7 operation constraints are not rendered; reachability means at least one request can match")
			warnings = append(warnings, "Istio L7 operation constraints cannot be evaluated from the policy snapshot")
		}
		if len(operation.Ports) == 0 {
			allPorts = true
			modeled++
			continue
		}
		for _, value := range operation.Ports {
			if value == "*" {
				allPorts = true
				modeled++
				continue
			}
			number, err := strconv.ParseInt(value, 10, 32)
			if err != nil || number < 1 || number > 65535 {
				warnings = append(warnings, fmt.Sprintf("Istio port %q is not a number in 1-65535", value))
				continue
			}
			protocol := corev1.ProtocolTCP
			port := intstr.FromInt32(int32(number))
			ports = append(ports, netv1.NetworkPolicyPort{Protocol: &protocol, Port: &port})
			modeled++
		}
	}
	if allPorts {
		ports = nil
	}
	return ports, uniqueStrings(notes), warnings, modeled == 0
}

func istioIPBlock(value string) (netv1.IPBlock, error) {
	if address, err := netip.ParseAddr(value); err == nil {
		return netv1.IPBlock{CIDR: netip.PrefixFrom(address, address.BitLen()).String()}, nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netv1.IPBlock{}, fmt.Errorf("invalid Istio IP block %q: %w", value, err)
	}
	return netv1.IPBlock{CIDR: prefix.Masked().String()}, nil
}

// istioMatchesString implements Istio's exact, prefix ("abc*"), suffix
// ("*abc") and presence ("*") matching. A leading "*" always selects suffix
// matching, so "*abc*" matches values ending in the literal "abc*".
func istioMatchesString(value, pattern string) bool {
	switch {
	case pattern == "*":
		return value != ""
	case strings.HasPrefix(pattern, "*"):
		return strings.HasSuffix(value, pattern[1:])
	case strings.HasSuffix(pattern, "*"):
		return strings.HasPrefix(value, pattern[:len(pattern)-1])
	default:
		return value == pattern
	}
}

// istioMatchesNamespace mirrors Istio's namespace matcher, which expands every
// "*" as a wildcard anywhere in the value.
func istioMatchesNamespace(value, pattern string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return value == pattern
	}
	if !strings.HasPrefix(value, parts[0]) {
		return false
	}
	rest := value[len(parts[0]):]
	for _, part := range parts[1 : len(parts)-1] {
		index := strings.Index(rest, part)
		if index < 0 {
			return false
		}
		rest = rest[index+len(part):]
	}
	return strings.HasSuffix(rest, parts[len(parts)-1])
}

// istioMatchesTrustDomain mirrors Istio's trust-domain matcher: "*" requires
// presence and the first "*" is a wildcard at any position.
func istioMatchesTrustDomain(value, pattern string) bool {
	if pattern == "*" {
		return value != ""
	}
	prefix, suffix, found := strings.Cut(pattern, "*")
	if !found {
		return value == pattern
	}
	return len(value) >= len(prefix)+len(suffix) && strings.HasPrefix(value, prefix) && strings.HasSuffix(value, suffix)
}

func istioMatchesServiceAccount(value, pattern string) bool {
	return value == pattern
}

// matchesAnyPattern reports whether any pattern matches. It keeps scanning
// after a non-matching wildcard; only a match ends the search.
func matchesAnyPattern(value string, patterns []string, match func(value, pattern string) bool) bool {
	for _, pattern := range patterns {
		if match(value, pattern) {
			return true
		}
	}
	return false
}

// istioIdentity is the mTLS identity a destination sidecar sees for a source.
type istioIdentity struct {
	state          meshState
	namespace      string
	serviceAccount string
	principal      string
}

func (i *istioIdentity) present() bool {
	return i.state == meshEnrolled
}

// identityMatch evaluates identity constraints. Sources outside the mesh
// present no identity: positive constraints never match them and negative
// constraints never exclude them.
func (p *normalizedPeer) identityMatch(identity *istioIdentity) matchResult {
	if !p.hasIdentityConstraints() {
		return matchYes
	}
	if identity.state == meshUnknown {
		return matchUnknown
	}
	present := identity.present()
	serviceAccount := identity.namespace + "/" + identity.serviceAccount
	checks := []struct {
		value    string
		positive []string
		negative []string
		match    func(value, pattern string) bool
	}{
		{identity.principal, p.Principals, p.NotPrincipals, istioMatchesString},
		{identity.namespace, p.Namespaces, p.NotNamespaces, istioMatchesNamespace},
		{serviceAccount, p.ServiceAccounts, p.NotServiceAccounts, istioMatchesServiceAccount},
		{istioTrustDomain, p.TrustDomains, p.NotTrustDomains, istioMatchesTrustDomain},
	}
	for _, check := range checks {
		if len(check.positive) > 0 && (!present || !matchesAnyPattern(check.value, check.positive, check.match)) {
			return matchNo
		}
		if present && matchesAnyPattern(check.value, check.negative, check.match) {
			return matchNo
		}
	}
	return matchYes
}
