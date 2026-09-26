// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"regexp"
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
	ciliumTargetNamespace      = "namespace"
	ciliumTargetServiceAccount = "serviceaccount"
	ciliumTargetPod            = "pod"
	ciliumNamespaceLabelPrefix = "io.cilium.k8s.namespace.labels."

	ciliumNamespaceLabelNote = "assumes Cilium 1.16 or later: peers selected only by io.cilium.k8s.namespace.labels.* " +
		"are not limited to the policy namespace (Cilium 1.15 and earlier limit them)"
	ciliumHostPolicyNote = "nodeSelector host policies apply to nodes and hostNetwork pods, outside the pod reachability graph"
	jsonNull             = "null"
)

// ciliumSvcName mirrors Cilium's IANA service-name check for named ports.
var ciliumSvcName = regexp.MustCompile(`^([a-zA-Z0-9]-?)*[a-zA-Z](-?[a-zA-Z0-9])*$`)

type ciliumPolicyResource struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Metadata   metav1.ObjectMeta  `json:"metadata"`
	Spec       *ciliumPolicyRule  `json:"spec,omitempty"`
	Specs      []ciliumPolicyRule `json:"specs,omitempty"`
}

type ciliumPolicyRule struct {
	EndpointSelector  *ciliumEndpointSelector `json:"endpointSelector,omitempty"`
	NodeSelector      *ciliumEndpointSelector `json:"nodeSelector,omitempty"`
	Ingress           []ciliumTrafficRule     `json:"ingress,omitempty"`
	IngressDeny       []ciliumTrafficRule     `json:"ingressDeny,omitempty"`
	Egress            []ciliumTrafficRule     `json:"egress,omitempty"`
	EgressDeny        []ciliumTrafficRule     `json:"egressDeny,omitempty"`
	EnableDefaultDeny ciliumDefaultDeny       `json:"enableDefaultDeny,omitempty"`
}

type ciliumDefaultDeny struct {
	Ingress *bool `json:"ingress,omitempty"`
	Egress  *bool `json:"egress,omitempty"`
}

type ciliumEndpointSelector struct {
	MatchLabels      map[string]string                 `json:"matchLabels,omitempty"`
	MatchExpressions []metav1.LabelSelectorRequirement `json:"matchExpressions,omitempty"`
}

type ciliumTrafficRule struct {
	FromEndpoints  []ciliumEndpointSelector `json:"fromEndpoints,omitempty"`
	ToEndpoints    []ciliumEndpointSelector `json:"toEndpoints,omitempty"`
	FromCIDR       []string                 `json:"fromCIDR,omitempty"`
	ToCIDR         []string                 `json:"toCIDR,omitempty"`
	FromCIDRSet    []ciliumCIDRRule         `json:"fromCIDRSet,omitempty"`
	ToCIDRSet      []ciliumCIDRRule         `json:"toCIDRSet,omitempty"`
	FromEntities   []string                 `json:"fromEntities,omitempty"`
	ToEntities     []string                 `json:"toEntities,omitempty"`
	ToPorts        []ciliumPortRule         `json:"toPorts,omitempty"`
	FromRequires   []json.RawMessage        `json:"fromRequires,omitempty"`
	ToRequires     []json.RawMessage        `json:"toRequires,omitempty"`
	FromGroups     []json.RawMessage        `json:"fromGroups,omitempty"`
	ToGroups       []json.RawMessage        `json:"toGroups,omitempty"`
	FromNodes      []json.RawMessage        `json:"fromNodes,omitempty"`
	ToNodes        []json.RawMessage        `json:"toNodes,omitempty"`
	ToServices     []json.RawMessage        `json:"toServices,omitempty"`
	ToFQDNs        []json.RawMessage        `json:"toFQDNs,omitempty"`
	ICMPs          []json.RawMessage        `json:"icmps,omitempty"`
	Authentication *ciliumAuthentication    `json:"authentication,omitempty"`
}

type ciliumAuthentication struct {
	Mode string `json:"mode,omitempty"`
}

type ciliumCIDRRule struct {
	CIDR              string                  `json:"cidr,omitempty"`
	Except            []string                `json:"except,omitempty"`
	CIDRGroupRef      string                  `json:"cidrGroupRef,omitempty"`
	CIDRGroupSelector *ciliumEndpointSelector `json:"cidrGroupSelector,omitempty"`
}

type ciliumPortRule struct {
	Ports          []ciliumPortProtocol `json:"ports,omitempty"`
	Rules          json.RawMessage      `json:"rules,omitempty"`
	TerminatingTLS json.RawMessage      `json:"terminatingTLS,omitempty"`
	OriginatingTLS json.RawMessage      `json:"originatingTLS,omitempty"`
	Listener       json.RawMessage      `json:"listener,omitempty"`
	ServerNames    []string             `json:"serverNames,omitempty"`
}

type ciliumPortProtocol struct {
	Port     string `json:"port,omitempty"`
	EndPort  int32  `json:"endPort,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// ciliumRuleFields selects the direction-specific peer fields of a rule.
type ciliumRuleFields struct {
	endpoints []ciliumEndpointSelector
	cidrs     []string
	cidrSets  []ciliumCIDRRule
	entities  []string
	nodes     []json.RawMessage
	groups    []json.RawMessage
	requires  []json.RawMessage
	services  []json.RawMessage
	fqdns     []json.RawMessage
}

func ciliumFields(direction Direction, source *ciliumTrafficRule) ciliumRuleFields {
	if direction == Egress {
		return ciliumRuleFields{
			endpoints: source.ToEndpoints, cidrs: source.ToCIDR, cidrSets: source.ToCIDRSet,
			entities: source.ToEntities, nodes: source.ToNodes, groups: source.ToGroups,
			requires: source.ToRequires, services: source.ToServices, fqdns: source.ToFQDNs,
		}
	}
	return ciliumRuleFields{
		endpoints: source.FromEndpoints, cidrs: source.FromCIDR, cidrSets: source.FromCIDRSet,
		entities: source.FromEntities, nodes: source.FromNodes, groups: source.FromGroups,
		requires: source.FromRequires,
	}
}

func normalizeCiliumPolicy(object *unstructured.Unstructured, policyType PolicyType) ([]*normalizedPolicy, []error) {
	var resource ciliumPolicyResource
	if err := decodeUnstructured(object, &resource); err != nil {
		return []*normalizedPolicy{selectionUnknownPolicy(object, policyType, err)}, []error{err}
	}
	if resource.APIVersion == "" {
		resource.APIVersion = "cilium.io/v2"
	}
	type specEntry struct {
		rule *ciliumPolicyRule
		path string
	}
	var specs []specEntry
	if resource.Spec != nil {
		specs = append(specs, specEntry{rule: resource.Spec, path: "spec"})
	}
	for index := range resource.Specs {
		specs = append(specs, specEntry{rule: &resource.Specs[index], path: fmt.Sprintf("specs[%d]", index)})
	}
	if len(specs) == 0 {
		policy := &normalizedPolicy{
			ObjectMeta: *resource.Metadata.DeepCopy(), Type: policyType, Version: resource.APIVersion,
			ClusterScoped: policyType == PolicyTypeCiliumClusterwideNetworkPolicy, State: policyInert,
			Notes: []string{"spec or specs must contain a policy rule; Cilium rejects this policy"},
		}
		policy.finalize()
		return []*normalizedPolicy{policy}, nil
	}

	policies := make([]*normalizedPolicy, 0, len(specs))
	var rejected, allErrs []error
	for index, spec := range specs {
		policy, validation, errs := normalizeCiliumPolicyRule(&resource, policyType, index, spec.path, len(specs), spec.rule)
		policies = append(policies, policy)
		for _, err := range validation {
			rejected = append(rejected, fmt.Errorf("%s: %w", spec.path, err))
		}
		allErrs = append(allErrs, validation...)
		allErrs = append(allErrs, errs...)
	}
	if len(rejected) > 0 {
		// Cilium validates every rule entry before importing the resource,
		// so one invalid entry rejects all of them.
		reason := "Cilium rejects this policy: " + strings.Join(errorStrings(rejected), "; ")
		for _, policy := range policies {
			if policy.State == policyEnforced {
				policy.State = policyEffectUnknown
			}
			if policy.State != policyInert {
				policy.Problems = append(policy.Problems, reason)
			}
		}
	}
	for _, policy := range policies {
		policy.finalize()
	}
	return policies, allErrs
}

// normalizeCiliumPolicyRule normalizes one spec entry. Validation errors make
// Cilium reject the whole resource and are returned separately.
func normalizeCiliumPolicyRule(
	resource *ciliumPolicyResource,
	policyType PolicyType,
	specIndex int,
	specPath string,
	specCount int,
	spec *ciliumPolicyRule,
) (policy *normalizedPolicy, validation, errs []error) {
	clusterScoped := policyType == PolicyTypeCiliumClusterwideNetworkPolicy
	policy = &normalizedPolicy{
		ObjectMeta:    *resource.Metadata.DeepCopy(),
		Type:          policyType,
		Version:       resource.APIVersion,
		SpecIndex:     specIndex,
		SpecPath:      specPath,
		SpecCount:     specCount,
		ClusterScoped: clusterScoped,
		Layer:         policyLayerNetwork,
	}
	if len(spec.Ingress)+len(spec.IngressDeny)+len(spec.Egress)+len(spec.EgressDeny) == 0 {
		validation = append(validation, errors.New("rule must have at least one of Ingress, IngressDeny, Egress, EgressDeny"))
	}
	switch {
	case spec.EndpointSelector != nil && spec.NodeSelector != nil:
		validation = append(validation, errors.New("rule cannot have both EndpointSelector and NodeSelector"))
	case spec.EndpointSelector == nil && spec.NodeSelector == nil:
		validation = append(validation, errors.New("rule must have one of EndpointSelector or NodeSelector"))
		policy.State = policySelectionUnknown
		policy.Problems = append(policy.Problems, "the rule has no endpointSelector; the pods it selects cannot be determined")
	case spec.NodeSelector != nil:
		policy.State = policyInert
		policy.HostPolicy = true
		policy.Notes = append(policy.Notes, ciliumHostPolicyNote)
	}
	if spec.EndpointSelector != nil {
		selector, unsupported, invalid, _ := normalizeCiliumSelector(spec.EndpointSelector, policy.Namespace, clusterScoped, true)
		policy.Selector = selector
		validation = append(validation, invalid...)
		if len(unsupported)+len(invalid) > 0 {
			policy.State = policySelectionUnknown
			policy.Problems = append(policy.Problems, fmt.Sprintf(
				"endpointSelector cannot be evaluated (%s); the pods it selects cannot be determined",
				strings.Join(errorStrings(append(unsupported, invalid...)), "; "),
			))
			errs = append(errs, unsupported...)
		}
	}

	policy.Ingress.Isolate = ciliumDirectionIsolates(
		spec.EnableDefaultDeny.Ingress, len(spec.Ingress) > 0 || len(spec.IngressDeny) > 0,
	)
	policy.Egress.Isolate = ciliumDirectionIsolates(
		spec.EnableDefaultDeny.Egress, len(spec.Egress) > 0 || len(spec.EgressDeny) > 0,
	)
	for _, section := range []struct {
		direction Direction
		action    PolicyAction
		rules     []ciliumTrafficRule
	}{
		{Ingress, PolicyActionAllow, spec.Ingress},
		{Ingress, PolicyActionDeny, spec.IngressDeny},
		{Egress, PolicyActionAllow, spec.Egress},
		{Egress, PolicyActionDeny, spec.EgressDeny},
	} {
		policyDirection := policy.direction(section.direction)
		for index := range section.rules {
			rule, ruleValidation := normalizeCiliumTrafficRule(policy, section.direction, section.action, index, &section.rules[index])
			policyDirection.Rules = append(policyDirection.Rules, rule)
			prefix := fmt.Sprintf("%s %s rule %d", strings.ToLower(section.direction.String()), section.action, index)
			for _, err := range ruleValidation {
				validation = append(validation, fmt.Errorf("%s: %w", prefix, err))
			}
			for _, warning := range rule.Warnings {
				errs = append(errs, fmt.Errorf("%s: %s", prefix, warning))
			}
		}
	}
	return policy, validation, errs
}

// ciliumDirectionIsolates mirrors Cilium's default-deny posture: only a
// direction with rules can isolate, and enableDefaultDeny can turn that off.
func ciliumDirectionIsolates(configured *bool, hasRules bool) bool {
	return hasRules && (configured == nil || *configured)
}

func normalizeCiliumTrafficRule(
	policy *normalizedPolicy,
	direction Direction,
	action PolicyAction,
	index int,
	source *ciliumTrafficRule,
) (normalizedRule, []error) {
	rule := normalizedRule{Index: index, Action: action, YAML: marshalPolicyRule(source)}
	fields := ciliumFields(direction, source)
	validation := validateCiliumL3Members(direction, source)
	families := appendCiliumEndpointPeers(policy, &rule, fields.endpoints, &validation)
	families += appendCiliumCIDRPeers(&rule, fields.cidrs, fields.cidrSets, &validation)
	families += appendCiliumEntityPeers(&rule, fields.entities, &validation)
	families += applyCiliumDynamicPeers(&rule, &fields)

	if len(source.ICMPs) > 0 {
		if len(source.ToPorts) > 0 {
			validation = append(validation, errors.New(
				"the ICMPs block may only be present without ToPorts. Define a separate rule to use ToPorts",
			))
		}
		rule.NoPorts = true
		rule.Notes = append(rule.Notes, "ICMP permissions are outside the graph's TCP/UDP/SCTP model")
	}
	ports := normalizeCiliumPorts(source.ToPorts, direction)
	validation = append(validation, ports.invalid...)
	rule.Ports = ports.ports
	rule.NoPorts = rule.NoPorts || ports.noPorts
	rule.Notes = append(rule.Notes, ports.notes...)
	rule.Warnings = append(rule.Warnings, ports.warnings...)
	if source.Authentication != nil && source.Authentication.Mode != "" && source.Authentication.Mode != "disabled" {
		rule.Notes = append(rule.Notes, "Cilium authentication requirements are not represented; reachability is existential")
		rule.Warnings = append(rule.Warnings, "Cilium authentication requirements cannot be evaluated from the policy snapshot")
	}
	// An empty Cilium traffic rule enables isolation without granting access.
	// Only a peerless L4 rule implies a wildcard peer.
	if !rule.Disabled && len(rule.Peers) == 0 &&
		(families > 0 || len(source.ToPorts)+len(source.ICMPs) == 0) {
		rule.MatchNone = true
	}
	rule.PeerStrings = normalizedPeerStrings(rule.Peers, rule.MatchNone)
	return rule, validation
}

// validateCiliumL3Members mirrors Cilium's rule validation: a rule may use only
// one non-empty L3 peer family.
func validateCiliumL3Members(direction Direction, source *ciliumTrafficRule) []error {
	type member struct {
		name  string
		count int
	}
	members := []member{
		{"FromEndpoints", len(source.FromEndpoints)}, {"FromCIDR", len(source.FromCIDR)},
		{"FromCIDRSet", len(source.FromCIDRSet)}, {"FromEntities", len(source.FromEntities)},
		{"FromNodes", len(source.FromNodes)}, {"FromGroups", len(source.FromGroups)},
	}
	if direction == Egress {
		members = []member{
			{"ToEndpoints", len(source.ToEndpoints)}, {"ToCIDR", len(source.ToCIDR)},
			{"ToCIDRSet", len(source.ToCIDRSet)}, {"ToEntities", len(source.ToEntities)},
			{"ToServices", len(source.ToServices)}, {"ToGroups", len(source.ToGroups)},
			{"ToNodes", len(source.ToNodes)}, {"ToFQDNs", len(source.ToFQDNs)},
		}
	}
	var present []string
	for _, item := range members {
		if item.count > 0 {
			present = append(present, item.name)
		}
	}
	if len(present) > 1 {
		return []error{fmt.Errorf("combining %s and %s is not supported yet", present[0], present[1])}
	}
	return nil
}

func appendCiliumEndpointPeers(
	policy *normalizedPolicy,
	rule *normalizedRule,
	endpoints []ciliumEndpointSelector,
	validation *[]error,
) int {
	if endpoints == nil {
		return 0
	}
	if len(endpoints) == 0 {
		rule.MatchNone = true
		return 1
	}
	for index := range endpoints {
		selector, unsupported, invalid, namespaceLabelsOnly := normalizeCiliumSelector(
			&endpoints[index], policy.Namespace, policy.ClusterScoped, false,
		)
		*validation = append(*validation, invalid...)
		if len(unsupported) > 0 {
			rule.UncertainPeers = true
			rule.Warnings = append(rule.Warnings, fmt.Sprintf(
				"peer selector cannot be evaluated: %s", strings.Join(errorStrings(unsupported), "; "),
			))
			continue
		}
		if namespaceLabelsOnly && !policy.ClusterScoped {
			rule.Notes = append(rule.Notes, ciliumNamespaceLabelNote)
		}
		rule.Peers = append(rule.Peers, normalizedPeer{
			PodSelector:            selector.Pod.DeepCopy(),
			NamespaceSelector:      selector.Namespace.DeepCopy(),
			ServiceAccountSelector: selector.ServiceAccount.DeepCopy(),
			AllNamespaces:          selector.Namespace != nil || policy.ClusterScoped,
		})
	}
	if len(rule.Peers) == 0 && rule.UncertainPeers {
		rule.Disabled = true
	}
	return 1
}

func appendCiliumCIDRPeers(rule *normalizedRule, cidrs []string, cidrSets []ciliumCIDRRule, validation *[]error) int {
	if cidrs == nil && cidrSets == nil {
		return 0
	}
	for _, cidr := range cidrs {
		block, err := ciliumIPBlock(cidr, nil)
		if err != nil {
			*validation = append(*validation, err)
			continue
		}
		rule.Peers = append(rule.Peers, normalizedPeer{IPBlocks: []netv1.IPBlock{block}})
	}
	groups := 0
	for _, cidrRule := range cidrSets {
		set := 0
		for _, present := range []bool{cidrRule.CIDR != "", cidrRule.CIDRGroupRef != "", cidrRule.CIDRGroupSelector != nil} {
			if present {
				set++
			}
		}
		switch {
		case set == 0:
			*validation = append(*validation, errors.New("one of cidr, cidrGroupRef, or cidrGroupSelector is required"))
			continue
		case set > 1:
			*validation = append(*validation, errors.New("more than one of cidr, cidrGroupRef, or cidrGroupSelector may not be set"))
			continue
		case cidrRule.CIDR == "":
			groups++
			continue
		}
		block, err := ciliumIPBlock(cidrRule.CIDR, cidrRule.Except)
		if err != nil {
			*validation = append(*validation, err)
			continue
		}
		rule.Peers = append(rule.Peers, normalizedPeer{IPBlocks: []netv1.IPBlock{block}})
	}
	if groups > 0 {
		rule.UncertainPeers = true
		rule.Warnings = append(rule.Warnings, "CIDR group references require runtime Cilium resolution")
		if len(rule.Peers) == 0 {
			rule.Disabled = true
		}
	}
	return 1
}

func appendCiliumEntityPeers(rule *normalizedRule, entities []string, validation *[]error) int {
	if entities == nil {
		return 0
	}
	peers, notes, errs := normalizeCiliumEntities(entities)
	rule.Peers = append(rule.Peers, peers...)
	rule.Notes = append(rule.Notes, notes...)
	*validation = append(*validation, errs...)
	if len(peers) == 0 {
		rule.MatchNone = true
	}
	return 1
}

// applyCiliumDynamicPeers handles peers that need runtime resolution. Such a
// rule may match any peer, so its uncertainty is not limited to known peers.
// It returns the number of L3 peer families the fields use.
func applyCiliumDynamicPeers(rule *normalizedRule, fields *ciliumRuleFields) int {
	families := 0
	dynamic := func(values []json.RawMessage, message string, family bool) {
		if len(values) == 0 {
			return
		}
		if family {
			families++
		}
		rule.Warnings = append(rule.Warnings, message)
		rule.UncertainPeers = true
		rule.Disabled = true
	}
	// Requirements name no peers themselves: Cilium adds them to the endpoint
	// selectors of every rule selecting the pod.
	dynamic(fields.requires, "fromRequires/toRequires identity constraints are not supported", false)
	dynamic(fields.groups, "cloud-provider groups require runtime Cilium resolution", true)
	dynamic(fields.services, "toServices requires live Service endpoint resolution", true)
	dynamic(fields.fqdns, "toFQDNs requires live DNS resolution", true)
	if len(fields.nodes) > 0 {
		families++
		rule.Notes = append(rule.Notes, "node peers are outside the pod reachability graph")
	}
	return families
}

// normalizeCiliumSelector translates Cilium endpoint selector keys. Keys the
// graph cannot evaluate are unsupported, while invalid selectors are also
// rejected by Cilium itself.
func normalizeCiliumSelector(
	source *ciliumEndpointSelector,
	policyNamespace string,
	clusterScoped, subject bool,
) (selector normalizedSelector, unsupported, invalid []error, namespaceLabelsOnly bool) {
	selector.Pod = metav1.LabelSelector{MatchLabels: map[string]string{}}
	namespace := metav1.LabelSelector{MatchLabels: map[string]string{}}
	serviceAccount := metav1.LabelSelector{MatchLabels: map[string]string{}}
	namespaceName, namespaceLabels, serviceAccountConstrained := false, false, false
	for _, key := range slices.Sorted(maps.Keys(source.MatchLabels)) {
		value := source.MatchLabels[key]
		target, normalizedKey, err := ciliumSelectorKey(key)
		if err != nil {
			unsupported = append(unsupported, err)
			continue
		}
		switch target {
		case ciliumTargetNamespace:
			namespace.MatchLabels[normalizedKey] = value
			if strings.HasPrefix(stripCiliumSource(key), ciliumNamespaceLabelPrefix) {
				namespaceLabels = true
			} else {
				namespaceName = true
			}
		case ciliumTargetServiceAccount:
			serviceAccount.MatchLabels[normalizedKey] = value
			serviceAccountConstrained = true
		default:
			selector.Pod.MatchLabels[normalizedKey] = value
		}
	}
	for _, requirement := range source.MatchExpressions {
		originalKey := requirement.Key
		target, normalizedKey, err := ciliumSelectorKey(originalKey)
		if err != nil {
			unsupported = append(unsupported, err)
			continue
		}
		requirement.Key = normalizedKey
		requirement.Values = slices.Clone(requirement.Values)
		switch target {
		case ciliumTargetNamespace:
			namespace.MatchExpressions = append(namespace.MatchExpressions, requirement)
			if strings.HasPrefix(stripCiliumSource(originalKey), ciliumNamespaceLabelPrefix) {
				namespaceLabels = true
			} else {
				namespaceName = true
			}
		case ciliumTargetServiceAccount:
			serviceAccount.MatchExpressions = append(serviceAccount.MatchExpressions, requirement)
			serviceAccountConstrained = true
		default:
			selector.Pod.MatchExpressions = append(selector.Pod.MatchExpressions, requirement)
		}
	}
	namespaceConstrained := namespaceName || namespaceLabels
	if !clusterScoped && (subject || !namespaceConstrained) {
		// A namespaced policy only selects subjects in its own namespace, so a
		// conflicting namespace requirement selects nothing.
		if existing, ok := namespace.MatchLabels[metadataNameLabel]; ok && existing != policyNamespace {
			namespace.MatchExpressions = append(namespace.MatchExpressions, metav1.LabelSelectorRequirement{
				Key: metadataNameLabel, Operator: metav1.LabelSelectorOpIn, Values: []string{policyNamespace},
			})
		} else {
			namespace.MatchLabels[metadataNameLabel] = policyNamespace
		}
		namespaceConstrained = true
	}
	if namespaceConstrained {
		selector.Namespace = &namespace
	}
	if serviceAccountConstrained {
		selector.ServiceAccount = &serviceAccount
	}
	for _, item := range []struct {
		name     string
		selector *metav1.LabelSelector
	}{{"pod", &selector.Pod}, {"namespace", selector.Namespace}, {"service account", selector.ServiceAccount}} {
		if item.selector == nil {
			continue
		}
		if _, err := metav1.LabelSelectorAsSelector(item.selector); err != nil {
			invalid = append(invalid, fmt.Errorf("invalid endpoint %s selector: %w", item.name, err))
		}
	}
	return selector, unsupported, invalid, namespaceLabels && !namespaceName
}

func stripCiliumSource(key string) string {
	key = strings.TrimPrefix(key, "k8s:")
	return strings.TrimPrefix(key, "any:")
}

func ciliumSelectorKey(key string) (target, normalized string, err error) {
	key = stripCiliumSource(key)
	switch {
	case key == "io.kubernetes.pod.namespace":
		return ciliumTargetNamespace, metadataNameLabel, nil
	case strings.HasPrefix(key, ciliumNamespaceLabelPrefix):
		return ciliumTargetNamespace, strings.TrimPrefix(key, ciliumNamespaceLabelPrefix), nil
	case key == "io.cilium.k8s.policy.serviceaccount":
		return ciliumTargetServiceAccount, "name", nil
	case key == "io.cilium.k8s.policy.cluster":
		return "", "", errors.New("Cilium cluster identity selectors require the local cluster name")
	case strings.HasPrefix(key, "io.cilium.k8s.policy."):
		return "", "", fmt.Errorf("Cilium identity selector %q is not supported", key)
	case strings.HasPrefix(key, "reserved:"):
		return "", "", fmt.Errorf("reserved Cilium selector %q is outside the pod graph", key)
	case strings.Contains(key, ":"):
		return "", "", fmt.Errorf("Cilium label source in selector key %q is not supported", key)
	default:
		return ciliumTargetPod, key, nil
	}
}

func ciliumIPBlock(cidr string, except []string) (netv1.IPBlock, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return netv1.IPBlock{}, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	block := netv1.IPBlock{CIDR: prefix.Masked().String()}
	for _, value := range except {
		excluded, parseErr := netip.ParsePrefix(value)
		if parseErr != nil {
			return netv1.IPBlock{}, fmt.Errorf("invalid excluded CIDR %q: %w", value, parseErr)
		}
		if excluded.Addr().BitLen() != prefix.Addr().BitLen() ||
			excluded.Bits() < prefix.Bits() || !prefix.Contains(excluded.Addr()) {
			return netv1.IPBlock{}, fmt.Errorf("excluded CIDR %q is not inside %q", value, cidr)
		}
		block.Except = append(block.Except, excluded.Masked().String())
	}
	return block, nil
}

// normalizeCiliumEntities maps Cilium entities onto graph peers. Entity names
// are case-sensitive; unknown names make Cilium reject the policy.
func normalizeCiliumEntities(entities []string) (peers []normalizedPeer, notes []string, errs []error) {
	empty := metav1.LabelSelector{}
	allPods := normalizedPeer{PodSelector: &empty, AllNamespaces: true}
	for _, entity := range entities {
		switch entity {
		case "cluster", "cluster-mesh":
			peers = append(peers, allPods)
		case "world":
			peers = append(peers, worldPeers()...)
		case "world-ipv4":
			peers = append(peers, normalizedPeer{IPBlocks: []netv1.IPBlock{{CIDR: allIPv4}}})
		case "world-ipv6":
			peers = append(peers, normalizedPeer{IPBlocks: []netv1.IPBlock{{CIDR: allIPv6}}})
		case "all":
			peers = append(peers, allPods)
			peers = append(peers, worldPeers()...)
		case "none":
		case "host", "init", "ingress", "unmanaged", "remote-node", "health", "kube-apiserver":
			notes = append(notes, fmt.Sprintf("Cilium entity %q is outside the pod/CIDR graph", entity))
		default:
			errs = append(errs, fmt.Errorf("unsupported entity: %s", entity))
		}
	}
	return peers, notes, errs
}

func worldPeers() []normalizedPeer {
	return []normalizedPeer{
		{IPBlocks: []netv1.IPBlock{{CIDR: allIPv4}}},
		{IPBlocks: []netv1.IPBlock{{CIDR: allIPv6}}},
	}
}

type ciliumPorts struct {
	ports    []netv1.NetworkPolicyPort
	noPorts  bool
	notes    []string
	warnings []string
	invalid  []error
}

func normalizeCiliumPorts(rules []ciliumPortRule, direction Direction) ciliumPorts {
	var result ciliumPorts
	allPorts := false
	l4Entries, otherEntries := 0, 0
	for index := range rules {
		rule := &rules[index]
		l7, err := ciliumL7Types(rule.Rules)
		if err != nil {
			result.invalid = append(result.invalid, err)
		}
		result.invalid = append(result.invalid, validateCiliumPortRule(rule, l7, direction)...)
		if len(l7) > 0 {
			result.notes = append(result.notes, "Cilium L7 rules are not rendered; reachability means at least one request can match")
			result.warnings = append(result.warnings, "Cilium L7 rules cannot be evaluated from the policy snapshot")
		}
		if len(rule.TerminatingTLS) > 0 || len(rule.OriginatingTLS) > 0 || len(rule.Listener) > 0 || len(rule.ServerNames) > 0 {
			result.notes = append(result.notes, "Cilium TLS, SNI, and listener constraints are not rendered")
			result.warnings = append(result.warnings, "Cilium TLS, SNI, and listener constraints cannot be evaluated from the policy snapshot")
		}
		if len(rule.Ports) == 0 {
			allPorts = true
			continue
		}
		dns := slices.Contains(l7, "dns")
		for _, port := range rule.Ports {
			converted, note, warning, err := ciliumPort(port, dns)
			switch {
			case err != nil:
				result.invalid = append(result.invalid, err)
				continue
			case note != "":
				result.notes = append(result.notes, note)
				otherEntries++
				continue
			case warning != "":
				result.warnings = append(result.warnings, warning)
			}
			l4Entries++
			result.ports = append(result.ports, converted...)
		}
	}
	if allPorts {
		result.ports = nil
	} else if l4Entries == 0 && otherEntries > 0 {
		result.noPorts = true
	}
	return result
}

// ciliumL7Types returns the non-empty L7 rule families of a port rule.
func ciliumL7Types(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == jsonNull {
		return nil, nil
	}
	var rules map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rules); err != nil {
		return nil, fmt.Errorf("invalid L7 rules: %w", err)
	}
	var families []string
	for _, family := range []string{"dns", "http", "kafka", "l7proto"} {
		value, ok := rules[family]
		if !ok || len(value) == 0 || string(value) == jsonNull || string(value) == "[]" || string(value) == `""` {
			continue
		}
		families = append(families, family)
	}
	if len(families) == 0 && len(rules) > 0 {
		families = append(families, "l7")
	}
	return families, nil
}

func validateCiliumPortRule(rule *ciliumPortRule, l7 []string, direction Direction) []error {
	var errs []error
	dns := slices.Contains(l7, "dns")
	if direction == Ingress && dns {
		errs = append(errs, errors.New("DNS rules are not allowed on ingress"))
	}
	if len(rule.ServerNames) > 0 && len(l7) > 0 && len(rule.TerminatingTLS) == 0 {
		errs = append(errs, errors.New("ServerNames are not allowed with L7 rules without TLS termination"))
	}
	if slices.Contains(rule.ServerNames, "") {
		errs = append(errs, errors.New("empty server name is not allowed"))
	}
	if len(l7) > 1 {
		errs = append(errs, errors.New("multiple L7 protocol rule types specified in single rule"))
	}
	if len(rule.Listener) > 0 && string(rule.Listener) != jsonNull {
		if direction == Ingress {
			errs = append(errs, errors.New("listener is not allowed on ingress"))
		}
		if len(l7) > 0 {
			errs = append(errs, errors.New("listener is not allowed with L7 rules"))
		}
	}
	if dns && len(rule.Ports) == 0 {
		errs = append(errs, errors.New("port 53 must be specified for DNS rules"))
	}
	if len(l7) == 0 {
		return errs
	}
	for _, port := range rule.Ports {
		if !ciliumIsSvcName(port.Port) {
			if number, err := strconv.ParseUint(port.Port, 0, 16); err == nil && number == 0 {
				errs = append(errs, errors.New("L7 rules can not be used when a port is 0"))
			}
		}
		if !dns && !strings.EqualFold(port.Protocol, string(corev1.ProtocolTCP)) {
			errs = append(errs, fmt.Errorf("L7 rules can only apply to TCP (not %s) except for DNS rules", port.Protocol))
		}
	}
	return errs
}

func ciliumIsSvcName(name string) bool {
	return name != "" && len(name) <= 15 && ciliumSvcName.MatchString(name)
}

// ciliumPort converts one Cilium port entry. A note reports entries outside
// the TCP/UDP/SCTP model; an error means Cilium rejects the policy.
func ciliumPort(source ciliumPortProtocol, dns bool) (ports []netv1.NetworkPolicyPort, note, warning string, err error) {
	protocol := strings.ToUpper(source.Protocol)
	var protocols []corev1.Protocol
	switch protocol {
	case "", "ANY":
		protocols = []corev1.Protocol{corev1.ProtocolTCP, corev1.ProtocolUDP, corev1.ProtocolSCTP}
	case "TCP", "UDP", "SCTP":
		protocols = []corev1.Protocol{corev1.Protocol(protocol)}
	case "ICMP", "ICMPV6":
		return nil, fmt.Sprintf("protocol %s is outside the graph's TCP/UDP/SCTP model", protocol), "", nil
	case "VRRP", "IGMP", "GRE", "IPIP", "IPV6", "ESP", "AH":
		if source.Port != "" && source.Port != "0" {
			return nil, "", "", fmt.Errorf("port must be empty or 0 for protocol %s", protocol)
		}
		return nil, fmt.Sprintf("protocol %s is outside the graph's TCP/UDP/SCTP model", protocol), "", nil
	default:
		return nil, "", "", fmt.Errorf("invalid protocol %q", source.Protocol)
	}
	if source.Port == "" {
		return nil, "", "", errors.New("port must be specified")
	}
	if source.EndPort < 0 || source.EndPort > 65535 {
		return nil, "", "", fmt.Errorf("endPort %d is outside 0-65535", source.EndPort)
	}
	var value *intstr.IntOrString
	var end *int32
	if ciliumIsSvcName(source.Port) {
		named := intstr.FromString(strings.ToLower(source.Port))
		value = &named
		if source.EndPort != 0 {
			warning = fmt.Sprintf("named port %q with endPort %d cannot be evaluated exactly", source.Port, source.EndPort)
		}
	} else {
		number, parseErr := strconv.ParseUint(source.Port, 0, 16)
		if parseErr != nil {
			return nil, "", "", fmt.Errorf("unable to parse port %q: %w", source.Port, parseErr)
		}
		if dns && source.EndPort > int32(number) {
			return nil, "", "", errors.New("DNS rules do not support port ranges")
		}
		if number != 0 {
			numeric := intstr.FromInt32(int32(number))
			value = &numeric
			if source.EndPort > int32(number) {
				endPort := source.EndPort
				end = &endPort
			}
		}
	}
	ports = make([]netv1.NetworkPolicyPort, 0, len(protocols))
	for _, protocol := range protocols {
		item := netv1.NetworkPolicyPort{Protocol: &protocol, Port: clonePort(value), EndPort: cloneInt32(end)}
		ports = append(ports, item)
	}
	return ports, "", warning, nil
}
