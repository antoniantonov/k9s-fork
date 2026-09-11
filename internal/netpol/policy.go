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
	"sigs.k8s.io/yaml"
)

type policyLayer uint8

const (
	policyLayerNetwork policyLayer = iota
	policyLayerAuthorization
)

type normalizedSelector struct {
	Pod            metav1.LabelSelector
	Namespace      *metav1.LabelSelector
	ServiceAccount *metav1.LabelSelector
}

type normalizedPolicy struct {
	metav1.ObjectMeta
	Type          PolicyType
	Version       string
	SpecIndex     int
	ClusterScoped bool
	Layer         policyLayer
	Selector      normalizedSelector
	Ingress       normalizedDirection
	Egress        normalizedDirection
	PolicyTypes   []netv1.PolicyType
	Notes         []string
	Disabled      bool
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
	TCPOnly     bool
	MatchNone   bool
	Disabled    bool
	YAML        string
	Notes       []string
	Warnings    []string
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
	RequestPrincipals      []string
	NotRequestPrincipals   []string
	TrustDomains           []string
	NotTrustDomains        []string
}

func (p *normalizedPolicy) direction(direction Direction) *normalizedDirection {
	if direction == Egress {
		return &p.Egress
	}
	return &p.Ingress
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

func normalizeSnapshotPolicies(snapshot *Snapshot) ([]normalizedPolicy, map[string]error) {
	policies := make([]normalizedPolicy, 0, len(snapshot.NetworkPolicies))
	for index := range snapshot.NetworkPolicies {
		policies = append(policies, normalizeNetworkPolicy(&snapshot.NetworkPolicies[index]))
	}

	failures := make(map[string][]error)
	appendResources := func(resource string, objects []unstructured.Unstructured, policyType PolicyType) {
		for index := range objects {
			normalized, errs := normalizeCustomPolicy(&objects[index], policyType, snapshot.IstioRootNamespace)
			policies = append(policies, normalized...)
			for _, err := range errs {
				failures[resource] = append(failures[resource], fmt.Errorf("%s: %w", objectIdentity(&objects[index]), err))
			}
		}
	}
	appendResources("ciliumnetworkpolicies", snapshot.CiliumNetworkPolicies, PolicyTypeCiliumNetworkPolicy)
	appendResources("ciliumclusterwidenetworkpolicies", snapshot.CiliumClusterwideNetworkPolicies, PolicyTypeCiliumClusterwideNetworkPolicy)
	appendResources("authorizationpolicies", snapshot.IstioAuthorizationPolicies, PolicyTypeIstioAuthorizationPolicy)

	joined := make(map[string]error, len(failures))
	for resource, errs := range failures {
		joined[resource] = errors.Join(errs...)
	}
	return policies, joined
}

func normalizeNetworkPolicy(policy *netv1.NetworkPolicy) normalizedPolicy {
	normalized := normalizedPolicy{
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

func normalizeCustomPolicy(
	object *unstructured.Unstructured,
	policyType PolicyType,
	istioRootNamespace string,
) ([]normalizedPolicy, []error) {
	switch policyType {
	case PolicyTypeCiliumNetworkPolicy, PolicyTypeCiliumClusterwideNetworkPolicy:
		return normalizeCiliumPolicy(object, policyType)
	case PolicyTypeIstioAuthorizationPolicy:
		return normalizeIstioPolicy(object, istioRootNamespace)
	default:
		return nil, []error{fmt.Errorf("unsupported policy type %q", policyType)}
	}
}

func objectIdentity(object *unstructured.Unstructured) string {
	if object.GetNamespace() == "" {
		return object.GetName()
	}
	return object.GetNamespace() + "/" + object.GetName()
}

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
	Authentication json.RawMessage          `json:"authentication,omitempty"`
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

func normalizeCiliumPolicy(object *unstructured.Unstructured, policyType PolicyType) ([]normalizedPolicy, []error) {
	var resource ciliumPolicyResource
	if err := decodeUnstructured(object, &resource); err != nil {
		return nil, []error{err}
	}
	if resource.APIVersion == "" {
		resource.APIVersion = "cilium.io/v2"
	}
	var specs []ciliumPolicyRule
	if resource.Spec != nil {
		specs = append(specs, *resource.Spec)
	}
	specs = append(specs, resource.Specs...)
	if len(specs) == 0 {
		return nil, []error{errors.New("spec or specs must contain a policy rule")}
	}

	var policies []normalizedPolicy
	var allErrs []error
	for specIndex := range specs {
		policy, errs := normalizeCiliumPolicyRule(&resource, policyType, specIndex, &specs[specIndex])
		policies = append(policies, policy)
		allErrs = append(allErrs, errs...)
	}
	return policies, allErrs
}

func normalizeCiliumPolicyRule(
	resource *ciliumPolicyResource,
	policyType PolicyType,
	specIndex int,
	spec *ciliumPolicyRule,
) (normalizedPolicy, []error) {
	clusterScoped := policyType == PolicyTypeCiliumClusterwideNetworkPolicy
	policy := normalizedPolicy{
		ObjectMeta:    *resource.Metadata.DeepCopy(),
		Type:          policyType,
		Version:       resource.APIVersion,
		SpecIndex:     specIndex,
		ClusterScoped: clusterScoped,
		Layer:         policyLayerNetwork,
	}
	var errs []error
	if spec.NodeSelector != nil {
		policy.Disabled = true
		errs = append(errs, errors.New("nodeSelector policies are outside the pod reachability graph"))
	}
	if spec.EndpointSelector == nil {
		policy.Disabled = true
		errs = append(errs, errors.New("endpointSelector is required for pod reachability"))
	} else {
		selector, selectorErrs := normalizeCiliumSelector(spec.EndpointSelector, policy.Namespace, clusterScoped, true)
		policy.Selector = selector
		errs = append(errs, selectorErrs...)
		if len(selectorErrs) > 0 {
			policy.Disabled = true
		}
	}

	policy.Ingress.Isolate = ciliumDirectionIsolates(
		spec.EnableDefaultDeny.Ingress,
		len(spec.Ingress) > 0 || len(spec.IngressDeny) > 0,
	)
	policy.Egress.Isolate = ciliumDirectionIsolates(
		spec.EnableDefaultDeny.Egress,
		len(spec.Egress) > 0 || len(spec.EgressDeny) > 0,
	)
	policy.Ingress.Rules, errs = appendCiliumRules(
		policy.Ingress.Rules, errs, &policy, Ingress, PolicyActionAllow, spec.Ingress,
	)
	policy.Ingress.Rules, errs = appendCiliumRules(
		policy.Ingress.Rules, errs, &policy, Ingress, PolicyActionDeny, spec.IngressDeny,
	)
	policy.Egress.Rules, errs = appendCiliumRules(
		policy.Egress.Rules, errs, &policy, Egress, PolicyActionAllow, spec.Egress,
	)
	policy.Egress.Rules, errs = appendCiliumRules(
		policy.Egress.Rules, errs, &policy, Egress, PolicyActionDeny, spec.EgressDeny,
	)
	return policy, errs
}

func ciliumDirectionIsolates(configured *bool, hasRules bool) bool {
	if configured != nil {
		return *configured
	}
	return hasRules
}

func appendCiliumRules(
	out []normalizedRule,
	errs []error,
	policy *normalizedPolicy,
	direction Direction,
	action PolicyAction,
	rules []ciliumTrafficRule,
) ([]normalizedRule, []error) {
	for index := range rules {
		rule, ruleErrs := normalizeCiliumTrafficRule(policy, direction, action, index, &rules[index])
		out = append(out, rule)
		for _, err := range ruleErrs {
			errs = append(errs, fmt.Errorf("%s %s rule %d: %w", strings.ToLower(direction.String()), action, index, err))
		}
	}
	return out, errs
}

func normalizeCiliumTrafficRule(
	policy *normalizedPolicy,
	direction Direction,
	action PolicyAction,
	index int,
	source *ciliumTrafficRule,
) (normalizedRule, []error) {
	rule := normalizedRule{
		Index:  index,
		Action: action,
		YAML:   marshalPolicyRule(source),
	}
	var errs []error
	endpoints, cidrs, cidrSets, entities := source.FromEndpoints, source.FromCIDR, source.FromCIDRSet, source.FromEntities
	unsupportedGroups, unsupportedNodes := source.FromGroups, source.FromNodes
	if direction == Egress {
		endpoints, cidrs, cidrSets, entities = source.ToEndpoints, source.ToCIDR, source.ToCIDRSet, source.ToEntities
		unsupportedGroups, unsupportedNodes = source.ToGroups, source.ToNodes
	}

	families := 0
	if endpoints != nil {
		families++
		if len(endpoints) == 0 {
			rule.MatchNone = true
		}
		for endpointIndex := range endpoints {
			selector, selectorErrs := normalizeCiliumSelector(
				&endpoints[endpointIndex], policy.Namespace, policy.ClusterScoped, false,
			)
			errs = append(errs, selectorErrs...)
			peer := normalizedPeer{
				PodSelector:            selector.Pod.DeepCopy(),
				NamespaceSelector:      selector.Namespace.DeepCopy(),
				ServiceAccountSelector: selector.ServiceAccount.DeepCopy(),
				AllNamespaces:          selector.Namespace != nil || policy.ClusterScoped,
			}
			rule.Peers = append(rule.Peers, peer)
		}
	}
	if cidrs != nil || cidrSets != nil {
		families++
		for _, cidr := range cidrs {
			block, err := ciliumIPBlock(cidr, nil)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			rule.Peers = append(rule.Peers, normalizedPeer{IPBlocks: []netv1.IPBlock{block}})
		}
		for _, cidrRule := range cidrSets {
			if cidrRule.CIDRGroupRef != "" || cidrRule.CIDRGroupSelector != nil {
				errs = append(errs, errors.New("CIDR group references require runtime Cilium resolution"))
				rule.Disabled = true
				continue
			}
			block, err := ciliumIPBlock(cidrRule.CIDR, cidrRule.Except)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			rule.Peers = append(rule.Peers, normalizedPeer{IPBlocks: []netv1.IPBlock{block}})
		}
	}
	if entities != nil {
		families++
		entityPeers, notes := normalizeCiliumEntities(entities)
		rule.Peers = append(rule.Peers, entityPeers...)
		rule.Notes = append(rule.Notes, notes...)
		if len(entityPeers) == 0 {
			rule.MatchNone = true
		}
	}
	if families > 1 {
		errs = append(errs, errors.New("multiple mutually exclusive peer families are set"))
		rule.Disabled = true
	}

	switch {
	case len(source.FromRequires) > 0 || len(source.ToRequires) > 0:
		errs = append(errs, errors.New("fromRequires/toRequires identity constraints are not supported"))
		rule.Disabled = true
	case len(unsupportedGroups) > 0:
		errs = append(errs, errors.New("cloud-provider groups require runtime Cilium resolution"))
		rule.Disabled = true
	case len(unsupportedNodes) > 0:
		rule.Notes = append(rule.Notes, "node peers are outside the pod reachability graph")
		if families == 0 {
			rule.MatchNone = true
		}
	case len(source.ToServices) > 0:
		errs = append(errs, errors.New("toServices requires live Service endpoint resolution"))
		rule.Disabled = true
	case len(source.ToFQDNs) > 0:
		errs = append(errs, errors.New("toFQDNs requires live DNS resolution"))
		rule.Disabled = true
	case len(source.ICMPs) > 0:
		errs = append(errs, errors.New("ICMP rules cannot be represented by the graph's L4 port model"))
		rule.Disabled = true
	}

	ports, notes, portErrs, invalid := normalizeCiliumPorts(source.ToPorts)
	rule.Ports = ports
	rule.Notes = append(rule.Notes, notes...)
	errs = append(errs, portErrs...)
	rule.Disabled = rule.Disabled || invalid
	if len(source.Authentication) > 0 && string(source.Authentication) != "null" {
		rule.Notes = append(rule.Notes, "Cilium authentication requirements are not represented; reachability is existential")
	}
	rule.PeerStrings = normalizedPeerStrings(rule.Peers, rule.MatchNone)
	rule.Notes = uniqueStrings(rule.Notes)
	rule.Warnings = errorStrings(errs)
	return rule, errs
}

func normalizeCiliumSelector(
	source *ciliumEndpointSelector,
	policyNamespace string,
	clusterScoped, subject bool,
) (normalizedSelector, []error) {
	selector := normalizedSelector{
		Pod: metav1.LabelSelector{MatchLabels: map[string]string{}},
	}
	namespace := metav1.LabelSelector{MatchLabels: map[string]string{}}
	serviceAccount := metav1.LabelSelector{MatchLabels: map[string]string{}}
	var errs []error
	namespaceConstrained := false
	serviceAccountConstrained := false
	for key, value := range source.MatchLabels {
		target, normalizedKey, err := ciliumSelectorKey(key)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		switch target {
		case "namespace":
			namespace.MatchLabels[normalizedKey] = value
			namespaceConstrained = true
		case "serviceaccount":
			serviceAccount.MatchLabels[normalizedKey] = value
			serviceAccountConstrained = true
		default:
			selector.Pod.MatchLabels[normalizedKey] = value
		}
	}
	for _, requirement := range source.MatchExpressions {
		target, normalizedKey, err := ciliumSelectorKey(requirement.Key)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		requirement.Key = normalizedKey
		requirement.Values = slices.Clone(requirement.Values)
		switch target {
		case "namespace":
			namespace.MatchExpressions = append(namespace.MatchExpressions, requirement)
			namespaceConstrained = true
		case "serviceaccount":
			serviceAccount.MatchExpressions = append(serviceAccount.MatchExpressions, requirement)
			serviceAccountConstrained = true
		default:
			selector.Pod.MatchExpressions = append(selector.Pod.MatchExpressions, requirement)
		}
	}
	if !clusterScoped && (subject || !namespaceConstrained) {
		namespace.MatchLabels["kubernetes.io/metadata.name"] = policyNamespace
		namespaceConstrained = true
	}
	if namespaceConstrained {
		selector.Namespace = &namespace
	}
	if serviceAccountConstrained {
		selector.ServiceAccount = &serviceAccount
	}
	if _, err := metav1.LabelSelectorAsSelector(&selector.Pod); err != nil {
		errs = append(errs, fmt.Errorf("invalid endpoint pod selector: %w", err))
	}
	if selector.Namespace != nil {
		if _, err := metav1.LabelSelectorAsSelector(selector.Namespace); err != nil {
			errs = append(errs, fmt.Errorf("invalid endpoint namespace selector: %w", err))
		}
	}
	if selector.ServiceAccount != nil {
		if _, err := metav1.LabelSelectorAsSelector(selector.ServiceAccount); err != nil {
			errs = append(errs, fmt.Errorf("invalid endpoint service account selector: %w", err))
		}
	}
	return selector, errs
}

func ciliumSelectorKey(key string) (target, normalized string, err error) {
	key = strings.TrimPrefix(key, "k8s:")
	key = strings.TrimPrefix(key, "any:")
	switch {
	case key == "io.kubernetes.pod.namespace":
		return "namespace", "kubernetes.io/metadata.name", nil
	case strings.HasPrefix(key, "io.cilium.k8s.namespace.labels."):
		return "namespace", strings.TrimPrefix(key, "io.cilium.k8s.namespace.labels."), nil
	case key == "io.cilium.k8s.policy.serviceaccount":
		return "serviceaccount", "name", nil
	case key == "io.cilium.k8s.policy.cluster":
		return "", "", errors.New("Cilium cluster identity selectors require the local cluster name")
	case strings.HasPrefix(key, "io.cilium.k8s.policy."):
		return "", "", fmt.Errorf("Cilium identity selector %q is not supported", key)
	case strings.HasPrefix(key, "reserved:"):
		return "", "", fmt.Errorf("reserved Cilium selector %q is outside the pod graph", key)
	case strings.Contains(key, ":"):
		return "", "", fmt.Errorf("Cilium label source in selector key %q is not supported", key)
	default:
		return "pod", key, nil
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
		if excluded.Addr().BitLen() != prefix.Addr().BitLen() || !prefix.Contains(excluded.Addr()) {
			return netv1.IPBlock{}, fmt.Errorf("excluded CIDR %q is not inside %q", value, cidr)
		}
		block.Except = append(block.Except, excluded.Masked().String())
	}
	return block, nil
}

func normalizeCiliumEntities(entities []string) ([]normalizedPeer, []string) {
	var peers []normalizedPeer
	var notes []string
	empty := metav1.LabelSelector{}
	for _, entity := range entities {
		switch strings.ToLower(entity) {
		case "cluster", "cluster-mesh":
			peers = append(peers, normalizedPeer{PodSelector: &empty, AllNamespaces: true})
		case "world":
			peers = append(peers, worldPeers()...)
		case "all":
			peers = append(peers, normalizedPeer{PodSelector: &empty, AllNamespaces: true})
			peers = append(peers, worldPeers()...)
		case "none":
		default:
			notes = append(notes, fmt.Sprintf("Cilium entity %q is outside the pod/CIDR graph", entity))
		}
	}
	return peers, notes
}

func worldPeers() []normalizedPeer {
	return []normalizedPeer{
		{IPBlocks: []netv1.IPBlock{{CIDR: "0.0.0.0/0"}}},
		{IPBlocks: []netv1.IPBlock{{CIDR: "::/0"}}},
	}
}

func normalizeCiliumPorts(rules []ciliumPortRule) (
	[]netv1.NetworkPolicyPort,
	[]string,
	[]error,
	bool,
) {
	var ports []netv1.NetworkPolicyPort
	var notes []string
	var errs []error
	for _, rule := range rules {
		if len(rule.Rules) > 0 && string(rule.Rules) != "null" {
			notes = append(notes, "Cilium L7 rules are not rendered; reachability means at least one request can match")
		}
		if len(rule.TerminatingTLS) > 0 || len(rule.OriginatingTLS) > 0 || len(rule.Listener) > 0 || len(rule.ServerNames) > 0 {
			notes = append(notes, "Cilium TLS, SNI, and listener constraints are not rendered")
		}
		if len(rule.Ports) == 0 {
			return nil, uniqueStrings(notes), errs, false
		}
		for _, port := range rule.Ports {
			converted, err := ciliumPort(port)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			ports = append(ports, converted...)
		}
	}
	return ports, uniqueStrings(notes), errs, len(errs) > 0 && len(ports) == 0
}

func ciliumPort(source ciliumPortProtocol) ([]netv1.NetworkPolicyPort, error) {
	var value intstr.IntOrString
	if number, err := strconv.ParseInt(source.Port, 10, 32); err == nil {
		if number < 1 || number > 65535 {
			return nil, fmt.Errorf("port %q is outside 1-65535", source.Port)
		}
		value = intstr.FromInt32(int32(number))
	} else {
		if source.Port == "" {
			return nil, errors.New("Cilium port must not be empty")
		}
		if source.EndPort != 0 {
			return nil, fmt.Errorf("named port %q cannot have endPort", source.Port)
		}
		value = intstr.FromString(source.Port)
	}
	if source.EndPort != 0 && (source.EndPort < value.IntVal || source.EndPort > 65535) {
		return nil, fmt.Errorf("endPort %d is outside the port range", source.EndPort)
	}

	protocols := []corev1.Protocol{corev1.ProtocolTCP, corev1.ProtocolUDP, corev1.ProtocolSCTP}
	switch strings.ToUpper(source.Protocol) {
	case "", "ANY":
	case "TCP":
		protocols = []corev1.Protocol{corev1.ProtocolTCP}
	case "UDP":
		protocols = []corev1.Protocol{corev1.ProtocolUDP}
	case "SCTP":
		protocols = []corev1.Protocol{corev1.ProtocolSCTP}
	default:
		return nil, fmt.Errorf("protocol %q is not supported by the graph's transport model", source.Protocol)
	}
	out := make([]netv1.NetworkPolicyPort, 0, len(protocols))
	for _, protocol := range protocols {
		proto, port := protocol, value
		item := netv1.NetworkPolicyPort{Protocol: &proto, Port: &port}
		if source.EndPort != 0 {
			end := source.EndPort
			item.EndPort = &end
		}
		out = append(out, item)
	}
	return out, nil
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

func normalizeIstioPolicy(object *unstructured.Unstructured, rootNamespace string) ([]normalizedPolicy, []error) {
	var resource istioPolicyResource
	if err := decodeUnstructured(object, &resource); err != nil {
		return nil, []error{err}
	}
	if strings.EqualFold(resource.Metadata.Annotations["istio.io/dry-run"], "true") {
		return nil, nil
	}
	if resource.APIVersion == "" {
		resource.APIVersion = "security.istio.io/v1"
	}
	action := strings.ToUpper(resource.Spec.Action)
	if action == "" {
		action = "ALLOW"
	}
	if action == "AUDIT" {
		return nil, nil
	}
	if rootNamespace == "" {
		rootNamespace = DefaultIstioRootNamespace
	}

	policy := normalizedPolicy{
		ObjectMeta: *resource.Metadata.DeepCopy(),
		Type:       PolicyTypeIstioAuthorizationPolicy,
		Version:    resource.APIVersion,
		Layer:      policyLayerAuthorization,
		Notes:      []string{"Istio principal and trust-domain matching assumes cluster.local"},
	}
	if resource.Spec.Selector != nil {
		policy.Selector.Pod.MatchLabels = mapsClone(resource.Spec.Selector.MatchLabels)
	}
	if policy.Namespace == rootNamespace {
		policy.ClusterScoped = true
		policy.Notes = append(policy.Notes, fmt.Sprintf(
			"policy is treated as mesh-wide because %s is the resolved Istio root namespace",
			rootNamespace,
		))
	}

	var errs []error
	if len(resource.Spec.TargetRef) > 0 || len(resource.Spec.TargetRefs) > 0 {
		policy.Disabled = true
		errs = append(errs, errors.New("targetRefs cannot be resolved to pods from the policy snapshot"))
	}
	if action == "CUSTOM" {
		policy.Disabled = true
		errs = append(errs, errors.New("CUSTOM authorization depends on an external provider"))
	}
	if action != "ALLOW" && action != "DENY" && action != "CUSTOM" {
		policy.Disabled = true
		errs = append(errs, fmt.Errorf("unsupported Istio action %q", action))
	}
	policy.Ingress.Isolate = action == "ALLOW"
	ruleAction := PolicyActionAllow
	if action == "DENY" {
		ruleAction = PolicyActionDeny
	}
	for index := range resource.Spec.Rules {
		rule, ruleErrs := normalizeIstioRule(&policy, index, ruleAction, &resource.Spec.Rules[index])
		policy.Ingress.Rules = append(policy.Ingress.Rules, rule)
		for _, err := range ruleErrs {
			errs = append(errs, fmt.Errorf("ingress %s rule %d: %w", ruleAction, index, err))
		}
	}
	return []normalizedPolicy{policy}, errs
}

func normalizeIstioRule(
	policy *normalizedPolicy,
	index int,
	action PolicyAction,
	source *istioRule,
) (normalizedRule, []error) {
	rule := normalizedRule{
		Index:   index,
		Action:  action,
		TCPOnly: true,
		YAML:    marshalPolicyRule(source),
	}
	var errs []error
	for _, from := range source.From {
		peer, peerErrs, invalid := normalizeIstioSource(policy.Namespace, &from.Source)
		rule.Peers = append(rule.Peers, peer)
		errs = append(errs, peerErrs...)
		rule.Disabled = rule.Disabled || invalid
	}
	ports, notes, portErrs, invalid := normalizeIstioOperations(source.To)
	rule.Ports = ports
	rule.Notes = append(rule.Notes, notes...)
	errs = append(errs, portErrs...)
	rule.Disabled = rule.Disabled || invalid
	if len(source.When) > 0 {
		errs = append(errs, errors.New("Istio when conditions cannot be evaluated from the policy snapshot"))
		rule.Disabled = true
	}
	if action == PolicyActionDeny && istioRuleHasUnmodeledPredicates(source) {
		errs = append(errs, errors.New("DENY has unmodeled L7 predicates; its ports are not subtracted"))
		rule.Disabled = true
	}
	rule.PeerStrings = normalizedPeerStrings(rule.Peers, false)
	rule.Notes = uniqueStrings(append(rule.Notes, policy.Notes...))
	rule.Warnings = errorStrings(errs)
	return rule, errs
}

func istioRuleHasUnmodeledPredicates(rule *istioRule) bool {
	for _, item := range rule.To {
		operation := item.Operation
		if len(operation.Hosts)+len(operation.NotHosts)+len(operation.Methods)+
			len(operation.NotMethods)+len(operation.Paths)+len(operation.NotPaths) > 0 {
			return true
		}
	}
	return false
}

func normalizeIstioSource(policyNamespace string, source *istioSource) (normalizedPeer, []error, bool) {
	peer := normalizedPeer{
		AllNamespaces:        true,
		Namespaces:           slices.Clone(source.Namespaces),
		NotNamespaces:        slices.Clone(source.NotNamespaces),
		ServiceAccounts:      normalizeServiceAccounts(policyNamespace, source.ServiceAccounts),
		NotServiceAccounts:   normalizeServiceAccounts(policyNamespace, source.NotServiceAccounts),
		Principals:           slices.Clone(source.Principals),
		NotPrincipals:        slices.Clone(source.NotPrincipals),
		RequestPrincipals:    slices.Clone(source.RequestPrincipals),
		NotRequestPrincipals: slices.Clone(source.NotRequestPrincipals),
		TrustDomains:         slices.Clone(source.TrustDomains),
		NotTrustDomains:      slices.Clone(source.NotTrustDomains),
		MatchPodIPs:          len(source.IPBlocks) > 0,
	}
	var errs []error
	invalid := false
	for _, value := range source.IPBlocks {
		block, err := istioIPBlock(value)
		if err != nil {
			errs = append(errs, err)
			invalid = true
			continue
		}
		peer.IPBlocks = append(peer.IPBlocks, block)
	}
	if len(source.NotIPBlocks) > 0 {
		errs = append(errs, errors.New("notIpBlocks cannot be represented without CIDR subtraction"))
		invalid = true
	}
	if len(source.RemoteIPBlocks) > 0 || len(source.NotRemoteIPBlocks) > 0 {
		errs = append(errs, errors.New("remoteIpBlocks depend on proxy forwarding configuration"))
		invalid = true
	}
	if len(source.RequestPrincipals) > 0 || len(source.NotRequestPrincipals) > 0 {
		errs = append(errs, errors.New("requestPrincipals depend on JWT request identity"))
		invalid = true
	}
	if istioSourceHasPeerIdentityConstraints(source) {
		errs = append(errs, errors.New(
			"Istio peer identity constraints assume mTLS identity is available and use the default cluster.local trust domain",
		))
	}
	if len(peer.IPBlocks) > 0 && istioSourceHasIdentityConstraints(source) {
		peer.CIDRMatchUnsupported = true
		errs = append(errs, errors.New("CIDR applicability cannot prove identity constraints ANDed with ipBlocks"))
	}
	return peer, errs, invalid
}

func istioSourceHasIdentityConstraints(source *istioSource) bool {
	return len(source.Principals)+len(source.NotPrincipals)+
		len(source.RequestPrincipals)+len(source.NotRequestPrincipals)+
		len(source.Namespaces)+len(source.NotNamespaces)+
		len(source.ServiceAccounts)+len(source.NotServiceAccounts)+
		len(source.TrustDomains)+len(source.NotTrustDomains) > 0
}

func istioSourceHasPeerIdentityConstraints(source *istioSource) bool {
	return len(source.Principals)+len(source.NotPrincipals)+
		len(source.Namespaces)+len(source.NotNamespaces)+
		len(source.ServiceAccounts)+len(source.NotServiceAccounts)+
		len(source.TrustDomains)+len(source.NotTrustDomains) > 0
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

func normalizeIstioOperations(operations []istioTo) (
	[]netv1.NetworkPolicyPort,
	[]string,
	[]error,
	bool,
) {
	if len(operations) == 0 {
		return nil, nil, nil, false
	}
	var ports []netv1.NetworkPolicyPort
	var notes []string
	var errs []error
	allPorts := false
	for _, item := range operations {
		operation := item.Operation
		if len(operation.NotPorts) > 0 {
			errs = append(errs, errors.New("notPorts cannot be represented without port subtraction"))
			continue
		}
		if len(operation.Hosts)+len(operation.NotHosts)+len(operation.Methods)+len(operation.NotMethods)+len(operation.Paths)+len(operation.NotPaths) > 0 {
			notes = append(notes, "Istio L7 operation constraints are not rendered; reachability means at least one request can match")
		}
		if len(operation.Ports) == 0 {
			allPorts = true
			continue
		}
		for _, value := range operation.Ports {
			if value == "*" {
				allPorts = true
				continue
			}
			number, err := strconv.ParseInt(value, 10, 32)
			if err != nil || number < 1 || number > 65535 {
				errs = append(errs, fmt.Errorf("Istio port %q is not a number in 1-65535", value))
				continue
			}
			protocol := corev1.ProtocolTCP
			port := intstr.FromInt32(int32(number))
			ports = append(ports, netv1.NetworkPolicyPort{Protocol: &protocol, Port: &port})
		}
	}
	if allPorts {
		ports = nil
	}
	return ports, uniqueStrings(notes), errs, len(errs) > 0 && !allPorts && len(ports) == 0
}

func istioIPBlock(value string) (netv1.IPBlock, error) {
	if address, err := netip.ParseAddr(value); err == nil {
		bits := 32
		if address.Is6() {
			bits = 128
		}
		return netv1.IPBlock{CIDR: netip.PrefixFrom(address, bits).String()}, nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netv1.IPBlock{}, fmt.Errorf("invalid Istio IP block %q: %w", value, err)
	}
	return netv1.IPBlock{CIDR: prefix.Masked().String()}, nil
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

func normalizedPolicySelectsPod(policy *normalizedPolicy, pod *corev1.Pod, namespace *corev1.Namespace) bool {
	if policy.Disabled {
		return false
	}
	if !policy.ClusterScoped && policy.Namespace != pod.Namespace {
		return false
	}
	if !matchesSelector(policy.Selector.Pod, pod.Labels) {
		return false
	}
	if policy.Selector.Namespace != nil &&
		!matchesSelector(*policy.Selector.Namespace, namespaceLabels(namespace, pod.Namespace)) {
		return false
	}
	return policy.Selector.ServiceAccount == nil ||
		matchesSelector(*policy.Selector.ServiceAccount, serviceAccountLabels(pod))
}

func normalizedRulePeersMatch(
	rule *normalizedRule,
	policyNamespace string,
	pod *corev1.Pod,
	namespace *corev1.Namespace,
) (bool, int) {
	if rule.Disabled || rule.MatchNone {
		return false, -1
	}
	if len(rule.Peers) == 0 {
		return true, -1
	}
	for index := range rule.Peers {
		if normalizedPeerMatchesPod(&rule.Peers[index], policyNamespace, pod, namespace) {
			return true, index
		}
	}
	return false, -1
}

func normalizedPeerMatchesPod(
	peer *normalizedPeer,
	policyNamespace string,
	pod *corev1.Pod,
	namespace *corev1.Namespace,
) bool {
	if len(peer.IPBlocks) > 0 {
		if !peer.MatchPodIPs || !podMatchesIPBlocks(pod, peer.IPBlocks) {
			return false
		}
	}
	if !peer.AllNamespaces && peer.NamespaceSelector == nil && pod.Namespace != policyNamespace {
		return false
	}
	if peer.NamespaceSelector != nil && !matchesSelector(*peer.NamespaceSelector, namespaceLabels(namespace, pod.Namespace)) {
		return false
	}
	if peer.PodSelector != nil && !matchesSelector(*peer.PodSelector, pod.Labels) {
		return false
	}
	if peer.ServiceAccountSelector != nil &&
		!matchesSelector(*peer.ServiceAccountSelector, serviceAccountLabels(pod)) {
		return false
	}
	if !matchesPatterns(pod.Namespace, peer.Namespaces) || matchesAnyPattern(pod.Namespace, peer.NotNamespaces) {
		return false
	}
	serviceAccount := pod.Spec.ServiceAccountName
	if serviceAccount == "" {
		serviceAccount = "default"
	}
	qualifiedServiceAccount := pod.Namespace + "/" + serviceAccount
	if !matchesPatterns(qualifiedServiceAccount, peer.ServiceAccounts) ||
		matchesAnyPattern(qualifiedServiceAccount, peer.NotServiceAccounts) {
		return false
	}
	principal := "cluster.local/ns/" + pod.Namespace + "/sa/" + serviceAccount
	if !matchesPatterns(principal, peer.Principals) || matchesAnyPattern(principal, peer.NotPrincipals) {
		return false
	}
	if !matchesPatterns("cluster.local", peer.TrustDomains) ||
		matchesAnyPattern("cluster.local", peer.NotTrustDomains) {
		return false
	}
	return len(peer.RequestPrincipals) == 0 && len(peer.NotRequestPrincipals) == 0
}

func normalizedRuleMatchesCIDR(rule *normalizedRule, ref *PrimitiveRef) (bool, int) {
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
	return peer.PodSelector == nil &&
		peer.NamespaceSelector == nil &&
		peer.ServiceAccountSelector == nil &&
		len(peer.Namespaces) == 0 &&
		len(peer.NotNamespaces) == 0 &&
		len(peer.ServiceAccounts) == 0 &&
		len(peer.NotServiceAccounts) == 0 &&
		len(peer.Principals) == 0 &&
		len(peer.NotPrincipals) == 0 &&
		len(peer.TrustDomains) == 0 &&
		len(peer.NotTrustDomains) == 0
}

func podMatchesIPBlocks(pod *corev1.Pod, blocks []netv1.IPBlock) bool {
	var values []string
	if pod.Status.PodIP != "" {
		values = append(values, pod.Status.PodIP)
	}
	for _, item := range pod.Status.PodIPs {
		values = append(values, item.IP)
	}
	for _, value := range uniqueStrings(values) {
		address, err := netip.ParseAddr(value)
		if err != nil {
			continue
		}
		for index := range blocks {
			if ipBlockContainsAddress(&blocks[index], address) {
				return true
			}
		}
	}
	return false
}

func ipBlockContainsAddress(block *netv1.IPBlock, address netip.Addr) bool {
	prefix, err := netip.ParsePrefix(block.CIDR)
	if err != nil || !prefix.Contains(address) {
		return false
	}
	for _, value := range block.Except {
		excluded, parseErr := netip.ParsePrefix(value)
		if parseErr == nil && excluded.Contains(address) {
			return false
		}
	}
	return true
}

func namespaceLabels(namespace *corev1.Namespace, name string) map[string]string {
	labels := map[string]string{"kubernetes.io/metadata.name": name}
	if namespace == nil {
		return labels
	}
	for key, value := range namespace.Labels {
		labels[key] = value
	}
	return labels
}

func serviceAccountLabels(pod *corev1.Pod) map[string]string {
	name := pod.Spec.ServiceAccountName
	if name == "" {
		name = "default"
	}
	return map[string]string{"name": name}
}

func matchesPatterns(value string, patterns []string) bool {
	return len(patterns) == 0 || matchesAnyPattern(value, patterns)
}

func matchesAnyPattern(value string, patterns []string) bool {
	for _, pattern := range patterns {
		switch {
		case pattern == "*":
			return value != ""
		case strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") && len(pattern) > 2:
			return strings.Contains(value, strings.Trim(pattern, "*"))
		case strings.HasPrefix(pattern, "*"):
			return strings.HasSuffix(value, strings.TrimPrefix(pattern, "*"))
		case strings.HasSuffix(pattern, "*"):
			return strings.HasPrefix(value, strings.TrimSuffix(pattern, "*"))
		case value == pattern:
			return true
		}
	}
	return false
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
