// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

type engine struct{}

const (
	syntheticDefaultDeny  = "default-deny"
	syntheticUnrestricted = "unrestricted"
)

// NewEvaluator returns a stateless NetworkPolicy evaluator.
func NewEvaluator() Evaluator {
	return &engine{}
}

//nolint:gocritic // Snapshot is part of the public Evaluator contract.
func (e *engine) EvaluateSubject(ref SubjectRef, snapshot Snapshot, options Options) (SubjectResult, error) {
	x := newSnapshotIndex(&snapshot)
	subject, warnings, err := x.resolveSubject(ref)
	if err != nil {
		return SubjectResult{}, err
	}
	warnings = append(warnings, x.incomplete...)
	generatedAt := snapshot.GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = time.Now()
	}
	result := SubjectResult{
		Subject:     subject,
		GeneratedAt: generatedAt,
		Warnings:    uniqueStrings(warnings),
		ResultLimit: options.Limit(),
	}
	ingressBudget := newDirectionBudget(result.ResultLimit)
	egressBudget := newDirectionBudget(result.ResultLimit)
	result.Ingress = e.evaluateDirection(x, &subject, Ingress, ingressBudget)
	result.Egress = e.evaluateDirection(x, &subject, Egress, egressBudget)
	result.Truncated = ingressBudget.truncated || egressBudget.truncated
	if result.Truncated {
		result.Warnings = uniqueStrings(append(result.Warnings, fmt.Sprintf("results truncated at limit %d per direction", result.ResultLimit)))
	}
	return result, nil
}

//nolint:gocritic // SubjectResult is part of the public Evaluator contract.
func (_ *engine) Rules(result SubjectResult, direction Direction) []RuleResult {
	return slices.Clone(result.Direction(direction).Rules)
}

//nolint:gocritic // SubjectResult is part of the public Evaluator contract.
func (_ *engine) Primitives(result SubjectResult, direction Direction, kinds sets.Set[PrimitiveKind]) []PrimitiveResult {
	return result.Direction(direction).FilteredPrimitives(kinds)
}

//nolint:gocritic // SubjectResult is part of the public Evaluator contract.
func (e *engine) DirectionApplicability(result SubjectResult, direction Direction, kinds sets.Set[PrimitiveKind]) []ApplicabilityRow {
	var rows []ApplicabilityRow
	primitives := e.Primitives(result, direction, kinds)
	for primitiveIndex := range primitives {
		primitive := &primitives[primitiveIndex]
		row := ApplicabilityRow{
			Primitive:          *primitive,
			EffectiveState:     primitive.State,
			Permissions:        canonicalPermissions(primitive.Permissions),
			PeerMatches:        false,
			OppositeSideAllows: len(primitive.PairDecisions) > 0,
		}
		for pairIndex := range primitive.PairDecisions {
			pair := &primitive.PairDecisions[pairIndex]
			if evidenceHasDirection(pair.Decision.Evidence, direction) {
				row.PeerMatches = true
			}
			if primitive.Ref.Kind == PrimitiveCIDR {
				if pair.Decision.State != AccessAllowed {
					row.OppositeSideAllows = false
				}
				continue
			}
			if _, found := evidencePermissionsForDirection(pair.Decision.Evidence, opposite(direction)); !found {
				row.OppositeSideAllows = false
			}
		}
		row.OppositeSideAllows = row.PeerMatches && row.OppositeSideAllows
		rows = append(rows, row)
	}
	return rows
}

//nolint:gocritic // SubjectResult is part of the public Evaluator contract.
func (e *engine) RuleApplicability(result SubjectResult, direction Direction, id RuleID, kinds sets.Set[PrimitiveKind]) []ApplicabilityRow {
	var rows []ApplicabilityRow
	primitives := e.Primitives(result, direction, kinds)
	for primitiveIndex := range primitives {
		primitive := &primitives[primitiveIndex]
		row := ApplicabilityRow{Primitive: *primitive}
		allEffective := len(primitive.PairDecisions) > 0
		anyEffective := false
		var permissions []PortPermission
		for pairIndex := range primitive.PairDecisions {
			pair := &primitive.PairDecisions[pairIndex]
			matched := evidenceContains(pair.Decision.Evidence, &id)
			if !matched {
				allEffective = false
				continue
			}
			row.PeerMatches = true
			selectedPermissions := evidencePermissions(pair.Decision.Evidence, &id)
			effective := pair.Decision.State == AccessAllowed
			overlap := selectedPermissions
			if primitive.Ref.Kind != PrimitiveCIDR {
				oppositePermissions, oppositeEvidence := evidencePermissionsForDirection(pair.Decision.Evidence, opposite(direction))
				var known bool
				overlap, known = intersectPermissions(selectedPermissions, oppositePermissions)
				effective = effective && oppositeEvidence && knownPermissions(overlap) && (known || knownPermissions(overlap))
			}
			overlap, _ = intersectPermissions(overlap, pair.Decision.Permissions)
			effective = effective && knownPermissions(overlap)
			if !effective {
				allEffective = false
			} else {
				anyEffective = true
				permissions = append(permissions, overlap...)
			}
		}
		row.OppositeSideAllows = row.PeerMatches && allEffective
		row.Permissions = canonicalPermissions(permissions)
		switch {
		case primitive.State == AccessPartialData:
			row.EffectiveState = AccessPartialData
		case len(primitive.PairDecisions) == 0:
			// Nothing was evaluated: no concrete pod pairs exist, so the rule's
			// effect on this peer is unknown rather than denied.
			row.EffectiveState = AccessUnknown
		case allEffective:
			row.EffectiveState = AccessAllowed
		case anyEffective:
			row.EffectiveState = AccessPartial
		default:
			row.EffectiveState = AccessDisallowed
		}
		rows = append(rows, row)
	}
	return rows
}

type directionBudget struct {
	limit      int
	candidates int
	pairs      int
	truncated  bool
}

func (b *directionBudget) takePair() bool {
	if b.pairs >= b.limit {
		b.truncated = true
		return false
	}
	b.pairs++
	return true
}

func newDirectionBudget(limit int) *directionBudget {
	return &directionBudget{limit: max(0, limit)}
}

func (b *directionBudget) takeCandidate() bool {
	if b.candidates >= b.limit {
		b.truncated = true
		return false
	}
	b.candidates++
	return true
}

func (e *engine) evaluateDirection(x *snapshotIndex, subject *Subject, direction Direction, budget *directionBudget) DirectionResult {
	result := DirectionResult{Primitives: map[PrimitiveKind][]PrimitiveResult{}}
	pods := sortedPods(x.pods)

	cidrRefs := cidrPrimitives(x, subject, direction)
	for index := range cidrRefs {
		if !budget.takeCandidate() {
			break
		}
		primitive, truncated := e.evaluateCIDRPrimitive(x, subject, direction, &cidrRefs[index], budget)
		budget.truncated = budget.truncated || truncated
		result.Primitives[PrimitiveCIDR] = append(result.Primitives[PrimitiveCIDR], primitive)
	}
	for _, p := range pods {
		if !budget.takeCandidate() {
			break
		}
		primitive, truncated := e.evaluatePodPrimitive(x, subject, direction, &PrimitiveRef{
			Kind: PrimitivePod, Namespace: p.Namespace, Name: p.Name, UID: p.UID,
		}, []*corev1.Pod{p}, nil, false, budget)
		budget.truncated = budget.truncated || truncated
		result.Primitives[PrimitivePod] = append(result.Primitives[PrimitivePod], primitive)
	}
	for _, ns := range sortedNamespaces(x) {
		if !budget.takeCandidate() {
			break
		}
		var members []*corev1.Pod
		for _, p := range pods {
			if p.Namespace == ns.Name {
				members = append(members, p)
			}
		}
		primitive, truncated := e.evaluatePodPrimitive(x, subject, direction, &PrimitiveRef{
			Kind: PrimitiveNamespace, Name: ns.Name, UID: ns.UID,
		}, members, nil, false, budget)
		budget.truncated = budget.truncated || truncated
		result.Primitives[PrimitiveNamespace] = append(result.Primitives[PrimitiveNamespace], primitive)
	}
	for _, deployment := range sortedDeployments(x) {
		if !budget.takeCandidate() {
			break
		}
		members, fallback := x.podsForDeployment(deployment.Namespace, deployment.UID, deployment.Spec.Selector)
		var warnings []string
		if fallback {
			warnings = append(warnings, fmt.Sprintf(
				"deployment %s/%s resolved by uncertain selector fallback; owner UID chain data is incomplete",
				deployment.Namespace, deployment.Name,
			))
		}
		primitive, truncated := e.evaluatePodPrimitive(x, subject, direction, &PrimitiveRef{
			Kind: PrimitiveDeployment, Namespace: deployment.Namespace, Name: deployment.Name, UID: deployment.UID,
		}, members, warnings, fallback, budget)
		budget.truncated = budget.truncated || truncated
		result.Primitives[PrimitiveDeployment] = append(result.Primitives[PrimitiveDeployment], primitive)
	}
	for _, job := range sortedJobs(x) {
		if !budget.takeCandidate() {
			break
		}
		members, fallback := x.podsForJob(job.Namespace, job.UID, job.Spec.Selector)
		var warnings []string
		if fallback {
			warnings = append(warnings, fmt.Sprintf("job %s/%s resolved by uncertain selector fallback; owner UID data is incomplete", job.Namespace, job.Name))
		}
		primitive, truncated := e.evaluatePodPrimitive(x, subject, direction, &PrimitiveRef{
			Kind: PrimitiveJob, Namespace: job.Namespace, Name: job.Name, UID: job.UID,
		}, members, warnings, fallback, budget)
		budget.truncated = budget.truncated || truncated
		result.Primitives[PrimitiveJob] = append(result.Primitives[PrimitiveJob], primitive)
	}
	result.Rules = e.buildRules(x, subject, direction, result.Primitives)
	return result
}

func (e *engine) evaluatePodPrimitive(
	x *snapshotIndex,
	subject *Subject,
	direction Direction,
	ref *PrimitiveRef,
	peers []*corev1.Pod,
	warnings []string,
	uncertain bool,
	budget *directionBudget,
) (PrimitiveResult, bool) {
	result := PrimitiveResult{Ref: *ref, Warnings: slices.Clone(warnings)}
	var permissions []PortPermission
	truncated := false
	for _, subjectRef := range subject.Pods {
		subjectPod := x.pods[key(subjectRef.Namespace, subjectRef.Name)]
		for _, peer := range peers {
			if !budget.takePair() {
				truncated = true
				break
			}
			var source, destination *corev1.Pod
			if direction == Ingress {
				source, destination = peer, subjectPod
			} else {
				source, destination = subjectPod, peer
			}
			if source == nil || destination == nil {
				continue
			}
			decision := e.evaluatePair(x, source, destination)
			result.PairDecisions = append(result.PairDecisions, PairDecision{
				Source: podRef(source), Destination: podRef(destination), Decision: decision,
			})
			result.TotalPairs++
			if decision.State == AccessAllowed {
				result.AllowedPairs++
			}
			permissions = append(permissions, decision.Permissions...)
			result.Evidence = append(result.Evidence, decision.Evidence...)
			result.Warnings = append(result.Warnings, decision.Warnings...)
		}
		if truncated {
			break
		}
	}
	result.Permissions = canonicalPermissions(permissions)
	result.Evidence = uniqueEvidence(result.Evidence)
	result.Warnings = uniqueStrings(result.Warnings)
	if truncated {
		result.Warnings = append(result.Warnings, "pair evaluation truncated by result limit")
	}
	result.State, result.Explanation = aggregateState(result.PairDecisions, len(x.incomplete) > 0 || uncertain || truncated)
	if len(x.incomplete) > 0 {
		result.Warnings = uniqueStrings(append(result.Warnings, x.incomplete...))
	}
	return result, truncated
}

func (e *engine) evaluatePair(x *snapshotIndex, source, destination *corev1.Pod) Decision {
	egress := e.evaluateSide(x, Egress, source, destination)
	ingress := e.evaluateSide(x, Ingress, destination, source)
	permissions, known := intersectPermissions(egress.Permissions, ingress.Permissions)
	decision := Decision{
		Permissions: permissions,
		Evidence:    uniqueEvidence(append(egress.Evidence, ingress.Evidence...)),
		Warnings:    uniqueStrings(append(egress.Warnings, ingress.Warnings...)),
	}
	switch {
	case egress.State == AccessDisallowed || ingress.State == AccessDisallowed:
		decision.State = AccessDisallowed
		decision.Explanation = "traffic is denied because source egress and destination ingress must both allow it"
	case knownPermissions(permissions):
		decision.State = AccessAllowed
		decision.Explanation = "source egress and destination ingress both definitely allow traffic"
		if egress.State == AccessUnknown || ingress.State == AccessUnknown || !known {
			decision.Warnings = uniqueStrings(append(decision.Warnings, "additional traffic may be allowed by an unresolved named destination port"))
		}
	case egress.State == AccessUnknown || ingress.State == AccessUnknown || !known:
		decision.State = AccessUnknown
		decision.Explanation = "traffic cannot be determined because a named destination port is ambiguous"
	case len(permissions) == 0:
		decision.State = AccessDisallowed
		decision.Explanation = "source egress and destination ingress allow no common protocol/port"
	}
	return decision
}

func (e *engine) evaluateSide(x *snapshotIndex, direction Direction, selectedPod, peerPod *corev1.Pod) Decision {
	namespace := x.namespaces[peerPod.Namespace]
	destination := selectedPod
	if direction == Egress {
		destination = peerPod
	}
	match := func(policy *normalizedPolicy, rule *normalizedRule) (bool, int) {
		return normalizedRulePeersMatch(rule, policy.Namespace, peerPod, namespace)
	}
	network := e.evaluatePolicyLayer(x, policyLayerNetwork, direction, selectedPod, destination, match)
	if direction == Egress {
		return network
	}
	authorization := e.evaluatePolicyLayer(x, policyLayerAuthorization, direction, selectedPod, destination, match)
	return combinePolicyLayers(network, authorization)
}

func (e *engine) evaluateCIDRPrimitive(x *snapshotIndex, subject *Subject, direction Direction, ref *PrimitiveRef, budget *directionBudget) (PrimitiveResult, bool) {
	result := PrimitiveResult{Ref: *ref}
	truncated := false
	for _, subjectRef := range subject.Pods {
		if !budget.takePair() {
			truncated = true
			break
		}
		pod := x.pods[key(subjectRef.Namespace, subjectRef.Name)]
		if pod == nil {
			continue
		}
		decision := e.evaluateCIDRSide(x, direction, pod, ref)
		result.TotalPairs++
		if decision.State == AccessAllowed {
			result.AllowedPairs++
		}
		result.Permissions = append(result.Permissions, decision.Permissions...)
		result.Evidence = append(result.Evidence, decision.Evidence...)
		pair := PairDecision{Decision: decision}
		if direction == Ingress {
			pair.Destination = podRef(pod)
		} else {
			pair.Source = podRef(pod)
		}
		result.PairDecisions = append(result.PairDecisions, pair)
	}
	result.Permissions = canonicalPermissions(result.Permissions)
	result.Evidence = uniqueEvidence(result.Evidence)
	if truncated {
		result.Warnings = append(result.Warnings, "pair evaluation truncated by result limit")
	}
	result.State, result.Explanation = aggregateState(result.PairDecisions, len(x.incomplete) > 0 || truncated)
	if len(x.incomplete) > 0 {
		result.Warnings = slices.Clone(x.incomplete)
	}
	return result, truncated
}

func (e *engine) evaluateCIDRSide(x *snapshotIndex, direction Direction, pod *corev1.Pod, ref *PrimitiveRef) Decision {
	destination := pod
	if direction == Egress {
		destination = nil
	}
	match := func(_ *normalizedPolicy, rule *normalizedRule) (bool, int) {
		return normalizedRuleMatchesCIDR(rule, ref)
	}
	network := e.evaluatePolicyLayer(x, policyLayerNetwork, direction, pod, destination, match)
	if direction == Egress {
		return network
	}
	authorization := e.evaluatePolicyLayer(x, policyLayerAuthorization, direction, pod, destination, match)
	return combinePolicyLayers(network, authorization)
}

type policyRuleMatcher func(*normalizedPolicy, *normalizedRule) (bool, int)

func (_ *engine) evaluatePolicyLayer(
	x *snapshotIndex,
	layer policyLayer,
	direction Direction,
	selectedPod, destination *corev1.Pod,
	match policyRuleMatcher,
) Decision {
	var selected []*normalizedPolicy
	isolated := false
	namespace := x.namespaces[selectedPod.Namespace]
	for _, policy := range x.policiesForPod(selectedPod) {
		policyDirection := policy.direction(direction)
		if policy.Layer != layer ||
			(!policyDirection.Isolate && len(policyDirection.Rules) == 0) ||
			!normalizedPolicySelectsPod(policy, selectedPod, namespace) {
			continue
		}
		selected = append(selected, policy)
		isolated = isolated || policyDirection.Isolate
	}

	var permissions []PortPermission
	var evidence []PolicyEvidence
	if !isolated {
		permissions = allPermissions()
		if layer == policyLayerNetwork || len(selected) > 0 {
			id := RuleID{Direction: direction, Index: -1, SyntheticKind: syntheticUnrestricted}
			evidence = append(evidence, PolicyEvidence{
				RuleID: id, PeerIndex: -1, Ports: allPermissions(),
				Summary: "no allow policy isolates this pod in this layer",
			})
		}
	}

	var denied []PortPermission
	var warnings []string
	unknown := false
	for _, policy := range selected {
		for index := range policy.direction(direction).Rules {
			rule := &policy.direction(direction).Rules[index]
			matches, peerIndex := match(policy, rule)
			if !matches {
				continue
			}
			perms, known := permissionsForNormalizedRule(rule, destination)
			unknown = unknown || !known
			item := policyEvidence(policy, direction, rule, peerIndex, perms)
			evidence = append(evidence, item)
			warnings = append(warnings, rule.Warnings...)
			if rule.Action == PolicyActionDeny {
				denied = append(denied, perms...)
			} else {
				permissions = append(permissions, perms...)
			}
		}
	}

	permissions = canonicalPermissions(permissions)
	var subtractionKnown bool
	permissions, subtractionKnown = subtractPermissions(permissions, canonicalPermissions(denied))
	unknown = unknown || !subtractionKnown
	evidence = uniqueEvidence(evidence)
	warnings = uniqueStrings(warnings)

	if len(permissions) == 0 {
		if unknown {
			return Decision{
				State: AccessUnknown, Evidence: evidence, Warnings: warnings,
				Explanation: "policy permissions cannot be determined exactly",
			}
		}
		if isolated && !evidenceHasExplicitRule(evidence) {
			id := RuleID{Direction: direction, Index: -1, SyntheticKind: syntheticDefaultDeny}
			evidence = append(evidence, PolicyEvidence{
				RuleID: id, PeerIndex: -1,
				Summary: "pod is isolated and no allow rule matches the peer",
			})
		}
		return Decision{
			State: AccessDisallowed, Evidence: uniqueEvidence(evidence), Warnings: warnings,
			Explanation: "policy isolation or an explicit deny rule permits no destination ports",
		}
	}
	state := AccessAllowed
	explanation := "matching policy rules permit one or more destination ports"
	if unknown && !knownPermissions(permissions) {
		state = AccessUnknown
		explanation = "matching policy rules contain unresolved port constraints"
	} else if unknown {
		warnings = uniqueStrings(append(warnings, "additional traffic may be affected by an unresolved port constraint"))
	}
	return Decision{
		State: state, Permissions: permissions, Evidence: evidence,
		Explanation: explanation, Warnings: warnings,
	}
}

func permissionsForNormalizedRule(rule *normalizedRule, destination *corev1.Pod) ([]PortPermission, bool) {
	if rule.TCPOnly && len(rule.Ports) == 0 {
		return []PortPermission{{Protocol: corev1.ProtocolTCP, All: true}}, true
	}
	return permissionsForPorts(rule.Ports, destination)
}

func combinePolicyLayers(network, authorization Decision) Decision {
	var networkTCP, networkNonTCP []PortPermission
	for _, permission := range network.Permissions {
		if normalizedProtocol(permission.Protocol) == corev1.ProtocolTCP {
			networkTCP = append(networkTCP, permission)
		} else {
			networkNonTCP = append(networkNonTCP, permission)
		}
	}
	tcpPermissions, known := intersectPermissions(networkTCP, authorization.Permissions)
	permissions := canonicalPermissions(append(networkNonTCP, tcpPermissions...))
	decision := Decision{
		Permissions: permissions,
		Evidence:    uniqueEvidence(append(network.Evidence, authorization.Evidence...)),
		Warnings:    uniqueStrings(append(network.Warnings, authorization.Warnings...)),
	}
	switch {
	case network.State == AccessDisallowed:
		decision.State = AccessDisallowed
		decision.Explanation = "network policy permits no traffic"
	case knownPermissions(permissions):
		decision.State = AccessAllowed
		if authorization.State == AccessDisallowed {
			decision.Explanation = "Istio authorization denies TCP, but non-TCP network permissions remain"
		} else {
			decision.Explanation = "network policy and TCP-scoped authorization both permit traffic"
		}
		if network.State == AccessUnknown || authorization.State == AccessUnknown || !known {
			decision.Warnings = uniqueStrings(append(decision.Warnings, "additional traffic may be affected by unresolved policy constraints"))
		}
	case authorization.State == AccessDisallowed:
		decision.State = AccessDisallowed
		decision.Explanation = "Istio authorization permits no TCP traffic and no non-TCP network permissions remain"
	case len(permissions) == 0 && network.State != AccessUnknown && authorization.State != AccessUnknown && known:
		decision.State = AccessDisallowed
		decision.Explanation = "network and authorization policy layers permit no common TCP traffic"
	default:
		decision.State = AccessUnknown
		decision.Explanation = "network and authorization policy layers have no definitely common ports"
	}
	return decision
}

func evidenceHasExplicitRule(evidence []PolicyEvidence) bool {
	for index := range evidence {
		if evidence[index].RuleID.PolicyName != "" {
			return true
		}
	}
	return false
}

func (_ *engine) buildRules(x *snapshotIndex, subject *Subject, direction Direction, primitives map[PrimitiveKind][]PrimitiveResult) []RuleResult {
	rules := map[string]*RuleResult{}
	matchedSubjects := map[string]map[string]struct{}{}
	for _, subjectRef := range subject.Pods {
		pod := x.pods[key(subjectRef.Namespace, subjectRef.Name)]
		if pod == nil {
			continue
		}
		selected := false
		namespace := x.namespaces[pod.Namespace]
		for _, policy := range x.policiesForPod(pod) {
			policyDirection := policy.direction(direction)
			if (!policyDirection.Isolate && len(policyDirection.Rules) == 0) ||
				!normalizedPolicySelectsPod(policy, pod, namespace) {
				continue
			}
			selected = selected || policyDirection.Isolate
			for index := range policyDirection.Rules {
				rule := &policyDirection.Rules[index]
				id := policy.ruleID(direction, rule)
				k := id.String()
				if rules[k] == nil {
					rules[k] = explicitRuleResult(policy, direction, rule)
				}
				rules[k].SubjectPodCount++
			}
		}
		kind := syntheticUnrestricted
		if selected {
			kind = syntheticDefaultDeny
		}
		id := RuleID{Direction: direction, Index: -1, SyntheticKind: kind}
		k := id.String()
		if rules[k] == nil {
			rules[k] = &RuleResult{
				ID:             id,
				PolicySelector: "<synthetic>",
				Synthetic:      true,
				PeerSummary:    kind,
				YAML:           fmt.Sprintf("syntheticRule:\n  direction: %s\n  kind: %s", strings.ToLower(direction.String()), kind),
			}
		}
		rules[k].SubjectPodCount++
	}
	for _, kind := range []PrimitiveKind{PrimitivePod, PrimitiveCIDR} {
		list := primitives[kind]
		for primitiveIndex := range list {
			primitive := &list[primitiveIndex]
			for pairIndex := range primitive.PairDecisions {
				pair := &primitive.PairDecisions[pairIndex]
				for evidenceIndex := range pair.Decision.Evidence {
					evidence := &pair.Decision.Evidence[evidenceIndex]
					k := evidence.RuleID.String()
					rule := rules[k]
					if rule == nil || evidence.RuleID.Direction != direction {
						continue
					}
					rule.Evidence = append(rule.Evidence, *evidence)
					rule.Permissions = append(rule.Permissions, evidence.Ports...)
					if matchedSubjects[k] == nil {
						matchedSubjects[k] = map[string]struct{}{}
					}
					selectedPod := pair.Destination
					if direction == Egress {
						selectedPod = pair.Source
					}
					matchedSubjects[k][selectedPod.ID()] = struct{}{}
				}
			}
		}
	}
	out := make([]RuleResult, 0, len(rules))
	for _, rule := range rules {
		rule.SubjectMatchCount = len(matchedSubjects[rule.ID.String()])
		rule.Evidence = uniqueEvidence(rule.Evidence)
		rule.Permissions = canonicalPermissions(rule.Permissions)
		out = append(out, *rule)
	}
	slices.SortFunc(out, func(a, b RuleResult) int { return cmpString(a.StableID(), b.StableID()) })
	return out
}

func explicitRuleResult(policy *normalizedPolicy, direction Direction, rule *normalizedRule) *RuleResult {
	result := &RuleResult{
		ID:             policy.ruleID(direction, rule),
		PolicySelector: policy.selectorString(),
		PeerSummary:    "all peers",
		Peers:          slices.Clone(rule.PeerStrings),
		YAML:           rule.YAML,
		Notes:          uniqueStrings(append(slices.Clone(policy.Notes), rule.Notes...)),
		Warnings:       slices.Clone(rule.Warnings),
	}
	result.PeerSummary = peerSummary(result.Peers)
	result.Permissions, _ = permissionsForNormalizedRule(rule, nil)
	return result
}

func rulePeerStrings(peers []netv1.NetworkPolicyPeer) []string {
	results := make([]string, 0, len(peers))
	for _, peer := range peers {
		if peer.IPBlock != nil {
			value := "ipBlock=" + peer.IPBlock.CIDR
			if len(peer.IPBlock.Except) > 0 {
				value += " except " + strings.Join(peer.IPBlock.Except, ",")
			}
			results = append(results, value)
			continue
		}
		results = append(results, fmt.Sprintf("namespaceSelector=%s, podSelector=%s",
			labelSelectorString(peer.NamespaceSelector), labelSelectorString(peer.PodSelector)))
	}
	return results
}

func labelSelectorString(selector *metav1.LabelSelector) string {
	if selector == nil {
		return "<none>"
	}
	value, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return "<invalid>"
	}
	if value.String() == "" {
		return "{}"
	}
	return value.String()
}

func peerSummary(peers []string) string {
	if len(peers) == 0 {
		return "all peers"
	}
	return strings.Join(peers, "; ")
}

func ruleYAML(direction string, peers []netv1.NetworkPolicyPeer, ports []netv1.NetworkPolicyPort) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s:\n", direction)
	peerKey := "from"
	if direction == "egress" {
		peerKey = "to"
	}
	fmt.Fprintf(&b, "  %s:\n", peerKey)
	if len(peers) == 0 {
		b.WriteString("    - {}\n")
	}
	for _, peer := range peers {
		b.WriteString("    -")
		if peer.IPBlock != nil {
			fmt.Fprintf(&b, "\n      ipBlock:\n        cidr: %s", peer.IPBlock.CIDR)
			if len(peer.IPBlock.Except) > 0 {
				fmt.Fprintf(&b, "\n        except: [%s]", strings.Join(peer.IPBlock.Except, ", "))
			}
			b.WriteString("\n")
			continue
		}
		fmt.Fprintf(&b, "\n      namespaceSelector: %s\n      podSelector: %s\n",
			labelSelectorString(peer.NamespaceSelector), labelSelectorString(peer.PodSelector))
	}
	b.WriteString("  ports:\n")
	if len(ports) == 0 {
		b.WriteString("    - all\n")
	}
	for _, port := range ports {
		protocol := corev1.ProtocolTCP
		if port.Protocol != nil {
			protocol = *port.Protocol
		}
		value := "all"
		if port.Port != nil {
			value = port.Port.String()
		}
		if port.EndPort != nil {
			value += fmt.Sprintf("-%d", *port.EndPort)
		}
		fmt.Fprintf(&b, "    - protocol: %s\n      port: %s\n", protocol, value)
	}
	return strings.TrimRight(b.String(), "\n")
}

func policyEvidence(
	policy *normalizedPolicy,
	direction Direction,
	rule *normalizedRule,
	peerIndex int,
	permissions []PortPermission,
) PolicyEvidence {
	return PolicyEvidence{
		RuleID:      policy.ruleID(direction, rule),
		PolicyTypes: slices.Clone(policy.PolicyTypes), PeerIndex: peerIndex,
		Ports: slices.Clone(permissions),
		Summary: fmt.Sprintf("%s %s/%s %s rule %d matched peer %d",
			policy.Type.Kind(), policy.Namespace, policy.Name, rule.Action, rule.Index, peerIndex),
	}
}

func aggregateState(pairs []PairDecision, partialData bool) (state AccessState, explanation string) {
	if len(pairs) == 0 {
		if partialData {
			return AccessPartialData, "no concrete pod pairs are available in the partial snapshot"
		}
		return AccessUnknown, "no concrete pod pairs are available"
	}
	allowed, denied, unknown := 0, 0, 0
	for index := range pairs {
		switch pairs[index].Decision.State {
		case AccessAllowed:
			allowed++
		case AccessDisallowed:
			denied++
		default:
			unknown++
		}
	}
	if partialData {
		return AccessPartialData, fmt.Sprintf("snapshot is partial; observed %d allowed, %d denied, and %d unknown pairs", allowed, denied, unknown)
	}
	if allowed == len(pairs) {
		return AccessAllowed, "all concrete pod pairs are allowed"
	}
	if denied == len(pairs) {
		return AccessDisallowed, "all concrete pod pairs are denied"
	}
	if unknown == len(pairs) {
		return AccessUnknown, "all concrete pod pairs are unknown"
	}
	return AccessPartial, fmt.Sprintf("%d of %d concrete pod pairs are allowed", allowed, len(pairs))
}

func cidrPrimitives(x *snapshotIndex, subject *Subject, direction Direction) []PrimitiveRef {
	refs := map[string]PrimitiveRef{}
	allAddresses := false
	for _, subjectRef := range subject.Pods {
		pod := x.pods[key(subjectRef.Namespace, subjectRef.Name)]
		if pod == nil {
			continue
		}
		namespace := x.namespaces[pod.Namespace]
		for _, policy := range x.policiesForPod(pod) {
			policyDirection := policy.direction(direction)
			if (!policyDirection.Isolate && len(policyDirection.Rules) == 0) ||
				!normalizedPolicySelectsPod(policy, pod, namespace) {
				continue
			}
			for ruleIndex := range policyDirection.Rules {
				rule := &policyDirection.Rules[ruleIndex]
				if rule.Disabled || rule.MatchNone {
					continue
				}
				if len(rule.Peers) == 0 {
					allAddresses = true
				}
				for peerIndex := range rule.Peers {
					peer := &rule.Peers[peerIndex]
					if normalizedPeerMatchesCIDR(peer, &PrimitiveRef{Kind: PrimitiveCIDR, CIDR: "0.0.0.0/0"}) &&
						len(peer.IPBlocks) == 0 {
						allAddresses = true
					}
					for blockIndex := range peer.IPBlocks {
						addCIDR(refs, &peer.IPBlocks[blockIndex])
					}
				}
			}
		}
	}
	if allAddresses {
		addCIDRRef(refs, &PrimitiveRef{Kind: PrimitiveCIDR, CIDR: "0.0.0.0/0"})
		addCIDRRef(refs, &PrimitiveRef{Kind: PrimitiveCIDR, CIDR: "::/0"})
	}
	keys := mapsKeys(refs)
	slices.Sort(keys)
	out := make([]PrimitiveRef, 0, len(keys))
	for _, k := range keys {
		out = append(out, refs[k])
	}
	return out
}

func addCIDR(refs map[string]PrimitiveRef, block *netv1.IPBlock) {
	if block == nil {
		return
	}
	addCIDRRef(refs, &PrimitiveRef{Kind: PrimitiveCIDR, CIDR: block.CIDR, CIDRExcept: slices.Clone(block.Except)})
}

func addCIDRRef(refs map[string]PrimitiveRef, ref *PrimitiveRef) {
	prefix, err := netip.ParsePrefix(ref.CIDR)
	if err != nil {
		return
	}
	ref.CIDR = prefix.Masked().String()
	for index, except := range ref.CIDRExcept {
		if parsed, parseErr := netip.ParsePrefix(except); parseErr == nil {
			ref.CIDRExcept[index] = parsed.Masked().String()
		}
	}
	ref.CIDRExcept = uniqueStrings(ref.CIDRExcept)
	refs[ref.ID()] = *ref
}

func peerMatchesCIDR(peer netv1.NetworkPolicyPeer, ref *PrimitiveRef) bool {
	if peer.IPBlock != nil {
		return ipBlockContains(peer.IPBlock, ref)
	}

	return peer.PodSelector == nil && peer.NamespaceSelector == nil
}

func ipBlockContains(block *netv1.IPBlock, ref *PrimitiveRef) bool {
	if block == nil {
		return false
	}
	allowed, err := netip.ParsePrefix(block.CIDR)
	if err != nil {
		return false
	}
	candidate, err := netip.ParsePrefix(ref.CIDR)
	if err != nil || allowed.Addr().BitLen() != candidate.Addr().BitLen() {
		return false
	}
	return prefixSetContained(
		candidate.Masked(), parsedPrefixes(ref.CIDRExcept, candidate.Addr().BitLen()),
		allowed.Masked(), parsedPrefixes(block.Except, allowed.Addr().BitLen()),
	)
}

func parsedPrefixes(values []string, bitLen int) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, value := range values {
		if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Addr().BitLen() == bitLen {
			prefixes = append(prefixes, prefix.Masked())
		}
	}
	return prefixes
}

func prefixSetContained(candidate netip.Prefix, candidateExcept []netip.Prefix, allowed netip.Prefix, allowedExcept []netip.Prefix) bool {
	if prefixCovered(candidate, candidateExcept) {
		return true
	}
	if !candidate.Contains(allowed.Addr()) && !allowed.Contains(candidate.Addr()) {
		return false
	}
	if !allowed.Contains(candidate.Addr()) || allowed.Bits() > candidate.Bits() {
		if candidate.Bits() == candidate.Addr().BitLen() {
			return false
		}
		left, right := splitPrefix(candidate)
		return prefixSetContained(left, candidateExcept, allowed, allowedExcept) &&
			prefixSetContained(right, candidateExcept, allowed, allowedExcept)
	}
	if !prefixOverlapsAny(candidate, allowedExcept) {
		return true
	}
	if candidate.Bits() == candidate.Addr().BitLen() {
		return false
	}
	left, right := splitPrefix(candidate)
	return prefixSetContained(left, candidateExcept, allowed, allowedExcept) &&
		prefixSetContained(right, candidateExcept, allowed, allowedExcept)
}

func prefixCovered(prefix netip.Prefix, exclusions []netip.Prefix) bool {
	for _, exclusion := range exclusions {
		if exclusion.Contains(prefix.Addr()) && exclusion.Bits() <= prefix.Bits() {
			return true
		}
	}
	return false
}

func prefixOverlapsAny(prefix netip.Prefix, others []netip.Prefix) bool {
	for _, other := range others {
		if prefix.Contains(other.Addr()) || other.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}
func ipBlockIntersects(block *netv1.IPBlock, ref *PrimitiveRef) bool {
	if block == nil {
		return false
	}
	left, err := netip.ParsePrefix(block.CIDR)
	if err != nil {
		return false
	}
	right, err := netip.ParsePrefix(ref.CIDR)
	if err != nil || left.Addr().BitLen() != right.Addr().BitLen() {
		return false
	}
	left, right = left.Masked(), right.Masked()
	var overlap netip.Prefix
	switch {
	case left.Contains(right.Addr()):
		overlap = right
	case right.Contains(left.Addr()):
		overlap = left
	default:
		return false
	}
	exclusions := make([]netip.Prefix, 0, len(block.Except)+len(ref.CIDRExcept))
	for _, value := range append(slices.Clone(block.Except), ref.CIDRExcept...) {
		if prefix, parseErr := netip.ParsePrefix(value); parseErr == nil && prefix.Addr().BitLen() == overlap.Addr().BitLen() {
			exclusions = append(exclusions, prefix.Masked())
		}
	}
	return prefixHasUnexcludedAddress(overlap, exclusions)
}

func prefixHasUnexcludedAddress(prefix netip.Prefix, exclusions []netip.Prefix) bool {
	var overlaps []netip.Prefix
	for _, exclusion := range exclusions {
		if exclusion.Contains(prefix.Addr()) && exclusion.Bits() <= prefix.Bits() {
			return false
		}
		if prefix.Contains(exclusion.Addr()) {
			overlaps = append(overlaps, exclusion)
		}
	}
	if len(overlaps) == 0 {
		return true
	}
	if prefix.Bits() == prefix.Addr().BitLen() {
		return false
	}
	left, right := splitPrefix(prefix)
	return prefixHasUnexcludedAddress(left, overlaps) || prefixHasUnexcludedAddress(right, overlaps)
}

func splitPrefix(prefix netip.Prefix) (left, right netip.Prefix) {
	bits := prefix.Bits()
	addr := prefix.Masked().Addr()
	if addr.Is4() {
		raw := addr.As4()
		raw[bits/8] |= 1 << (7 - uint(bits%8))
		return netip.PrefixFrom(addr, bits+1), netip.PrefixFrom(netip.AddrFrom4(raw), bits+1)
	}
	raw := addr.As16()
	raw[bits/8] |= 1 << (7 - uint(bits%8))
	return netip.PrefixFrom(addr, bits+1), netip.PrefixFrom(netip.AddrFrom16(raw), bits+1)
}

func sortedPods(pods map[string]*corev1.Pod) []*corev1.Pod {
	out := make([]*corev1.Pod, 0, len(pods))
	for _, pod := range pods {
		out = append(out, pod)
	}
	slices.SortFunc(out, func(a, b *corev1.Pod) int {
		if a.Namespace != b.Namespace {
			return cmpString(a.Namespace, b.Namespace)
		}
		return cmpString(a.Name, b.Name)
	})
	return out
}

func sortedNamespaces(x *snapshotIndex) []*corev1.Namespace {
	out := make([]*corev1.Namespace, 0, len(x.namespaces))
	for _, ns := range x.namespaces {
		out = append(out, ns)
	}
	slices.SortFunc(out, func(a, b *corev1.Namespace) int { return cmpString(a.Name, b.Name) })
	return out
}

func sortedDeployments(x *snapshotIndex) []*appsv1.Deployment {
	out := make([]*appsv1.Deployment, 0, len(x.deployments))
	for _, item := range x.deployments {
		out = append(out, item)
	}
	slices.SortFunc(out, func(a, b *appsv1.Deployment) int {
		return cmpString(key(a.Namespace, a.Name), key(b.Namespace, b.Name))
	})
	return out
}

func sortedJobs(x *snapshotIndex) []*batchv1.Job {
	out := make([]*batchv1.Job, 0, len(x.jobs))
	for _, item := range x.jobs {
		out = append(out, item)
	}
	slices.SortFunc(out, func(a, b *batchv1.Job) int { return cmpString(key(a.Namespace, a.Name), key(b.Namespace, b.Name)) })
	return out
}

func uniqueEvidence(in []PolicyEvidence) []PolicyEvidence {
	seen := map[string]PolicyEvidence{}
	for index := range in {
		evidence := &in[index]
		k := fmt.Sprintf("%s\x00%d\x00%s", evidence.RuleID.String(), evidence.PeerIndex, permissionsKey(evidence.Ports))
		seen[k] = *evidence
	}
	keys := mapsKeys(seen)
	slices.Sort(keys)
	out := make([]PolicyEvidence, 0, len(keys))
	for _, k := range keys {
		out = append(out, seen[k])
	}
	return out
}

func permissionsKey(permissions []PortPermission) string {
	var values []string
	for _, permission := range canonicalPermissions(permissions) {
		values = append(values, permission.String())
	}
	return fmt.Sprint(values)
}

func uniqueStrings(in []string) []string {
	set := map[string]struct{}{}
	for _, value := range in {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	values := mapsKeys(set)
	slices.Sort(values)
	return values
}

func evidenceContains(evidence []PolicyEvidence, id *RuleID) bool {
	for index := range evidence {
		if evidence[index].RuleID.String() == id.String() {
			return true
		}
	}
	return false
}

// evidenceHasDirection reports whether a real (non default-deny) rule in the
// given direction covers the pair. Synthetic default-deny evidence is present
// on every denied pair, so counting it would make peer matching degenerate to
// "always true". This mirrors evidencePermissionsForDirection, which skips the
// same synthetic kind.
func evidenceHasDirection(evidence []PolicyEvidence, direction Direction) bool {
	for index := range evidence {
		item := &evidence[index]
		if item.RuleID.Direction != direction || item.RuleID.SyntheticKind == syntheticDefaultDeny {
			continue
		}
		return true
	}
	return false
}

func evidencePermissions(evidence []PolicyEvidence, id *RuleID) []PortPermission {
	var permissions []PortPermission
	for index := range evidence {
		item := &evidence[index]
		if item.RuleID.String() != id.String() {
			continue
		}
		if item.RuleID.SyntheticKind == syntheticUnrestricted {
			permissions = append(permissions, allPermissions()...)
		} else {
			permissions = append(permissions, item.Ports...)
		}
	}
	return canonicalPermissions(permissions)
}

func evidencePermissionsForDirection(evidence []PolicyEvidence, direction Direction) ([]PortPermission, bool) {
	var permissions []PortPermission
	found := false
	for index := range evidence {
		item := &evidence[index]
		if item.RuleID.Direction != direction || item.RuleID.SyntheticKind == syntheticDefaultDeny {
			continue
		}
		found = true
		if item.RuleID.SyntheticKind == syntheticUnrestricted {
			permissions = append(permissions, allPermissions()...)
		} else {
			permissions = append(permissions, item.Ports...)
		}
	}
	return canonicalPermissions(permissions), found
}

func opposite(direction Direction) Direction {
	if direction == Ingress {
		return Egress
	}
	return Ingress
}
