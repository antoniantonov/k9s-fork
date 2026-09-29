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

type engine struct {
	cache *normalizationCache
}

const (
	syntheticDefaultDeny  = SyntheticDefaultDeny
	syntheticUnrestricted = SyntheticUnrestricted
	cidrPartialDeny       = "CIDR partially overlaps an explicit deny; listed known permissions apply throughout the range, but other ports may vary by address"
)

// NewEvaluator returns a NetworkPolicy evaluator. It keeps no evaluation
// state between calls apart from a cache of normalized policies.
func NewEvaluator() Evaluator {
	return &engine{cache: newNormalizationCache()}
}

//nolint:gocritic // Snapshot is part of the public Evaluator contract.
func (e *engine) EvaluateSubject(ref SubjectRef, snapshot Snapshot, options Options) (SubjectResult, error) {
	e.cache.begin()
	x := buildSnapshotIndex(&snapshot, e.cache)
	e.cache.sweep()
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
		Notes:       uniqueStrings(snapshot.Notes),
		ResultLimit: options.Limit(),
	}
	ingressBudget := newDirectionBudget(result.ResultLimit)
	egressBudget := newDirectionBudget(result.ResultLimit)
	result.Ingress = e.evaluateDirection(x, &subject, Ingress, ingressBudget)
	result.Egress = e.evaluateDirection(x, &subject, Egress, egressBudget)
	// Only uncertainty that affected an evaluated pair of this subject is
	// reported; unrelated uncertain policies leave the subject definitive.
	warnings = append(warnings, x.uncertaintyWarnings()...)
	result.Warnings = uniqueStrings(warnings)
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
			// Matching allow evidence may have been overridden by a deny or
			// destination authorization, so require effective permissions too.
			if _, found := evidencePermissionsForDirection(pair.Decision.Evidence, opposite(direction)); !found || !knownPermissions(pair.Decision.Permissions) {
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
		unknownPairs := 0
		var permissions []PortPermission
		for pairIndex := range primitive.PairDecisions {
			pair := &primitive.PairDecisions[pairIndex]
			matched := evidenceContains(pair.Decision.Evidence, &id)
			if !matched {
				allEffective = false
				continue
			}
			row.PeerMatches = true
			if id.Action == PolicyActionDeny || pair.Decision.State == AccessDisallowed {
				allEffective = false
				continue
			}
			selectedPermissions := evidencePermissions(pair.Decision.Evidence, &id)
			possible := selectedPermissions
			if primitive.Ref.Kind != PrimitiveCIDR {
				oppositePermissions, _ := evidencePermissionsForDirection(pair.Decision.Evidence, opposite(direction))
				possible, _ = intersectPermissions(possible, oppositePermissions)
			}
			overlap, _ := intersectPermissions(possible, pair.Decision.Permissions)
			var guaranteed []PortPermission
			for _, permission := range overlap {
				if !permission.Unknown {
					guaranteed = append(guaranteed, permission)
				}
			}
			effective := len(guaranteed) > 0
			uncertain := !effective && len(overlap) > 0
			if primitive.Ref.Kind == PrimitiveCIDR && slices.Contains(pair.Decision.Warnings, cidrPartialDeny) {
				// CIDR allow evidence already excludes whole-range denies.
				// Only its remaining possible ports can vary by address.
				unguaranteed, _ := subtractPermissions(possible, guaranteed)
				if len(unguaranteed) > 0 {
					effective, uncertain = false, true
				}
			}
			if !effective {
				allEffective = false
			} else {
				anyEffective = true
			}
			if uncertain {
				unknownPairs++
			}
			permissions = append(permissions, guaranteed...)
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
		case unknownPairs == len(primitive.PairDecisions):
			row.EffectiveState = AccessUnknown
		case anyEffective || unknownPairs > 0:
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
	rules := newRuleAccumulator(direction)

	cidrRefs := cidrPrimitives(x, subject, direction)
	for index := range cidrRefs {
		if !budget.takeCandidate() {
			break
		}
		primitive, truncated := e.evaluateCIDRPrimitive(x, subject, direction, &cidrRefs[index], budget, rules)
		budget.truncated = budget.truncated || truncated
		result.Primitives[PrimitiveCIDR] = append(result.Primitives[PrimitiveCIDR], primitive)
	}
	for _, p := range pods {
		if !budget.takeCandidate() {
			break
		}
		primitive, truncated := e.evaluatePodPrimitive(x, subject, direction, &PrimitiveRef{
			Kind: PrimitivePod, Namespace: p.Namespace, Name: p.Name, UID: p.UID,
		}, []*corev1.Pod{p}, nil, false, budget, rules)
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
		}, members, nil, false, budget, nil)
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
		}, members, warnings, fallback, budget, nil)
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
		}, members, warnings, fallback, budget, nil)
		budget.truncated = budget.truncated || truncated
		result.Primitives[PrimitiveJob] = append(result.Primitives[PrimitiveJob], primitive)
	}
	result.Rules = e.buildRules(x, subject, direction, rules)
	return result
}

// evaluatePodPrimitive aggregates the pairs between the subject pods and the
// primitive's pods. Only pod primitives feed the rule accumulator: namespace
// and workload primitives repeat the same pairs.
func (e *engine) evaluatePodPrimitive(
	x *snapshotIndex,
	subject *Subject,
	direction Direction,
	ref *PrimitiveRef,
	peers []*corev1.Pod,
	warnings []string,
	uncertain bool,
	budget *directionBudget,
	rules *ruleAccumulator,
) (PrimitiveResult, bool) {
	result := PrimitiveResult{Ref: *ref, Warnings: slices.Clone(warnings)}
	var permissions []PortPermission
	var evidence evidenceSet
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
			pair := e.evaluatePair(x, source, destination)
			decision := pair.decision
			result.PairDecisions = append(result.PairDecisions, PairDecision{
				Source: podRef(source), Destination: podRef(destination), Decision: decision,
			})
			result.TotalPairs++
			if decision.State == AccessAllowed {
				result.AllowedPairs++
			}
			permissions = append(permissions, decision.Permissions...)
			evidence.add(pair.keys, decision.Evidence)
			rules.add(pair.keys, decision.Evidence, subjectPod)
			result.Warnings = append(result.Warnings, decision.Warnings...)
		}
		if truncated {
			break
		}
	}
	result.Permissions = canonicalPermissions(permissions)
	result.Evidence = evidence.sorted()
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

// layerDecision is a side or layer decision plus the reasons that make the
// pair partial data. Uncertainty is kept apart from State so that layer
// composition still works on the modeled permissions.
type layerDecision struct {
	Decision
	uncertain []string
}

// pairResult is a memoized pair decision with the sort keys of its evidence.
type pairResult struct {
	decision Decision
	keys     []string
}

// evaluatePair evaluates one source/destination pair. The result is shared by
// the pod, namespace, deployment and job primitives containing the pair.
func (e *engine) evaluatePair(x *snapshotIndex, source, destination *corev1.Pod) pairResult {
	pair := pairKey{source: source, destination: destination}
	if result, ok := x.pairs[pair]; ok {
		return result
	}
	sourceInfo, destinationInfo := x.info(source), x.info(destination)
	egress := e.evaluateSide(x, Egress, sourceInfo, destinationInfo)
	ingress := e.evaluateSide(x, Ingress, destinationInfo, sourceInfo)
	permissions, known := intersectPermissions(egress.Permissions, ingress.Permissions)
	evidence, keys := uniqueEvidenceKeys(append(slices.Clone(egress.Evidence), ingress.Evidence...))
	decision := Decision{
		Permissions: permissions,
		Evidence:    evidence,
		Warnings:    uniqueStrings(append(slices.Clone(egress.Warnings), ingress.Warnings...)),
	}
	switch {
	case egress.State == AccessDisallowed || ingress.State == AccessDisallowed:
		decision.State = AccessDisallowed
		decision.Explanation = "traffic is denied because source egress and destination ingress must both allow it"
	case len(permissions) == 0:
		decision.State = AccessDisallowed
		decision.Explanation = "source egress and destination ingress allow no common protocol/port"
	case knownPermissions(permissions):
		decision.State = AccessAllowed
		decision.Explanation = "source egress and destination ingress both definitely allow traffic"
		if egress.State == AccessUnknown || ingress.State == AccessUnknown || !known {
			decision.Warnings = uniqueStrings(append(decision.Warnings, "additional traffic may be allowed by an unresolved named destination port"))
		}
	default:
		decision.State = AccessUnknown
		decision.Explanation = "traffic cannot be determined because a named destination port is ambiguous"
	}
	x.applyUncertainty(&decision, append(slices.Clone(egress.uncertain), ingress.uncertain...))
	result := pairResult{decision: decision, keys: keys}
	x.pairs[pair] = result
	return result
}

// applyUncertainty marks a decision as partial data when a policy that could
// affect it cannot be evaluated. The modeled permissions are kept.
func (x *snapshotIndex) applyUncertainty(decision *Decision, uncertain []string) {
	uncertain = uniqueStrings(uncertain)
	if len(uncertain) == 0 {
		return
	}
	x.noteUncertainty(uncertain)
	decision.State = AccessPartialData
	decision.Explanation = "policy data needed for this pair is incomplete; " + decision.Explanation
	decision.Warnings = uniqueStrings(append(decision.Warnings, uncertain...))
}

func (e *engine) evaluateSide(x *snapshotIndex, direction Direction, selected, peer *podInfo) layerDecision {
	destination := selected.pod
	if direction == Egress {
		destination = peer.pod
	}
	matcher := podMatcher{x: x, peer: peer}
	network := e.evaluatePolicyLayer(x, policyLayerNetwork, direction, selected, destination, matcher)
	if direction == Egress {
		return network
	}
	authorization := e.evaluatePolicyLayer(x, policyLayerAuthorization, direction, selected, destination, matcher)
	return combinePolicyLayers(&network, &authorization)
}

func (e *engine) evaluateCIDRPrimitive(
	x *snapshotIndex,
	subject *Subject,
	direction Direction,
	ref *PrimitiveRef,
	budget *directionBudget,
	rules *ruleAccumulator,
) (PrimitiveResult, bool) {
	result := PrimitiveResult{Ref: *ref}
	var evidence evidenceSet
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
		decision := e.evaluateCIDRSide(x, direction, x.info(pod), ref)
		var keys []string
		decision.Evidence, keys = uniqueEvidenceKeys(decision.Evidence)
		result.TotalPairs++
		if decision.State == AccessAllowed {
			result.AllowedPairs++
		}
		result.Permissions = append(result.Permissions, decision.Permissions...)
		evidence.add(keys, decision.Evidence)
		rules.add(keys, decision.Evidence, pod)
		result.Warnings = append(result.Warnings, decision.Warnings...)
		pair := PairDecision{Decision: decision}
		if direction == Ingress {
			pair.Destination = podRef(pod)
		} else {
			pair.Source = podRef(pod)
		}
		result.PairDecisions = append(result.PairDecisions, pair)
	}
	result.Permissions = canonicalPermissions(result.Permissions)
	result.Evidence = evidence.sorted()
	if truncated {
		result.Warnings = append(result.Warnings, "pair evaluation truncated by result limit")
	}
	result.State, result.Explanation = aggregateState(result.PairDecisions, len(x.incomplete) > 0 || truncated)
	if slices.Contains(result.Warnings, cidrPartialDeny) {
		result.Explanation += "; " + cidrPartialDeny
	}
	if len(x.incomplete) > 0 {
		result.Warnings = append(result.Warnings, x.incomplete...)
	}
	result.Warnings = uniqueStrings(result.Warnings)
	return result, truncated
}

func (e *engine) evaluateCIDRSide(x *snapshotIndex, direction Direction, info *podInfo, ref *PrimitiveRef) Decision {
	destination := info.pod
	if direction == Egress {
		destination = nil
	}
	evaluate := func(matcher *cidrMatcher) layerDecision {
		network := e.evaluatePolicyLayer(x, policyLayerNetwork, direction, info, destination, matcher)
		if direction == Egress {
			return network
		}
		authorization := e.evaluatePolicyLayer(x, policyLayerAuthorization, direction, info, destination, matcher)
		return combinePolicyLayers(&network, &authorization)
	}
	matcher := &cidrMatcher{ref: ref, partialDeny: true}
	decision := evaluate(matcher)
	if matcher.intersected {
		// Subtract intersecting denies to retain only whole-range guarantees.
		// A different containment-only result means permissions can vary within
		// the CIDR, not that every address is uniformly denied.
		possible := evaluate(&cidrMatcher{ref: ref})
		// Bound each allow's evidence by the post-deny possible result before
		// attributing uncertainty to that selected rule. Keep deny evidence
		// and the rule's separately recorded declared ports intact.
		evidence := slices.Clone(decision.Evidence)
		for index := range evidence {
			item := &evidence[index]
			if item.RuleID.Action != PolicyActionDeny {
				item.Ports, _ = intersectPermissions(item.Ports, possible.Permissions)
			}
		}
		decision.Evidence = uniqueEvidence(evidence)
		if permissionsKey(decision.Permissions) != permissionsKey(possible.Permissions) {
			decision.State = AccessUnknown
			decision.Explanation = cidrPartialDeny
			decision.Warnings = uniqueStrings(append(decision.Warnings, cidrPartialDeny))
		}
	}
	x.applyUncertainty(&decision.Decision, decision.uncertain)
	return decision.Decision
}

func (*engine) evaluatePolicyLayer(
	x *snapshotIndex,
	layer policyLayer,
	direction Direction,
	selected *podInfo,
	destination *corev1.Pod,
	matcher sideMatcher,
) layerDecision {
	podSelection := x.selection(selected)
	selection := podSelection.layer(direction, layer)
	uncertain := slices.Clone(selection.uncertain)
	if reason := matcher.peerUncertainty(layer, podSelection, direction); reason != "" {
		uncertain = append(uncertain, reason)
	}

	var permissions []PortPermission
	var evidence []PolicyEvidence
	if !selection.isolated {
		permissions = allPermissions()
		if layer == policyLayerNetwork {
			id := RuleID{Direction: direction, Index: -1, SyntheticKind: syntheticUnrestricted}
			evidence = append(evidence, PolicyEvidence{
				RuleID: id, PeerIndex: -1, Ports: allPermissions(),
				Summary: "no allow policy isolates this pod in the network layer",
			})
		}
	}

	var denied []PortPermission
	for _, policy := range selection.policies {
		policyDirection := policy.direction(direction)
		for index := range policyDirection.Rules {
			rule := &policyDirection.Rules[index]
			if len(rule.uncertain) > 0 && matcher.couldMatch(policy, rule) {
				uncertain = append(uncertain, rule.uncertain...)
			}
			match := matcher.match(policy, direction, rule)
			if match.uncertain != "" {
				uncertain = append(uncertain, match.uncertain)
			}
			if !match.matched {
				continue
			}
			perms := permissionsForNormalizedRule(rule, destination)
			evidence = append(evidence, policyEvidence(policy, direction, rule, match.peerIndex, perms))
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
	unknown := !subtractionKnown
	evidence = uniqueEvidence(evidence)
	result := layerDecision{uncertain: uniqueStrings(uncertain)}

	if len(permissions) == 0 {
		if unknown {
			result.Decision = Decision{
				State: AccessUnknown, Evidence: evidence,
				Explanation: "policy permissions cannot be determined exactly",
			}
			return result
		}
		if selection.isolated && !evidenceHasExplicitRule(evidence) {
			kind, summary := syntheticDefaultDeny, "pod is isolated and no allow rule matches the peer"
			if layer == policyLayerAuthorization {
				kind, summary = SyntheticAuthorizationDefaultDeny,
					"an Istio ALLOW policy isolates TCP to this pod and no allow rule matches the request"
			}
			evidence = append(evidence, PolicyEvidence{
				RuleID:    RuleID{Direction: direction, Index: -1, SyntheticKind: kind},
				PeerIndex: -1, Summary: summary,
			})
		}
		result.Decision = Decision{
			State: AccessDisallowed, Evidence: uniqueEvidence(evidence),
			Explanation: "policy isolation or an explicit deny rule permits no destination ports",
		}
		return result
	}
	state := AccessAllowed
	explanation := "matching policy rules permit one or more destination ports"
	var warnings []string
	if unknown && !knownPermissions(permissions) {
		state = AccessUnknown
		explanation = "matching policy rules contain unresolved port constraints"
	} else if unknown {
		warnings = []string{"additional traffic may be affected by an unresolved port constraint"}
	}
	result.Decision = Decision{
		State: state, Permissions: permissions, Evidence: evidence,
		Explanation: explanation, Warnings: warnings,
	}
	return result
}

func permissionsForNormalizedRule(rule *normalizedRule, destination *corev1.Pod) []PortPermission {
	if rule.MatchNone || rule.NoPorts {
		return nil
	}
	if rule.TCPOnly && len(rule.Ports) == 0 {
		return []PortPermission{{Protocol: corev1.ProtocolTCP, All: true}}
	}
	permissions, _ := permissionsForPorts(rule.Ports, destination)
	return permissions
}

// combinePolicyLayers intersects network TCP permissions with the Istio
// authorization layer. Non-TCP network permissions pass through unchanged.
func combinePolicyLayers(network, authorization *layerDecision) layerDecision {
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
		Evidence:    uniqueEvidence(append(slices.Clone(network.Evidence), authorization.Evidence...)),
		Warnings:    uniqueStrings(append(slices.Clone(network.Warnings), authorization.Warnings...)),
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
	case len(permissions) == 0:
		decision.State = AccessDisallowed
		decision.Explanation = "network and authorization policy layers permit no common TCP traffic"
	default:
		decision.State = AccessUnknown
		decision.Explanation = "network and authorization policy layers have no definitely common ports"
	}
	return layerDecision{
		Decision:  decision,
		uncertain: uniqueStrings(append(slices.Clone(network.uncertain), authorization.uncertain...)),
	}
}

func evidenceHasExplicitRule(evidence []PolicyEvidence) bool {
	for index := range evidence {
		if evidence[index].RuleID.PolicyName != "" {
			return true
		}
	}
	return false
}

func (*engine) buildRules(x *snapshotIndex, subject *Subject, direction Direction, accumulator *ruleAccumulator) []RuleResult {
	rules := map[string]*RuleResult{}
	addSynthetic := func(kind string) {
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
	for _, subjectRef := range subject.Pods {
		pod := x.pods[key(subjectRef.Namespace, subjectRef.Name)]
		if pod == nil {
			continue
		}
		selection := x.selection(x.info(pod))
		for _, layer := range []policyLayer{policyLayerNetwork, policyLayerAuthorization} {
			layerSelection := selection.layer(direction, layer)
			for _, policy := range append(slices.Clone(layerSelection.policies), layerSelection.effectUnknown...) {
				policyDirection := policy.direction(direction)
				for index := range policyDirection.Rules {
					rule := &policyDirection.Rules[index]
					k := policy.ruleID(direction, rule).String()
					if rules[k] == nil {
						rules[k] = explicitRuleResult(policy, direction, rule)
					}
					rules[k].SubjectPodCount++
				}
			}
		}
		// Each layer explains its own isolation: an Istio ALLOW only isolates
		// TCP, so it must not turn the network row into a full default deny.
		if selection.layer(direction, policyLayerNetwork).isolated {
			addSynthetic(syntheticDefaultDeny)
		} else {
			addSynthetic(syntheticUnrestricted)
		}
		if selection.layer(direction, policyLayerAuthorization).isolated {
			addSynthetic(SyntheticAuthorizationDefaultDeny)
		}
	}
	out := make([]RuleResult, 0, len(rules))
	for k, rule := range rules {
		rule.Evidence = accumulator.evidence(k)
		for index := range rule.Evidence {
			rule.Permissions = append(rule.Permissions, rule.Evidence[index].Ports...)
		}
		rule.SubjectMatchCount = accumulator.subjectCount(k)
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
	if policy.SpecPath != "" {
		result.PolicySpec = policy.SpecPath
		result.PolicySpecCount = policy.SpecCount
	}
	result.PeerSummary = peerSummary(result.Peers)
	result.Permissions = permissionsForNormalizedRule(rule, nil)
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
		Summary: fmt.Sprintf("%s %s %s rule %d matched peer %d",
			policy.Type.Kind(), policy.reference(), rule.Action, rule.Index, peerIndex),
	}
}

func aggregateState(pairs []PairDecision, partialData bool) (state AccessState, explanation string) {
	if len(pairs) == 0 {
		if partialData {
			return AccessPartialData, "no concrete pod pairs are available in the partial snapshot"
		}
		return AccessUnknown, "no concrete pod pairs are available"
	}
	allowed, denied, unknown, partial := 0, 0, 0, 0
	for index := range pairs {
		switch pairs[index].Decision.State {
		case AccessAllowed:
			allowed++
		case AccessDisallowed:
			denied++
		case AccessPartialData:
			partial++
		default:
			unknown++
		}
	}
	if partialData {
		return AccessPartialData, fmt.Sprintf("snapshot is partial; observed %d allowed, %d denied, and %d unknown pairs", allowed, denied, unknown+partial)
	}
	if partial > 0 {
		return AccessPartialData, fmt.Sprintf("%d of %d concrete pod pairs depend on policy data that cannot be evaluated", partial, len(pairs))
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
		selection := x.selection(x.info(pod))
		for _, layer := range []policyLayer{policyLayerNetwork, policyLayerAuthorization} {
			layerSelection := selection.layer(direction, layer)
			for _, policy := range append(slices.Clone(layerSelection.policies), layerSelection.effectUnknown...) {
				policyDirection := policy.direction(direction)
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
						if len(peer.IPBlocks) == 0 && peerMatchesAddresses(peer) {
							allAddresses = true
						}
						for blockIndex := range peer.IPBlocks {
							addCIDR(refs, &peer.IPBlocks[blockIndex])
						}
					}
				}
			}
		}
	}
	if allAddresses {
		addCIDRRef(refs, &PrimitiveRef{Kind: PrimitiveCIDR, CIDR: allIPv4})
		addCIDRRef(refs, &PrimitiveRef{Kind: PrimitiveCIDR, CIDR: allIPv6})
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
	if left.Bits() > right.Bits() {
		left, right = right, left
	}
	if !left.Contains(right.Addr()) {
		return false
	}
	overlap := right
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

func permissionsKey(permissions []PortPermission) string {
	canonical := canonicalPermissions(permissions)
	values := make([]string, 0, len(canonical))
	for _, permission := range canonical {
		values = append(values, permissionKey(permission))
	}
	return "[" + strings.Join(values, " ") + "]"
}

func uniqueStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(in))
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
	target := id.String()
	for index := range evidence {
		if evidence[index].RuleID.String() == target {
			return true
		}
	}
	return false
}

// isDefaultDenyKind reports synthetic default-deny evidence. It is present on
// every denied pair of an isolated pod, so it never counts as a peer match.
func isDefaultDenyKind(kind string) bool {
	return kind == syntheticDefaultDeny || kind == SyntheticAuthorizationDefaultDeny
}

// evidenceHasDirection reports whether a real (non default-deny) rule in the
// given direction covers the pair. Synthetic default-deny evidence is present
// on every denied pair, so counting it would make peer matching degenerate to
// "always true". This mirrors evidencePermissionsForDirection, which skips the
// same synthetic kinds.
func evidenceHasDirection(evidence []PolicyEvidence, direction Direction) bool {
	for index := range evidence {
		item := &evidence[index]
		if item.RuleID.Direction != direction || isDefaultDenyKind(item.RuleID.SyntheticKind) {
			continue
		}
		return true
	}
	return false
}

func evidencePermissions(evidence []PolicyEvidence, id *RuleID) []PortPermission {
	var permissions []PortPermission
	target := id.String()
	for index := range evidence {
		item := &evidence[index]
		if item.RuleID.String() != target {
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
		if item.RuleID.Direction != direction || isDefaultDenyKind(item.RuleID.SyntheticKind) {
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
