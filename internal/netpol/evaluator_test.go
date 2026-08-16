// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
)

func TestEvaluateEffectivePodAccess(t *testing.T) {
	base := testSnapshot()
	allowIngress := ingressPolicy("server-ingress", "server", []netv1.NetworkPolicyIngressRule{{
		From:  []netv1.NetworkPolicyPeer{{NamespaceSelector: selector(map[string]string{"team": "client"}), PodSelector: selector(map[string]string{"role": "client"})}},
		Ports: []netv1.NetworkPolicyPort{numericPolicyPort(80, 90)},
	}})
	denyIngress := ingressPolicy("server-ingress", "server", []netv1.NetworkPolicyIngressRule{})
	allowEgress := egressPolicy("client-egress", []netv1.NetworkPolicyEgressRule{{
		To:    []netv1.NetworkPolicyPeer{{NamespaceSelector: selector(map[string]string{"team": "server"}), PodSelector: selector(map[string]string{"role": "server"})}},
		Ports: []netv1.NetworkPolicyPort{numericPolicyPort(85, 0)},
	}})
	denyEgress := egressPolicy("client-egress", []netv1.NetworkPolicyEgressRule{})

	tests := []struct {
		name        string
		policies    []netv1.NetworkPolicy
		wantState   AccessState
		wantPorts   []string
		explanation string
	}{
		{"unrestricted both sides", nil, AccessAllowed, []string{"SCTP/all", "TCP/all", "UDP/all"}, "all concrete"},
		{"destination default deny", []netv1.NetworkPolicy{denyIngress}, AccessDisallowed, []string{}, "all concrete"},
		{"source default deny", []netv1.NetworkPolicy{allowIngress, denyEgress}, AccessDisallowed, []string{}, "all concrete"},
		{"both sides allow and ports intersect", []netv1.NetworkPolicy{allowIngress, allowEgress}, AccessAllowed, []string{"TCP/85"}, "all concrete"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := base
			snapshot.NetworkPolicies = test.policies
			result, err := NewEvaluator().EvaluateSubject(
				SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"},
				snapshot, Options{},
			)
			require.NoError(t, err)
			primitive := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
			require.Equal(t, test.wantState, primitive.State)
			require.Equal(t, test.wantPorts, permissionStrings(primitive.Permissions))
			require.Contains(t, primitive.Explanation, test.explanation)
			require.Len(t, primitive.PairDecisions, 1)
			require.NotEmpty(t, primitive.PairDecisions[0].Decision.Evidence)
		})
	}
}

func TestAdditivePoliciesPeerUnionEmptyPeersAndPorts(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.NetworkPolicies = []netv1.NetworkPolicy{
		ingressPolicy("deny-rule", "server", []netv1.NetworkPolicyIngressRule{{From: []netv1.NetworkPolicyPeer{{PodSelector: selector(map[string]string{"no": "match"})}}}}),
		ingressPolicy("allow-all-rule", "server", []netv1.NetworkPolicyIngressRule{{}}),
	}
	result, err := NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, snapshot, Options{},
	)
	require.NoError(t, err)
	primitive := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
	require.Equal(t, AccessAllowed, primitive.State)
	require.Equal(t, []string{"SCTP/all", "TCP/all", "UDP/all"}, permissionStrings(primitive.Permissions))
	foundMatch := false
	for _, evidence := range primitive.Evidence {
		foundMatch = foundMatch || evidence.RuleID.PolicyName == "allow-all-rule"
	}
	require.True(t, foundMatch)
}

func TestAggregateIsConservativeAndPartialSnapshotIsExplicit(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.Pods = append(snapshot.Pods, corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "client", Name: "other", UID: "other", Labels: map[string]string{"role": "other"},
	}})
	snapshot.NetworkPolicies = []netv1.NetworkPolicy{ingressPolicy("allow-client", "server", []netv1.NetworkPolicyIngressRule{{
		From: []netv1.NetworkPolicyPeer{{NamespaceSelector: selector(map[string]string{"team": "client"}), PodSelector: selector(map[string]string{"role": "client"})}},
	}})}

	result, err := NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, snapshot, Options{},
	)
	require.NoError(t, err)
	namespace := findPrimitive(t, result.Ingress, PrimitiveNamespace, "", "client")
	require.Equal(t, AccessPartial, namespace.State)
	require.Equal(t, 1, namespace.AllowedPairs)
	require.Equal(t, 2, namespace.TotalPairs)

	snapshot.Incomplete = map[string]error{"pods": errors.New("list timed out")}
	result, err = NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, snapshot, Options{},
	)
	require.NoError(t, err)
	namespace = findPrimitive(t, result.Ingress, PrimitiveNamespace, "", "client")
	require.Equal(t, AccessPartialData, namespace.State)
	require.Contains(t, namespace.Warnings[0], "incomplete")
	require.NotEmpty(t, result.Warnings)
}

func TestNamedPortsCIDRExceptAndAmbiguity(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.Pods[1].Spec.Containers = []corev1.Container{
		{Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}}},
		{Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8081}}},
	}

	http := intstr.FromString("http")
	snapshot.NetworkPolicies = []netv1.NetworkPolicy{
		ingressPolicy("named", "server", []netv1.NetworkPolicyIngressRule{{
			From:  []netv1.NetworkPolicyPeer{{NamespaceSelector: &metav1.LabelSelector{}}},
			Ports: []netv1.NetworkPolicyPort{{Port: &http}},
		}}),
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "server", Name: "cidr", UID: "cidr-policy"},
			Spec: netv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"role": "server"}},
				PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
				Ingress: []netv1.NetworkPolicyIngressRule{{From: []netv1.NetworkPolicyPeer{{IPBlock: &netv1.IPBlock{
					CIDR: "10.0.0.0/8", Except: []string{"10.1.0.0/16"},
				}}}}},
			},
		},
	}
	result, err := NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, snapshot, Options{},
	)
	require.NoError(t, err)
	pod := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
	require.Equal(t, AccessUnknown, pod.State)
	require.True(t, pod.Permissions[0].Unknown)

	cidr := findPrimitive(t, result.Ingress, PrimitiveCIDR, "", "")
	require.Equal(t, "10.0.0.0/8", cidr.Ref.CIDR)
	require.Equal(t, []string{"10.1.0.0/16"}, cidr.Ref.CIDRExcept)
	require.Equal(t, AccessAllowed, cidr.State)
}

func TestRulesApplicabilityStableSyntheticAndEffective(t *testing.T) {
	snapshot := testSnapshot()
	policy := ingressPolicy("allow", "server", []netv1.NetworkPolicyIngressRule{{
		From: []netv1.NetworkPolicyPeer{{NamespaceSelector: selector(map[string]string{"team": "client"})}},
	}})
	policy.UID = "allow-uid"
	snapshot.NetworkPolicies = []netv1.NetworkPolicy{policy, egressPolicy("deny", []netv1.NetworkPolicyEgressRule{})}
	result, err := NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, snapshot, Options{},
	)
	require.NoError(t, err)

	var rule RuleResult
	for _, candidate := range result.Ingress.Rules {
		if candidate.ID.PolicyName == "allow" {
			rule = candidate
		}
	}
	require.Equal(t, rule.StableID(), rule.ID.String())
	require.Equal(t, 1, rule.SubjectPodCount)
	require.Equal(t, 1, rule.SubjectMatchCount)
	require.Equal(t, "allow-uid", string(rule.ID.PolicyUID))
	require.Equal(t, "role=server", rule.PolicySelector)
	require.Len(t, rule.Peers, 1)
	require.Contains(t, rule.Peers[0], "namespaceSelector=team=client")
	require.Contains(t, rule.YAML, "ingress:")
	require.Contains(t, rule.YAML, "namespaceSelector: team=client")
	rows := NewEvaluator().RuleApplicability(result, Ingress, rule.ID, sets.New(PrimitivePod))
	clientRow := findApplicability(t, rows)
	require.True(t, clientRow.PeerMatches)
	require.False(t, clientRow.OppositeSideAllows)
	require.Equal(t, AccessDisallowed, clientRow.EffectiveState)

	foundDefaultDeny := false
	for _, candidate := range result.Ingress.Rules {
		if candidate.Synthetic && candidate.ID.SyntheticKind == "default-deny" {
			foundDefaultDeny = true
			require.Equal(t, "<synthetic>", candidate.PolicySelector)
			require.Contains(t, candidate.YAML, "kind: default-deny")
		}
	}
	require.True(t, foundDefaultDeny)
}

func TestRuleApplicabilityRequiresPortOverlap(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.NetworkPolicies = []netv1.NetworkPolicy{
		ingressPolicy("allow-http", "server", []netv1.NetworkPolicyIngressRule{{
			From:  []netv1.NetworkPolicyPeer{{NamespaceSelector: selector(map[string]string{"team": "client"})}},
			Ports: []netv1.NetworkPolicyPort{numericPolicyPort(80, 0)},
		}}),
		egressPolicy("allow-https", []netv1.NetworkPolicyEgressRule{{
			To:    []netv1.NetworkPolicyPeer{{NamespaceSelector: selector(map[string]string{"team": "server"})}},
			Ports: []netv1.NetworkPolicyPort{numericPolicyPort(443, 0)},
		}}),
	}

	result, err := NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, snapshot, Options{},
	)
	require.NoError(t, err)

	var ruleID RuleID
	for _, rule := range result.Ingress.Rules {
		if rule.ID.PolicyName == "allow-http" {
			ruleID = rule.ID
		}
	}
	row := findApplicability(t, NewEvaluator().RuleApplicability(result, Ingress, ruleID, sets.New(PrimitivePod)))
	require.True(t, row.PeerMatches)
	require.False(t, row.OppositeSideAllows)

	unknown := PortPermission{Protocol: corev1.ProtocolTCP, Unknown: true}
	primitive := PrimitiveResult{
		Ref: PrimitiveRef{Kind: PrimitivePod, Namespace: "client", Name: "client"},
		PairDecisions: []PairDecision{{Decision: Decision{
			State: AccessUnknown,
			Evidence: []PolicyEvidence{
				{RuleID: ruleID, Ports: []PortPermission{{Protocol: corev1.ProtocolTCP, All: true}}},
				{RuleID: RuleID{Direction: Egress, Index: 0}, Ports: []PortPermission{unknown}},
			},
		}}},
	}
	manual := SubjectResult{Ingress: DirectionResult{Primitives: map[PrimitiveKind][]PrimitiveResult{PrimitivePod: {primitive}}}}
	row = findApplicability(t, NewEvaluator().RuleApplicability(manual, Ingress, ruleID, sets.New(PrimitivePod)))
	require.False(t, row.OppositeSideAllows)
}

func TestDirectionApplicabilityEffectiveStates(t *testing.T) {
	tests := []struct {
		name      string
		snapshot  Snapshot
		kind      PrimitiveKind
		namespace string
		primitive string
		want      AccessState
	}{
		{
			name: "allowed",
			snapshot: func() Snapshot {
				snapshot := testSnapshot()
				snapshot.NetworkPolicies = []netv1.NetworkPolicy{ingressPolicy("allow-client", "server", []netv1.NetworkPolicyIngressRule{{
					From: []netv1.NetworkPolicyPeer{{NamespaceSelector: selector(map[string]string{"team": "client"})}},
				}})}
				return snapshot
			}(),
			kind: PrimitivePod, namespace: "client", primitive: "client", want: AccessAllowed,
		},
		{
			name: "disallowed",
			snapshot: func() Snapshot {
				snapshot := testSnapshot()
				snapshot.NetworkPolicies = []netv1.NetworkPolicy{ingressPolicy("deny-client", "server", []netv1.NetworkPolicyIngressRule{})}
				return snapshot
			}(),
			kind: PrimitivePod, namespace: "client", primitive: "client", want: AccessDisallowed,
		},
		{
			name: "partial",
			snapshot: func() Snapshot {
				snapshot := testSnapshot()
				snapshot.Pods = append(snapshot.Pods, corev1.Pod{ObjectMeta: metav1.ObjectMeta{
					Namespace: "client", Name: "other", UID: "other", Labels: map[string]string{"role": "other"},
				}})
				snapshot.NetworkPolicies = []netv1.NetworkPolicy{ingressPolicy("allow-client", "server", []netv1.NetworkPolicyIngressRule{{
					From: []netv1.NetworkPolicyPeer{{NamespaceSelector: selector(map[string]string{"team": "client"}), PodSelector: selector(map[string]string{"role": "client"})}},
				}})}
				return snapshot
			}(),
			kind: PrimitiveNamespace, primitive: "client", want: AccessPartial,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := NewEvaluator().EvaluateSubject(
				SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, test.snapshot, Options{},
			)
			require.NoError(t, err)
			rows := NewEvaluator().DirectionApplicability(result, Ingress, sets.New(test.kind))
			var row ApplicabilityRow
			found := false
			for index := range rows {
				candidate := &rows[index]
				if candidate.Primitive.Ref.Namespace == test.namespace && candidate.Primitive.Ref.Name == test.primitive {
					row = *candidate
					found = true
					break
				}
			}
			require.True(t, found)
			require.Equal(t, test.want, row.EffectiveState)
		})
	}
}

func TestRuleApplicabilityZeroPodPairsIsUnknown(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.Namespaces = append(snapshot.Namespaces, corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: "empty", Labels: map[string]string{"team": "empty"},
	}})
	snapshot.NetworkPolicies = []netv1.NetworkPolicy{ingressPolicy("allow-all", "server", []netv1.NetworkPolicyIngressRule{{}})}

	result, err := NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, snapshot, Options{},
	)
	require.NoError(t, err)

	var ruleID RuleID
	for _, rule := range result.Ingress.Rules {
		if rule.ID.PolicyName == "allow-all" {
			ruleID = rule.ID
		}
	}
	require.NotEmpty(t, ruleID.PolicyName)

	primitive := findPrimitive(t, result.Ingress, PrimitiveNamespace, "", "empty")
	require.Zero(t, primitive.TotalPairs)

	findRow := func(rows []ApplicabilityRow) ApplicabilityRow {
		t.Helper()
		for index := range rows {
			row := &rows[index]
			if row.Primitive.Ref.ID() == primitive.Ref.ID() {
				return *row
			}
		}
		require.FailNow(t, "applicability row not found", "%s", primitive.Ref.ID())
		return ApplicabilityRow{}
	}

	ruleRow := findRow(NewEvaluator().RuleApplicability(result, Ingress, ruleID, sets.New(PrimitiveNamespace)))
	require.Zero(t, ruleRow.Primitive.TotalPairs)
	require.Equal(t, AccessUnknown, ruleRow.EffectiveState)

	directionRow := findRow(NewEvaluator().DirectionApplicability(result, Ingress, sets.New(PrimitiveNamespace)))
	require.Equal(t, AccessUnknown, directionRow.EffectiveState)
}

// A peer that matches no rule must report PeerMatches=false in the aggregate,
// exactly as it does per-rule. Synthetic default-deny evidence is attached to
// every denied pair, so counting it would make this column always true and
// contradict the State column.
func TestDirectionApplicabilityPeerMatchesExcludesDefaultDeny(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.NetworkPolicies = []netv1.NetworkPolicy{
		ingressPolicy("narrow", "server", []netv1.NetworkPolicyIngressRule{{
			From: []netv1.NetworkPolicyPeer{{
				PodSelector:       selector(map[string]string{"role": "absent"}),
				NamespaceSelector: &metav1.LabelSelector{},
			}},
		}}),
	}
	result, err := NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, snapshot, Options{},
	)
	require.NoError(t, err)

	var ruleID RuleID
	for _, rule := range result.Ingress.Rules {
		if rule.ID.PolicyName == "narrow" {
			ruleID = rule.ID
		}
	}
	directionRows := NewEvaluator().DirectionApplicability(result, Ingress, sets.New(PrimitivePod))
	ruleRows := NewEvaluator().RuleApplicability(result, Ingress, ruleID, sets.New(PrimitivePod))
	require.NotEmpty(t, directionRows)
	require.Len(t, ruleRows, len(directionRows))

	for index := range directionRows {
		row := &directionRows[index]
		require.Equal(t, AccessDisallowed, row.EffectiveState, "no peer is selected by the rule")
		require.False(t, row.PeerMatches,
			"peer %q matches no rule, so the aggregate must not claim a peer match", row.Primitive.Ref.Name)
		require.False(t, row.OppositeSideAllows,
			"a peer with no matching rule cannot be reported as fully allowed")
		require.Equal(t, ruleRows[index].PeerMatches, row.PeerMatches,
			"aggregate and per-rule peer matching must agree when only one rule exists")
	}
}

func TestDirectionApplicabilityCIDRMatchesRuleConvention(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.NetworkPolicies = []netv1.NetworkPolicy{ingressPolicy("cidr", "server", []netv1.NetworkPolicyIngressRule{{From: []netv1.NetworkPolicyPeer{{
		IPBlock: &netv1.IPBlock{CIDR: "10.0.0.0/8"},
	}}}})}
	result, err := NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, snapshot, Options{},
	)
	require.NoError(t, err)
	var ruleID RuleID
	for _, rule := range result.Ingress.Rules {
		if rule.ID.PolicyName == "cidr" {
			ruleID = rule.ID
		}
	}
	directionRows := NewEvaluator().DirectionApplicability(result, Ingress, sets.New(PrimitiveCIDR))
	ruleRows := NewEvaluator().RuleApplicability(result, Ingress, ruleID, sets.New(PrimitiveCIDR))
	require.Len(t, directionRows, 1)
	require.Len(t, ruleRows, 1)
	require.Equal(t, ruleRows[0].PeerMatches, directionRows[0].PeerMatches)
	require.Equal(t, ruleRows[0].OppositeSideAllows, directionRows[0].OppositeSideAllows)
	require.Equal(t, ruleRows[0].EffectiveState, directionRows[0].EffectiveState)
}

func TestDirectionApplicabilityPreservesPartialData(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.Incomplete = map[string]error{"pods": errors.New("list timed out")}
	result, err := NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, snapshot, Options{},
	)
	require.NoError(t, err)
	row := findApplicability(t, NewEvaluator().DirectionApplicability(result, Ingress, sets.New(PrimitivePod)))
	require.Equal(t, AccessPartialData, row.Primitive.State)
	require.Equal(t, AccessPartialData, row.EffectiveState)
}

func TestDirectionApplicabilityFiltersKinds(t *testing.T) {
	result, err := NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, testSnapshot(), Options{},
	)
	require.NoError(t, err)
	rows := NewEvaluator().DirectionApplicability(result, Ingress, sets.New(PrimitivePod))
	require.NotEmpty(t, rows)
	for _, row := range rows {
		require.Equal(t, PrimitivePod, row.Primitive.Ref.Kind)
	}
	require.Empty(t, NewEvaluator().DirectionApplicability(result, Ingress, sets.New[PrimitiveKind]()))
}

func TestDirectionApplicabilityMatchesSingleRuleApplicability(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.NetworkPolicies = []netv1.NetworkPolicy{ingressPolicy("allow-all", "server", []netv1.NetworkPolicyIngressRule{{}})}
	result, err := NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, snapshot, Options{},
	)
	require.NoError(t, err)
	var ruleID RuleID
	for _, rule := range result.Ingress.Rules {
		if rule.ID.PolicyName == "allow-all" {
			ruleID = rule.ID
		}
	}
	directionRows := NewEvaluator().DirectionApplicability(result, Ingress, sets.New(PrimitivePod, PrimitiveCIDR))
	ruleRows := NewEvaluator().RuleApplicability(result, Ingress, ruleID, sets.New(PrimitivePod, PrimitiveCIDR))
	require.Len(t, directionRows, len(ruleRows))
	for index := range ruleRows {
		require.Equal(t, ruleRows[index].Primitive.Ref, directionRows[index].Primitive.Ref)
		require.Equal(t, ruleRows[index].EffectiveState, directionRows[index].EffectiveState)
		require.Equal(t, ruleRows[index].PeerMatches, directionRows[index].PeerMatches)
	}
}

func TestCIDRSetSemanticsAndEmptyPeers(t *testing.T) {
	block := &netv1.IPBlock{CIDR: "10.0.0.0/8", Except: []string{"10.0.0.0/9"}}
	require.True(t, ipBlockIntersects(block, &PrimitiveRef{Kind: PrimitiveCIDR, CIDR: "10.128.0.0/9"}))
	require.False(t, ipBlockIntersects(block, &PrimitiveRef{Kind: PrimitiveCIDR, CIDR: "10.1.0.0/16"}))
	require.False(t, ipBlockIntersects(block, &PrimitiveRef{
		Kind: PrimitiveCIDR, CIDR: "10.0.0.0/8", CIDRExcept: []string{"10.128.0.0/9"},
	}))
	refs := map[string]PrimitiveRef{}
	addCIDR(refs, &netv1.IPBlock{CIDR: "10.1.2.3/8", Except: []string{"10.2.3.4/16"}})
	require.Contains(t, refs, PrimitiveRef{Kind: PrimitiveCIDR, CIDR: "10.0.0.0/8", CIDRExcept: []string{"10.2.0.0/16"}}.ID())

	snapshot := testSnapshot()
	snapshot.NetworkPolicies = []netv1.NetworkPolicy{ingressPolicy("all-addresses", "server", []netv1.NetworkPolicyIngressRule{{}})}
	result, err := NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, snapshot, Options{},
	)
	require.NoError(t, err)
	require.Len(t, result.Ingress.Primitives[PrimitiveCIDR], 2)
	require.Empty(t, result.Egress.Primitives[PrimitiveCIDR])
	for index := range result.Ingress.Primitives[PrimitiveCIDR] {
		require.Equal(t, AccessAllowed, result.Ingress.Primitives[PrimitiveCIDR][index].State)
	}
}

func TestWorkloadPrimitiveOwnershipFallbackIsUncertainOnlyWhenIncomplete(t *testing.T) {
	selector := selector(map[string]string{"app": "worker"})
	snapshot := testSnapshot()
	snapshot.Deployments = []appsv1.Deployment{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "server", Name: "scaled-zero", UID: "deployment"},
		Spec:       appsv1.DeploymentSpec{Selector: selector},
	}}
	snapshot.Jobs = []batchv1.Job{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "server", Name: "finished", UID: "job"},
		Spec:       batchv1.JobSpec{Selector: selector},
	}}
	snapshot.Pods = append(snapshot.Pods, corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "server", Name: "similarly-labeled", Labels: map[string]string{"app": "worker"},
	}})

	result, err := NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, snapshot, Options{},
	)
	require.NoError(t, err)
	deployment := findPrimitive(t, result.Ingress, PrimitiveDeployment, "server", "scaled-zero")
	job := findPrimitive(t, result.Ingress, PrimitiveJob, "server", "finished")
	require.Zero(t, deployment.TotalPairs)
	require.Zero(t, job.TotalPairs)
	require.Empty(t, deployment.Warnings)
	require.Empty(t, job.Warnings)

	snapshot.Incomplete = map[string]error{"replicasets": errors.New("forbidden")}
	result, err = NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, snapshot, Options{},
	)
	require.NoError(t, err)
	deployment = findPrimitive(t, result.Ingress, PrimitiveDeployment, "server", "scaled-zero")
	require.Equal(t, AccessPartialData, deployment.State)
	require.NotZero(t, deployment.TotalPairs)
	require.Contains(t, deployment.Warnings[0], "incomplete")

	snapshot.Incomplete = map[string]error{"pods": errors.New("forbidden")}
	result, err = NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, snapshot, Options{},
	)
	require.NoError(t, err)
	job = findPrimitive(t, result.Ingress, PrimitiveJob, "server", "finished")
	require.Equal(t, AccessPartialData, job.State)
	require.NotZero(t, job.TotalPairs)
}

func TestResultLimitAndGeneratedAt(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.GeneratedAt = time.Unix(123, 0)
	result, err := NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, snapshot, Options{ResultLimit: 2},
	)
	require.NoError(t, err)
	require.True(t, result.Truncated)
	require.Equal(t, 2, result.ResultLimit)
	require.Equal(t, snapshot.GeneratedAt, result.GeneratedAt)
	total := 0
	for _, direction := range []DirectionResult{result.Ingress, result.Egress} {
		for _, list := range direction.Primitives {
			total += len(list)
		}
	}
	require.Equal(t, 4, total)
	require.Len(t, result.Ingress.Primitives[PrimitivePod], 2)
	require.Len(t, result.Egress.Primitives[PrimitivePod], 2)
	require.Contains(t, result.Warnings[len(result.Warnings)-1], "truncated")
}

func TestResultLimitBoundsPairsIndependentlyPerDirection(t *testing.T) {
	snapshot := testSnapshot()
	for i := range 8 {
		snapshot.Pods = append(snapshot.Pods, corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "server", Name: fmt.Sprintf("server-%d", i), UID: typesUID(fmt.Sprintf("server-%d", i)),
		}})
	}
	result, err := NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectNamespace, Name: "server"}, snapshot, Options{ResultLimit: 3},
	)
	require.NoError(t, err)
	require.True(t, result.Truncated)
	for _, direction := range []DirectionResult{result.Ingress, result.Egress} {
		candidates, pairs := 0, 0
		for _, primitives := range direction.Primitives {
			candidates += len(primitives)
			for _, primitive := range primitives {
				pairs += len(primitive.PairDecisions)
			}
		}
		require.LessOrEqual(t, candidates, 3)
		require.Equal(t, 3, pairs)
	}
}

func testSnapshot() Snapshot {
	return Snapshot{
		Namespaces: []corev1.Namespace{
			{ObjectMeta: metav1.ObjectMeta{Name: "client", Labels: map[string]string{"team": "client"}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "server", Labels: map[string]string{"team": "server"}}},
		},
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Namespace: "client", Name: "client", UID: "client", Labels: map[string]string{"role": "client"}}},
			{ObjectMeta: metav1.ObjectMeta{Namespace: "server", Name: "server", UID: "server", Labels: map[string]string{"role": "server"}}},
		},
	}
}

func ingressPolicy(name, namespace string, rules []netv1.NetworkPolicyIngressRule) netv1.NetworkPolicy {
	return netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: typesUID(name)},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"role": "server"}},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
			Ingress:     rules,
		},
	}
}

func egressPolicy(name string, rules []netv1.NetworkPolicyEgressRule) netv1.NetworkPolicy {
	return netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "client", Name: name, UID: typesUID(name)},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"role": "client"}},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
			Egress:      rules,
		},
	}
}

func selector(labels map[string]string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchLabels: labels}
}

func numericPolicyPort(start, end int32) netv1.NetworkPolicyPort {
	port := intstr.FromInt32(start)
	result := netv1.NetworkPolicyPort{Port: &port}
	if end != 0 {
		result.EndPort = &end
	}
	return result
}

func findPrimitive(t *testing.T, result DirectionResult, kind PrimitiveKind, namespace, name string) PrimitiveResult {
	t.Helper()
	for index := range result.Primitives[kind] {
		primitive := &result.Primitives[kind][index]
		if primitive.Ref.Namespace == namespace && primitive.Ref.Name == name {
			return *primitive
		}
	}
	require.FailNow(t, "primitive not found", "%s %s/%s", kind, namespace, name)
	return PrimitiveResult{}
}

func findApplicability(t *testing.T, rows []ApplicabilityRow) ApplicabilityRow {
	t.Helper()
	for index := range rows {
		row := &rows[index]
		if row.Primitive.Ref.Namespace == "client" && row.Primitive.Ref.Name == "client" {
			return *row
		}
	}
	require.FailNow(t, "applicability row not found")
	return ApplicabilityRow{}
}

func typesUID(value string) types.UID {
	return types.UID(value)
}

func TestDefiniteAdditiveAllowSurvivesAmbiguousNamedPort(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.Pods[1].Spec.Containers = []corev1.Container{
		{Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}}},
		{Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8081}}},
	}
	http := intstr.FromString("http")
	snapshot.NetworkPolicies = []netv1.NetworkPolicy{
		ingressPolicy("numeric", "server", []netv1.NetworkPolicyIngressRule{{
			From:  []netv1.NetworkPolicyPeer{{NamespaceSelector: &metav1.LabelSelector{}}},
			Ports: []netv1.NetworkPolicyPort{numericPolicyPort(80, 0)},
		}}),
		ingressPolicy("ambiguous", "server", []netv1.NetworkPolicyIngressRule{{
			From:  []netv1.NetworkPolicyPeer{{NamespaceSelector: &metav1.LabelSelector{}}},
			Ports: []netv1.NetworkPolicyPort{{Port: &http}},
		}}),
	}

	result, err := NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, snapshot, Options{},
	)
	require.NoError(t, err)
	pod := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
	require.Equal(t, AccessAllowed, pod.State)
	require.Contains(t, permissionStrings(pod.Permissions), "TCP/80")
	require.NotEmpty(t, pod.Warnings)
}

func TestRuleApplicabilityRequiresEveryPrimitivePairToMatch(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.Pods = append(snapshot.Pods, corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "server", Name: "unselected", UID: "unselected", Labels: map[string]string{"role": "other"},
	}})
	snapshot.NetworkPolicies = []netv1.NetworkPolicy{ingressPolicy("allow-client", "server", []netv1.NetworkPolicyIngressRule{{
		From: []netv1.NetworkPolicyPeer{{NamespaceSelector: selector(map[string]string{"team": "client"})}},
	}})}
	result, err := NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectNamespace, Name: "server"}, snapshot, Options{},
	)
	require.NoError(t, err)
	var ruleID RuleID
	for _, rule := range result.Ingress.Rules {
		if rule.ID.PolicyName == "allow-client" {
			ruleID = rule.ID
		}
	}
	row := findApplicability(t, NewEvaluator().RuleApplicability(result, Ingress, ruleID, sets.New(PrimitivePod)))
	require.True(t, row.PeerMatches)
	require.False(t, row.OppositeSideAllows)
	require.Equal(t, AccessPartial, row.EffectiveState)
}

func TestCIDRPrimitivesAreSubjectApplicableAndRequireFullContainment(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.Pods = append(snapshot.Pods, corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "server", Name: "other", UID: "other", Labels: map[string]string{"role": "other"},
	}})
	selectedExcept := ingressPolicy("selected-except", "server", []netv1.NetworkPolicyIngressRule{{From: []netv1.NetworkPolicyPeer{{
		IPBlock: &netv1.IPBlock{CIDR: "10.0.0.0/8", Except: []string{"10.0.0.0/9"}},
	}}}})
	otherAll := ingressPolicy("other-all", "server", []netv1.NetworkPolicyIngressRule{{From: []netv1.NetworkPolicyPeer{{
		IPBlock: &netv1.IPBlock{CIDR: "10.0.0.0/8"},
	}}}})
	otherAll.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"role": "other"}}
	unrelated := ingressPolicy("unrelated", "client", []netv1.NetworkPolicyIngressRule{{}})
	snapshot.NetworkPolicies = []netv1.NetworkPolicy{selectedExcept, otherAll, unrelated}

	result, err := NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectNamespace, Name: "server"}, snapshot, Options{},
	)
	require.NoError(t, err)
	cidrs := result.Ingress.Primitives[PrimitiveCIDR]
	require.Len(t, cidrs, 2)
	for _, primitive := range cidrs {
		require.NotEqual(t, "0.0.0.0/0", primitive.Ref.CIDR)
		if len(primitive.Ref.CIDRExcept) == 0 {
			require.Equal(t, AccessPartial, primitive.State)
			require.Equal(t, 1, primitive.AllowedPairs)
			require.Equal(t, 2, primitive.TotalPairs)
		}
	}
	require.False(t, ipBlockContains(
		&netv1.IPBlock{CIDR: "10.0.0.0/8", Except: []string{"10.0.0.0/9"}},
		&PrimitiveRef{Kind: PrimitiveCIDR, CIDR: "10.0.0.0/8"},
	))
}
