// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPeerMatchesPodSelectorSemantics(t *testing.T) {
	empty := metav1.LabelSelector{}
	appA := metav1.LabelSelector{MatchLabels: map[string]string{"app": "a"}}
	teamBlue := metav1.LabelSelector{MatchLabels: map[string]string{"team": "blue"}}
	byName := metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "blue"}}
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "blue", Name: "pod", Labels: map[string]string{"app": "a"}}}
	namespace := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "blue", Labels: map[string]string{"team": "blue"}}}

	tests := []struct {
		name            string
		peer            netv1.NetworkPolicyPeer
		policyNamespace string
		missingNS       bool
		want            matchResult
	}{
		{"both absent means same namespace", netv1.NetworkPolicyPeer{}, "blue", false, matchYes},
		{"both absent rejects other namespace", netv1.NetworkPolicyPeer{}, "red", false, matchNo},
		{"present empty namespace selects all namespaces", netv1.NetworkPolicyPeer{NamespaceSelector: &empty}, "red", false, matchYes},
		{"pod selector is namespace local", netv1.NetworkPolicyPeer{PodSelector: &appA}, "blue", false, matchYes},
		{"pod selector rejects other namespace", netv1.NetworkPolicyPeer{PodSelector: &appA}, "red", false, matchNo},
		{"selectors intersect", netv1.NetworkPolicyPeer{PodSelector: &appA, NamespaceSelector: &teamBlue}, "red", false, matchYes},
		{"ip block does not match pods", netv1.NetworkPolicyPeer{IPBlock: &netv1.IPBlock{CIDR: "10.0.0.0/8"}}, "blue", false, matchNo},
		// The immutable kubernetes.io/metadata.name label is always present,
		// even when the Namespace object is missing from the snapshot.
		{"metadata name label is injected", netv1.NetworkPolicyPeer{NamespaceSelector: &byName}, "red", false, matchYes},
		{"empty namespace selector matches missing namespace", netv1.NetworkPolicyPeer{NamespaceSelector: &empty}, "red", true, matchYes},
		{"metadata name matches missing namespace", netv1.NetworkPolicyPeer{NamespaceSelector: &byName}, "red", true, matchYes},
		{"missing namespace has no other labels", netv1.NetworkPolicyPeer{NamespaceSelector: &teamBlue}, "red", true, matchNo},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := Snapshot{Pods: []corev1.Pod{pod}}
			if !test.missingNS {
				snapshot.Namespaces = []corev1.Namespace{namespace}
			}
			x := newSnapshotIndex(&snapshot)
			policy := normalizeNetworkPolicy(&netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: test.policyNamespace, Name: "policy"},
				Spec:       netv1.NetworkPolicySpec{Ingress: []netv1.NetworkPolicyIngressRule{{From: []netv1.NetworkPolicyPeer{test.peer}}}},
			})
			peer := &policy.Ingress.Rules[0].Peers[0]
			require.Equal(t, test.want, peerMatchesPod(peer, policy, x.info(&snapshot.Pods[0])))
		})
	}
}

func TestRulePeerUnionAndEmpty(t *testing.T) {
	snapshot := Snapshot{
		Pods:       []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod", Labels: map[string]string{"app": "a"}}}},
		Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "ns"}}},
	}
	x := newSnapshotIndex(&snapshot)
	noMatch := metav1.LabelSelector{MatchLabels: map[string]string{"app": "b"}}
	match := metav1.LabelSelector{MatchLabels: map[string]string{"app": "a"}}
	policy := normalizeNetworkPolicy(&netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "policy"},
		Spec: netv1.NetworkPolicySpec{Ingress: []netv1.NetworkPolicyIngressRule{
			{},
			{From: []netv1.NetworkPolicyPeer{{PodSelector: &noMatch}, {PodSelector: &match}}},
		}},
	})
	matcher := podMatcher{x: x, peer: x.info(&snapshot.Pods[0])}

	result := matcher.match(policy, Ingress, &policy.Ingress.Rules[0])
	require.True(t, result.matched)
	require.Equal(t, -1, result.peerIndex)

	result = matcher.match(policy, Ingress, &policy.Ingress.Rules[1])
	require.True(t, result.matched)
	require.Equal(t, 1, result.peerIndex)
	require.Empty(t, result.uncertain)
}

func TestPolicyDirectionDefaults(t *testing.T) {
	tests := []struct {
		name      string
		spec      netv1.NetworkPolicySpec
		direction Direction
		want      bool
	}{
		{"implicit ingress", netv1.NetworkPolicySpec{}, Ingress, true},
		{"implicit no egress", netv1.NetworkPolicySpec{}, Egress, false},
		{"empty egress does not default egress", netv1.NetworkPolicySpec{Egress: []netv1.NetworkPolicyEgressRule{}}, Egress, false},
		{"nonempty egress defaults egress", netv1.NetworkPolicySpec{Egress: []netv1.NetworkPolicyEgressRule{{}}}, Egress, true},
		{"egress rules still default ingress", netv1.NetworkPolicySpec{Egress: []netv1.NetworkPolicyEgressRule{{}}}, Ingress, true},
		{"explicit egress", netv1.NetworkPolicySpec{PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress}}, Egress, true},
		{"explicit egress excludes ingress", netv1.NetworkPolicySpec{PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress}}, Ingress, false},
		{"explicit ingress excludes egress", netv1.NetworkPolicySpec{PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress}}, Egress, false},
		{"explicit empty egress isolates", netv1.NetworkPolicySpec{
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress}, Egress: []netv1.NetworkPolicyEgressRule{},
		}, Egress, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, policyHasDirection(&netv1.NetworkPolicy{Spec: test.spec}, test.direction))
		})
	}
}

func TestNativeSelectorExpressionBoundaries(t *testing.T) {
	tests := []struct {
		name     string
		operator metav1.LabelSelectorOperator
		values   []string
		want     []bool
	}{
		{"in", metav1.LabelSelectorOpIn, []string{"client"}, []bool{true, false, false}},
		{"not-in", metav1.LabelSelectorOpNotIn, []string{"client"}, []bool{false, true, true}},
		{"exists", metav1.LabelSelectorOpExists, nil, []bool{true, true, false}},
		{"does-not-exist", metav1.LabelSelectorOpDoesNotExist, nil, []bool{false, false, true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := testSnapshot()
			requirement := metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key: "role", Operator: test.operator, Values: test.values,
			}}}
			policy := ingressPolicy("expressions", "server", []netv1.NetworkPolicyIngressRule{{
				From: []netv1.NetworkPolicyPeer{{
					NamespaceSelector: selector(map[string]string{"team": "client"}), PodSelector: &requirement,
				}},
				Ports: []netv1.NetworkPolicyPort{numericPolicyPort(8080, 0)},
			}})
			snapshot.NetworkPolicies = []netv1.NetworkPolicy{policy}
			for index, role := range []string{"client", "other", ""} {
				snapshot.Pods[0].Labels = map[string]string{}
				if role != "" {
					snapshot.Pods[0].Labels["role"] = role
				}
				result := evaluateServer(t, &snapshot)
				peer := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
				if test.want[index] {
					require.Equal(t, AccessAllowed, peer.State, "role=%q", role)
					require.Equal(t, []string{"TCP/8080"}, permissionStrings(peer.Permissions))
				} else {
					require.Equal(t, AccessDisallowed, peer.State, "role=%q", role)
					require.Empty(t, peer.Permissions)
				}
				require.Empty(t, peer.Warnings)
			}
			snapshot.Pods[0].Labels = map[string]string{"role": "client"}
			snapshot.Namespaces[0].Labels["team"] = "other"
			result := evaluateServer(t, &snapshot)
			require.Equal(t, AccessDisallowed,
				findPrimitive(t, result.Ingress, PrimitivePod, "client", "client").State,
				"namespace and pod expressions are conjunctive")
		})
	}
}

func TestNativeEmptyEgressBeforeAPIDefaulting(t *testing.T) {
	// API-server snapshots already contain policyTypes; this raw-object
	// regression checks that local defaulting agrees with API admission.
	snapshot := testSnapshot()
	policy := ingressPolicy("raw-defaults", "server", nil)
	policy.Spec.PolicyTypes = nil
	policy.Spec.Egress = []netv1.NetworkPolicyEgressRule{}
	snapshot.NetworkPolicies = []netv1.NetworkPolicy{policy}
	result := evaluateServer(t, &snapshot)
	require.Equal(t, AccessDisallowed, findPrimitive(t, result.Ingress, PrimitivePod, "client", "client").State)
	egress := findPrimitive(t, result.Egress, PrimitivePod, "client", "client")
	require.Equal(t, AccessAllowed, egress.State)
	require.Equal(t, []string{"SCTP/all", "TCP/all", "UDP/all"}, permissionStrings(egress.Permissions))
	require.Empty(t, egress.Warnings)
}
