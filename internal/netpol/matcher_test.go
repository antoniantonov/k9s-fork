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
		{"implicit egress when field present", netv1.NetworkPolicySpec{Egress: []netv1.NetworkPolicyEgressRule{}}, Egress, true},
		{"explicit egress", netv1.NetworkPolicySpec{PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress}}, Egress, true},
		{"explicit egress excludes ingress", netv1.NetworkPolicySpec{PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress}}, Ingress, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, policyHasDirection(&netv1.NetworkPolicy{Spec: test.spec}, test.direction))
		})
	}
}
