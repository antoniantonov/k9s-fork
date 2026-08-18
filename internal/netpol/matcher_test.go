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
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "blue", Labels: map[string]string{"app": "a"}}}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "blue", Labels: map[string]string{"team": "blue"}}}

	tests := []struct {
		name            string
		peer            netv1.NetworkPolicyPeer
		policyNamespace string
		want            bool
	}{
		{"both absent means same namespace", netv1.NetworkPolicyPeer{}, "blue", true},
		{"both absent rejects other namespace", netv1.NetworkPolicyPeer{}, "red", false},
		{"present empty namespace selects all namespaces", netv1.NetworkPolicyPeer{NamespaceSelector: &empty}, "red", true},
		{"pod selector is namespace local", netv1.NetworkPolicyPeer{PodSelector: &appA}, "blue", true},
		{"pod selector rejects other namespace", netv1.NetworkPolicyPeer{PodSelector: &appA}, "red", false},
		{"selectors intersect", netv1.NetworkPolicyPeer{PodSelector: &appA, NamespaceSelector: &teamBlue}, "red", true},
		{"ip block does not match pods", netv1.NetworkPolicyPeer{IPBlock: &netv1.IPBlock{CIDR: "10.0.0.0/8"}}, "blue", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, peerMatchesPod(test.peer, test.policyNamespace, pod, namespace))
		})
	}
}

func TestRulePeerUnionAndEmpty(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Labels: map[string]string{"app": "a"}}}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns"}}
	noMatch := metav1.LabelSelector{MatchLabels: map[string]string{"app": "b"}}
	match := metav1.LabelSelector{MatchLabels: map[string]string{"app": "a"}}

	ok, index := rulePeersMatch(nil, "ns", pod, namespace)
	require.True(t, ok)
	require.Equal(t, -1, index)

	ok, index = rulePeersMatch([]netv1.NetworkPolicyPeer{{PodSelector: &noMatch}, {PodSelector: &match}}, "ns", pod, namespace)
	require.True(t, ok)
	require.Equal(t, 1, index)
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
