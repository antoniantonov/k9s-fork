// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func matchesSelector(selector metav1.LabelSelector, set map[string]string) bool {
	s, err := metav1.LabelSelectorAsSelector(&selector)
	return err == nil && s.Matches(labels.Set(set))
}

func matchesSelectorPtr(selector *metav1.LabelSelector, set map[string]string) bool {
	return selector != nil && matchesSelector(*selector, set)
}

func policySelectsPod(policy *netv1.NetworkPolicy, pod *corev1.Pod) bool {
	return policy.Namespace == pod.Namespace && matchesSelector(policy.Spec.PodSelector, pod.Labels)
}

func peerMatchesPod(peer netv1.NetworkPolicyPeer, policyNamespace string, pod *corev1.Pod, namespace *corev1.Namespace) bool {
	if peer.IPBlock != nil {
		return false
	}
	if peer.NamespaceSelector == nil && pod.Namespace != policyNamespace {
		return false
	}
	if peer.NamespaceSelector != nil {
		if namespace == nil || !matchesSelector(*peer.NamespaceSelector, namespace.Labels) {
			return false
		}
	}
	if peer.PodSelector != nil && !matchesSelector(*peer.PodSelector, pod.Labels) {
		return false
	}
	return true
}

func rulePeersMatch(
	peers []netv1.NetworkPolicyPeer,
	policyNamespace string,
	pod *corev1.Pod,
	namespace *corev1.Namespace,
) (matches bool, peerIndex int) {
	if len(peers) == 0 {
		return true, -1
	}
	for i, peer := range peers {
		if peerMatchesPod(peer, policyNamespace, pod, namespace) {
			return true, i
		}
	}
	return false, -1
}

func policyHasDirection(policy *netv1.NetworkPolicy, direction Direction) bool {
	if len(policy.Spec.PolicyTypes) == 0 {
		if direction == Ingress {
			return true
		}
		return policy.Spec.Egress != nil
	}
	want := netv1.PolicyTypeIngress
	if direction == Egress {
		want = netv1.PolicyTypeEgress
	}
	for _, policyType := range policy.Spec.PolicyTypes {
		if policyType == want {
			return true
		}
	}
	return false
}
