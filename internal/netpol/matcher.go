// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
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
