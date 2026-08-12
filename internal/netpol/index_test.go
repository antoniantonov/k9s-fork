// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSnapshotIndexIsTypedSortedAndReportsPartialData(t *testing.T) {
	x := newSnapshotIndex(&Snapshot{
		Pods: []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod"}}},
		NetworkPolicies: []netv1.NetworkPolicy{
			{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "z"}},
			{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "a"}},
		},
		Incomplete: map[string]error{"pods": errors.New("forbidden"), "jobs": nil},
	})
	require.Equal(t, "pod", x.pods[key("ns", "pod")].Name)
	require.Equal(t, []string{"a", "z"}, []string{x.policies["ns"][0].Name, x.policies["ns"][1].Name})
	require.Equal(t, []string{
		`snapshot resource "jobs" is incomplete`,
		`snapshot resource "pods" is incomplete: forbidden`,
	}, x.incomplete)
}
