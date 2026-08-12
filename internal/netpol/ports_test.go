// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestPermissionsForPorts(t *testing.T) {
	tcp := corev1.ProtocolTCP
	udp := corev1.ProtocolUDP
	end := int32(90)
	http := intstr.FromString("http")
	absent := intstr.FromString("absent")
	numeric := intstr.FromInt32(80)
	pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{
		{Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}, {Name: "dns", ContainerPort: 53, Protocol: udp}}},
	}}}

	tests := []struct {
		name  string
		ports []netv1.NetworkPolicyPort
		pod   *corev1.Pod
		want  []string
		known bool
	}{
		{"empty means all protocols", nil, pod, []string{"SCTP/all", "TCP/all", "UDP/all"}, true},
		{"nil port means protocol all", []netv1.NetworkPolicyPort{{Protocol: &udp}}, pod, []string{"UDP/all"}, true},
		{"numeric range", []netv1.NetworkPolicyPort{{Protocol: &tcp, Port: &numeric, EndPort: &end}}, pod, []string{"TCP/80-90"}, true},
		{"named resolves on destination", []netv1.NetworkPolicyPort{{Port: &http}}, pod, []string{"TCP/8080"}, true},
		{"missing name allows nothing", []netv1.NetworkPolicyPort{{Port: &absent}}, pod, []string{}, true},
		{"external named port is unknown", []netv1.NetworkPolicyPort{{Port: &http}}, nil, []string{"unknown"}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, known := permissionsForPorts(test.ports, test.pod)
			require.Equal(t, test.known, known)
			require.Equal(t, test.want, permissionStrings(got))
		})
	}
}

func TestAmbiguousNamedPortAndIntersections(t *testing.T) {
	http := intstr.FromString("http")
	pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{
		{Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}}},
		{Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8081}}},
	}}}
	got, known := permissionsForPorts([]netv1.NetworkPolicyPort{{Port: &http}}, pod)
	require.False(t, known)
	require.True(t, got[0].Unknown)

	aStart, aEnd := intstr.FromInt32(80), int32(100)
	bStart, bEnd := intstr.FromInt32(90), int32(110)
	intersection, known := intersectPermissions(
		[]PortPermission{{Protocol: corev1.ProtocolTCP, Port: &aStart, EndPort: &aEnd}},
		[]PortPermission{{Protocol: corev1.ProtocolTCP, Port: &bStart, EndPort: &bEnd}},
	)
	require.True(t, known)
	require.Equal(t, []string{"TCP/90-100"}, permissionStrings(intersection))

	intersection, _ = intersectPermissions(
		[]PortPermission{{Protocol: corev1.ProtocolTCP, All: true}},
		[]PortPermission{{Protocol: corev1.ProtocolUDP, All: true}},
	)
	require.Empty(t, intersection)
}

func permissionStrings(permissions []PortPermission) []string {
	out := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		out = append(out, permission.String())
	}
	return out
}
