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

func TestSubtractPermissions(t *testing.T) {
	deniedPort := intstr.FromInt32(8080)
	allowed, known := subtractPermissions(
		[]PortPermission{
			{Protocol: corev1.ProtocolTCP, All: true},
			{Protocol: corev1.ProtocolUDP, All: true},
		},
		[]PortPermission{{Protocol: corev1.ProtocolTCP, Port: &deniedPort}},
	)
	require.True(t, known)
	require.Equal(t, []string{"TCP/1-8079", "TCP/8081-65535", "UDP/all"}, permissionStrings(allowed))

	allowed, known = subtractPermissions(
		[]PortPermission{{Protocol: corev1.ProtocolTCP, All: true}},
		[]PortPermission{{Protocol: corev1.ProtocolTCP, All: true}},
	)
	require.True(t, known)
	require.Empty(t, allowed)

	allowed, known = subtractPermissions(
		[]PortPermission{{Protocol: corev1.ProtocolTCP, All: true}},
		[]PortPermission{{Protocol: corev1.ProtocolTCP, Unknown: true}},
	)
	require.False(t, known)
	require.Equal(t, []string{"unknown"}, permissionStrings(allowed))
	require.True(t, allowed[0].Unknown)
}

func TestSubtractUnknownPermissionsAndProtocolWideDenies(t *testing.T) {
	unknown := PortPermission{Protocol: corev1.ProtocolTCP, Unknown: true}
	for _, denyTCP := range []PortPermission{
		{Protocol: corev1.ProtocolTCP, All: true},
		rangePermission(corev1.ProtocolTCP, 1, 65535),
	} {
		for _, denies := range [][]PortPermission{{unknown, denyTCP}, {denyTCP, unknown}} {
			remaining, known := subtractPermissions(
				[]PortPermission{{Protocol: corev1.ProtocolTCP, All: true}, {Protocol: corev1.ProtocolUDP, All: true}},
				denies,
			)
			require.True(t, known)
			require.Equal(t, []string{"UDP/all"}, permissionStrings(remaining))
		}
	}
	remaining, known := subtractPermissions([]PortPermission{unknown}, nil)
	require.False(t, known)
	require.True(t, remaining[0].Unknown)
}

func TestUnknownEvidenceRetainsProtocolIdentity(t *testing.T) {
	id := RuleID{PolicyNamespace: "server", PolicyName: "named", PolicyType: PolicyTypeCiliumNetworkPolicy}
	evidence := uniqueEvidence([]PolicyEvidence{
		{RuleID: id, Ports: []PortPermission{{Protocol: corev1.ProtocolTCP, Unknown: true}}},
		{RuleID: id, Ports: []PortPermission{{Protocol: corev1.ProtocolUDP, Unknown: true}}},
	})
	require.Len(t, evidence, 2)
}

func TestIntersectUncertainPermissionBounds(t *testing.T) {
	tcp, udp := corev1.ProtocolTCP, corev1.ProtocolUDP
	http := intstr.FromString("http")
	metrics := intstr.FromString("metrics")
	named := PortPermission{Protocol: tcp, Port: &http, Unknown: true}
	tests := []struct {
		name        string
		left, right PortPermission
		want        []PortPermission
		known       bool
	}{
		{"disjoint-ports", uncertainRange(tcp, 8080, 8080), rangePermission(tcp, 9090, 9090), nil, true},
		{"disjoint-ranges", uncertainRange(tcp, 8080, 8085), rangePermission(tcp, 8090, 8100), nil, true},
		{"overlapping-ranges", uncertainRange(tcp, 8080, 8085), rangePermission(tcp, 8083, 8090),
			[]PortPermission{uncertainRange(tcp, 8083, 8085)}, false},
		{"disjoint-uncertain-ranges", uncertainRange(tcp, 8080, 8085), uncertainRange(tcp, 8090, 8100), nil, true},
		{"overlapping-uncertain-ranges", uncertainRange(tcp, 8080, 8085), uncertainRange(tcp, 8083, 8090),
			[]PortPermission{uncertainRange(tcp, 8083, 8085)}, false},
		{"different-protocol", uncertainRange(tcp, 8080, 8085), rangePermission(udp, 8080, 8085), nil, true},
		{"bounded-by-numeric", named, rangePermission(tcp, 9090, 9090),
			[]PortPermission{uncertainRange(tcp, 9090, 9090)}, false},
		{"unbounded-name", named, PortPermission{Protocol: tcp, All: true}, []PortPermission{named}, false},
		{"same-unresolved-name", named, named, []PortPermission{named}, false},
		{"different-unresolved-names", named, PortPermission{Protocol: tcp, Port: &metrics, Unknown: true},
			[]PortPermission{{Protocol: tcp, Unknown: true}}, false},
		{"unbounded-unknown", PortPermission{Protocol: tcp, Unknown: true}, rangePermission(tcp, 8080, 8085),
			[]PortPermission{uncertainRange(tcp, 8080, 8085)}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, sides := range [][2]PortPermission{{test.left, test.right}, {test.right, test.left}} {
				overlap, known := intersectPermissions([]PortPermission{sides[0]}, []PortPermission{sides[1]})
				require.Equal(t, test.known, known)
				require.Equal(t, canonicalPermissions(test.want), overlap)
			}
		})
	}
}

func TestSubtractUncertainPermissionBounds(t *testing.T) {
	tcp, udp := corev1.ProtocolTCP, corev1.ProtocolUDP
	http := intstr.FromString("http")
	named := PortPermission{Protocol: tcp, Port: &http, Unknown: true}
	tests := []struct {
		name          string
		allowed, deny PortPermission
		want          []PortPermission
		known         bool
	}{
		{"named-deny-retains-allow-bound", rangePermission(tcp, 8080, 8085), named,
			[]PortPermission{uncertainRange(tcp, 8080, 8085)}, false},
		{"known-deny-removes-uncertain-bound", uncertainRange(tcp, 8080, 8085), rangePermission(tcp, 8080, 8085), nil, true},
		{"known-deny-splits-uncertain-bound", uncertainRange(tcp, 8080, 8090), rangePermission(tcp, 8083, 8087),
			[]PortPermission{uncertainRange(tcp, 8080, 8082), uncertainRange(tcp, 8088, 8090)}, false},
		{"uncertain-deny-disjoint", rangePermission(tcp, 8080, 8085), uncertainRange(tcp, 8090, 8100),
			[]PortPermission{rangePermission(tcp, 8080, 8085)}, true},
		{"uncertain-deny-overlap", rangePermission(tcp, 8080, 8090), uncertainRange(tcp, 8083, 8087),
			[]PortPermission{rangePermission(tcp, 8080, 8082), uncertainRange(tcp, 8083, 8087), rangePermission(tcp, 8088, 8090)}, false},
		{"both-uncertain", uncertainRange(tcp, 8080, 8090), uncertainRange(tcp, 8083, 8087),
			[]PortPermission{uncertainRange(tcp, 8080, 8090)}, false},
		{"other-protocol-unaffected", rangePermission(udp, 53, 53), named,
			[]PortPermission{rangePermission(udp, 53, 53)}, true},
		{"numeric-deny-bounds-unresolved-name", named, rangePermission(tcp, 80, 90),
			[]PortPermission{uncertainRange(tcp, 1, 79), uncertainRange(tcp, 91, 65535)}, false},
		{"unbounded-named-deny", PortPermission{Protocol: tcp, All: true}, named,
			[]PortPermission{{Protocol: tcp, All: true, Unknown: true}}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			remaining, known := subtractPermissions([]PortPermission{test.allowed}, []PortPermission{test.deny})
			require.Equal(t, test.known, known)
			require.Equal(t, canonicalPermissions(test.want), remaining)
		})
	}
}

func TestUnknownEvidenceRetainsNumericBounds(t *testing.T) {
	first, second := uncertainRange(corev1.ProtocolTCP, 8080, 8085), uncertainRange(corev1.ProtocolTCP, 9090, 9095)
	id := RuleID{PolicyNamespace: "server", PolicyName: "bounded", PolicyType: PolicyTypeCiliumNetworkPolicy}
	require.NotEqual(t, permissionKey(first), permissionKey(second))
	require.NotEqual(t, permissionKey(first), permissionKey(uncertainRange(corev1.ProtocolTCP, 8080, 8090)))
	require.NotEqual(t, permissionKey(first), permissionKey(PortPermission{Protocol: corev1.ProtocolTCP, Unknown: true}))
	require.NotEqual(t, permissionsKey([]PortPermission{first}), permissionsKey([]PortPermission{second}))
	require.NotEqual(t, permissionKey(first), permissionKey(rangePermission(corev1.ProtocolTCP, 8080, 8085)))
	for _, permissions := range [][]PortPermission{{first, second, first}, {second, first, second}} {
		union := canonicalPermissions(permissions)
		require.Len(t, union, 2)
		require.ElementsMatch(t, []PortPermission{first, second}, union)
		for _, port := range []int32{8080, 9090} {
			overlap, known := intersectPermissions(union, []PortPermission{rangePermission(corev1.ProtocolTCP, port, port)})
			require.False(t, known)
			require.Equal(t, []PortPermission{uncertainRange(corev1.ProtocolTCP, port, port)}, overlap)
		}
		gap, known := intersectPermissions(union, []PortPermission{rangePermission(corev1.ProtocolTCP, 8500, 8500)})
		require.True(t, known)
		require.Empty(t, gap)
	}
	evidence := uniqueEvidence([]PolicyEvidence{
		{RuleID: id, Ports: []PortPermission{first}},
		{RuleID: id, Ports: []PortPermission{second}},
		{RuleID: id, Ports: []PortPermission{first}},
	})
	require.Len(t, evidence, 2)
	require.ElementsMatch(t, []PortPermission{first, second}, evidencePermissions(evidence, &id))
}

func TestIstioUncertainNetworkBoundsRequireCommonPorts(t *testing.T) {
	network := layerDecision{Decision: Decision{
		State:       AccessUnknown,
		Permissions: []PortPermission{uncertainRange(corev1.ProtocolTCP, 8080, 8080)},
	}}
	for _, port := range []int32{8080, 9090} {
		value := intstr.FromInt32(port)
		t.Run(value.String(), func(t *testing.T) {
			authorization := layerDecision{Decision: Decision{
				State:       AccessAllowed,
				Permissions: []PortPermission{rangePermission(corev1.ProtocolTCP, port, port)},
			}}
			decision := combinePolicyLayers(&network, &authorization)
			if port == 8080 {
				require.Equal(t, AccessUnknown, decision.State)
				require.Equal(t, network.Permissions, decision.Permissions)
			} else {
				require.Equal(t, AccessDisallowed, decision.State)
				require.Empty(t, decision.Permissions)
			}
		})
	}
}

func uncertainRange(protocol corev1.Protocol, start, end int32) PortPermission {
	permission := rangePermission(protocol, start, end)
	permission.Unknown = true
	return permission
}

func permissionStrings(permissions []PortPermission) []string {
	out := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		out = append(out, permission.String())
	}
	return out
}

func TestCanonicalPermissionsMergesCoveredRanges(t *testing.T) {
	named := intstr.FromString("http")
	tests := []struct {
		name string
		in   []PortPermission
		want []string
	}{
		{
			name: "all covers a single port",
			in:   []PortPermission{rangePermission(corev1.ProtocolTCP, 8080, 8080), {Protocol: corev1.ProtocolTCP, All: true}},
			want: []string{"TCP/all"},
		},
		{
			name: "overlapping ranges merge",
			in:   []PortPermission{rangePermission(corev1.ProtocolTCP, 8000, 8080), rangePermission(corev1.ProtocolTCP, 8050, 8100)},
			want: []string{"TCP/8000-8100"},
		},
		{
			name: "contained range is dropped",
			in:   []PortPermission{rangePermission(corev1.ProtocolTCP, 8000, 8100), rangePermission(corev1.ProtocolTCP, 8080, 8080)},
			want: []string{"TCP/8000-8100"},
		},
		{
			name: "adjacent declared ports stay separate",
			in:   []PortPermission{rangePermission(corev1.ProtocolTCP, 8080, 8080), rangePermission(corev1.ProtocolTCP, 8081, 8081)},
			want: []string{"TCP/8080", "TCP/8081"},
		},
		{
			name: "adjacent ranges covering every port become all",
			in: []PortPermission{
				rangePermission(corev1.ProtocolTCP, 1, 8079),
				rangePermission(corev1.ProtocolTCP, 8080, 8080),
				rangePermission(corev1.ProtocolTCP, 8081, 65535),
			},
			want: []string{"TCP/all"},
		},
		{
			name: "full numeric range is all",
			in:   []PortPermission{rangePermission(corev1.ProtocolUDP, 1, 65535)},
			want: []string{"UDP/all"},
		},
		{
			name: "protocols do not merge",
			in:   []PortPermission{{Protocol: corev1.ProtocolUDP, All: true}, rangePermission(corev1.ProtocolTCP, 53, 53)},
			want: []string{"TCP/53", "UDP/all"},
		},
		{
			name: "known all covers unknown named port",
			in:   []PortPermission{{Protocol: corev1.ProtocolTCP, All: true}, {Protocol: corev1.ProtocolTCP, Port: &named, Unknown: true}},
			want: []string{"TCP/all"},
		},
		{
			name: "known range covers unknown numeric range",
			in:   []PortPermission{rangePermission(corev1.ProtocolUDP, 8000, 9000), uncertainRange(corev1.ProtocolUDP, 8080, 8081)},
			want: []string{"UDP/8000-9000"},
		},
		{
			name: "partially covered unknown range is kept",
			in:   []PortPermission{rangePermission(corev1.ProtocolTCP, 8000, 8080), uncertainRange(corev1.ProtocolTCP, 8080, 8090)},
			want: []string{"TCP/8000-8080", "unknown"},
		},
		{
			name: "unknown named port without a covering range is kept",
			in:   []PortPermission{rangePermission(corev1.ProtocolTCP, 8000, 8080), {Protocol: corev1.ProtocolTCP, Port: &named, Unknown: true}},
			want: []string{"TCP/8000-8080", "unknown"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, permissionStrings(canonicalPermissions(test.in)))
		})
	}
	require.Empty(t, canonicalPermissions(nil))
	require.Equal(t, []string{"TCP/80"}, permissionStrings(canonicalPermissions([]PortPermission{
		rangePermission("", 80, 80), rangePermission(corev1.ProtocolTCP, 80, 80),
	})), "duplicates and the default protocol collapse without merging")
	custom := corev1.Protocol("QUIC")
	require.Equal(t, []string{"QUIC/1-20"}, permissionStrings(canonicalPermissions([]PortPermission{
		rangePermission(custom, 1, 10), rangePermission(custom, 5, 20),
	})), "unusual protocols still merge overlapping ranges")
	require.Equal(t, 3, protocolSlot(corev1.ProtocolSCTP)+1)
	require.False(t, isFullNumericRange(PortPermission{Protocol: corev1.ProtocolTCP, All: true}))
}
