// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	"slices"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func permissionsForPorts(ports []netv1.NetworkPolicyPort, destination *corev1.Pod) ([]PortPermission, bool) {
	if len(ports) == 0 {
		return allPermissions(), true
	}
	var out []PortPermission
	unknown := false
	for _, port := range ports {
		proto := corev1.ProtocolTCP
		if port.Protocol != nil {
			proto = *port.Protocol
		}
		if port.Port == nil {
			out = append(out, PortPermission{Protocol: proto, All: true})
			continue
		}
		value := *port.Port
		if value.Type == intstr.String {
			if destination == nil {
				out = append(out, PortPermission{Protocol: proto, Port: clonePort(port.Port), Unknown: true})
				unknown = true
				continue
			}
			numbers := namedPortNumbers(destination, value.StrVal, proto)
			switch len(numbers) {
			case 0:
				continue
			case 1:
				value = intstr.FromInt32(numbers[0])
			default:
				out = append(out, PortPermission{Protocol: proto, Port: clonePort(port.Port), Unknown: true})
				unknown = true
				continue
			}
		}
		out = append(out, PortPermission{Protocol: proto, Port: &value, EndPort: cloneInt32(port.EndPort)})
	}
	return canonicalPermissions(out), !unknown
}

func namedPortNumbers(pod *corev1.Pod, name string, protocol corev1.Protocol) []int32 {
	if pod == nil {
		return nil
	}
	seen := map[int32]struct{}{}
	containers := append(slices.Clone(pod.Spec.InitContainers), pod.Spec.Containers...)
	for containerIndex := range containers {
		for _, port := range containers[containerIndex].Ports {
			p := port.Protocol
			if p == "" {
				p = corev1.ProtocolTCP
			}
			if port.Name == name && p == protocol {
				seen[port.ContainerPort] = struct{}{}
			}
		}
	}
	keys := mapsKeys(seen)
	slices.Sort(keys)
	return keys
}

func intersectPermissions(a, b []PortPermission) ([]PortPermission, bool) {
	var out []PortPermission
	known := true
	for _, left := range a {
		for _, right := range b {
			if left.Unknown || right.Unknown {
				if protocolsEqual(left.Protocol, right.Protocol) {
					out = append(out, PortPermission{Protocol: normalizedProtocol(left.Protocol), Unknown: true})
					known = false
				}
				continue
			}
			if !protocolsEqual(left.Protocol, right.Protocol) {
				continue
			}
			if left.All {
				out = append(out, right)
				continue
			}
			if right.All {
				out = append(out, left)
				continue
			}
			ls, le := permissionRange(left)
			rs, re := permissionRange(right)
			start, end := max32(ls, rs), min32(le, re)
			if start <= end {
				v := intstr.FromInt32(start)
				p := PortPermission{Protocol: normalizedProtocol(left.Protocol), Port: &v}
				if end != start {
					p.EndPort = &end
				}
				out = append(out, p)
			}
		}
	}
	return canonicalPermissions(out), known
}

func canonicalPermissions(in []PortPermission) []PortPermission {
	seen := map[string]PortPermission{}
	for _, p := range in {
		p.Protocol = normalizedProtocol(p.Protocol)
		seen[p.String()] = p
	}

	keys := mapsKeys(seen)
	slices.Sort(keys)
	out := make([]PortPermission, 0, len(keys))
	for _, k := range keys {
		out = append(out, seen[k])
	}
	return out
}

func knownPermissions(in []PortPermission) bool {
	for _, permission := range in {
		if !permission.Unknown {
			return true
		}
	}
	return false
}
func allPermissions() []PortPermission {
	return []PortPermission{
		{Protocol: corev1.ProtocolSCTP, All: true},
		{Protocol: corev1.ProtocolTCP, All: true},
		{Protocol: corev1.ProtocolUDP, All: true},
	}
}

func permissionRange(p PortPermission) (start, end int32) {
	start = p.Port.IntVal
	if p.EndPort != nil {
		return start, *p.EndPort
	}
	return start, start
}

func protocolsEqual(a, b corev1.Protocol) bool {
	return normalizedProtocol(a) == normalizedProtocol(b)
}

func normalizedProtocol(p corev1.Protocol) corev1.Protocol {
	if p == "" {
		return corev1.ProtocolTCP
	}
	return p
}

func clonePort(p *intstr.IntOrString) *intstr.IntOrString {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneInt32(p *int32) *int32 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func mapsKeys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func min32(a, b int32) int32 {
	if a < b {
		return a
	}
	return b
}

func max32(a, b int32) int32 {
	if a > b {
		return a
	}
	return b
}
