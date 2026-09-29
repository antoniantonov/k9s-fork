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
			if !protocolsEqual(left.Protocol, right.Protocol) {
				continue
			}
			ls, le, leftNumeric := permissionBounds(left)
			rs, re, rightNumeric := permissionBounds(right)
			var permission PortPermission
			switch {
			case left.All || left.Port == nil:
				permission = right
			case right.All || right.Port == nil:
				permission = left
			case !leftNumeric && !rightNumeric && left.Port.StrVal != right.Port.StrVal:
				permission = PortPermission{Protocol: left.Protocol}
			case !leftNumeric:
				permission = right
			case !rightNumeric:
				permission = left
			default:
				start, end := max32(ls, rs), min32(le, re)
				if start > end {
					continue
				}
				permission = rangePermission(left.Protocol, start, end)
			}
			permission.Unknown = left.Unknown || right.Unknown || !leftNumeric || !rightNumeric
			known = known && !permission.Unknown
			out = append(out, permission)
		}
	}
	return canonicalPermissions(out), known
}

func subtractPermissions(allowed, denied []PortPermission) ([]PortPermission, bool) {
	out := slices.Clone(allowed)
	for _, deny := range denied {
		var next []PortPermission
		for _, allow := range out {
			remaining, _ := subtractPermission(allow, deny)
			next = append(next, remaining...)
		}
		out = next
	}
	out = canonicalPermissions(out)
	return out, !slices.ContainsFunc(out, func(permission PortPermission) bool { return permission.Unknown })
}

func subtractPermission(allowed, denied PortPermission) ([]PortPermission, bool) {
	if !protocolsEqual(allowed.Protocol, denied.Protocol) {
		return []PortPermission{allowed}, !allowed.Unknown
	}
	denyStart, denyEnd, denyNumeric := permissionBounds(denied)
	if !denyNumeric {
		allowed.Unknown = true
		return []PortPermission{allowed}, false
	}
	allowStart, allowEnd, allowNumeric := permissionBounds(allowed)
	if !allowNumeric {
		allowStart, allowEnd = 1, 65535
		allowed.Unknown = true
	}
	if denyEnd < allowStart || denyStart > allowEnd {
		return []PortPermission{allowed}, !allowed.Unknown
	}
	if denied.Unknown && (allowed.Unknown || denyStart <= allowStart && denyEnd >= allowEnd) {
		allowed.Unknown = true
		return []PortPermission{allowed}, false
	}
	var out []PortPermission
	appendRange := func(start, end int32, unknown bool) {
		permission := rangePermission(allowed.Protocol, start, end)
		permission.Unknown = unknown
		out = append(out, permission)
	}
	if denyStart > allowStart {
		appendRange(allowStart, denyStart-1, allowed.Unknown)
	}
	if denied.Unknown {
		appendRange(max32(allowStart, denyStart), min32(allowEnd, denyEnd), true)
	}
	if denyEnd < allowEnd {
		appendRange(denyEnd+1, allowEnd, allowed.Unknown)
	}
	return out, len(out) == 0 || !allowed.Unknown && !denied.Unknown
}

// Numeric bounds remain upper bounds on possible traffic when Unknown is set.
// A genuinely unresolved name has no numeric bounds until another constraint
// limits it; uncertainty must never widen an existing numeric permission.
func permissionBounds(permission PortPermission) (start, end int32, numeric bool) {
	if permission.All || permission.Port == nil {
		return 1, 65535, true
	}
	if permission.Port.Type != intstr.Int {
		return 0, 0, false
	}
	start, end = permissionRange(permission)
	return start, end, true
}

func rangePermission(protocol corev1.Protocol, start, end int32) PortPermission {
	port := intstr.FromInt32(start)
	permission := PortPermission{Protocol: normalizedProtocol(protocol), Port: &port}
	if end != start {
		permission.EndPort = &end
	}
	return permission
}

// canonicalPermissions deduplicates and sorts permissions. Within a protocol,
// overlapping known ranges are merged and entries covered by a known range
// are dropped, so a list never shows both TCP/8080 and TCP/all. Adjacent
// ranges stay separate unless together they cover every port.
func canonicalPermissions(in []PortPermission) []PortPermission {
	seen := make(map[string]PortPermission, len(in))
	var protocols [4]int
	merge := false
	for _, p := range in {
		p.Protocol = normalizedProtocol(p.Protocol)
		k := permissionKey(p)
		if _, duplicate := seen[k]; !duplicate {
			slot := protocolSlot(p.Protocol)
			protocols[slot]++
			// Several entries of one protocol may overlap, and a lone full
			// numeric range is rewritten as protocol/all.
			merge = merge || protocols[slot] > 1 || slot == len(protocols)-1 || isFullNumericRange(p)
		}
		seen[k] = p
	}
	if merge {
		seen = mergePermissions(seen)
	}
	keys := mapsKeys(seen)
	slices.Sort(keys)
	out := make([]PortPermission, 0, len(keys))
	for _, k := range keys {
		out = append(out, seen[k])
	}
	return out
}

func protocolSlot(protocol corev1.Protocol) int {
	switch protocol {
	case corev1.ProtocolTCP:
		return 0
	case corev1.ProtocolUDP:
		return 1
	case corev1.ProtocolSCTP:
		return 2
	default:
		return 3
	}
}

func isFullNumericRange(permission PortPermission) bool {
	start, end, numeric := permissionBounds(permission)
	return numeric && !permission.Unknown && !permission.All && permission.Port != nil && start == 1 && end == 65535
}

func mergePermissions(seen map[string]PortPermission) map[string]PortPermission {
	byProtocol := map[corev1.Protocol][]PortPermission{}
	for _, p := range seen {
		byProtocol[p.Protocol] = append(byProtocol[p.Protocol], p)
	}
	merged := make(map[string]PortPermission, len(seen))
	for protocol, permissions := range byProtocol {
		for _, p := range mergeProtocolPermissions(protocol, permissions) {
			merged[permissionKey(p)] = p
		}
	}
	return merged
}

type portSpan struct {
	start, end int32
}

func mergeProtocolPermissions(protocol corev1.Protocol, permissions []PortPermission) []PortPermission {
	if len(permissions) == 1 {
		if start, end, numeric := permissionBounds(permissions[0]); numeric && !permissions[0].Unknown &&
			!permissions[0].All && start == 1 && end == 65535 {
			return []PortPermission{{Protocol: protocol, All: true}}
		}
		return permissions
	}
	var spans []portSpan
	var uncertain []PortPermission
	for _, permission := range permissions {
		start, end, numeric := permissionBounds(permission)
		if permission.Unknown || !numeric {
			uncertain = append(uncertain, permission)
			continue
		}
		spans = append(spans, portSpan{start: start, end: end})
	}
	slices.SortFunc(spans, func(a, b portSpan) int { return int(a.start - b.start) })
	var overlapping, contiguous []portSpan
	for _, span := range spans {
		overlapping = appendSpan(overlapping, span, 0)
		contiguous = appendSpan(contiguous, span, 1)
	}
	if len(contiguous) == 1 && contiguous[0] == (portSpan{start: 1, end: 65535}) {
		// Every port is known to be allowed, so nothing else can add to it.
		return []PortPermission{{Protocol: protocol, All: true}}
	}
	out := make([]PortPermission, 0, len(overlapping)+len(uncertain))
	for _, span := range overlapping {
		out = append(out, rangePermission(protocol, span.start, span.end))
	}
	for _, permission := range uncertain {
		start, end, numeric := permissionBounds(permission)
		if numeric && spanCovered(overlapping, portSpan{start: start, end: end}) {
			continue
		}
		out = append(out, permission)
	}
	return out
}

// appendSpan merges span into sorted spans when it overlaps the last span, or
// when it starts within gap ports of its end.
func appendSpan(spans []portSpan, span portSpan, gap int32) []portSpan {
	if len(spans) > 0 {
		last := &spans[len(spans)-1]
		if span.start <= last.end+gap {
			last.end = max32(last.end, span.end)
			return spans
		}
	}
	return append(spans, span)
}

func spanCovered(spans []portSpan, target portSpan) bool {
	for _, span := range spans {
		if span.start <= target.start && span.end >= target.end {
			return true
		}
	}
	return false
}

func permissionKey(permission PortPermission) string {
	if permission.Unknown {
		permission.Unknown = false
		return string(normalizedProtocol(permission.Protocol)) + "/unknown/" + permission.String()
	}
	return permission.String()
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
