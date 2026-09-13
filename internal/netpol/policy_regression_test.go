// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
)

func TestCiliumEmptyRulesDoNotAllowTraffic(t *testing.T) {
	for _, policyType := range ciliumPolicyTypes() {
		for _, direction := range []Direction{Ingress, Egress} {
			for _, peerField := range []string{"", "Endpoints", "CIDR", "CIDRSet", "Entities"} {
				t.Run(fmt.Sprintf("%s/%s/%s", policyType.Kind(), direction, peerField), func(t *testing.T) {
					snapshot := testSnapshot()
					rule := "{}"
					if peerField != "" {
						rule = fmt.Sprintf("{%s%s: []}", ciliumPeerPrefix(direction), peerField)
					}
					addCiliumPolicy(&snapshot, policyType, ciliumTestPolicy(t, policyType, "empty", `
  endpointSelector:
    matchLabels: {role: server}
  `+strings.ToLower(direction.String())+`: [`+rule+`]`))

					result := evaluateServer(t, snapshot)
					primitive := findPrimitive(t, result.Direction(direction), PrimitivePod, "client", "client")
					require.Equal(t, AccessDisallowed, primitive.State)
					require.Empty(t, primitive.Permissions)
					require.Empty(t, result.Warnings)
					ruleResult := findPolicyRule(t, result.Direction(direction), "empty")
					require.Empty(t, ruleResult.Permissions)
					require.Equal(t, "<none>", ruleResult.PeerSummary)
					row := findApplicability(t, NewEvaluator().RuleApplicability(
						result, direction, ruleResult.ID, sets.New(PrimitivePod),
					))
					require.False(t, row.PeerMatches)
					require.False(t, row.OppositeSideAllows)
					require.Equal(t, AccessDisallowed, row.EffectiveState)
				})
			}
		}
	}
}

func TestCiliumCIDRDenyOverlapIsNotUniformAllow(t *testing.T) {
	for _, policyType := range ciliumPolicyTypes() {
		for _, direction := range []Direction{Ingress, Egress} {
			for _, prefixes := range [][2]string{
				{"192.0.2.0/24", "192.0.2.0/25"},
				{"2001:db8::/64", "2001:db8::/65"},
			} {
				t.Run(fmt.Sprintf("%s/%s/%s", policyType.Kind(), direction, prefixes[0]), func(t *testing.T) {
					snapshot := testSnapshot()
					field := strings.ToLower(direction.String())
					peer := ciliumPeerPrefix(direction)
					addCiliumPolicy(&snapshot, policyType, ciliumTestPolicy(t, policyType, "cidr-deny", fmt.Sprintf(`
  endpointSelector:
    matchLabels: {role: server}
  %s:
    - %sCIDR: [%q]
      toPorts: [{ports: [{port: "80", protocol: TCP}]}]
  %sDeny:
    - %sCIDR: [%q]
      toPorts: [{ports: [{port: "80", protocol: TCP}]}]
`, field, peer, prefixes[0], field, peer, prefixes[1])))

					result := evaluateServer(t, snapshot)
					broad := findCIDRPrimitive(t, result.Direction(direction), prefixes[0], nil)
					require.Equal(t, AccessUnknown, broad.State)
					require.Empty(t, broad.Permissions, "no TCP/80 permission applies throughout the broad CIDR")
					require.Contains(t, broad.Explanation, "partially overlaps")
					require.Contains(t, strings.Join(broad.Warnings, "\n"), "deny")
					narrow := findCIDRPrimitive(t, result.Direction(direction), prefixes[1], nil)
					require.Equal(t, AccessDisallowed, narrow.State)
					require.Empty(t, narrow.Permissions)
					require.Empty(t, result.Warnings, "a known partial CIDR overlap is not missing snapshot data")

					allow := findPolicyRuleAction(t, result.Direction(direction), "cidr-deny", PolicyActionAllow)
					effective := findCIDRApplicability(t, NewEvaluator().DirectionApplicability(
						result, direction, sets.New(PrimitiveCIDR),
					), broad.Ref.ID())
					selected := findCIDRApplicability(t, NewEvaluator().RuleApplicability(
						result, direction, allow.ID, sets.New(PrimitiveCIDR),
					), broad.Ref.ID())
					require.Equal(t, effective.EffectiveState, selected.EffectiveState)
					require.Equal(t, AccessUnknown, selected.EffectiveState)
					require.True(t, selected.PeerMatches)
					require.False(t, selected.OppositeSideAllows)
					require.Empty(t, selected.Permissions)
					deny := findPolicyRuleAction(t, result.Direction(direction), "cidr-deny", PolicyActionDeny)
					denied := findCIDRApplicability(t, NewEvaluator().RuleApplicability(
						result, direction, deny.ID, sets.New(PrimitiveCIDR),
					), broad.Ref.ID())
					require.True(t, denied.PeerMatches)
					require.Equal(t, AccessDisallowed, denied.EffectiveState, "a deny never supplies an allow permission")
					require.Empty(t, denied.Permissions)
				})
			}
		}
	}
}

func TestCiliumCIDRDenyRespectsExcludedAddresses(t *testing.T) {
	for _, direction := range []Direction{Ingress, Egress} {
		t.Run(direction.String(), func(t *testing.T) {
			snapshot := testSnapshot()
			field := strings.ToLower(direction.String())
			peer := ciliumPeerPrefix(direction)
			addCiliumPolicy(&snapshot, PolicyTypeCiliumNetworkPolicy, ciliumTestPolicy(
				t, PolicyTypeCiliumNetworkPolicy, "excluded-deny", fmt.Sprintf(`
  endpointSelector:
    matchLabels: {role: server}
  %s:
    - %sCIDRSet: [{cidr: "192.0.2.0/24", except: ["192.0.2.0/25"]}]
      toPorts: [{ports: [{port: "80", protocol: TCP}]}]
  %sDeny:
    - %sCIDR: ["192.0.2.0/25"]
      toPorts: [{ports: [{port: "80", protocol: TCP}]}]
`, field, peer, field, peer)))

			result := evaluateServer(t, snapshot)
			allowed := findCIDRPrimitive(t, result.Direction(direction), "192.0.2.0/24", []string{"192.0.2.0/25"})
			require.Equal(t, AccessAllowed, allowed.State)
			require.Equal(t, []string{"TCP/80"}, permissionStrings(allowed.Permissions))
			require.Empty(t, allowed.Warnings)
		})
	}
}

func TestCiliumCIDRDenyOverlapKeepsUniformPermissions(t *testing.T) {
	for _, direction := range []Direction{Ingress, Egress} {
		t.Run(direction.String(), func(t *testing.T) {
			snapshot := testSnapshot()
			field := strings.ToLower(direction.String())
			peer := ciliumPeerPrefix(direction)
			addCiliumPolicy(&snapshot, PolicyTypeCiliumNetworkPolicy, ciliumTestPolicy(
				t, PolicyTypeCiliumNetworkPolicy, "partial-ports", fmt.Sprintf(`
  endpointSelector: {matchLabels: {role: server}}
  %s:
    - %sCIDR: ["192.0.2.0/24"]
      toPorts: [{ports: [{port: "80", protocol: TCP}, {port: "90", protocol: TCP}, {port: "53", protocol: UDP}]}]
  %sDeny:
    - %sCIDR: ["192.0.2.0/25"]
      toPorts: [{ports: [{port: "80", protocol: TCP}]}]
`, field, peer, field, peer)))

			result := evaluateServer(t, snapshot)
			broad := findCIDRPrimitive(t, result.Direction(direction), "192.0.2.0/24", nil)
			require.Equal(t, AccessUnknown, broad.State)
			require.Equal(t, []string{"TCP/90", "UDP/53"}, permissionStrings(broad.Permissions))
			allow := findPolicyRuleAction(t, result.Direction(direction), "partial-ports", PolicyActionAllow)
			row := findCIDRApplicability(t, NewEvaluator().RuleApplicability(
				result, direction, allow.ID, sets.New(PrimitiveCIDR),
			), broad.Ref.ID())
			require.Equal(t, AccessUnknown, row.EffectiveState)
			require.Equal(t, permissionStrings(broad.Permissions), permissionStrings(row.Permissions))
		})
	}
}

func TestCiliumCIDRDenyExclusionsAndProtocolIsolation(t *testing.T) {
	tests := []struct {
		name     string
		allowed  string
		denied   string
		protocol string
		except   []string
	}{
		{"different-protocol", `{cidr: "192.0.2.0/24"}`, `{cidr: "192.0.2.0/25"}`, "UDP", nil},
		{"candidate-excludes-deny", `{cidr: "192.0.2.0/24", except: ["192.0.2.0/25"]}`, `{cidr: "192.0.2.0/25"}`, "TCP", []string{"192.0.2.0/25"}},
		{"deny-excludes-candidate", `{cidr: "192.0.2.0/24"}`, `{cidr: "192.0.0.0/16", except: ["192.0.2.0/24"]}`, "TCP", nil},
		{"disjoint-remainders", `{cidr: "192.0.2.0/24", except: ["192.0.2.0/25"]}`,
			`{cidr: "192.0.2.0/24", except: ["192.0.2.128/25"]}`, "TCP", []string{"192.0.2.0/25"}},
	}
	for _, direction := range []Direction{Ingress, Egress} {
		for _, test := range tests {
			t.Run(direction.String()+"/"+test.name, func(t *testing.T) {
				snapshot := testSnapshot()
				field, peer := strings.ToLower(direction.String()), ciliumPeerPrefix(direction)
				addCiliumPolicy(&snapshot, PolicyTypeCiliumClusterwideNetworkPolicy, ciliumTestPolicy(
					t, PolicyTypeCiliumClusterwideNetworkPolicy, "excluded", fmt.Sprintf(`
  endpointSelector: {matchLabels: {role: server}}
  %s:
    - %sCIDRSet: [%s]
      toPorts: [{ports: [{port: "80", protocol: TCP}]}]
  %sDeny:
    - %sCIDRSet: [%s]
      toPorts: [{ports: [{port: "80", protocol: %s}]}]
`, field, peer, test.allowed, field, peer, test.denied, test.protocol)))
				result := evaluateServer(t, snapshot)
				primitive := findCIDRPrimitive(t, result.Direction(direction), "192.0.2.0/24", test.except)
				require.Equal(t, AccessAllowed, primitive.State)
				require.Equal(t, []string{"TCP/80"}, permissionStrings(primitive.Permissions))
				require.Empty(t, primitive.Warnings)
			})
		}
	}
}

func TestCiliumRejectsSupernetCIDRExclusions(t *testing.T) {
	for _, direction := range []Direction{Ingress, Egress} {
		t.Run(direction.String(), func(t *testing.T) {
			snapshot := testSnapshot()
			addCiliumPolicy(&snapshot, PolicyTypeCiliumNetworkPolicy, ciliumTestPolicy(t, PolicyTypeCiliumNetworkPolicy, "invalid-except", fmt.Sprintf(`
  endpointSelector: {matchLabels: {role: server}}
  %s:
    - %sCIDRSet: [{cidr: "192.0.0.0/24", except: ["192.0.0.0/16"]}]
`, strings.ToLower(direction.String()), ciliumPeerPrefix(direction))))
			result := evaluateServer(t, snapshot)
			require.Contains(t, strings.Join(result.Warnings, "\n"), "is not inside")
			require.Empty(t, result.Direction(direction).Primitives[PrimitiveCIDR])
			for _, primitive := range result.Direction(direction).Primitives[PrimitivePod] {
				require.Equal(t, AccessPartialData, primitive.State)
				require.Empty(t, primitive.Permissions)
			}
		})
	}
}

func TestUnmodeledPolicyConstraintsArePartialData(t *testing.T) {
	tests := []struct {
		name       string
		policyType PolicyType
		direction  Direction
		rule       string
		warning    string
	}{
		{"cilium-http", PolicyTypeCiliumNetworkPolicy, Ingress,
			`toPorts: [{ports: [{port: "8080", protocol: TCP}], rules: {http: [{method: GET}]}}]`, "L7"},
		{"cilium-sni", PolicyTypeCiliumClusterwideNetworkPolicy, Egress,
			`toPorts: [{ports: [{port: "443", protocol: TCP}], serverNames: ["example.com"]}]`, "SNI"},
		{"cilium-tls", PolicyTypeCiliumNetworkPolicy, Ingress,
			`toPorts: [{ports: [{port: "443", protocol: TCP}], terminatingTLS: {secret: {name: tls}}}]`, "TLS"},
		{"cilium-listener", PolicyTypeCiliumClusterwideNetworkPolicy, Egress,
			`toPorts: [{ports: [{port: "443", protocol: TCP}], listener: {name: custom}}]`, "listener"},
		{"cilium-authentication", PolicyTypeCiliumNetworkPolicy, Ingress,
			`fromEntities: [cluster]
      authentication: {mode: required}`, "authentication"},
		{"cilium-late-l7", PolicyTypeCiliumNetworkPolicy, Egress,
			`toPorts: [{}, {ports: [{port: "8080", protocol: TCP}], rules: {http: [{method: GET}]}}]`, "L7"},
		{"istio-allow-l7", PolicyTypeIstioAuthorizationPolicy, Ingress,
			`to: [{operation: {ports: ["8080"], methods: [GET], notMethods: [GET]}}]`, "L7"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := testSnapshot()
			if test.policyType == PolicyTypeIstioAuthorizationPolicy {
				snapshot.IstioAuthorizationPolicies = []unstructured.Unstructured{policyObject(t, `
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata: {name: unsupported, namespace: server}
spec:
  selector: {matchLabels: {role: server}}
  action: ALLOW
  rules:
    - `+test.rule)}
			} else {
				addCiliumPolicy(&snapshot, test.policyType, ciliumTestPolicy(t, test.policyType, "unsupported", `
  endpointSelector: {matchLabels: {role: server}}
  `+strings.ToLower(test.direction.String())+`:
    - `+test.rule))
			}
			result := evaluateServer(t, snapshot)
			primitive := findPrimitive(t, result.Direction(test.direction), PrimitivePod, "client", "client")
			require.Equal(t, AccessPartialData, primitive.State)
			require.Contains(t, strings.Join(result.Warnings, "\n"), test.warning)
			want := []string{"TCP/443"}
			switch test.name {
			case "cilium-http":
				want = []string{"TCP/8080"}
			case "cilium-authentication", "cilium-late-l7":
				want = []string{"SCTP/all", "TCP/all", "UDP/all"}
			case "istio-allow-l7":
				want = []string{"SCTP/all", "TCP/8080", "UDP/all"}
			}
			require.Equal(t, want, permissionStrings(primitive.Permissions))
			rule := findPolicyRule(t, result.Direction(test.direction), "unsupported")
			require.Equal(t, test.policyType, rule.ID.SourceType())
			require.Equal(t, PolicyActionAllow, rule.ID.Action)
			require.Contains(t, strings.Join(rule.Warnings, "\n"), test.warning)
			require.NotEmpty(t, rule.Notes)
			row := findApplicability(t, NewEvaluator().RuleApplicability(
				result, test.direction, rule.ID, sets.New(PrimitivePod),
			))
			require.Equal(t, AccessPartialData, row.EffectiveState)
			for _, oppositePrimitive := range result.Direction(opposite(test.direction)).Primitives[PrimitivePod] {
				require.Equal(t, AccessPartialData, oppositePrimitive.State, "normalization uncertainty is snapshot-wide")
			}
		})
	}
}

func TestCiliumUnknownPortDeniesDoNotProveAllows(t *testing.T) {
	for _, direction := range []Direction{Ingress, Egress} {
		t.Run(direction.String(), func(t *testing.T) {
			snapshot := testSnapshot()
			destination := 1
			if direction == Egress {
				destination = 0
			}
			snapshot.Pods[destination].Spec.Containers = []corev1.Container{
				{Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}}},
				{Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8081}}},
			}
			field := strings.ToLower(direction.String())
			addCiliumPolicy(&snapshot, PolicyTypeCiliumNetworkPolicy, ciliumTestPolicy(
				t, PolicyTypeCiliumNetworkPolicy, "unknown-deny", fmt.Sprintf(`
  endpointSelector: {matchLabels: {role: server}}
  %s:
    - toPorts: [{ports: [{port: "8080", protocol: TCP}]}]
  %sDeny:
    - toPorts: [{ports: [{port: "http", protocol: TCP}]}]
`, field, field)))

			result := evaluateServer(t, snapshot)
			primitive := findPrimitive(t, result.Direction(direction), PrimitivePod, "client", "client")
			require.Equal(t, AccessUnknown, primitive.State)
			require.False(t, knownPermissions(primitive.Permissions))
			require.NotContains(t, permissionStrings(primitive.Permissions), "TCP/8080")
		})
	}
}

func TestCiliumProtocolWideDenyRemovesUnknownAllow(t *testing.T) {
	snapshot := testSnapshot()
	http := intstr.FromString("http")
	snapshot.Pods[1].Spec.Containers = []corev1.Container{
		{Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}}},
		{Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8081}}},
	}
	snapshot.NetworkPolicies = []netv1.NetworkPolicy{ingressPolicy("named", "server", []netv1.NetworkPolicyIngressRule{{
		Ports: []netv1.NetworkPolicyPort{{Port: &http}},
	}})}
	addCiliumPolicy(&snapshot, PolicyTypeCiliumNetworkPolicy, ciliumTestPolicy(t, PolicyTypeCiliumNetworkPolicy, "deny-all", `
  endpointSelector: {matchLabels: {role: server}}
  ingressDeny: [{fromEntities: [all]}]`))

	result := evaluateServer(t, snapshot)
	primitive := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
	require.Equal(t, AccessDisallowed, primitive.State)
	require.Empty(t, primitive.Permissions)
}

func TestCiliumUnknownAnyProtocolPreservesProtocols(t *testing.T) {
	ports, err := ciliumPort(ciliumPortProtocol{Port: "http", Protocol: "ANY"})
	require.NoError(t, err)
	permissions, known := permissionsForPorts(ports, nil)
	require.False(t, known)
	require.Len(t, permissions, 3)
	for _, protocol := range []corev1.Protocol{corev1.ProtocolTCP, corev1.ProtocolUDP, corev1.ProtocolSCTP} {
		overlap, exact := intersectPermissions(permissions, []PortPermission{{Protocol: protocol, All: true}})
		require.False(t, exact)
		require.Len(t, overlap, 1)
		require.Equal(t, protocol, overlap[0].Protocol)
		require.True(t, overlap[0].Unknown)
	}
}

func TestCiliumUnknownNamedRuleApplicability(t *testing.T) {
	for _, policyType := range ciliumPolicyTypes() {
		for _, direction := range []Direction{Ingress, Egress} {
			t.Run(fmt.Sprintf("%s/%s", policyType.Kind(), direction), func(t *testing.T) {
				snapshot := testSnapshot()
				destination := 1
				if direction == Egress {
					destination = 0
				}
				snapshot.Pods[destination].Spec.Containers = []corev1.Container{
					{Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}}},
					{Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8081}}},
				}
				addCiliumPolicy(&snapshot, policyType, ciliumTestPolicy(t, policyType, "named-allow", fmt.Sprintf(`
  endpointSelector: {matchLabels: {role: server}}
  %s: [{toPorts: [{ports: [{port: "http", protocol: TCP}]}]}]
`, strings.ToLower(direction.String()))))
				result := evaluateServer(t, snapshot)
				primitive := findPrimitive(t, result.Direction(direction), PrimitivePod, "client", "client")
				require.Equal(t, AccessUnknown, primitive.State)
				rule := findPolicyRule(t, result.Direction(direction), "named-allow")
				row := findApplicability(t, NewEvaluator().RuleApplicability(result, direction, rule.ID, sets.New(PrimitivePod)))
				require.True(t, row.PeerMatches)
				require.False(t, row.OppositeSideAllows)
				require.Equal(t, AccessUnknown, row.EffectiveState)
				require.False(t, knownPermissions(row.Permissions))
			})
		}
	}
}

func TestCustomPolicyConversionFailuresStayPartial(t *testing.T) {
	for _, policyType := range []PolicyType{
		PolicyTypeCiliumNetworkPolicy, PolicyTypeCiliumClusterwideNetworkPolicy, PolicyTypeIstioAuthorizationPolicy,
	} {
		t.Run(policyType.Kind(), func(t *testing.T) {
			snapshot := testSnapshot()
			if policyType == PolicyTypeIstioAuthorizationPolicy {
				object := istioTestPolicy(t, "server", "malformed", "server", "ALLOW", "[{}]")
				object.Object["spec"] = true
				snapshot.IstioAuthorizationPolicies = []unstructured.Unstructured{object}
			} else {
				object := ciliumTestPolicy(t, policyType, "malformed", "  endpointSelector: {}")
				object.Object["spec"] = true
				addCiliumPolicy(&snapshot, policyType, object)
			}
			result := evaluateServer(t, snapshot)
			require.Contains(t, strings.Join(result.Warnings, "\n"), "malformed")
			require.Contains(t, strings.Join(result.Warnings, "\n"), "decode policy resource")
			for _, direction := range []Direction{Ingress, Egress} {
				for _, primitive := range result.Direction(direction).Primitives[PrimitivePod] {
					require.Equal(t, AccessPartialData, primitive.State)
					require.Equal(t, []string{"SCTP/all", "TCP/all", "UDP/all"}, permissionStrings(primitive.Permissions))
				}
			}
		})
	}
}

func TestDirectionApplicabilityRejectsOppositeDenyEvidence(t *testing.T) {
	for _, policyType := range ciliumPolicyTypes() {
		for _, direction := range []Direction{Ingress, Egress} {
			t.Run(fmt.Sprintf("%s/%s", policyType.Kind(), direction), func(t *testing.T) {
				snapshot := testSnapshot()
				tcp := []netv1.NetworkPolicyPort{numericPolicyPort(8080, 0)}
				snapshot.NetworkPolicies = []netv1.NetworkPolicy{
					nativeTransportPolicy(Egress, "client", "client", tcp),
					nativeTransportPolicy(Ingress, "server", "server", tcp),
				}
				subject, peer := "server", "client"
				if direction == Egress {
					subject, peer = "client", "server"
				}
				addCiliumPolicy(&snapshot, policyType, ciliumPairPolicy(
					t, policyType, peer, "opposite-deny", peer, opposite(direction), subject, subject,
					[]string{"8080"}, []string{"8080"},
				))
				result, err := NewEvaluator().EvaluateSubject(
					SubjectRef{Kind: SubjectPod, Namespace: subject, Name: subject}, snapshot, Options{},
				)
				require.NoError(t, err)
				row := findPodApplicability(t, NewEvaluator().DirectionApplicability(
					result, direction, sets.New(PrimitivePod),
				), peer, peer)
				require.Equal(t, AccessDisallowed, row.EffectiveState)
				require.True(t, row.PeerMatches)
				require.False(t, row.OppositeSideAllows, "matching allow evidence is overridden by the opposite deny")
				require.Empty(t, row.Permissions)
			})
		}
	}
}

func ciliumPolicyTypes() []PolicyType {
	return []PolicyType{PolicyTypeCiliumNetworkPolicy, PolicyTypeCiliumClusterwideNetworkPolicy}
}

func ciliumPeerPrefix(direction Direction) string {
	if direction == Egress {
		return "to"
	}
	return "from"
}

func ciliumTestPolicy(t *testing.T, policyType PolicyType, name, spec string) unstructured.Unstructured {
	t.Helper()
	namespace := ""
	if policyType == PolicyTypeCiliumNetworkPolicy {
		namespace = "\n  namespace: server"
	}
	return policyObject(t, fmt.Sprintf(`
apiVersion: cilium.io/v2
kind: %s
metadata:
  name: %s
  uid: %s-uid%s
spec:
%s
`, policyType.Kind(), name, name, namespace, spec))
}

func addCiliumPolicy(snapshot *Snapshot, policyType PolicyType, object unstructured.Unstructured) {
	if policyType == PolicyTypeCiliumClusterwideNetworkPolicy {
		snapshot.CiliumClusterwideNetworkPolicies = append(snapshot.CiliumClusterwideNetworkPolicies, object)
	} else {
		snapshot.CiliumNetworkPolicies = append(snapshot.CiliumNetworkPolicies, object)
	}
}

func evaluateServer(t *testing.T, snapshot Snapshot) SubjectResult {
	t.Helper()
	result, err := NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, snapshot, Options{},
	)
	require.NoError(t, err)
	return result
}

func findCIDRPrimitive(t *testing.T, result DirectionResult, cidr string, except []string) PrimitiveResult {
	t.Helper()
	id := PrimitiveRef{Kind: PrimitiveCIDR, CIDR: cidr, CIDRExcept: except}.ID()
	for _, primitive := range result.Primitives[PrimitiveCIDR] {
		if primitive.Ref.ID() == id {
			return primitive
		}
	}
	require.FailNow(t, "CIDR primitive not found", "%s except %v", cidr, except)
	return PrimitiveResult{}
}

func findCIDRApplicability(t *testing.T, rows []ApplicabilityRow, id string) ApplicabilityRow {
	t.Helper()
	for _, row := range rows {
		if row.Primitive.Ref.ID() == id {
			return row
		}
	}
	require.FailNow(t, "CIDR applicability not found", "%s", id)
	return ApplicabilityRow{}
}
