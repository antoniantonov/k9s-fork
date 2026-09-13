// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/sets"
)

func TestCiliumDirectionIsolationMatrix(t *testing.T) {
	all := []string{"SCTP/all", "TCP/all", "UDP/all"}
	tests := []struct {
		name          string
		rules         string
		defaultDeny   string
		deny          string
		nativeIsolate bool
		want          []string
	}{
		{name: "omitted", want: all},
		{name: "empty-list", rules: "[]", want: all},
		{name: "empty-rule", rules: "[{}]"},
		{name: "default-deny-explicit", rules: "[{}]", defaultDeny: "true"},
		{name: "port-only-wildcard", rules: `[{toPorts: [{ports: [{port: "8080", protocol: TCP}]}]}]`, want: []string{"TCP/8080"}},
		{name: "explicit-all", rules: "[{%sEntities: [all]}]", want: all},
		{name: "empty-endpoints-with-port", rules: `[{%sEndpoints: [], toPorts: [{ports: [{port: "8080", protocol: TCP}]}]}]`},
		{name: "default-deny-disabled", rules: `[{toPorts: [{ports: [{port: "8080", protocol: TCP}]}]}]`, defaultDeny: "false",
			want: []string{"SCTP/all", "TCP/8080", "TCP/all", "UDP/all"}},
		{name: "empty-rule-isolation-disabled", rules: "[{}]", defaultDeny: "false", want: all},
		{name: "another-policy-isolates", rules: `[{toPorts: [{ports: [{port: "8080", protocol: TCP}]}]}]`,
			defaultDeny: "false", nativeIsolate: true, want: []string{"TCP/8080"}},
		{name: "deny-only-isolates", deny: `[{toPorts: [{ports: [{port: "8080", protocol: TCP}]}]}]`},
		{name: "deny-without-isolation", defaultDeny: "false", deny: `[{toPorts: [{ports: [{port: "8080", protocol: TCP}]}]}]`,
			want: []string{"SCTP/all", "TCP/1-8079", "TCP/8081-65535", "UDP/all"}},
		{name: "empty-deny-is-not-blanket-deny", rules: "[{%sEntities: [all]}]", deny: "[{}]", want: all},
	}
	for _, policyType := range ciliumPolicyTypes() {
		for _, direction := range []Direction{Ingress, Egress} {
			for _, test := range tests {
				t.Run(fmt.Sprintf("%s/%s/%s", policyType.Kind(), direction, test.name), func(t *testing.T) {
					snapshot := testSnapshot()
					field := strings.ToLower(direction.String())
					spec := "  endpointSelector: {matchLabels: {role: server}}\n"
					if test.rules != "" {
						spec += "  " + field + ": " + strings.ReplaceAll(test.rules, "%s", ciliumPeerPrefix(direction)) + "\n"
					}
					if test.deny != "" {
						spec += "  " + field + "Deny: " + test.deny + "\n"
					}
					if test.defaultDeny != "" {
						spec += "  enableDefaultDeny: {" + field + ": " + test.defaultDeny + "}\n"
					}
					addCiliumPolicy(&snapshot, policyType, ciliumTestPolicy(t, policyType, "isolation", spec))
					if test.nativeIsolate {
						policy := ingressPolicy("native-isolation", "server", nil)
						if direction == Egress {
							policy.Spec.PolicyTypes = []netv1.PolicyType{netv1.PolicyTypeEgress}
						}
						snapshot.NetworkPolicies = []netv1.NetworkPolicy{policy}
					}
					result := evaluateServer(t, snapshot)
					primitive := findPrimitive(t, result.Direction(direction), PrimitivePod, "client", "client")
					require.ElementsMatch(t, test.want, permissionStrings(primitive.Permissions))
					wantState := AccessAllowed
					if len(test.want) == 0 {
						wantState = AccessDisallowed
					}
					require.Equal(t, wantState, primitive.State)
					require.Empty(t, result.Warnings)
					other := findPrimitive(t, result.Direction(opposite(direction)), PrimitivePod, "client", "client")
					require.Equal(t, AccessAllowed, other.State)
					require.Equal(t, all, permissionStrings(other.Permissions), "isolation is direction-specific")
				})
			}
		}
	}
}

func TestCiliumPeerScopeAndEntitiesEffectiveMatrix(t *testing.T) {
	tests := []struct {
		name       string
		peer       string
		local      bool
		cross      bool
		crossCCNP  bool
		worldCIDRs bool
	}{
		{name: "implicit-namespace", peer: `%sEndpoints: [{matchLabels: {role: client}}]`, local: true, crossCCNP: true},
		{name: "namespace-label", peer: `%sEndpoints: [{matchLabels: {role: client, io.cilium.k8s.namespace.labels.team: client}}]`,
			cross: true, crossCCNP: true},
		{name: "combined-expressions", peer: `%sEndpoints: [{matchExpressions: [{key: role, operator: In, values: [client]}, {key: io.kubernetes.pod.namespace, operator: In, values: [client]}]}]`,
			cross: true, crossCCNP: true},
		{name: "service-account", peer: `%sEndpoints: [{matchLabels: {io.kubernetes.pod.namespace: client, io.cilium.k8s.policy.serviceaccount: caller}}]`,
			cross: true, crossCCNP: true},
		{name: "cluster", peer: "%sEntities: [cluster]", local: true, cross: true, crossCCNP: true},
		{name: "cluster-mesh-local-pods", peer: "%sEntities: [cluster-mesh]", local: true, cross: true, crossCCNP: true},
		{name: "all", peer: "%sEntities: [all]", local: true, cross: true, crossCCNP: true, worldCIDRs: true},
		{name: "world-not-pods", peer: "%sEntities: [world]", worldCIDRs: true},
		{name: "none", peer: "%sEntities: [none]"},
	}
	for _, policyType := range ciliumPolicyTypes() {
		for _, direction := range []Direction{Ingress, Egress} {
			for _, test := range tests {
				t.Run(fmt.Sprintf("%s/%s/%s", policyType.Kind(), direction, test.name), func(t *testing.T) {
					snapshot := testSnapshot()
					snapshot.Pods[0].Spec.ServiceAccountName = "caller"
					snapshot.Pods[0].Status.PodIP = "192.0.2.10"
					local := snapshot.Pods[0].DeepCopy()
					local.Namespace, local.Name, local.UID = "server", "local", "local"
					snapshot.Pods = append(snapshot.Pods, *local)
					addCiliumPolicy(&snapshot, policyType, ciliumTestPolicy(t, policyType, "peers", fmt.Sprintf(`
  endpointSelector: {matchLabels: {role: server}}
  %s:
    - %s
`, strings.ToLower(direction.String()), fmt.Sprintf(test.peer, ciliumPeerPrefix(direction)))))

					result := evaluateServer(t, snapshot)
					cross := test.cross
					if policyType == PolicyTypeCiliumClusterwideNetworkPolicy {
						cross = test.crossCCNP
					}
					for _, peer := range []struct {
						namespace string
						name      string
						allowed   bool
					}{{"client", "client", cross}, {"server", "local", test.local}} {
						primitive := findPrimitive(t, result.Direction(direction), PrimitivePod, peer.namespace, peer.name)
						wantState := AccessDisallowed
						if peer.allowed {
							wantState = AccessAllowed
						}
						require.Equal(t, wantState, primitive.State, peer.name)
						if peer.allowed {
							require.Equal(t, []string{"SCTP/all", "TCP/all", "UDP/all"}, permissionStrings(primitive.Permissions))
						} else {
							require.Empty(t, primitive.Permissions)
						}
					}
					require.Empty(t, result.Warnings)
					if test.worldCIDRs {
						require.Len(t, result.Direction(direction).Primitives[PrimitiveCIDR], 2)
						for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
							primitive := findCIDRPrimitive(t, result.Direction(direction), cidr, nil)
							require.Equal(t, AccessAllowed, primitive.State)
						}
					} else {
						require.Empty(t, result.Direction(direction).Primitives[PrimitiveCIDR])
					}
				})
			}
		}
	}
}

func TestCiliumCrossEndpointPortIntersection(t *testing.T) {
	tests := []struct {
		name       string
		policyType PolicyType
		egress     []string
		ingress    []string
		denied     []string
		want       []string
	}{
		{"cnp-overlap", PolicyTypeCiliumNetworkPolicy, []string{"8080", "8081"}, []string{"8081", "8082"}, nil, []string{"TCP/8081"}},
		{"cnp-mismatch", PolicyTypeCiliumNetworkPolicy, []string{"8080", "8081"}, []string{"9090"}, nil, nil},
		{"ccnp-deny-overrides", PolicyTypeCiliumClusterwideNetworkPolicy, []string{"9090", "9091", "9092"}, []string{"9091", "9092"}, []string{"9091"}, []string{"TCP/9092"}},
		{"ccnp-denies-intersection", PolicyTypeCiliumClusterwideNetworkPolicy, []string{"9091"}, []string{"9091", "9092"}, []string{"9091"}, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := testSnapshot()
			otherSource := snapshot.Pods[0].DeepCopy()
			otherSource.Name, otherSource.UID, otherSource.Labels = "other-source", "other-source", map[string]string{"role": "other"}
			otherDestination := snapshot.Pods[1].DeepCopy()
			otherDestination.Name, otherDestination.UID, otherDestination.Labels = "other-target", "other-target", map[string]string{"role": "other"}
			snapshot.Pods = append(snapshot.Pods, *otherSource, *otherDestination)
			addCiliumPolicy(&snapshot, test.policyType, ciliumPairPolicy(
				t, test.policyType, "client", "source", "client", Egress, "server", "server", test.egress, nil,
			))
			addCiliumPolicy(&snapshot, test.policyType, ciliumPairPolicy(
				t, test.policyType, "server", "destination", "server", Ingress, "client", "client", test.ingress, test.denied,
			))
			for _, side := range []struct {
				subject   SubjectRef
				direction Direction
				namespace string
				peer      string
				policy    string
				control   string
			}{
				{SubjectRef{Kind: SubjectPod, Namespace: "client", Name: "client"}, Egress, "server", "server", "source", "other-target"},
				{SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, Ingress, "client", "client", "destination", "other-source"},
			} {
				t.Run(side.direction.String(), func(t *testing.T) {
					result, err := NewEvaluator().EvaluateSubject(side.subject, snapshot, Options{})
					require.NoError(t, err)
					require.Empty(t, result.Warnings)
					primitive := findPrimitive(t, result.Direction(side.direction), PrimitivePod, side.namespace, side.peer)
					require.ElementsMatch(t, test.want, permissionStrings(primitive.Permissions))
					wantState := AccessAllowed
					if len(test.want) == 0 {
						wantState = AccessDisallowed
					}
					require.Equal(t, wantState, primitive.State)
					control := findPrimitive(t, result.Direction(side.direction), PrimitivePod, side.namespace, side.control)
					require.Equal(t, AccessDisallowed, control.State)
					require.Empty(t, control.Permissions)
					require.Len(t, primitive.PairDecisions, 1)
					directions := sets.New[Direction]()
					for _, evidence := range primitive.Evidence {
						require.Equal(t, test.policyType, evidence.RuleID.SourceType())
						require.Equal(t, "cilium.io/v2", evidence.RuleID.PolicyVersion)
						require.Equal(t, 0, evidence.PeerIndex)
						directions.Insert(evidence.RuleID.Direction)
					}
					require.True(t, directions.HasAll(Ingress, Egress))
					rule := findPolicyRuleAction(t, result.Direction(side.direction), side.policy, PolicyActionAllow)
					require.Equal(t, 1, rule.SubjectPodCount)
					require.Equal(t, 1, rule.SubjectMatchCount)
					row := findPodApplicability(t, NewEvaluator().RuleApplicability(
						result, side.direction, rule.ID, sets.New(PrimitivePod),
					), side.namespace, side.peer)
					require.True(t, row.PeerMatches)
					require.Equal(t, wantState, row.EffectiveState)
					require.Equal(t, len(test.want) > 0, row.OppositeSideAllows)
					require.ElementsMatch(t, test.want, permissionStrings(row.Permissions))
					if side.direction == Ingress && len(test.denied) > 0 {
						deny := findPolicyRuleAction(t, result.Ingress, side.policy, PolicyActionDeny)
						denyRow := findPodApplicability(t, NewEvaluator().RuleApplicability(
							result, Ingress, deny.ID, sets.New(PrimitivePod),
						), side.namespace, side.peer)
						require.True(t, denyRow.PeerMatches)
						require.Equal(t, AccessDisallowed, denyRow.EffectiveState)
						require.Empty(t, denyRow.Permissions)
					}
				})
			}
		})
	}
}

func TestCiliumNativeAndCustomAllowsAreAdditiveBeforeDenies(t *testing.T) {
	snapshot := testSnapshot()
	udp := corev1.ProtocolUDP
	dns := numericPolicyPort(53, 0)
	dns.Protocol = &udp
	snapshot.NetworkPolicies = []netv1.NetworkPolicy{
		egressPolicy("native-source", []netv1.NetworkPolicyEgressRule{{
			Ports: []netv1.NetworkPolicyPort{numericPolicyPort(8000, 8009), dns},
		}}),
		ingressPolicy("native-destination", "server", []netv1.NetworkPolicyIngressRule{{
			Ports: []netv1.NetworkPolicyPort{numericPolicyPort(8004, 8012), dns},
		}}),
	}
	addCiliumPolicy(&snapshot, PolicyTypeCiliumNetworkPolicy, ciliumPairPolicy(
		t, PolicyTypeCiliumNetworkPolicy, "client", "source-extra", "client", Egress, "server", "server",
		[]string{"8020"}, []string{"8006"},
	))
	addCiliumPolicy(&snapshot, PolicyTypeCiliumClusterwideNetworkPolicy, ciliumPairPolicy(
		t, PolicyTypeCiliumClusterwideNetworkPolicy, "server", "destination-extra", "server", Ingress, "client", "client",
		[]string{"8020"}, []string{"8007"},
	))
	for _, side := range []struct {
		namespace string
		direction Direction
		peer      string
	}{{"client", Egress, "server"}, {"server", Ingress, "client"}} {
		t.Run(side.direction.String(), func(t *testing.T) {
			result, err := NewEvaluator().EvaluateSubject(
				SubjectRef{Kind: SubjectPod, Namespace: side.namespace, Name: side.namespace}, snapshot, Options{},
			)
			require.NoError(t, err)
			primitive := findPrimitive(t, result.Direction(side.direction), PrimitivePod, side.peer, side.peer)
			require.Equal(t, AccessAllowed, primitive.State)
			require.Equal(t, []string{"TCP/8004-8005", "TCP/8008-8009", "TCP/8020", "UDP/53"}, permissionStrings(primitive.Permissions))
			kinds, actions := sets.New[PolicyType](), sets.New[PolicyAction]()
			for _, evidence := range primitive.Evidence {
				kinds.Insert(evidence.RuleID.SourceType())
				actions.Insert(evidence.RuleID.Action)
			}
			require.True(t, kinds.HasAll(PolicyTypeNetworkPolicy, PolicyTypeCiliumNetworkPolicy, PolicyTypeCiliumClusterwideNetworkPolicy))
			require.True(t, actions.HasAll(PolicyActionAllow, PolicyActionDeny))
			require.Empty(t, result.Warnings)
		})
	}
}

func TestCiliumEffectivePortMatrix(t *testing.T) {
	tests := []struct {
		name  string
		ports string
		want  []string
		state AccessState
	}{
		{"all-ports", "", []string{"SCTP/all", "TCP/all", "UDP/all"}, AccessAllowed},
		{"default-any", `toPorts: [{ports: [{port: "53"}]}]`, []string{"SCTP/53", "TCP/53", "UDP/53"}, AccessAllowed},
		{"explicit-any", `toPorts: [{ports: [{port: "53", protocol: ANY}]}]`, []string{"SCTP/53", "TCP/53", "UDP/53"}, AccessAllowed},
		{"udp", `toPorts: [{ports: [{port: "53", protocol: UDP}]}]`, []string{"UDP/53"}, AccessAllowed},
		{"sctp", `toPorts: [{ports: [{port: "9000", protocol: SCTP}]}]`, []string{"SCTP/9000"}, AccessAllowed},
		{"tcp-range", `toPorts: [{ports: [{port: "8080", endPort: 8085, protocol: TCP}]}]`, []string{"TCP/8080-8085"}, AccessAllowed},
		{"destination-named", `toPorts: [{ports: [{port: "http", protocol: TCP}]}]`, []string{"TCP/8181"}, AccessAllowed},
		{"missing-named", `toPorts: [{ports: [{port: "missing", protocol: TCP}]}]`, nil, AccessDisallowed},
	}
	for _, policyType := range ciliumPolicyTypes() {
		for _, direction := range []Direction{Ingress, Egress} {
			for _, test := range tests {
				t.Run(fmt.Sprintf("%s/%s/%s", policyType.Kind(), direction, test.name), func(t *testing.T) {
					snapshot := testSnapshot()
					for index := range snapshot.Pods {
						number := int32(9999)
						if (direction == Ingress && index == 1) || (direction == Egress && index == 0) {
							number = 8181
						}
						snapshot.Pods[index].Spec.Containers = []corev1.Container{{
							Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: number, Protocol: corev1.ProtocolTCP}},
						}}
					}
					addCiliumPolicy(&snapshot, policyType, ciliumTestPolicy(t, policyType, "ports", fmt.Sprintf(`
  endpointSelector: {matchLabels: {role: server}}
  %s:
    - %sEntities: [cluster]
      %s
`, strings.ToLower(direction.String()), ciliumPeerPrefix(direction), test.ports)))
					result := evaluateServer(t, snapshot)
					primitive := findPrimitive(t, result.Direction(direction), PrimitivePod, "client", "client")
					require.Equal(t, test.state, primitive.State)
					require.ElementsMatch(t, test.want, permissionStrings(primitive.Permissions))
					require.Empty(t, result.Warnings)
					rule := findPolicyRule(t, result.Direction(direction), "ports")
					row := findApplicability(t, NewEvaluator().RuleApplicability(result, direction, rule.ID, sets.New(PrimitivePod)))
					require.True(t, row.PeerMatches)
					require.Equal(t, test.state, row.EffectiveState)
					require.ElementsMatch(t, test.want, permissionStrings(row.Permissions))
				})
			}
		}
	}
}

func TestCiliumMultipleSpecsHaveDistinctStableProvenance(t *testing.T) {
	snapshot := testSnapshot()
	for _, policyType := range ciliumPolicyTypes() {
		object := ciliumTestPolicy(t, policyType, "same-name", `
  endpointSelector: {matchLabels: {role: server}}
  ingress: [{toPorts: [{ports: [{port: "8080", protocol: TCP}]}]}]
  egress: [{toPorts: [{ports: [{port: "53", protocol: UDP}]}]}]`)
		extra := policyObject(t, `
spec:
  endpointSelector: {matchLabels: {role: server}}
  ingress: [{toPorts: [{ports: [{port: "8081", protocol: TCP}]}]}]
  ingressDeny: [{toPorts: [{ports: [{port: "8080", protocol: TCP}]}]}]
  egress: [{toPorts: [{ports: [{port: "9000", protocol: SCTP}]}]}]
  egressDeny: [{toPorts: [{ports: [{port: "53", protocol: UDP}]}]}]`)
		object.Object["specs"] = []any{extra.Object["spec"]}
		addCiliumPolicy(&snapshot, policyType, object)
	}
	result := evaluateServer(t, snapshot)
	require.Empty(t, result.Warnings)
	seen := sets.New[string]()
	for _, direction := range []Direction{Ingress, Egress} {
		primitive := findPrimitive(t, result.Direction(direction), PrimitivePod, "client", "client")
		want := []string{"TCP/8081"}
		if direction == Egress {
			want = []string{"SCTP/9000"}
		}
		require.Equal(t, AccessAllowed, primitive.State)
		require.Equal(t, want, permissionStrings(primitive.Permissions))
		explicit := 0
		for _, rule := range result.Direction(direction).Rules {
			if rule.Synthetic {
				continue
			}
			explicit++
			require.False(t, seen.Has(rule.StableID()))
			seen.Insert(rule.StableID())
			require.Equal(t, "same-name-uid", string(rule.ID.PolicyUID))
			require.Equal(t, "cilium.io/v2", rule.ID.PolicyVersion)
			require.Equal(t, 0, rule.ID.Index)
			require.Contains(t, []int{0, 1}, rule.ID.PolicySpecIndex)
			require.Contains(t, rule.YAML, "toPorts:")
			if rule.ID.Action == PolicyActionDeny {
				require.Equal(t, 1, rule.ID.PolicySpecIndex)
			}
		}
		require.Equal(t, 6, explicit)
	}
	slices.Reverse(snapshot.Pods)
	slices.Reverse(snapshot.Namespaces)
	repeated := evaluateServer(t, snapshot)
	for _, direction := range []Direction{Ingress, Egress} {
		var first, second []string
		for _, rule := range result.Direction(direction).Rules {
			first = append(first, rule.StableID())
		}
		for _, rule := range repeated.Direction(direction).Rules {
			second = append(second, rule.StableID())
		}
		require.Equal(t, first, second)
	}
}

func ciliumPairPolicy(
	t *testing.T, policyType PolicyType, namespace, name, role string, direction Direction,
	peerNamespace, peerRole string, allowed, denied []string,
) unstructured.Unstructured {
	t.Helper()
	field, prefix := strings.ToLower(direction.String()), ciliumPeerPrefix(direction)
	renderRule := func(ports []string) string {
		var items []string
		for _, port := range ports {
			items = append(items, fmt.Sprintf("{port: %q, protocol: TCP}", port))
		}
		return fmt.Sprintf(`
    - %sEndpoints:
        - matchLabels: {role: %s, io.kubernetes.pod.namespace: %s}
      toPorts: [{ports: [%s]}]
`, prefix, peerRole, peerNamespace, strings.Join(items, ", "))
	}
	spec := fmt.Sprintf("  endpointSelector: {matchLabels: {role: %s, io.kubernetes.pod.namespace: %s}}\n", role, namespace)
	if len(allowed) > 0 {
		spec += "  " + field + ":" + renderRule(allowed)
	}
	if len(denied) > 0 {
		spec += "  " + field + "Deny:" + renderRule(denied)
	}
	object := ciliumTestPolicy(t, policyType, name, spec)
	if policyType == PolicyTypeCiliumNetworkPolicy {
		object.SetNamespace(namespace)
	}
	return object
}

func findPodApplicability(t *testing.T, rows []ApplicabilityRow, namespace, name string) ApplicabilityRow {
	t.Helper()
	for _, row := range rows {
		if row.Primitive.Ref.Kind == PrimitivePod && row.Primitive.Ref.Namespace == namespace && row.Primitive.Ref.Name == name {
			return row
		}
	}
	require.FailNow(t, "pod applicability not found", "%s/%s", namespace, name)
	return ApplicabilityRow{}
}

func nativeTransportPolicy(direction Direction, namespace, role string, ports []netv1.NetworkPolicyPort) netv1.NetworkPolicy {
	policy := netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "transport", Namespace: namespace},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"role": role}},
		},
	}
	if direction == Egress {
		policy.Spec.PolicyTypes = []netv1.PolicyType{netv1.PolicyTypeEgress}
		policy.Spec.Egress = []netv1.NetworkPolicyEgressRule{{Ports: ports}}
	} else {
		policy.Spec.PolicyTypes = []netv1.PolicyType{netv1.PolicyTypeIngress}
		policy.Spec.Ingress = []netv1.NetworkPolicyIngressRule{{Ports: ports}}
	}
	return policy
}
