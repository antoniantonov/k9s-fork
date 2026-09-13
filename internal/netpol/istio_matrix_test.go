// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/sets"
)

func TestIstioDestinationAuthorizationMatrix(t *testing.T) {
	all := []string{"SCTP/9000", "TCP/8080", "TCP/8081", "UDP/5353"}
	nonTCP := []string{"SCTP/9000", "UDP/5353"}
	tests := []struct {
		name        string
		action      string
		rules       string
		deny        string
		dryRun      bool
		sourceLocal bool
		want        []string
	}{
		{name: "no-authorization", want: all},
		{name: "default-allow-omitted-rules", action: "ALLOW", want: nonTCP},
		{name: "allow-empty-rules", action: "ALLOW", rules: "[]", want: nonTCP},
		{name: "allow-empty-matching-rule", action: "ALLOW", rules: "[{}]", want: all},
		{name: "allow-deny-precedence", action: "ALLOW", rules: `[{to: [{operation: {ports: ["8080", "8081"]}}]}]`,
			deny: `[{to: [{operation: {ports: ["8081"]}}]}]`, want: []string{"SCTP/9000", "TCP/8080", "UDP/5353"}},
		{name: "allow-disjoint-ports", action: "ALLOW", rules: `[{to: [{operation: {ports: ["9090"]}}]}]`, want: nonTCP},
		{name: "deny-only", action: "DENY", rules: `[{to: [{operation: {ports: ["8081"]}}]}]`,
			want: []string{"SCTP/9000", "TCP/8080", "UDP/5353"}},
		{name: "deny-all-tcp", action: "DENY", rules: "[{}]", want: nonTCP},
		{name: "deny-omitted-rules", action: "DENY", want: all},
		{name: "deny-empty-rules", action: "DENY", rules: "[]", want: all},
		{name: "audit-does-not-enforce", action: "AUDIT", rules: "[{}]", want: all},
		{name: "dry-run-does-not-enforce", action: "DENY", rules: "[{}]", dryRun: true, want: all},
		{name: "source-local-does-not-constrain-egress", action: "ALLOW", rules: `[{to: [{operation: {ports: ["8080"]}}]}]`,
			sourceLocal: true, want: []string{"SCTP/9000", "TCP/8080", "UDP/5353"}},
	}
	for _, version := range []string{"security.istio.io/v1", "security.istio.io/v1beta1"} {
		for _, test := range tests {
			t.Run(version+"/"+test.name, func(t *testing.T) {
				snapshot := istioTransportSnapshot()
				if test.action != "" {
					object := istioTestPolicy(t, "server", "destination-authz", "server", test.action, test.rules)
					object.SetAPIVersion(version)
					if test.dryRun {
						object.SetAnnotations(map[string]string{"istio.io/dry-run": "true"})
					}
					if test.name == "default-allow-omitted-rules" {
						unstructured.RemoveNestedField(object.Object, "spec", "action")
					}
					snapshot.IstioAuthorizationPolicies = append(snapshot.IstioAuthorizationPolicies, object)
				}
				if test.deny != "" {
					object := istioTestPolicy(t, "server", "destination-deny", "server", "DENY", test.deny)
					object.SetAPIVersion(version)
					snapshot.IstioAuthorizationPolicies = append(snapshot.IstioAuthorizationPolicies, object)
				}
				if test.sourceLocal {
					snapshot.IstioAuthorizationPolicies = append(snapshot.IstioAuthorizationPolicies,
						istioTestPolicy(t, "client", "source-local-ingress", "client", "DENY", "[{}]"),
					)
				}
				for _, side := range []struct {
					namespace string
					peer      string
					direction Direction
				}{{"client", "server", Egress}, {"server", "client", Ingress}} {
					t.Run(side.direction.String(), func(t *testing.T) {
						result, err := NewEvaluator().EvaluateSubject(
							SubjectRef{Kind: SubjectPod, Namespace: side.namespace, Name: side.namespace}, snapshot, Options{},
						)
						require.NoError(t, err)
						require.Empty(t, result.Warnings)
						primitive := findPrimitive(t, result.Direction(side.direction), PrimitivePod, side.peer, side.peer)
						require.Equal(t, AccessAllowed, primitive.State, "UDP and SCTP remain permitted")
						require.Equal(t, test.want, permissionStrings(primitive.Permissions))
						for _, evidence := range primitive.Evidence {
							require.NotEqual(t, "source-local-ingress", evidence.RuleID.PolicyName)
							if evidence.RuleID.SourceType() == PolicyTypeIstioAuthorizationPolicy {
								require.Equal(t, Ingress, evidence.RuleID.Direction)
								require.Equal(t, "server", evidence.RuleID.PolicyNamespace)
								require.Equal(t, version, evidence.RuleID.PolicyVersion)
							}
						}
						for _, rule := range result.Egress.Rules {
							require.NotEqual(t, PolicyTypeIstioAuthorizationPolicy, rule.ID.SourceType(),
								"AuthorizationPolicy never creates a source-local egress rule")
						}
						row := findPodApplicability(t, NewEvaluator().DirectionApplicability(
							result, side.direction, sets.New(PrimitivePod),
						), side.peer, side.peer)
						require.Equal(t, primitive.State, row.EffectiveState)
						require.Equal(t, test.want, permissionStrings(row.Permissions))
					})
				}
			})
		}
	}
}

func TestIstioEmptyAllowDeniesTCPInBothViews(t *testing.T) {
	snapshot := testSnapshot()
	tcp := []netv1.NetworkPolicyPort{numericPolicyPort(8080, 0)}
	snapshot.NetworkPolicies = []netv1.NetworkPolicy{
		nativeTransportPolicy(Egress, "client", "client", tcp),
		nativeTransportPolicy(Ingress, "server", "server", tcp),
	}
	snapshot.IstioAuthorizationPolicies = []unstructured.Unstructured{
		istioTestPolicy(t, "server", "empty-allow", "server", "ALLOW", "[]"),
	}
	for _, side := range []struct {
		namespace string
		peer      string
		direction Direction
	}{{"client", "server", Egress}, {"server", "client", Ingress}} {
		t.Run(side.direction.String(), func(t *testing.T) {
			result, err := NewEvaluator().EvaluateSubject(
				SubjectRef{Kind: SubjectPod, Namespace: side.namespace, Name: side.namespace}, snapshot, Options{},
			)
			require.NoError(t, err)
			primitive := findPrimitive(t, result.Direction(side.direction), PrimitivePod, side.peer, side.peer)
			require.Equal(t, AccessDisallowed, primitive.State)
			require.Empty(t, primitive.Permissions)
			require.Empty(t, result.Warnings)
			native := findPolicyRule(t, result.Direction(side.direction), "transport")
			selected := findPodApplicability(t, NewEvaluator().RuleApplicability(
				result, side.direction, native.ID, sets.New(PrimitivePod),
			), side.peer, side.peer)
			require.True(t, selected.PeerMatches)
			require.False(t, selected.OppositeSideAllows)
			require.Equal(t, AccessDisallowed, selected.EffectiveState)
			require.Empty(t, selected.Permissions)
			if side.direction == Egress {
				row := findPodApplicability(t, NewEvaluator().DirectionApplicability(
					result, Egress, sets.New(PrimitivePod),
				), side.peer, side.peer)
				require.False(t, row.OppositeSideAllows, "the destination authorization layer denies all modeled TCP")
			}
		})
	}
}

func TestIstioAuthorizationRootAndWorkloadScope(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		role      string
		applies   bool
	}{
		{"configured-root-with-selector", "mesh-root", "server", true},
		{"configured-root-without-selector", "mesh-root", "", true},
		{"old-default-is-not-root", "istio-system", "server", false},
		{"workload-namespace", "server", "server", true},
		{"different-workload-namespace", "client", "server", false},
		{"unmatched-root-selector", "mesh-root", "other", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := istioTransportSnapshot()
			snapshot.IstioRootNamespace = "mesh-root"
			snapshot.IstioAuthorizationPolicies = []unstructured.Unstructured{
				istioTestPolicy(t, test.namespace, "scoped", test.role, "ALLOW", `[{to: [{operation: {ports: ["8080"]}}]}]`),
			}
			for _, side := range []struct {
				namespace string
				peer      string
				direction Direction
			}{{"client", "server", Egress}, {"server", "client", Ingress}} {
				result, err := NewEvaluator().EvaluateSubject(
					SubjectRef{Kind: SubjectPod, Namespace: side.namespace, Name: side.namespace}, snapshot, Options{},
				)
				require.NoError(t, err)
				primitive := findPrimitive(t, result.Direction(side.direction), PrimitivePod, side.peer, side.peer)
				require.Equal(t, AccessAllowed, primitive.State)
				want := []string{"SCTP/9000", "TCP/8080", "UDP/5353"}
				if !test.applies {
					want = []string{"SCTP/9000", "TCP/8080", "TCP/8081", "UDP/5353"}
				}
				require.Equal(t, want, permissionStrings(primitive.Permissions))
				require.Empty(t, result.Warnings)
			}
		})
	}
}

func TestIstioSourceIdentityAndIPBoundaries(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		matches bool
		warning string
	}{
		{"ipv4-source", `ipBlocks: ["192.0.2.0/24"]`, true, ""},
		{"ipv6-source", `ipBlocks: ["2001:db8::/64"]`, true, ""},
		{"unmatched-address", `ipBlocks: ["198.51.100.0/24"]`, false, ""},
		{"namespace", `namespaces: [client]`, true, "mTLS identity"},
		{"namespace-negative", `namespaces: [client], notNamespaces: [client]`, false, "mTLS identity"},
		{"principal-prefix", `principals: ["cluster.local/ns/client/sa/*"]`, true, "mTLS identity"},
		{"principal-negative", `notPrincipals: ["cluster.local/ns/client/sa/caller"]`, false, "mTLS identity"},
		{"service-account-qualified", `serviceAccounts: ["client/caller"]`, true, "mTLS identity"},
		{"service-account-policy-relative", `serviceAccounts: [caller]`, false, "mTLS identity"},
		{"service-account-negative", `notServiceAccounts: ["client/caller"]`, false, "mTLS identity"},
		{"trust-domain", `trustDomains: [cluster.local]`, true, "mTLS identity"},
		{"trust-domain-negative", `notTrustDomains: [cluster.local]`, false, "mTLS identity"},
		{"address-and-identity", `ipBlocks: ["192.0.2.0/24"], namespaces: [client]`, true, "CIDR applicability"},
		{"jwt-unsupported", `requestPrincipals: ["issuer/user"]`, false, "JWT request identity"},
		{"forwarded-ip-unsupported", `remoteIpBlocks: ["192.0.2.0/24"]`, false, "proxy forwarding"},
		{"negative-ip-unsupported", `notIpBlocks: ["198.51.100.0/24"]`, false, "notIpBlocks"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := istioTransportSnapshot()
			snapshot.Pods[0].Spec.ServiceAccountName = "caller"
			snapshot.Pods[0].Status = corev1.PodStatus{
				PodIP: "192.0.2.10", PodIPs: []corev1.PodIP{{IP: "192.0.2.10"}, {IP: "2001:db8::10"}},
			}
			snapshot.IstioAuthorizationPolicies = []unstructured.Unstructured{
				istioTestPolicy(t, "server", "source-constraints", "server", "ALLOW",
					fmt.Sprintf("[{from: [{source: {%s}}], to: [{operation: {ports: [\"8080\"]}}]}]", test.source)),
			}
			for _, side := range []struct {
				namespace string
				peer      string
				direction Direction
			}{{"client", "server", Egress}, {"server", "client", Ingress}} {
				t.Run(side.direction.String(), func(t *testing.T) {
					result, err := NewEvaluator().EvaluateSubject(
						SubjectRef{Kind: SubjectPod, Namespace: side.namespace, Name: side.namespace}, snapshot, Options{},
					)
					require.NoError(t, err)
					primitive := findPrimitive(t, result.Direction(side.direction), PrimitivePod, side.peer, side.peer)
					want := []string{"SCTP/9000", "UDP/5353"}
					if test.matches {
						want = []string{"SCTP/9000", "TCP/8080", "UDP/5353"}
					}
					require.Equal(t, want, permissionStrings(primitive.Permissions))
					wantState := AccessAllowed
					if test.warning != "" {
						wantState = AccessPartialData
						require.Contains(t, strings.Join(result.Warnings, "\n"), test.warning)
						require.Contains(t, strings.Join(primitive.Warnings, "\n"), test.warning)
					} else {
						require.Empty(t, result.Warnings)
					}
					require.Equal(t, wantState, primitive.State)
					if side.direction == Ingress {
						rule := findPolicyRule(t, result.Ingress, "source-constraints")
						row := findApplicability(t, NewEvaluator().RuleApplicability(
							result, Ingress, rule.ID, sets.New(PrimitivePod),
						))
						require.Equal(t, test.matches, row.PeerMatches)
						if test.warning != "" {
							require.Equal(t, AccessPartialData, row.EffectiveState)
						}
						if test.name == "address-and-identity" {
							cidr := findCIDRPrimitive(t, result.Ingress, "192.0.2.0/24", nil)
							require.Equal(t, AccessPartialData, cidr.State)
							require.NotContains(t, permissionStrings(cidr.Permissions), "TCP/8080",
								"an address-only peer cannot prove the ANDed identity")
						}
					}
				})
			}
		})
	}
}

func TestIstioAuthorizationAggregateSubjectsAndEgressPeers(t *testing.T) {
	for _, kind := range []SubjectKind{SubjectNamespace, SubjectDeployment, SubjectJob} {
		t.Run(kind.String(), func(t *testing.T) {
			snapshot := testSnapshot()
			snapshot.Pods[1].Labels["access"] = "allowed"
			blocked := snapshot.Pods[1].DeepCopy()
			blocked.Name, blocked.UID = "blocked", "blocked"
			blocked.Labels["access"] = "blocked"
			snapshot.Pods = append(snapshot.Pods, *blocked)
			ref := SubjectRef{Kind: kind, Namespace: "server", Name: "group"}
			primitiveKind := PrimitiveNamespace
			switch kind {
			case SubjectNamespace:
				ref.Name = "server"
			case SubjectDeployment:
				primitiveKind = PrimitiveDeployment
				snapshot.Deployments = []appsv1.Deployment{{ObjectMeta: metav1.ObjectMeta{
					Namespace: "server", Name: "group", UID: "deployment",
				}}}
				snapshot.ReplicaSets = []appsv1.ReplicaSet{{ObjectMeta: metav1.ObjectMeta{
					Namespace: "server", Name: "group-rs", UID: "replicaset",
					OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", UID: "deployment"}},
				}}}
				for _, index := range []int{1, 2} {
					snapshot.Pods[index].OwnerReferences = []metav1.OwnerReference{{Kind: "ReplicaSet", UID: "replicaset"}}
				}
			case SubjectJob:
				primitiveKind = PrimitiveJob
				snapshot.Jobs = []batchv1.Job{{ObjectMeta: metav1.ObjectMeta{
					Namespace: "server", Name: "group", UID: "job",
				}}}
				for _, index := range []int{1, 2} {
					snapshot.Pods[index].OwnerReferences = []metav1.OwnerReference{{Kind: "Job", UID: "job"}}
				}
			}
			tcp := []netv1.NetworkPolicyPort{numericPolicyPort(8080, 0)}
			snapshot.NetworkPolicies = []netv1.NetworkPolicy{
				nativeTransportPolicy(Egress, "client", "client", tcp),
				nativeTransportPolicy(Ingress, "server", "server", tcp),
			}
			allow := istioTestPolicy(t, "server", "allow-one", "server", "ALLOW", `[{to: [{operation: {ports: ["8080"]}}]}]`)
			require.NoError(t, unstructured.SetNestedStringMap(allow.Object, map[string]string{"access": "allowed"}, "spec", "selector", "matchLabels"))
			snapshot.IstioAuthorizationPolicies = []unstructured.Unstructured{
				istioTestPolicy(t, "server", "default-deny", "server", "ALLOW", "[]"), allow,
			}

			result, err := NewEvaluator().EvaluateSubject(ref, snapshot, Options{})
			require.NoError(t, err)
			require.Len(t, result.Subject.Pods, 2)
			require.Empty(t, result.Warnings)
			primitive := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
			require.Equal(t, AccessPartial, primitive.State)
			require.Equal(t, 1, primitive.AllowedPairs)
			require.Equal(t, 2, primitive.TotalPairs)
			require.Equal(t, []string{"TCP/8080"}, permissionStrings(primitive.Permissions))
			rule := findPolicyRule(t, result.Ingress, "allow-one")
			require.Equal(t, 1, rule.SubjectPodCount)
			require.Equal(t, 1, rule.SubjectMatchCount)
			row := findApplicability(t, NewEvaluator().RuleApplicability(result, Ingress, rule.ID, sets.New(PrimitivePod)))
			require.True(t, row.PeerMatches)
			require.False(t, row.OppositeSideAllows)
			require.Equal(t, AccessPartial, row.EffectiveState)
			require.Equal(t, []string{"TCP/8080"}, permissionStrings(row.Permissions))

			source, err := NewEvaluator().EvaluateSubject(
				SubjectRef{Kind: SubjectPod, Namespace: "client", Name: "client"}, snapshot, Options{},
			)
			require.NoError(t, err)
			namespace := "server"
			if primitiveKind == PrimitiveNamespace {
				namespace = ""
			}
			destination := findPrimitive(t, source.Egress, primitiveKind, namespace, ref.Name)
			require.Equal(t, AccessPartial, destination.State)
			require.Equal(t, 1, destination.AllowedPairs)
			require.Equal(t, 2, destination.TotalPairs)
			require.Equal(t, []string{"TCP/8080"}, permissionStrings(destination.Permissions))
		})
	}
}

func istioTransportSnapshot() Snapshot {
	snapshot := testSnapshot()
	udp, sctp := corev1.ProtocolUDP, corev1.ProtocolSCTP
	dns, stream := numericPolicyPort(5353, 0), numericPolicyPort(9000, 0)
	dns.Protocol, stream.Protocol = &udp, &sctp
	ports := []netv1.NetworkPolicyPort{numericPolicyPort(8080, 0), numericPolicyPort(8081, 0), dns, stream}
	snapshot.NetworkPolicies = []netv1.NetworkPolicy{
		nativeTransportPolicy(Egress, "client", "client", ports),
		nativeTransportPolicy(Ingress, "server", "server", ports),
	}
	return snapshot
}

func istioTestPolicy(t *testing.T, namespace, name, role, action, rules string) unstructured.Unstructured {
	t.Helper()
	spec := "  action: " + action + "\n"
	if role != "" {
		spec += "  selector: {matchLabels: {role: " + role + "}}\n"
	}
	if rules != "" {
		spec += "  rules: " + rules + "\n"
	}
	return policyObject(t, fmt.Sprintf(`
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata: {name: %s, namespace: %s, uid: %s-uid}
spec:
%s
`, name, namespace, name, spec))
}
