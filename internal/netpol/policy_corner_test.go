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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
)

func TestCiliumSelectorAliasTargets(t *testing.T) {
	for _, key := range []string{"role", "io.kubernetes.pod.namespace", "io.cilium.k8s.namespace.labels.team", "io.cilium.k8s.policy.serviceaccount"} {
		t.Run(key, func(t *testing.T) {
			for _, same := range []bool{false, true} {
				first := "other"
				if same {
					first = "client"
				}
				selector, unsupported, invalid, _ := normalizeCiliumSelector(&ciliumEndpointSelector{
					MatchLabels: map[string]string{"any:" + key: first, "k8s:" + key: "client"},
				}, "client", true, false)
				require.Empty(t, unsupported)
				require.Empty(t, invalid)
				selector.compile()
				compiled, values := selector.pod, labels.Set{"role": "client"}
				switch key {
				case "io.kubernetes.pod.namespace":
					compiled, values = selector.namespace, labels.Set{metadataNameLabel: "client"}
				case "io.cilium.k8s.namespace.labels.team":
					compiled, values = selector.namespace, labels.Set{"team": "client"}
				case "io.cilium.k8s.policy.serviceaccount":
					compiled, values = selector.serviceAccount, labels.Set{"name": "client"}
				}
				require.Equal(t, same, compiled.Matches(values),
					"normalizing label sources must preserve every conjunct, key=%s same=%t", key, same)
			}
		})
	}
}

func TestCiliumSelectorSourceAliasesRemainConjunctive(t *testing.T) {
	for _, policyType := range ciliumPolicyTypes() {
		t.Run(policyType.Kind(), func(t *testing.T) {
			snapshot := testSnapshot()
			snapshot.NetworkPolicies = []netv1.NetworkPolicy{
				nativeTransportPolicy(Egress, "server", "server", transportTestPorts()),
			}
			addCiliumPolicy(&snapshot, policyType, ciliumTestPolicy(t, policyType, "observe", `
  endpointSelector: {matchLabels: {role: server}}
  enableDefaultDeny: {egress: false}
  egress:
    - toEndpoints:
        - matchLabels: {"any:role": other, "k8s:role": client, io.kubernetes.pod.namespace: client}
      toPorts: [{ports: [{port: "80", protocol: TCP}]}]
    - toEndpoints:
        - matchLabels: {"any:role": client, "k8s:role": client, io.kubernetes.pod.namespace: client}
      toPorts: [{ports: [{port: "8080", protocol: TCP}]}]
specs:
  - endpointSelector: {matchLabels: {role: server}}
    enableDefaultDeny: {egress: false}
    egressDeny:
      - toEndpoints: [{matchLabels: {role: client, io.kubernetes.pod.namespace: client}}]
        toPorts: [{ports: [{port: "8081", protocol: TCP}]}]`))
			result := evaluateServer(t, &snapshot)
			peer := findPrimitive(t, result.Egress, PrimitivePod, "client", "client")
			require.Equal(t, AccessAllowed, peer.State)
			require.Equal(t, []string{"SCTP/9000", "TCP/8080", "UDP/5353"}, permissionStrings(peer.Permissions))
			require.Empty(t, peer.Warnings)
			checked := 0
			for _, rule := range result.Egress.Rules {
				if rule.ID.PolicyName != "observe" || rule.ID.Action != PolicyActionAllow {
					continue
				}
				checked++
				row := findPodApplicability(t, NewEvaluator().RuleApplicability(result, Egress, rule.ID, sets.New(PrimitivePod)), "client", "client")
				require.Equal(t, rule.ID.Index == 1, row.PeerMatches)
				require.Equal(t, rule.ID.Index == 1, row.OppositeSideAllows)
				if rule.ID.Index == 0 {
					require.Equal(t, AccessDisallowed, row.EffectiveState)
					require.Empty(t, row.Permissions)
				} else {
					require.Equal(t, AccessAllowed, row.EffectiveState)
					require.Equal(t, []string{"TCP/8080"}, permissionStrings(row.Permissions))
				}
			}
			require.Equal(t, 2, checked)
		})
	}
}

func TestCiliumRejectedEntryInvalidatesSiblingSpecs(t *testing.T) {
	for _, policyType := range ciliumPolicyTypes() {
		for _, specsOnly := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/specs-only=%t", policyType.Kind(), specsOnly), func(t *testing.T) {
				snapshot := testSnapshot()
				object := ciliumTestPolicy(t, policyType, "rejected-sibling", `
  endpointSelector: {matchLabels: {role: server}}
  egress: [{toPorts: [{ports: [{port: "443", protocol: TCP}]}]}]
specs:
  - endpointSelector: {matchLabels: {role: nonexistent}}
    egress: [{toPorts: [{ports: [{port: "70000", protocol: TCP}]}]}]`)
				path, invalidPath := "spec", "specs[0]"
				if specsOnly {
					object.Object["specs"] = append([]any{object.Object["spec"]}, object.Object["specs"].([]any)...)
					delete(object.Object, "spec")
					path, invalidPath = "specs[0]", "specs[1]"
				}
				addCiliumPolicy(&snapshot, policyType, object)
				result := evaluateServer(t, &snapshot)
				peer := findPrimitive(t, result.Egress, PrimitivePod, "client", "client")
				require.Equal(t, AccessPartialData, peer.State)
				require.Equal(t, []string{"SCTP/all", "TCP/all", "UDP/all"}, permissionStrings(peer.Permissions))
				rejection := "Cilium rejects this policy: " + invalidPath +
					`: egress allow rule 0: unable to parse port "70000": strconv.ParseUint: parsing "70000": value out of range`
				ref := "server/rejected-sibling"
				if policyType == PolicyTypeCiliumClusterwideNetworkPolicy {
					ref = "rejected-sibling"
				}
				require.Equal(t, []string{policyType.Kind() + " " + ref + " " + path + ": " + rejection}, peer.Warnings)
				require.Contains(t, result.Warnings, peer.Warnings[0])
				rule := findPolicyRule(t, result.Egress, "rejected-sibling")
				require.Equal(t, path, rule.PolicySpec)
				require.Equal(t, 0, rule.ID.PolicySpecIndex)
				require.Equal(t, 2, rule.PolicySpecCount)
				require.Equal(t, []string{rejection}, rule.Warnings)
				row := findPodApplicability(t, NewEvaluator().DirectionApplicability(result, Egress, sets.New(PrimitivePod)), "client", "client")
				require.True(t, row.PeerMatches)
				require.True(t, row.OppositeSideAllows)
				control := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
				require.Equal(t, AccessAllowed, control.State)
				require.Empty(t, control.Warnings)
			})
		}
	}
}

func TestCiliumUnsupportedFieldBranchesAreScoped(t *testing.T) {
	for _, test := range []struct {
		name    string
		rule    string
		warning string
		tls     bool
	}{
		{"to-requires", `toRequires: [{matchLabels: {env: prod}}]`,
			"fromRequires/toRequires identity constraints are not supported", false},
		{"to-groups", `toGroups: [{aws: {labels: {env: prod}}}]`,
			"cloud-provider groups require runtime Cilium resolution", false},
		{"cidr-group-selector", `toCIDRSet: [{cidrGroupSelector: {matchLabels: {env: prod}}}]`,
			"CIDR group references require runtime Cilium resolution", false},
		{"identity-selector", `toEndpoints: [{matchLabels: {io.cilium.k8s.policy.unmodeled: value}}]`,
			`peer selector cannot be evaluated: Cilium identity selector "io.cilium.k8s.policy.unmodeled" is not supported`, false},
		{"originating-tls", `toEndpoints: [{matchLabels: {role: client, io.kubernetes.pod.namespace: client}}]
      toPorts: [{ports: [{port: "443", protocol: TCP}], originatingTLS: {secret: {name: tls}}}]`,
			"Cilium TLS, SNI, and listener constraints cannot be evaluated from the policy snapshot", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := testSnapshot()
			addCiliumPolicy(&snapshot, PolicyTypeCiliumNetworkPolicy, ciliumTestPolicy(t, PolicyTypeCiliumNetworkPolicy, "features", `
  endpointSelector: {matchLabels: {role: server}}
  egress:
    - `+test.rule))
			result := evaluateServer(t, &snapshot)
			peer := findPrimitive(t, result.Egress, PrimitivePod, "client", "client")
			require.Equal(t, AccessPartialData, peer.State)
			require.Equal(t, []string{"CiliumNetworkPolicy server/features: egress allow rule 0: " + test.warning}, peer.Warnings)
			row := findPodApplicability(t, NewEvaluator().DirectionApplicability(result, Egress, sets.New(PrimitivePod)), "client", "client")
			require.Equal(t, test.tls, row.PeerMatches)
			require.Equal(t, test.tls, row.OppositeSideAllows)
			if test.tls {
				require.Equal(t, []string{"TCP/443"}, permissionStrings(peer.Permissions))
			} else {
				require.Empty(t, peer.Permissions)
			}
			other := findPrimitive(t, result.Egress, PrimitivePod, "server", "server")
			if test.tls {
				require.Equal(t, AccessDisallowed, other.State)
				require.Empty(t, other.Warnings)
			} else {
				require.Equal(t, AccessPartialData, other.State, "dynamic peers can match any peer")
			}
			control := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
			require.Equal(t, AccessAllowed, control.State)
			require.Empty(t, control.Warnings)
		})
	}
}

func TestIstioUnsupportedPredicateBranchesAreScoped(t *testing.T) {
	for _, test := range []struct {
		name      string
		source    string
		operation string
		warning   string
		l7        bool
	}{
		{"hosts", "", "hosts: [api.example]", "Istio L7 operation constraints cannot be evaluated from the policy snapshot", true},
		{"not-hosts", "", "notHosts: [admin.example]", "Istio L7 operation constraints cannot be evaluated from the policy snapshot", true},
		{"methods", "", "methods: [GET]", "Istio L7 operation constraints cannot be evaluated from the policy snapshot", true},
		{"not-methods", "", "notMethods: [DELETE]", "Istio L7 operation constraints cannot be evaluated from the policy snapshot", true},
		{"paths", "", `paths: ["/public*"]`, "Istio L7 operation constraints cannot be evaluated from the policy snapshot", true},
		{"not-paths", "", `notPaths: ["/private*"]`, "Istio L7 operation constraints cannot be evaluated from the policy snapshot", true},
		{"not-request-principals", "notRequestPrincipals: [issuer/blocked]", "",
			"requestPrincipals depend on JWT request identity", false},
		{"not-remote-ip-blocks", `notRemoteIpBlocks: ["192.0.2.0/24"]`, "",
			"remoteIpBlocks depend on proxy forwarding configuration", false},
	} {
		for _, action := range []string{"ALLOW", "DENY"} {
			t.Run(test.name+"/"+action, func(t *testing.T) {
				snapshot := istioTransportSnapshot()
				snapshot.Pods = append(snapshot.Pods, corev1.Pod{ObjectMeta: metav1.ObjectMeta{
					Name: "control", Namespace: "other", Labels: map[string]string{istioDataplaneModeLabel: "ambient"},
				}})
				snapshot.Namespaces = append(snapshot.Namespaces, corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "other"}})
				// Keep the opposite endpoint unrestricted so the negative
				// control tests authorization source scope, not network denial.
				snapshot.NetworkPolicies = []netv1.NetworkPolicy{nativeTransportPolicy(Ingress, "server", "server", transportTestPorts())}
				snapshot.IstioAuthorizationPolicies = []unstructured.Unstructured{
					istioTestPolicy(t, "server", "predicate", "server", action, fmt.Sprintf(
						`[{from: [{source: {namespaces: [client], %s}}], to: [{operation: {ports: ["8080"], %s}}]}]`,
						test.source, test.operation)),
				}
				result := evaluateServer(t, &snapshot)
				peer := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
				require.Equal(t, AccessPartialData, peer.State)
				want := []string{"SCTP/9000", "UDP/5353"}
				if action == "DENY" {
					want = []string{"SCTP/9000", "TCP/8080", "TCP/8081", "UDP/5353"}
				} else if test.l7 {
					want = []string{"SCTP/9000", "TCP/8080", "UDP/5353"}
				}
				require.Equal(t, want, permissionStrings(peer.Permissions))
				expectedWarnings := []string{"AuthorizationPolicy server/predicate: ingress " + strings.ToLower(action) + " rule 0: " + test.warning}
				if action == "DENY" && test.l7 {
					expectedWarnings = append(expectedWarnings,
						"AuthorizationPolicy server/predicate: ingress deny rule 0: DENY has unmodeled L7 predicates; its ports are not subtracted")
				}
				require.ElementsMatch(t, expectedWarnings, peer.Warnings)
				row := findPodApplicability(t, NewEvaluator().DirectionApplicability(result, Ingress, sets.New(PrimitivePod)), "client", "client")
				require.True(t, row.PeerMatches)
				require.True(t, row.OppositeSideAllows, "non-TCP permissions survive every authorization predicate")
				control := findPrimitive(t, result.Ingress, PrimitivePod, "other", "control")
				require.Equal(t, AccessAllowed, control.State)
				require.Empty(t, control.Warnings)
				controlPorts := []string{"SCTP/9000", "UDP/5353"}
				if action == "DENY" {
					controlPorts = []string{"SCTP/9000", "TCP/8080", "TCP/8081", "UDP/5353"}
				}
				require.Equal(t, controlPorts, permissionStrings(control.Permissions))
			})
		}
	}
}

func TestIstioTargetRefsUncertaintyIsNamespaceScoped(t *testing.T) {
	for _, field := range []string{"targetRef", "targetRefs"} {
		t.Run(field, func(t *testing.T) {
			snapshot := istioTransportSnapshot()
			object := istioTestPolicy(t, "server", "attached", "", "ALLOW", "[]")
			target := map[string]any{"kind": "Service", "name": "api", "group": ""}
			if field == "targetRefs" {
				object.Object["spec"].(map[string]any)[field] = []any{target}
			} else {
				object.Object["spec"].(map[string]any)[field] = target
			}
			snapshot.IstioAuthorizationPolicies = []unstructured.Unstructured{object}
			result := evaluateServer(t, &snapshot)
			peer := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
			require.Equal(t, AccessPartialData, peer.State, "the service attachment cannot be resolved from workload labels")
			require.Equal(t, []string{"SCTP/9000", "TCP/8080", "TCP/8081", "UDP/5353"}, permissionStrings(peer.Permissions))
			require.Equal(t, []string{
				"AuthorizationPolicy server/attached: targetRefs cannot be resolved to pods from the policy snapshot; the pods it selects cannot be determined",
			}, peer.Warnings)
			control := findPrimitive(t, result.Egress, PrimitivePod, "client", "client")
			require.Equal(t, AccessAllowed, control.State)
			require.Empty(t, control.Warnings)
		})
	}
}

func TestIstioInjectionSignalPrecedence(t *testing.T) {
	for _, test := range []struct {
		name       string
		label      string
		annotation string
		partial    bool
	}{
		{"annotation", "", "true", true},
		{"label-precedence", "true", "false", true},
		{"optout-precedence", "false", "true", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := testSnapshot()
			delete(snapshot.Namespaces[1].Labels, istioDataplaneModeLabel)
			snapshot.Pods[1].Annotations = map[string]string{istioInjectLabel: test.annotation}
			if test.label != "" {
				snapshot.Pods[1].Labels[istioInjectLabel] = test.label
			}
			snapshot.NetworkPolicies = []netv1.NetworkPolicy{
				nativeTransportPolicy(Ingress, "server", "server", []netv1.NetworkPolicyPort{numericPolicyPort(8080, 0)}),
			}
			snapshot.IstioAuthorizationPolicies = []unstructured.Unstructured{
				istioTestPolicy(t, "server", "allow-nothing", "server", "ALLOW", "[]"),
			}
			result := evaluateServer(t, &snapshot)
			peer := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
			row := findPodApplicability(t, NewEvaluator().DirectionApplicability(result, Ingress, sets.New(PrimitivePod)), "client", "client")
			require.True(t, row.PeerMatches)
			require.Equal(t, !test.partial, row.OppositeSideAllows)
			if test.partial {
				require.Equal(t, AccessPartialData, peer.State)
				require.Empty(t, peer.Permissions)
				require.Equal(t, []string{
					"Istio AuthorizationPolicy enforcement for pod server/server is uncertain: " +
						"sidecar injection is enabled for pod server/server, but it has no istio-proxy container",
				}, peer.Warnings)
			} else {
				require.Equal(t, AccessAllowed, peer.State)
				require.Equal(t, []string{"TCP/8080"}, permissionStrings(peer.Permissions))
				require.Empty(t, peer.Warnings)
			}
			control := findPrimitive(t, result.Egress, PrimitivePod, "client", "client")
			require.Equal(t, AccessAllowed, control.State)
			require.Empty(t, control.Warnings)
		})
	}
}

func transportTestPorts() []netv1.NetworkPolicyPort {
	udp, sctp := corev1.ProtocolUDP, corev1.ProtocolSCTP
	dns, stream := numericPolicyPort(5353, 0), numericPolicyPort(9000, 0)
	dns.Protocol, stream.Protocol = &udp, &sctp
	return []netv1.NetworkPolicyPort{numericPolicyPort(8080, 0), numericPolicyPort(8081, 0), dns, stream}
}
