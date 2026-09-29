// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/yaml"
)

func TestCiliumNetworkPolicyEvaluatesNamespacedIngress(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.Pods[0].Spec.ServiceAccountName = "caller"
	snapshot.Pods[1].Spec.ServiceAccountName = "api"
	snapshot.CiliumNetworkPolicies = []unstructured.Unstructured{policyObject(t, `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-client
  namespace: server
  uid: cnp-uid
spec:
  endpointSelector:
    matchLabels:
      role: server
      io.cilium.k8s.policy.serviceaccount: api
  ingress:
    - fromEndpoints:
        - matchLabels:
            k8s:role: client
            k8s:io.kubernetes.pod.namespace: client
            k8s:io.cilium.k8s.policy.serviceaccount: caller
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
`)}

	result, err := NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, snapshot, Options{},
	)
	require.NoError(t, err)
	primitive := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
	require.Equal(t, AccessAllowed, primitive.State)
	require.Equal(t, []string{"TCP/8080"}, permissionStrings(primitive.Permissions))

	rule := findPolicyRule(t, result.Ingress, "allow-client")
	require.Equal(t, PolicyTypeCiliumNetworkPolicy, rule.ID.SourceType())
	require.Equal(t, "cilium.io/v2", rule.ID.PolicyVersion)
	require.Equal(t, PolicyActionAllow, rule.ID.Action)
	require.Equal(t, "cnp-uid", string(rule.ID.PolicyUID))
	require.Contains(t, rule.Peers[0], "kubernetes.io/metadata.name=client")
	require.Contains(t, rule.Peers[0], "serviceAccountSelector=name=caller")
}

func TestCiliumClusterwideNetworkPolicySelectsAcrossNamespaces(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.CiliumClusterwideNetworkPolicies = []unstructured.Unstructured{policyObject(t, `
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: cluster-ingress
  uid: ccnp-uid
specs:
  - endpointSelector:
      matchLabels:
        role: server
        io.cilium.k8s.namespace.labels.team: server
    ingress:
      - fromEndpoints:
          - matchLabels:
              role: client
              io.cilium.k8s.namespace.labels.team: client
    egress:
      - toEndpoints:
          - matchLabels:
              role: client
              io.cilium.k8s.namespace.labels.team: client
        toPorts:
          - ports:
              - port: "8443"
                protocol: TCP
`)}

	result, err := NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, snapshot, Options{},
	)
	require.NoError(t, err)
	primitive := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
	require.Equal(t, AccessAllowed, primitive.State)
	require.Equal(t, []string{"SCTP/all", "TCP/all", "UDP/all"}, permissionStrings(primitive.Permissions))
	egress := findPrimitive(t, result.Egress, PrimitivePod, "client", "client")
	require.Equal(t, AccessAllowed, egress.State)
	require.Equal(t, []string{"TCP/8443"}, permissionStrings(egress.Permissions))

	rule := findPolicyRule(t, result.Ingress, "cluster-ingress")
	require.Equal(t, PolicyTypeCiliumClusterwideNetworkPolicy, rule.ID.SourceType())
	require.Equal(t, 0, rule.ID.PolicySpecIndex)
	require.Contains(t, rule.PolicySelector, "namespaceSelector=team=server")
	require.Contains(t, rule.Peers[0], "namespaceSelector=team=client")
}

func TestCiliumExplicitDenySubtractsMatchingPorts(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.CiliumNetworkPolicies = []unstructured.Unstructured{policyObject(t, `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-with-deny
  namespace: server
spec:
  endpointSelector:
    matchLabels:
      role: server
  ingress:
    - fromEndpoints:
        - matchLabels:
            role: client
            io.kubernetes.pod.namespace: client
      toPorts:
        - ports:
            - {port: "8000", endPort: 8010, protocol: TCP}
  ingressDeny:
    - fromEndpoints:
        - matchLabels:
            role: client
            io.kubernetes.pod.namespace: client
      toPorts:
        - ports:
            - {port: "8005", protocol: TCP}
`)}

	result, err := NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, snapshot, Options{},
	)
	require.NoError(t, err)
	primitive := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
	require.Equal(t, AccessAllowed, primitive.State)
	require.Equal(t, []string{"TCP/8000-8004", "TCP/8006-8010"}, permissionStrings(primitive.Permissions))
	allowRule := findPolicyRuleAction(t, result.Ingress, "allow-with-deny", PolicyActionAllow)
	denyRule := findPolicyRuleAction(t, result.Ingress, "allow-with-deny", PolicyActionDeny)
	require.Equal(t, PolicyActionDeny, denyRule.ID.Action)

	allowRow := findApplicability(t, NewEvaluator().RuleApplicability(
		result, Ingress, allowRule.ID, sets.New(PrimitivePod),
	))
	require.Equal(t, AccessAllowed, allowRow.EffectiveState)
	require.Equal(t, []string{"TCP/8000-8004", "TCP/8006-8010"}, permissionStrings(allowRow.Permissions))

	denyRow := findApplicability(t, NewEvaluator().RuleApplicability(
		result, Ingress, denyRule.ID, sets.New(PrimitivePod),
	))
	require.Equal(t, AccessDisallowed, denyRow.EffectiveState)
	require.Empty(t, denyRow.Permissions)
}

func TestIstioAuthorizationPolicyRestrictsDestinationIngress(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.Pods[0].Spec.ServiceAccountName = "caller"
	snapshot.Pods = append(snapshot.Pods, corev1.Pod{
		ObjectMeta: snapshot.Pods[0].ObjectMeta,
		Spec:       corev1.PodSpec{ServiceAccountName: "other"},
	})
	snapshot.Pods[2].Name = "other"
	snapshot.Pods[2].UID = "other"
	snapshot.IstioAuthorizationPolicies = []unstructured.Unstructured{policyObject(t, `
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: server-authz
  namespace: server
  uid: authz-uid
spec:
  selector:
    matchLabels:
      role: server
  action: ALLOW
  rules:
    - from:
        - source:
            serviceAccounts: ["client/caller"]
      to:
        - operation:
            ports: ["8080"]
`)}

	result, err := NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, snapshot, Options{},
	)
	require.NoError(t, err)
	allowed := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
	require.Equal(t, AccessAllowed, allowed.State, "identity matching is a lower-confidence note, not partial data")
	require.Equal(t, []string{"SCTP/all", "TCP/8080", "UDP/all"}, permissionStrings(allowed.Permissions))
	other := findPrimitive(t, result.Ingress, PrimitivePod, "client", "other")
	require.Equal(t, AccessAllowed, other.State)
	require.Equal(t, []string{"SCTP/all", "UDP/all"}, permissionStrings(other.Permissions))
	require.Empty(t, result.Warnings)

	rule := findPolicyRule(t, result.Ingress, "server-authz")
	require.Empty(t, rule.Warnings)
	require.Contains(t, strings.Join(rule.Notes, "\n"), "mesh mTLS")
	require.Equal(t, PolicyTypeIstioAuthorizationPolicy, rule.ID.SourceType())
	require.Equal(t, PolicyActionAllow, rule.ID.Action)
	require.Equal(t, "security.istio.io/v1", rule.ID.PolicyVersion)
	require.Contains(t, rule.Peers[0], "serviceAccounts=client/caller")
}

func TestIstioDenyOverridesAllowByPort(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.IstioAuthorizationPolicies = []unstructured.Unstructured{
		policyObject(t, `
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: allow-all
  namespace: server
spec:
  selector:
    matchLabels:
      role: server
  action: ALLOW
  rules:
    - {}
`),
		policyObject(t, `
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: deny-admin
  namespace: server
spec:
  selector:
    matchLabels:
      role: server
  action: DENY
  rules:
    - to:
        - operation:
            ports: ["8080"]
`),
	}

	result, err := NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, snapshot, Options{},
	)
	require.NoError(t, err)
	primitive := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
	require.Equal(t, AccessAllowed, primitive.State)
	require.Equal(t, []string{"SCTP/all", "TCP/1-8079", "TCP/8081-65535", "UDP/all"}, permissionStrings(primitive.Permissions))
	require.Equal(t, PolicyActionDeny, findPolicyRule(t, result.Ingress, "deny-admin").ID.Action)
}

func TestIstioConditionalDenyDoesNotRemoveWholePort(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.IstioAuthorizationPolicies = []unstructured.Unstructured{
		policyObject(t, `
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: allow-web
  namespace: server
spec:
  selector:
    matchLabels:
      role: server
  action: ALLOW
  rules:
    - to:
        - operation:
            ports: ["8080"]
`),
		policyObject(t, `
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: deny-get
  namespace: server
spec:
  selector:
    matchLabels:
      role: server
  action: DENY
  rules:
    - to:
        - operation:
            ports: ["8080"]
            methods: ["GET"]
`),
	}

	result, err := NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, snapshot, Options{},
	)
	require.NoError(t, err)
	primitive := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
	require.Equal(t, AccessPartialData, primitive.State)
	require.Contains(t, permissionStrings(primitive.Permissions), "TCP/8080")
	require.Contains(t, strings.Join(result.Warnings, "\n"), "ports are not subtracted")
}

func TestUnsupportedCustomPolicySemanticsProducePartialData(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.CiliumNetworkPolicies = []unstructured.Unstructured{policyObject(t, `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: fqdn-egress
  namespace: server
spec:
  endpointSelector:
    matchLabels:
      role: server
  egress:
    - toFQDNs:
        - matchName: example.com
`)}

	result, err := NewEvaluator().EvaluateSubject(
		SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}, snapshot, Options{},
	)
	require.NoError(t, err)
	require.NotEmpty(t, result.Warnings)
	require.Contains(t, result.Warnings[0], "toFQDNs")
	for _, primitive := range result.Egress.Primitives[PrimitivePod] {
		require.Equal(t, AccessPartialData, primitive.State)
	}
}

func TestUnsupportedCiliumClusterIdentitySelectorIsExplicit(t *testing.T) {
	object := policyObject(t, `
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: remote-cluster
spec:
  endpointSelector:
    matchLabels:
      io.cilium.k8s.policy.cluster: cluster-two
  ingress:
    - {}
`)
	policies, errs := normalizeCiliumPolicy(&object, PolicyTypeCiliumClusterwideNetworkPolicy)
	require.Len(t, policies, 1)
	require.Equal(t, policySelectionUnknown, policies[0].State)
	require.True(t, policies[0].ClusterScoped)
	require.ErrorContains(t, errors.Join(errs...), "local cluster name")
	require.Contains(t, policies[0].reasons[0], "CiliumClusterwideNetworkPolicy remote-cluster: endpointSelector cannot be evaluated")
}

func TestCiliumSelectorCIDREntityAndPortNormalization(t *testing.T) {
	selector, unsupported, invalid, labelsOnly := normalizeCiliumSelector(&ciliumEndpointSelector{
		MatchLabels: map[string]string{
			"k8s:app":                                 "api",
			"io.kubernetes.pod.namespace":             "payments",
			"io.cilium.k8s.namespace.labels.team":     "backend",
			"io.cilium.k8s.policy.serviceaccount":     "api",
			"any:example.com/workload-classification": "critical",
		},
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: "k8s:track", Operator: metav1.LabelSelectorOpIn, Values: []string{"stable"},
		}},
	}, "payments", false, true)
	require.Empty(t, unsupported)
	require.Empty(t, invalid)
	require.False(t, labelsOnly)
	require.Equal(t, "api", selector.Pod.MatchLabels["app"])
	require.Equal(t, "critical", selector.Pod.MatchLabels["example.com/workload-classification"])
	require.Equal(t, "payments", selector.Namespace.MatchLabels["kubernetes.io/metadata.name"])
	require.Equal(t, "backend", selector.Namespace.MatchLabels["team"])
	require.Equal(t, "api", selector.ServiceAccount.MatchLabels["name"])

	conflicting, _, _, _ := normalizeCiliumSelector(&ciliumEndpointSelector{
		MatchLabels: map[string]string{"io.kubernetes.pod.namespace": "other"},
	}, "payments", false, true)
	conflicting.compile()
	require.False(t, conflicting.namespace.Matches(labels.Set{"kubernetes.io/metadata.name": "other"}),
		"a namespaced policy never selects subjects outside its namespace")
	require.False(t, conflicting.namespace.Matches(labels.Set{"kubernetes.io/metadata.name": "payments"}))

	labelScoped, _, _, labelsOnly := normalizeCiliumSelector(&ciliumEndpointSelector{
		MatchLabels: map[string]string{"k8s:io.cilium.k8s.namespace.labels.team": "backend"},
	}, "payments", false, false)
	require.True(t, labelsOnly)
	require.NotContains(t, labelScoped.Namespace.MatchLabels, "kubernetes.io/metadata.name",
		"Cilium 1.16+ does not scope namespace-label peers to the policy namespace")

	_, unsupported, invalid, _ = normalizeCiliumSelector(&ciliumEndpointSelector{
		MatchLabels: map[string]string{
			"io.cilium.k8s.policy.cluster": "remote",
			"reserved:host":                "",
			"custom:source":                "value",
		},
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: "app", Operator: "Invalid",
		}},
	}, "payments", true, false)
	require.ErrorContains(t, errors.Join(unsupported...), "local cluster name")
	require.ErrorContains(t, errors.Join(unsupported...), "reserved Cilium selector")
	require.ErrorContains(t, errors.Join(unsupported...), "label source")
	require.ErrorContains(t, errors.Join(invalid...), "invalid endpoint pod selector")

	block, err := ciliumIPBlock("10.2.3.4/24", []string{"10.2.3.128/25"})
	require.NoError(t, err)
	require.Equal(t, "10.2.3.0/24", block.CIDR)
	require.Equal(t, []string{"10.2.3.128/25"}, block.Except)
	_, err = ciliumIPBlock("not-a-cidr", nil)
	require.ErrorContains(t, err, "invalid CIDR")
	_, err = ciliumIPBlock("10.0.0.0/24", []string{"10.1.0.0/24"})
	require.ErrorContains(t, err, "is not inside")
	_, err = ciliumIPBlock("10.0.0.0/24", []string{"invalid"})
	require.ErrorContains(t, err, "invalid excluded CIDR")

	peers, notes, entityErrs := normalizeCiliumEntities([]string{"cluster", "cluster-mesh", "world", "all", "none", "host"})
	require.Len(t, peers, 7)
	require.Empty(t, entityErrs)
	require.Contains(t, notes, `Cilium entity "host" is outside the pod/CIDR graph`)
	require.Equal(t, "0.0.0.0/0", worldPeers()[0].IPBlocks[0].CIDR)
	peers, _, entityErrs = normalizeCiliumEntities([]string{"world-ipv4", "world-ipv6", "World"})
	require.Len(t, peers, 2)
	require.Equal(t, "0.0.0.0/0", peers[0].IPBlocks[0].CIDR)
	require.Equal(t, "::/0", peers[1].IPBlocks[0].CIDR)
	require.ErrorContains(t, errors.Join(entityErrs...), "unsupported entity: World", "entity names are case-sensitive")

	tests := []struct {
		name        string
		source      ciliumPortProtocol
		wantPorts   []string
		wantNote    string
		wantWarning string
		wantErr     string
	}{
		{name: "any protocol", source: ciliumPortProtocol{Port: "53", Protocol: "ANY"}, wantPorts: []string{"TCP/53", "UDP/53", "SCTP/53"}},
		{name: "numeric range", source: ciliumPortProtocol{Port: "8000", EndPort: 8010, Protocol: "TCP"}, wantPorts: []string{"TCP/8000-8010"}},
		{name: "named lower-cased", source: ciliumPortProtocol{Port: "HTTP", Protocol: "TCP"}, wantPorts: []string{"TCP/http"}},
		{name: "zero is a wildcard", source: ciliumPortProtocol{Port: "0", Protocol: "TCP"}, wantPorts: []string{"TCP/all"}},
		{name: "hex literal is a service name", source: ciliumPortProtocol{Port: "0x50", Protocol: "UDP"}, wantPorts: []string{"UDP/0x50"}},
		{name: "octal literal", source: ciliumPortProtocol{Port: "017", Protocol: "TCP"}, wantPorts: []string{"TCP/15"}},
		{name: "end before start is one port", source: ciliumPortProtocol{Port: "9000", EndPort: 8000}, wantPorts: []string{"TCP/9000", "UDP/9000", "SCTP/9000"}},
		{name: "icmp outside transport model", source: ciliumPortProtocol{Port: "0", Protocol: "ICMP"}, wantNote: "ICMP is outside"},
		{name: "extended protocol", source: ciliumPortProtocol{Protocol: "VRRP"}, wantNote: "VRRP is outside"},
		{name: "named range", source: ciliumPortProtocol{Port: "http", EndPort: 8080}, wantPorts: []string{"TCP/http", "UDP/http", "SCTP/http"}, wantWarning: "endPort"},
		{name: "empty", source: ciliumPortProtocol{}, wantErr: "port must be specified"},
		{name: "unparseable", source: ciliumPortProtocol{Port: "70000"}, wantErr: "unable to parse port"},
		{name: "not a service name", source: ciliumPortProtocol{Port: "http_1"}, wantErr: "unable to parse port"},
		{name: "extended protocol port", source: ciliumPortProtocol{Port: "80", Protocol: "GRE"}, wantErr: "port must be empty or 0"},
		{name: "end port too large", source: ciliumPortProtocol{Port: "80", EndPort: 70000}, wantErr: "outside 0-65535"},
		{name: "unknown protocol", source: ciliumPortProtocol{Port: "80", Protocol: "QUIC"}, wantErr: "invalid protocol"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ports, note, warning, portErr := ciliumPort(test.source, false)
			if test.wantErr != "" {
				require.ErrorContains(t, portErr, test.wantErr)
				return
			}
			require.NoError(t, portErr)
			if test.wantNote != "" {
				require.Contains(t, note, test.wantNote)
				require.Empty(t, ports)
				return
			}
			require.Empty(t, note)
			if test.wantWarning != "" {
				require.Contains(t, warning, test.wantWarning)
			} else {
				require.Empty(t, warning)
			}
			permissions := make([]string, 0, len(ports))
			for _, port := range ports {
				value := "all"
				if port.Port != nil {
					value = port.Port.String()
				}
				if port.EndPort != nil {
					value += "-" + strconv.Itoa(int(*port.EndPort))
				}
				permissions = append(permissions, string(*port.Protocol)+"/"+value)
			}
			require.Equal(t, test.wantPorts, permissions)
		})
	}
	_, _, _, dnsErr := ciliumPort(ciliumPortProtocol{Port: "53", EndPort: 60, Protocol: "UDP"}, true)
	require.ErrorContains(t, dnsErr, "DNS rules do not support port ranges")

	result := normalizeCiliumPorts([]ciliumPortRule{{
		Ports:          []ciliumPortProtocol{{Port: "443", Protocol: "TCP"}},
		Rules:          json.RawMessage(`{"http":[{"method":"GET"}]}`),
		TerminatingTLS: json.RawMessage(`{"secret":{"name":"tls"}}`),
		ServerNames:    []string{"example.com"},
	}}, Ingress)
	require.Empty(t, result.invalid)
	require.Len(t, result.ports, 1)
	require.Len(t, result.notes, 2)
	require.Contains(t, strings.Join(result.warnings, "\n"), "L7 rules")
	require.Contains(t, strings.Join(result.warnings, "\n"), "TLS, SNI")

	result = normalizeCiliumPorts([]ciliumPortRule{{
		Ports: []ciliumPortProtocol{{Port: "70000"}, {Port: "http_1"}},
	}}, Egress)
	require.Len(t, result.invalid, 2)
	require.Empty(t, result.ports)

	result = normalizeCiliumPorts([]ciliumPortRule{{Ports: []ciliumPortProtocol{{Protocol: "ICMPV6", Port: "0"}}}}, Egress)
	require.True(t, result.noPorts, "a rule with only non-transport protocols grants no TCP/UDP/SCTP ports")
	result = normalizeCiliumPorts([]ciliumPortRule{
		{Ports: []ciliumPortProtocol{{Protocol: "ICMP", Port: "0"}}},
		{},
	}, Egress)
	require.False(t, result.noPorts)
	require.Nil(t, result.ports, "an empty port rule still allows every transport port")
}

func TestCiliumPortRuleValidationMirrorsCilium(t *testing.T) {
	tests := []struct {
		name      string
		rule      ciliumPortRule
		direction Direction
		want      string
	}{
		{"dns on ingress", ciliumPortRule{Ports: []ciliumPortProtocol{{Port: "53", Protocol: "UDP"}}, Rules: json.RawMessage(`{"dns":[{"matchPattern":"*"}]}`)}, Ingress, "DNS rules are not allowed on ingress"},
		{"dns without port", ciliumPortRule{Rules: json.RawMessage(`{"dns":[{"matchPattern":"*"}]}`)}, Egress, "port 53 must be specified"},
		{"l7 on zero port", ciliumPortRule{Ports: []ciliumPortProtocol{{Port: "0", Protocol: "TCP"}}, Rules: json.RawMessage(`{"http":[{}]}`)}, Egress, "port is 0"},
		{"l7 not tcp", ciliumPortRule{Ports: []ciliumPortProtocol{{Port: "80", Protocol: "UDP"}}, Rules: json.RawMessage(`{"http":[{}]}`)}, Egress, "only apply to TCP"},
		{"l7 any protocol", ciliumPortRule{Ports: []ciliumPortProtocol{{Port: "80"}}, Rules: json.RawMessage(`{"http":[{}]}`)}, Egress, "only apply to TCP"},
		{"multiple l7 types", ciliumPortRule{Ports: []ciliumPortProtocol{{Port: "80", Protocol: "TCP"}}, Rules: json.RawMessage(`{"http":[{}],"kafka":[{}]}`)}, Egress, "multiple L7 protocol"},
		{"server names with l7 without tls", ciliumPortRule{Ports: []ciliumPortProtocol{{Port: "443", Protocol: "TCP"}}, ServerNames: []string{"a"}, Rules: json.RawMessage(`{"http":[{}]}`)}, Egress, "ServerNames are not allowed"},
		{"empty server name", ciliumPortRule{Ports: []ciliumPortProtocol{{Port: "443", Protocol: "TCP"}}, ServerNames: []string{""}}, Egress, "empty server name"},
		{"listener on ingress", ciliumPortRule{Ports: []ciliumPortProtocol{{Port: "443", Protocol: "TCP"}}, Listener: json.RawMessage(`{"name":"l"}`)}, Ingress, "listener is not allowed on ingress"},
		{"listener with l7", ciliumPortRule{Ports: []ciliumPortProtocol{{Port: "443", Protocol: "TCP"}}, Listener: json.RawMessage(`{"name":"l"}`), Rules: json.RawMessage(`{"http":[{}]}`)}, Egress, "listener is not allowed with L7"},
		{"invalid l7 document", ciliumPortRule{Ports: []ciliumPortProtocol{{Port: "443", Protocol: "TCP"}}, Rules: json.RawMessage(`[]`)}, Egress, "invalid L7 rules"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := normalizeCiliumPorts([]ciliumPortRule{test.rule}, test.direction)
			require.ErrorContains(t, errors.Join(result.invalid...), test.want)
		})
	}
	valid := normalizeCiliumPorts([]ciliumPortRule{{
		Ports: []ciliumPortProtocol{{Port: "53", Protocol: "ANY"}},
		Rules: json.RawMessage(`{"dns":[{"matchPattern":"*"}],"http":null}`),
	}}, Egress)
	require.Empty(t, valid.invalid)
	families, err := ciliumL7Types(json.RawMessage(`{"custom":{}}`))
	require.NoError(t, err)
	require.Equal(t, []string{"l7"}, families)
}

func TestCiliumTrafficRuleUnsupportedSemanticsAreExplicit(t *testing.T) {
	policy := normalizedPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "payments"},
		Type:       PolicyTypeCiliumNetworkPolicy,
	}
	raw := []json.RawMessage{json.RawMessage(`{}`)}
	tests := []struct {
		name           string
		direction      Direction
		source         ciliumTrafficRule
		invalid        string
		warning        string
		matchNone      bool
		noPorts        bool
		uncertainPeers bool
	}{
		{
			name:    "endpoints and CIDR",
			source:  ciliumTrafficRule{FromEndpoints: []ciliumEndpointSelector{{}}, FromCIDR: []string{"10.0.0.0/8"}},
			invalid: "combining FromEndpoints and FromCIDR is not supported yet",
		},
		{
			name:      "CIDR and CIDR set",
			direction: Egress,
			source:    ciliumTrafficRule{ToCIDR: []string{"10.0.0.0/8"}, ToCIDRSet: []ciliumCIDRRule{{CIDR: "10.1.0.0/16"}}},
			invalid:   "combining ToCIDR and ToCIDRSet is not supported yet",
		},
		{
			name:      "entities and nodes",
			direction: Egress,
			source:    ciliumTrafficRule{ToEntities: []string{"world"}, ToNodes: raw},
			invalid:   "combining ToEntities and ToNodes is not supported yet",
		},
		{
			name:           "FQDNs and services",
			direction:      Egress,
			source:         ciliumTrafficRule{ToFQDNs: raw, ToServices: raw},
			invalid:        "combining ToServices and ToFQDNs is not supported yet",
			uncertainPeers: true,
		},
		{name: "requires", source: ciliumTrafficRule{FromRequires: raw}, warning: "identity constraints", uncertainPeers: true},
		{name: "groups", source: ciliumTrafficRule{FromGroups: raw}, warning: "cloud-provider groups", uncertainPeers: true},
		{name: "nodes", source: ciliumTrafficRule{FromNodes: raw}, matchNone: true},
		{name: "services", direction: Egress, source: ciliumTrafficRule{ToServices: raw}, warning: "live Service", uncertainPeers: true},
		{name: "fqdns", direction: Egress, source: ciliumTrafficRule{ToFQDNs: raw}, warning: "live DNS", uncertainPeers: true},
		{name: "icmp only", source: ciliumTrafficRule{FromEntities: []string{"cluster"}, ICMPs: raw}, noPorts: true},
		{
			name:    "icmp with ports",
			source:  ciliumTrafficRule{ICMPs: raw, ToPorts: []ciliumPortRule{{Ports: []ciliumPortProtocol{{Port: "80", Protocol: "TCP"}}}}},
			invalid: "ICMPs block may only be present without ToPorts",
			noPorts: true,
		},
		{
			name:           "cidr group",
			source:         ciliumTrafficRule{FromCIDRSet: []ciliumCIDRRule{{CIDRGroupRef: "external"}}},
			warning:        "runtime Cilium resolution",
			uncertainPeers: true,
		},
		{
			name:      "cidr rule without target",
			source:    ciliumTrafficRule{FromCIDRSet: []ciliumCIDRRule{{Except: []string{"10.0.0.0/8"}}}},
			invalid:   "one of cidr, cidrGroupRef, or cidrGroupSelector is required",
			matchNone: true,
		},
		{
			name:      "cidr rule with two targets",
			source:    ciliumTrafficRule{FromCIDRSet: []ciliumCIDRRule{{CIDR: "10.0.0.0/8", CIDRGroupRef: "external"}}},
			invalid:   "more than one of cidr",
			matchNone: true,
		},
		{name: "unknown entity", source: ciliumTrafficRule{FromEntities: []string{"everyone"}}, invalid: "unsupported entity", matchNone: true},
		{
			name:           "unsupported peer selector",
			source:         ciliumTrafficRule{FromEndpoints: []ciliumEndpointSelector{{MatchLabels: map[string]string{"reserved:host": ""}}}},
			warning:        "peer selector cannot be evaluated",
			uncertainPeers: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rule, validation := normalizeCiliumTrafficRule(
				&policy, test.direction, PolicyActionAllow, 0, &test.source,
			)
			require.Equal(t, test.matchNone, rule.MatchNone)
			require.Equal(t, test.noPorts, rule.NoPorts)
			require.Equal(t, test.uncertainPeers, rule.UncertainPeers)
			if test.invalid != "" {
				require.ErrorContains(t, errors.Join(validation...), test.invalid)
			} else {
				require.Empty(t, validation)
			}
			if test.warning != "" {
				require.Contains(t, strings.Join(rule.Warnings, "\n"), test.warning)
			}
		})
	}

	rule, validation := normalizeCiliumTrafficRule(&policy, Ingress, PolicyActionAllow, 0, &ciliumTrafficRule{
		FromEntities:   []string{"cluster"},
		Authentication: &ciliumAuthentication{Mode: "required"},
	})
	require.Empty(t, validation)
	require.Contains(t, strings.Join(rule.Warnings, "\n"), "authentication requirements")
	require.Contains(t, rule.Notes, "Cilium authentication requirements are not represented; reachability is existential")
	rule, _ = normalizeCiliumTrafficRule(&policy, Ingress, PolicyActionAllow, 0, &ciliumTrafficRule{
		FromEntities:   []string{"cluster"},
		Authentication: &ciliumAuthentication{Mode: "disabled"},
	})
	require.Empty(t, rule.Warnings, "disabled authentication does not constrain traffic")

	disabled, enabled := false, true
	require.False(t, ciliumDirectionIsolates(&disabled, true))
	require.True(t, ciliumDirectionIsolates(&enabled, true))
	require.True(t, ciliumDirectionIsolates(nil, true))
	require.False(t, ciliumDirectionIsolates(nil, false))
	require.False(t, ciliumDirectionIsolates(&enabled, false), "enableDefaultDeny needs rules in that direction")
	require.False(t, ciliumDirectionIsolates(&disabled, false))
}

func TestIstioConservativeSourceAndConditionHandling(t *testing.T) {
	source := istioSource{
		Principals:      []string{"cluster.local/ns/client/sa/caller"},
		Namespaces:      []string{"client"},
		IPBlocks:        []string{"10.0.0.10"},
		TrustDomains:    []string{"cluster.local"},
		NotTrustDomains: []string{"external.local"},
	}
	peer, warnings, notes, disabled := normalizeIstioSource("server", &source)
	require.False(t, disabled)
	require.Empty(t, warnings, "identity constraints are notes, not uncertainty")
	require.Empty(t, notes)
	require.True(t, peer.CIDRMatchUnsupported)
	require.Equal(t, "10.0.0.10/32", peer.IPBlocks[0].CIDR)
	require.True(t, peer.hasIdentityConstraints())
	require.True(t, peer.hasPositiveIdentityConstraints())
	require.False(t, normalizedPeerMatchesCIDR(&peer, &PrimitiveRef{Kind: PrimitiveCIDR, CIDR: "10.0.0.10/32"}))

	_, warnings, _, disabled = normalizeIstioSource("server", &istioSource{
		IPBlocks:             []string{"invalid"},
		NotIPBlocks:          []string{"10.0.0.0/8"},
		RemoteIPBlocks:       []string{"192.0.2.0/24"},
		NotRemoteIPBlocks:    []string{"198.51.100.0/24"},
		RequestPrincipals:    []string{"issuer/user"},
		NotRequestPrincipals: []string{"issuer/blocked"},
	})
	require.True(t, disabled)
	message := strings.Join(warnings, "\n")
	require.Contains(t, message, "invalid Istio IP block")
	require.Contains(t, message, "notIpBlocks")
	require.Contains(t, message, "proxy forwarding")
	require.Contains(t, message, "JWT request identity")

	_, warnings, notes, disabled = normalizeIstioSource("server", &istioSource{
		ServiceAccounts: []string{"client/*"},
		Principals:      []string{"cluster.local/ns/*/sa/caller"},
	})
	require.False(t, disabled)
	require.Contains(t, strings.Join(warnings, "\n"), "does not allow")
	require.Contains(t, strings.Join(warnings, "\n"), "together with principals or namespaces")
	require.Contains(t, strings.Join(notes, "\n"), "literally")

	object := policyObject(t, `
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: conditional
  namespace: server
spec:
  selector:
    matchLabels: {role: server}
  action: ALLOW
  rules:
    - when:
        - key: source.namespace
          values: [prod]
`)
	policies, policyErrs := normalizeIstioPolicy(&object, nil)
	require.Len(t, policies, 1)
	require.True(t, policies[0].Ingress.Rules[0].Disabled)
	require.ErrorContains(t, errors.Join(policyErrs...), "when conditions")
	require.Equal(t,
		[]string{"AuthorizationPolicy server/conditional: ingress allow rule 0: Istio when conditions cannot be evaluated from the policy snapshot"},
		policies[0].Ingress.Rules[0].uncertain,
	)
}

func TestIstioPolicyActionsScopeOperationsAndMatching(t *testing.T) {
	dryRun := policyObject(t, `
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: dry-run
  namespace: server
  annotations: {istio.io/dry-run: "true"}
spec: {action: DENY}
`)
	policies, errs := normalizeIstioPolicy(&dryRun, nil)
	require.Empty(t, policies)
	require.Empty(t, errs)

	audit := policyObject(t, `
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata: {name: audit, namespace: server}
spec: {action: AUDIT}
`)
	policies, errs = normalizeIstioPolicy(&audit, nil)
	require.Empty(t, policies)
	require.Empty(t, errs)

	root := policyObject(t, `
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata: {name: mesh-policy, namespace: mesh-root}
spec:
  selector:
    matchLabels: {role: server}
  rules: [{}]
`)
	policies, errs = normalizeIstioPolicy(&root, &istioRootConfig{root: "mesh-root"})
	require.Empty(t, errs)
	require.True(t, policies[0].ClusterScoped)
	require.Contains(t, strings.Join(policies[0].Notes, "\n"), "resolved Istio root namespace")

	policies, _ = normalizeIstioPolicy(&root, &istioRootConfig{root: "mesh-root", candidates: []string{"mesh-root", "other-root"}})
	require.Equal(t, policySelectionUnknown, policies[0].State)
	require.True(t, policies[0].ClusterScoped)
	require.Contains(t, policies[0].reasons[0], "different root namespaces (mesh-root, other-root)")

	target := policyObject(t, `apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata: {name: target, namespace: server}
spec: {targetRef: {kind: Service, name: api}}`)
	policies, errs = normalizeIstioPolicy(&target, nil)
	require.Len(t, policies, 1)
	require.Equal(t, policySelectionUnknown, policies[0].State)
	require.False(t, policies[0].ClusterScoped, "selection-unknown namespaced policies stay in their namespace")
	require.ErrorContains(t, errors.Join(errs...), "targetRefs")

	custom := policyObject(t, `apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata: {name: custom, namespace: server}
spec: {action: CUSTOM, provider: {name: ext-authz}, rules: [{to: [{operation: {ports: ["8080"]}}]}]}`)
	policies, errs = normalizeIstioPolicy(&custom, nil)
	require.Len(t, policies, 1)
	require.Equal(t, policyEnforced, policies[0].State)
	require.False(t, policies[0].Ingress.Isolate, "CUSTOM never activates default deny")
	require.Equal(t, PolicyActionCustom, policies[0].Ingress.Rules[0].Action)
	require.True(t, policies[0].Ingress.Rules[0].Disabled)
	require.ErrorContains(t, errors.Join(errs...), "external provider")

	unknown := policyObject(t, `apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata: {name: unknown, namespace: server}
spec: {action: BLOCK}`)
	policies, errs = normalizeIstioPolicy(&unknown, nil)
	require.Len(t, policies, 1)
	require.Equal(t, policyEffectUnknown, policies[0].State)
	require.ErrorContains(t, errors.Join(errs...), `unsupported Istio action "BLOCK"`)

	malformed := policyObject(t, `apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata: {name: malformed, namespace: mesh-root}
spec: {rules: true}`)
	policies, errs = normalizeIstioPolicy(&malformed, &istioRootConfig{root: "mesh-root"})
	require.Len(t, policies, 1)
	require.Equal(t, policySelectionUnknown, policies[0].State)
	require.True(t, policies[0].ClusterScoped, "an undecodable root-namespace policy may apply mesh-wide")
	require.NotEmpty(t, errs)

	ports, notes, warnings, disabled := normalizeIstioOperations([]istioTo{
		{Operation: istioOperation{Ports: []string{"8080"}, Methods: []string{"GET"}}},
		{Operation: istioOperation{Ports: []string{"*"}}},
	})
	require.False(t, disabled)
	require.Nil(t, ports)
	require.NotEmpty(t, notes)
	require.Contains(t, strings.Join(warnings, "\n"), "L7 operation")

	ports, _, warnings, disabled = normalizeIstioOperations([]istioTo{
		{Operation: istioOperation{NotPorts: []string{"8080"}}},
		{Operation: istioOperation{Ports: []string{"invalid"}}},
	})
	require.True(t, disabled)
	require.Empty(t, ports)
	require.Len(t, warnings, 2)

	block, err := istioIPBlock("2001:db8::1")
	require.NoError(t, err)
	require.Equal(t, "2001:db8::1/128", block.CIDR)
	block, err = istioIPBlock("192.0.2.4/24")
	require.NoError(t, err)
	require.Equal(t, "192.0.2.0/24", block.CIDR)
	_, err = istioIPBlock("invalid")
	require.ErrorContains(t, err, "invalid Istio IP block")
}

func TestIstioPeerIdentityRequiresMeshEnrollment(t *testing.T) {
	enrolled := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "client", Name: "caller", Labels: map[string]string{"role": "client"}},
		Spec:       corev1.PodSpec{ServiceAccountName: "caller"},
		Status: corev1.PodStatus{
			PodIP:  "10.0.0.10",
			PodIPs: []corev1.PodIP{{IP: "2001:db8::1"}, {IP: "invalid"}},
		},
	}
	outside := *enrolled.DeepCopy()
	outside.Namespace, outside.Name = "plain", "outside"
	unknown := *enrolled.DeepCopy()
	unknown.Namespace, unknown.Name = "plain", "unknown"
	unknown.Annotations = map[string]string{istioSidecarStatusAnnotation: "{}"}
	snapshot := Snapshot{
		Pods: []corev1.Pod{enrolled, outside, unknown},
		Namespaces: []corev1.Namespace{
			{ObjectMeta: metav1.ObjectMeta{Name: "client", Labels: map[string]string{istioDataplaneModeLabel: "ambient"}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "plain"}},
		},
	}
	x := newSnapshotIndex(&snapshot)
	policy := &normalizedPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "server", Name: "authz"}}
	peer := normalizedPeer{
		AllNamespaces:   true,
		IPBlocks:        []netv1.IPBlock{{CIDR: "10.0.0.0/24"}, {CIDR: "2001:db8::/64"}},
		MatchPodIPs:     true,
		Namespaces:      []string{"cli*"},
		ServiceAccounts: []string{"client/caller"},
		Principals:      []string{"cluster.local/ns/client/sa/*"},
		TrustDomains:    []string{"cluster.*"},
		NotTrustDomains: []string{"external.local"},
	}
	peer.compile()
	caller := x.info(&snapshot.Pods[0])
	require.Equal(t, matchYes, peerMatchesPod(&peer, policy, caller))
	peer.NotNamespaces = []string{"kube-*", "client"}
	require.Equal(t, matchNo, peerMatchesPod(&peer, policy, caller), "later negative patterns are still checked")
	peer.NotNamespaces = nil
	peer.TrustDomains = []string{"external.local"}
	require.Equal(t, matchNo, peerMatchesPod(&peer, policy, caller))

	negative := normalizedPeer{AllNamespaces: true, NotPrincipals: []string{"cluster.local/ns/client/sa/caller"}}
	require.Equal(t, matchNo, peerMatchesPod(&negative, policy, caller))
	require.Equal(t, matchYes, peerMatchesPod(&negative, policy, x.info(&snapshot.Pods[1])),
		"a source outside the mesh has no principal, so negative constraints do not exclude it")
	positive := normalizedPeer{AllNamespaces: true, Principals: []string{"*"}}
	require.Equal(t, matchYes, peerMatchesPod(&positive, policy, caller))
	require.Equal(t, matchNo, peerMatchesPod(&positive, policy, x.info(&snapshot.Pods[1])),
		"a source outside the mesh has no mTLS identity")
	require.Equal(t, matchUnknown, peerMatchesPod(&positive, policy, x.info(&snapshot.Pods[2])))
	require.Equal(t, matchYes, peerMatchesPod(&normalizedPeer{AllNamespaces: true}, policy, x.info(&snapshot.Pods[2])),
		"peers without identity constraints do not depend on enrollment")

	require.True(t, caller.matchesBlocks(&normalizedPeer{IPBlocks: []netv1.IPBlock{{CIDR: "10.0.0.0/24"}}}))
	require.False(t, caller.matchesBlocks(&normalizedPeer{IPBlocks: []netv1.IPBlock{{
		CIDR: "10.0.0.0/24", Except: []string{"10.0.0.0/24"},
	}}}))
	address, err := netip.ParseAddr(enrolled.Status.PodIPs[0].IP)
	require.NoError(t, err)
	blocks := compileBlocks([]netv1.IPBlock{{CIDR: "2001:db8::/64"}, {CIDR: "invalid"}})
	require.Len(t, blocks, 1)
	require.True(t, blocks[0].contains(address))
}

func TestPolicyMatchingUtilityEdges(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		patterns []string
		match    func(value, pattern string) bool
		want     bool
	}{
		{"no patterns", "client", nil, istioMatchesString, false},
		{"presence", "client", []string{"*"}, istioMatchesString, true},
		{"presence requires a value", "", []string{"*"}, istioMatchesString, false},
		{"suffix", "client", []string{"*ent"}, istioMatchesString, true},
		{"prefix", "client", []string{"cli*"}, istioMatchesString, true},
		{"exact", "client", []string{"client"}, istioMatchesString, true},
		{"mismatch", "client", []string{"server"}, istioMatchesString, false},
		{"later exact after wildcard", "client", []string{"prod-*", "client"}, istioMatchesString, true},
		{"later wildcard after wildcard", "istio-system", []string{"kube-*", "istio-*"}, istioMatchesNamespace, true},
		{"double wildcard is a literal suffix", "client", []string{"*lie*"}, istioMatchesString, false},
		{"double wildcard literal suffix matches", "cliea*", []string{"*ea*"}, istioMatchesString, true},
		{"inner wildcard is literal for principals", "a-b", []string{"a*b"}, istioMatchesString, false},
		{"namespace inner wildcard", "prod-eu-1", []string{"prod-*-1"}, istioMatchesNamespace, true},
		{"namespace contains wildcard", "client", []string{"*lie*"}, istioMatchesNamespace, true},
		{"namespace multiple wildcards", "aXbYc", []string{"a*b*c"}, istioMatchesNamespace, true},
		{"namespace wildcard mismatch", "abc", []string{"a*d"}, istioMatchesNamespace, false},
		{"namespace exact", "client", []string{"client"}, istioMatchesNamespace, true},
		{"namespace suffix overlap", "ab", []string{"ab*b"}, istioMatchesNamespace, false},
		{"trust domain presence", "cluster.local", []string{"*"}, istioMatchesTrustDomain, true},
		{"trust domain suffix", "cluster.local", []string{"*.local"}, istioMatchesTrustDomain, true},
		{"trust domain inner wildcard", "cluster.local", []string{"clu*cal"}, istioMatchesTrustDomain, true},
		{"trust domain overlap", "ab", []string{"ab*b"}, istioMatchesTrustDomain, false},
		{"trust domain exact", "cluster.local", []string{"example.org", "cluster.local"}, istioMatchesTrustDomain, true},
		{"service accounts are exact", "client/caller", []string{"client/*"}, istioMatchesServiceAccount, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, matchesAnyPattern(test.value, test.patterns, test.match))
		})
	}

	port := intstr.FromInt32(8080)
	peer := normalizedPeer{
		TrustDomains:    []string{"cluster.local"},
		NotTrustDomains: []string{"external.local"},
	}
	peerStrings := normalizedPeerStrings([]normalizedPeer{peer}, false)
	require.Contains(t, peerStrings[0], "trustDomains=cluster.local")
	require.Contains(t, peerStrings[0], "notTrustDomains=external.local")
	require.Equal(t, []string{"<none>"}, normalizedPeerStrings(nil, true))
	require.Equal(t, "TCP/8080", PortPermission{Port: &port}.String())
}

func policyObject(t *testing.T, manifest string) unstructured.Unstructured {
	t.Helper()
	var object map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(manifest), &object))
	return unstructured.Unstructured{Object: object}
}

func findPolicyRule(t *testing.T, result DirectionResult, name string) RuleResult {
	t.Helper()
	for index := range result.Rules {
		if result.Rules[index].ID.PolicyName == name {
			return result.Rules[index]
		}
	}
	require.FailNow(t, "policy rule not found", "%s", name)
	return RuleResult{}
}

func findPolicyRuleAction(t *testing.T, result DirectionResult, name string, action PolicyAction) RuleResult {
	t.Helper()
	for index := range result.Rules {
		if result.Rules[index].ID.PolicyName == name && result.Rules[index].ID.Action == action {
			return result.Rules[index]
		}
	}
	require.FailNow(t, "policy rule not found", "%s %s", name, action)
	return RuleResult{}
}
