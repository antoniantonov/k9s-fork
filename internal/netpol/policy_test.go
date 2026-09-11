// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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
	require.Equal(t, AccessPartialData, allowed.State)
	require.Equal(t, []string{"SCTP/all", "TCP/8080", "UDP/all"}, permissionStrings(allowed.Permissions))
	other := findPrimitive(t, result.Ingress, PrimitivePod, "client", "other")
	require.Equal(t, AccessPartialData, other.State)
	require.Equal(t, []string{"SCTP/all", "UDP/all"}, permissionStrings(other.Permissions))
	require.Contains(t, strings.Join(result.Warnings, "\n"), "mTLS identity")

	rule := findPolicyRule(t, result.Ingress, "server-authz")
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
	require.True(t, policies[0].Disabled)
	require.ErrorContains(t, errors.Join(errs...), "local cluster name")
}

func TestCiliumSelectorCIDREntityAndPortNormalization(t *testing.T) {
	selector, errs := normalizeCiliumSelector(&ciliumEndpointSelector{
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
	require.Empty(t, errs)
	require.Equal(t, "api", selector.Pod.MatchLabels["app"])
	require.Equal(t, "critical", selector.Pod.MatchLabels["example.com/workload-classification"])
	require.Equal(t, "payments", selector.Namespace.MatchLabels["kubernetes.io/metadata.name"])
	require.Equal(t, "backend", selector.Namespace.MatchLabels["team"])
	require.Equal(t, "api", selector.ServiceAccount.MatchLabels["name"])

	_, errs = normalizeCiliumSelector(&ciliumEndpointSelector{
		MatchLabels: map[string]string{
			"io.cilium.k8s.policy.cluster": "remote",
			"reserved:host":                "",
			"custom:source":                "value",
		},
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: "app", Operator: "Invalid",
		}},
	}, "payments", true, false)
	require.ErrorContains(t, errors.Join(errs...), "local cluster name")
	require.ErrorContains(t, errors.Join(errs...), "reserved Cilium selector")
	require.ErrorContains(t, errors.Join(errs...), "label source")
	require.ErrorContains(t, errors.Join(errs...), "invalid endpoint pod selector")

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

	peers, notes := normalizeCiliumEntities([]string{"cluster", "cluster-mesh", "world", "all", "none", "host"})
	require.Len(t, peers, 7)
	require.Contains(t, notes, `Cilium entity "host" is outside the pod/CIDR graph`)
	require.Equal(t, "0.0.0.0/0", worldPeers()[0].IPBlocks[0].CIDR)

	tests := []struct {
		name      string
		source    ciliumPortProtocol
		wantCount int
		wantErr   string
	}{
		{name: "any protocol", source: ciliumPortProtocol{Port: "53", Protocol: "ANY"}, wantCount: 3},
		{name: "numeric range", source: ciliumPortProtocol{Port: "8000", EndPort: 8010, Protocol: "TCP"}, wantCount: 1},
		{name: "named", source: ciliumPortProtocol{Port: "http", Protocol: "TCP"}, wantCount: 1},
		{name: "empty", source: ciliumPortProtocol{}, wantErr: "must not be empty"},
		{name: "numeric below range", source: ciliumPortProtocol{Port: "0"}, wantErr: "outside 1-65535"},
		{name: "named range", source: ciliumPortProtocol{Port: "http", EndPort: 8080}, wantErr: "cannot have endPort"},
		{name: "end before start", source: ciliumPortProtocol{Port: "9000", EndPort: 8000}, wantErr: "outside the port range"},
		{name: "unsupported protocol", source: ciliumPortProtocol{Port: "80", Protocol: "ICMP"}, wantErr: "not supported"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ports, err := ciliumPort(test.source)
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				return
			}
			require.NoError(t, err)
			require.Len(t, ports, test.wantCount)
		})
	}

	ports, notes, portErrs, invalid := normalizeCiliumPorts([]ciliumPortRule{{
		Ports:          []ciliumPortProtocol{{Port: "443", Protocol: "TCP"}},
		Rules:          json.RawMessage(`{"http":[{"method":"GET"}]}`),
		TerminatingTLS: json.RawMessage(`{"secret":{"name":"tls"}}`),
		ServerNames:    []string{"example.com"},
	}})
	require.False(t, invalid)
	require.Len(t, ports, 1)
	require.Len(t, notes, 2)
	require.Empty(t, portErrs)

	ports, _, portErrs, invalid = normalizeCiliumPorts([]ciliumPortRule{{
		Ports: []ciliumPortProtocol{{Port: "invalid", EndPort: 90}},
	}})
	require.True(t, invalid)
	require.Empty(t, ports)
	require.NotEmpty(t, portErrs)
}

func TestCiliumTrafficRuleUnsupportedSemanticsAreExplicit(t *testing.T) {
	policy := normalizedPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "payments"},
		Type:       PolicyTypeCiliumNetworkPolicy,
	}
	tests := []struct {
		name      string
		direction Direction
		source    ciliumTrafficRule
		want      string
		matchNone bool
	}{
		{
			name: "multiple peer families",
			source: ciliumTrafficRule{
				FromEndpoints: []ciliumEndpointSelector{{}},
				FromCIDR:      []string{"10.0.0.0/8"},
			},
			want: "multiple mutually exclusive",
		},
		{name: "requires", source: ciliumTrafficRule{FromRequires: []json.RawMessage{json.RawMessage(`{}`)}}, want: "identity constraints"},
		{name: "groups", source: ciliumTrafficRule{FromGroups: []json.RawMessage{json.RawMessage(`{}`)}}, want: "cloud-provider groups"},
		{name: "nodes", source: ciliumTrafficRule{FromNodes: []json.RawMessage{json.RawMessage(`{}`)}}, matchNone: true},
		{name: "services", direction: Egress, source: ciliumTrafficRule{ToServices: []json.RawMessage{json.RawMessage(`{}`)}}, want: "live Service"},
		{name: "fqdns", direction: Egress, source: ciliumTrafficRule{ToFQDNs: []json.RawMessage{json.RawMessage(`{}`)}}, want: "live DNS"},
		{name: "icmp", source: ciliumTrafficRule{ICMPs: []json.RawMessage{json.RawMessage(`{}`)}}, want: "L4 port model"},
		{
			name: "cidr group",
			source: ciliumTrafficRule{FromCIDRSet: []ciliumCIDRRule{{
				CIDRGroupRef: "external",
			}}},
			want: "runtime Cilium resolution",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rule, errs := normalizeCiliumTrafficRule(
				&policy, test.direction, PolicyActionAllow, 0, &test.source,
			)
			require.Equal(t, test.matchNone, rule.MatchNone)
			if test.want != "" {
				require.ErrorContains(t, errors.Join(errs...), test.want)
			}
		})
	}

	auth := json.RawMessage(`{"mode":"required"}`)
	rule, errs := normalizeCiliumTrafficRule(&policy, Ingress, PolicyActionAllow, 0, &ciliumTrafficRule{
		FromEntities:   []string{"cluster"},
		Authentication: auth,
	})
	require.Empty(t, errs)
	require.Contains(t, rule.Notes, "Cilium authentication requirements are not represented; reachability is existential")

	disabled := false
	require.False(t, ciliumDirectionIsolates(&disabled, true))
	require.True(t, ciliumDirectionIsolates(nil, true))
	require.False(t, ciliumDirectionIsolates(nil, false))
}

func TestIstioConservativeSourceAndConditionHandling(t *testing.T) {
	source := istioSource{
		Principals:      []string{"cluster.local/ns/client/sa/caller"},
		Namespaces:      []string{"client"},
		IPBlocks:        []string{"10.0.0.10"},
		TrustDomains:    []string{"cluster.local"},
		NotTrustDomains: []string{"external.local"},
	}
	peer, errs, invalid := normalizeIstioSource("server", &source)
	require.False(t, invalid)
	require.True(t, peer.CIDRMatchUnsupported)
	require.Equal(t, "10.0.0.10/32", peer.IPBlocks[0].CIDR)
	require.ErrorContains(t, errors.Join(errs...), "cluster.local trust domain")
	require.ErrorContains(t, errors.Join(errs...), "CIDR applicability")
	require.True(t, istioSourceHasIdentityConstraints(&source))
	require.True(t, istioSourceHasPeerIdentityConstraints(&source))
	require.False(t, normalizedPeerMatchesCIDR(&peer, &PrimitiveRef{Kind: PrimitiveCIDR, CIDR: "10.0.0.10/32"}))

	_, errs, invalid = normalizeIstioSource("server", &istioSource{
		IPBlocks:             []string{"invalid"},
		NotIPBlocks:          []string{"10.0.0.0/8"},
		RemoteIPBlocks:       []string{"192.0.2.0/24"},
		NotRemoteIPBlocks:    []string{"198.51.100.0/24"},
		RequestPrincipals:    []string{"issuer/user"},
		NotRequestPrincipals: []string{"issuer/blocked"},
	})
	require.True(t, invalid)
	message := errors.Join(errs...).Error()
	require.Contains(t, message, "invalid Istio IP block")
	require.Contains(t, message, "notIpBlocks")
	require.Contains(t, message, "proxy forwarding")
	require.Contains(t, message, "JWT request identity")

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
	policies, policyErrs := normalizeIstioPolicy(&object, DefaultIstioRootNamespace)
	require.Len(t, policies, 1)
	require.True(t, policies[0].Ingress.Rules[0].Disabled)
	require.ErrorContains(t, errors.Join(policyErrs...), "when conditions")
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
	policies, errs := normalizeIstioPolicy(&dryRun, DefaultIstioRootNamespace)
	require.Empty(t, policies)
	require.Empty(t, errs)

	audit := policyObject(t, `
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata: {name: audit, namespace: server}
spec: {action: AUDIT}
`)
	policies, errs = normalizeIstioPolicy(&audit, DefaultIstioRootNamespace)
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
	policies, errs = normalizeIstioPolicy(&root, "mesh-root")
	require.Empty(t, errs)
	require.True(t, policies[0].ClusterScoped)
	require.Contains(t, policies[0].Notes[1], "resolved Istio root namespace")

	for _, manifest := range []string{
		`apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata: {name: target, namespace: server}
spec: {targetRef: {kind: Service, name: api}}`,
		`apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata: {name: custom, namespace: server}
spec: {action: CUSTOM, provider: {name: ext-authz}}`,
		`apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata: {name: unknown, namespace: server}
spec: {action: BLOCK}`,
	} {
		object := policyObject(t, manifest)
		policies, errs = normalizeIstioPolicy(&object, DefaultIstioRootNamespace)
		require.Len(t, policies, 1)
		require.True(t, policies[0].Disabled)
		require.NotEmpty(t, errs)
	}

	ports, notes, operationErrs, invalid := normalizeIstioOperations([]istioTo{
		{Operation: istioOperation{Ports: []string{"8080"}, Methods: []string{"GET"}}},
		{Operation: istioOperation{Ports: []string{"*"}}},
	})
	require.False(t, invalid)
	require.Nil(t, ports)
	require.NotEmpty(t, notes)
	require.Empty(t, operationErrs)

	ports, _, operationErrs, invalid = normalizeIstioOperations([]istioTo{
		{Operation: istioOperation{NotPorts: []string{"8080"}}},
		{Operation: istioOperation{Ports: []string{"invalid"}}},
	})
	require.True(t, invalid)
	require.Empty(t, ports)
	require.Len(t, operationErrs, 2)

	block, err := istioIPBlock("2001:db8::1")
	require.NoError(t, err)
	require.Equal(t, "2001:db8::1/128", block.CIDR)
	block, err = istioIPBlock("192.0.2.4/24")
	require.NoError(t, err)
	require.Equal(t, "192.0.2.0/24", block.CIDR)
	_, err = istioIPBlock("invalid")
	require.ErrorContains(t, err, "invalid Istio IP block")

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "client", Labels: map[string]string{"role": "client"}},
		Spec:       corev1.PodSpec{ServiceAccountName: "caller"},
		Status: corev1.PodStatus{
			PodIP:  "10.0.0.10",
			PodIPs: []corev1.PodIP{{IP: "2001:db8::1"}, {IP: "invalid"}},
		},
	}
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
	require.True(t, normalizedPeerMatchesPod(&peer, "server", pod, &corev1.Namespace{}))
	peer.NotNamespaces = []string{"client"}
	require.False(t, normalizedPeerMatchesPod(&peer, "server", pod, &corev1.Namespace{}))
	peer.NotNamespaces = nil
	peer.TrustDomains = []string{"external.local"}
	require.False(t, normalizedPeerMatchesPod(&peer, "server", pod, &corev1.Namespace{}))

	require.True(t, podMatchesIPBlocks(pod, []netv1.IPBlock{{CIDR: "10.0.0.0/24"}}))
	require.False(t, podMatchesIPBlocks(pod, []netv1.IPBlock{{
		CIDR: "10.0.0.0/24", Except: []string{"10.0.0.0/24"},
	}}))
	address, err := netip.ParseAddr(pod.Status.PodIPs[0].IP)
	require.NoError(t, err)
	require.True(t, ipBlockContainsAddress(&netv1.IPBlock{CIDR: "2001:db8::/64"}, address))
}

func TestPolicyMatchingUtilityEdges(t *testing.T) {
	tests := []struct {
		value    string
		patterns []string
		want     bool
	}{
		{value: "client", patterns: nil, want: false},
		{value: "client", patterns: []string{"*"}, want: true},
		{value: "client", patterns: []string{"*lie*"}, want: true},
		{value: "client", patterns: []string{"*ent"}, want: true},
		{value: "client", patterns: []string{"cli*"}, want: true},
		{value: "client", patterns: []string{"client"}, want: true},
		{value: "client", patterns: []string{"server"}, want: false},
	}
	for _, test := range tests {
		require.Equal(t, test.want, matchesAnyPattern(test.value, test.patterns), "%q %#v", test.value, test.patterns)
	}

	port := intstr.FromInt32(8080)
	peer := normalizedPeer{
		TrustDomains:    []string{"cluster.local"},
		NotTrustDomains: []string{"external.local"},
	}
	strings := normalizedPeerStrings([]normalizedPeer{peer}, false)
	require.Contains(t, strings[0], "trustDomains=cluster.local")
	require.Contains(t, strings[0], "notTrustDomains=external.local")
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
