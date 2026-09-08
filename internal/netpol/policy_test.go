// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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
	require.Equal(t, PolicyActionDeny, findPolicyRuleAction(t, result.Ingress, "allow-with-deny", PolicyActionDeny).ID.Action)
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
	require.Equal(t, AccessAllowed, allowed.State)
	require.Equal(t, []string{"SCTP/all", "TCP/8080", "UDP/all"}, permissionStrings(allowed.Permissions))
	other := findPrimitive(t, result.Ingress, PrimitivePod, "client", "other")
	require.Equal(t, AccessAllowed, other.State)
	require.Equal(t, []string{"SCTP/all", "UDP/all"}, permissionStrings(other.Permissions))

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
