// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
)

// scopedSnapshot adds an unrelated "other" namespace to the client/server
// topology. The server only has a native NetworkPolicy allowing TCP/8080.
func scopedSnapshot() Snapshot {
	snapshot := testSnapshot()
	snapshot.Namespaces = append(snapshot.Namespaces, corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: "other", Labels: map[string]string{"team": "other", istioDataplaneModeLabel: "ambient"},
	}})
	snapshot.Pods = append(snapshot.Pods, corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "other", Name: "other", UID: "other", Labels: map[string]string{"role": "other"},
	}})
	snapshot.NetworkPolicies = []netv1.NetworkPolicy{ingressPolicy("allow-client", "server", []netv1.NetworkPolicyIngressRule{{
		From:  []netv1.NetworkPolicyPeer{{NamespaceSelector: selector(map[string]string{"team": "client"})}},
		Ports: []netv1.NetworkPolicyPort{numericPolicyPort(8080, 0)},
	}})}
	return snapshot
}

func TestUnrelatedUncertainPoliciesDoNotDegradeKnownSubjects(t *testing.T) {
	istio := func(rules string) func(*testing.T, *Snapshot) {
		return func(t *testing.T, snapshot *Snapshot) {
			snapshot.IstioAuthorizationPolicies = append(snapshot.IstioAuthorizationPolicies,
				istioTestPolicy(t, "other", "unrelated", "other", "ALLOW", rules))
		}
	}
	cilium := func(policyType PolicyType, spec string) func(*testing.T, *Snapshot) {
		return func(t *testing.T, snapshot *Snapshot) {
			object := ciliumTestPolicy(t, policyType, "unrelated", spec)
			if policyType == PolicyTypeCiliumNetworkPolicy {
				object.SetNamespace("other")
			}
			addCiliumPolicy(snapshot, policyType, object)
		}
	}
	tests := []struct {
		name string
		add  func(*testing.T, *Snapshot)
	}{
		{"istio-principals", istio(`[{from: [{source: {principals: ["cluster.local/ns/client/sa/default"]}}]}]`)},
		{"istio-methods", istio(`[{to: [{operation: {methods: [GET]}}]}]`)},
		{"cilium-http", cilium(PolicyTypeCiliumNetworkPolicy, `
  endpointSelector: {matchLabels: {role: other}}
  ingress: [{toPorts: [{ports: [{port: "80", protocol: TCP}], rules: {http: [{method: GET}]}}]}]`)},
		{"cilium-fqdn", cilium(PolicyTypeCiliumNetworkPolicy, `
  endpointSelector: {matchLabels: {role: other}}
  egress: [{toFQDNs: [{matchName: example.com}]}]`)},
		{"cilium-host-policy", cilium(PolicyTypeCiliumClusterwideNetworkPolicy, `
  nodeSelector: {matchLabels: {node-role.kubernetes.io/worker: ""}}
  ingress: [{fromEntities: [cluster]}]`)},
		{"cilium-rejected", cilium(PolicyTypeCiliumNetworkPolicy, `
  endpointSelector: {matchLabels: {role: other}}
  egress: [{toCIDR: ["192.0.2.0/24"], toCIDRSet: [{cidr: "198.51.100.0/24"}]}]`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := scopedSnapshot()
			test.add(t, &snapshot)
			result := evaluateServer(t, &snapshot)
			primitive := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
			require.Equal(t, AccessAllowed, primitive.State)
			require.Equal(t, []string{"TCP/8080"}, permissionStrings(primitive.Permissions))
			require.Empty(t, primitive.Warnings)
			for _, warning := range result.Warnings {
				require.Contains(t, warning, "other/", "only pairs with the other pod can depend on the unrelated policy")
			}
			for _, direction := range []Direction{Ingress, Egress} {
				for _, candidate := range result.Direction(direction).Primitives[PrimitivePod] {
					if candidate.Ref.Namespace != "other" {
						require.NotEqual(t, AccessPartialData, candidate.State, "%s %s", direction, candidate.Ref.Name)
					}
				}
			}
		})
	}
}

func TestUncertainRulesOnlyDegradePairsTheyCouldMatch(t *testing.T) {
	snapshot := scopedSnapshot()
	addCiliumPolicy(&snapshot, PolicyTypeCiliumNetworkPolicy, ciliumTestPolicy(t, PolicyTypeCiliumNetworkPolicy, "l7", `
  endpointSelector: {matchLabels: {role: server}}
  ingress:
    - fromEndpoints: [{matchLabels: {role: client, io.kubernetes.pod.namespace: client}}]
      toPorts: [{ports: [{port: "9090", protocol: TCP}], rules: {http: [{method: GET}]}}]`))
	result := evaluateServer(t, &snapshot)
	client := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
	require.Equal(t, AccessPartialData, client.State)
	require.Equal(t, []string{"TCP/8080", "TCP/9090"}, permissionStrings(client.Permissions))
	require.Contains(t, strings.Join(client.Warnings, "\n"),
		"CiliumNetworkPolicy server/l7: ingress allow rule 0: Cilium L7 rules cannot be evaluated from the policy snapshot")
	other := findPrimitive(t, result.Ingress, PrimitivePod, "other", "other")
	require.Equal(t, AccessDisallowed, other.State, "the L7 rule cannot match the other pod")
	require.Empty(t, other.Warnings)
	namespace := findPrimitive(t, result.Ingress, PrimitiveNamespace, "", "client")
	require.Equal(t, AccessPartialData, namespace.State)
	require.Contains(t, namespace.Explanation, "1 of 1 concrete pod pairs depend on policy data")

	rule := findPolicyRule(t, result.Ingress, "l7")
	require.NotEmpty(t, rule.Warnings)
	row := findApplicability(t, NewEvaluator().RuleApplicability(result, Ingress, rule.ID, sets.New(PrimitivePod)))
	require.Equal(t, AccessPartialData, row.EffectiveState)
	require.Equal(t, []string{
		"CiliumNetworkPolicy server/l7: ingress allow rule 0: Cilium L7 rules cannot be evaluated from the policy snapshot",
	}, result.Warnings)
}

func TestDynamicPeersDegradeEveryPeerOfSelectedPods(t *testing.T) {
	snapshot := scopedSnapshot()
	addCiliumPolicy(&snapshot, PolicyTypeCiliumNetworkPolicy, ciliumTestPolicy(t, PolicyTypeCiliumNetworkPolicy, "fqdn", `
  endpointSelector: {matchLabels: {role: server}}
  egress: [{toFQDNs: [{matchName: example.com}], toPorts: [{ports: [{port: "443", protocol: TCP}]}]}]`))
	result := evaluateServer(t, &snapshot)
	for _, peer := range []string{"client", "other", "server"} {
		primitive := findPrimitive(t, result.Egress, PrimitivePod, peer, peer)
		require.Equal(t, AccessPartialData, primitive.State, peer)
		require.Empty(t, primitive.Permissions, "the disabled FQDN rule grants nothing that is modeled")
	}
	client, err := NewEvaluator().EvaluateSubject(SubjectRef{Kind: SubjectPod, Namespace: "client", Name: "client"}, snapshot, Options{})
	require.NoError(t, err)
	require.Equal(t, AccessAllowed, findPrimitive(t, client.Egress, PrimitivePod, "server", "server").State,
		"the FQDN rule only affects the server's egress")
	require.Equal(t, AccessPartialData, findPrimitive(t, client.Ingress, PrimitivePod, "server", "server").State)
	require.Equal(t, []string{"CiliumNetworkPolicy server/fqdn: egress allow rule 0: toFQDNs requires live DNS resolution"}, client.Warnings)
}

func TestIstioDenyDoesNotFakeAPeerMatch(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.NetworkPolicies = []netv1.NetworkPolicy{ingressPolicy("isolate", "server", []netv1.NetworkPolicyIngressRule{{
		From: []netv1.NetworkPolicyPeer{{PodSelector: selector(map[string]string{"role": "nobody"})}},
	}})}
	baseline := evaluateServer(t, &snapshot)
	row := findApplicability(t, NewEvaluator().DirectionApplicability(baseline, Ingress, sets.New(PrimitivePod)))
	require.False(t, row.PeerMatches)

	snapshot.IstioAuthorizationPolicies = []unstructured.Unstructured{
		istioTestPolicy(t, "server", "deny-address", "server", "DENY", `[{from: [{source: {ipBlocks: ["192.0.2.1/32"]}}]}]`),
	}
	result := evaluateServer(t, &snapshot)
	row = findApplicability(t, NewEvaluator().DirectionApplicability(result, Ingress, sets.New(PrimitivePod)))
	require.False(t, row.PeerMatches, "a DENY-only authorization layer adds no synthetic rule match")
	require.Equal(t, AccessDisallowed, row.EffectiveState)
	for _, evidence := range row.Primitive.Evidence {
		if evidence.RuleID.Direction == Ingress {
			require.NotEqual(t, SyntheticUnrestricted, evidence.RuleID.SyntheticKind)
		}
	}
}

func TestIstioAuthorizationOnlyAppliesToMeshWorkloads(t *testing.T) {
	sidecar := func(pod *corev1.Pod) {
		pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: istioProxyContainer})
	}
	tests := []struct {
		name   string
		mutate func(*Snapshot)
		state  AccessState
		ports  []string
	}{
		{name: "outside-mesh", mutate: func(*Snapshot) {}, state: AccessAllowed, ports: []string{"SCTP/all", "TCP/all", "UDP/all"}},
		{name: "sidecar", mutate: func(s *Snapshot) { sidecar(&s.Pods[1]) }, state: AccessAllowed, ports: []string{"SCTP/all", "UDP/all"}},
		{
			name: "ambient-namespace", state: AccessAllowed, ports: []string{"SCTP/all", "UDP/all"},
			mutate: func(s *Snapshot) { s.Namespaces[1].Labels[istioDataplaneModeLabel] = istioDataplaneModeAmbient },
		},
		{
			name: "ambient-opt-out", state: AccessAllowed, ports: []string{"SCTP/all", "TCP/all", "UDP/all"},
			mutate: func(s *Snapshot) {
				s.Namespaces[1].Labels[istioDataplaneModeLabel] = istioDataplaneModeAmbient
				s.Pods[1].Labels[istioDataplaneModeLabel] = istioDataplaneModeNone
			},
		},
		{
			name: "stale-sidecar-status", state: AccessPartialData, ports: []string{"SCTP/all", "UDP/all"},
			mutate: func(s *Snapshot) { s.Pods[1].Annotations = map[string]string{istioSidecarStatusAnnotation: "{}"} },
		},
		{
			name: "injection-without-sidecar", state: AccessPartialData, ports: []string{"SCTP/all", "UDP/all"},
			mutate: func(s *Snapshot) { s.Namespaces[1].Labels[istioInjectionNamespaceLabel] = "enabled" },
		},
		{
			name: "injection-opt-out", state: AccessAllowed, ports: []string{"SCTP/all", "TCP/all", "UDP/all"},
			mutate: func(s *Snapshot) {
				s.Namespaces[1].Labels[istioInjectionNamespaceLabel] = "enabled"
				s.Pods[1].Labels[istioInjectLabel] = "false"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := testSnapshot()
			for index := range snapshot.Namespaces {
				snapshot.Namespaces[index].Labels = map[string]string{"team": snapshot.Namespaces[index].Name}
			}
			snapshot.Namespaces = append(snapshot.Namespaces, corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: DefaultIstioRootNamespace}})
			// A mesh-wide allow-nothing baseline.
			snapshot.IstioAuthorizationPolicies = []unstructured.Unstructured{
				istioTestPolicy(t, DefaultIstioRootNamespace, "allow-nothing", "", "ALLOW", ""),
			}
			test.mutate(&snapshot)
			result := evaluateServer(t, &snapshot)
			primitive := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
			require.Equal(t, test.state, primitive.State)
			require.Equal(t, test.ports, permissionStrings(primitive.Permissions))
			if test.state == AccessPartialData {
				require.Contains(t, strings.Join(primitive.Warnings, "\n"), "Istio AuthorizationPolicy enforcement for pod server/server is uncertain")
			}
			authorizationRows := 0
			for _, rule := range result.Ingress.Rules {
				if rule.ID.SyntheticKind == SyntheticAuthorizationDefaultDeny {
					authorizationRows++
				}
			}
			enforced := test.ports[len(test.ports)-1] == "UDP/all" && len(test.ports) == 2
			require.Equal(t, enforced, authorizationRows == 1, "only an enforced ALLOW isolates the authorization layer")
		})
	}
}

func TestMeshEnrollmentDetection(t *testing.T) {
	always := corev1.ContainerRestartPolicyAlways
	namespace := func(labels map[string]string) *corev1.Namespace {
		return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns", Labels: labels}}
	}
	tests := []struct {
		name      string
		pod       corev1.Pod
		namespace *corev1.Namespace
		want      meshState
		reason    string
	}{
		{name: "sidecar container", pod: corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: istioProxyContainer}}}}, want: meshEnrolled},
		{
			name: "native sidecar", want: meshEnrolled,
			pod: corev1.Pod{Spec: corev1.PodSpec{InitContainers: []corev1.Container{{Name: istioProxyContainer, RestartPolicy: &always}}}},
		},
		{
			name: "init container is not a sidecar", namespace: namespace(nil), want: meshNotEnrolled,
			pod: corev1.Pod{Spec: corev1.PodSpec{InitContainers: []corev1.Container{{Name: istioProxyContainer}}}},
		},
		{name: "host network", pod: corev1.Pod{Spec: corev1.PodSpec{HostNetwork: true}}, want: meshNotEnrolled, reason: "hostNetwork"},
		{
			name: "ambient pod label", want: meshEnrolled,
			pod: corev1.Pod{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{istioDataplaneModeLabel: istioDataplaneModeAmbient}}},
		},
		{
			name: "ambient redirection", want: meshEnrolled,
			pod: corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{istioAmbientRedirectionAnnotation: "enabled"}}},
		},
		{
			name: "ambient namespace", namespace: namespace(map[string]string{istioDataplaneModeLabel: istioDataplaneModeAmbient}),
			want: meshEnrolled,
		},
		{
			name: "dataplane opt out", namespace: namespace(map[string]string{istioDataplaneModeLabel: istioDataplaneModeAmbient}),
			pod:  corev1.Pod{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{istioDataplaneModeLabel: istioDataplaneModeNone}}},
			want: meshNotEnrolled, reason: "opts out",
		},
		{
			name: "stale status", want: meshUnknown, reason: "annotation",
			pod: corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{istioSidecarStatusAnnotation: "{}"}}},
		},
		{name: "missing namespace", want: meshUnknown, reason: "missing from the snapshot"},
		{name: "injection namespace", namespace: namespace(map[string]string{istioInjectionNamespaceLabel: "enabled"}), want: meshUnknown, reason: "injection"},
		{name: "revision namespace", namespace: namespace(map[string]string{istioRevisionLabel: "canary"}), want: meshUnknown},
		{
			name: "revision namespace injection disabled", want: meshNotEnrolled,
			namespace: namespace(map[string]string{istioRevisionLabel: "canary", istioInjectionNamespaceLabel: "disabled"}),
		},
		{
			name: "pod injection label", namespace: namespace(nil), want: meshUnknown,
			pod: corev1.Pod{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{istioInjectLabel: "true"}}},
		},
		{
			name: "annotation opt out", namespace: namespace(map[string]string{istioInjectionNamespaceLabel: "enabled"}), want: meshNotEnrolled,
			pod: corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{istioInjectLabel: "false"}}},
		},
		{name: "plain pod", namespace: namespace(nil), want: meshNotEnrolled, reason: "no Istio sidecar"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.pod.Namespace, test.pod.Name = "ns", "pod"
			enrollment := podMeshEnrollment(&test.pod, test.namespace)
			require.Equal(t, test.want, enrollment.state)
			require.Contains(t, enrollment.reason, test.reason)
			identity := istioPodIdentity(&test.pod, enrollment)
			require.Equal(t, test.want == meshEnrolled, identity.present())
			if identity.present() {
				require.Equal(t, "cluster.local/ns/ns/sa/default", identity.principal)
			}
		})
	}
}

func TestCiliumHostNetworkPodsArePartialData(t *testing.T) {
	cnp := func(t *testing.T, spec string) unstructured.Unstructured {
		return ciliumTestPolicy(t, PolicyTypeCiliumNetworkPolicy, "server-ingress", spec)
	}
	t.Run("host network peer", func(t *testing.T) {
		snapshot := testSnapshot()
		snapshot.Pods[0].Spec.HostNetwork = true
		addCiliumPolicy(&snapshot, PolicyTypeCiliumNetworkPolicy, cnp(t, `
  endpointSelector: {matchLabels: {role: server}}
  ingress: [{fromEndpoints: [{matchLabels: {role: client, io.kubernetes.pod.namespace: client}}]}]`))
		result := evaluateServer(t, &snapshot)
		primitive := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
		require.Equal(t, AccessPartialData, primitive.State)
		require.Contains(t, strings.Join(primitive.Warnings, "\n"), "peer pod client/client uses hostNetwork")
		egress := findPrimitive(t, result.Egress, PrimitivePod, "client", "client")
		require.Equal(t, AccessAllowed, egress.State, "no Cilium policy constrains the server's egress")
	})
	t.Run("host network subject", func(t *testing.T) {
		snapshot := testSnapshot()
		snapshot.Pods[1].Spec.HostNetwork = true
		addCiliumPolicy(&snapshot, PolicyTypeCiliumNetworkPolicy, cnp(t, `
  endpointSelector: {matchLabels: {role: server}}
  ingress: [{fromEntities: [cluster]}]`))
		result := evaluateServer(t, &snapshot)
		primitive := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
		require.Equal(t, AccessPartialData, primitive.State)
		require.Contains(t, strings.Join(primitive.Warnings, "\n"), "pod server/server uses hostNetwork")
	})
	t.Run("host policies", func(t *testing.T) {
		snapshot := testSnapshot()
		snapshot.Pods[1].Spec.HostNetwork = true
		addCiliumPolicy(&snapshot, PolicyTypeCiliumClusterwideNetworkPolicy, ciliumTestPolicy(t, PolicyTypeCiliumClusterwideNetworkPolicy, "host", `
  nodeSelector: {}
  ingress: [{fromEntities: [cluster]}]`))
		result := evaluateServer(t, &snapshot)
		for _, direction := range []Direction{Ingress, Egress} {
			primitive := findPrimitive(t, result.Direction(direction), PrimitivePod, "client", "client")
			require.Equal(t, AccessPartialData, primitive.State, direction.String())
		}
	})
	t.Run("native only", func(t *testing.T) {
		snapshot := testSnapshot()
		snapshot.Pods[0].Spec.HostNetwork = true
		snapshot.NetworkPolicies = []netv1.NetworkPolicy{ingressPolicy("native", "server", []netv1.NetworkPolicyIngressRule{{}})}
		result := evaluateServer(t, &snapshot)
		require.Equal(t, AccessAllowed, findPrimitive(t, result.Ingress, PrimitivePod, "client", "client").State)
		require.Empty(t, result.Warnings)
	})
}

func TestSyntheticRowsArePerLayer(t *testing.T) {
	snapshot := istioTransportSnapshot()
	snapshot.NetworkPolicies = snapshot.NetworkPolicies[:1]
	snapshot.IstioAuthorizationPolicies = []unstructured.Unstructured{
		istioTestPolicy(t, "server", "allow-8080", "server", "ALLOW", `[{to: [{operation: {ports: ["8080"]}}]}]`),
	}
	result := evaluateServer(t, &snapshot)
	kinds := map[string]RuleResult{}
	for _, rule := range result.Ingress.Rules {
		if rule.Synthetic {
			kinds[rule.ID.SyntheticKind] = rule
		}
	}
	require.Contains(t, kinds, SyntheticUnrestricted, "only Istio isolates, so the network layer stays unrestricted")
	require.Contains(t, kinds, SyntheticAuthorizationDefaultDeny)
	require.NotContains(t, kinds, SyntheticDefaultDeny)
	primitive := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
	require.Equal(t, AccessAllowed, primitive.State)
	require.Equal(t, []string{"SCTP/9000", "TCP/8080", "UDP/5353"}, permissionStrings(primitive.Permissions))

	snapshot.IstioAuthorizationPolicies = []unstructured.Unstructured{
		istioTestPolicy(t, "server", "allow-nothing", "server", "ALLOW", "[]"),
	}
	result = evaluateServer(t, &snapshot)
	var authorization RuleResult
	for _, rule := range result.Ingress.Rules {
		if rule.ID.SyntheticKind == SyntheticAuthorizationDefaultDeny {
			authorization = rule
		}
	}
	require.Equal(t, 1, authorization.SubjectMatchCount, "the TCP denial is attributed to the authorization default deny")
	row := findApplicability(t, NewEvaluator().DirectionApplicability(result, Ingress, sets.New(PrimitivePod)))
	require.True(t, row.PeerMatches, "the network layer is unrestricted")
	require.Equal(t, []string{"SCTP/9000", "UDP/5353"}, permissionStrings(row.Permissions))
}

func TestCiliumRuleSpecProvenance(t *testing.T) {
	snapshot := testSnapshot()
	addCiliumPolicy(&snapshot, PolicyTypeCiliumNetworkPolicy, ciliumTestPolicy(t, PolicyTypeCiliumNetworkPolicy, "multi", `
  endpointSelector: {matchLabels: {role: server}}
  ingress: [{fromEntities: [cluster]}]
specs:
  - endpointSelector: {matchLabels: {role: server}}
    ingressDeny: [{fromEntities: [cluster], toPorts: [{ports: [{port: "22", protocol: TCP}]}]}]`))
	addCiliumPolicy(&snapshot, PolicyTypeCiliumNetworkPolicy, ciliumTestPolicy(t, PolicyTypeCiliumNetworkPolicy, "single", `
  endpointSelector: {matchLabels: {role: server}}
  ingress: [{fromEntities: [cluster]}]`))
	result := evaluateServer(t, &snapshot)
	allow := findPolicyRuleAction(t, result.Ingress, "multi", PolicyActionAllow)
	deny := findPolicyRuleAction(t, result.Ingress, "multi", PolicyActionDeny)
	require.Equal(t, "spec", allow.PolicySpec)
	require.Equal(t, "specs[0]", deny.PolicySpec)
	require.Equal(t, 2, allow.PolicySpecCount)
	require.Equal(t, 1, deny.ID.PolicySpecIndex)
	single := findPolicyRule(t, result.Ingress, "single")
	require.Equal(t, "spec", single.PolicySpec)
	require.Equal(t, 1, single.PolicySpecCount)
}

func TestCiliumValidationAndPortSemanticsEndToEnd(t *testing.T) {
	t.Run("port zero is a wildcard", func(t *testing.T) {
		snapshot := testSnapshot()
		addCiliumPolicy(&snapshot, PolicyTypeCiliumNetworkPolicy, ciliumTestPolicy(t, PolicyTypeCiliumNetworkPolicy, "zero", `
  endpointSelector: {matchLabels: {role: server}}
  ingress: [{fromEntities: [cluster], toPorts: [{ports: [{port: "0", protocol: TCP}]}]}]`))
		result := evaluateServer(t, &snapshot)
		primitive := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
		require.Equal(t, AccessAllowed, primitive.State)
		require.Equal(t, []string{"TCP/all"}, permissionStrings(primitive.Permissions))
		require.Empty(t, result.Warnings)
	})
	t.Run("icmp only rule isolates without transport ports", func(t *testing.T) {
		snapshot := testSnapshot()
		addCiliumPolicy(&snapshot, PolicyTypeCiliumNetworkPolicy, ciliumTestPolicy(t, PolicyTypeCiliumNetworkPolicy, "icmp", `
  endpointSelector: {matchLabels: {role: server}}
  ingress: [{fromEntities: [cluster], icmps: [{fields: [{type: 8}]}]}]`))
		result := evaluateServer(t, &snapshot)
		primitive := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
		require.Equal(t, AccessDisallowed, primitive.State)
		require.Empty(t, primitive.Permissions)
		require.Empty(t, result.Warnings)
		rule := findPolicyRule(t, result.Ingress, "icmp")
		require.Contains(t, strings.Join(rule.Notes, "\n"), "ICMP")
		require.Empty(t, rule.Permissions)
	})
	t.Run("combined CIDR families are rejected", func(t *testing.T) {
		snapshot := testSnapshot()
		addCiliumPolicy(&snapshot, PolicyTypeCiliumNetworkPolicy, ciliumTestPolicy(t, PolicyTypeCiliumNetworkPolicy, "combined", `
  endpointSelector: {matchLabels: {role: server}}
  egress: [{toCIDR: ["192.0.2.0/24"], toCIDRSet: [{cidr: "198.51.100.0/24"}]}]`))
		result := evaluateServer(t, &snapshot)
		primitive := findPrimitive(t, result.Egress, PrimitivePod, "client", "client")
		require.Equal(t, AccessPartialData, primitive.State)
		require.Contains(t, strings.Join(result.Warnings, "\n"),
			"CiliumNetworkPolicy server/combined: Cilium rejects this policy: spec: egress allow rule 0: combining ToCIDR and ToCIDRSet is not supported yet")
		require.Equal(t, AccessAllowed, findPrimitive(t, result.Ingress, PrimitivePod, "client", "client").State)
	})
	t.Run("custom authorization only degrades matching requests", func(t *testing.T) {
		snapshot := istioTransportSnapshot()
		snapshot.IstioAuthorizationPolicies = []unstructured.Unstructured{
			istioTestPolicy(t, "server", "ext", "server", "CUSTOM", `[{from: [{source: {namespaces: [client]}}]}]`),
		}
		result := evaluateServer(t, &snapshot)
		primitive := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
		require.Equal(t, AccessPartialData, primitive.State)
		require.Equal(t, []string{"SCTP/9000", "TCP/8080", "TCP/8081", "UDP/5353"}, permissionStrings(primitive.Permissions))
		self := findPrimitive(t, result.Ingress, PrimitivePod, "server", "server")
		require.NotEqual(t, AccessPartialData, self.State, "the CUSTOM rule cannot match sources from the server namespace")
		rule := findPolicyRule(t, result.Ingress, "ext")
		require.Equal(t, PolicyActionCustom, rule.ID.Action)
	})
}

func TestRootNamespaceConflictsMakeRootPoliciesSelectionUnknown(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.IstioRootNamespace = DefaultIstioRootNamespace
	snapshot.IstioRootNamespaceCandidates = []string{"mesh-root", DefaultIstioRootNamespace}
	snapshot.IstioAuthorizationPolicies = []unstructured.Unstructured{
		istioTestPolicy(t, "mesh-root", "maybe-mesh-wide", "", "ALLOW", ""),
	}
	result := evaluateServer(t, &snapshot)
	primitive := findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
	require.Equal(t, AccessPartialData, primitive.State)
	require.Contains(t, strings.Join(result.Warnings, "\n"), "different root namespaces")

	snapshot.IstioRootNamespaceCandidates = nil
	result = evaluateServer(t, &snapshot)
	primitive = findPrimitive(t, result.Ingress, PrimitivePod, "client", "client")
	require.Equal(t, AccessAllowed, primitive.State, "outside the resolved root the policy is namespace-local")
	require.Empty(t, result.Warnings)
}

func TestSnapshotNotesAreCopiedToResults(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.Notes = []string{"b", "a", "a"}
	result := evaluateServer(t, &snapshot)
	require.Equal(t, []string{"a", "b"}, result.Notes)
	require.Empty(t, result.Warnings)
}

func TestNormalizationCacheReusesAndEvictsPolicies(t *testing.T) {
	evaluator, ok := NewEvaluator().(*engine)
	require.True(t, ok)
	snapshot := testSnapshot()
	policy := ingressPolicy("cached", "server", []netv1.NetworkPolicyIngressRule{{}})
	policy.ResourceVersion = "1"
	snapshot.NetworkPolicies = []netv1.NetworkPolicy{policy}
	object := ciliumTestPolicy(t, PolicyTypeCiliumNetworkPolicy, "cached-cnp", `
  endpointSelector: {matchLabels: {role: server}}
  egress: [{toEntities: [cluster]}]`)
	object.SetResourceVersion("7")
	addCiliumPolicy(&snapshot, PolicyTypeCiliumNetworkPolicy, object)

	subject := SubjectRef{Kind: SubjectPod, Namespace: "server", Name: "server"}
	first, err := evaluator.EvaluateSubject(subject, snapshot, Options{})
	require.NoError(t, err)
	require.Equal(t, 2, evaluator.cache.size())
	cached := evaluator.cache.entries[nativeCacheKey(&snapshot.NetworkPolicies[0])].policies[0]

	second, err := evaluator.EvaluateSubject(subject, snapshot, Options{})
	require.NoError(t, err)
	require.Same(t, cached, evaluator.cache.entries[nativeCacheKey(&snapshot.NetworkPolicies[0])].policies[0])
	require.Equal(t, first.Ingress.Rules, second.Ingress.Rules)

	snapshot.NetworkPolicies[0].ResourceVersion = "2"
	snapshot.NetworkPolicies[0].Spec.Ingress = nil
	third, err := evaluator.EvaluateSubject(subject, snapshot, Options{})
	require.NoError(t, err)
	require.Equal(t, 2, evaluator.cache.size(), "the stale version is evicted")
	require.Equal(t, AccessDisallowed, findPrimitive(t, third.Ingress, PrimitivePod, "client", "client").State)

	snapshot.CiliumNetworkPolicies = nil
	_, err = evaluator.EvaluateSubject(subject, snapshot, Options{})
	require.NoError(t, err)
	require.Equal(t, 1, evaluator.cache.size())

	uncached := snapshot.NetworkPolicies[0].DeepCopy()
	uncached.ResourceVersion = ""
	require.Empty(t, nativeCacheKey(uncached))
	require.Empty(t, customCacheKey(&unstructured.Unstructured{Object: map[string]any{}}, PolicyTypeCiliumNetworkPolicy, nil))
	var nilCache *normalizationCache
	nilCache.begin()
	nilCache.sweep()
	require.Len(t, nilCache.load("key", func() []*normalizedPolicy { return []*normalizedPolicy{{}} }), 1)
}

func TestEvaluationMatchesUncachedResults(t *testing.T) {
	snapshot := benchmarkSnapshot(6, 3, 6)
	evaluator := NewEvaluator()
	subject := SubjectRef{Kind: SubjectNamespace, Name: benchNamespace(1)}
	for range 2 {
		cached, err := evaluator.EvaluateSubject(subject, snapshot, Options{})
		require.NoError(t, err)
		fresh, err := (&engine{}).EvaluateSubject(subject, snapshot, Options{})
		require.NoError(t, err)
		cached.GeneratedAt = fresh.GeneratedAt
		require.Equal(t, fresh, cached)
	}
	result, err := evaluator.EvaluateSubject(subject, snapshot, Options{})
	require.NoError(t, err)
	require.NotEmpty(t, result.Ingress.Rules)
	for _, rule := range result.Ingress.Rules {
		require.Equal(t, rule.ID.String(), rule.StableID(), rule.ID.String())
	}
}

func TestNormalizationEdgeCases(t *testing.T) {
	object := policyObject(t, `
apiVersion: example.io/v1
kind: Unknown
metadata: {name: odd, namespace: server}
spec: {}`)
	policies, errs := normalizeCustomPolicy(&object, PolicyType("odd"), nil)
	require.Len(t, policies, 1)
	require.Equal(t, policySelectionUnknown, policies[0].State)
	require.ErrorContains(t, errors.Join(errs...), `unsupported policy type "odd"`)

	snapshot := testSnapshot()
	x := newSnapshotIndex(&snapshot)
	unfinalized := &normalizedPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "server", Name: "manual"},
		Selector: normalizedSelector{
			Pod:            metav1.LabelSelector{MatchLabels: map[string]string{"role": "server"}},
			ServiceAccount: &metav1.LabelSelector{MatchLabels: map[string]string{"name": "default"}},
		},
	}
	require.True(t, policySelectsPod(unfinalized, x.info(&snapshot.Pods[1])))
	require.False(t, policySelectsPod(unfinalized, x.info(&snapshot.Pods[0])))
	require.False(t, selectorMatches(nil, nil, nil))
	invalid := compileSelector(&metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "app", Operator: "Invalid"}},
	})
	require.False(t, invalid.Matches(labels.Set{"app": "x"}), "an invalid selector compiles to one that matches nothing")

	empty := policyObject(t, `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: {name: empty, namespace: server}`)
	policies, errs = normalizeCiliumPolicy(&empty, PolicyTypeCiliumNetworkPolicy)
	require.Empty(t, errs)
	require.Equal(t, policyInert, policies[0].State)

	both := policyObject(t, `
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata: {name: both}
spec:
  endpointSelector: {}
  nodeSelector: {}
  ingress: [{}]`)
	policies, _ = normalizeCiliumPolicy(&both, PolicyTypeCiliumClusterwideNetworkPolicy)
	require.Equal(t, policyEffectUnknown, policies[0].State)
	require.Contains(t, policies[0].reasons[0], "rule cannot have both EndpointSelector and NodeSelector")

	neither := policyObject(t, `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: {name: neither, namespace: server}
spec:
  egress: [{}]`)
	policies, _ = normalizeCiliumPolicy(&neither, PolicyTypeCiliumNetworkPolicy)
	require.Equal(t, policySelectionUnknown, policies[0].State)
	require.False(t, policies[0].affects(Ingress))
	require.True(t, policies[0].affects(Egress))

	noRules := policyObject(t, `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: {name: no-rules, namespace: server}
spec:
  endpointSelector: {}
  enableDefaultDeny: {ingress: true}`)
	policies, errs = normalizeCiliumPolicy(&noRules, PolicyTypeCiliumNetworkPolicy)
	require.ErrorContains(t, errors.Join(errs...), "rule must have at least one of Ingress")
	require.Equal(t, policyEffectUnknown, policies[0].State)
	require.False(t, policies[0].affects(Ingress), "a rejected policy without rules degrades nothing")
}

func TestUncertainRulesCanMatchCIDRPrimitives(t *testing.T) {
	snapshot := testSnapshot()
	addCiliumPolicy(&snapshot, PolicyTypeCiliumNetworkPolicy, ciliumTestPolicy(t, PolicyTypeCiliumNetworkPolicy, "cidr", `
  endpointSelector: {matchLabels: {role: server}}
  egress:
    - toCIDR: ["192.0.2.0/24"]
      toPorts: [{ports: [{port: "443", protocol: TCP}], serverNames: [example.com]}]
    - toCIDR: ["198.51.100.0/24"]
    - toFQDNs: [{matchName: example.com}]`))
	result := evaluateServer(t, &snapshot)
	tls := findCIDRPrimitive(t, result.Egress, "192.0.2.0/24", nil)
	require.Equal(t, AccessPartialData, tls.State)
	require.Contains(t, strings.Join(tls.Warnings, "\n"), "TLS, SNI")
	plain := findCIDRPrimitive(t, result.Egress, "198.51.100.0/24", nil)
	require.Equal(t, AccessPartialData, plain.State, "the FQDN rule may resolve to any address")
	require.Equal(t, []string{"SCTP/all", "TCP/all", "UDP/all"}, permissionStrings(plain.Permissions))
	matcher := &cidrMatcher{ref: &PrimitiveRef{Kind: PrimitiveCIDR, CIDR: "203.0.113.0/24"}}
	require.False(t, matcher.couldMatch(nil, &normalizedRule{MatchNone: true}))
	require.True(t, matcher.couldMatch(nil, &normalizedRule{}))
	require.False(t, matcher.couldMatch(nil, &normalizedRule{Peers: []normalizedPeer{{IPBlocks: []netv1.IPBlock{{CIDR: "192.0.2.0/24"}}}}}))
	require.True(t, matcher.couldMatch(nil, &normalizedRule{Peers: []normalizedPeer{{NotPrincipals: []string{"x"}}}}))
	require.False(t, matcher.couldMatch(nil, &normalizedRule{Peers: []normalizedPeer{{Principals: []string{"x"}}}}))
	require.Equal(t, "rule", ruleKeyOf("rule"))
}

func TestEvaluatorIsSafeForConcurrentUse(t *testing.T) {
	snapshot := benchmarkSnapshot(8, 2, 8)
	evaluator := NewEvaluator()
	want, err := evaluator.EvaluateSubject(SubjectRef{Kind: SubjectNamespace, Name: benchNamespace(2)}, snapshot, Options{})
	require.NoError(t, err)
	var wg sync.WaitGroup
	results := make([]SubjectResult, 4)
	errs := make([]error, 4)
	for index := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[index], errs[index] = evaluator.EvaluateSubject(
				SubjectRef{Kind: SubjectNamespace, Name: benchNamespace(2)}, snapshot, Options{},
			)
		}()
	}
	wg.Wait()
	for index := range results {
		require.NoError(t, errs[index])
		results[index].GeneratedAt = want.GeneratedAt
		require.Equal(t, want, results[index], "concurrent evaluations share cached policies safely")
	}
}
