// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	benchNamespaces       = 40
	benchPodsPerNamespace = 25
	benchNativePerNS      = 5
)

// BenchmarkEvaluateSubjectNativeOnly measures a 1,000-pod cluster that only
// uses Kubernetes NetworkPolicy.
func BenchmarkEvaluateSubjectNativeOnly(b *testing.B) {
	snapshot := benchmarkSnapshot(0, 0, 0)
	benchmarkEvaluateSubject(b, &snapshot)
}

// BenchmarkEvaluateSubjectModerateCustom adds a moderate number of Cilium and
// Istio policies to the native topology.
func BenchmarkEvaluateSubjectModerateCustom(b *testing.B) {
	snapshot := benchmarkSnapshot(40, 10, 40)
	benchmarkEvaluateSubject(b, &snapshot)
}

// BenchmarkEvaluateSubjectHeavyCustom stresses cluster-wide and root-namespace
// policy scans.
func BenchmarkEvaluateSubjectHeavyCustom(b *testing.B) {
	snapshot := benchmarkSnapshot(120, 50, 80)
	benchmarkEvaluateSubject(b, &snapshot)
}

func benchmarkEvaluateSubject(b *testing.B, snapshot *Snapshot) {
	b.Helper()
	evaluator := NewEvaluator()
	subject := SubjectRef{Kind: SubjectNamespace, Name: benchNamespace(0)}
	if _, err := evaluator.EvaluateSubject(subject, *snapshot, Options{}); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := evaluator.EvaluateSubject(subject, *snapshot, Options{}); err != nil {
			b.Fatal(err)
		}
	}
}

func benchNamespace(index int) string {
	return fmt.Sprintf("bench-%02d", index)
}

func benchmarkSnapshot(cnps, ccnps, authzs int) Snapshot {
	tiers := []string{"frontend", "backend", "data"}
	var snapshot Snapshot
	for n := range benchNamespaces {
		namespace := benchNamespace(n)
		snapshot.Namespaces = append(snapshot.Namespaces, corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
			Name: namespace, UID: types.UID("ns-" + namespace),
			Labels: map[string]string{"team": fmt.Sprintf("team-%d", n%5), "istio.io/dataplane-mode": "ambient"},
		}})
		for p := range benchPodsPerNamespace {
			snapshot.Pods = append(snapshot.Pods, corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace, Name: fmt.Sprintf("pod-%02d", p),
					UID:    types.UID(fmt.Sprintf("%s-pod-%02d", namespace, p)),
					Labels: map[string]string{"app": fmt.Sprintf("app-%d", p%5), "tier": tiers[p%3]},
				},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{
					Name: "app",
					Ports: []corev1.ContainerPort{
						{Name: "http", ContainerPort: 8080},
						{Name: "metrics", ContainerPort: 9090},
					},
				}}},
				Status: corev1.PodStatus{PodIP: fmt.Sprintf("10.%d.%d.%d", 10+n/200, n%200, p+10)},
			})
		}
		snapshot.NetworkPolicies = append(snapshot.NetworkPolicies, benchmarkNativePolicies(namespace, n)...)
	}
	for index := range cnps {
		snapshot.CiliumNetworkPolicies = append(snapshot.CiliumNetworkPolicies, benchmarkCNP(index))
	}
	for index := range ccnps {
		snapshot.CiliumClusterwideNetworkPolicies = append(snapshot.CiliumClusterwideNetworkPolicies, benchmarkCCNP(index))
	}
	for index := range authzs {
		snapshot.IstioAuthorizationPolicies = append(snapshot.IstioAuthorizationPolicies, benchmarkAuthz(index))
	}
	return snapshot
}

func benchmarkNativePolicies(namespace string, index int) []netv1.NetworkPolicy {
	tcp, udp := corev1.ProtocolTCP, corev1.ProtocolUDP
	http, dns, postgres := intstr.FromString("http"), intstr.FromInt32(53), intstr.FromInt32(5432)
	meta := func(name string) metav1.ObjectMeta {
		return metav1.ObjectMeta{
			Namespace: namespace, Name: name, UID: types.UID(namespace + "-" + name), ResourceVersion: "1",
		}
	}
	policies := []netv1.NetworkPolicy{
		{
			ObjectMeta: meta("default-deny"),
			Spec: netv1.NetworkPolicySpec{
				PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress, netv1.PolicyTypeEgress},
			},
		},
		{
			ObjectMeta: meta("allow-frontend"),
			Spec: netv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tier": "backend"}},
				PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
				Ingress: []netv1.NetworkPolicyIngressRule{{
					From: []netv1.NetworkPolicyPeer{{
						NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": fmt.Sprintf("team-%d", index%5)}},
						PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "frontend"}},
					}},
					Ports: []netv1.NetworkPolicyPort{{Protocol: &tcp, Port: &http}},
				}},
			},
		},
		{
			ObjectMeta: meta("allow-data-egress"),
			Spec: netv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tier": "backend"}},
				PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
				Egress: []netv1.NetworkPolicyEgressRule{{
					To: []netv1.NetworkPolicyPeer{{
						NamespaceSelector: &metav1.LabelSelector{},
						PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "data"}},
					}},
					Ports: []netv1.NetworkPolicyPort{{Protocol: &tcp, Port: &postgres}},
				}},
			},
		},
		{
			ObjectMeta: meta("allow-external"),
			Spec: netv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"tier": "frontend"}},
				PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
				Egress: []netv1.NetworkPolicyEgressRule{{
					To: []netv1.NetworkPolicyPeer{{IPBlock: &netv1.IPBlock{
						CIDR: "0.0.0.0/0", Except: []string{"10.0.0.0/8"},
					}}},
				}},
			},
		},
		{
			ObjectMeta: meta("allow-dns"),
			Spec: netv1.NetworkPolicySpec{
				PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
				Egress: []netv1.NetworkPolicyEgressRule{{
					To: []netv1.NetworkPolicyPeer{{
						NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "team-0"}},
					}},
					Ports: []netv1.NetworkPolicyPort{{Protocol: &udp, Port: &dns}, {Protocol: &tcp, Port: &dns}},
				}},
			},
		},
	}
	return policies[:benchNativePerNS]
}

func benchmarkCNP(index int) unstructured.Unstructured {
	namespace := benchNamespace(index % benchNamespaces)
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumNetworkPolicy",
		"metadata": map[string]any{
			"name": fmt.Sprintf("cnp-%03d", index), "namespace": namespace,
			"uid": fmt.Sprintf("cnp-%03d", index), "resourceVersion": "1",
		},
		"spec": map[string]any{
			"endpointSelector": map[string]any{"matchLabels": map[string]any{"app": fmt.Sprintf("app-%d", index%5)}},
			"ingress": []any{map[string]any{
				"fromEndpoints": []any{map[string]any{"matchLabels": map[string]any{
					"k8s:io.cilium.k8s.namespace.labels.team": fmt.Sprintf("team-%d", index%5),
					"tier": "frontend",
				}}},
				"toPorts": []any{map[string]any{"ports": []any{map[string]any{"port": "8080", "protocol": "TCP"}}}},
			}},
			"egressDeny": []any{map[string]any{
				"toEndpoints": []any{map[string]any{"matchLabels": map[string]any{"tier": "data"}}},
				"toPorts":     []any{map[string]any{"ports": []any{map[string]any{"port": "6379", "protocol": "TCP"}}}},
			}},
		},
	}}
}

func benchmarkCCNP(index int) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumClusterwideNetworkPolicy",
		"metadata": map[string]any{
			"name": fmt.Sprintf("ccnp-%03d", index), "uid": fmt.Sprintf("ccnp-%03d", index), "resourceVersion": "1",
		},
		"spec": map[string]any{
			"endpointSelector": map[string]any{"matchLabels": map[string]any{
				"tier": "backend", "k8s:io.cilium.k8s.namespace.labels.team": fmt.Sprintf("team-%d", index%5),
			}},
			"ingress": []any{map[string]any{
				"fromEndpoints": []any{map[string]any{"matchLabels": map[string]any{"app": fmt.Sprintf("app-%d", index%5)}}},
				"toPorts":       []any{map[string]any{"ports": []any{map[string]any{"port": "9090", "protocol": "TCP"}}}},
			}},
		},
	}}
}

func benchmarkAuthz(index int) unstructured.Unstructured {
	namespace := benchNamespace(index % benchNamespaces)
	action := "ALLOW"
	if index%4 == 3 {
		action = "DENY"
	}
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "security.istio.io/v1",
		"kind":       "AuthorizationPolicy",
		"metadata": map[string]any{
			"name": fmt.Sprintf("authz-%03d", index), "namespace": namespace,
			"uid": fmt.Sprintf("authz-%03d", index), "resourceVersion": "1",
		},
		"spec": map[string]any{
			"selector": map[string]any{"matchLabels": map[string]any{"app": fmt.Sprintf("app-%d", index%5)}},
			"action":   action,
			"rules": []any{map[string]any{
				"from": []any{map[string]any{"source": map[string]any{
					"namespaces": []any{benchNamespace((index + 1) % benchNamespaces), "bench-1*"},
				}}},
				"to": []any{map[string]any{"operation": map[string]any{"ports": []any{"8080", "9090"}}}},
			}},
		},
	}}
}
