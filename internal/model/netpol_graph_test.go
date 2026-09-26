// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package model

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/derailed/k9s/internal"
	"github.com/derailed/k9s/internal/client"
	"github.com/derailed/k9s/internal/dao"
	"github.com/derailed/k9s/internal/netpol"
	"github.com/derailed/k9s/internal/watch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/discovery/cached/disk"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/rest"
)

func TestNetPolGraphRefreshBuildsClusterSnapshot(t *testing.T) {
	factory := newNetPolGraphFactory()
	factory.add(client.PodGVR, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns"}})
	factory.add(client.NsGVR, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns"}})
	factory.add(client.NpGVR, &netv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "ns"}})
	factory.add(client.DpGVR, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "deployment", Namespace: "ns"}})
	factory.add(client.RsGVR, &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "replicaset", Namespace: "ns"}})
	factory.add(client.JobGVR, &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "job", Namespace: "ns"}})
	factory.add(client.CnpGVR, customPolicy("cilium.io/v2", "CiliumNetworkPolicy", "ns", "cnp"))
	factory.add(client.CcnpGVR, customPolicy("cilium.io/v2", "CiliumClusterwideNetworkPolicy", "", "ccnp"))
	factory.add(client.AuthzGVR, customPolicy("security.istio.io/v1", "AuthorizationPolicy", "ns", "authz"))

	evaluator := &netPolGraphEvaluator{}
	model := NewNetPolGraph(evaluator)
	subject := netpol.SubjectRef{Kind: netpol.SubjectPod, Namespace: "ns", Name: "pod"}
	model.SetSubject(subject)

	if err := model.Refresh(netPolGraphContext(factory)); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}

	snapshot := evaluator.lastSnapshot()
	if len(snapshot.Pods) != 1 || len(snapshot.Namespaces) != 1 || len(snapshot.NetworkPolicies) != 1 ||
		len(snapshot.CiliumNetworkPolicies) != 1 || len(snapshot.CiliumClusterwideNetworkPolicies) != 1 ||
		len(snapshot.IstioAuthorizationPolicies) != 1 || len(snapshot.Deployments) != 1 ||
		len(snapshot.ReplicaSets) != 1 || len(snapshot.Jobs) != 1 {
		t.Fatalf("unexpected snapshot sizes: %+v", snapshot)
	}
	if snapshot.GeneratedAt.IsZero() {
		t.Fatal("snapshot generation time was not recorded")
	}
	if snapshot.CiliumNetworkPolicies[0].GetName() != "cnp" ||
		snapshot.CiliumClusterwideNetworkPolicies[0].GetName() != "ccnp" ||
		snapshot.IstioAuthorizationPolicies[0].GetAPIVersion() != "security.istio.io/v1" {
		t.Fatalf("custom policy objects were not preserved: %+v", snapshot)
	}
	if snapshot.IstioRootNamespace != netpol.DefaultIstioRootNamespace {
		t.Fatalf("expected default Istio root namespace, got %q", snapshot.IstioRootNamespace)
	}
	if evaluator.lastSubject() != subject {
		t.Fatalf("expected subject %+v, got %+v", subject, evaluator.lastSubject())
	}
	clusterScopedLists := 0
	for _, namespace := range factory.namespaces() {
		switch namespace {
		case client.BlankNamespace:
		case client.ClusterScope:
			clusterScopedLists++
		default:
			t.Fatalf("expected all-namespace or cluster-scoped list, got namespace %q", namespace)
		}
	}
	if clusterScopedLists != 1 {
		t.Fatalf("expected one cluster-scoped list, got %d", clusterScopedLists)
	}
}

func TestNetPolGraphPartialSnapshotReturnsResultAndError(t *testing.T) {
	factory := newNetPolGraphFactory()
	listErr := errors.New("networkpolicies forbidden")
	factory.errs[client.NpGVR.String()] = listErr
	evaluator := &netPolGraphEvaluator{}
	listener := newNetPolGraphListener()
	model := NewNetPolGraph(evaluator)
	model.SetSubject(netpol.SubjectRef{Kind: netpol.SubjectNamespace, Name: "ns"})
	model.AddListener(listener)

	err := model.Refresh(netPolGraphContext(factory))
	var incomplete *IncompleteSnapshotError
	if !errors.As(err, &incomplete) {
		t.Fatalf("expected incomplete snapshot error, got %v", err)
	}

	if !errors.Is(err, listErr) {
		t.Fatalf("expected wrapped list error, got %v", err)
	}
	if _, ok := incomplete.Incomplete["networkpolicies"]; !ok {
		t.Fatalf("missing NetworkPolicy failure: %#v", incomplete.Incomplete)
	}
	if evaluator.calls() != 1 {
		t.Fatalf("evaluator was called %d times", evaluator.calls())
	}
	if listener.changedCount() != 1 || listener.failedCount() != 1 {
		t.Fatalf("expected result and partial failure, got changed=%d failed=%d", listener.changedCount(), listener.failedCount())
	}
	if _, ok := model.LastRefresh().Incomplete["networkpolicies"]; !ok {
		t.Fatal("refresh metadata did not retain partial failure")
	}
}

func TestSelectOptionalResourcePrefersServedVersionAndFallsBack(t *testing.T) {
	discovery := &optionalPolicyDiscovery{
		resources: map[string][]metav1.APIResource{
			"security.istio.io/v1":      {{Name: "peerauthentications"}},
			"security.istio.io/v1beta1": {{Name: "authorizationpolicies"}},
		},
	}
	gvr, err := selectOptionalResource(discovery, []*client.GVR{client.AuthzGVR, client.AuthzV1BetaGVR})
	if err != nil {
		t.Fatalf("select optional resource: %v", err)
	}
	if gvr != client.AuthzV1BetaGVR {
		t.Fatalf("expected v1beta1 fallback, got %v", gvr)
	}

	discovery.resources["security.istio.io/v1"] = []metav1.APIResource{{Name: "authorizationpolicies"}}
	gvr, err = selectOptionalResource(discovery, []*client.GVR{client.AuthzGVR, client.AuthzV1BetaGVR})
	if err != nil {
		t.Fatalf("select preferred resource: %v", err)
	}
	if gvr != client.AuthzGVR {
		t.Fatalf("expected preferred v1 resource, got %v", gvr)
	}
}

func TestSelectOptionalResourceIgnoresMissingAPIGroups(t *testing.T) {
	discovery := &optionalPolicyDiscovery{
		resources: map[string][]metav1.APIResource{
			"security.istio.io/v1beta1": {{Name: "authorizationpolicies"}},
		},
		errs: map[string]error{
			"security.istio.io/v1": apierrors.NewNotFound(
				schema.GroupResource{Group: "security.istio.io", Resource: "v1"}, "",
			),
		},
	}
	gvr, err := selectOptionalResource(discovery, []*client.GVR{client.AuthzGVR, client.AuthzV1BetaGVR})
	if err != nil {
		t.Fatalf("missing API group should be ignored: %v", err)
	}
	if gvr != client.AuthzV1BetaGVR {
		t.Fatalf("expected v1beta1 fallback, got %v", gvr)
	}

	discovery.errs["security.istio.io/v1"] = errors.New("discovery unavailable")
	if _, err := selectOptionalResource(discovery, []*client.GVR{client.AuthzGVR}); err == nil {
		t.Fatal("expected non-absence discovery error")
	}
}

func TestLoadIstioRootNamespace(t *testing.T) {
	newSnapshot := func() netpol.Snapshot {
		return netpol.Snapshot{
			IstioAuthorizationPolicies: []unstructured.Unstructured{*customPolicy(
				"security.istio.io/v1", "AuthorizationPolicy", "payments", "authz",
			)},
			IstioRootNamespace: netpol.DefaultIstioRootNamespace,
			Incomplete:         map[string]error{},
		}
	}

	t.Run("resolved from revision config", func(t *testing.T) {
		factory := newNetPolGraphFactory()
		factory.add(client.CmGVR, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: "default"},
			Data:       map[string]string{"mesh": "rootNamespace: ignored"},
		})
		factory.add(client.CmGVR, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "istio-canary", Namespace: "istio-system"},
			Data:       map[string]string{"mesh": "rootNamespace: mesh-root\n"},
		})
		snapshot := newSnapshot()
		loadIstioRootNamespace(factory, &snapshot)
		if snapshot.IstioRootNamespace != "mesh-root" {
			t.Fatalf("expected resolved root namespace, got %q", snapshot.IstioRootNamespace)
		}
		if len(snapshot.Incomplete) != 0 {
			t.Fatalf("unexpected root namespace errors: %v", snapshot.Incomplete)
		}
	})

	t.Run("ambiguous revisions are partial", func(t *testing.T) {
		factory := newNetPolGraphFactory()
		for name, root := range map[string]string{"istio": "root-a", "istio-canary": "root-b"} {
			factory.add(client.CmGVR, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "istio-system"},
				Data:       map[string]string{"mesh": "rootNamespace: " + root},
			})
		}
		snapshot := newSnapshot()
		loadIstioRootNamespace(factory, &snapshot)
		if snapshot.IstioRootNamespace != netpol.DefaultIstioRootNamespace {
			t.Fatalf("ambiguous roots must retain the default, got %q", snapshot.IstioRootNamespace)
		}
		if err := snapshot.Incomplete["istio-mesh-config"]; err == nil ||
			!strings.Contains(err.Error(), "multiple Istio root namespaces") {
			t.Fatalf("expected ambiguity error, got %v", err)
		}
	})

	t.Run("list and parse failures are partial", func(t *testing.T) {
		factory := newNetPolGraphFactory()
		factory.errs[client.CmGVR.String()] = errors.New("configmaps forbidden")
		snapshot := newSnapshot()
		loadIstioRootNamespace(factory, &snapshot)
		if err := snapshot.Incomplete["istio-mesh-config"]; err == nil ||
			!errors.Is(err, factory.errs[client.CmGVR.String()]) {
			t.Fatalf("expected wrapped list error, got %v", err)
		}

		factory = newNetPolGraphFactory()
		factory.add(client.CmGVR, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "istio", Namespace: "istio-system"},
			Data:       map[string]string{"mesh": "rootNamespace: ["},
		})
		snapshot = newSnapshot()
		loadIstioRootNamespace(factory, &snapshot)
		if err := snapshot.Incomplete["istio-mesh-config"]; err == nil ||
			!strings.Contains(err.Error(), "parse ConfigMap") {
			t.Fatalf("expected parse error, got %v", err)
		}
	})
}

func TestLoadIstioRootNamespaceDefaultConfigurations(t *testing.T) {
	tests := []struct {
		name      string
		data      map[string]string
		otherRoot string
		wantRoot  string
		ambiguous bool
	}{
		{
			name: "missing mesh key is not a configuration", data: map[string]string{"other": "value"},
			otherRoot: "mesh-root", wantRoot: "mesh-root",
		},
		{
			name: "empty mesh document conflicts with a custom root", data: map[string]string{"mesh": ""},
			otherRoot: "mesh-root", wantRoot: netpol.DefaultIstioRootNamespace, ambiguous: true,
		},
		{
			name: "empty mapping conflicts with a custom root", data: map[string]string{"mesh": "{}"},
			otherRoot: "mesh-root", wantRoot: netpol.DefaultIstioRootNamespace, ambiguous: true,
		},
		{
			name: "omitted root conflicts with a custom root", data: map[string]string{"mesh": "enableTracing: true"},
			otherRoot: "mesh-root", wantRoot: netpol.DefaultIstioRootNamespace, ambiguous: true,
		},
		{
			name: "empty document uses default", data: map[string]string{"mesh": ""},
			wantRoot: netpol.DefaultIstioRootNamespace,
		},
		{
			name: "omitted root agrees with explicit default", data: map[string]string{"mesh": "enableTracing: true"},
			otherRoot: netpol.DefaultIstioRootNamespace, wantRoot: netpol.DefaultIstioRootNamespace,
		},
		{
			name: "matching custom roots are unambiguous", data: map[string]string{"mesh": "rootNamespace: mesh-root"},
			otherRoot: "mesh-root", wantRoot: "mesh-root",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			factory := newNetPolGraphFactory()
			factory.add(client.CmGVR, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "istio", Namespace: "istio-system"},
				Data:       test.data,
			})
			if test.otherRoot != "" {
				factory.add(client.CmGVR, &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "istio-canary", Namespace: "istio-system"},
					Data:       map[string]string{"mesh": "rootNamespace: " + test.otherRoot},
				})
			}
			snapshot := netpol.Snapshot{
				IstioAuthorizationPolicies: []unstructured.Unstructured{*customPolicy(
					"security.istio.io/v1", "AuthorizationPolicy", "payments", "authz",
				)},
				IstioRootNamespace: netpol.DefaultIstioRootNamespace,
				Incomplete:         map[string]error{},
			}
			loadIstioRootNamespace(factory, &snapshot)
			if snapshot.IstioRootNamespace != test.wantRoot {
				t.Errorf("root namespace = %q, want %q", snapshot.IstioRootNamespace, test.wantRoot)
			}
			err := snapshot.Incomplete["istio-mesh-config"]
			if test.ambiguous {
				want := "multiple Istio root namespaces discovered: istio-system, mesh-root"
				if err == nil || err.Error() != want {
					t.Errorf("mesh configuration error = %v, want %q", err, want)
				}
			} else if err != nil {
				t.Errorf("unexpected mesh configuration error: %v", err)
			}
		})
	}
}

func TestNetPolGraphResultNotesAreIsolated(t *testing.T) {
	for _, mutate := range []string{"evaluator", "peek", "listener"} {
		t.Run(mutate, func(t *testing.T) {
			subject := netpol.SubjectRef{Kind: netpol.SubjectPod, Namespace: "ns", Name: "pod"}
			newResult := func() netpol.SubjectResult {
				return netpol.SubjectResult{
					Subject: netpol.Subject{Ref: subject},
					Ingress: netpol.DirectionResult{Rules: []netpol.RuleResult{{Notes: []string{"ingress note"}}}},
					Egress:  netpol.DirectionResult{Rules: []netpol.RuleResult{{Notes: []string{"egress note"}}}},
				}
			}
			source, want := newResult(), newResult()
			model := NewNetPolGraph(&netPolGraphEvaluator{result: &source})
			model.SetSubject(subject)
			var first, second netpol.SubjectResult
			changeNotes := func(result netpol.SubjectResult) {
				result.Ingress.Rules[0].Notes[0] = "changed ingress"
				result.Egress.Rules[0].Notes[0] = "changed egress"
			}
			model.AddListener(&netPolGraphListener{resultHook: func(result netpol.SubjectResult) {
				first = result
				if mutate == "listener" {
					changeNotes(result)
				}
			}})
			model.AddListener(&netPolGraphListener{resultHook: func(result netpol.SubjectResult) {
				second = result
			}})
			if err := model.Refresh(netPolGraphContext(newNetPolGraphFactory())); err != nil {
				t.Fatalf("refresh failed: %v", err)
			}
			switch mutate {
			case "evaluator":
				changeNotes(source)
			case "peek":
				result, ok := model.Peek()
				if !ok {
					t.Fatal("missing result")
				}
				changeNotes(result)
			}
			got, ok := model.Peek()
			if !ok || !reflect.DeepEqual(got, want) {
				t.Errorf("mutating %s notes changed the stored result: %+v", mutate, got)
			}
			if !reflect.DeepEqual(second, want) {
				t.Errorf("mutating %s notes changed the second listener result: %+v", mutate, second)
			}
			if mutate != "listener" && !reflect.DeepEqual(first, want) {
				t.Errorf("mutating %s notes changed the first listener result: %+v", mutate, first)
			}
			if mutate != "evaluator" && !reflect.DeepEqual(source, want) {
				t.Errorf("mutating %s notes changed the evaluator result: %+v", mutate, source)
			}
		})
	}
}

func TestNetPolGraphRefreshOptionalResourceDiscovery(t *testing.T) {
	tests := []struct {
		name      string
		resources map[string][]metav1.APIResource
		wantGVRs  []*client.GVR
	}{
		{name: "optional API groups are absent"},
		{
			name:      "Cilium namespaced resource only",
			resources: map[string][]metav1.APIResource{"cilium.io/v2": {{Name: client.CnpGVR.R(), Namespaced: true}}},
			wantGVRs:  []*client.GVR{client.CnpGVR},
		},
		{
			name:      "Cilium clusterwide resource only",
			resources: map[string][]metav1.APIResource{"cilium.io/v2": {{Name: client.CcnpGVR.R()}}},
			wantGVRs:  []*client.GVR{client.CcnpGVR},
		},
		{
			name: "Istio v1 is preferred",
			resources: map[string][]metav1.APIResource{
				"security.istio.io/v1":      {{Name: client.AuthzGVR.R(), Namespaced: true}},
				"security.istio.io/v1beta1": {{Name: client.AuthzV1BetaGVR.R(), Namespaced: true}},
			},
			wantGVRs: []*client.GVR{client.AuthzGVR},
		},
		{
			name: "Istio v1 resource is absent",
			resources: map[string][]metav1.APIResource{
				"security.istio.io/v1":      {{Name: "peerauthentications", Namespaced: true}},
				"security.istio.io/v1beta1": {{Name: client.AuthzV1BetaGVR.R(), Namespaced: true}},
			},
			wantGVRs: []*client.GVR{client.AuthzV1BetaGVR},
		},
		{
			name: "Istio v1 API version is absent",
			resources: map[string][]metav1.APIResource{
				"security.istio.io/v1beta1": {{Name: client.AuthzV1BetaGVR.R(), Namespaced: true}},
			},
			wantGVRs: []*client.GVR{client.AuthzV1BetaGVR},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			factory := newNetPolGraphFactory()
			factory.connection = newNetPolGraphDiscovery(t, test.resources, nil)
			for _, gvr := range []*client.GVR{client.CnpGVR, client.CcnpGVR, client.AuthzGVR, client.AuthzV1BetaGVR} {
				namespace := "ns"
				if gvr == client.CcnpGVR {
					namespace = ""
				}
				factory.add(gvr, customPolicy(gvr.GV().String(), "Policy", namespace, "policy"))
			}
			evaluator := &netPolGraphEvaluator{}
			model := NewNetPolGraph(evaluator)
			model.SetSubject(netpol.SubjectRef{Kind: netpol.SubjectPod, Namespace: "ns", Name: "pod"})
			err := model.Refresh(netPolGraphContext(factory))
			require.NoError(t, err, "resource failures: %v", model.LastRefresh().Incomplete)
			snapshot := evaluator.lastSnapshot()
			require.Empty(t, snapshot.Incomplete)
			for _, gvr := range []*client.GVR{client.CnpGVR, client.CcnpGVR, client.AuthzGVR, client.AuthzV1BetaGVR} {
				var wantNS []string
				if slices.Contains(test.wantGVRs, gvr) {
					namespace := client.BlankNamespace
					if gvr == client.CcnpGVR {
						namespace = client.ClusterScope
					}
					wantNS = []string{namespace}
				}
				assert.Equal(t, wantNS, factory.listNamespaces(gvr), gvr.String())
			}
			assert.Len(t, snapshot.CiliumNetworkPolicies, len(factory.listNamespaces(client.CnpGVR)))
			assert.Len(t, snapshot.CiliumClusterwideNetworkPolicies, len(factory.listNamespaces(client.CcnpGVR)))
			authzGVR := client.AuthzGVR
			if slices.Contains(test.wantGVRs, client.AuthzV1BetaGVR) {
				authzGVR = client.AuthzV1BetaGVR
			}
			if slices.Contains(test.wantGVRs, authzGVR) {
				require.Len(t, snapshot.IstioAuthorizationPolicies, 1)
				assert.Equal(t, authzGVR.GV().String(), snapshot.IstioAuthorizationPolicies[0].GetAPIVersion())
				assert.Equal(t, []string{client.BlankNamespace}, factory.listNamespaces(client.CmGVR))
			} else {
				assert.Empty(t, snapshot.IstioAuthorizationPolicies)
				assert.Empty(t, factory.listNamespaces(client.CmGVR))
			}
		})
	}
}

func TestNetPolGraphSnapshotCustomPoliciesAreIsolated(t *testing.T) {
	factory := newNetPolGraphFactory()
	gvrs := []*client.GVR{client.CnpGVR, client.CcnpGVR, client.AuthzGVR}
	originals := make(map[string]runtime.Object)
	for _, gvr := range gvrs {
		policy := customPolicy(gvr.GV().String(), "Policy", "ns", "policy")
		policy.SetLabels(map[string]string{"app": "original"})
		policy.Object["spec"] = map[string]any{
			"selector": map[string]any{"matchLabels": map[string]any{"app": "original"}},
			"rules":    []any{map[string]any{"ports": []any{"8080"}}},
		}
		factory.add(gvr, policy)
		originals[gvr.String()] = factory.inventory[gvr.String()][0].DeepCopyObject()
	}
	evaluator := &netPolGraphEvaluator{}
	model := NewNetPolGraph(evaluator)
	model.SetSubject(netpol.SubjectRef{Kind: netpol.SubjectPod, Namespace: "ns", Name: "pod"})
	require.NoError(t, model.Refresh(netPolGraphContext(factory)))
	snapshot := evaluator.lastSnapshot()
	for index, policies := range [][]unstructured.Unstructured{
		snapshot.CiliumNetworkPolicies, snapshot.CiliumClusterwideNetworkPolicies, snapshot.IstioAuthorizationPolicies,
	} {
		require.Len(t, policies, 1)
		policy := &policies[0]
		require.NoError(t, unstructured.SetNestedField(policy.Object, "changed", "metadata", "labels", "app"))
		require.NoError(t, unstructured.SetNestedField(policy.Object, "changed", "spec", "selector", "matchLabels", "app"))
		spec := policy.Object["spec"].(map[string]any)
		spec["rules"].([]any)[0].(map[string]any)["ports"].([]any)[0] = "9090"
		assert.Equal(t, originals[gvrs[index].String()], factory.inventory[gvrs[index].String()][0],
			"snapshot mutations must not modify informer-owned policy objects")
	}
}

func TestNetPolGraphRefreshOptionalPolicyConversionFailures(t *testing.T) {
	for _, gvr := range []*client.GVR{client.CnpGVR, client.CcnpGVR, client.AuthzGVR} {
		t.Run(gvr.R(), func(t *testing.T) {
			factory := newNetPolGraphFactory()
			factory.inventory[gvr.String()] = []runtime.Object{&runtime.Unknown{Raw: []byte("{")}}
			factory.add(gvr, customPolicy(gvr.GV().String(), "Policy", "ns", "valid"))
			evaluator := &netPolGraphEvaluator{}
			model := NewNetPolGraph(evaluator)
			model.SetSubject(netpol.SubjectRef{Kind: netpol.SubjectPod, Namespace: "ns", Name: "pod"})
			var incomplete *IncompleteSnapshotError
			require.ErrorAs(t, model.Refresh(netPolGraphContext(factory)), &incomplete)
			require.Len(t, incomplete.Incomplete, 1)
			assert.ErrorContains(t, incomplete.Incomplete[gvr.R()], "item 0")
			snapshot := evaluator.lastSnapshot()
			var policies []unstructured.Unstructured
			switch gvr {
			case client.CnpGVR:
				policies = snapshot.CiliumNetworkPolicies
			case client.CcnpGVR:
				policies = snapshot.CiliumClusterwideNetworkPolicies
			default:
				policies = snapshot.IstioAuthorizationPolicies
			}
			require.Len(t, policies, 1, "a bad object must not discard the usable policies")
			assert.Equal(t, "valid", policies[0].GetName())
			_, ok := model.Peek()
			assert.True(t, ok)
		})
	}
}

func TestNetPolGraphRefreshOptionalResourceFailures(t *testing.T) {
	type failureCase struct {
		name              string
		connectionErr     error
		discoveryFailures map[string]error
		listGVR           *client.GVR
		listErr           error
		wantFailed        []string
	}
	forbidden := apierrors.NewForbidden(schema.GroupResource{Resource: "policies"}, "", errors.New("forbidden"))
	tests := []failureCase{
		{
			name: "cached discovery unavailable", connectionErr: errors.New("connection unavailable"),
			wantFailed: []string{client.CnpGVR.R(), client.CcnpGVR.R(), client.AuthzGVR.R()},
		},
		{
			name: "Cilium discovery forbidden", discoveryFailures: map[string]error{"cilium.io/v2": forbidden},
			wantFailed: []string{client.CnpGVR.R(), client.CcnpGVR.R()},
		},
		{
			name:              "Istio discovery forbidden does not downgrade",
			discoveryFailures: map[string]error{"security.istio.io/v1": forbidden},
			wantFailed:        []string{client.AuthzGVR.R()},
		},
		{
			name:              "Istio discovery unavailable does not downgrade",
			discoveryFailures: map[string]error{"security.istio.io/v1": apierrors.NewServiceUnavailable("unavailable")},
			wantFailed:        []string{client.AuthzGVR.R()},
		},
	}
	for _, gvr := range []*client.GVR{client.CnpGVR, client.CcnpGVR, client.AuthzGVR, client.AuthzV1BetaGVR} {
		for reason, err := range map[string]error{
			"forbidden": forbidden,
			"not found after successful discovery": apierrors.NewNotFound(schema.GroupResource{
				Group: gvr.G(), Resource: gvr.R(),
			}, ""),
		} {
			tests = append(tests, failureCase{
				name: gvr.String() + " list " + reason, listGVR: gvr, listErr: err,
				wantFailed: []string{gvr.R()},
			})
		}
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resources := map[string][]metav1.APIResource{
				"cilium.io/v2":              {{Name: client.CnpGVR.R(), Namespaced: true}, {Name: client.CcnpGVR.R()}},
				"security.istio.io/v1":      {{Name: client.AuthzGVR.R(), Namespaced: true}},
				"security.istio.io/v1beta1": {{Name: client.AuthzV1BetaGVR.R(), Namespaced: true}},
			}
			if test.listGVR == client.AuthzV1BetaGVR {
				resources["security.istio.io/v1"] = []metav1.APIResource{{Name: "peerauthentications"}}
			}
			factory := newNetPolGraphFactory()
			if test.connectionErr != nil {
				factory.connection = &netPolGraphConnection{err: test.connectionErr}
			} else {
				factory.connection = newNetPolGraphDiscovery(t, resources, test.discoveryFailures)
			}
			for _, gvr := range []*client.GVR{client.CnpGVR, client.CcnpGVR, client.AuthzGVR, client.AuthzV1BetaGVR} {
				factory.add(gvr, customPolicy(gvr.GV().String(), "Policy", "ns", "policy"))
			}
			if test.listGVR != nil {
				factory.errs[test.listGVR.String()] = test.listErr
			}
			evaluator := &netPolGraphEvaluator{}
			model := NewNetPolGraph(evaluator)
			model.SetSubject(netpol.SubjectRef{Kind: netpol.SubjectPod, Namespace: "ns", Name: "pod"})
			listener := newNetPolGraphListener()
			model.AddListener(listener)
			err := model.Refresh(netPolGraphContext(factory))
			var incomplete *IncompleteSnapshotError
			require.ErrorAs(t, err, &incomplete)
			var failed []string
			for resource := range incomplete.Incomplete {
				failed = append(failed, resource)
			}
			assert.ElementsMatch(t, test.wantFailed, failed)
			assert.Equal(t, incomplete.Incomplete, model.LastRefresh().Incomplete)
			assert.Equal(t, incomplete.Incomplete, evaluator.lastSnapshot().Incomplete)
			if test.connectionErr != nil {
				assert.ErrorIs(t, err, test.connectionErr)
			}
			if test.listErr != nil {
				assert.ErrorIs(t, err, test.listErr)
			}
			for gv, failure := range test.discoveryFailures {
				resource := client.AuthzGVR.R()
				if gv == "cilium.io/v2" {
					resource = client.CnpGVR.R()
				}
				if apierrors.IsForbidden(failure) {
					assert.True(t, apierrors.IsForbidden(incomplete.Incomplete[resource]))
				} else {
					assert.True(t, apierrors.IsServiceUnavailable(incomplete.Incomplete[resource]))
				}
			}
			assert.Equal(t, 1, listener.changedCount())
			assert.Equal(t, 1, listener.failedCount())
			_, ok := model.Peek()
			assert.True(t, ok, "partial snapshots still publish a result")
			snapshot := evaluator.lastSnapshot()
			for resource, count := range map[string]int{
				client.CnpGVR.R():   len(snapshot.CiliumNetworkPolicies),
				client.CcnpGVR.R():  len(snapshot.CiliumClusterwideNetworkPolicies),
				client.AuthzGVR.R(): len(snapshot.IstioAuthorizationPolicies),
			} {
				want := 1
				if slices.Contains(test.wantFailed, resource) {
					want = 0
				}
				assert.Equal(t, want, count, resource)
			}
			if test.discoveryFailures["security.istio.io/v1"] != nil {
				assert.Empty(t, factory.listNamespaces(client.AuthzGVR))
				assert.Empty(t, factory.listNamespaces(client.AuthzV1BetaGVR))
			}
		})
	}
}

func TestNetPolGraphRefreshIstioVersionProvenance(t *testing.T) {
	for _, gvr := range []*client.GVR{client.AuthzGVR, client.AuthzV1BetaGVR} {
		t.Run(gvr.GV().String(), func(t *testing.T) {
			factory := newNetPolGraphFactory()
			factory.connection = newNetPolGraphDiscovery(t, map[string][]metav1.APIResource{
				gvr.GV().String(): {{Name: gvr.R(), Namespaced: true}},
			}, nil)
			factory.add(client.PodGVR, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns"}})
			factory.add(client.NsGVR, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns"}})
			policy := customPolicy(gvr.GV().String(), "AuthorizationPolicy", "ns", "authorize")
			policy.Object["spec"] = map[string]any{
				"action": "ALLOW",
				"rules": []any{map[string]any{
					"to": []any{map[string]any{"operation": map[string]any{"ports": []any{"8080"}}}},
				}},
			}
			factory.add(gvr, policy)
			model := NewNetPolGraph(netpol.NewEvaluator())
			model.SetSubject(netpol.SubjectRef{Kind: netpol.SubjectPod, Namespace: "ns", Name: "pod"})
			require.NoError(t, model.Refresh(netPolGraphContext(factory)))
			result, ok := model.Peek()
			require.True(t, ok)
			var found bool
			for _, rule := range result.Ingress.Rules {
				if rule.ID.PolicyName == "authorize" {
					found = true
					assert.Equal(t, netpol.PolicyTypeIstioAuthorizationPolicy, rule.ID.SourceType())
					assert.Equal(t, gvr.GV().String(), rule.ID.PolicyVersion)
					assert.Equal(t, netpol.Ingress, rule.ID.Direction)
				}
			}
			assert.True(t, found, "the served policy version must reach the graph result")
			for _, rule := range result.Egress.Rules {
				assert.NotEqual(t, netpol.PolicyTypeIstioAuthorizationPolicy, rule.ID.SourceType(),
					"destination authorization must not create a source-local egress rule")
			}
		})
	}
}

func TestNetPolGraphNestedResultCopiesAreIsolated(t *testing.T) {
	subject := netpol.SubjectRef{Kind: netpol.SubjectPod, Namespace: "ns", Name: "pod"}
	permissions := func() []netpol.PortPermission {
		port, end := intstr.FromInt32(8080), int32(8090)
		return []netpol.PortPermission{{Protocol: corev1.ProtocolTCP, Port: &port, EndPort: &end}}
	}
	evidence := func(direction netpol.Direction) []netpol.PolicyEvidence {
		return []netpol.PolicyEvidence{{
			RuleID:      netpol.RuleID{PolicyType: netpol.PolicyTypeCiliumNetworkPolicy, PolicyVersion: "cilium.io/v2", Direction: direction},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress, netv1.PolicyTypeEgress}, Ports: permissions(),
		}}
	}
	direction := func(d netpol.Direction) netpol.DirectionResult {
		return netpol.DirectionResult{
			Rules: []netpol.RuleResult{{
				ID:    netpol.RuleID{PolicyName: "policy", PolicyType: netpol.PolicyTypeCiliumNetworkPolicy, Direction: d},
				Peers: []string{"peer"}, Permissions: permissions(), Evidence: evidence(d),
				Notes: []string{"note"}, Warnings: []string{"warning"},
			}},
			Primitives: map[netpol.PrimitiveKind][]netpol.PrimitiveResult{
				netpol.PrimitiveCIDR: {{
					Ref:         netpol.PrimitiveRef{Kind: netpol.PrimitiveCIDR, CIDR: "10.0.0.0/8", CIDRExcept: []string{"10.1.0.0/16"}},
					Permissions: permissions(), Evidence: evidence(d), Warnings: []string{"primitive warning"},
					PairDecisions: []netpol.PairDecision{{Decision: netpol.Decision{
						Permissions: permissions(), Evidence: evidence(d), Warnings: []string{"pair warning"},
					}}},
				}},
			},
		}
	}
	newResult := func() netpol.SubjectResult {
		return netpol.SubjectResult{
			Subject: netpol.Subject{Ref: subject, Pods: []netpol.PodRef{{Name: "pod"}}},
			Ingress: direction(netpol.Ingress), Egress: direction(netpol.Egress), Warnings: []string{"result warning"},
		}
	}
	mutatePermissions := func(items []netpol.PortPermission) {
		*items[0].Port = intstr.FromInt32(9090)
		*items[0].EndPort = 9099
		items[0].Protocol = corev1.ProtocolUDP
	}
	mutateEvidence := func(items []netpol.PolicyEvidence) {
		items[0].RuleID.PolicyVersion = "changed"
		items[0].PolicyTypes[0] = netv1.PolicyTypeEgress
		mutatePermissions(items[0].Ports)
	}
	mutate := func(result netpol.SubjectResult) {
		result.Subject.Pods[0].Name = "changed"
		result.Warnings[0] = "changed"
		for _, direction := range []netpol.DirectionResult{result.Ingress, result.Egress} {
			rule := &direction.Rules[0]
			rule.ID.PolicyName, rule.Peers[0], rule.Notes[0], rule.Warnings[0] = "changed", "changed", "changed", "changed"
			mutatePermissions(rule.Permissions)
			mutateEvidence(rule.Evidence)
			primitive := &direction.Primitives[netpol.PrimitiveCIDR][0]
			primitive.Ref.CIDRExcept[0], primitive.Warnings[0] = "changed", "changed"
			mutatePermissions(primitive.Permissions)
			mutateEvidence(primitive.Evidence)
			pair := &primitive.PairDecisions[0]
			pair.Source.Name, pair.Decision.Warnings[0] = "changed", "changed"
			mutatePermissions(pair.Decision.Permissions)
			mutateEvidence(pair.Decision.Evidence)
			delete(direction.Primitives, netpol.PrimitiveCIDR)
		}
	}
	source, want := newResult(), newResult()
	model := NewNetPolGraph(&netPolGraphEvaluator{result: &source})
	model.SetSubject(subject)
	model.AddListener(&netPolGraphListener{resultHook: mutate})
	var delivered netpol.SubjectResult
	model.AddListener(&netPolGraphListener{resultHook: func(result netpol.SubjectResult) { delivered = result }})
	require.NoError(t, model.Refresh(netPolGraphContext(newNetPolGraphFactory())))
	assert.Equal(t, want, source, "listener mutations must not reach the evaluator")
	assert.Equal(t, want, delivered, "listener deliveries must be independent")
	peeked, ok := model.Peek()
	require.True(t, ok)
	assert.Equal(t, want, peeked)
	mutate(peeked)
	mutate(source)
	got, ok := model.Peek()
	require.True(t, ok)
	assert.Equal(t, want, got, "Peek and evaluator mutations must not reach stored results")
	assert.Equal(t, want, delivered, "previous listener deliveries must stay isolated")
}

func TestNetPolGraphRefreshMeshConfigFailuresRemainPartial(t *testing.T) {
	configMap := func(name, mesh string) runtime.Object {
		return &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "istio-system"},
			Data:       map[string]string{"mesh": mesh},
		}
	}
	for _, test := range []struct {
		name    string
		objects []runtime.Object
		listErr error
		want    string
		root    string
	}{
		{name: "forbidden", listErr: errors.New("configmaps forbidden"), want: "list Istio mesh config", root: netpol.DefaultIstioRootNamespace},
		{
			name: "parse error with usable revision", objects: []runtime.Object{
				configMap("istio", "rootNamespace: ["), configMap("istio-canary", "rootNamespace: mesh-root"),
			},
			want: "parse ConfigMap istio-system/istio", root: "mesh-root",
		},
		{
			name: "conflicting default revision", objects: []runtime.Object{
				configMap("istio", ""), configMap("istio-canary", "rootNamespace: mesh-root"),
			},
			want: "multiple Istio root namespaces discovered: istio-system, mesh-root", root: netpol.DefaultIstioRootNamespace,
		},
		{
			name: "conversion error with usable revision", objects: []runtime.Object{
				&unstructured.Unstructured{Object: map[string]any{
					"apiVersion": "v1", "kind": "ConfigMap", "data": []any{"invalid"},
				}},
				configMap("istio-canary", "rootNamespace: mesh-root"),
			},
			want: "item 0", root: "mesh-root",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			factory := newNetPolGraphFactory()
			factory.add(client.AuthzGVR, customPolicy("security.istio.io/v1", "AuthorizationPolicy", "ns", "authorize"))
			for _, object := range test.objects {
				factory.add(client.CmGVR, object)
			}
			factory.errs[client.CmGVR.String()] = test.listErr
			evaluator := &netPolGraphEvaluator{}
			model := NewNetPolGraph(evaluator)
			model.SetSubject(netpol.SubjectRef{Kind: netpol.SubjectPod, Namespace: "ns", Name: "pod"})
			listener := newNetPolGraphListener()
			model.AddListener(listener)
			err := model.Refresh(netPolGraphContext(factory))
			var incomplete *IncompleteSnapshotError
			require.ErrorAs(t, err, &incomplete)
			require.Len(t, incomplete.Incomplete, 1)
			require.ErrorContains(t, incomplete.Incomplete["istio-mesh-config"], test.want)
			if test.listErr != nil {
				assert.ErrorIs(t, err, test.listErr)
			}
			snapshot := evaluator.lastSnapshot()
			assert.Equal(t, test.root, snapshot.IstioRootNamespace)
			assert.Len(t, snapshot.IstioAuthorizationPolicies, 1)
			assert.Equal(t, 1, listener.changedCount())
			assert.Equal(t, 1, listener.failedCount())
			metadata := model.LastRefresh()
			delete(metadata.Incomplete, "istio-mesh-config")
			delete(incomplete.Incomplete, "istio-mesh-config")
			assert.Contains(t, model.LastRefresh().Incomplete, "istio-mesh-config")
			assert.Contains(t, snapshot.Incomplete, "istio-mesh-config")
		})
	}
}

func TestNetPolGraphRefreshOptionalPolicyFailuresReachResults(t *testing.T) {
	for _, gvr := range []*client.GVR{client.CnpGVR, client.CcnpGVR, client.AuthzGVR} {
		t.Run(gvr.R(), func(t *testing.T) {
			factory := newNetPolGraphFactory()
			for _, name := range []string{"subject", "peer"} {
				factory.add(client.PodGVR, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"}})
			}
			factory.add(client.NsGVR, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns"}})
			failure := apierrors.NewForbidden(schema.GroupResource{Group: gvr.G(), Resource: gvr.R()}, "", errors.New("forbidden"))
			factory.errs[gvr.String()] = failure
			model := NewNetPolGraph(netpol.NewEvaluator())
			model.SetSubject(netpol.SubjectRef{Kind: netpol.SubjectPod, Namespace: "ns", Name: "subject"})
			require.ErrorIs(t, model.Refresh(netPolGraphContext(factory)), failure)
			result, ok := model.Peek()
			require.True(t, ok)
			assert.Contains(t, strings.Join(result.Warnings, "\n"), gvr.R())
			for _, direction := range []netpol.Direction{netpol.Ingress, netpol.Egress} {
				var found bool
				for _, primitive := range result.Direction(direction).Primitives[netpol.PrimitivePod] {
					if primitive.Ref.Name == "peer" {
						found = true
						assert.Equal(t, netpol.AccessPartialData, primitive.State, direction.String())
					}
				}
				assert.True(t, found, direction.String())
			}
		})
	}
}

func TestNetPolGraphRefreshCancellationKeepsAcceptedResult(t *testing.T) {
	for _, phase := range []string{"before snapshot", "optional list", "evaluation"} {
		t.Run(phase, func(t *testing.T) {
			factory := newNetPolGraphFactory()
			evaluator := &netPolGraphEvaluator{}
			model := NewNetPolGraph(evaluator)
			model.SetSubject(netpol.SubjectRef{Kind: netpol.SubjectPod, Namespace: "ns", Name: "pod"})
			listener := newNetPolGraphListener()
			model.AddListener(listener)
			require.NoError(t, model.Refresh(netPolGraphContext(factory)))
			previous, ok := model.Peek()
			require.True(t, ok)
			metadata := model.LastRefresh()
			ctx, cancel := context.WithCancel(netPolGraphContext(factory))
			defer cancel()
			switch phase {
			case "before snapshot":
				cancel()
			case "optional list":
				factory.listHook = func(gvr *client.GVR) {
					if gvr == client.CnpGVR {
						cancel()
					}
				}
			case "evaluation":
				evaluator.started, evaluator.release = make(chan struct{}), make(chan struct{})
			}
			done := make(chan error, 1)
			go func() { done <- model.Refresh(ctx) }()
			if phase == "evaluation" {
				<-evaluator.started
				cancel()
				close(evaluator.release)
			}
			require.ErrorIs(t, <-done, context.Canceled)
			got, ok := model.Peek()
			require.True(t, ok)
			assert.Equal(t, previous, got)
			assert.Equal(t, metadata, model.LastRefresh())
			assert.Equal(t, 1, listener.changedCount())
			assert.Zero(t, listener.failedCount())
			if phase != "evaluation" {
				assert.Equal(t, 1, evaluator.calls(), "a canceled snapshot must not be evaluated")
			}
		})
	}
}

func TestNetPolGraphRejectsStaleGeneration(t *testing.T) {
	factory := newNetPolGraphFactory()
	started, release := make(chan struct{}), make(chan struct{})
	evaluator := &netPolGraphEvaluator{started: started, release: release}
	listener := newNetPolGraphListener()
	model := NewNetPolGraph(evaluator)
	model.SetSubject(netpol.SubjectRef{Kind: netpol.SubjectPod, Namespace: "ns", Name: "old"})
	model.AddListener(listener)

	done := make(chan error, 1)
	go func() { done <- model.Refresh(netPolGraphContext(factory)) }()
	<-started
	model.SetSubject(netpol.SubjectRef{Kind: netpol.SubjectPod, Namespace: "ns", Name: "new"})
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	if listener.changedCount() != 0 {
		t.Fatal("stale result was delivered")
	}
	if _, ok := model.Peek(); ok {
		t.Fatal("stale result was retained")
	}
}

func TestNetPolGraphDoesNotPublishPartialErrorAfterSubjectChange(t *testing.T) {
	factory := newNetPolGraphFactory()
	factory.errs[client.NpGVR.String()] = errors.New("networkpolicies forbidden")
	model := NewNetPolGraph(&netPolGraphEvaluator{})
	oldSubject := netpol.SubjectRef{Kind: netpol.SubjectPod, Namespace: "ns", Name: "old"}
	newSubject := netpol.SubjectRef{Kind: netpol.SubjectPod, Namespace: "ns", Name: "new"}
	listener := newNetPolGraphListener()
	staleListener := newNetPolGraphListener()
	listener.changedHook = func() { model.SetSubject(newSubject) }
	model.SetSubject(oldSubject)
	model.AddListener(listener)
	model.AddListener(staleListener)

	if err := model.Refresh(netPolGraphContext(factory)); err != nil {
		t.Fatalf("stale partial snapshot error was returned after the subject changed: %v", err)
	}
	if listener.changedCount() != 1 {
		t.Fatalf("expected accepted old-subject result, got %d changes", listener.changedCount())
	}
	if listener.failedCount() != 0 {
		t.Fatal("stale partial-data error was delivered after the listener changed the subject")
	}
	if staleListener.changedCount() != 0 || staleListener.failedCount() != 0 {
		t.Fatal("result or partial-data error was delivered to a later listener after the subject changed")
	}
	if model.Subject() != newSubject {
		t.Fatalf("expected subject %+v, got %+v", newSubject, model.Subject())
	}
}

func TestNetPolGraphWatchRefreshesAndCancels(t *testing.T) {
	factory := newNetPolGraphFactory()
	evaluator := &netPolGraphEvaluator{}
	model := NewNetPolGraph(evaluator)
	model.SetSubject(netpol.SubjectRef{Kind: netpol.SubjectPod, Namespace: "ns", Name: "pod"})
	model.SetDebounce(5 * time.Millisecond)
	model.SetRefreshRate(10 * time.Millisecond)

	ctx, cancel := context.WithCancel(netPolGraphContext(factory))
	if err := model.Watch(ctx); err != nil {
		t.Fatalf("watch failed: %v", err)
	}
	deadline := time.After(500 * time.Millisecond)
	for evaluator.calls() < 2 {
		select {
		case <-deadline:
			t.Fatalf("expected periodic refresh, got %d evaluation(s)", evaluator.calls())
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	time.Sleep(20 * time.Millisecond)
	count := evaluator.calls()
	time.Sleep(30 * time.Millisecond)
	if evaluator.calls() != count {
		t.Fatalf("evaluation continued after cancellation: %d -> %d", count, evaluator.calls())
	}
}

func TestNetPolGraphWatchReplacesPriorUpdaterAndRestartsAfterStop(t *testing.T) {
	factory := newNetPolGraphFactory()
	evaluator := &netPolGraphEvaluator{}
	model := NewNetPolGraph(evaluator)
	model.SetSubject(netpol.SubjectRef{Kind: netpol.SubjectPod, Namespace: "ns", Name: "one"})
	model.SetDebounce(0)
	model.SetRefreshRate(time.Hour)

	firstCtx, cancelFirst := context.WithCancel(netPolGraphContext(factory))
	defer cancelFirst()
	if err := model.Watch(firstCtx); err != nil {
		t.Fatalf("first watch failed: %v", err)
	}
	secondCtx, cancelSecond := context.WithCancel(netPolGraphContext(factory))
	defer cancelSecond()
	if err := model.Watch(secondCtx); err != nil {
		t.Fatalf("replacement watch failed: %v", err)
	}

	model.SetSubject(netpol.SubjectRef{Kind: netpol.SubjectPod, Namespace: "ns", Name: "two"})
	waitForNetPolGraphCalls(t, evaluator, 3)
	time.Sleep(20 * time.Millisecond)
	if calls := evaluator.calls(); calls != 3 {
		t.Fatalf("replacement left duplicate updaters running: got %d evaluations, want 3", calls)
	}

	model.Stop()
	model.Stop()
	model.SetSubject(netpol.SubjectRef{Kind: netpol.SubjectPod, Namespace: "ns", Name: "stopped"})
	time.Sleep(20 * time.Millisecond)
	if calls := evaluator.calls(); calls != 3 {
		t.Fatalf("stopped model refreshed unexpectedly: got %d evaluations", calls)
	}

	if err := model.Watch(netPolGraphContext(factory)); err != nil {
		t.Fatalf("restart watch failed: %v", err)
	}
	if calls := evaluator.calls(); calls != 4 {
		t.Fatalf("restart did not perform exactly one initial refresh: got %d evaluations", calls)
	}
	model.Stop()
}

func TestNetPolGraphConcurrentLifecycle(_ *testing.T) {
	factory := newNetPolGraphFactory()
	model := NewNetPolGraph(&netPolGraphEvaluator{})
	model.SetDebounce(0)
	model.SetRefreshRate(time.Hour)

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(3)
		go func(i int) {
			defer wg.Done()
			model.SetSubject(netpol.SubjectRef{Kind: netpol.SubjectPod, Namespace: "ns", Name: string(rune('a' + i))})
		}(i)
		go func() {
			defer wg.Done()
			_ = model.Watch(netPolGraphContext(factory))
		}()
		go func() {
			defer wg.Done()
			model.Stop()
		}()
	}
	wg.Wait()
	model.Stop()
}

func waitForNetPolGraphCalls(t *testing.T, evaluator *netPolGraphEvaluator, want int) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if evaluator.calls() >= want {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("timed out waiting for %d evaluations; got %d", want, evaluator.calls())
		case <-ticker.C:
		}
	}
}

type netPolGraphFactory struct {
	mu         sync.Mutex
	inventory  map[string][]runtime.Object
	errs       map[string]error
	listNS     []string
	listGVRs   []string
	getPaths   []string
	connection client.Connection
	listHook   func(*client.GVR)
}

type netPolGraphConnection struct {
	client.Connection
	discovery *disk.CachedDiscoveryClient
	err       error
}

func (c *netPolGraphConnection) CachedDiscovery() (*disk.CachedDiscoveryClient, error) {
	return c.discovery, c.err
}

func newNetPolGraphDiscovery(t *testing.T, resources map[string][]metav1.APIResource, failures map[string]error) client.Connection {
	t.Helper()
	groupVersions := sets.New[string]()
	for gv := range resources {
		groupVersions.Insert(gv)
	}
	for gv := range failures {
		groupVersions.Insert(gv)
	}
	groups := make(map[string]*metav1.APIGroup)
	for _, gv := range sets.List(groupVersions) {
		group, version, _ := strings.Cut(gv, "/")
		if groups[group] == nil {
			groups[group] = &metav1.APIGroup{Name: group}
		}
		groups[group].Versions = append(groups[group].Versions, metav1.GroupVersionForDiscovery{
			GroupVersion: gv, Version: version,
		})
	}
	groupList := metav1.APIGroupList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIGroupList"}}
	for _, group := range groups {
		groupList.Groups = append(groupList.Groups, *group)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var response any
		switch r.URL.Path {
		case "/api":
			response = metav1.APIVersions{
				TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIVersions"},
				Versions: []string{"v1"},
			}
		case "/apis":
			response = groupList
		case "/api/v1":
			response = metav1.APIResourceList{
				TypeMeta:     metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"},
				GroupVersion: "v1", APIResources: []metav1.APIResource{{Name: "pods", Namespaced: true}},
			}
		default:
			gv := strings.TrimPrefix(r.URL.Path, "/apis/")
			if err := failures[gv]; err != nil {
				status := err.(apierrors.APIStatus).Status()
				status.TypeMeta = metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}
				w.WriteHeader(int(status.Code))
				response = status
			} else {
				response = metav1.APIResourceList{
					TypeMeta:     metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"},
					GroupVersion: gv, APIResources: resources[gv],
				}
			}
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("encode discovery response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	discovery, err := disk.NewCachedDiscoveryClientForConfig(
		&rest.Config{Host: server.URL}, t.TempDir(), "", time.Hour,
	)
	require.NoError(t, err)
	return &netPolGraphConnection{discovery: discovery}
}

type optionalPolicyDiscovery struct {
	resources map[string][]metav1.APIResource
	errs      map[string]error
}

func (d *optionalPolicyDiscovery) ServerResourcesForGroupVersion(groupVersion string) (*metav1.APIResourceList, error) {
	if err := d.errs[groupVersion]; err != nil {
		return nil, err
	}
	return &metav1.APIResourceList{
		GroupVersion: groupVersion,
		APIResources: d.resources[groupVersion],
	}, nil
}

func newNetPolGraphFactory() *netPolGraphFactory {
	return &netPolGraphFactory{
		inventory: make(map[string][]runtime.Object),
		errs:      make(map[string]error),
	}
}

func customPolicy(apiVersion, kind, namespace, name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
		},
		"spec": map[string]any{},
	}}
}

func (f *netPolGraphFactory) add(gvr *client.GVR, object runtime.Object) {
	raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(object)
	if err != nil {
		panic(err)
	}
	f.inventory[gvr.String()] = append(f.inventory[gvr.String()], &unstructured.Unstructured{Object: raw})
}

func (f *netPolGraphFactory) Client() client.Connection { return f.connection }
func (f *netPolGraphFactory) Get(gvr *client.GVR, path string, _ bool, _ labels.Selector) (runtime.Object, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getPaths = append(f.getPaths, path)
	objects := f.inventory[gvr.String()]
	if len(objects) == 0 {
		return nil, errors.New("not found")
	}
	return objects[0], nil
}
func (f *netPolGraphFactory) List(gvr *client.GVR, namespace string, _ bool, _ labels.Selector) ([]runtime.Object, error) {
	f.mu.Lock()
	f.listNS = append(f.listNS, namespace)
	f.listGVRs = append(f.listGVRs, gvr.String())
	objects, err, hook := f.inventory[gvr.String()], f.errs[gvr.String()], f.listHook
	f.mu.Unlock()
	if hook != nil {
		hook(gvr)
	}
	return objects, err
}
func (*netPolGraphFactory) ForResource(string, *client.GVR) (informers.GenericInformer, error) {
	return nil, nil
}
func (*netPolGraphFactory) CanForResource(string, *client.GVR, []string) (informers.GenericInformer, error) {
	return nil, nil
}
func (*netPolGraphFactory) WaitForCacheSync()            {}
func (*netPolGraphFactory) DeleteForwarder(string)       {}
func (*netPolGraphFactory) Forwarders() watch.Forwarders { return nil }
func (f *netPolGraphFactory) namespaces() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.listNS...)
}
func (f *netPolGraphFactory) listNamespaces(gvr *client.GVR) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var namespaces []string
	for index, resource := range f.listGVRs {
		if resource == gvr.String() {
			namespaces = append(namespaces, f.listNS[index])
		}
	}
	return namespaces
}
func (f *netPolGraphFactory) lastGetPath() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.getPaths) == 0 {
		return ""
	}
	return f.getPaths[len(f.getPaths)-1]
}

var _ dao.Factory = (*netPolGraphFactory)(nil)

type netPolGraphEvaluator struct {
	mu       sync.Mutex
	count    int
	subject  netpol.SubjectRef
	snapshot netpol.Snapshot
	started  chan struct{}
	release  chan struct{}
	result   *netpol.SubjectResult
}

//nolint:gocritic // Snapshot is required by the Evaluator interface.
func (e *netPolGraphEvaluator) EvaluateSubject(subject netpol.SubjectRef, snapshot netpol.Snapshot, _ netpol.Options) (netpol.SubjectResult, error) {
	e.mu.Lock()
	e.count++
	e.subject, e.snapshot = subject, snapshot
	started, release, result := e.started, e.release, e.result
	e.mu.Unlock()
	if started != nil {
		close(started)
	}
	if release != nil {
		<-release
	}
	if result != nil {
		return *result, nil
	}
	return netpol.SubjectResult{Subject: netpol.Subject{Ref: subject}, GeneratedAt: snapshot.GeneratedAt}, nil
}
func (*netPolGraphEvaluator) Rules(netpol.SubjectResult, netpol.Direction) []netpol.RuleResult {
	return nil
}
func (*netPolGraphEvaluator) Primitives(netpol.SubjectResult, netpol.Direction, sets.Set[netpol.PrimitiveKind]) []netpol.PrimitiveResult {
	return nil
}
func (*netPolGraphEvaluator) DirectionApplicability(netpol.SubjectResult, netpol.Direction, sets.Set[netpol.PrimitiveKind]) []netpol.ApplicabilityRow {
	return nil
}
func (*netPolGraphEvaluator) RuleApplicability(netpol.SubjectResult, netpol.Direction, netpol.RuleID, sets.Set[netpol.PrimitiveKind]) []netpol.ApplicabilityRow {
	return nil
}
func (e *netPolGraphEvaluator) calls() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.count
}
func (e *netPolGraphEvaluator) lastSnapshot() netpol.Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.snapshot
}
func (e *netPolGraphEvaluator) lastSubject() netpol.SubjectRef {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.subject
}

type netPolGraphListener struct {
	mu          sync.Mutex
	changed     int
	failed      int
	changedHook func()
	resultHook  func(netpol.SubjectResult)
}

func newNetPolGraphListener() *netPolGraphListener { return &netPolGraphListener{} }
func (l *netPolGraphListener) NetPolGraphChanged(result netpol.SubjectResult) {
	l.mu.Lock()
	l.changed++
	hook, resultHook := l.changedHook, l.resultHook
	l.mu.Unlock()
	if hook != nil {
		hook()
	}
	if resultHook != nil {
		resultHook(result)
	}
}
func (l *netPolGraphListener) NetPolGraphFailed(error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failed++
}
func (l *netPolGraphListener) changedCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.changed
}
func (l *netPolGraphListener) failedCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.failed
}

func netPolGraphContext(factory dao.Factory) context.Context {
	return context.WithValue(context.Background(), internal.KeyFactory, factory)
}

func TestNetPolGraphFetchesSelectedSubjectWhenClusterListFails(t *testing.T) {
	tests := []struct {
		name     string
		subject  netpol.SubjectRef
		resource string
		gvr      *client.GVR
		object   runtime.Object
		assert   func(*testing.T, netpol.Snapshot)
	}{
		{
			name: "pod", subject: netpol.SubjectRef{Kind: netpol.SubjectPod, Namespace: "ns", Name: "pod"},
			resource: "pods", gvr: client.PodGVR,
			object: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod"}},
			assert: func(t *testing.T, snapshot netpol.Snapshot) {
				if len(snapshot.Pods) != 1 {
					t.Fatalf("missing selected pod")
				}
			},
		},
		{
			name: "deployment", subject: netpol.SubjectRef{Kind: netpol.SubjectDeployment, Namespace: "ns", Name: "deployment"},
			resource: "deployments", gvr: client.DpGVR,
			object: &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "deployment"}},
			assert: func(t *testing.T, snapshot netpol.Snapshot) {
				if len(snapshot.Deployments) != 1 {
					t.Fatalf("missing selected deployment")
				}
			},
		},
		{
			name: "job", subject: netpol.SubjectRef{Kind: netpol.SubjectJob, Namespace: "ns", Name: "job"},
			resource: "jobs", gvr: client.JobGVR,
			object: &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "job"}},
			assert: func(t *testing.T, snapshot netpol.Snapshot) {
				if len(snapshot.Jobs) != 1 {
					t.Fatalf("missing selected job")
				}
			},
		},
		{
			name: "namespace", subject: netpol.SubjectRef{Kind: netpol.SubjectNamespace, Name: "ns"},
			resource: "namespaces", gvr: client.NsGVR,
			object: &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns"}},
			assert: func(t *testing.T, snapshot netpol.Snapshot) {
				if len(snapshot.Namespaces) != 1 {
					t.Fatalf("missing selected namespace")
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			factory := newNetPolGraphFactory()
			factory.errs[test.gvr.String()] = errors.New("forbidden")
			factory.add(test.gvr, test.object)
			evaluator := &netPolGraphEvaluator{}
			model := NewNetPolGraph(evaluator)
			model.SetSubject(test.subject)

			err := model.Refresh(netPolGraphContext(factory))
			var incomplete *IncompleteSnapshotError
			if !errors.As(err, &incomplete) {
				t.Fatalf("expected incomplete snapshot warning, got %v", err)
			}
			if _, ok := incomplete.Incomplete[test.resource]; !ok {
				t.Fatalf("missing incomplete marker for %s", test.resource)
			}
			test.assert(t, evaluator.lastSnapshot())
			if got := factory.lastGetPath(); got == "" {
				t.Fatal("selected subject was not fetched")
			}
		})
	}
}
