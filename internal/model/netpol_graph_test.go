// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package model

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/derailed/k9s/internal"
	"github.com/derailed/k9s/internal/client"
	"github.com/derailed/k9s/internal/dao"
	"github.com/derailed/k9s/internal/netpol"
	"github.com/derailed/k9s/internal/watch"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/informers"
)

func TestNetPolGraphRefreshBuildsClusterSnapshot(t *testing.T) {
	factory := newNetPolGraphFactory()
	factory.add(client.PodGVR, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns"}})
	factory.add(client.NsGVR, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns"}})
	factory.add(client.NpGVR, &netv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "ns"}})
	factory.add(client.DpGVR, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "deployment", Namespace: "ns"}})
	factory.add(client.RsGVR, &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "replicaset", Namespace: "ns"}})
	factory.add(client.JobGVR, &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "job", Namespace: "ns"}})

	evaluator := &netPolGraphEvaluator{}
	model := NewNetPolGraph(evaluator)
	subject := netpol.SubjectRef{Kind: netpol.SubjectPod, Namespace: "ns", Name: "pod"}
	model.SetSubject(subject)

	if err := model.Refresh(netPolGraphContext(factory)); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}

	snapshot := evaluator.lastSnapshot()
	if len(snapshot.Pods) != 1 || len(snapshot.Namespaces) != 1 || len(snapshot.NetworkPolicies) != 1 ||
		len(snapshot.Deployments) != 1 || len(snapshot.ReplicaSets) != 1 || len(snapshot.Jobs) != 1 {
		t.Fatalf("unexpected snapshot sizes: %+v", snapshot)
	}
	if snapshot.GeneratedAt.IsZero() {
		t.Fatal("snapshot generation time was not recorded")
	}
	if evaluator.lastSubject() != subject {
		t.Fatalf("expected subject %+v, got %+v", subject, evaluator.lastSubject())
	}
	for _, namespace := range factory.namespaces() {
		if namespace != client.BlankNamespace {
			t.Fatalf("expected cluster-wide list, got namespace %q", namespace)
		}
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
	mu        sync.Mutex
	inventory map[string][]runtime.Object
	errs      map[string]error
	listNS    []string
	getPaths  []string
}

func newNetPolGraphFactory() *netPolGraphFactory {
	return &netPolGraphFactory{
		inventory: make(map[string][]runtime.Object),
		errs:      make(map[string]error),
	}
}

func (f *netPolGraphFactory) add(gvr *client.GVR, object runtime.Object) {
	raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(object)
	if err != nil {
		panic(err)
	}
	f.inventory[gvr.String()] = append(f.inventory[gvr.String()], &unstructured.Unstructured{Object: raw})
}

func (*netPolGraphFactory) Client() client.Connection { return nil }
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
	defer f.mu.Unlock()
	f.listNS = append(f.listNS, namespace)
	return f.inventory[gvr.String()], f.errs[gvr.String()]
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
}

//nolint:gocritic // Snapshot is required by the Evaluator interface.
func (e *netPolGraphEvaluator) EvaluateSubject(subject netpol.SubjectRef, snapshot netpol.Snapshot, _ netpol.Options) (netpol.SubjectResult, error) {
	e.mu.Lock()
	e.count++
	e.subject, e.snapshot = subject, snapshot
	started, release := e.started, e.release
	e.mu.Unlock()
	if started != nil {
		close(started)
	}
	if release != nil {
		<-release
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
}

func newNetPolGraphListener() *netPolGraphListener { return &netPolGraphListener{} }
func (l *netPolGraphListener) NetPolGraphChanged(netpol.SubjectResult) {
	l.mu.Lock()
	l.changed++
	hook := l.changedHook
	l.mu.Unlock()
	if hook != nil {
		hook()
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
