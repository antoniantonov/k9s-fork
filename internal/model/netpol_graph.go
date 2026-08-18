// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package model

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/derailed/k9s/internal"
	"github.com/derailed/k9s/internal/client"
	"github.com/derailed/k9s/internal/dao"
	"github.com/derailed/k9s/internal/netpol"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	// NetPolGraphRefreshRate is the interval between periodic graph
	// reevaluations while auto-refresh is enabled.
	NetPolGraphRefreshRate = 5 * time.Second

	defaultNetPolGraphDebounce = 150 * time.Millisecond
)

// NetPolGraphListener listens for NetworkPolicy graph evaluations.
type NetPolGraphListener interface {
	NetPolGraphChanged(netpol.SubjectResult)
	NetPolGraphFailed(error)
}

// NetworkPolicyGraphListener is a descriptive alias for NetPolGraphListener.
type NetworkPolicyGraphListener = NetPolGraphListener

// NetPolGraphRefresh describes the most recently completed refresh.
type NetPolGraphRefresh struct {
	Generation          uint64
	Subject             netpol.SubjectRef
	StartedAt           time.Time
	SnapshotGeneratedAt time.Time
	CompletedAt         time.Time
	Incomplete          map[string]error
}

// IncompleteSnapshotError reports resources which could not be included in a
// graph snapshot. A result may still be available when this error is reported.
type IncompleteSnapshotError struct {
	Incomplete map[string]error
}

func (e *IncompleteSnapshotError) Error() string {
	return fmt.Sprintf("network policy snapshot is incomplete: %d resource(s) failed", len(e.Incomplete))
}

// Unwrap makes the individual list failures available to errors.Is/As.
func (e *IncompleteSnapshotError) Unwrap() []error {
	errs := make([]error, 0, len(e.Incomplete))
	for _, err := range e.Incomplete {
		errs = append(errs, err)
	}
	return errs
}

// NetPolGraph periodically evaluates NetworkPolicy reachability for a subject.
type NetPolGraph struct {
	mu          sync.RWMutex
	refreshMu   sync.Mutex
	watchMu     sync.Mutex
	evaluator   netpol.Evaluator
	subject     netpol.SubjectRef
	options     netpol.Options
	generation  uint64
	watchID     uint64
	watchCancel context.CancelFunc
	listeners   []NetPolGraphListener
	result      *netpol.SubjectResult
	lastRefresh NetPolGraphRefresh
	refreshRate time.Duration
	debounce    time.Duration
	trigger     chan struct{}
}

// NetworkPolicyGraph is a descriptive alias for NetPolGraph.
type NetworkPolicyGraph = NetPolGraph

// NewNetPolGraph returns a watched NetworkPolicy graph model.
func NewNetPolGraph(evaluator netpol.Evaluator) *NetPolGraph {
	return &NetPolGraph{
		evaluator:   evaluator,
		refreshRate: NetPolGraphRefreshRate,
		debounce:    defaultNetPolGraphDebounce,
		trigger:     make(chan struct{}, 1),
	}
}

// NewNetworkPolicyGraph returns a watched NetworkPolicy graph model.
func NewNetworkPolicyGraph(evaluator netpol.Evaluator) *NetPolGraph {
	return NewNetPolGraph(evaluator)
}

// SetSubject configures the subject evaluated by the model.
func (m *NetPolGraph) SetSubject(subject netpol.SubjectRef) {
	m.mu.Lock()
	if m.subject == subject {
		m.mu.Unlock()
		return
	}
	m.subject = subject
	m.generation++
	m.result = nil
	m.mu.Unlock()
	m.requestRefresh()
}

// Subject returns the currently configured subject.
func (m *NetPolGraph) Subject() netpol.SubjectRef {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.subject
}

// SetOptions configures evaluator options and schedules a refresh.
func (m *NetPolGraph) SetOptions(options netpol.Options) {
	m.mu.Lock()
	m.options = options
	m.generation++
	m.mu.Unlock()
	m.requestRefresh()
}

// SetRefreshRate sets the periodic refresh interval.
func (m *NetPolGraph) SetRefreshRate(rate time.Duration) {
	m.mu.Lock()
	if rate > 0 {
		m.refreshRate = rate
	}
	m.mu.Unlock()
}

// SetDebounce sets the delay used to coalesce subject/configuration changes.
func (m *NetPolGraph) SetDebounce(delay time.Duration) {
	m.mu.Lock()
	if delay >= 0 {
		m.debounce = delay
	}
	m.mu.Unlock()
}

// AddListener adds a graph listener.
func (m *NetPolGraph) AddListener(listener NetPolGraphListener) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listeners = append(m.listeners, listener)
}

// RemoveListener removes a graph listener.
func (m *NetPolGraph) RemoveListener(listener NetPolGraphListener) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, candidate := range m.listeners {
		if candidate == listener {
			m.listeners = append(m.listeners[:i], m.listeners[i+1:]...)
			return
		}
	}
}

// Peek returns a copy of the most recently accepted result.
func (m *NetPolGraph) Peek() (netpol.SubjectResult, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.result == nil {
		return netpol.SubjectResult{}, false
	}
	return cloneSubjectResult(m.result), true
}

// LastRefresh returns metadata for the most recently accepted refresh.
func (m *NetPolGraph) LastRefresh() NetPolGraphRefresh {
	m.mu.RLock()
	defer m.mu.RUnlock()
	meta := m.lastRefresh
	meta.Incomplete = maps.Clone(meta.Incomplete)
	return meta
}

// Watch performs an initial refresh and starts periodic reconciliation.
func (m *NetPolGraph) Watch(ctx context.Context) error {
	select {
	case <-m.trigger:
	default:
	}

	watchCtx, cancel := context.WithCancel(ctx)
	m.watchMu.Lock()
	if m.watchCancel != nil {
		m.watchCancel()
	}
	m.watchID++
	watchID := m.watchID
	m.watchCancel = cancel
	m.watchMu.Unlock()

	err := m.Refresh(watchCtx)
	if watchCtx.Err() == nil && m.isActiveWatch(watchID) {
		go m.updater(watchCtx, watchID)
	} else {
		m.clearWatch(watchID)
	}
	return err
}

// Stop terminates the active watch loop. It is safe to call repeatedly.
func (m *NetPolGraph) Stop() {
	m.watchMu.Lock()
	if m.watchCancel != nil {
		m.watchCancel()
		m.watchCancel = nil
	}
	m.watchID++
	m.watchMu.Unlock()
}

// Refresh immediately rebuilds and evaluates the graph snapshot.
func (m *NetPolGraph) Refresh(ctx context.Context) error {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()

	started := time.Now()
	m.mu.RLock()
	subject, options, generation := m.subject, m.options, m.generation
	evaluator := m.evaluator
	m.mu.RUnlock()

	if evaluator == nil {
		err := errors.New("network policy evaluator is not configured")
		m.finishFailure(generation, subject, started, time.Time{}, nil, err)
		return err
	}
	if subject.Name == "" {
		err := errors.New("network policy graph subject is not configured")
		m.finishFailure(generation, subject, started, time.Time{}, nil, err)
		return err
	}
	factory, ok := ctx.Value(internal.KeyFactory).(dao.Factory)
	if !ok {
		err := fmt.Errorf("expected Factory in context but got %T", ctx.Value(internal.KeyFactory))
		m.finishFailure(generation, subject, started, time.Time{}, nil, err)
		return err
	}

	snapshot := buildNetPolSnapshot(ctx, factory, subject)
	if err := ctx.Err(); err != nil {
		return err
	}
	result, evalErr := evaluator.EvaluateSubject(subject, snapshot, options)
	if err := ctx.Err(); err != nil {
		return err
	}

	var partialErr error
	if len(snapshot.Incomplete) > 0 {
		partialErr = &IncompleteSnapshotError{Incomplete: maps.Clone(snapshot.Incomplete)}
	}
	if evalErr != nil {
		evalErr = errors.Join(evalErr, partialErr)
		m.finishFailure(generation, subject, started, snapshot.GeneratedAt, snapshot.Incomplete, evalErr)
		return evalErr
	}
	if !m.acceptResult(generation, subject, started, snapshot.GeneratedAt, snapshot.Incomplete, &result) {
		return nil
	}
	if partialErr != nil {
		if !m.isCurrent(generation, subject) {
			return nil
		}
		m.fireFailed(generation, subject, partialErr)
	}
	return partialErr
}

func (m *NetPolGraph) updater(ctx context.Context, watchID uint64) {
	defer m.clearWatch(watchID)
	timer := time.NewTimer(m.currentRefreshRate())
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if !m.isActiveWatch(watchID) {
				return
			}
			_ = m.Refresh(ctx)
			timer.Reset(m.currentRefreshRate())
		case <-m.trigger:
			if !m.isActiveWatch(watchID) {
				m.requestRefresh()
				return
			}
			if !m.waitForDebounce(ctx) {
				if !m.isActiveWatch(watchID) {
					m.requestRefresh()
				}
				return
			}
			if !m.isActiveWatch(watchID) {
				m.requestRefresh()
				return
			}
			_ = m.Refresh(ctx)
			timer.Reset(m.currentRefreshRate())
		}
	}
}

func (m *NetPolGraph) isActiveWatch(watchID uint64) bool {
	m.watchMu.Lock()
	defer m.watchMu.Unlock()
	return m.watchID == watchID && m.watchCancel != nil
}

func (m *NetPolGraph) clearWatch(watchID uint64) {
	m.watchMu.Lock()
	if m.watchID == watchID {
		m.watchCancel = nil
	}
	m.watchMu.Unlock()
}

func (m *NetPolGraph) waitForDebounce(ctx context.Context) bool {
	delay := m.currentDebounce()
	if delay <= 0 {
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		case <-m.trigger:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(delay)
		}
	}
}

func (m *NetPolGraph) requestRefresh() {
	select {
	case m.trigger <- struct{}{}:
	default:
	}
}

func (m *NetPolGraph) currentRefreshRate() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.refreshRate
}

func (m *NetPolGraph) currentDebounce() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.debounce
}

func (m *NetPolGraph) acceptResult(
	generation uint64,
	subject netpol.SubjectRef,
	started, generated time.Time,
	incomplete map[string]error,
	result *netpol.SubjectResult,
) bool {
	m.mu.Lock()
	if generation != m.generation || subject != m.subject {
		m.mu.Unlock()
		return false
	}
	resultCopy := cloneSubjectResult(result)
	m.result = &resultCopy
	m.lastRefresh = NetPolGraphRefresh{
		Generation:          generation,
		Subject:             subject,
		StartedAt:           started,
		SnapshotGeneratedAt: generated,
		CompletedAt:         time.Now(),
		Incomplete:          maps.Clone(incomplete),
	}
	listeners := append([]NetPolGraphListener(nil), m.listeners...)
	m.mu.Unlock()

	for _, listener := range listeners {
		if !m.isCurrent(generation, subject) {
			break
		}
		listener.NetPolGraphChanged(cloneSubjectResult(result))
	}
	return true
}

func (m *NetPolGraph) finishFailure(generation uint64, subject netpol.SubjectRef, started, generated time.Time, incomplete map[string]error, err error) {
	m.mu.Lock()
	if generation != m.generation || subject != m.subject {
		m.mu.Unlock()
		return
	}
	m.lastRefresh = NetPolGraphRefresh{
		Generation:          generation,
		Subject:             subject,
		StartedAt:           started,
		SnapshotGeneratedAt: generated,
		CompletedAt:         time.Now(),
		Incomplete:          maps.Clone(incomplete),
	}
	listeners := append([]NetPolGraphListener(nil), m.listeners...)
	m.mu.Unlock()
	for _, listener := range listeners {
		if !m.isCurrent(generation, subject) {
			return
		}
		listener.NetPolGraphFailed(err)
	}
}

func (m *NetPolGraph) fireFailed(generation uint64, subject netpol.SubjectRef, err error) {
	m.mu.RLock()
	listeners := append([]NetPolGraphListener(nil), m.listeners...)
	m.mu.RUnlock()
	for _, listener := range listeners {
		if !m.isCurrent(generation, subject) {
			return
		}
		listener.NetPolGraphFailed(err)
	}
}

func (m *NetPolGraph) isCurrent(generation uint64, subject netpol.SubjectRef) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return generation == m.generation && subject == m.subject
}

func buildNetPolSnapshot(ctx context.Context, factory dao.Factory, subject netpol.SubjectRef) netpol.Snapshot {
	snapshot := netpol.Snapshot{
		Incomplete:  make(map[string]error),
		GeneratedAt: time.Now(),
	}
	list := func(name string, gvr *client.GVR) []runtime.Object {
		if err := ctx.Err(); err != nil {
			snapshot.Incomplete[name] = err
			return nil
		}
		// Wait for cache sync: a cold informer otherwise yields an empty list
		// and the subject looks like it does not exist.
		objects, err := factory.List(gvr, client.BlankNamespace, true, labels.Everything())
		if err != nil {
			snapshot.Incomplete[name] = err
			return nil
		}
		return objects
	}

	snapshot.Pods = convertSnapshotObjects[corev1.Pod]("pods", list("pods", client.PodGVR), &snapshot)
	snapshot.Namespaces = convertSnapshotObjects[corev1.Namespace]("namespaces", list("namespaces", client.NsGVR), &snapshot)
	snapshot.NetworkPolicies = convertSnapshotObjects[netv1.NetworkPolicy]("networkpolicies", list("networkpolicies", client.NpGVR), &snapshot)
	snapshot.Deployments = convertSnapshotObjects[appsv1.Deployment]("deployments", list("deployments", client.DpGVR), &snapshot)
	snapshot.ReplicaSets = convertSnapshotObjects[appsv1.ReplicaSet]("replicasets", list("replicasets", client.RsGVR), &snapshot)
	snapshot.Jobs = convertSnapshotObjects[batchv1.Job]("jobs", list("jobs", client.JobGVR), &snapshot)
	injectSelectedSubject(ctx, factory, subject, &snapshot)
	return snapshot
}

func injectSelectedSubject(ctx context.Context, factory dao.Factory, subject netpol.SubjectRef, snapshot *netpol.Snapshot) {
	var resource string
	var gvr *client.GVR
	var path string
	switch subject.Kind {
	case netpol.SubjectPod:
		resource, gvr, path = "pods", client.PodGVR, client.FQN(subject.Namespace, subject.Name)
	case netpol.SubjectDeployment:
		resource, gvr, path = "deployments", client.DpGVR, client.FQN(subject.Namespace, subject.Name)
	case netpol.SubjectJob:
		resource, gvr, path = "jobs", client.JobGVR, client.FQN(subject.Namespace, subject.Name)
	case netpol.SubjectNamespace:
		resource, gvr, path = "namespaces", client.NsGVR, client.FQN(client.ClusterScope, subject.Name)
	default:
		return
	}
	if _, failed := snapshot.Incomplete[resource]; !failed || ctx.Err() != nil {
		return
	}
	object, err := factory.Get(gvr, path, true, labels.Everything())
	if err != nil {
		snapshot.Incomplete[resource] = errors.Join(snapshot.Incomplete[resource], fmt.Errorf("get selected subject %s: %w", path, err))
		return
	}
	switch subject.Kind {
	case netpol.SubjectPod:
		snapshot.Pods = appendConvertedObject("pods", snapshot.Pods, object, snapshot)
	case netpol.SubjectDeployment:
		snapshot.Deployments = appendConvertedObject("deployments", snapshot.Deployments, object, snapshot)
	case netpol.SubjectJob:
		snapshot.Jobs = appendConvertedObject("jobs", snapshot.Jobs, object, snapshot)
	case netpol.SubjectNamespace:
		snapshot.Namespaces = appendConvertedObject("namespaces", snapshot.Namespaces, object, snapshot)
	}
}

func appendConvertedObject[T any](resource string, items []T, object runtime.Object, snapshot *netpol.Snapshot) []T {
	converted := convertSnapshotObjects[T](resource, []runtime.Object{object}, snapshot)
	return append(items, converted...)
}

func convertSnapshotObjects[T any](resource string, objects []runtime.Object, snapshot *netpol.Snapshot) []T {
	items := make([]T, 0, len(objects))
	var conversionErrors []error
	for i, object := range objects {
		var raw map[string]any
		switch value := object.(type) {
		case *unstructured.Unstructured:
			raw = value.Object
		default:
			var err error
			raw, err = runtime.DefaultUnstructuredConverter.ToUnstructured(object)
			if err != nil {
				conversionErrors = append(conversionErrors, fmt.Errorf("item %d (%T): %w", i, object, err))
				continue
			}
		}
		var item T
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(raw, &item); err != nil {
			conversionErrors = append(conversionErrors, fmt.Errorf("item %d (%T): %w", i, object, err))
			continue
		}
		items = append(items, item)
	}
	if len(conversionErrors) > 0 {
		snapshot.Incomplete[resource] = errors.Join(conversionErrors...)
	}
	return items
}

func cloneSubjectResult(source *netpol.SubjectResult) netpol.SubjectResult {
	result := *source
	result.Subject.Pods = append([]netpol.PodRef(nil), result.Subject.Pods...)
	result.Warnings = append([]string(nil), result.Warnings...)
	result.Ingress = cloneDirectionResult(result.Ingress)
	result.Egress = cloneDirectionResult(result.Egress)
	return result
}

func cloneDirectionResult(result netpol.DirectionResult) netpol.DirectionResult {
	result.Rules = append([]netpol.RuleResult(nil), result.Rules...)
	for i := range result.Rules {
		result.Rules[i].Peers = append([]string(nil), result.Rules[i].Peers...)
		result.Rules[i].Permissions = clonePermissions(result.Rules[i].Permissions)
		result.Rules[i].Evidence = cloneEvidence(result.Rules[i].Evidence)
		result.Rules[i].Warnings = append([]string(nil), result.Rules[i].Warnings...)
	}

	result.Primitives = maps.Clone(result.Primitives)
	for kind, primitives := range result.Primitives {
		cloned := append([]netpol.PrimitiveResult(nil), primitives...)
		for i := range cloned {
			cloned[i].Ref.CIDRExcept = append([]string(nil), cloned[i].Ref.CIDRExcept...)
			cloned[i].Permissions = clonePermissions(cloned[i].Permissions)
			cloned[i].Evidence = cloneEvidence(cloned[i].Evidence)
			cloned[i].Warnings = append([]string(nil), cloned[i].Warnings...)
			cloned[i].PairDecisions = append([]netpol.PairDecision(nil), cloned[i].PairDecisions...)
			for j := range cloned[i].PairDecisions {
				cloned[i].PairDecisions[j].Decision = cloneDecision(&cloned[i].PairDecisions[j].Decision)
			}
		}
		result.Primitives[kind] = cloned
	}
	return result
}

func cloneDecision(source *netpol.Decision) netpol.Decision {
	decision := *source
	decision.Permissions = clonePermissions(decision.Permissions)
	decision.Evidence = cloneEvidence(decision.Evidence)
	decision.Warnings = append([]string(nil), decision.Warnings...)
	return decision
}

func cloneEvidence(evidence []netpol.PolicyEvidence) []netpol.PolicyEvidence {
	cloned := append([]netpol.PolicyEvidence(nil), evidence...)
	for i := range cloned {
		cloned[i].PolicyTypes = append([]netv1.PolicyType(nil), cloned[i].PolicyTypes...)
		cloned[i].Ports = clonePermissions(cloned[i].Ports)
	}
	return cloned
}

func clonePermissions(permissions []netpol.PortPermission) []netpol.PortPermission {
	cloned := append([]netpol.PortPermission(nil), permissions...)
	for i := range cloned {
		if cloned[i].Port != nil {
			port := *cloned[i].Port
			cloned[i].Port = &port
		}
		if cloned[i].EndPort != nil {
			endPort := *cloned[i].EndPort
			cloned[i].EndPort = &endPort
		}
	}
	return cloned
}
