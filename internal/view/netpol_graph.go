// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package view

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"

	"github.com/derailed/k9s/internal"
	"github.com/derailed/k9s/internal/client"
	"github.com/derailed/k9s/internal/config"
	"github.com/derailed/k9s/internal/dao"
	"github.com/derailed/k9s/internal/model"
	"github.com/derailed/k9s/internal/netpol"
	"github.com/derailed/k9s/internal/slogs"
	"github.com/derailed/k9s/internal/ui"
	"github.com/derailed/k9s/internal/view/cmd"
	"github.com/derailed/tcell/v2"
	"github.com/derailed/tview"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	netPolGraphTitle      = "NetworkPolicy Reachability"
	netPolKindsDialogPage = "netpol-primitive-kinds"
	netPolSearchPage      = "netpol-search"
	netPolSubjectPage     = "netpol-subject"
	subjectInfoRowLimit   = 300
)

type netPolGraphModel interface {
	SetSubject(netpol.SubjectRef)
	Subject() netpol.SubjectRef
	AddListener(model.NetPolGraphListener)
	RemoveListener(model.NetPolGraphListener)
	Watch(context.Context) error
	Stop()
	Refresh(context.Context) error
	Peek() (netpol.SubjectResult, bool)
	LastRefresh() model.NetPolGraphRefresh
}

type reachabilityModeState struct {
	scroll ui.ReachabilityScrollState
	filter string
}

type reachabilityDirectionState struct {
	mode    ui.ReachabilityProjection
	visible bool
	states  map[ui.ReachabilityProjection]reachabilityModeState
}

type reachabilityFocus uint8

const (
	focusSubject reachabilityFocus = iota
	focusIngress
	focusEgress
	focusDetails
	focusApplicability
)

// NetworkPolicyGraph displays evaluated ingress and egress NetworkPolicy reachability.
type NetworkPolicyGraph struct {
	*tview.Flex

	app         *App
	model       netPolGraphModel
	evaluator   netpol.Evaluator
	subject     netpol.SubjectRef
	command     *cmd.Interpreter
	actions     *ui.KeyActions
	subjectInfo *ui.SubjectInfo
	directions  *tview.Flex
	details     *tview.Flex
	placeholder *tview.TextView
	detailItem  tview.Primitive
	panels      map[netpol.Direction]*ui.DirectionPanel
	state       map[netpol.Direction]*reachabilityDirectionState
	kinds       sets.Set[netpol.PrimitiveKind]
	focus       netpol.Direction
	focusTarget reachabilityFocus
	result      netpol.SubjectResult
	haveResult  bool
	autoRefresh bool
	detailShown detailScrollState
	lastError   error
	cancel      context.CancelFunc
	listening   bool
	mx          sync.Mutex
}

var (
	_ model.Component           = (*NetworkPolicyGraph)(nil)
	_ Viewer                    = (*NetworkPolicyGraph)(nil)
	_ model.NetPolGraphListener = (*NetworkPolicyGraph)(nil)
	_ config.StyleListener      = (*NetworkPolicyGraph)(nil)
)

// NewNetworkPolicyGraph creates a complete reachability viewer for subject.
func NewNetworkPolicyGraph(subject netpol.SubjectRef) *NetworkPolicyGraph {
	evaluator := netpol.NewEvaluator()
	graph := model.NewNetPolGraph(evaluator)
	graph.SetSubject(subject)
	return newNetworkPolicyGraph(subject, evaluator, graph)
}

func newNetworkPolicyGraph(subject netpol.SubjectRef, evaluator netpol.Evaluator, graph netPolGraphModel) *NetworkPolicyGraph {
	v := &NetworkPolicyGraph{
		Flex:        tview.NewFlex().SetDirection(tview.FlexRow),
		model:       graph,
		evaluator:   evaluator,
		subject:     subject,
		actions:     ui.NewKeyActions(),
		subjectInfo: ui.NewSubjectInfo(),
		directions:  tview.NewFlex(),
		details:     tview.NewFlex(),
		panels:      make(map[netpol.Direction]*ui.DirectionPanel, 2),
		state:       make(map[netpol.Direction]*reachabilityDirectionState, 2),
		kinds:       netpol.AllPrimitiveKinds(),
		focus:       netpol.Ingress,
		focusTarget: focusIngress,
	}
	for _, direction := range []netpol.Direction{netpol.Ingress, netpol.Egress} {
		v.state[direction] = &reachabilityDirectionState{
			mode:    ui.RulesProjection,
			visible: true,
			states: map[ui.ReachabilityProjection]reachabilityModeState{
				ui.RulesProjection:      {},
				ui.PrimitivesProjection: {},
			},
		}
		panel := ui.NewDirectionPanel(direction)
		panel.SetSelectionChangedFunc(func(string) {
			v.savePanelState(direction)
			// The detail pane always mirrors the focused direction. Reloading
			// the other panel must not repaint it, or a refresh would drop the
			// focused pane's cursor.
			if direction == v.focus {
				v.updateDetails(direction)
			}
		})
		v.panels[direction] = panel
	}
	v.AddItem(v.subjectInfo, 0, 1, false)
	v.AddItem(v.directions, 0, 3, true)
	v.AddItem(v.details, 0, 2, false)
	v.bindKeys()
	v.SetInputCapture(v.keyboard)
	v.rebuildDirections()
	v.updateSubject()
	v.showMessage("Waiting for NetworkPolicy evaluation...")
	return v
}

// Init initializes the component.
func (v *NetworkPolicyGraph) Init(ctx context.Context) error {
	app, err := extractApp(ctx)
	if err != nil {
		return err
	}
	v.app = app
	v.model.SetSubject(v.subject)
	v.ensureListeners()
	v.StylesChanged(app.Styles)
	v.applyASCII(app.Config.K9s.UI.NoIcons)
	if result, ok := v.model.Peek(); ok {
		v.applyResult(&result)
	}
	return nil
}

func (v *NetworkPolicyGraph) ensureListeners() {
	if v.listening || v.app == nil {
		return
	}
	v.model.AddListener(v)
	v.app.Styles.AddListener(v)
	v.listening = true
}

// Start loads the graph. Periodic reevaluation only runs while auto-refresh is
// enabled; otherwise a single evaluation is performed and further updates are
// driven by the refresh key.
func (v *NetworkPolicyGraph) Start() {
	v.stopWatch()
	v.ensureListeners()
	if v.autoRefresh {
		v.startWatch()
		return
	}
	v.Refresh()
}

// Stop terminates graph updates and releases listeners.
func (v *NetworkPolicyGraph) Stop() {
	v.stopWatch()
	if v.listening {
		v.model.RemoveListener(v)
		if v.app != nil {
			v.app.Styles.RemoveListener(v)
		}
		v.listening = false
	}
}

func (v *NetworkPolicyGraph) startWatch() {
	ctx, cancel := context.WithCancel(v.defaultCtx())
	v.mx.Lock()
	v.cancel = cancel
	v.mx.Unlock()
	go func() {
		if err := v.model.Watch(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("NetworkPolicy graph watch failed", slogs.Error, err)
		}
	}()
}

func (v *NetworkPolicyGraph) stopWatch() {
	v.mx.Lock()
	if v.cancel != nil {
		v.cancel()
		v.cancel = nil
	}
	v.mx.Unlock()
	v.model.Stop()
}

func (v *NetworkPolicyGraph) defaultCtx() context.Context {
	var factory dao.Factory
	if v.app != nil {
		factory = v.app.factory
	}
	return context.WithValue(context.Background(), internal.KeyFactory, factory)
}

// AutoRefresh reports whether the graph is periodically reevaluated.
func (v *NetworkPolicyGraph) AutoRefresh() bool { return v.autoRefresh }

// Refresh immediately reevaluates the graph.
func (v *NetworkPolicyGraph) Refresh() {
	if v.app == nil {
		return
	}
	ctx := v.defaultCtx()
	go func() {
		if err := v.model.Refresh(ctx); err != nil {
			slog.Warn("NetworkPolicy graph refresh failed", slogs.Error, err)
		}
	}()
}

func (v *NetworkPolicyGraph) toggleAutoRefresh() {
	v.autoRefresh = !v.autoRefresh
	if v.autoRefresh {
		v.startWatch()
	} else {
		v.stopWatch()
	}
	v.updateSubject()
	if v.app != nil {
		if v.autoRefresh {
			v.app.Flash().Infof("Auto-refresh is enabled (every %s)", model.NetPolGraphRefreshRate)
		} else {
			v.app.Flash().Info("Auto-refresh is disabled. Press Ctrl-R to refresh")
		}
	}
}

// NetPolGraphChanged handles model updates on the UI queue.
//
//nolint:gocritic // Value parameter implements the public model listener contract.
func (v *NetworkPolicyGraph) NetPolGraphChanged(result netpol.SubjectResult) {
	if v.app == nil {
		v.applyResult(&result)
		return
	}
	v.app.QueueUpdateDraw(func() { v.applyResult(&result) })
}

// NetPolGraphFailed reports failures while retaining any usable partial result.
func (v *NetworkPolicyGraph) NetPolGraphFailed(err error) {
	if v.app == nil {
		v.applyError(err)
		return
	}
	v.app.QueueUpdateDraw(func() { v.applyError(err) })
}

func (v *NetworkPolicyGraph) applyError(err error) {
	v.lastError = err
	v.updateSubject()
	if !v.haveResult {
		v.showMessage("NetworkPolicy evaluation failed:\n" + err.Error())
	} else {
		v.updateDetails(v.focus)
	}
}

func (v *NetworkPolicyGraph) applyResult(result *netpol.SubjectResult) {
	v.result, v.haveResult, v.lastError = *result, true, nil
	for _, direction := range []netpol.Direction{netpol.Ingress, netpol.Egress} {
		// Capture the live cursor first: loadPanel restores from the saved
		// state, which would otherwise reset the panel to whatever position was
		// recorded the last time the selection changed.
		v.savePanelState(direction)
		v.loadPanel(direction)
	}
	v.updateSubject()
	v.updateDetails(v.focus)
}

func (v *NetworkPolicyGraph) loadPanel(direction netpol.Direction) {
	panel, state := v.panels[direction], v.state[direction]
	modeState := state.states[state.mode]
	panel.SetProjection(state.mode).
		SetFilter(modeState.filter)
	if state.mode == ui.PrimitivesProjection && len(v.kinds) == 0 {
		panel.SetData(nil, nil).SetEmptyMessage("No primitive kinds selected. Press f to enable kinds.")
	} else {
		panel.SetEmptyMessage("No reachability results match this view.").
			SetData(
				v.evaluator.Rules(v.result, direction),
				v.evaluator.Primitives(v.result, direction, v.kinds),
			)
	}
	panel.RestoreScrollState(modeState.scroll)
}

func (v *NetworkPolicyGraph) savePanelState(direction netpol.Direction) {
	state := v.state[direction]
	modeState := state.states[state.mode]
	modeState.scroll = v.panels[direction].ScrollState()
	modeState.filter = v.panels[direction].Filter()
	state.states[state.mode] = modeState
}

func (v *NetworkPolicyGraph) rebuildDirections() {
	v.directions.Clear()
	visible := 0
	for _, direction := range []netpol.Direction{netpol.Ingress, netpol.Egress} {
		if v.state[direction].visible {
			v.directions.AddItem(v.panels[direction], 0, 1, direction == v.focus)
			visible++
		}
	}
	if visible == 0 {
		v.placeholder = tview.NewTextView().
			SetTextAlign(tview.AlignCenter).
			SetText("Both directions are hidden. Press i for ingress or e for egress.")
		v.placeholder.SetBorder(true).SetTitle(" Directions ")
		v.directions.AddItem(v.placeholder, 0, 1, true)
		return
	}
	v.placeholder = nil
	if !v.state[v.focus].visible {
		v.focus = v.firstVisibleDirection()
		if v.focus == netpol.Ingress {
			v.focusTarget = focusIngress
		} else {
			v.focusTarget = focusEgress
		}
	}
	if v.app != nil {
		v.app.SetFocus(v.panels[v.focus])
	}
}

func (v *NetworkPolicyGraph) firstVisibleDirection() netpol.Direction {
	if v.state[netpol.Ingress].visible {
		return netpol.Ingress
	}
	return netpol.Egress
}

func (v *NetworkPolicyGraph) toggleDirection(direction netpol.Direction) {
	v.savePanelState(direction)
	v.state[direction].visible = !v.state[direction].visible
	if v.state[direction].visible {
		v.focus = direction
		v.loadPanel(direction)
	}
	v.rebuildDirections()
	v.updateSubject()
	v.updateDetails(v.focus)
}

func (v *NetworkPolicyGraph) switchMode(direction netpol.Direction) {
	v.savePanelState(direction)
	state := v.state[direction]
	if state.mode == ui.RulesProjection {
		state.mode = ui.PrimitivesProjection
	} else {
		state.mode = ui.RulesProjection
	}
	v.loadPanel(direction)
	v.updateDetails(direction)
}

func (v *NetworkPolicyGraph) switchVisibleModesFromFocus() {
	// Propagate the focused panel's current mode; it must not toggle first,
	// otherwise the focused panel ends up in the mode you did not ask for.
	mode := v.state[v.focus].mode
	for _, direction := range []netpol.Direction{netpol.Ingress, netpol.Egress} {
		if direction == v.focus || !v.state[direction].visible || v.state[direction].mode == mode {
			continue
		}
		v.savePanelState(direction)
		v.state[direction].mode = mode
		v.loadPanel(direction)
	}
	v.updateDetails(v.focus)
}

func (v *NetworkPolicyGraph) focusDirection(direction netpol.Direction) {
	if !v.state[direction].visible {
		return
	}
	v.focus = direction
	if direction == netpol.Ingress {
		v.focusTarget = focusIngress
	} else {
		v.focusTarget = focusEgress
	}
	if v.app != nil {
		v.app.SetFocus(v.panels[direction])
	}
	v.updateDetails(direction)
}

func (v *NetworkPolicyGraph) cycleFocus(reverse bool) {
	targets := v.focusTargets()
	if len(targets) < 2 {
		return
	}
	current := 0
	for index, target := range targets {
		if target == v.focusTarget {
			current = index
			break
		}
	}
	step := 1
	if reverse {
		step = -1
	}
	v.applyFocusTarget(targets[(current+step+len(targets))%len(targets)])
}

func (v *NetworkPolicyGraph) focusTargets() []reachabilityFocus {
	targets := []reachabilityFocus{focusSubject}
	if v.state[netpol.Ingress].visible {
		targets = append(targets, focusIngress)
	}
	if v.state[netpol.Egress].visible {
		targets = append(targets, focusEgress)
	}
	if v.detailItem != nil && v.panels[v.focus].SelectedID() != "" {
		targets = append(targets, focusDetails)
		if detail, ok := v.detailItem.(*ui.RuleDetails); ok && detail.Applicability.GetRowCount() > 1 {
			targets = append(targets, focusApplicability)
		}
	}
	return targets
}

func (v *NetworkPolicyGraph) applyFocusTarget(target reachabilityFocus) {
	v.focusTarget = target
	switch target {
	case focusSubject:
		if v.app != nil {
			v.app.SetFocus(v.subjectInfo)
		}
		return
	case focusIngress:
		v.focus = netpol.Ingress
	case focusEgress:
		v.focus = netpol.Egress
	case focusDetails:
		if v.app != nil {
			if detail, ok := v.detailItem.(*ui.RuleDetails); ok {
				v.app.SetFocus(detail.Text)
			} else {
				v.app.SetFocus(v.detailItem)
			}
		}
		return
	case focusApplicability:
		if v.app != nil {
			if detail, ok := v.detailItem.(*ui.RuleDetails); ok {
				v.app.SetFocus(detail.Applicability)
			}
		}
		return
	}
	if v.app != nil {
		v.app.SetFocus(v.panels[v.focus])
	}
	v.updateDetails(v.focus)
}

func (v *NetworkPolicyGraph) updateSubject() {
	subject := v.subject
	path := subject.Name
	if subject.Namespace != "" {
		path = subject.Namespace + "/" + subject.Name
	}
	podCount := 0
	if v.haveResult {
		podCount = len(v.result.Subject.Pods)
	}
	extras := []string{}
	if v.haveResult && v.result.Truncated {
		extras = append(extras, fmt.Sprintf("TRUNCATED at %d results", v.result.ResultLimit))
	}
	warnings := len(v.result.Warnings)
	if refresh := v.model.LastRefresh(); len(refresh.Incomplete) > 0 {
		warnings += len(refresh.Incomplete)
	}
	if warnings > 0 {
		extras = append(extras, fmt.Sprintf("PARTIAL DATA (%d warning(s))", warnings))
	}
	if v.lastError != nil {
		extras = append(extras, "ERROR: "+v.lastError.Error())
	}
	workloads, workloadNotes := v.subjectWorkloads()
	extras = append(extras, workloadNotes...)
	summary := fmt.Sprintf("%s %s · %d %s · Ingress %s · Egress %s · Kinds: %s · Auto-refresh %s",
		subject.Kind, path, podCount, pluralize("pod", podCount),
		onOff(v.state[netpol.Ingress].visible),
		onOff(v.state[netpol.Egress].visible),
		primitiveKindsSummary(v.kinds),
		onOff(v.autoRefresh),
	)
	if len(extras) > 0 {
		summary += " · " + strings.Join(extras, " · ")
	}
	v.subjectInfo.SetSubject(subject, podCount).SetSummary(summary).SetWorkloads(workloads)
}

func (v *NetworkPolicyGraph) subjectWorkloads() ([]ui.SubjectWorkload, []string) {
	if !v.haveResult {
		return nil, nil
	}
	if v.app == nil || v.app.factory == nil {
		return nil, []string{"workloads unavailable: no resource factory"}
	}
	switch v.subject.Kind {
	case netpol.SubjectNamespace:
		return v.namespaceSubjectWorkloads(v.subject.Name)
	case netpol.SubjectPod, netpol.SubjectDeployment, netpol.SubjectJob:
		return v.subjectPodWorkloads()
	default:
		return nil, nil
	}
}

func (v *NetworkPolicyGraph) subjectPodWorkloads() ([]ui.SubjectWorkload, []string) {
	pods := v.result.Subject.Pods
	if len(pods) == 0 {
		return nil, nil
	}
	byNamespace := make(map[string][]netpol.PodRef)
	for _, pod := range pods {
		byNamespace[pod.Namespace] = append(byNamespace[pod.Namespace], pod)
	}
	statuses := make(map[string]string, len(pods))
	notes := []string{}
	for namespace := range byNamespace {
		objects, err := v.listUnstructured(client.PodGVR, namespace)
		if err != nil {
			return nil, []string{fmt.Sprintf("workloads unavailable: pod list in %s failed: %v", namespace, err)}
		}
		for _, object := range objects {
			statuses[objectKey(object.GetNamespace(), object.GetName())] = podStatus(object)
		}
	}
	workloads := make([]ui.SubjectWorkload, 0, min(len(pods), subjectInfoRowLimit))
	truncated := false
	for _, pod := range pods {
		if len(workloads) >= subjectInfoRowLimit {
			truncated = true
			break
		}
		workloads = append(workloads, ui.SubjectWorkload{
			Kind:      "Pod",
			Namespace: pod.Namespace,
			Name:      pod.Name,
			Status:    statuses[objectKey(pod.Namespace, pod.Name)],
		})
	}
	if truncated {
		notes = append(notes, fmt.Sprintf("workloads truncated at %d rows", subjectInfoRowLimit))
	}
	return workloads, notes
}

func (v *NetworkPolicyGraph) namespaceSubjectWorkloads(namespace string) ([]ui.SubjectWorkload, []string) {
	specs := []struct {
		gvr  *client.GVR
		kind string
	}{
		{client.DpGVR, "Deployment"},
		{client.RsGVR, "ReplicaSet"},
		{client.StsGVR, "StatefulSet"},
		{client.DsGVR, "DaemonSet"},
		{client.JobGVR, "Job"},
		{client.PodGVR, "Pod"},
	}
	workloads := make([]ui.SubjectWorkload, 0, subjectInfoRowLimit)
	notes := []string{}
	truncated := false
	for _, spec := range specs {
		if len(workloads) >= subjectInfoRowLimit {
			truncated = true
			break
		}
		objects, err := v.listUnstructured(spec.gvr, namespace)
		if err != nil {
			return nil, []string{fmt.Sprintf("workloads unavailable: %s list failed: %v", spec.kind, err)}
		}
		for _, object := range objects {
			if len(workloads) >= subjectInfoRowLimit {
				truncated = true
				break
			}
			workloads = append(workloads, ui.SubjectWorkload{
				Kind:      spec.kind,
				Namespace: object.GetNamespace(),
				Name:      object.GetName(),
				Status:    workloadStatus(spec.kind, object),
			})
		}
	}
	if truncated {
		notes = append(notes, fmt.Sprintf("workloads truncated at %d rows", subjectInfoRowLimit))
	}
	return workloads, notes
}

// listUnstructured returns namespace/name sorted objects. The informer cache
// iterates a map, so an unsorted list reshuffles the subject workload rows on
// every refresh and makes the row cap pick an arbitrary subset.
func (v *NetworkPolicyGraph) listUnstructured(gvr *client.GVR, namespace string) ([]*unstructured.Unstructured, error) {
	objects, err := v.app.factory.List(gvr, namespace, true, labels.Everything())
	if err != nil {
		return nil, err
	}
	items := make([]*unstructured.Unstructured, 0, len(objects))
	for _, object := range objects {
		if item, ok := object.(*unstructured.Unstructured); ok {
			items = append(items, item)
		}
	}
	slices.SortFunc(items, func(a, b *unstructured.Unstructured) int {
		return strings.Compare(
			objectKey(a.GetNamespace(), a.GetName()),
			objectKey(b.GetNamespace(), b.GetName()),
		)
	})
	return items, nil
}

func workloadStatus(kind string, object *unstructured.Unstructured) string {
	switch kind {
	case "Pod":
		return podStatus(object)
	case "Deployment", "ReplicaSet", "StatefulSet":
		return readyReplicasStatus(object)
	case "DaemonSet":
		return daemonSetStatus(object)
	case "Job":
		return jobStatus(object)
	default:
		return ""
	}
}

func podStatus(object *unstructured.Unstructured) string {
	phase, _, _ := unstructured.NestedString(object.Object, "status", "phase")
	ready, total := podReadyContainers(object)
	parts := []string{}
	if phase != "" {
		parts = append(parts, phase)
	}
	if total > 0 {
		parts = append(parts, fmt.Sprintf("%d/%d ready", ready, total))
	}
	if owner := ownerSummary(object); owner != "" {
		parts = append(parts, "owner "+owner)
	}
	return strings.Join(parts, " · ")
}

func podReadyContainers(object *unstructured.Unstructured) (int, int) {
	statuses, _, _ := unstructured.NestedSlice(object.Object, "status", "containerStatuses")
	ready := 0
	for _, status := range statuses {
		statusMap, ok := status.(map[string]interface{})
		if !ok {
			continue
		}
		if value, ok := statusMap["ready"].(bool); ok && value {
			ready++
		}
	}
	total := len(statuses)
	if total == 0 {
		containers, _, _ := unstructured.NestedSlice(object.Object, "spec", "containers")
		total = len(containers)
	}
	return ready, total
}

func ownerSummary(object *unstructured.Unstructured) string {
	owners := object.GetOwnerReferences()
	if len(owners) == 0 {
		return ""
	}
	return owners[0].Kind + "/" + owners[0].Name
}

func readyReplicasStatus(object *unstructured.Unstructured) string {
	ready, _, _ := unstructured.NestedInt64(object.Object, "status", "readyReplicas")
	desired, found, _ := unstructured.NestedInt64(object.Object, "spec", "replicas")
	if !found {
		desired = 0
	}
	return fmt.Sprintf("%d/%d ready", ready, desired)
}

func daemonSetStatus(object *unstructured.Unstructured) string {
	ready, _, _ := unstructured.NestedInt64(object.Object, "status", "numberReady")
	desired, _, _ := unstructured.NestedInt64(object.Object, "status", "desiredNumberScheduled")
	return fmt.Sprintf("%d/%d ready", ready, desired)
}

func jobStatus(object *unstructured.Unstructured) string {
	for _, condition := range jobConditions(object) {
		if conditionType, _ := condition["type"].(string); conditionType != "" {
			if status, _ := condition["status"].(string); status == "True" {
				return conditionType
			}
		}
	}
	succeeded, _, _ := unstructured.NestedInt64(object.Object, "status", "succeeded")
	completions, found, _ := unstructured.NestedInt64(object.Object, "spec", "completions")
	if !found {
		completions = 1
	}
	return fmt.Sprintf("%d/%d complete", succeeded, completions)
}

func jobConditions(object *unstructured.Unstructured) []map[string]interface{} {
	conditions, _, _ := unstructured.NestedSlice(object.Object, "status", "conditions")
	items := make([]map[string]interface{}, 0, len(conditions))
	for _, condition := range conditions {
		if item, ok := condition.(map[string]interface{}); ok {
			items = append(items, item)
		}
	}
	return items
}

func objectKey(namespace, name string) string {
	return namespace + "/" + name
}

func primitiveKindsSummary(kinds sets.Set[netpol.PrimitiveKind]) string {
	if len(kinds) == 0 {
		return "none"
	}
	names := make([]string, 0, len(kinds))
	for _, kind := range []netpol.PrimitiveKind{
		netpol.PrimitiveCIDR,
		netpol.PrimitivePod,
		netpol.PrimitiveNamespace,
		netpol.PrimitiveDeployment,
		netpol.PrimitiveJob,
	} {
		if kinds.Has(kind) {
			names = append(names, kind.String())
		}
	}
	return strings.Join(names, ",")
}

func pluralize(word string, count int) string {
	if count == 1 {
		return word
	}
	return word + "s"
}

func onOff(value bool) string {
	if value {
		return "on"
	}
	return "off"
}

func (v *NetworkPolicyGraph) updateDetails(direction netpol.Direction) {
	// The detail pane is rebuilt from scratch on every refresh, so remember
	// where the cursor was before dropping the old primitives.
	previous := v.captureDetailState()
	v.details.Clear()
	v.detailItem = nil
	v.detailShown = detailScrollState{}
	if !v.haveResult || !v.state[direction].visible {
		v.showMessage("No selected reachability result.")
		return
	}
	id := v.panels[direction].SelectedID()
	if id == "" {
		v.showMessage("No selected reachability result.")
		return
	}
	var detail tview.Primitive
	if v.state[direction].mode == ui.RulesProjection {
		rule, ok := v.selectedRule(direction, id)
		if !ok {
			v.showMessage("Selected rule is no longer available.")
			return
		}
		rows := v.evaluator.RuleApplicability(v.result, direction, rule.ID, v.kinds)
		ruleDetail := ui.NewRuleDetailsWithStyle(rule, rows, v.reachabilityStyle())
		v.applyDetailFocusStyle(ruleDetail)
		var text strings.Builder
		text.WriteString(v.detailPrefix(direction))
		text.WriteString("\n")
		text.WriteString(ui.RuleDetailsText(rule))
		v.appendResultWarnings(&text)
		ruleDetail.Text.SetText(strings.TrimSpace(text.String()))
		detail = ruleDetail
	} else {
		primitive, ok := v.selectedPrimitive(direction, id)
		if !ok {
			v.showMessage("Selected primitive is no longer available.")
			return
		}
		text := ui.NewPrimitiveDetails(primitive)
		text.SetText(v.primitiveDetails(direction, &primitive))
		v.applyTextFocusStyle(text)
		detail = text
	}
	v.details.AddItem(detail, 0, 1, false)
	v.detailItem = detail
	v.detailShown = detailScrollState{direction: direction, selectionID: id}
	v.restoreDetailState(previous, direction, id)
	if v.focusTarget == focusDetails || v.focusTarget == focusApplicability {
		v.applyFocusTarget(v.focusTarget)
	}
}

// detailScrollState remembers what the detail pane renders and where its cursor
// sits so a refresh does not scroll the user back to the top of the rebuilt
// widgets.
type detailScrollState struct {
	direction     netpol.Direction
	selectionID   string
	applicability string
	textRow       int
	textColumn    int
}

// captureDetailState reads the live cursor off the currently rendered pane. The
// pane identity comes from detailShown rather than the panels because the
// panels may already carry the freshly loaded data.
func (v *NetworkPolicyGraph) captureDetailState() detailScrollState {
	state := v.detailShown
	switch detail := v.detailItem.(type) {
	case *ui.RuleDetails:
		state.applicability = detail.SelectedApplicabilityID()
		state.textRow, state.textColumn = detail.Text.GetScrollOffset()
	case *tview.TextView:
		state.textRow, state.textColumn = detail.GetScrollOffset()
	}
	return state
}

func (v *NetworkPolicyGraph) restoreDetailState(state detailScrollState, direction netpol.Direction, id string) {
	// A different rule/primitive is rendered: the old cursor is meaningless.
	if state.direction != direction || state.selectionID != id {
		return
	}
	switch detail := v.detailItem.(type) {
	case *ui.RuleDetails:
		detail.SelectApplicabilityID(state.applicability)
		detail.Text.ScrollTo(state.textRow, state.textColumn)
	case *tview.TextView:
		detail.ScrollTo(state.textRow, state.textColumn)
	}
}

func (v *NetworkPolicyGraph) detailPrefix(direction netpol.Direction) string {
	ref := v.result.Subject.Ref
	return fmt.Sprintf("Direction: %s\nSubject: %s %s/%s\nSubject UID: %s",
		direction, ref.Kind, ref.Namespace, ref.Name, valueOrUnknown(string(ref.UID)))
}

func (v *NetworkPolicyGraph) primitiveDetails(direction netpol.Direction, primitive *netpol.PrimitiveResult) string {
	ref := primitive.Ref
	identity := ref.Name
	if ref.Namespace != "" {
		identity = ref.Namespace + "/" + ref.Name
	}
	if ref.Kind == netpol.PrimitiveCIDR {
		identity = ref.CIDR
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\nIdentity: %s %s\nUID: %s\nCoverage: %d/%d pairs\n",
		v.detailPrefix(direction), ref.Kind, valueOrUnknown(identity),
		valueOrUnknown(string(ref.UID)), primitive.AllowedPairs, primitive.TotalPairs)
	b.WriteString(ui.PrimitiveDetailsText(*primitive))
	v.appendResultWarnings(&b)
	return strings.TrimSpace(b.String())
}

func (v *NetworkPolicyGraph) appendResultWarnings(b *strings.Builder) {
	if v.result.Truncated {
		fmt.Fprintf(b, "\nWarning: results truncated at %d entries\n", v.result.ResultLimit)
	}
	for _, warning := range v.result.Warnings {
		fmt.Fprintf(b, "\nWarning: %s", warning)
	}
	if refresh := v.model.LastRefresh(); len(refresh.Incomplete) > 0 {
		keys := make([]string, 0, len(refresh.Incomplete))
		for resource := range refresh.Incomplete {
			keys = append(keys, resource)
		}
		slices.Sort(keys)
		for _, resource := range keys {
			fmt.Fprintf(b, "\nWarning: partial %s data: %v", resource, refresh.Incomplete[resource])
		}
	}
}

func valueOrUnknown(value string) string {
	if value == "" {
		return "<unknown>"
	}
	return value
}

func (v *NetworkPolicyGraph) showMessage(message string) {
	v.details.Clear()
	text := tview.NewTextView().SetText(message).SetWrap(true)
	text.SetBorder(true).SetTitle(" Details ")
	v.applyTextFocusStyle(text)
	v.details.AddItem(text, 0, 1, false)
	v.detailItem = text
	v.detailShown = detailScrollState{}
}

func (v *NetworkPolicyGraph) selectedRule(direction netpol.Direction, id string) (netpol.RuleResult, bool) {
	rules := v.evaluator.Rules(v.result, direction)
	for index := range rules {
		rule := &rules[index]
		if rule.StableID() == id {
			return *rule, true
		}
	}
	return netpol.RuleResult{}, false
}

func (v *NetworkPolicyGraph) selectedPrimitive(direction netpol.Direction, id string) (netpol.PrimitiveResult, bool) {
	primitives := v.evaluator.Primitives(v.result, direction, v.kinds)
	for index := range primitives {
		primitive := &primitives[index]
		if primitive.StableID() == id {
			return *primitive, true
		}
	}
	return netpol.PrimitiveResult{}, false
}

func (v *NetworkPolicyGraph) openKindsDialog() {
	if v.app == nil || !v.state[v.focus].visible {
		return
	}
	styles := v.app.Styles.Dialog()
	dialog := ui.NewPrimitiveKindDialog(v.kinds, func(kinds sets.Set[netpol.PrimitiveKind]) {
		v.app.Content.RemovePage(netPolKindsDialogPage)
		v.kinds = kinds
		for _, direction := range []netpol.Direction{netpol.Ingress, netpol.Egress} {
			v.loadPanel(direction)
		}
		v.updateSubject()
		v.updateDetails(v.focus)
		v.app.SetFocus(v.panels[v.focus])
	}, func() {
		v.app.Content.RemovePage(netPolKindsDialogPage)
		v.app.SetFocus(v.panels[v.focus])
	})
	styleForm(dialog.Form, &styles)
	modal := tview.NewModalForm("<Primitive Kinds (global)>", dialog.Form)
	modal.SetBackgroundColor(styles.BgColor.Color()).SetTextColor(styles.FgColor.Color())
	modal.SetDoneFunc(func(int, string) { dialog.Cancel() })
	v.app.Content.AddPage(netPolKindsDialogPage, modal, false, false)
	v.app.Content.ShowPage(netPolKindsDialogPage)
	v.app.SetFocus(modal)
}

func (v *NetworkPolicyGraph) openSearchDialog() {
	if v.app == nil || !v.state[v.focus].visible {
		return
	}
	styles := v.app.Styles.Dialog()
	input := tview.NewInputField().
		SetLabel("Filter: ").
		SetText(v.state[v.focus].states[v.state[v.focus].mode].filter)
	form := tview.NewForm().
		AddFormItem(input).
		AddButton("Apply", func() {
			v.applySearch(input.GetText())
			v.app.Content.RemovePage(netPolSearchPage)
		}).
		AddButton("Clear", func() {
			v.applySearch("")
			v.app.Content.RemovePage(netPolSearchPage)
		}).
		AddButton("Cancel", func() {
			v.app.Content.RemovePage(netPolSearchPage)
			v.app.SetFocus(v.panels[v.focus])
		})
	form.SetCancelFunc(func() {
		v.app.Content.RemovePage(netPolSearchPage)
		v.app.SetFocus(v.panels[v.focus])
	})
	styleForm(form, &styles)
	modal := tview.NewModalForm("<Reachability Search>", form)
	modal.SetBackgroundColor(styles.BgColor.Color()).SetTextColor(styles.FgColor.Color())
	modal.SetDoneFunc(func(int, string) {
		v.app.Content.RemovePage(netPolSearchPage)
		v.app.SetFocus(v.panels[v.focus])
	})
	v.app.Content.AddPage(netPolSearchPage, modal, false, false)
	v.app.Content.ShowPage(netPolSearchPage)
	v.app.SetFocus(modal)
}

func styleForm(form *tview.Form, styles *config.Dialog) {
	form.SetItemPadding(0).
		SetButtonsAlign(tview.AlignCenter).
		SetButtonBackgroundColor(styles.ButtonBgColor.Color()).
		SetButtonTextColor(styles.ButtonFgColor.Color()).
		SetLabelColor(styles.LabelFgColor.Color()).
		SetFieldTextColor(styles.FieldFgColor.Color()).
		SetFieldBackgroundColor(styles.BgColor.Color())
	for i := range form.GetButtonCount() {
		if b := form.GetButton(i); b != nil {
			b.SetBackgroundColorActivated(styles.ButtonFocusBgColor.Color())
			b.SetLabelColorActivated(styles.ButtonFocusFgColor.Color())
		}
	}
}

func (v *NetworkPolicyGraph) openSubjectDialog() {
	if v.app == nil || v.app.factory == nil {
		return
	}
	styles := v.app.Styles.Dialog()
	picker := ui.NewSubjectPicker(&styles, subjectKinds(), v.loadSubjects, func(ref netpol.SubjectRef) {
		v.app.Content.RemovePage(netPolSubjectPage)
		v.applySubject(ref)
	}, func() {
		v.app.Content.RemovePage(netPolSubjectPage)
		v.app.SetFocus(v.panels[v.focus])
	})
	v.app.Content.AddPage(netPolSubjectPage, picker, false, false)
	v.app.Content.ShowPage(netPolSubjectPage)
	v.app.SetFocus(picker)
}

func (v *NetworkPolicyGraph) applySubject(ref netpol.SubjectRef) {
	v.subject = ref
	v.model.SetSubject(ref)
	v.result, v.haveResult, v.lastError = netpol.SubjectResult{}, false, nil
	for _, direction := range []netpol.Direction{netpol.Ingress, netpol.Egress} {
		v.loadPanel(direction)
	}
	v.updateSubject()
	v.showMessage("Waiting for NetworkPolicy evaluation...")
	if v.app != nil {
		v.app.SetFocus(v.panels[v.focus])
	}
	// Without a watch loop nothing consumes the model refresh request, so the
	// new subject would never be evaluated while auto-refresh is disabled.
	if !v.autoRefresh {
		v.Refresh()
	}
}

func subjectKinds() []netpol.SubjectKind {
	return []netpol.SubjectKind{
		netpol.SubjectPod,
		netpol.SubjectDeployment,
		netpol.SubjectJob,
		netpol.SubjectNamespace,
	}
}

func (v *NetworkPolicyGraph) loadSubjects(kind netpol.SubjectKind) ([]netpol.SubjectRef, error) {
	return listSubjectRefs(v.app.factory, kind)
}

func listSubjectRefs(factory dao.Factory, kind netpol.SubjectKind) ([]netpol.SubjectRef, error) {
	gvr := subjectGVR(kind)
	if gvr == nil {
		return nil, fmt.Errorf("unsupported subject kind %s", kind)
	}
	objects, err := factory.List(gvr, client.BlankNamespace, true, labels.Everything())
	if err != nil {
		return nil, err
	}
	refs := make([]netpol.SubjectRef, 0, len(objects))
	for _, object := range objects {
		ref, ok := subjectRefFromObject(kind, object)
		if ok {
			refs = append(refs, ref)
		}
	}
	return refs, nil
}

func subjectGVR(kind netpol.SubjectKind) *client.GVR {
	switch kind {
	case netpol.SubjectPod:
		return client.PodGVR
	case netpol.SubjectDeployment:
		return client.DpGVR
	case netpol.SubjectJob:
		return client.JobGVR
	case netpol.SubjectNamespace:
		return client.NsGVR
	default:
		return nil
	}
}

func subjectRefFromObject(kind netpol.SubjectKind, object runtime.Object) (netpol.SubjectRef, bool) {
	unstructuredObject, ok := object.(*unstructured.Unstructured)
	if !ok {
		return netpol.SubjectRef{}, false
	}
	name := unstructuredObject.GetName()
	if name == "" {
		return netpol.SubjectRef{}, false
	}
	ref := netpol.SubjectRef{
		Kind:      kind,
		Name:      name,
		UID:       types.UID(unstructuredObject.GetUID()),
		Namespace: unstructuredObject.GetNamespace(),
	}
	if kind == netpol.SubjectNamespace {
		ref.Namespace = ""
	}
	return ref, true
}

func (v *NetworkPolicyGraph) applySearch(filter string) {
	state := v.state[v.focus]
	modeState := state.states[state.mode]
	modeState.filter = filter
	state.states[state.mode] = modeState
	v.panels[v.focus].SetFilter(filter)
	v.savePanelState(v.focus)
	v.updateDetails(v.focus)
	if v.app != nil {
		v.app.SetFocus(v.panels[v.focus])
	}
}

func (v *NetworkPolicyGraph) yamlCmd(_ *tcell.EventKey) *tcell.EventKey {
	namespace, name, ok := v.selectedPolicy()
	if !ok {
		if v.app != nil {
			v.app.Flash().Errf("selected item does not reference a NetworkPolicy")
		}
		return nil
	}
	path := name
	if namespace != "" {
		path = namespace + "/" + name
	}
	live := NewLiveView(v.app, yamlAction, model.NewYAML(client.NpGVR, path))
	if err := v.app.inject(live, false); err != nil {
		v.app.Flash().Err(err)
	}
	return nil
}

func (v *NetworkPolicyGraph) selectedPolicy() (namespace, name string, found bool) {
	id := v.panels[v.focus].SelectedID()
	if v.state[v.focus].mode == ui.RulesProjection {
		rule, ok := v.selectedRule(v.focus, id)
		return rule.ID.PolicyNamespace, rule.ID.PolicyName, ok && rule.ID.PolicyName != ""
	}
	primitive, ok := v.selectedPrimitive(v.focus, id)
	if !ok || len(primitive.Evidence) == 0 {
		return "", "", false
	}
	idRef := primitive.Evidence[0].RuleID
	return idRef.PolicyNamespace, idRef.PolicyName, idRef.PolicyName != ""
}

func (v *NetworkPolicyGraph) enterCmd(evt *tcell.EventKey) *tcell.EventKey {
	if v.focusTarget == focusIngress || v.focusTarget == focusEgress {
		v.applyFocusTarget(focusDetails)
		return nil
	}
	if v.focusTarget == focusDetails {
		if detail, ok := v.detailItem.(*ui.RuleDetails); ok && detail.Applicability.GetRowCount() > 1 {
			v.applyFocusTarget(focusApplicability)
			return nil
		}
	}
	return evt
}

func (v *NetworkPolicyGraph) openResourceCmd(evt *tcell.EventKey) *tcell.EventKey {
	if v.app == nil {
		return evt
	}
	if namespace, name, ok := v.selectedPolicy(); v.state[v.focus].mode == ui.RulesProjection && ok {
		v.app.gotoResource("networkpolicies", namespace+"/"+name, false, true)
		return nil
	}
	primitive, ok := v.selectedPrimitive(v.focus, v.panels[v.focus].SelectedID())
	if !ok {
		return evt
	}
	command, path := primitiveCommand(&primitive.Ref)
	if command == "" {
		v.app.Flash().Errf("CIDR primitives are not Kubernetes resources")
		return nil
	}
	v.app.gotoResource(command, path, false, true)
	return nil
}

func primitiveCommand(ref *netpol.PrimitiveRef) (command, resourcePath string) {
	path := ref.Name
	if ref.Namespace != "" {
		path = ref.Namespace + "/" + ref.Name
	}
	switch ref.Kind {
	case netpol.PrimitivePod:
		return "pods", path
	case netpol.PrimitiveNamespace:
		return "namespaces", ref.Name
	case netpol.PrimitiveDeployment:
		return "deployments", path
	case netpol.PrimitiveJob:
		return "jobs", path
	default:
		return "", ""
	}
}

func (v *NetworkPolicyGraph) bindKeys() {
	v.actions.Bulk(ui.KeyMap{
		ui.KeyI: ui.NewKeyAction("Toggle Ingress", func(*tcell.EventKey) *tcell.EventKey { v.toggleDirection(netpol.Ingress); return nil }, true),
		ui.KeyE: ui.NewKeyAction("Toggle Egress", func(*tcell.EventKey) *tcell.EventKey { v.toggleDirection(netpol.Egress); return nil }, true),
		ui.KeyM: ui.NewKeyAction("Toggle Mode", func(*tcell.EventKey) *tcell.EventKey { v.switchMode(v.focus); return nil }, true),
		ui.KeyShiftM: ui.NewKeyAction("Set Visible Modes", func(*tcell.EventKey) *tcell.EventKey {
			v.switchVisibleModesFromFocus()
			return nil
		}, true),
		ui.KeyF:        ui.NewKeyAction("Primitive Kinds", func(*tcell.EventKey) *tcell.EventKey { v.openKindsDialog(); return nil }, true),
		ui.KeyO:        ui.NewKeyAction("Open Resource", v.openResourceCmd, true),
		ui.KeyS:        ui.NewKeyAction("Subject", func(*tcell.EventKey) *tcell.EventKey { v.openSubjectDialog(); return nil }, true),
		ui.KeySlash:    ui.NewKeyAction("Search", func(*tcell.EventKey) *tcell.EventKey { v.openSearchDialog(); return nil }, true),
		ui.KeyR:        ui.NewKeyAction("Toggle Auto-Refresh", func(*tcell.EventKey) *tcell.EventKey { v.toggleAutoRefresh(); return nil }, true),
		tcell.KeyCtrlR: ui.NewKeyAction("Refresh", func(*tcell.EventKey) *tcell.EventKey { v.Refresh(); return nil }, true),
		ui.KeyY:        ui.NewKeyAction("YAML", v.yamlCmd, true),
		tcell.KeyEnter: ui.NewKeyAction("Focus Details", v.enterCmd, true),
		tcell.KeyEscape: ui.NewKeyAction("Back", func(evt *tcell.EventKey) *tcell.EventKey {
			if v.app != nil {
				return v.app.PrevCmd(evt)
			}
			return evt
		}, false),
		tcell.KeyLeft:    ui.NewKeyAction("Focus Ingress", func(*tcell.EventKey) *tcell.EventKey { v.focusDirection(netpol.Ingress); return nil }, false),
		tcell.KeyRight:   ui.NewKeyAction("Focus Egress", func(*tcell.EventKey) *tcell.EventKey { v.focusDirection(netpol.Egress); return nil }, false),
		tcell.KeyTAB:     ui.NewKeyAction("Next Panel", func(*tcell.EventKey) *tcell.EventKey { v.cycleFocus(false); return nil }, false),
		tcell.KeyBacktab: ui.NewKeyAction("Previous Panel", func(*tcell.EventKey) *tcell.EventKey { v.cycleFocus(true); return nil }, false),
	})
}

func (v *NetworkPolicyGraph) keyboard(evt *tcell.EventKey) *tcell.EventKey {
	if action, ok := v.actions.Get(ui.AsKey(evt)); ok {
		return action.Action(evt)
	}
	return evt
}

func (v *NetworkPolicyGraph) applyASCII(ascii bool) {
	for _, panel := range v.panels {
		panel.SetASCII(ascii)
	}
}

func (v *NetworkPolicyGraph) reachabilityStyle() config.Reachability {
	if v.app == nil {
		return config.Reachability{}
	}
	return v.app.Styles.Reachability()
}

func (v *NetworkPolicyGraph) reachabilityFocusColor() tcell.Color {
	if v.app == nil {
		return config.NewStyles().Reachability().FocusColor.Color()
	}
	return v.app.Styles.Reachability().FocusColor.Color()
}

func (v *NetworkPolicyGraph) applyTextFocusStyle(text *tview.TextView) {
	text.SetBorder(true)
	text.SetBorderFocusColor(v.reachabilityFocusColor())
	text.SetBorderAttributes(tcell.AttrBold)
}

func (v *NetworkPolicyGraph) applyTableFocusStyle(table *tview.Table) {
	table.SetBorder(true)
	table.SetBorderFocusColor(v.reachabilityFocusColor())
	table.SetBorderAttributes(tcell.AttrBold)
}

func (v *NetworkPolicyGraph) applyDetailFocusStyle(detail *ui.RuleDetails) {
	v.applyTextFocusStyle(detail.Text)
	v.applyTableFocusStyle(detail.Applicability)
}

// StylesChanged applies reachability and frame skin settings.
func (v *NetworkPolicyGraph) StylesChanged(styles *config.Styles) {
	reachability := styles.Reachability()
	for _, panel := range v.panels {
		panel.SetReachabilityStyle(reachability)
		panel.SetBorderFocusColor(reachability.FocusColor.Color())
	}
	v.SetBackgroundColor(styles.BgColor())
	v.subjectInfo.SetStyles(styles)
	v.subjectInfo.SetBorderFocusColor(v.reachabilityFocusColor())
	v.subjectInfo.SetBorderAttributes(tcell.AttrBold)
	if v.haveResult {
		v.updateDetails(v.focus)
	}
}

// Actions returns active menu actions.
func (v *NetworkPolicyGraph) Actions() *ui.KeyActions { return v.actions }

// App returns the application handle.
func (v *NetworkPolicyGraph) App() *App { return v.app }

// Hints returns active key hints.
func (v *NetworkPolicyGraph) Hints() model.MenuHints { return v.actions.Hints() }

// ExtraHints returns no additional hints.
func (*NetworkPolicyGraph) ExtraHints() map[string]string { return nil }

// Name returns the component name.
func (*NetworkPolicyGraph) Name() string { return netPolGraphTitle }

// InCmdMode reports whether a command buffer owns input.
func (*NetworkPolicyGraph) InCmdMode() bool { return false }

// SetCommand records the command used to open this view.
func (v *NetworkPolicyGraph) SetCommand(command *cmd.Interpreter) { v.command = command }

// SetFilter applies an initial text filter to both current direction modes.
func (v *NetworkPolicyGraph) SetFilter(filter string, _ bool) {
	for _, direction := range []netpol.Direction{netpol.Ingress, netpol.Egress} {
		state := v.state[direction]
		modeState := state.states[state.mode]
		modeState.filter = filter
		state.states[state.mode] = modeState
		v.panels[direction].SetFilter(filter)
	}
}

// SetLabelSelector is unsupported for evaluated reachability.
func (*NetworkPolicyGraph) SetLabelSelector(labels.Selector, bool) {}
