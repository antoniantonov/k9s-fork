// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package view

import (
	"context"
	"errors"
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
	netPolGraphCrumb      = "npg"
	netPolKindsDialogPage = "netpol-primitive-kinds"
	netPolSearchPage      = "netpol-search"
	netPolSubjectPage     = "netpol-subject"
	subjectInfoRowLimit   = 300
	openPrimitiveHint     = "Open Primitive"
)

// Section sizing. Every section above the applicability table is sized to its
// own content, but capped so that a subject with hundreds of workloads or a
// direction with hundreds of rules cannot squeeze the applicability table --
// the table this view exists to show -- off the screen. The caps alone are not
// enough: the rule detail text is long enough to hit its cap on almost every
// rule, so the applicability table also reserves a share of the view up front
// and the sections above it are trimmed from the bottom up to honour it.
const (
	subjectMaxPercent    = 25
	directionMaxPercent  = 35
	detailTextMaxPercent = 30
	// applicabilityPercent is the share of the view the applicability table
	// keeps before any section above it is allowed to grow into it.
	applicabilityPercent = 28
	// minSectionHeight is a border plus a single row of content.
	minSectionHeight = 3
	// minApplicabilityHeight is a border, the header row and two data rows.
	minApplicabilityHeight = 5
	// minDetailsHeight keeps the detail text and a usable applicability table
	// on screen no matter how tall the sections above want to be.
	minDetailsHeight = minSectionHeight + minApplicabilityHeight
)

// sectionRequest is one fixed-height section of a top-to-bottom stack.
type sectionRequest struct {
	desired int
	min     int
	// max caps the section. Zero means uncapped.
	max int
}

// size returns the height the section would take on its own, before it competes
// with anything else. A zero request stays zero so panes that ask for nothing
// reserve nothing.
func (s sectionRequest) size() int {
	if s.desired == 0 && s.min == 0 {
		return 0
	}
	size := s.desired
	if s.max > 0 && size > s.max {
		size = s.max
	}
	return max(size, s.min)
}

// solveSectionHeights sizes a stack of content-driven sections that share a
// container with a trailing flexible section. Each section gets the height its
// content asks for, clamped to its own bounds, and is then shrunk from the
// bottom up until the flexible section keeps at least remainder rows.
func solveSectionHeights(total, remainder int, requests []sectionRequest) []int {
	sizes := make([]int, len(requests))
	if total <= 0 {
		return sizes
	}
	for index := range requests {
		sizes[index] = max(0, requests[index].size())
	}
	// Give the flexible section its floor by trimming the sections above it,
	// starting with the one nearest to it.
	shrink(sizes, total-remainder, func(index int) int { return requests[index].min })
	// The container is too small to honour even the minimums: keep the topmost
	// sections and drop the ones that no longer fit at all.
	shrink(sizes, total, func(int) int { return 0 })
	return sizes
}

// shrink trims sizes from the bottom up until they sum to at most budget, never
// taking a section below the floor reported for its index.
func shrink(sizes []int, budget int, floor func(index int) int) {
	for index := len(sizes) - 1; index >= 0; index-- {
		excess := sum(sizes) - budget
		if excess <= 0 {
			return
		}
		room := min(sizes[index]-floor(index), excess)
		if room > 0 {
			sizes[index] -= room
		}
	}
}

func sum(values []int) int {
	total := 0
	for _, value := range values {
		total += value
	}
	return total
}

func percentOf(total, percent int) int {
	return total * percent / 100
}

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

type reachabilitySearchTarget uint8

const (
	searchNone reachabilitySearchTarget = iota
	searchSubject
	searchDirection
	searchApplicability
)

// projectionCache memoizes the per-direction projections derived from the last
// evaluated result. The evaluator clones its whole slice on every call and the
// detail pane derives it several times per keystroke, which is enough work to
// stall the UI on a large subject.
type projectionCache struct {
	generation uint64
	kindMask   uint32
	rules      []netpol.RuleResult
	ruleIndex  map[string]int
	primitives []netpol.PrimitiveResult
	primIndex  map[string]int
}

// applicabilityMemo caches the last applicability projection. Rendering the
// detail pane recomputes it, and a single keystroke repaints the pane more than
// once.
type applicabilityMemo struct {
	generation uint64
	kindMask   uint32
	direction  netpol.Direction
	ruleID     netpol.RuleID
	effective  bool
	rows       []netpol.ApplicabilityRow
}

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
	appFilters  map[netpol.Direction]string
	mode        ui.ReachabilityProjection
	allowedOnly bool
	focus       netpol.Direction
	focusTarget reachabilityFocus
	result      netpol.SubjectResult
	haveResult  bool
	autoRefresh bool
	detailShown detailScrollState
	lastError   error
	cancel      context.CancelFunc
	listening   bool
	logoBadge   ui.LogoBadgeToken
	mx          sync.Mutex

	// Workload rows are collected from the informers, which can block, so they
	// are gathered off the UI goroutine and published back into these fields.
	// Everything here is only ever touched on the UI goroutine.
	workloads        []ui.SubjectWorkload
	workloadNotes    []string
	workloadsLoading bool
	workloadSeq      uint64
	// collectWorkloads overrides the workload collector. It exists so tests can
	// stall collection and prove the UI path never waits on the informers.
	collectWorkloads func(netpol.SubjectRef, []netpol.PodRef) ([]ui.SubjectWorkload, []string)

	// dataGen invalidates the projection caches whenever the evaluated result
	// or the enabled primitive kinds change.
	dataGen     uint64
	projections map[netpol.Direction]*projectionCache
	// rows memoizes one applicability projection per direction. The focus ring
	// asks about both directions on every Tab, so a single slot would evict the
	// focused pane's rows on every keystroke.
	rows map[netpol.Direction]*applicabilityMemo

	// pendingResult and pendingErr hold the newest queued notification of each
	// kind. The model reports a result and a partial-data failure back to back
	// for the same refresh, so a single slot would let the failure discard the
	// evaluation entirely.
	pendingResult *netpol.SubjectResult
	pendingErr    error
	updateQueued  bool
	refreshing    bool
	refreshQueued bool
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
		projections: make(map[netpol.Direction]*projectionCache, 2),
		rows:        make(map[netpol.Direction]*applicabilityMemo, 2),
		appFilters:  make(map[netpol.Direction]string, 2),
		kinds:       netpol.AllPrimitiveKinds(),
		mode:        ui.RulesProjection,
		focus:       netpol.Ingress,
		focusTarget: focusSubject,
	}
	for _, direction := range []netpol.Direction{netpol.Ingress, netpol.Egress} {
		v.state[direction] = &reachabilityDirectionState{
			visible: true,
			states: map[ui.ReachabilityProjection]reachabilityModeState{
				ui.RulesProjection:      {scroll: ui.ReachabilityScrollState{Cleared: true}},
				ui.PrimitivesProjection: {scroll: ui.ReachabilityScrollState{Cleared: true}},
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
	v.AddItem(v.subjectInfo, 0, 1, true)
	v.AddItem(v.directions, 0, 3, false)
	// The details pane is the flexible section: every section above it is
	// resized to its content at draw time and this one absorbs the remainder.
	v.AddItem(v.details, 0, 1, false)
	v.bindKeys()
	v.SetInputCapture(v.keyboard)
	v.rebuildDirections()
	v.updateSubject()
	v.showMessage("Waiting for NetworkPolicy evaluation...")
	// rebuildDirections anchors focus on a direction panel. The Tab ring starts
	// at the subject, so the view opens there instead.
	v.applyFocusTarget(focusSubject)
	return v
}

// Draw sizes every section from its own content before painting. tview flex
// proportions cannot express "as tall as the content, but no taller than a
// share of the screen", so the sizes are recomputed on each paint and pushed
// into the flex. This runs on the UI goroutine and must stay side-effect free:
// no focus changes, no detail pane rebuilds.
func (v *NetworkPolicyGraph) Draw(screen tcell.Screen) {
	v.applyLayout()
	v.Flex.Draw(screen)
}

// applyLayout gives each section the height its content needs, capped so the
// applicability table always keeps usable space, and hands whatever is left to
// the details pane.
func (v *NetworkPolicyGraph) applyLayout() {
	_, _, width, height := v.GetInnerRect()
	if width <= 0 || height <= 0 {
		return
	}
	// The applicability table is reserved first so the sections above it
	// compete for what is left rather than the other way round.
	applicability := max(minApplicabilityHeight, percentOf(height, applicabilityPercent))
	text := v.detailTextRequest(width, height)
	sizes := solveSectionHeights(height, text.size()+applicability, []sectionRequest{
		{desired: v.subjectInfo.ContentHeight(), min: minSectionHeight, max: percentOf(height, subjectMaxPercent)},
		{desired: v.directionsContentHeight(), min: minSectionHeight, max: percentOf(height, directionMaxPercent)},
	})
	v.ResizeItem(v.subjectInfo, sizes[0], 0)
	v.ResizeItem(v.directions, sizes[1], 0)
	v.ResizeItem(v.details, 0, 1)
	v.applyDetailLayout(applicability, height-sizes[0]-sizes[1], text)
}

// detailTextRequest sizes the rule detail text from its content. Panes that
// render a single widget report no request: they already fill the pane.
func (v *NetworkPolicyGraph) detailTextRequest(width, height int) sectionRequest {
	detail, ok := v.detailItem.(*ui.RuleDetails)
	if !ok {
		return sectionRequest{}
	}
	return sectionRequest{
		desired: detail.TextHeight(width),
		min:     minSectionHeight,
		max:     percentOf(height, detailTextMaxPercent),
	}
}

// applyDetailLayout splits the details pane between the rule text and the
// applicability table, which keeps everything the text does not need.
func (v *NetworkPolicyGraph) applyDetailLayout(applicability, available int, text sectionRequest) {
	detail, ok := v.detailItem.(*ui.RuleDetails)
	if !ok || available <= 0 {
		return
	}
	sizes := solveSectionHeights(available, applicability, []sectionRequest{text})
	detail.ResizeItem(detail.Text, sizes[0], 0)
	detail.ResizeItem(detail.Applicability, 0, 1)
}

// directionsContentHeight returns the tallest content among the visible
// direction panels, which is what the row of panels needs to render fully.
func (v *NetworkPolicyGraph) directionsContentHeight() int {
	height := 0
	if v.placeholder == nil {
		for _, direction := range []netpol.Direction{netpol.Ingress, netpol.Egress} {
			if v.state[direction].visible {
				height = max(height, v.panels[direction].ContentHeight())
			}
		}
	}
	return max(height, minSectionHeight)
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
// enabled; otherwise a single evaluation is performed.
func (v *NetworkPolicyGraph) Start() {
	v.stopWatch()
	v.ensureListeners()
	if v.app != nil && v.logoBadge == 0 {
		if logo := v.app.Logo(); logo != nil {
			v.logoBadge = logo.SetViewBadge("read-only graph", tcell.ColorYellow, tcell.ColorRed)
		}
	}
	if v.autoRefresh {
		v.startWatch()
		return
	}
	v.Refresh()
}

// Stop terminates graph updates and releases listeners.
func (v *NetworkPolicyGraph) Stop() {
	v.stopWatch()
	if v.logoBadge != 0 {
		if v.app != nil {
			if logo := v.app.Logo(); logo != nil {
				logo.ClearViewBadge(v.logoBadge)
			}
		}
		v.logoBadge = 0
	}
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

// Refresh immediately reevaluates the graph. Repeated presses collapse into a
// single follow-up evaluation instead of queueing an unbounded number of
// full-cluster snapshots behind the model's refresh lock.
func (v *NetworkPolicyGraph) Refresh() {
	if v.app == nil {
		return
	}
	v.mx.Lock()
	if v.refreshing {
		v.refreshQueued = true
		v.mx.Unlock()
		return
	}
	v.refreshing = true
	v.mx.Unlock()

	ctx := v.defaultCtx()
	go func() {
		for {
			if err := v.model.Refresh(ctx); err != nil {
				slog.Warn("NetworkPolicy graph refresh failed", slogs.Error, err)
			}
			v.mx.Lock()
			again := v.refreshQueued
			v.refreshQueued = false
			if !again {
				v.refreshing = false
			}
			v.mx.Unlock()
			if !again {
				return
			}
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
			v.app.Flash().Info("Auto-refresh is disabled")
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
	v.queueUpdate(&result, nil)
}

// NetPolGraphFailed reports failures while retaining any usable partial result.
func (v *NetworkPolicyGraph) NetPolGraphFailed(err error) {
	if v.app == nil {
		v.applyError(err)
		return
	}
	v.queueUpdate(nil, err)
}

// queueUpdate coalesces model notifications. Evaluations can complete faster
// than the UI can render them, and every queued update spawns a goroutine that
// contends for tview's fixed-size update queue; replaying stale notifications
// made the view appear permanently stuck.
//
// Results and failures are tracked separately on purpose. A partial-data
// refresh fires NetPolGraphChanged immediately followed by NetPolGraphFailed,
// and the queued drain cannot have run in between, so a single slot would let
// the failure overwrite - and silently discard - the evaluated result.
func (v *NetworkPolicyGraph) queueUpdate(result *netpol.SubjectResult, err error) {
	v.mx.Lock()
	if result != nil {
		v.pendingResult = result
	}
	if err != nil {
		v.pendingErr = err
	}
	queue := !v.updateQueued
	v.updateQueued = true
	v.mx.Unlock()
	if !queue {
		return
	}
	v.app.QueueUpdateDraw(v.drainPendingUpdate)
}

// drainPendingUpdate applies the newest queued notifications, the result first
// so a partial-data failure annotates it instead of replacing it.
func (v *NetworkPolicyGraph) drainPendingUpdate() {
	v.mx.Lock()
	result, err := v.pendingResult, v.pendingErr
	v.pendingResult, v.pendingErr, v.updateQueued = nil, nil, false
	v.mx.Unlock()
	if result != nil {
		v.applyResult(result)
	}
	if err != nil {
		v.applyError(err)
	}
}

func (v *NetworkPolicyGraph) applyError(err error) {
	v.lastError = err
	v.updateSubject()
	if !v.haveResult {
		v.showMessage("NetworkPolicy evaluation failed:\n" + err.Error())
		v.syncActions()
	} else {
		v.updateDetails(v.focus)
	}
}

func (v *NetworkPolicyGraph) applyResult(result *netpol.SubjectResult) {
	capturePanelState := v.haveResult
	v.result, v.haveResult, v.lastError = *result, true, nil
	v.invalidateProjections()
	for _, direction := range []netpol.Direction{netpol.Ingress, netpol.Egress} {
		// Capture the live cursor first: loadPanel restores from the saved
		// state, which would otherwise reset the panel to whatever position was
		// recorded the last time the selection changed.
		if capturePanelState {
			v.savePanelState(direction)
		}
		v.loadPanel(direction)
	}
	v.scheduleWorkloads()
	v.updateSubject()
	v.updateDetails(v.focus)
}

func (v *NetworkPolicyGraph) loadPanel(direction netpol.Direction) {
	panel, state := v.panels[direction], v.state[direction]
	modeState := state.states[v.mode]
	panel.SetProjection(v.mode).
		SetFilter(modeState.filter)
	if v.mode == ui.PrimitivesProjection && len(v.kinds) == 0 {
		panel.SetData(nil, nil).SetEmptyMessage("No primitive kinds selected. Press p to enable kinds.")
	} else {
		cache := v.projection(direction)
		panel.SetEmptyMessage("No reachability results match this view.").
			SetData(cache.rules, cache.primitives)
	}
	panel.RestoreScrollState(modeState.scroll)
}

func (v *NetworkPolicyGraph) savePanelState(direction netpol.Direction) {
	state := v.state[direction]
	modeState := state.states[v.mode]
	modeState.scroll = v.panels[direction].ScrollState()
	modeState.filter = v.panels[direction].Filter()
	state.states[v.mode] = modeState
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
		// Both panels just left the widget tree. Focus has to move with them or
		// tview drops the whole view out of the focus chain and every key dies.
		v.focusTarget = v.directionFocusTarget()
		if v.app != nil {
			v.app.SetFocus(v.placeholder)
		}
		return
	}
	v.placeholder = nil
	if !v.state[v.focus].visible {
		v.focus = v.firstVisibleDirection()
	}
	v.focusActiveDirection()
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

// switchMode toggles the projection for both directions. The mode is global:
// ingress and egress always render the same projection.
func (v *NetworkPolicyGraph) switchMode() {
	directions := []netpol.Direction{netpol.Ingress, netpol.Egress}
	for _, direction := range directions {
		v.savePanelState(direction)
	}
	if v.mode == ui.RulesProjection {
		v.mode = ui.PrimitivesProjection
	} else {
		v.mode = ui.RulesProjection
	}
	for _, direction := range directions {
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
	stops := v.focusStops()
	if len(stops) == 0 {
		return
	}
	step := 1
	if reverse {
		step = -1
	}
	current := v.currentStopIndex(stops)
	if current < 0 {
		// Focus sits on a stop that no longer exists. Enter the ring from
		// whichever end the key is heading towards rather than jumping across
		// it, which is what anchoring on the subject would do in reverse.
		if reverse {
			v.applyFocusStop(stops[len(stops)-1])
		} else {
			v.applyFocusStop(stops[0])
		}
		return
	}
	v.applyFocusStop(stops[(current+step+len(stops))%len(stops)])
}

// focusStop is one stop on the Tab ring. The detail stops repeat once per
// direction, so a stop has to name the direction it belongs to.
type focusStop struct {
	target    reachabilityFocus
	direction netpol.Direction
}

// focusStops lists the ring in order: subject, then each visible direction
// followed immediately by its own details and applicability. Keeping a
// direction's detail stops next to its panel means Tab reaches the ingress
// applicability without first walking through egress.
func (v *NetworkPolicyGraph) focusStops() []focusStop {
	stops := []focusStop{{target: focusSubject}}
	for _, direction := range []netpol.Direction{netpol.Ingress, netpol.Egress} {
		if !v.state[direction].visible {
			continue
		}
		stops = append(stops, focusStop{target: directionFocus(direction), direction: direction})
		details, applicability := v.detailStops(direction)
		if details {
			stops = append(stops, focusStop{target: focusDetails, direction: direction})
		}
		if applicability {
			stops = append(stops, focusStop{target: focusApplicability, direction: direction})
		}
	}
	return stops
}

// detailStops reports which detail stops a direction offers. It answers from
// the evaluated data rather than the rendered widget on purpose: the pane only
// ever holds the focused direction, but the ring has to place the other
// direction's stops too. It mirrors what renderDetails would build.
func (v *NetworkPolicyGraph) detailStops(direction netpol.Direction) (details, applicability bool) {
	if !v.haveResult || !v.state[direction].visible {
		return false, false
	}
	id := v.panels[direction].SelectedID()
	if id == "" {
		if v.mode == ui.PrimitivesProjection {
			return true, false
		}
		return true, len(v.visibleApplicability(direction, v.directionApplicability(direction))) > 0
	}
	if v.mode == ui.RulesProjection {
		rule, ok := v.selectedRule(direction, id)
		if !ok {
			return false, false
		}
		return true, len(v.visibleApplicability(direction, v.ruleApplicability(direction, rule.ID))) > 0
	}
	// Primitives render a plain text pane with no applicability table.
	_, ok := v.selectedPrimitive(direction, id)
	return ok, false
}

// currentStopIndex locates the ring position focus sits on, or -1 when focus is
// on no stop at all. The detail stops appear once per direction, so the active
// direction disambiguates them.
func (v *NetworkPolicyGraph) currentStopIndex(stops []focusStop) int {
	for index, stop := range stops {
		if stop.target != v.focusTarget {
			continue
		}
		if stop.target == focusSubject || stop.direction == v.focus {
			return index
		}
	}
	return -1
}

// applyFocusStop moves to a ring stop, switching the active direction first
// when the stop belongs to the other one. The detail pane only ever renders the
// active direction, so it has to be rebuilt before focus can land on it.
func (v *NetworkPolicyGraph) applyFocusStop(stop focusStop) {
	isDetail := stop.target == focusDetails || stop.target == focusApplicability
	if isDetail && v.focus != stop.direction && v.state[stop.direction].visible {
		v.focus = stop.direction
		// Set the target before rebuilding: renderDetails re-anchors focus
		// through refocusDetail once the new pane exists.
		v.focusTarget = stop.target
		v.updateDetails(stop.direction)
		return
	}
	v.applyFocusTarget(stop.target)
}

// Focus routes focus to the widget the view believes holds it. tview.Flex would
// otherwise always delegate to the item flagged at AddItem time, so every
// re-focus of the graph -- most visibly when a pushed view is popped back off
// the stack -- would land somewhere focusTarget does not name, leaving the key
// bindings acting on a pane the user cannot see highlighted.
func (v *NetworkPolicyGraph) Focus(delegate func(tview.Primitive)) {
	if target := v.focusPrimitive(); target != nil {
		delegate(target)
		return
	}
	v.Flex.Focus(delegate)
}

// focusPrimitive resolves focusTarget to a widget, mirroring the order
// applyFocusTarget falls back through. It never mutates: tview calls Focus
// during its own focus cycle, so this has to be a pure lookup.
func (v *NetworkPolicyGraph) focusPrimitive() tview.Primitive {
	switch v.focusTarget {
	case focusSubject:
		return v.subjectInfo
	case focusDetails, focusApplicability:
		if detail, ok := v.detailItem.(*ui.RuleDetails); ok {
			if v.focusTarget == focusApplicability {
				return detail.Applicability
			}
			return detail.Text
		}
		if v.detailItem != nil {
			return v.detailItem
		}
	}
	// Both directions hidden: the panels are no longer in the widget tree.
	if v.placeholder != nil {
		return v.placeholder
	}
	if state, ok := v.state[v.focus]; ok && state.visible {
		return v.panels[v.focus]
	}
	return v.subjectInfo
}

// applyFocusTarget moves focus to a target, falling back when the requested
// target no longer exists. tview only dispatches keys while the root reports
// focus, and a Flex reports focus only for its current items, so leaving focus
// on a widget that details.Clear() detached would silently kill every binding
// in the view.
func (v *NetworkPolicyGraph) applyFocusTarget(target reachabilityFocus) {
	v.focusTarget = target
	switch target {
	case focusSubject:
		if v.app != nil {
			v.app.SetFocus(v.subjectInfo)
		}
		v.syncActions()
		return
	case focusIngress:
		v.focus = netpol.Ingress
	case focusEgress:
		v.focus = netpol.Egress
	case focusDetails:
		if v.detailItem == nil {
			v.applyFocusTarget(v.directionFocusTarget())
			return
		}
		if v.app != nil {
			if detail, ok := v.detailItem.(*ui.RuleDetails); ok {
				v.app.SetFocus(detail.Text)
			} else {
				v.app.SetFocus(v.detailItem)
			}
		}
		v.syncActions()
		return
	case focusApplicability:
		if _, ok := v.detailItem.(*ui.RuleDetails); !ok {
			// The pane was rebuilt without a table, e.g. by toggling to
			// Primitives mode while the table had focus.
			v.applyFocusTarget(focusDetails)
			return
		}
		if v.app != nil {
			v.app.SetFocus(v.detailItem.(*ui.RuleDetails).Applicability)
		}
		v.syncActions()
		return
	}
	if v.app != nil {
		// With both directions hidden the panels are no longer in the widget
		// tree, so focusing one would drop the view out of tview's focus chain
		// and kill every binding.
		if v.placeholder != nil {
			v.app.SetFocus(v.placeholder)
		} else {
			v.app.SetFocus(v.panels[v.focus])
		}
	}
	v.updateDetails(v.focus)
}

// directionFocusTarget returns the focus target for the active direction panel.
func (v *NetworkPolicyGraph) directionFocusTarget() reachabilityFocus {
	return directionFocus(v.focus)
}

// directionFocus maps a direction onto its panel focus target.
func directionFocus(direction netpol.Direction) reachabilityFocus {
	if direction == netpol.Ingress {
		return focusIngress
	}
	return focusEgress
}

// focusActiveDirection returns focus to the active direction panel and records
// it. Dialogs must go through this rather than SetFocus, or focusTarget keeps
// pointing at a detail pane that no longer has focus and the next Enter or
// arrow key acts on the wrong pane.
func (v *NetworkPolicyGraph) focusActiveDirection() {
	v.applyFocusTarget(v.directionFocusTarget())
}

// refocusDetail re-anchors focus after the detail pane has been rebuilt.
func (v *NetworkPolicyGraph) refocusDetail() {
	if v.focusTarget == focusDetails || v.focusTarget == focusApplicability {
		v.applyFocusTarget(v.focusTarget)
	}
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
	extras = append(extras, v.workloadNotes...)
	if v.workloadsLoading {
		extras = append(extras, "workloads loading...")
	}
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
	v.subjectInfo.SetSubject(subject, podCount).SetSummary(summary).SetWorkloads(v.workloads)
}

// scheduleWorkloads recollects the subject workload rows off the UI goroutine.
// The listers behind the factory perform RBAC round trips and can block for
// seconds waiting on a cold informer cache, so collecting them inline froze the
// whole application on every evaluation.
func (v *NetworkPolicyGraph) scheduleWorkloads() {
	v.workloadSeq++
	if !v.haveResult {
		v.workloads, v.workloadNotes, v.workloadsLoading = nil, nil, false
		return
	}
	collect := v.workloadCollector()
	if collect == nil || v.app == nil {
		v.workloads, v.workloadNotes, v.workloadsLoading = nil, []string{"workloads unavailable: no resource factory"}, false
		return
	}
	seq, subject := v.workloadSeq, v.subject
	pods := slices.Clone(v.result.Subject.Pods)
	v.workloadsLoading = true
	go func() {
		workloads, notes := collect(subject, pods)
		v.app.QueueUpdateDraw(func() {
			// A newer evaluation already superseded this collection.
			if seq != v.workloadSeq {
				return
			}
			v.workloads, v.workloadNotes, v.workloadsLoading = workloads, notes, false
			v.updateSubject()
			// The rows landing auto-selects one, which is what decides whether
			// the Subject panel has any YAML to show. Without this the key
			// stays retracted until an unrelated event happens to resync it.
			v.syncActions()
		})
	}()
}

// workloadCollector returns the collector used to gather subject workload rows,
// or nil when no resource factory is available.
func (v *NetworkPolicyGraph) workloadCollector() func(netpol.SubjectRef, []netpol.PodRef) ([]ui.SubjectWorkload, []string) {
	if v.collectWorkloads != nil {
		return v.collectWorkloads
	}
	if v.app == nil || v.app.factory == nil {
		return nil
	}
	factory := v.app.factory
	return func(subject netpol.SubjectRef, pods []netpol.PodRef) ([]ui.SubjectWorkload, []string) {
		return collectSubjectWorkloads(factory, subject, pods)
	}
}

func collectSubjectWorkloads(factory dao.Factory, subject netpol.SubjectRef, pods []netpol.PodRef) ([]ui.SubjectWorkload, []string) {
	switch subject.Kind {
	case netpol.SubjectNamespace:
		return namespaceSubjectWorkloads(factory, subject.Name)
	case netpol.SubjectPod, netpol.SubjectDeployment, netpol.SubjectJob:
		return subjectPodWorkloads(factory, pods)
	default:
		return nil, nil
	}
}

func subjectPodWorkloads(factory dao.Factory, pods []netpol.PodRef) ([]ui.SubjectWorkload, []string) {
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
		objects, err := listUnstructured(factory, client.PodGVR, namespace)
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
			UID:       pod.UID,
			Status:    statuses[objectKey(pod.Namespace, pod.Name)],
		})
	}
	if truncated {
		notes = append(notes, fmt.Sprintf("workloads truncated at %d rows", subjectInfoRowLimit))
	}
	return workloads, notes
}

func namespaceSubjectWorkloads(factory dao.Factory, namespace string) ([]ui.SubjectWorkload, []string) {
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
		objects, err := listUnstructured(factory, spec.gvr, namespace)
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
				UID:       object.GetUID(),
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
func listUnstructured(factory dao.Factory, gvr *client.GVR, namespace string) ([]*unstructured.Unstructured, error) {
	objects, err := factory.List(gvr, namespace, true, labels.Everything())
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
	v.renderDetails(direction)
	v.syncActions()
}

func (v *NetworkPolicyGraph) renderDetails(direction netpol.Direction) {
	// The detail pane is rebuilt from scratch on every refresh, so remember
	// where the cursor was before dropping the old primitives.
	previous := v.captureDetailState()
	v.details.Clear()
	v.detailItem = nil
	v.detailShown = detailScrollState{}
	if !v.haveResult || !v.state[direction].visible {
		v.showMessage("No selected reachability result.")
		v.refocusDetail()
		return
	}
	id := v.panels[direction].SelectedID()
	if id == "" {
		v.showEffectiveDetails(direction, previous)
		return
	}
	var detail tview.Primitive
	if v.mode == ui.RulesProjection {
		rule, ok := v.selectedRule(direction, id)
		if !ok {
			v.showMessage("Selected rule is no longer available.")
			v.refocusDetail()
			return
		}
		rows := v.visibleApplicability(direction, v.ruleApplicability(direction, rule.ID))
		ruleDetail := ui.NewRuleDetailsWithStyle(rule, rows, v.reachabilityStyle())
		ruleDetail.Applicability.SetTitle(v.applicabilityTitle("Applicability", direction))
		v.applyDetailFocusStyle(ruleDetail)
		// Moving through the applicability rows changes what YAML is
		// reachable, so the key hints have to follow the cursor.
		ruleDetail.SetApplicabilityChangedFunc(func(string) { v.syncActions() })
		var text strings.Builder
		text.WriteString(v.detailPrefix(direction))
		text.WriteString("\n")
		text.WriteString(ui.RuleDetailsText(rule))
		v.appendResultWarnings(&text)
		ruleDetail.Text.SetText(ui.HighlightRuleStateWithStyle(strings.TrimSpace(text.String()), &rule, v.reachabilityStyle()))
		detail = ruleDetail
	} else {
		primitive, ok := v.selectedPrimitive(direction, id)
		if !ok {
			v.showMessage("Selected primitive is no longer available.")
			v.refocusDetail()
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
	v.restoreDetailState(previous)
	v.refocusDetail()
}

// showEffectiveDetails renders the direction's reachability after every rule has
// been applied. Rules mode includes the effective applicability table;
// Primitives mode omits it because the direction panels already show those rows.
func (v *NetworkPolicyGraph) showEffectiveDetails(direction netpol.Direction, previous detailScrollState) {
	allRows := v.directionApplicability(direction)
	body := v.effectiveDetailsText(direction, allRows)
	if v.mode == ui.PrimitivesProjection {
		detail := tview.NewTextView().
			SetText(tview.Escape(body)).
			SetScrollable(true).
			SetWrap(true)
		detail.SetBorder(true).SetTitle(" Effective Details ")
		v.applyTextFocusStyle(detail)
		v.details.AddItem(detail, 0, 1, false)
		v.detailItem = detail
	} else {
		rows := v.visibleApplicability(direction, allRows)
		detail := ui.NewEffectiveDetailsWithStyle(body, rows, direction, v.reachabilityStyle())
		detail.Applicability.SetTitle(v.applicabilityTitle("Effective Applicability", direction))
		v.applyDetailFocusStyle(detail)
		detail.SetApplicabilityChangedFunc(func(string) { v.syncActions() })
		v.details.AddItem(detail, 0, 1, false)
		v.detailItem = detail
	}
	v.detailShown = detailScrollState{direction: direction, effective: true}
	v.restoreDetailState(previous)
	v.refocusDetail()
}

func (v *NetworkPolicyGraph) effectiveDetailsText(direction netpol.Direction, rows []netpol.ApplicabilityRow) string {
	// Every state is enumerated so the breakdown always sums to the total.
	states := []netpol.AccessState{
		netpol.AccessAllowed,
		netpol.AccessPartial,
		netpol.AccessDisallowed,
		netpol.AccessUnknown,
		netpol.AccessPartialData,
	}
	counts := make(map[netpol.AccessState]int, len(states))
	for index := range rows {
		counts[rows[index].EffectiveState]++
	}
	breakdown := make([]string, 0, len(states))
	for _, state := range states {
		breakdown = append(breakdown, fmt.Sprintf("%s %d", strings.ToLower(state.String()), counts[state]))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\nMode: %s\nSelection: none (effective %s after all rules)\nKinds: %s\n",
		v.detailPrefix(direction), v.mode, direction, primitiveKindsSummary(v.kinds))
	fmt.Fprintf(&b, "Primitives: %d · %s\n", len(rows), strings.Join(breakdown, " · "))
	if len(rows) == 0 {
		b.WriteString("\nNo primitives match the enabled kinds for this direction.\n")
	}
	b.WriteString("\nThis is the aggregate result of every evaluated rule. Select a ")
	if v.mode == ui.PrimitivesProjection {
		b.WriteString("primitive")
	} else {
		b.WriteString("rule")
	}
	b.WriteString(" to inspect its individual contribution.\n")
	v.appendResultWarnings(&b)
	return strings.TrimSpace(b.String())
}

func (v *NetworkPolicyGraph) applicabilityTitle(prefix string, direction netpol.Direction) string {
	suffix := ""
	if v.mode == ui.RulesProjection && v.allowedOnly {
		suffix = " (Allowed only)"
	}
	title := fmt.Sprintf(" %s (%s)%s ", prefix, direction, suffix)
	if filter := v.appFilters[direction]; filter != "" {
		title = strings.TrimSuffix(title, " ") + fmt.Sprintf(" · filter: %s ", filter)
	}
	return title
}

// detailScrollState remembers what the detail pane renders and where its cursor
// sits so a refresh does not scroll the user back to the top of the rebuilt
// widgets.
type detailScrollState struct {
	direction     netpol.Direction
	selectionID   string
	effective     bool
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

// restoreDetailState reapplies a previously captured cursor, but only when the
// pane still renders the same thing. The effective pane carries no selection
// ID, so identity is compared on the whole triple.
func (v *NetworkPolicyGraph) restoreDetailState(state detailScrollState) {
	current := v.detailShown
	if state.direction != current.direction ||
		state.selectionID != current.selectionID ||
		state.effective != current.effective {
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
	cache := v.projection(direction)
	index, ok := cache.ruleIndex[id]
	if !ok {
		return netpol.RuleResult{}, false
	}
	return cache.rules[index], true
}

func (v *NetworkPolicyGraph) selectedPrimitive(direction netpol.Direction, id string) (netpol.PrimitiveResult, bool) {
	cache := v.projection(direction)
	index, ok := cache.primIndex[id]
	if !ok {
		return netpol.PrimitiveResult{}, false
	}
	return cache.primitives[index], true
}

// invalidateProjections drops the memoized projections. It must be called
// whenever the evaluated result or the subject changes. Changing the enabled
// kinds needs no call: they are part of the cache key.
func (v *NetworkPolicyGraph) invalidateProjections() {
	v.dataGen++
	clear(v.rows)
}

// kindMask encodes the enabled primitive kinds so the caches key on them
// directly rather than relying on every mutation site to invalidate.
func (v *NetworkPolicyGraph) kindMask() uint32 {
	var mask uint32
	for kind := range v.kinds {
		mask |= 1 << kind
	}
	return mask
}

// projection returns the memoized rule and primitive projections for a
// direction, rebuilding them only when the underlying data changed.
func (v *NetworkPolicyGraph) projection(direction netpol.Direction) *projectionCache {
	mask := v.kindMask()
	if cache, ok := v.projections[direction]; ok && cache.generation == v.dataGen && cache.kindMask == mask {
		return cache
	}
	cache := &projectionCache{
		generation: v.dataGen,
		kindMask:   mask,
		rules:      v.evaluator.Rules(v.result, direction),
		primitives: v.evaluator.Primitives(v.result, direction, v.kinds),
	}
	cache.ruleIndex = make(map[string]int, len(cache.rules))
	for index := range cache.rules {
		cache.ruleIndex[cache.rules[index].StableID()] = index
	}
	cache.primIndex = make(map[string]int, len(cache.primitives))
	for index := range cache.primitives {
		cache.primIndex[cache.primitives[index].StableID()] = index
	}
	v.projections[direction] = cache
	return cache
}

// ruleApplicability returns the applicability rows contributed by a single
// rule, reusing the last computation when the pane repaints unchanged.
func (v *NetworkPolicyGraph) ruleApplicability(direction netpol.Direction, id netpol.RuleID) []netpol.ApplicabilityRow {
	mask := v.kindMask()
	if memo := v.rows[direction]; memo != nil && memo.generation == v.dataGen && memo.kindMask == mask &&
		!memo.effective && memo.ruleID == id {
		return memo.rows
	}
	v.rows[direction] = &applicabilityMemo{
		generation: v.dataGen,
		kindMask:   mask,
		direction:  direction,
		ruleID:     id,
		rows:       v.evaluator.RuleApplicability(v.result, direction, id, v.kinds),
	}
	return v.rows[direction].rows
}

// directionApplicability returns the effective applicability rows for a whole
// direction, reusing the last computation when the pane repaints unchanged.
func (v *NetworkPolicyGraph) directionApplicability(direction netpol.Direction) []netpol.ApplicabilityRow {
	mask := v.kindMask()
	if memo := v.rows[direction]; memo != nil && memo.generation == v.dataGen && memo.kindMask == mask &&
		memo.effective {
		return memo.rows
	}
	v.rows[direction] = &applicabilityMemo{
		generation: v.dataGen,
		kindMask:   mask,
		direction:  direction,
		effective:  true,
		rows:       v.evaluator.DirectionApplicability(v.result, direction, v.kinds),
	}
	return v.rows[direction].rows
}

func (v *NetworkPolicyGraph) visibleApplicability(
	direction netpol.Direction,
	rows []netpol.ApplicabilityRow,
) []netpol.ApplicabilityRow {
	filter := strings.TrimSpace(v.appFilters[direction])
	if (v.mode != ui.RulesProjection || !v.allowedOnly) && filter == "" {
		return rows
	}
	visible := make([]netpol.ApplicabilityRow, 0, len(rows))
	for index := range rows {
		row := &rows[index]
		if v.mode == ui.RulesProjection && v.allowedOnly && row.EffectiveState != netpol.AccessAllowed {
			continue
		}
		if !matchesApplicabilityFilter(row, filter) {
			continue
		}
		visible = append(visible, *row)
	}
	return visible
}

func matchesApplicabilityFilter(row *netpol.ApplicabilityRow, filter string) bool {
	if filter == "" {
		return true
	}
	ref := &row.Primitive.Ref
	peer := fmt.Sprintf("%t", row.PeerMatches)
	opposite := fmt.Sprintf("%t", row.OppositeSideAllows)
	ports := applicabilityPermissionsText(row.Permissions)
	if ref.Kind == netpol.PrimitiveCIDR {
		opposite = "n/a"
	}
	if row.Primitive.TotalPairs == 0 {
		peer, opposite, ports = "n/a", "n/a", "n/a"
	}
	displayed := []string{
		applicabilityPrimitiveText(ref),
		peer,
		opposite,
		row.EffectiveState.String(),
		ports,
	}
	return strings.Contains(
		strings.ToLower(strings.Join(displayed, " ")),
		strings.ToLower(strings.TrimSpace(filter)),
	)
}

func applicabilityPrimitiveText(ref *netpol.PrimitiveRef) string {
	valueOrDash := func(value string) string {
		if value == "" {
			return "—"
		}
		return value
	}
	if ref.Kind == netpol.PrimitiveCIDR {
		if len(ref.CIDRExcept) == 0 {
			return "CIDR " + valueOrDash(ref.CIDR)
		}
		return fmt.Sprintf("CIDR %s (except %s)", valueOrDash(ref.CIDR), strings.Join(ref.CIDRExcept, ", "))
	}
	name := ref.Name
	if ref.Namespace != "" {
		name = ref.Namespace + "/" + name
	}
	return ref.Kind.String() + " " + valueOrDash(name)
}

func applicabilityPermissionsText(permissions []netpol.PortPermission) string {
	if len(permissions) == 0 {
		return "no ports"
	}
	values := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		values = append(values, permission.String())
	}
	return strings.Join(values, ", ")
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
		v.focusActiveDirection()
	}, func() {
		v.app.Content.RemovePage(netPolKindsDialogPage)
		v.focusActiveDirection()
	})
	styleForm(dialog.Form, &styles)
	modal := tview.NewModalForm("<Primitive Kinds (global)>", dialog.Form)
	modal.SetBackgroundColor(styles.BgColor.Color()).SetTextColor(styles.FgColor.Color())
	ui.SizePrimitiveKindDialog(modal, dialog.Form, 0, 0)
	modal.SetDoneFunc(func(int, string) { dialog.Cancel() })
	v.app.Content.AddPage(netPolKindsDialogPage, modal, false, false)
	v.app.Content.ShowPage(netPolKindsDialogPage)
	v.app.SetFocus(modal)
}

func (v *NetworkPolicyGraph) openSearchDialog() {
	target := v.searchTarget()
	if v.app == nil || target == searchNone {
		return
	}
	stop := focusStop{target: v.focusTarget, direction: v.focus}
	finish := func() {
		v.app.Content.RemovePage(netPolSearchPage)
		v.restoreSearchFocus(stop)
	}
	styles := v.app.Styles.Dialog()
	input := tview.NewInputField().
		SetLabel("Filter: ").
		SetText(v.searchFilter(target, v.focus))
	form := tview.NewForm().
		AddFormItem(input).
		AddButton("Apply", func() {
			v.applySearchTarget(target, stop.direction, input.GetText())
			finish()
		}).
		AddButton("Clear", func() {
			v.applySearchTarget(target, stop.direction, "")
			finish()
		}).
		AddButton("Cancel", func() {
			finish()
		})
	form.SetCancelFunc(func() {
		finish()
	})
	styleForm(form, &styles)
	modal := tview.NewModalForm("<Reachability Search>", form)
	modal.SetBackgroundColor(styles.BgColor.Color()).SetTextColor(styles.FgColor.Color())
	modal.SetDoneFunc(func(int, string) {
		finish()
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
	picker := ui.NewSubjectPickerWithPublisher(&styles, subjectKinds(), v.loadSubjects,
		// Listing subjects hits the informers, which can block for seconds; the
		// picker loads them off the UI goroutine and publishes back through here.
		v.app.QueueUpdateDraw,
		func(ref netpol.SubjectRef) {
			v.app.Content.RemovePage(netPolSubjectPage)
			v.applySubject(ref)
		}, func() {
			v.app.Content.RemovePage(netPolSubjectPage)
			v.focusActiveDirection()
		})
	v.app.Content.AddPage(netPolSubjectPage, picker, false, false)
	v.app.Content.ShowPage(netPolSubjectPage)
	v.app.SetFocus(picker)
}

func (v *NetworkPolicyGraph) applySubject(ref netpol.SubjectRef) {
	v.subject = ref
	v.model.SetSubject(ref)
	v.result, v.haveResult, v.lastError = netpol.SubjectResult{}, false, nil
	v.invalidateProjections()
	for _, direction := range []netpol.Direction{netpol.Ingress, netpol.Egress} {
		state := v.state[direction]
		for projection, modeState := range state.states {
			modeState.scroll = ui.ReachabilityScrollState{Cleared: true}
			state.states[projection] = modeState
		}
		v.loadPanel(direction)
	}
	v.scheduleWorkloads()
	v.updateSubject()
	v.applyFocusTarget(focusSubject)
	v.showMessage("Waiting for NetworkPolicy evaluation...")
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

func (v *NetworkPolicyGraph) searchTarget() reachabilitySearchTarget {
	switch v.focusTarget {
	case focusSubject:
		return searchSubject
	case focusIngress, focusEgress:
		if v.state[v.focus].visible {
			return searchDirection
		}
	case focusApplicability:
		if _, ok := v.detailItem.(*ui.RuleDetails); ok {
			return searchApplicability
		}
	case focusDetails:
		if v.detailShown.effective {
			return searchNone
		}
		switch v.detailItem.(type) {
		case *ui.RuleDetails:
			return searchApplicability
		case *tview.TextView:
			if v.mode == ui.PrimitivesProjection && v.state[v.focus].visible &&
				v.panels[v.focus].SelectedID() != "" {
				return searchDirection
			}
		}
	}
	return searchNone
}

func (v *NetworkPolicyGraph) searchFilter(target reachabilitySearchTarget, direction netpol.Direction) string {
	switch target {
	case searchSubject:
		return v.subjectInfo.Filter()
	case searchDirection:
		return v.state[direction].states[v.mode].filter
	case searchApplicability:
		return v.appFilters[direction]
	default:
		return ""
	}
}

func (v *NetworkPolicyGraph) applySearch(filter string) {
	v.applySearchTarget(v.searchTarget(), v.focus, filter)
}

func (v *NetworkPolicyGraph) applySearchTarget(
	target reachabilitySearchTarget,
	direction netpol.Direction,
	filter string,
) {
	switch target {
	case searchSubject:
		v.subjectInfo.SetFilter(filter)
	case searchDirection:
		state := v.state[direction]
		modeState := state.states[v.mode]
		modeState.filter = filter
		state.states[v.mode] = modeState
		v.panels[direction].SetFilter(filter)
		v.savePanelState(direction)
		if direction == v.focus {
			v.updateDetails(direction)
		}
	case searchApplicability:
		v.appFilters[direction] = filter
		if direction == v.focus {
			v.updateDetails(direction)
		}
	}
}

func (v *NetworkPolicyGraph) restoreSearchFocus(stop focusStop) {
	if stop.target != focusSubject && v.state[stop.direction].visible {
		v.focus = stop.direction
	}
	v.applyFocusTarget(stop.target)
}

// selectedRulePolicy returns the policy behind the direction's selected rule.
func (v *NetworkPolicyGraph) selectedRulePolicy(direction netpol.Direction) (namespace, name string, found bool) {
	if !v.state[direction].visible {
		return "", "", false
	}
	id := v.panels[direction].SelectedID()
	if id == "" {
		return "", "", false
	}
	rule, ok := v.selectedRule(direction, id)
	if !ok || rule.Synthetic || rule.ID.PolicyName == "" {
		return "", "", false
	}
	return rule.ID.PolicyNamespace, rule.ID.PolicyName, true
}

func (v *NetworkPolicyGraph) yamlCmd(_ *tcell.EventKey) *tcell.EventKey {
	gvr, path, ok := v.yamlTarget()
	if !ok {
		if v.app != nil {
			v.app.Flash().Errf("the current selection has no YAML to show")
		}
		return nil
	}
	if v.app == nil {
		return nil
	}
	live := NewLiveView(v.app, yamlAction, model.NewYAML(gvr, path))
	if err := v.app.inject(live, false); err != nil {
		v.app.Flash().Err(err)
	}
	return nil
}

// yamlTarget resolves whatever the focused section has selected to the resource
// whose YAML should be shown. Selections with no backing manifest -- CIDR
// primitives, synthetic rules, an empty selection -- report no target so the
// key stays hidden.
func (v *NetworkPolicyGraph) yamlTarget() (gvr *client.GVR, path string, found bool) {
	switch v.focusTarget {
	case focusSubject:
		return v.workloadYAMLTarget()
	case focusApplicability:
		return v.applicabilityYAMLTarget()
	case focusIngress, focusEgress, focusDetails:
		// The detail pane always mirrors the focused direction's selection.
		return v.directionYAMLTarget(v.focus)
	default:
		return nil, "", false
	}
}

func (v *NetworkPolicyGraph) workloadYAMLTarget() (*client.GVR, string, bool) {
	id := v.subjectInfo.SelectedID()
	if id == "" {
		return nil, "", false
	}
	index := slices.IndexFunc(v.workloads, func(item ui.SubjectWorkload) bool { return item.ID() == id })
	if index < 0 {
		return nil, "", false
	}
	workload := v.workloads[index]
	gvr, ok := workloadGVR(workload.Kind)
	if !ok {
		return nil, "", false
	}
	return gvr, objectKey(workload.Namespace, workload.Name), true
}

func (v *NetworkPolicyGraph) directionYAMLTarget(direction netpol.Direction) (*client.GVR, string, bool) {
	if !v.state[direction].visible {
		return nil, "", false
	}
	id := v.panels[direction].SelectedID()
	if id == "" {
		return nil, "", false
	}
	if v.mode == ui.RulesProjection {
		namespace, name, ok := v.selectedRulePolicy(direction)
		if !ok {
			return nil, "", false
		}
		return client.NpGVR, objectKey(namespace, name), true
	}
	primitive, ok := v.selectedPrimitive(direction, id)
	if !ok {
		return nil, "", false
	}
	return primitiveGVR(&primitive.Ref)
}

func (v *NetworkPolicyGraph) applicabilityYAMLTarget() (*client.GVR, string, bool) {
	detail, ok := v.detailItem.(*ui.RuleDetails)
	if !ok {
		return nil, "", false
	}
	id := detail.SelectedApplicabilityID()
	if id == "" {
		return nil, "", false
	}
	primitive, ok := v.selectedPrimitive(v.focus, id)
	if !ok {
		return nil, "", false
	}
	return primitiveGVR(&primitive.Ref)
}

// workloadGVR maps a subject workload kind to its GVR. The kinds are the ones
// produced by the workload collector.
func workloadGVR(kind string) (*client.GVR, bool) {
	switch kind {
	case "Pod":
		return client.PodGVR, true
	case "Deployment":
		return client.DpGVR, true
	case "ReplicaSet":
		return client.RsGVR, true
	case "StatefulSet":
		return client.StsGVR, true
	case "DaemonSet":
		return client.DsGVR, true
	case "Job":
		return client.JobGVR, true
	default:
		return nil, false
	}
}

// primitiveGVR maps a primitive to the resource whose YAML describes it. CIDR
// primitives are not Kubernetes resources and report no target.
func primitiveGVR(ref *netpol.PrimitiveRef) (*client.GVR, string, bool) {
	command, path := primitiveCommand(ref)
	switch command {
	case "pods":
		return client.PodGVR, path, true
	case "namespaces":
		return client.NsGVR, path, true
	case "deployments":
		return client.DpGVR, path, true
	case "jobs":
		return client.JobGVR, path, true
	default:
		return nil, "", false
	}
}

// escapeCmd clears the focused panel selection so the details pane shows the
// direction's effective applicability. With nothing selected it falls through
// to the standard back navigation.
func (v *NetworkPolicyGraph) escapeCmd(evt *tcell.EventKey) *tcell.EventKey {
	if v.state[v.focus].visible && v.panels[v.focus].HasSelection() {
		v.panels[v.focus].ClearSelection()
		v.savePanelState(v.focus)
		v.updateDetails(v.focus)
		return nil
	}
	if v.app != nil {
		return v.app.PrevCmd(evt)
	}
	return evt
}

// focusDirectionCmd focuses a direction panel, but only while the arrows still
// belong to the view. Once focus sits inside the detail pane the event is
// handed to the widget so its text and table can scroll horizontally.
func (v *NetworkPolicyGraph) focusDirectionCmd(direction netpol.Direction) func(*tcell.EventKey) *tcell.EventKey {
	return func(evt *tcell.EventKey) *tcell.EventKey {
		if v.focusTarget == focusDetails || v.focusTarget == focusApplicability {
			return evt
		}
		v.focusDirection(direction)
		return nil
	}
}

// enterCmd walks focus into the detail pane so applicability rows can be
// scrolled. Applicability owns Enter as an inert navigation key; resources are
// opened consistently with "o".
func (v *NetworkPolicyGraph) enterCmd(evt *tcell.EventKey) *tcell.EventKey {
	switch v.focusTarget {
	case focusSubject:
		// The view opens here, so Enter has to lead somewhere rather than
		// being the one key that does nothing on the default focus.
		if !v.state[v.focus].visible {
			return evt
		}
		v.focusDirection(v.focus)
		return nil
	case focusIngress, focusEgress:
		return v.focusDetailPane(evt)
	case focusApplicability:
		return evt
	case focusDetails:
		if v.mode != ui.PrimitivesProjection ||
			!v.state[v.focus].visible ||
			v.panels[v.focus].SelectedID() == "" {
			return evt
		}
		return v.openPrimitiveCmd(evt)
	default:
		return evt
	}
}

func (v *NetworkPolicyGraph) directionPrimitiveTarget(direction netpol.Direction) (command, path string, err error) {
	id := v.panels[direction].SelectedID()
	if !v.state[direction].visible || id == "" {
		return "", "", errNoPrimitiveTarget
	}
	if v.mode == ui.RulesProjection {
		namespace, name, ok := v.selectedRulePolicy(direction)
		if !ok {
			return "", "", errNoPrimitiveTarget
		}
		return "networkpolicies", objectKey(namespace, name), nil
	}
	primitive, ok := v.selectedPrimitive(direction, id)
	if !ok {
		return "", "", errPrimitiveUnavailable
	}
	command, path = primitiveCommand(&primitive.Ref)
	if command == "" {
		return "", "", errPrimitiveNotResource
	}
	return command, path, nil
}

// focusDetailPane moves focus onto the applicability table when one is
// rendered, and onto the detail text otherwise. It works with an empty panel
// selection because the effective pane also renders an applicability table, and
// it never swallows the key without moving focus or explaining why.
func (v *NetworkPolicyGraph) focusDetailPane(evt *tcell.EventKey) *tcell.EventKey {
	details, applicability := v.detailStops(v.focus)
	if applicability {
		v.applyFocusTarget(focusApplicability)
		return nil
	}
	if details {
		v.applyFocusTarget(focusDetails)
		return nil
	}
	if v.app != nil {
		v.app.Flash().Info("No details to focus")
		return nil
	}
	return evt
}

var (
	errNoApplicabilityTable = errors.New("the detail pane renders no applicability table")
	errNoApplicabilityRow   = errors.New("no applicability row is highlighted")
	errNoPrimitiveTarget    = errors.New("no Kubernetes primitive is selected")
	errPrimitiveUnavailable = errors.New("the highlighted primitive is no longer available")
	errPrimitiveNotResource = errors.New("the highlighted primitive is not a Kubernetes resource")
)

// applicabilityTarget resolves the highlighted applicability row to the k9s
// command and resource path that renders its primitive. Applicability rows are
// built from the same kind-filtered primitive set as the panels, so the row's
// stable ID always resolves against that projection.
func (v *NetworkPolicyGraph) applicabilityTarget() (command, path string, err error) {
	detail, ok := v.detailItem.(*ui.RuleDetails)
	if !ok {
		return "", "", errNoApplicabilityTable
	}
	id := detail.SelectedApplicabilityID()
	if id == "" {
		return "", "", errNoApplicabilityRow
	}
	primitive, ok := v.selectedPrimitive(v.focus, id)
	if !ok {
		return "", "", errPrimitiveUnavailable
	}
	command, path = primitiveCommand(&primitive.Ref)
	if command == "" {
		return "", "", errPrimitiveNotResource
	}
	return command, path, nil
}

func (v *NetworkPolicyGraph) applicabilitySubjectTarget() (netpol.SubjectRef, bool) {
	if v.mode != ui.RulesProjection || v.focusTarget != focusApplicability {
		return netpol.SubjectRef{}, false
	}
	detail, ok := v.detailItem.(*ui.RuleDetails)
	if !ok {
		return netpol.SubjectRef{}, false
	}
	id := detail.SelectedApplicabilityID()
	if id == "" {
		return netpol.SubjectRef{}, false
	}
	primitive, ok := v.selectedPrimitive(v.focus, id)
	if !ok {
		return netpol.SubjectRef{}, false
	}
	ref := netpol.SubjectRef{Name: primitive.Ref.Name, UID: primitive.Ref.UID}
	switch primitive.Ref.Kind {
	case netpol.PrimitivePod:
		ref.Kind, ref.Namespace = netpol.SubjectPod, primitive.Ref.Namespace
	case netpol.PrimitiveDeployment:
		ref.Kind, ref.Namespace = netpol.SubjectDeployment, primitive.Ref.Namespace
	case netpol.PrimitiveJob:
		ref.Kind, ref.Namespace = netpol.SubjectJob, primitive.Ref.Namespace
	case netpol.PrimitiveNamespace:
		ref.Kind = netpol.SubjectNamespace
	default:
		return netpol.SubjectRef{}, false
	}
	return ref, true
}

func (v *NetworkPolicyGraph) subjectWorkloadTarget() (netpol.SubjectRef, bool) {
	if v.focusTarget != focusSubject {
		return netpol.SubjectRef{}, false
	}
	id := v.subjectInfo.SelectedID()
	index := slices.IndexFunc(v.workloads, func(item ui.SubjectWorkload) bool {
		return item.ID() == id
	})
	if index < 0 {
		return netpol.SubjectRef{}, false
	}
	workload := &v.workloads[index]
	ref := netpol.SubjectRef{
		Namespace: workload.Namespace,
		Name:      workload.Name,
		UID:       workload.UID,
	}
	switch workload.Kind {
	case "Pod":
		ref.Kind = netpol.SubjectPod
	case "Deployment":
		ref.Kind = netpol.SubjectDeployment
	case "Job":
		ref.Kind = netpol.SubjectJob
	default:
		return netpol.SubjectRef{}, false
	}
	return ref, true
}

func (v *NetworkPolicyGraph) subjectPromotionTarget() (netpol.SubjectRef, bool) {
	if ref, ok := v.subjectWorkloadTarget(); ok {
		return ref, true
	}
	return v.applicabilitySubjectTarget()
}

// openPrimitiveTarget resolves the native Kubernetes resource selected by the
// focused pane. Rule detail text is intentionally excluded: only its
// applicability rows identify primitives.
func (v *NetworkPolicyGraph) openPrimitiveTarget() (command, path string, err error) {
	switch v.focusTarget {
	case focusSubject:
		gvr, resourcePath, ok := v.workloadYAMLTarget()
		if !ok {
			return "", "", errNoPrimitiveTarget
		}
		return gvr.GVR().Resource, resourcePath, nil
	case focusIngress, focusEgress:
		return v.directionPrimitiveTarget(v.focus)
	case focusApplicability:
		return v.applicabilityTarget()
	case focusDetails:
		if v.mode != ui.PrimitivesProjection {
			return "", "", errNoPrimitiveTarget
		}
		return v.directionPrimitiveTarget(v.focus)
	default:
		return "", "", errNoPrimitiveTarget
	}
}

// openPrimitiveCmd opens the native Kubernetes resource selected by the
// focused pane and pushes it onto the view stack.
func (v *NetworkPolicyGraph) openPrimitiveCmd(evt *tcell.EventKey) *tcell.EventKey {
	if v.app == nil {
		return evt
	}
	command, path, err := v.openPrimitiveTarget()
	if err != nil {
		if errors.Is(err, errPrimitiveNotResource) {
			v.app.Flash().Errf("CIDR primitives are not Kubernetes resources")
		} else {
			v.app.Flash().Info(err.Error())
		}
		return nil
	}
	v.app.gotoResource(command, path, false, true)
	return nil
}

func (v *NetworkPolicyGraph) applySubjectPromotionCmd(evt *tcell.EventKey) *tcell.EventKey {
	ref, ok := v.subjectPromotionTarget()
	if !ok {
		return evt
	}
	v.applySubject(ref)
	return nil
}

func (v *NetworkPolicyGraph) toggleAllowedOnly() {
	if v.mode != ui.RulesProjection {
		return
	}
	v.allowedOnly = !v.allowedOnly
	v.updateDetails(v.focus)
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
		ui.KeyI:          ui.NewKeyAction("Toggle Ingress", func(*tcell.EventKey) *tcell.EventKey { v.toggleDirection(netpol.Ingress); return nil }, true),
		ui.KeyE:          ui.NewKeyAction("Toggle Egress", func(*tcell.EventKey) *tcell.EventKey { v.toggleDirection(netpol.Egress); return nil }, true),
		ui.KeyM:          ui.NewKeyAction("Toggle Mode", func(*tcell.EventKey) *tcell.EventKey { v.switchMode(); return nil }, true),
		ui.KeyP:          ui.NewKeyAction("Primitive Kinds", func(*tcell.EventKey) *tcell.EventKey { v.openKindsDialog(); return nil }, true),
		ui.KeyS:          ui.NewKeyAction("Subject", func(*tcell.EventKey) *tcell.EventKey { v.openSubjectDialog(); return nil }, true),
		ui.KeyR:          ui.NewKeyAction("Toggle Auto-Refresh", func(*tcell.EventKey) *tcell.EventKey { v.toggleAutoRefresh(); return nil }, true),
		tcell.KeyEnter:   ui.NewKeyAction("Focus Details/Open", v.enterCmd, false),
		tcell.KeyEscape:  ui.NewKeyAction("Clear Selection/Back", v.escapeCmd, false),
		tcell.KeyLeft:    ui.NewKeyAction("Focus Ingress", v.focusDirectionCmd(netpol.Ingress), false),
		tcell.KeyRight:   ui.NewKeyAction("Focus Egress", v.focusDirectionCmd(netpol.Egress), false),
		tcell.KeyTAB:     ui.NewKeyAction("Next Panel", func(*tcell.EventKey) *tcell.EventKey { v.cycleFocus(false); return nil }, false),
		tcell.KeyBacktab: ui.NewKeyAction("Previous Panel", func(*tcell.EventKey) *tcell.EventKey { v.cycleFocus(true); return nil }, false),
	})
	v.syncActions()
}

// syncActions binds the selection sensitive keys only while they have something
// to act on, so the menu never advertises an action that would just flash an
// error. It must run after anything that changes focus, mode, or a selection.
func (v *NetworkPolicyGraph) syncActions() {
	if v.searchTarget() != searchNone {
		v.actions.Add(ui.KeySlash, ui.NewKeyAction("Search", func(*tcell.EventKey) *tcell.EventKey {
			v.openSearchDialog()
			return nil
		}, true))
	} else {
		v.actions.Delete(ui.KeySlash)
	}
	if v.mode == ui.RulesProjection {
		v.actions.Add(ui.KeyA, ui.NewKeyAction("Allowed Only", func(*tcell.EventKey) *tcell.EventKey {
			v.toggleAllowedOnly()
			return nil
		}, true))
	} else {
		v.actions.Delete(ui.KeyA)
	}
	if _, ok := v.subjectPromotionTarget(); ok {
		v.actions.Add(tcell.KeyCtrlS, ui.NewKeyAction("Set As Subject", v.applySubjectPromotionCmd, true))
	} else {
		v.actions.Delete(tcell.KeyCtrlS)
	}
	if _, _, err := v.openPrimitiveTarget(); err == nil {
		v.actions.Add(ui.KeyO, ui.NewKeyAction(openPrimitiveHint, v.openPrimitiveCmd, true))
	} else {
		v.actions.Delete(ui.KeyO)
	}
	if _, _, ok := v.yamlTarget(); ok {
		v.actions.Add(ui.KeyY, ui.NewKeyAction("YAML", v.yamlCmd, true))
	} else {
		v.actions.Delete(ui.KeyY)
	}
	// Only the visible component owns the menu. Repainting it from a background
	// evaluation that landed after the user navigated away would clobber the
	// hints of whatever view is now on top.
	if v.app != nil && v.listening {
		v.app.Menu().HydrateMenu(v.Hints())
	}
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
		// SetStyles rather than SetReachabilityStyle: it also refreshes the
		// cursor colors and the neutral color used for synthetic rows, neither
		// of which is carried by config.Reachability.
		panel.SetStyles(styles)
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

// Name returns the component name used for breadcrumbs.
func (*NetworkPolicyGraph) Name() string { return netPolGraphCrumb }

// InCmdMode reports whether a command buffer owns input.
func (*NetworkPolicyGraph) InCmdMode() bool { return false }

// SetCommand records the command used to open this view.
func (v *NetworkPolicyGraph) SetCommand(command *cmd.Interpreter) { v.command = command }

// SetFilter applies an initial text filter to both directions in the current mode.
func (v *NetworkPolicyGraph) SetFilter(filter string, _ bool) {
	for _, direction := range []netpol.Direction{netpol.Ingress, netpol.Egress} {
		state := v.state[direction]
		modeState := state.states[v.mode]
		modeState.filter = filter
		state.states[v.mode] = modeState
		v.panels[direction].SetFilter(filter)
	}
}

// SetLabelSelector is unsupported for evaluated reachability.
func (*NetworkPolicyGraph) SetLabelSelector(labels.Selector, bool) {}
