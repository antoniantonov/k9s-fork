// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package view

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/derailed/k9s/internal/client"
	"github.com/derailed/k9s/internal/config"
	"github.com/derailed/k9s/internal/model"
	"github.com/derailed/k9s/internal/netpol"
	"github.com/derailed/k9s/internal/ui"
	"github.com/derailed/k9s/internal/view/cmd"
	"github.com/derailed/tcell/v2"
	"github.com/derailed/tview"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
)

func TestNetworkPolicyGraphCommand(t *testing.T) {
	uu := map[string]struct {
		kind string
		fqn  string
		want string
	}{
		"pod": {
			kind: "pod",
			fqn:  "payments/api",
			want: "npg pod api payments",
		},
		"deployment": {
			kind: "deployment",
			fqn:  "payments/api",
			want: "npg deployment api payments",
		},
		"job": {
			kind: "job",
			fqn:  "ops/cleanup",
			want: "npg job cleanup ops",
		},
		"namespace": {
			kind: "namespace",
			fqn:  "payments",
			want: "npg namespace payments",
		},
	}
	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.want, networkPolicyGraphCommand(u.kind, u.fqn))
		})
	}
}

type fakeNetPolGraphModel struct {
	mx        sync.Mutex
	subject   netpol.SubjectRef
	result    netpol.SubjectResult
	refresh   model.NetPolGraphRefresh
	listeners []model.NetPolGraphListener
	watches   int
	refreshes int
	err       error
}

func (m *fakeNetPolGraphModel) SetSubject(subject netpol.SubjectRef) { m.subject = subject }
func (m *fakeNetPolGraphModel) Subject() netpol.SubjectRef           { return m.subject }
func (m *fakeNetPolGraphModel) LastRefresh() model.NetPolGraphRefresh {
	return m.refresh
}
func (m *fakeNetPolGraphModel) AddListener(listener model.NetPolGraphListener) {
	m.listeners = append(m.listeners, listener)
}
func (m *fakeNetPolGraphModel) RemoveListener(listener model.NetPolGraphListener) {
	for index, candidate := range m.listeners {
		if candidate == listener {
			m.listeners = append(m.listeners[:index], m.listeners[index+1:]...)
			return
		}
	}
}
func (m *fakeNetPolGraphModel) Watch(context.Context) error {
	m.mx.Lock()
	defer m.mx.Unlock()
	m.watches++
	return m.err
}
func (m *fakeNetPolGraphModel) watchCount() int {
	m.mx.Lock()
	defer m.mx.Unlock()
	return m.watches
}
func (*fakeNetPolGraphModel) Stop() {}
func (m *fakeNetPolGraphModel) Refresh(context.Context) error {
	m.mx.Lock()
	defer m.mx.Unlock()
	m.refreshes++
	return m.err
}
func (m *fakeNetPolGraphModel) Peek() (netpol.SubjectResult, bool) {
	return m.result, m.result.Subject.Ref.Name != ""
}
func (m *fakeNetPolGraphModel) refreshCount() int {
	m.mx.Lock()
	defer m.mx.Unlock()
	return m.refreshes
}

func TestNetworkPolicyGraphSubjectMapping(t *testing.T) {
	tests := []struct {
		name      string
		args      cmd.NetworkPolicyGraphArgs
		activeNS  string
		expected  netpol.SubjectRef
		errorText string
	}{
		{
			name:     "pod uses active namespace",
			args:     cmd.NetworkPolicyGraphArgs{Kind: "pod", Name: "api"},
			activeNS: "payments",
			expected: netpol.SubjectRef{Kind: netpol.SubjectPod, Namespace: "payments", Name: "api"},
		},
		{
			name:     "explicit deployment namespace",
			args:     cmd.NetworkPolicyGraphArgs{Kind: "deployment", Name: "api", Namespace: "prod"},
			activeNS: "payments",
			expected: netpol.SubjectRef{Kind: netpol.SubjectDeployment, Namespace: "prod", Name: "api"},
		},
		{
			name:     "namespace is cluster scoped",
			args:     cmd.NetworkPolicyGraphArgs{Kind: "namespace", Name: "payments"},
			activeNS: "ignored",
			expected: netpol.SubjectRef{Kind: netpol.SubjectNamespace, Name: "payments"},
		},
		{
			name:      "all namespaces is actionable",
			args:      cmd.NetworkPolicyGraphArgs{Kind: "job", Name: "cleanup"},
			activeNS:  "all",
			errorText: "concrete namespace",
		},
		{
			name:      "unsupported kind",
			args:      cmd.NetworkPolicyGraphArgs{Kind: "service", Name: "api"},
			activeNS:  "payments",
			errorText: "unsupported",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := networkPolicyGraphSubject(test.args, test.activeNS)
			if test.errorText != "" {
				require.ErrorContains(t, err, test.errorText)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestNetworkPolicyGraphSpecialCommandAliasesAndActionableErrors(t *testing.T) {
	app := NewApp(config.NewConfig(nil))
	command := NewCommand(app)

	for _, alias := range []string{"npg", "npgraph", "netpolgraph"} {
		t.Run(alias, func(t *testing.T) {
			assert.True(t, command.specialCmd(cmd.NewInterpreter(alias+" pod api default"), true))
			message := <-app.Flash().Channel()
			assert.Equal(t, model.FlashErr, message.Level)
			assert.Contains(t, message.Text, "active Kubernetes connection")
			assert.Empty(t, app.cmdHistory.List(), "failed dispatch must not pollute history")
		})
	}

	// Kind-only is valid syntax now that it resolves to the first instance, so
	// a missing connection must be reported as such, not as a usage error.
	assert.True(t, command.specialCmd(cmd.NewInterpreter("npg pod"), true))
	message := <-app.Flash().Channel()
	assert.Contains(t, message.Text, "active Kubernetes connection")
	assert.Empty(t, app.cmdHistory.List())

	// Genuinely malformed input still gets the usage error.
	for _, line := range []string{"npg service api default", "npg pod api default extra", "npg namespace payments extra"} {
		assert.True(t, command.specialCmd(cmd.NewInterpreter(line), true))
		message := <-app.Flash().Channel()
		assert.Contains(t, message.Text, "npg <pod|deployment|job|namespace> <name> [namespace]", line)
		assert.Empty(t, app.cmdHistory.List())
	}
}

func TestNetworkPolicyGraphInitialLayoutAndDirectionToggles(t *testing.T) {
	view := newTestNetworkPolicyGraph()

	assert.True(t, view.state[netpol.Ingress].visible)
	assert.True(t, view.state[netpol.Egress].visible)
	assert.Nil(t, view.placeholder)

	view.applyResult(testSubjectResult())
	for _, direction := range []netpol.Direction{netpol.Ingress, netpol.Egress} {
		assert.Empty(t, view.panels[direction].SelectedID())
		assert.False(t, view.panels[direction].HasSelection())
	}
	detail, ok := view.detailItem.(*ui.RuleDetails)
	require.True(t, ok)
	assert.True(t, view.detailShown.effective)
	assert.Equal(t, " Effective Applicability (Ingress) ", detail.Applicability.GetTitle())

	view.switchMode()
	require.Equal(t, ui.PrimitivesProjection, view.mode)
	for _, direction := range []netpol.Direction{netpol.Ingress, netpol.Egress} {
		assert.Empty(t, view.panels[direction].SelectedID())
		assert.False(t, view.panels[direction].HasSelection())
	}
	view.switchMode()

	view.toggleDirection(netpol.Ingress)
	assert.False(t, view.state[netpol.Ingress].visible)
	assert.True(t, view.state[netpol.Egress].visible)

	view.toggleDirection(netpol.Egress)
	assert.False(t, view.state[netpol.Egress].visible)
	require.NotNil(t, view.placeholder)
	assert.Contains(t, view.placeholder.GetText(true), "Both directions are hidden")

	view.toggleDirection(netpol.Ingress)
	assert.True(t, view.state[netpol.Ingress].visible)
	assert.Nil(t, view.placeholder)
}

func TestNetworkPolicyGraphModesKeepIndependentState(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := testSubjectResult()
	view.applyResult(result)
	ingress := view.panels[netpol.Ingress]
	ruleID := selectRule(t, view, result, netpol.Ingress, 0)

	view.focusDirection(netpol.Ingress)
	view.applySearch("allow-api")
	view.savePanelState(netpol.Ingress)
	view.switchMode()
	assert.Equal(t, ui.PrimitivesProjection, view.mode)
	assert.Equal(t, ui.PrimitivesProjection, ingress.Projection())
	assert.Equal(t, ui.PrimitivesProjection, view.panels[netpol.Egress].Projection())
	assert.Empty(t, ingress.Filter())

	view.applySearch("peer")
	primitiveID := selectPrimitive(t, view, result, netpol.Ingress, netpol.PrimitivePod, 0)
	view.focusDirection(netpol.Egress)
	assert.Empty(t, view.panels[netpol.Egress].Filter())
	view.applySearch("egress-peer")

	view.switchMode()
	assert.Equal(t, ui.RulesProjection, view.mode)
	assert.Equal(t, "allow-api", ingress.Filter())
	assert.Equal(t, ruleID, ingress.SelectedID())
	assert.Empty(t, view.panels[netpol.Egress].Filter())

	view.focusDirection(netpol.Egress)
	view.applySearch("egress-rule")

	view.switchMode()
	assert.Equal(t, ui.PrimitivesProjection, view.mode)
	assert.Equal(t, "peer", ingress.Filter())
	assert.Equal(t, primitiveID, ingress.SelectedID())
	assert.Equal(t, "egress-peer", view.panels[netpol.Egress].Filter())

	view.switchMode()
	assert.Equal(t, ui.RulesProjection, view.mode)
	assert.Equal(t, "allow-api", ingress.Filter())
	assert.Equal(t, "egress-rule", view.panels[netpol.Egress].Filter())
}

func TestNetworkPolicyGraphGlobalKindsAndEmptySelection(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())

	view.kinds = sets.New[netpol.PrimitiveKind]()
	view.loadPanel(netpol.Ingress)
	view.updateDetails(netpol.Ingress)
	assert.NotContains(t, view.panels[netpol.Ingress].PanelTitle(), "kinds:")
	assert.Contains(t, view.panels[netpol.Ingress].GetCell(0, 0).Text, "allow-api", "rules remain visible")
	ruleDetails, ok := view.detailItem.(*ui.RuleDetails)
	require.True(t, ok)
	assert.Equal(t, 1, ruleDetails.Applicability.GetRowCount(), "global kind filters constrain applicability")

	view.switchMode()
	assert.Contains(t, view.panels[netpol.Ingress].GetCell(0, 0).Text, "No primitive kinds selected")
	assert.True(t, view.panels[netpol.Ingress].GetCell(0, 0).NotSelectable)
	assert.Contains(t, view.panels[netpol.Egress].GetCell(0, 0).Text, "No primitive kinds selected")

	view.kinds = sets.New(netpol.PrimitivePod)
	view.loadPanel(netpol.Ingress)
	view.loadPanel(netpol.Egress)
	assert.NotContains(t, view.panels[netpol.Ingress].PanelTitle(), "kinds:")
	assert.NotContains(t, view.panels[netpol.Egress].PanelTitle(), "CIDR,Pod,Namespace,Deployment,Job")
}

func TestNetworkPolicyGraphDetailsUseGlobalKindsAndExposeWarnings(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := testSubjectResult()
	result.Truncated = true
	result.ResultLimit = 42
	result.Warnings = []string{"pods list was incomplete"}
	view.model.(*fakeNetPolGraphModel).refresh.Incomplete = map[string]error{"jobs": errors.New("forbidden")}
	view.applyResult(result)
	selectRule(t, view, result, netpol.Ingress, 0)

	ruleDetails, ok := view.detailItem.(*ui.RuleDetails)
	require.True(t, ok)
	ruleText := ruleDetails.Text.GetText(true)
	assert.Contains(t, ruleText, "Direction: Ingress")
	assert.Contains(t, ruleText, "Subject: Pod payments/api")
	assert.Contains(t, ruleText, "results truncated at 42")
	assert.Contains(t, ruleText, "partial jobs data: forbidden")
	assert.Equal(t, 2, ruleDetails.Applicability.GetRowCount())

	view.kinds = sets.New[netpol.PrimitiveKind]()
	view.updateDetails(netpol.Ingress)
	ruleDetails, ok = view.detailItem.(*ui.RuleDetails)
	require.True(t, ok)
	assert.Equal(t, 1, ruleDetails.Applicability.GetRowCount())

	view.kinds = netpol.AllPrimitiveKinds()
	view.loadPanel(netpol.Ingress)
	view.switchMode()
	selectPrimitive(t, view, result, netpol.Ingress, netpol.PrimitivePod, 0)
	primitiveText, ok := view.detailItem.(*tview.TextView)
	require.True(t, ok)
	text := primitiveText.GetText(true)
	for _, expected := range []string{
		"Direction: Ingress", "Identity: Pod payments/peer", "UID: peer-uid",
		"State: Partial Data", "Coverage: 1/1 pairs", "Ports:", "Evidence:",
		"Explanation:", "Warnings:",
	} {
		assert.Contains(t, text, expected)
	}
}

func TestNetworkPolicyGraphKeyboardModesFocusAndNavigation(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())

	assert.Nil(t, view.keyboard(tcell.NewEventKey(tcell.KeyRune, 'm', tcell.ModNone)))
	assert.Equal(t, ui.PrimitivesProjection, view.mode)
	assert.Equal(t, ui.PrimitivesProjection, view.panels[netpol.Ingress].Projection())
	assert.Equal(t, ui.PrimitivesProjection, view.panels[netpol.Egress].Projection())

	// Applicability focus only exists in Rules mode, so return both panels to it
	// before exercising the focus cycle below.
	assert.Nil(t, view.keyboard(tcell.NewEventKey(tcell.KeyRune, 'm', tcell.ModNone)))
	assert.Equal(t, ui.RulesProjection, view.mode)
	assert.Equal(t, ui.RulesProjection, view.panels[netpol.Ingress].Projection())
	assert.Equal(t, ui.RulesProjection, view.panels[netpol.Egress].Projection())

	assert.Nil(t, view.keyboard(tcell.NewEventKey(tcell.KeyRight, 0, tcell.ModNone)))
	assert.Equal(t, netpol.Egress, view.focus)
	assert.Equal(t, focusEgress, view.focusTarget)
	assert.Nil(t, view.keyboard(tcell.NewEventKey(tcell.KeyTAB, 0, tcell.ModNone)))
	assert.Equal(t, focusDetails, view.focusTarget)
	assert.Nil(t, view.keyboard(tcell.NewEventKey(tcell.KeyTAB, 0, tcell.ModNone)))
	assert.Equal(t, focusApplicability, view.focusTarget)
	assert.Nil(t, view.keyboard(tcell.NewEventKey(tcell.KeyBacktab, 0, tcell.ModShift)))
	assert.Equal(t, focusDetails, view.focusTarget)
	assert.Nil(t, view.keyboard(tcell.NewEventKey(tcell.KeyBacktab, 0, tcell.ModShift)))
	assert.Equal(t, focusEgress, view.focusTarget)
	// Walking back out of egress lands on the ingress detail stops, not on the
	// ingress panel: each direction owns the stops that follow it.
	assert.Nil(t, view.keyboard(tcell.NewEventKey(tcell.KeyBacktab, 0, tcell.ModShift)))
	assert.Equal(t, focusApplicability, view.focusTarget)
	assert.Equal(t, netpol.Ingress, view.focus)
	assert.Nil(t, view.keyboard(tcell.NewEventKey(tcell.KeyBacktab, 0, tcell.ModShift)))
	assert.Equal(t, focusDetails, view.focusTarget)
	assert.Equal(t, netpol.Ingress, view.focus)
	assert.Nil(t, view.keyboard(tcell.NewEventKey(tcell.KeyBacktab, 0, tcell.ModShift)))
	assert.Equal(t, focusIngress, view.focusTarget)
	assert.Nil(t, view.keyboard(tcell.NewEventKey(tcell.KeyBacktab, 0, tcell.ModShift)))
	assert.Equal(t, focusSubject, view.focusTarget)
	assert.Nil(t, view.keyboard(tcell.NewEventKey(tcell.KeyTAB, 0, tcell.ModNone)))
	assert.Equal(t, netpol.Ingress, view.focus)
	assert.Equal(t, focusIngress, view.focusTarget)

	view.focusDirection(netpol.Ingress)
	enter := tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone)
	assert.Nil(t, view.keyboard(enter))
	assert.Equal(t, focusApplicability, view.focusTarget, "Enter walks into the applicability table")

	view.focusDirection(netpol.Ingress)
	assert.Nil(t, view.keyboard(tcell.NewEventKey(tcell.KeyRune, 'i', tcell.ModNone)))
	assert.False(t, view.state[netpol.Ingress].visible)
	assert.Equal(t, netpol.Egress, view.focus)
	assert.NotNil(t, view.keyboard(tcell.NewEventKey(tcell.KeyUp, 0, tcell.ModNone)))
}

func TestNetworkPolicyGraphSwitchModeIsGlobal(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())

	view.focusDirection(netpol.Egress)
	view.switchMode()
	assert.Equal(t, ui.PrimitivesProjection, view.mode)
	assert.Equal(t, ui.PrimitivesProjection, view.panels[netpol.Ingress].Projection())
	assert.Equal(t, ui.PrimitivesProjection, view.panels[netpol.Egress].Projection())

	view.focusDirection(netpol.Ingress)
	assert.Nil(t, view.keyboard(tcell.NewEventKey(tcell.KeyRune, 'm', tcell.ModNone)))
	assert.Equal(t, ui.RulesProjection, view.mode)
	assert.Equal(t, ui.RulesProjection, view.panels[netpol.Ingress].Projection())
	assert.Equal(t, ui.RulesProjection, view.panels[netpol.Egress].Projection())
}

func TestNetworkPolicyGraphOpenRuleKeys(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := testSubjectResult()
	view.applyResult(result)
	// The view opens on the subject panel; Open Rule belongs to a direction.
	view.focusDirection(netpol.Ingress)
	selectRule(t, view, result, netpol.Ingress, 0)

	open, ok := view.actions.Get(ui.KeyO)
	require.True(t, ok)
	assert.Equal(t, "Open Rule", open.Description)
	assert.True(t, open.Opts.Visible)
	enterAction, ok := view.actions.Get(tcell.KeyEnter)
	require.True(t, ok)
	assert.Equal(t, "Focus Details/Open", enterAction.Description)
	assert.False(t, enterAction.Opts.Visible)

	// Enter now walks focus into the detail pane; only "o" opens directly.
	o := tcell.NewEventKey(tcell.KeyRune, 'o', tcell.ModNone)
	assert.Equal(t, o, view.keyboard(o), "nil-app rule navigation falls through without panicking")
	enter := tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone)
	assert.Nil(t, view.keyboard(enter))
	assert.Equal(t, focusApplicability, view.focusTarget)
	_, ok = view.actions.Get(ui.KeyO)
	assert.False(t, ok, "the direction panel no longer holds focus")

	view.focusDirection(netpol.Ingress)
	_, ok = view.actions.Get(ui.KeyO)
	require.True(t, ok, "returning focus to the panel restores Open Rule")

	view.switchMode()
	require.Equal(t, ui.PrimitivesProjection, view.mode)
	selectPrimitive(t, view, result, netpol.Ingress, netpol.PrimitivePod, 0)
	_, ok = view.actions.Get(ui.KeyO)
	assert.False(t, ok, "Open Rule only ever opens a NetworkPolicy")
	assert.Nil(t, view.keyboard(enter))
	assert.Equal(t, focusDetails, view.focusTarget, "Primitives mode has no applicability table")
}

func TestNetworkPolicyGraphName(t *testing.T) {
	assert.Equal(t, "npg", newTestNetworkPolicyGraph().Name())
}

func TestNetworkPolicyGraphEscapeClearsSelectionBeforeBack(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := testSubjectResult()
	view.applyResult(result)
	selectRule(t, view, result, netpol.Ingress, 0)
	require.True(t, view.panels[netpol.Ingress].HasSelection())
	require.NotEmpty(t, view.panels[netpol.Ingress].SelectedID())

	evt := tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone)
	assert.Nil(t, view.escapeCmd(evt))
	assert.Equal(t, netpol.Ingress, view.focus)
	assert.Empty(t, view.panels[netpol.Ingress].SelectedID())
	assert.False(t, view.panels[netpol.Ingress].HasSelection())

	assert.Equal(t, evt, view.escapeCmd(evt))
}

func TestNetworkPolicyGraphEffectiveDetailsWithoutSelection(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())
	view.panels[netpol.Ingress].ClearSelection()
	view.updateDetails(netpol.Ingress)

	details, ok := view.detailItem.(*ui.RuleDetails)
	require.True(t, ok)
	text := details.Text.GetText(true)
	assert.Contains(t, text, "Selection: none")
	assert.Contains(t, text, "Primitives:")
	assert.Greater(t, details.Applicability.GetRowCount(), 1)
}

func TestNetworkPolicyGraphPrimitivesModeHidesEffectiveApplicabilityWithoutSelection(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())
	view.switchMode()
	require.Equal(t, ui.PrimitivesProjection, view.mode)

	for _, direction := range []netpol.Direction{netpol.Ingress, netpol.Egress} {
		require.Empty(t, view.panels[direction].SelectedID())
		view.updateDetails(direction)

		detail, ok := view.detailItem.(*tview.TextView)
		require.True(t, ok, "%s effective details must not include an applicability table", direction)
		assert.Equal(t, " Effective Details ", detail.GetTitle())
		assert.Contains(t, detail.GetText(true), "Selection: none")
		assert.Contains(t, detail.GetText(true), "Select a primitive")

		details, applicability := view.detailStops(direction)
		assert.True(t, details)
		assert.False(t, applicability)
	}

	for _, stop := range view.focusStops() {
		assert.NotEqual(t, focusApplicability, stop.target)
	}
}

func TestNetworkPolicyGraphEffectiveDetailsAreFocusable(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())
	view.panels[netpol.Ingress].ClearSelection()
	view.updateDetails(netpol.Ingress)

	details, applicability := view.detailStops(netpol.Ingress)
	assert.True(t, details)
	assert.True(t, applicability)
}

// The per-state breakdown must account for every row, including Unknown,
// otherwise the printed counts silently fail to add up to the total.
func TestNetworkPolicyGraphEffectiveDetailsCountsSumToTotal(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())

	rows := []netpol.ApplicabilityRow{
		{EffectiveState: netpol.AccessAllowed},
		{EffectiveState: netpol.AccessPartial},
		{EffectiveState: netpol.AccessDisallowed},
		{EffectiveState: netpol.AccessUnknown},
		{EffectiveState: netpol.AccessPartialData},
		{EffectiveState: netpol.AccessUnknown},
	}
	text := view.effectiveDetailsText(netpol.Ingress, rows)

	line := ""
	for _, candidate := range strings.Split(text, "\n") {
		if strings.HasPrefix(candidate, "Primitives:") {
			line = candidate
			break
		}
	}
	require.NotEmpty(t, line, "effective details must report a primitive breakdown")
	assert.Contains(t, line, "unknown 2", "Unknown results must be counted")

	segments := strings.Split(line, " · ")
	require.Greater(t, len(segments), 1)
	total, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(segments[0], "Primitives:")))
	require.NoError(t, err)
	assert.Equal(t, len(rows), total)

	sum := 0
	for _, segment := range segments[1:] {
		fields := strings.Fields(segment)
		require.NotEmpty(t, fields)
		value, convErr := strconv.Atoi(fields[len(fields)-1])
		require.NoError(t, convErr)
		sum += value
	}
	assert.Equal(t, total, sum, "per-state counts must sum to the primitive total: %s", line)
}

// A cleared selection must round-trip through the saved panel state, otherwise
// the next evaluation silently re-selects a rule and hides the effective view.
func TestNetworkPolicyGraphClearedSelectionSurvivesRefresh(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := testSubjectResult()
	view.applyResult(result)
	selectRule(t, view, result, netpol.Ingress, 0)
	selectRule(t, view, result, netpol.Egress, 0)
	view.focusDirection(netpol.Ingress)
	require.Nil(t, view.escapeCmd(tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone)))
	require.Empty(t, view.panels[netpol.Ingress].SelectedID())

	view.applyResult(result)

	assert.Empty(t, view.panels[netpol.Ingress].SelectedID(), "refresh must not re-select a cleared panel")
	assert.False(t, view.panels[netpol.Ingress].HasSelection())
	_, ok := view.detailItem.(*ui.RuleDetails)
	assert.True(t, ok, "details keep rendering the effective pane after a refresh")
	assert.NotEmpty(t, view.panels[netpol.Egress].SelectedID(), "clearing one direction must not clear the other")
}

func TestNetworkPolicyGraphClearedSelectionModeStateIsolation(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := testSubjectResult()
	view.applyResult(result)
	selectRule(t, view, result, netpol.Ingress, 0)
	view.panels[netpol.Ingress].ClearSelection()
	require.False(t, view.panels[netpol.Ingress].HasSelection())

	view.switchMode()
	assert.Equal(t, ui.PrimitivesProjection, view.mode)
	selectPrimitive(t, view, result, netpol.Ingress, netpol.PrimitivePod, 0)
	assert.True(t, view.panels[netpol.Ingress].HasSelection(), "the other mode has independent selection state")

	view.switchMode()
	assert.Equal(t, ui.RulesProjection, view.mode)
	assert.Empty(t, view.panels[netpol.Ingress].SelectedID())
	assert.False(t, view.panels[netpol.Ingress].HasSelection())
}

func TestNetworkPolicyGraphClearedSelectionSurvivesDirectionToggle(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())
	view.panels[netpol.Ingress].ClearSelection()

	view.toggleDirection(netpol.Ingress)
	require.False(t, view.state[netpol.Ingress].visible)
	view.toggleDirection(netpol.Ingress)

	assert.True(t, view.state[netpol.Ingress].visible)
	assert.Empty(t, view.panels[netpol.Ingress].SelectedID())
	assert.False(t, view.panels[netpol.Ingress].HasSelection())
}

func TestNetworkPolicyGraphClearedPrimitiveSelectionSurvivesEmptyKinds(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())
	view.switchMode()
	require.Equal(t, ui.PrimitivesProjection, view.mode)
	view.panels[netpol.Ingress].ClearSelection()

	view.kinds = sets.New[netpol.PrimitiveKind]()
	view.loadPanel(netpol.Ingress)
	assert.Contains(t, view.panels[netpol.Ingress].GetCell(0, 0).Text, "No primitive kinds selected")
	assert.Empty(t, view.panels[netpol.Ingress].SelectedID())
	assert.False(t, view.panels[netpol.Ingress].HasSelection())

	view.kinds = netpol.AllPrimitiveKinds()
	view.loadPanel(netpol.Ingress)
	assert.Empty(t, view.panels[netpol.Ingress].SelectedID())
	assert.False(t, view.panels[netpol.Ingress].HasSelection())
}

func TestNetworkPolicyGraphBothClearedSurviveRefreshAndDetailsFollowFocus(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())
	view.panels[netpol.Ingress].ClearSelection()
	view.panels[netpol.Egress].ClearSelection()

	view.applyResult(testSubjectResult())

	assert.Empty(t, view.panels[netpol.Ingress].SelectedID())
	assert.Empty(t, view.panels[netpol.Egress].SelectedID())
	details, ok := view.detailItem.(*ui.RuleDetails)
	require.True(t, ok)
	assert.Contains(t, details.Text.GetText(true), "Direction: Ingress")
	assert.Contains(t, details.Text.GetText(true), "Selection: none")

	view.focusDirection(netpol.Egress)
	details, ok = view.detailItem.(*ui.RuleDetails)
	require.True(t, ok)
	assert.Contains(t, details.Text.GetText(true), "Direction: Egress")
	assert.Contains(t, details.Text.GetText(true), "Selection: none")
}

func TestNetworkPolicyGraphSubjectChangeClearsEveryDirectionAndProjection(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := testSubjectResult()
	view.applyResult(result)
	selectRule(t, view, result, netpol.Ingress, 0)
	selectRule(t, view, result, netpol.Egress, 0)
	view.switchMode()
	selectPrimitive(t, view, result, netpol.Ingress, netpol.PrimitivePod, 0)
	selectPrimitive(t, view, result, netpol.Egress, netpol.PrimitivePod, 0)
	view.switchMode()

	next := netpol.SubjectRef{
		Kind: netpol.SubjectNamespace, Name: "other", UID: types.UID("other-uid"),
	}
	view.applySubject(next)
	result = testSubjectResult()
	result.Subject.Ref = next
	view.applyResult(result)

	for _, projection := range []ui.ReachabilityProjection{ui.RulesProjection, ui.PrimitivesProjection} {
		if view.mode != projection {
			view.switchMode()
		}
		for _, direction := range []netpol.Direction{netpol.Ingress, netpol.Egress} {
			assert.Empty(t, view.panels[direction].SelectedID())
			assert.False(t, view.panels[direction].HasSelection())
		}
	}
	if view.mode != ui.RulesProjection {
		view.switchMode()
	}
	view.focusDirection(netpol.Ingress)
	detail, ok := view.detailItem.(*ui.RuleDetails)
	require.True(t, ok)
	assert.True(t, view.detailShown.effective)
	assert.Equal(t, " Effective Applicability (Ingress) ", detail.Applicability.GetTitle())
}

func TestNetworkPolicyGraphClearedSelectionFocusCycleIncludesApplicability(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())
	view.panels[netpol.Ingress].ClearSelection()
	view.updateDetails(netpol.Ingress)

	details, applicability := view.detailStops(netpol.Ingress)
	assert.True(t, details)
	assert.True(t, applicability)

	// The ingress detail stops sit directly behind the ingress panel, so the
	// effective applicability is reachable without passing through egress.
	view.focusDirection(netpol.Ingress)
	view.cycleFocus(false)
	assert.Equal(t, focusDetails, view.focusTarget)
	assert.Equal(t, netpol.Ingress, view.focus)
	view.cycleFocus(false)
	assert.Equal(t, focusApplicability, view.focusTarget)
	assert.Equal(t, netpol.Ingress, view.focus)
	view.cycleFocus(false)
	assert.Equal(t, focusEgress, view.focusTarget)
}

// The Tab ring pairs each direction with its own detail stops, so the ingress
// applicability is reachable without walking through the egress panel.
func TestNetworkPolicyGraphFocusRingOrder(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())

	want := []focusStop{
		{target: focusSubject},
		{target: focusIngress, direction: netpol.Ingress},
		{target: focusDetails, direction: netpol.Ingress},
		{target: focusApplicability, direction: netpol.Ingress},
		{target: focusEgress, direction: netpol.Egress},
		{target: focusDetails, direction: netpol.Egress},
		{target: focusApplicability, direction: netpol.Egress},
	}
	assert.Equal(t, want, view.focusStops())

	// Forward from the subject walks the whole ring and wraps back to it.
	view.applyFocusTarget(focusSubject)
	for _, stop := range append(want[1:], want[0]) {
		view.cycleFocus(false)
		assert.Equal(t, stop.target, view.focusTarget, "forward ring target")
		if stop.target != focusSubject {
			assert.Equal(t, stop.direction, view.focus, "forward ring direction")
			assert.Equal(t, stop.direction, view.detailShown.direction, "forward ring pane")
		}
	}

	// And the same stops in reverse. Starting from ingress makes the first step
	// cross into the egress detail stops, which has to rebuild the pane.
	view.focusDirection(netpol.Ingress)
	view.applyFocusTarget(focusSubject)
	require.Equal(t, netpol.Ingress, view.focus)
	reverse := []focusStop{want[6], want[5], want[4], want[3], want[2], want[1], want[0]}
	for _, stop := range reverse {
		view.cycleFocus(true)
		assert.Equal(t, stop.target, view.focusTarget, "reverse ring target")
		if stop.target != focusSubject {
			assert.Equal(t, stop.direction, view.focus, "reverse ring direction")
			assert.Equal(t, stop.direction, view.detailShown.direction, "reverse ring pane")
		}
	}
}

// Crossing into the other direction's detail stops must rebuild the pane, or
// focus would land on a table still showing the direction we came from.
func TestNetworkPolicyGraphFocusRingRebuildsPaneAcrossDirections(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())

	// Shift-Tab off the egress panel lands on the ingress applicability.
	view.focusDirection(netpol.Egress)
	require.Equal(t, netpol.Egress, view.detailShown.direction)
	view.cycleFocus(true)

	assert.Equal(t, focusApplicability, view.focusTarget)
	assert.Equal(t, netpol.Ingress, view.focus)
	assert.Equal(t, netpol.Ingress, view.detailShown.direction,
		"the pane must render the direction the stop belongs to")
	detail, ok := view.detailItem.(*ui.RuleDetails)
	require.True(t, ok)
	assert.Contains(t, detail.Applicability.GetTitle(), "(Ingress)")
}

// A hidden direction drops its panel and its detail stops together.
func TestNetworkPolicyGraphFocusRingSkipsHiddenDirection(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())
	view.toggleDirection(netpol.Ingress)
	require.False(t, view.state[netpol.Ingress].visible)

	for _, stop := range view.focusStops() {
		assert.NotEqual(t, focusIngress, stop.target)
		if stop.target != focusSubject {
			assert.Equal(t, netpol.Egress, stop.direction, "no ingress stop may survive")
		}
	}

	view.applyFocusTarget(focusSubject)
	view.cycleFocus(false)
	assert.Equal(t, focusEgress, view.focusTarget)
}

// Primitives mode renders a plain detail pane, so the direction contributes a
// details stop but no applicability stop.
func TestNetworkPolicyGraphFocusRingOmitsApplicabilityInPrimitivesMode(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := testSubjectResult()
	view.applyResult(result)
	view.switchMode()
	require.Equal(t, ui.PrimitivesProjection, view.mode)
	selectPrimitive(t, view, result, netpol.Ingress, netpol.PrimitivePod, 0)
	selectPrimitive(t, view, result, netpol.Egress, netpol.PrimitivePod, 0)

	details, applicability := view.detailStops(netpol.Ingress)
	assert.True(t, details)
	assert.False(t, applicability)

	for _, stop := range view.focusStops() {
		assert.NotEqual(t, focusApplicability, stop.target)
	}
}

// The view opens on the subject panel, which is where the ring starts.
func TestNetworkPolicyGraphOpensFocusedOnSubject(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	assert.Equal(t, focusSubject, view.focusTarget)

	view.applyResult(testSubjectResult())
	assert.Equal(t, focusSubject, view.focusTarget, "loading a result must not steal focus")

	view.cycleFocus(false)
	assert.Equal(t, focusIngress, view.focusTarget)
}

// With both directions hidden only the subject remains, and Tab must still be
// able to reach it from the placeholder rather than dead-ending.
func TestNetworkPolicyGraphFocusRingWithBothDirectionsHidden(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())
	view.toggleDirection(netpol.Ingress)
	view.toggleDirection(netpol.Egress)
	require.NotNil(t, view.placeholder)

	assert.Equal(t, []focusStop{{target: focusSubject}}, view.focusStops())

	view.cycleFocus(false)
	assert.Equal(t, focusSubject, view.focusTarget)
	view.cycleFocus(true)
	assert.Equal(t, focusSubject, view.focusTarget)
}

func TestNetworkPolicyGraphEscapeWhenBothDirectionsHiddenFallsThrough(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())
	view.toggleDirection(netpol.Ingress)
	view.toggleDirection(netpol.Egress)
	require.NotNil(t, view.placeholder)

	evt := tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone)
	assert.Equal(t, evt, view.escapeCmd(evt))
}

// Clearing the selection only hides the cursor; navigation brings it back.
func TestNetworkPolicyGraphClearedSelectionRecoversOnNavigation(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := testSubjectResult()
	view.applyResult(result)
	panel := view.panels[netpol.Ingress]
	original := selectRule(t, view, result, netpol.Ingress, 0)

	require.Nil(t, view.escapeCmd(tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone)))
	require.Empty(t, panel.SelectedID())

	panel.InputHandler()(tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone), func(tview.Primitive) {})

	assert.Equal(t, original, panel.SelectedID())
	assert.True(t, panel.HasSelection())
}

// Open Rule resolves the NetworkPolicy behind the selected rule and is only
// offered while a direction panel holds focus in Rules mode.
func TestNetworkPolicyGraphOpenRuleTargets(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := testSubjectResult()
	view.applyResult(result)
	view.focusDirection(netpol.Ingress)
	selectRule(t, view, result, netpol.Ingress, 0)

	namespace, name, ok := view.openRuleTarget()
	require.True(t, ok)
	assert.Equal(t, "payments", namespace)
	assert.Equal(t, "allow-api", name)

	view.switchMode()
	require.Equal(t, ui.PrimitivesProjection, view.mode)
	selectPrimitive(t, view, result, netpol.Ingress, netpol.PrimitivePod, 0)
	_, _, ok = view.openRuleTarget()
	assert.False(t, ok, "Primitives mode never opens a rule")
	primitive, ok := view.selectedPrimitive(netpol.Ingress, view.panels[netpol.Ingress].SelectedID())
	require.True(t, ok)
	command, path := primitiveCommand(&primitive.Ref)
	assert.Equal(t, "pods", command)
	assert.Equal(t, "payments/peer", path)

	// With nothing selected there is no rule to open.
	view.switchMode()
	require.Equal(t, ui.RulesProjection, view.mode)
	view.panels[netpol.Ingress].ClearSelection()
	view.syncActions()
	_, _, ok = view.openRuleTarget()
	assert.False(t, ok)
	_, ok = view.actions.Get(ui.KeyO)
	assert.False(t, ok)
}

// Synthetic default-deny/unrestricted rows have no backing NetworkPolicy, so
// Open Rule must not be offered for them at all.
func TestNetworkPolicyGraphOpenRuleSkipsSyntheticSelection(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.app = NewApp(config.NewConfig(nil))
	result := testSubjectResult()
	result.Ingress.Rules = []netpol.RuleResult{{
		ID: netpol.RuleID{
			Direction: netpol.Ingress, SyntheticKind: "default-deny",
		},
		Synthetic: true, SubjectPodCount: 1, SubjectMatchCount: 1, PeerSummary: "none",
	}}
	view.applyResult(result)
	view.focusDirection(netpol.Ingress)
	selectRule(t, view, result, netpol.Ingress, 0)

	namespace, name, ok := view.openRuleTarget()
	require.False(t, ok, "a synthetic rule references no NetworkPolicy")
	require.Empty(t, namespace)
	require.Empty(t, name)
	_, ok = view.actions.Get(ui.KeyO)
	assert.False(t, ok, "the key hint must be hidden, not just inert")

	evt := tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone)
	assert.Nil(t, view.openRuleCmd(evt), "an explicit call is consumed, not silently ignored")
	message := <-view.app.Flash().Channel()
	assert.Contains(t, message.Text, "Select a NetworkPolicy rule")
}

func TestNetworkPolicyGraphSubjectInfoReportsState(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := testSubjectResult()
	result.Truncated, result.ResultLimit = true, 17
	result.Warnings = []string{"partial"}
	view.applyResult(result)

	summary := view.subjectInfo.SummaryText()
	assert.Contains(t, summary, "Pod payments/api")
	assert.Contains(t, summary, "1 pod")
	assert.Contains(t, summary, "Ingress on")
	assert.Contains(t, summary, "Egress on")
	assert.Contains(t, summary, "Kinds: CIDR,Pod,Namespace,Deployment,Job")
	assert.Contains(t, summary, "TRUNCATED at 17")
	assert.Contains(t, summary, "PARTIAL DATA")
	assert.Contains(t, summary, "workloads unavailable")
	assert.Contains(t, view.subjectInfo.Table.GetCell(0, 0).Text, "No workloads found")
}

func TestNetworkPolicyGraphSubjectKindsIgnorePrimitiveFilter(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.kinds = sets.New[netpol.PrimitiveKind]()

	assert.Equal(t, []netpol.SubjectKind{
		netpol.SubjectPod,
		netpol.SubjectDeployment,
		netpol.SubjectJob,
		netpol.SubjectNamespace,
	}, subjectKinds())
}

func TestNetworkPolicyGraphAutoRefreshIsDisabledByDefault(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())

	assert.False(t, view.AutoRefresh())
	assert.Contains(t, view.subjectInfo.SummaryText(), "Auto-refresh off")

	graph, ok := view.model.(*fakeNetPolGraphModel)
	require.True(t, ok)
	view.Start()
	assert.Zero(t, graph.watches, "no watch loop must run while auto-refresh is off")
}

func TestNetworkPolicyGraphReadOnlyBadgeLifecycle(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.app = NewApp(config.NewConfig(nil))

	assert.NotContains(t, view.app.Logo().Status().GetText(true), "read-only graph")
	view.Start()
	token := view.logoBadge
	require.NotZero(t, token)
	assert.Contains(t, view.app.Logo().Status().GetText(true), "read-only graph")

	view.Start()
	assert.Equal(t, token, view.logoBadge, "restarting the active view must not replace its badge token")

	view.Stop()
	assert.Zero(t, view.logoBadge)
	assert.NotContains(t, view.app.Logo().Status().GetText(true), "read-only graph")
}

func TestNetworkPolicyGraphToggleAutoRefreshStartsAndStopsTheWatch(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())
	graph, ok := view.model.(*fakeNetPolGraphModel)
	require.True(t, ok)

	assert.Nil(t, view.keyboard(tcell.NewEventKey(tcell.KeyRune, 'r', tcell.ModNone)))
	assert.True(t, view.AutoRefresh())
	assert.Contains(t, view.subjectInfo.SummaryText(), "Auto-refresh on")
	assert.Eventually(t, func() bool { return graph.watchCount() > 0 }, time.Second, 10*time.Millisecond)

	assert.Nil(t, view.keyboard(tcell.NewEventKey(tcell.KeyRune, 'r', tcell.ModNone)))
	assert.False(t, view.AutoRefresh())
	assert.Contains(t, view.subjectInfo.SummaryText(), "Auto-refresh off")
}

func TestNetworkPolicyGraphHasNoManualRefreshShortcut(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	ctrlR := tcell.NewEventKey(tcell.KeyCtrlR, 0, tcell.ModCtrl)

	_, ok := view.actions.Get(tcell.KeyCtrlR)
	assert.False(t, ok)
	assert.False(t, visibleHint(view, "Ctrl-R"))
	assert.Equal(t, ctrlR, view.keyboard(ctrlR))
}

func TestNetworkPolicyGraphRefreshKeepsPanelSelection(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := multiRuleSubjectResult()
	view.applyResult(result)

	ingress := view.panels[netpol.Ingress]
	require.True(t, ingress.SelectID(result.Ingress.Rules[2].StableID()))
	selected := ingress.SelectedID()
	require.NotEmpty(t, selected)

	// Simulate a stale snapshot: the saved scroll state lags behind the live
	// cursor whenever the panel moves without notifying the view.
	state := view.state[netpol.Ingress]
	modeState := state.states[view.mode]
	modeState.scroll = ui.ReachabilityScrollState{SelectedID: result.Ingress.Rules[0].StableID()}
	state.states[view.mode] = modeState

	view.applyResult(multiRuleSubjectResult())

	assert.Equal(t, selected, ingress.SelectedID(), "a refresh must not reset the cursor")
}

func TestNetworkPolicyGraphRefreshKeepsApplicabilitySelection(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(multiPrimitiveSubjectResult())

	details, ok := view.detailItem.(*ui.RuleDetails)
	require.True(t, ok)
	require.Equal(t, 4, details.Applicability.GetRowCount())
	require.True(t, details.SelectApplicabilityID(details.Applicability.GetCell(3, 0).GetReference().(string)))
	id := details.SelectedApplicabilityID()
	require.NotEmpty(t, id)

	view.applyResult(multiPrimitiveSubjectResult())

	details, ok = view.detailItem.(*ui.RuleDetails)
	require.True(t, ok)
	assert.Equal(t, id, details.SelectedApplicabilityID())
}

func TestNetworkPolicyGraphSubjectChangeResetsDetailState(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := multiRuleSubjectResult()
	view.applyResult(result)
	require.True(t, view.panels[netpol.Ingress].SelectID(result.Ingress.Rules[2].StableID()))

	view.applySubject(netpol.SubjectRef{
		Kind: netpol.SubjectNamespace, Name: "other", UID: types.UID("other-uid"),
	})

	assert.Equal(t, netpol.SubjectNamespace, view.subject.Kind)
	assert.Empty(t, view.panels[netpol.Ingress].SelectedID())
}

func newTestNetworkPolicyGraph() *NetworkPolicyGraph {
	subject := netpol.SubjectRef{
		Kind: netpol.SubjectPod, Namespace: "payments", Name: "api", UID: types.UID("subject-uid"),
	}
	graph := &fakeNetPolGraphModel{subject: subject}
	return newNetworkPolicyGraph(subject, netpol.NewEvaluator(), graph)
}

func selectRule(
	t *testing.T,
	view *NetworkPolicyGraph,
	result *netpol.SubjectResult,
	direction netpol.Direction,
	index int,
) string {
	t.Helper()
	rules := result.Ingress.Rules
	if direction == netpol.Egress {
		rules = result.Egress.Rules
	}
	require.Equal(t, ui.RulesProjection, view.mode)
	require.Less(t, index, len(rules))
	id := rules[index].StableID()
	require.True(t, view.panels[direction].SelectID(id))
	require.Equal(t, id, view.panels[direction].SelectedID())
	return id
}

func selectPrimitive(
	t *testing.T,
	view *NetworkPolicyGraph,
	result *netpol.SubjectResult,
	direction netpol.Direction,
	kind netpol.PrimitiveKind,
	index int,
) string {
	t.Helper()
	primitives := result.Ingress.Primitives
	if direction == netpol.Egress {
		primitives = result.Egress.Primitives
	}
	require.Equal(t, ui.PrimitivesProjection, view.mode)
	require.Less(t, index, len(primitives[kind]))
	id := primitives[kind][index].StableID()
	require.True(t, view.panels[direction].SelectID(id))
	require.Equal(t, id, view.panels[direction].SelectedID())
	return id
}

func testSubjectResult() *netpol.SubjectResult {
	subject := netpol.SubjectRef{
		Kind: netpol.SubjectPod, Namespace: "payments", Name: "api", UID: types.UID("subject-uid"),
	}
	ingressID := netpol.RuleID{
		PolicyNamespace: "payments", PolicyName: "allow-api", PolicyUID: types.UID("policy-uid"),
		Direction: netpol.Ingress, Index: 0,
	}
	egressID := netpol.RuleID{
		PolicyNamespace: "payments", PolicyName: "allow-api", PolicyUID: types.UID("policy-uid"),
		Direction: netpol.Egress, Index: 0,
	}
	primitive := func(direction netpol.Direction, id netpol.RuleID) netpol.PrimitiveResult {
		return netpol.PrimitiveResult{
			Ref:          netpol.PrimitiveRef{Kind: netpol.PrimitivePod, Namespace: "payments", Name: "peer", UID: types.UID("peer-uid")},
			State:        netpol.AccessAllowed,
			AllowedPairs: 1,
			TotalPairs:   1,
			Permissions:  []netpol.PortPermission{{All: true}},
			Evidence:     []netpol.PolicyEvidence{{RuleID: id, Summary: "allow-api evidence"}},
			Explanation:  "selected by allow-api",
			Warnings:     []string{"example warning"},
			PairDecisions: []netpol.PairDecision{{
				Source:      netpol.PodRef{Namespace: "payments", Name: "peer"},
				Destination: netpol.PodRef{Namespace: "payments", Name: "api"},
				Decision: netpol.Decision{
					State:       netpol.AccessAllowed,
					Permissions: []netpol.PortPermission{{All: true}},
					Evidence: []netpol.PolicyEvidence{
						{RuleID: id, Summary: direction.String() + " evidence"},
						{RuleID: netpol.RuleID{Direction: oppositeDirection(direction)}, Summary: "opposite evidence"},
					},
				},
			}},
		}
	}
	rule := func(id netpol.RuleID) netpol.RuleResult {
		return netpol.RuleResult{
			ID: id, SubjectPodCount: 1, SubjectMatchCount: 1, PeerSummary: "peer",
			Permissions: []netpol.PortPermission{{All: true}},
			Evidence:    []netpol.PolicyEvidence{{RuleID: id, Summary: "policy evidence"}},
		}
	}
	return &netpol.SubjectResult{
		Subject: netpol.Subject{Ref: subject, Pods: []netpol.PodRef{{Namespace: "payments", Name: "api"}}},
		Ingress: netpol.DirectionResult{
			Rules: []netpol.RuleResult{rule(ingressID)},
			Primitives: map[netpol.PrimitiveKind][]netpol.PrimitiveResult{
				netpol.PrimitivePod: {primitive(netpol.Ingress, ingressID)},
			},
		},
		Egress: netpol.DirectionResult{
			Rules: []netpol.RuleResult{rule(egressID)},
			Primitives: map[netpol.PrimitiveKind][]netpol.PrimitiveResult{
				netpol.PrimitivePod: {primitive(netpol.Egress, egressID)},
			},
		},
	}
}

func oppositeDirection(direction netpol.Direction) netpol.Direction {
	if direction == netpol.Ingress {
		return netpol.Egress
	}
	return netpol.Ingress
}

// multiRuleSubjectResult yields several selectable rules per direction so
// selection retention can be observed across a refresh.
func multiRuleSubjectResult() *netpol.SubjectResult {
	subject := netpol.SubjectRef{
		Kind: netpol.SubjectPod, Namespace: "payments", Name: "api", UID: types.UID("subject-uid"),
	}
	rule := func(direction netpol.Direction, index int, policy string) netpol.RuleResult {
		id := netpol.RuleID{
			PolicyNamespace: "payments", PolicyName: policy, PolicyUID: types.UID(policy + "-uid"),
			Direction: direction, Index: index,
		}
		return netpol.RuleResult{
			ID: id, SubjectPodCount: 1, SubjectMatchCount: 1, PeerSummary: "peer",
			Permissions: []netpol.PortPermission{{All: true}},
			Evidence:    []netpol.PolicyEvidence{{RuleID: id, Summary: "policy evidence"}},
		}
	}
	return &netpol.SubjectResult{
		Subject: netpol.Subject{Ref: subject, Pods: []netpol.PodRef{{Namespace: "payments", Name: "api"}}},
		Ingress: netpol.DirectionResult{
			Rules: []netpol.RuleResult{
				rule(netpol.Ingress, 0, "allow-a"),
				rule(netpol.Ingress, 1, "allow-b"),
				rule(netpol.Ingress, 2, "allow-c"),
			},
		},
		Egress: netpol.DirectionResult{
			Rules: []netpol.RuleResult{rule(netpol.Egress, 0, "allow-a")},
		},
	}
}

// multiPrimitiveSubjectResult yields several applicability rows for the single
// ingress rule so detail selection retention can be observed.
func multiPrimitiveSubjectResult() *netpol.SubjectResult {
	result := testSubjectResult()
	id := result.Ingress.Rules[0].ID
	for _, spec := range []struct {
		kind netpol.PrimitiveKind
		name string
	}{
		{netpol.PrimitiveDeployment, "peer-dp"},
		{netpol.PrimitiveJob, "peer-job"},
	} {
		result.Ingress.Primitives[spec.kind] = []netpol.PrimitiveResult{{
			Ref: netpol.PrimitiveRef{
				Kind: spec.kind, Namespace: "payments", Name: spec.name,
				UID: types.UID(spec.name + "-uid"),
			},
			State:        netpol.AccessAllowed,
			AllowedPairs: 1,
			TotalPairs:   1,
			Permissions:  []netpol.PortPermission{{All: true}},
			Evidence:     []netpol.PolicyEvidence{{RuleID: id, Summary: "allow-api evidence"}},
			PairDecisions: []netpol.PairDecision{{
				Source:      netpol.PodRef{Namespace: "payments", Name: spec.name},
				Destination: netpol.PodRef{Namespace: "payments", Name: "api"},
				Decision: netpol.Decision{
					State:       netpol.AccessAllowed,
					Permissions: []netpol.PortPermission{{All: true}},
					Evidence: []netpol.PolicyEvidence{
						{RuleID: id, Summary: "Ingress evidence"},
						{RuleID: netpol.RuleID{Direction: netpol.Egress}, Summary: "opposite evidence"},
					},
				},
			}},
		}}
	}
	return result
}

func subjectPromotionResult() *netpol.SubjectResult {
	result := multiPrimitiveSubjectResult()
	id := result.Ingress.Rules[0].ID
	result.Ingress.Primitives[netpol.PrimitiveNamespace] = []netpol.PrimitiveResult{{
		Ref: netpol.PrimitiveRef{
			Kind: netpol.PrimitiveNamespace, Name: "shared", UID: types.UID("shared-uid"),
		},
		State:        netpol.AccessAllowed,
		AllowedPairs: 1,
		TotalPairs:   1,
		Permissions:  []netpol.PortPermission{{All: true}},
		Evidence:     []netpol.PolicyEvidence{{RuleID: id, Summary: "namespace evidence"}},
		PairDecisions: []netpol.PairDecision{{
			Source:      netpol.PodRef{Namespace: "shared", Name: "peer"},
			Destination: netpol.PodRef{Namespace: "payments", Name: "api"},
			Decision: netpol.Decision{
				State:       netpol.AccessAllowed,
				Permissions: []netpol.PortPermission{{All: true}},
				Evidence: []netpol.PolicyEvidence{
					{RuleID: id, Summary: "Ingress evidence"},
					{RuleID: netpol.RuleID{Direction: netpol.Egress}, Summary: "opposite evidence"},
				},
			},
		}},
	}}
	result.Ingress.Primitives[netpol.PrimitiveCIDR] = []netpol.PrimitiveResult{{
		Ref:          netpol.PrimitiveRef{Kind: netpol.PrimitiveCIDR, CIDR: "10.0.0.0/8"},
		State:        netpol.AccessAllowed,
		AllowedPairs: 1,
		TotalPairs:   1,
		Permissions:  []netpol.PortPermission{{All: true}},
		Evidence:     []netpol.PolicyEvidence{{RuleID: id, Summary: "cidr evidence"}},
		PairDecisions: []netpol.PairDecision{{
			Source:      netpol.PodRef{Name: "10.0.0.1"},
			Destination: netpol.PodRef{Namespace: "payments", Name: "api"},
			Decision: netpol.Decision{
				State:       netpol.AccessAllowed,
				Permissions: []netpol.PortPermission{{All: true}},
				Evidence:    []netpol.PolicyEvidence{{RuleID: id, Summary: "Ingress evidence"}},
			},
		}},
	}}
	return result
}

func mixedApplicabilitySubjectResult() *netpol.SubjectResult {
	result := testSubjectResult()
	result.Ingress.Primitives = mixedApplicabilityPrimitives(netpol.Ingress, result.Ingress.Rules[0].ID)
	result.Egress.Primitives = mixedApplicabilityPrimitives(netpol.Egress, result.Egress.Rules[0].ID)
	return result
}

func mixedApplicabilityPrimitives(
	direction netpol.Direction,
	ruleID netpol.RuleID,
) map[netpol.PrimitiveKind][]netpol.PrimitiveResult {
	permission := netpol.PortPermission{All: true}
	oppositeID := netpol.RuleID{Direction: oppositeDirection(direction), SyntheticKind: "unrestricted"}
	pair := func(name string, allowed bool) netpol.PairDecision {
		evidence := []netpol.PolicyEvidence{{RuleID: ruleID, Ports: []netpol.PortPermission{permission}}}
		if allowed {
			evidence = append(evidence, netpol.PolicyEvidence{RuleID: oppositeID})
		}
		state := netpol.AccessDisallowed
		if allowed {
			state = netpol.AccessAllowed
		}
		return netpol.PairDecision{
			Source:      netpol.PodRef{Namespace: "payments", Name: name + "-source"},
			Destination: netpol.PodRef{Namespace: "payments", Name: name + "-destination"},
			Decision: netpol.Decision{
				State:       state,
				Permissions: []netpol.PortPermission{permission},
				Evidence:    evidence,
			},
		}
	}
	primitive := func(name string, state netpol.AccessState, pairs ...netpol.PairDecision) netpol.PrimitiveResult {
		allowed := 0
		for index := range pairs {
			if pairs[index].Decision.State == netpol.AccessAllowed {
				allowed++
			}
		}
		return netpol.PrimitiveResult{
			Ref: netpol.PrimitiveRef{
				Kind: netpol.PrimitivePod, Namespace: "payments", Name: name, UID: types.UID(name + "-uid"),
			},
			State:         state,
			AllowedPairs:  allowed,
			TotalPairs:    len(pairs),
			Permissions:   []netpol.PortPermission{permission},
			PairDecisions: pairs,
		}
	}
	return map[netpol.PrimitiveKind][]netpol.PrimitiveResult{
		netpol.PrimitivePod: {
			primitive("allowed", netpol.AccessAllowed, pair("allowed", true)),
			primitive("disallowed", netpol.AccessDisallowed, pair("disallowed", false)),
			primitive("partial", netpol.AccessPartial, pair("partial-allowed", true), pair("partial-denied", false)),
			primitive("unknown", netpol.AccessUnknown),
			primitive("partial-data", netpol.AccessPartialData, pair("partial-data", true)),
		},
	}
}

func visibleHint(view *NetworkPolicyGraph, mnemonic string) bool {
	for _, hint := range view.Hints() {
		if hint.Mnemonic == mnemonic && hint.Visible {
			return true
		}
	}
	return false
}

func applicabilityStates(t *testing.T, view *NetworkPolicyGraph) []string {
	t.Helper()
	detail, ok := view.detailItem.(*ui.RuleDetails)
	require.True(t, ok)
	states := make([]string, 0, detail.Applicability.GetRowCount()-1)
	for row := 1; row < detail.Applicability.GetRowCount(); row++ {
		states = append(states, detail.Applicability.GetCell(row, 3).Text)
	}
	return states
}

func TestPrimitiveCommand(t *testing.T) {
	tests := map[netpol.PrimitiveKind]string{
		netpol.PrimitivePod:        "pods",
		netpol.PrimitiveNamespace:  "namespaces",
		netpol.PrimitiveDeployment: "deployments",
		netpol.PrimitiveJob:        "jobs",
	}
	for kind, command := range tests {
		actual, path := primitiveCommand(&netpol.PrimitiveRef{Kind: kind, Namespace: "payments", Name: "peer"})
		assert.Equal(t, command, actual)
		if kind == netpol.PrimitiveNamespace {
			assert.Equal(t, "peer", path)
		} else {
			assert.Equal(t, "payments/peer", path)
		}
	}
	command, path := primitiveCommand(&netpol.PrimitiveRef{Kind: netpol.PrimitiveCIDR, CIDR: "10.0.0.0/8"})
	assert.Empty(t, command)
	assert.Empty(t, path)
}

func TestNetworkPolicyGraphErrorWithoutResult(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyError(errors.New("forbidden"))
	details := view.detailItem.(*tview.TextView).GetText(true)
	assert.True(t, strings.Contains(details, "failed") && strings.Contains(details, "forbidden"))
}

// Enter walks focus into the applicability table so the rows can be scrolled,
// which is the whole point of separating it from Open Resource.
func TestNetworkPolicyGraphEnterFocusesApplicability(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := multiPrimitiveSubjectResult()
	view.applyResult(result)
	view.focusDirection(netpol.Ingress)
	selectRule(t, view, result, netpol.Ingress, 0)
	require.Equal(t, focusIngress, view.focusTarget)

	details, ok := view.detailItem.(*ui.RuleDetails)
	require.True(t, ok)
	require.Greater(t, details.Applicability.GetRowCount(), 1)

	assert.Nil(t, view.enterCmd(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone)))
	assert.Equal(t, focusApplicability, view.focusTarget)
	// Focus has left the direction panel, so the title is all that says which
	// rule the table explains.
	assert.Equal(t, " Applicability (Ingress) ", details.Applicability.GetTitle())
}

// With nothing selected the detail pane renders the direction's effective
// applicability, and Enter must reach it just the same.
func TestNetworkPolicyGraphEnterFocusesEffectiveApplicabilityWithoutSelection(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(multiPrimitiveSubjectResult())
	view.panels[netpol.Ingress].ClearSelection()
	view.updateDetails(netpol.Ingress)
	require.Empty(t, view.panels[netpol.Ingress].SelectedID())
	require.True(t, view.detailShown.effective)

	view.focusTarget = focusIngress
	assert.Nil(t, view.enterCmd(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone)))
	assert.Equal(t, focusApplicability, view.focusTarget)

	details, ok := view.detailItem.(*ui.RuleDetails)
	require.True(t, ok)
	assert.Equal(t, " Effective Applicability (Ingress) ", details.Applicability.GetTitle())

	view.panels[netpol.Egress].ClearSelection()
	view.updateDetails(netpol.Egress)
	details, ok = view.detailItem.(*ui.RuleDetails)
	require.True(t, ok)
	assert.Equal(t, " Effective Applicability (Egress) ", details.Applicability.GetTitle())
}

// Primitives mode renders a plain text pane, so Enter falls back to it rather
// than becoming a silent no-op.
func TestNetworkPolicyGraphEnterFallsBackToDetailText(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := testSubjectResult()
	view.applyResult(result)
	view.switchMode()
	require.Equal(t, ui.PrimitivesProjection, view.mode)
	selectPrimitive(t, view, result, netpol.Ingress, netpol.PrimitivePod, 0)
	_, isRuleDetails := view.detailItem.(*ui.RuleDetails)
	require.False(t, isRuleDetails)

	view.focusTarget = focusIngress
	assert.Nil(t, view.enterCmd(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone)))
	assert.Equal(t, focusDetails, view.focusTarget)
}

// An applicability table with no data rows must not capture focus.
func TestNetworkPolicyGraphEnterFallsBackWhenApplicabilityIsEmpty(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())
	view.kinds = sets.New[netpol.PrimitiveKind]()
	view.updateDetails(netpol.Ingress)

	details, ok := view.detailItem.(*ui.RuleDetails)
	require.True(t, ok)
	require.Equal(t, 1, details.Applicability.GetRowCount(), "header only")

	view.focusTarget = focusIngress
	assert.Nil(t, view.enterCmd(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone)))
	assert.Equal(t, focusDetails, view.focusTarget)
}

// A second Enter, from the applicability table, opens the highlighted primitive.
func TestNetworkPolicyGraphEnterOpensHighlightedPrimitive(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())
	view.focusDirection(netpol.Ingress)
	require.Nil(t, view.enterCmd(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone)))
	require.Equal(t, focusApplicability, view.focusTarget)

	command, path, err := view.applicabilityTarget()
	require.NoError(t, err)
	assert.Equal(t, "pods", command)
	assert.Equal(t, "payments/peer", path)
}

// CIDR rows describe address ranges, not Kubernetes objects.
func TestNetworkPolicyGraphEnterReportsCIDRApplicabilityRow(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.app = NewApp(config.NewConfig(nil))
	result := testSubjectResult()
	id := result.Ingress.Rules[0].ID
	result.Ingress.Primitives = map[netpol.PrimitiveKind][]netpol.PrimitiveResult{
		netpol.PrimitiveCIDR: {{
			Ref:          netpol.PrimitiveRef{Kind: netpol.PrimitiveCIDR, Name: "10.0.0.0/8"},
			State:        netpol.AccessAllowed,
			AllowedPairs: 1,
			TotalPairs:   1,
			Permissions:  []netpol.PortPermission{{All: true}},
			Evidence:     []netpol.PolicyEvidence{{RuleID: id, Summary: "cidr evidence"}},
			PairDecisions: []netpol.PairDecision{{
				Source:      netpol.PodRef{Namespace: "payments", Name: "api"},
				Destination: netpol.PodRef{Name: "10.0.0.1"},
				Decision: netpol.Decision{
					State:       netpol.AccessAllowed,
					Permissions: []netpol.PortPermission{{All: true}},
					Evidence:    []netpol.PolicyEvidence{{RuleID: id, Summary: "Ingress evidence"}},
				},
			}},
		}},
	}
	view.applyResult(result)
	view.focusDirection(netpol.Ingress)

	require.Nil(t, view.enterCmd(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone)))
	require.Equal(t, focusApplicability, view.focusTarget)

	_, _, err := view.applicabilityTarget()
	require.ErrorIs(t, err, errPrimitiveNotResource)

	assert.Nil(t, view.enterCmd(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone)))
	message := <-view.app.Flash().Channel()
	assert.Contains(t, message.Text, "CIDR primitives are not Kubernetes resources")
}

func TestNetworkPolicyGraphCtrlSIsDistinctFromPlainEnter(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := subjectPromotionResult()
	view.applyResult(result)
	view.focusDirection(netpol.Ingress)

	plainEnter := tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone)
	assert.Nil(t, view.keyboard(plainEnter))
	assert.Equal(t, focusApplicability, view.focusTarget, "plain Enter retains detail navigation")
	assert.Equal(t, netpol.SubjectRef{
		Kind: netpol.SubjectPod, Namespace: "payments", Name: "api", UID: types.UID("subject-uid"),
	}, view.subject)

	detail := view.detailItem.(*ui.RuleDetails)
	pod := result.Ingress.Primitives[netpol.PrimitivePod][0]
	require.True(t, detail.SelectApplicabilityID(pod.StableID()))
	view.syncActions()

	// Plain Enter still follows the existing open-resource path. With no app
	// installed it falls through and, critically, does not replace the subject.
	assert.Equal(t, plainEnter, view.keyboard(plainEnter))
	assert.Equal(t, "api", view.subject.Name)

	ctrlS := tcell.NewEventKey(tcell.KeyCtrlS, 0, tcell.ModCtrl)
	assert.Nil(t, view.keyboard(ctrlS))
	assert.Equal(t, netpol.SubjectRef{
		Kind: netpol.SubjectPod, Namespace: "payments", Name: "peer", UID: types.UID("peer-uid"),
	}, view.subject)
	assert.Equal(t, focusSubject, view.focusTarget)
}

func TestNetworkPolicyGraphCtrlSApplicabilityAvailability(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := subjectPromotionResult()
	view.applyResult(result)
	ctrlS := tcell.NewEventKey(tcell.KeyCtrlS, 0, tcell.ModCtrl)

	assert.False(t, visibleHint(view, "Ctrl-S"), "subject focus has no loaded workload")
	assert.Equal(t, ctrlS, view.keyboard(ctrlS), "unbound Ctrl-S must fall through")

	for _, target := range []reachabilityFocus{focusIngress, focusDetails} {
		view.applyFocusTarget(target)
		assert.False(t, visibleHint(view, "Ctrl-S"), "focus target %d", target)
		assert.Equal(t, ctrlS, view.keyboard(ctrlS))
	}

	view.applyFocusTarget(focusApplicability)
	detail := view.detailItem.(*ui.RuleDetails)
	podID := result.Ingress.Primitives[netpol.PrimitivePod][0].StableID()
	require.True(t, detail.SelectApplicabilityID(podID))
	view.syncActions()
	assert.True(t, visibleHint(view, "Ctrl-S"), "subject-capable applicability row")
	action, ok := view.actions.Get(tcell.KeyCtrlS)
	require.True(t, ok)
	assert.Equal(t, "Set As Subject", action.Description)

	cidrID := result.Ingress.Primitives[netpol.PrimitiveCIDR][0].StableID()
	require.True(t, detail.SelectApplicabilityID(cidrID))
	view.syncActions()
	assert.False(t, visibleHint(view, "Ctrl-S"), "CIDR cannot become a subject")
	assert.Equal(t, ctrlS, view.keyboard(ctrlS))

	detail.Applicability.Select(0, 0)
	view.syncActions()
	assert.False(t, visibleHint(view, "Ctrl-S"), "no highlighted row")
	assert.Equal(t, ctrlS, view.keyboard(ctrlS))

	require.True(t, detail.SelectApplicabilityID(podID))
	view.result.Ingress.Primitives[netpol.PrimitivePod] = nil
	view.invalidateProjections()
	view.syncActions()
	assert.False(t, visibleHint(view, "Ctrl-S"), "stale row no longer resolves")
	assert.Equal(t, ctrlS, view.keyboard(ctrlS))

	view.applyResult(subjectPromotionResult())
	view.switchMode()
	require.Equal(t, ui.PrimitivesProjection, view.mode)
	assert.False(t, visibleHint(view, "Ctrl-S"), "Primitives mode")
	assert.Equal(t, ctrlS, view.keyboard(ctrlS))
}

func TestNetworkPolicyGraphPromotesApplicabilityPrimitiveToSubject(t *testing.T) {
	tests := []struct {
		name string
		kind netpol.PrimitiveKind
		want netpol.SubjectRef
	}{
		{
			name: "pod",
			kind: netpol.PrimitivePod,
			want: netpol.SubjectRef{
				Kind: netpol.SubjectPod, Namespace: "payments", Name: "peer", UID: types.UID("peer-uid"),
			},
		},
		{
			name: "deployment",
			kind: netpol.PrimitiveDeployment,
			want: netpol.SubjectRef{
				Kind: netpol.SubjectDeployment, Namespace: "payments", Name: "peer-dp",
				UID: types.UID("peer-dp-uid"),
			},
		},
		{
			name: "job",
			kind: netpol.PrimitiveJob,
			want: netpol.SubjectRef{
				Kind: netpol.SubjectJob, Namespace: "payments", Name: "peer-job",
				UID: types.UID("peer-job-uid"),
			},
		},
		{
			name: "namespace",
			kind: netpol.PrimitiveNamespace,
			want: netpol.SubjectRef{
				Kind: netpol.SubjectNamespace, Name: "shared", UID: types.UID("shared-uid"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			view := newTestNetworkPolicyGraph()
			result := subjectPromotionResult()
			view.applyResult(result)
			view.applyFocusTarget(focusApplicability)
			detail := view.detailItem.(*ui.RuleDetails)
			primitive := result.Ingress.Primitives[test.kind][0]
			require.True(t, detail.SelectApplicabilityID(primitive.StableID()))
			view.syncActions()
			require.True(t, visibleHint(view, "Ctrl-S"))

			ctrlS := tcell.NewEventKey(tcell.KeyCtrlS, 0, tcell.ModCtrl)
			require.Nil(t, view.keyboard(ctrlS))

			assert.Equal(t, test.want, view.subject)
			assert.Equal(t, test.want, view.model.Subject(), "promotion must call model.SetSubject")
			assert.False(t, view.haveResult, "the old subject result must be discarded")
			assert.Empty(t, view.panels[netpol.Ingress].SelectedID())
			assert.Empty(t, view.panels[netpol.Egress].SelectedID())
			assert.Equal(t, focusSubject, view.focusTarget)
			assert.Contains(t, view.detailItem.(*tview.TextView).GetText(true), "Waiting for NetworkPolicy evaluation")
		})
	}

	t.Run("CIDR is not promotable", func(t *testing.T) {
		view := newTestNetworkPolicyGraph()
		result := subjectPromotionResult()
		view.applyResult(result)
		view.applyFocusTarget(focusApplicability)
		detail := view.detailItem.(*ui.RuleDetails)
		require.True(t, detail.SelectApplicabilityID(result.Ingress.Primitives[netpol.PrimitiveCIDR][0].StableID()))
		view.syncActions()

		before := view.subject
		ctrlS := tcell.NewEventKey(tcell.KeyCtrlS, 0, tcell.ModCtrl)
		assert.False(t, visibleHint(view, "Ctrl-S"))
		assert.Equal(t, ctrlS, view.keyboard(ctrlS))
		assert.Equal(t, before, view.subject)
		assert.Equal(t, before, view.model.Subject())
		assert.True(t, view.haveResult)
	})
}

func TestNetworkPolicyGraphPromotesSubjectPanelWorkload(t *testing.T) {
	tests := []struct {
		kind string
		want netpol.SubjectKind
	}{
		{kind: "Pod", want: netpol.SubjectPod},
		{kind: "Deployment", want: netpol.SubjectDeployment},
		{kind: "Job", want: netpol.SubjectJob},
	}
	for _, test := range tests {
		t.Run(test.kind, func(t *testing.T) {
			view := newTestNetworkPolicyGraph()
			view.applyResult(testSubjectResult())
			workload := ui.SubjectWorkload{
				Kind: test.kind, Namespace: "payments", Name: strings.ToLower(test.kind),
				UID: types.UID(strings.ToLower(test.kind) + "-uid"), Status: "Ready",
			}
			view.workloads = []ui.SubjectWorkload{workload}
			view.updateSubject()
			view.applyFocusTarget(focusSubject)
			view.syncActions()
			require.True(t, visibleHint(view, "Ctrl-S"))

			ctrlS := tcell.NewEventKey(tcell.KeyCtrlS, 0, tcell.ModCtrl)
			require.Nil(t, view.keyboard(ctrlS))

			expected := netpol.SubjectRef{
				Kind: test.want, Namespace: workload.Namespace, Name: workload.Name, UID: workload.UID,
			}
			assert.Equal(t, expected, view.subject)
			assert.Equal(t, expected, view.model.Subject())
			assert.Equal(t, focusSubject, view.focusTarget)
			assert.Empty(t, view.panels[netpol.Ingress].SelectedID())
			assert.Empty(t, view.panels[netpol.Egress].SelectedID())
		})
	}
}

func TestNetworkPolicyGraphCtrlSRejectsUnsupportedSubjectWorkload(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())
	view.workloads = []ui.SubjectWorkload{{
		Kind: "ReplicaSet", Namespace: "payments", Name: "api-rs", UID: types.UID("rs-uid"),
	}}
	view.updateSubject()
	view.applyFocusTarget(focusSubject)
	view.syncActions()

	ctrlS := tcell.NewEventKey(tcell.KeyCtrlS, 0, tcell.ModCtrl)
	assert.False(t, visibleHint(view, "Ctrl-S"))
	assert.Equal(t, ctrlS, view.keyboard(ctrlS))
	assert.Equal(t, "api", view.subject.Name)
}

func TestNetworkPolicyGraphAllowedOnlyActionAvailability(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(mixedApplicabilitySubjectResult())
	a := tcell.NewEventKey(tcell.KeyRune, 'a', tcell.ModNone)

	assertAllowedAction := func(t *testing.T, want bool) {
		t.Helper()
		_, bound := view.actions.Get(ui.KeyA)
		assert.Equal(t, want, bound)
		assert.Equal(t, want, visibleHint(view, "a"))
	}

	assertAllowedAction(t, true)
	for _, target := range []reachabilityFocus{
		focusIngress,
		focusDetails,
		focusApplicability,
		focusEgress,
		focusDetails,
		focusApplicability,
	} {
		view.applyFocusTarget(target)
		assertAllowedAction(t, true)
	}

	view.switchMode()
	require.Equal(t, ui.PrimitivesProjection, view.mode)
	for _, target := range []reachabilityFocus{focusSubject, focusIngress, focusDetails, focusEgress, focusDetails} {
		view.applyFocusTarget(target)
		assertAllowedAction(t, false)
		assert.Equal(t, a, view.keyboard(a), "a must be unbound throughout Primitives mode")
	}

	view.switchMode()
	require.Equal(t, ui.RulesProjection, view.mode)
	assertAllowedAction(t, true)
}

func TestNetworkPolicyGraphAllowedOnlyFiltersSelectedAndEffectiveApplicability(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := mixedApplicabilitySubjectResult()
	view.applyResult(result)
	view.focusDirection(netpol.Ingress)
	selectRule(t, view, result, netpol.Ingress, 0)
	view.applyFocusTarget(focusApplicability)
	detail := view.detailItem.(*ui.RuleDetails)
	allowedID := result.Ingress.Primitives[netpol.PrimitivePod][0].StableID()
	require.True(t, detail.SelectApplicabilityID(allowedID))
	view.syncActions()

	fullStates := []string{"Allowed", "Disallowed", "Partial", "Unknown", "Partial Data"}
	assert.ElementsMatch(t, fullStates, applicabilityStates(t, view))

	a := tcell.NewEventKey(tcell.KeyRune, 'a', tcell.ModNone)
	require.Nil(t, view.keyboard(a))
	detail = view.detailItem.(*ui.RuleDetails)
	assert.Equal(t, " Applicability (Ingress) (Allowed only) ", detail.Applicability.GetTitle())
	assert.Equal(t, []string{"Allowed"}, applicabilityStates(t, view),
		"only exact AccessAllowed rows remain")
	assert.Equal(t, allowedID, detail.SelectedApplicabilityID(),
		"a still-visible applicability selection must retain its stable ID")

	view.focusDirection(netpol.Egress)
	selectRule(t, view, result, netpol.Egress, 0)
	detail = view.detailItem.(*ui.RuleDetails)
	assert.Equal(t, " Applicability (Egress) (Allowed only) ", detail.Applicability.GetTitle())
	assert.Equal(t, []string{"Allowed"}, applicabilityStates(t, view),
		"the setting is global across ingress and egress")

	view.panels[netpol.Egress].ClearSelection()
	view.updateDetails(netpol.Egress)
	detail = view.detailItem.(*ui.RuleDetails)
	assert.True(t, view.detailShown.effective)
	assert.Equal(t, " Effective Applicability (Egress) (Allowed only) ", detail.Applicability.GetTitle())
	assert.Equal(t, []string{"Allowed"}, applicabilityStates(t, view),
		"no-selection Effective Applicability uses the same filter")
	effectiveText := detail.Text.GetText(true)
	for _, state := range []string{"allowed 1", "partial 1", "disallowed 1", "unknown 1", "partial data 1"} {
		assert.Contains(t, effectiveText, state, "Effective Details keeps the complete state breakdown")
	}
	assert.Contains(t, effectiveText, "Primitives: 5")

	view.switchMode()
	require.Equal(t, ui.PrimitivesProjection, view.mode)
	assert.False(t, visibleHint(view, "a"))
	view.switchMode()
	require.Equal(t, ui.RulesProjection, view.mode)
	detail = view.detailItem.(*ui.RuleDetails)
	assert.Equal(t, " Effective Applicability (Egress) (Allowed only) ", detail.Applicability.GetTitle(),
		"the setting persists across Rules -> Primitives -> Rules")
	assert.Equal(t, []string{"Allowed"}, applicabilityStates(t, view))

	require.Nil(t, view.keyboard(a))
	detail = view.detailItem.(*ui.RuleDetails)
	assert.Equal(t, " Effective Applicability (Egress) ", detail.Applicability.GetTitle())
	assert.ElementsMatch(t, fullStates, applicabilityStates(t, view), "toggling off restores every state")

	view.focusDirection(netpol.Ingress)
	detail = view.detailItem.(*ui.RuleDetails)
	assert.Equal(t, " Applicability (Ingress) ", detail.Applicability.GetTitle())
	assert.ElementsMatch(t, fullStates, applicabilityStates(t, view))
}

func TestNetworkPolicyGraphAllowedOnlyCanRecoverFromZeroRows(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := mixedApplicabilitySubjectResult()
	result.Ingress.Primitives[netpol.PrimitivePod] = result.Ingress.Primitives[netpol.PrimitivePod][1:]
	view.applyResult(result)
	view.focusDirection(netpol.Ingress)
	selectRule(t, view, result, netpol.Ingress, 0)

	a := tcell.NewEventKey(tcell.KeyRune, 'a', tcell.ModNone)
	require.Nil(t, view.keyboard(a))
	detail := view.detailItem.(*ui.RuleDetails)
	assert.Equal(t, " Applicability (Ingress) (Allowed only) ", detail.Applicability.GetTitle())
	assert.Equal(t, 1, detail.Applicability.GetRowCount(), "zero allowed rows leave the header visible")
	assert.Empty(t, detail.SelectedApplicabilityID())
	assert.True(t, visibleHint(view, "a"), "the filter action remains available from the fallback detail focus")

	require.Nil(t, view.keyboard(a))
	detail = view.detailItem.(*ui.RuleDetails)
	assert.Equal(t, " Applicability (Ingress) ", detail.Applicability.GetTitle())
	assert.ElementsMatch(t, []string{"Disallowed", "Partial", "Unknown", "Partial Data"}, applicabilityStates(t, view))
}

func TestNetworkPolicyGraphDynamicApplicabilityActionHints(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := subjectPromotionResult()
	view.applyResult(result)

	assert.True(t, visibleHint(view, "a"))
	assert.False(t, visibleHint(view, "Ctrl-S"))

	view.focusDirection(netpol.Ingress)
	assert.True(t, visibleHint(view, "a"))
	assert.False(t, visibleHint(view, "Ctrl-S"))

	view.applyFocusTarget(focusApplicability)
	detail := view.detailItem.(*ui.RuleDetails)
	podID := result.Ingress.Primitives[netpol.PrimitivePod][0].StableID()
	cidrID := result.Ingress.Primitives[netpol.PrimitiveCIDR][0].StableID()
	require.True(t, detail.SelectApplicabilityID(podID))
	view.syncActions()
	assert.True(t, visibleHint(view, "a"))
	assert.True(t, visibleHint(view, "Ctrl-S"))

	require.True(t, detail.SelectApplicabilityID(cidrID))
	view.syncActions()
	assert.True(t, visibleHint(view, "a"))
	assert.False(t, visibleHint(view, "Ctrl-S"), "cursor moved to CIDR")

	detail.Applicability.Select(0, 0)
	view.syncActions()
	assert.False(t, visibleHint(view, "Ctrl-S"), "selection moved off all data rows")

	require.True(t, detail.SelectApplicabilityID(podID))
	view.syncActions()
	assert.True(t, visibleHint(view, "Ctrl-S"))
	view.applyFocusTarget(focusDetails)
	assert.False(t, visibleHint(view, "Ctrl-S"), "focus left applicability")

	view.switchMode()
	assert.False(t, visibleHint(view, "a"))
	assert.False(t, visibleHint(view, "Ctrl-S"))
	view.switchMode()
	assert.True(t, visibleHint(view, "a"))

	view.applyFocusTarget(focusApplicability)
	detail = view.detailItem.(*ui.RuleDetails)
	require.True(t, detail.SelectApplicabilityID(podID))
	view.syncActions()
	assert.True(t, visibleHint(view, "Ctrl-S"), "mode and cursor restoration recompute dynamic hints")
}

func TestNetworkPolicyGraphSearchTargetsFollowFocus(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := mixedApplicabilitySubjectResult()
	view.applyResult(result)
	view.workloads = []ui.SubjectWorkload{
		{Kind: "Pod", Namespace: "payments", Name: "api", Status: "Running"},
		{Kind: "Job", Namespace: "payments", Name: "cleanup", Status: "Complete"},
	}
	view.updateSubject()

	assert.True(t, visibleHint(view, "/"), "Subject is searchable")
	view.applySearch("cleanup")
	assert.Equal(t, " Subject · filter: cleanup ", view.subjectInfo.GetTitle())
	assert.Equal(t, "Job/payments/cleanup", view.subjectInfo.SelectedID())

	view.focusDirection(netpol.Ingress)
	assert.True(t, visibleHint(view, "/"), "direction panels are searchable")
	view.applySearch("allow-api")
	assert.Equal(t, "allow-api", view.panels[netpol.Ingress].Filter())
	selectRule(t, view, result, netpol.Ingress, 0)

	view.applyFocusTarget(focusDetails)
	assert.True(t, visibleHint(view, "/"), "selected Rule Details searches its applicability table")
	view.applySearch("partial")
	detail := view.detailItem.(*ui.RuleDetails)
	assert.Equal(t, " Applicability (Ingress) · filter: partial ", detail.Applicability.GetTitle())
	assert.Equal(t, []string{"Partial", "Partial Data"}, applicabilityStates(t, view))
	assert.Equal(t, focusDetails, view.focusTarget)

	view.applyFocusTarget(focusApplicability)
	assert.True(t, visibleHint(view, "/"), "Applicability is searchable")

	view.panels[netpol.Ingress].ClearSelection()
	view.updateDetails(netpol.Ingress)
	view.applyFocusTarget(focusDetails)
	assert.True(t, view.detailShown.effective)
	assert.False(t, visibleHint(view, "/"), "Effective Details is the only normal detail stop without search")

	view.applyFocusTarget(focusApplicability)
	assert.True(t, visibleHint(view, "/"), "Effective Applicability remains searchable")

	view.switchMode()
	require.Equal(t, ui.PrimitivesProjection, view.mode)
	view.focusDirection(netpol.Ingress)
	selectPrimitive(t, view, result, netpol.Ingress, netpol.PrimitivePod, 0)
	view.applyFocusTarget(focusDetails)
	assert.True(t, visibleHint(view, "/"), "Primitive Details searches the parent primitive panel")
}

func TestNetworkPolicyGraphApplicabilitySearchIsDirectionLocal(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(mixedApplicabilitySubjectResult())
	view.focusDirection(netpol.Ingress)
	view.applyFocusTarget(focusApplicability)

	view.applySearch("unknown")

	detail := view.detailItem.(*ui.RuleDetails)
	assert.Equal(t, " Effective Applicability (Ingress) · filter: unknown ", detail.Applicability.GetTitle())
	assert.Equal(t, []string{"Unknown"}, applicabilityStates(t, view))

	view.focusDirection(netpol.Egress)
	detail = view.detailItem.(*ui.RuleDetails)
	assert.Equal(t, " Effective Applicability (Egress) ", detail.Applicability.GetTitle())
	assert.ElementsMatch(t,
		[]string{"Allowed", "Disallowed", "Partial", "Unknown", "Partial Data"},
		applicabilityStates(t, view),
	)
}

func TestNetworkPolicyGraphApplicabilitySearchMatchesDisplayedNotApplicableValues(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(mixedApplicabilitySubjectResult())
	view.focusDirection(netpol.Ingress)
	view.applyFocusTarget(focusApplicability)

	view.applySearch("n/a")

	detail := view.detailItem.(*ui.RuleDetails)
	assert.Equal(t, " Effective Applicability (Ingress) · filter: n/a ", detail.Applicability.GetTitle())
	assert.Equal(t, []string{"Unknown"}, applicabilityStates(t, view))
	for _, column := range []int{1, 2, 4} {
		assert.Equal(t, "n/a", detail.Applicability.GetCell(1, column).Text)
	}
}

// Once focus sits inside the detail pane the arrows belong to the widget so its
// text and table can scroll horizontally.
func TestNetworkPolicyGraphArrowsReachTheDetailPane(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())

	left := tcell.NewEventKey(tcell.KeyLeft, 0, tcell.ModNone)
	assert.Nil(t, view.keyboard(left), "arrows switch direction while a panel is focused")

	view.applyFocusTarget(focusApplicability)
	assert.Equal(t, left, view.keyboard(left), "arrows fall through to the focused detail widget")
	right := tcell.NewEventKey(tcell.KeyRight, 0, tcell.ModNone)
	assert.Equal(t, right, view.keyboard(right))
}

// blockingWorkloads stalls workload collection, standing in for a cold informer
// cache that has not synced yet.
func blockingWorkloads(started chan<- struct{}, release <-chan struct{}) func(netpol.SubjectRef, []netpol.PodRef) ([]ui.SubjectWorkload, []string) {
	return func(netpol.SubjectRef, []netpol.PodRef) ([]ui.SubjectWorkload, []string) {
		close(started)
		<-release
		return nil, nil
	}
}

// Collecting subject workloads lists several resource kinds through the
// informers, which blocks on RBAC checks and cache syncs. Doing that inline
// froze the whole application on every evaluation.
func TestNetworkPolicyGraphUIPathNeverWaitsOnWorkloadCollection(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	defer close(release)

	view := newTestNetworkPolicyGraph()
	view.app = NewApp(config.NewConfig(nil))
	view.collectWorkloads = blockingWorkloads(started, release)

	done := make(chan struct{})
	go func() {
		defer close(done)
		view.applyResult(testSubjectResult())
		view.updateDetails(netpol.Ingress)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the UI path blocked waiting on workload collection")
	}

	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("workloads were never collected in the background")
	}
	assert.Contains(t, view.subjectInfo.SummaryText(), "workloads loading")
}

// Evaluations can complete faster than the UI renders them; replaying every
// queued result made the view appear permanently stuck.
func TestNetworkPolicyGraphCoalescesQueuedUpdates(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.app = NewApp(config.NewConfig(nil))

	first, second := testSubjectResult(), multiRuleSubjectResult()
	view.queueUpdate(first, nil)
	view.queueUpdate(second, nil)

	view.drainPendingUpdate()
	assert.Equal(t, len(second.Ingress.Rules), len(view.result.Ingress.Rules), "the newest result wins")

	view.mx.Lock()
	result, err, queued := view.pendingResult, view.pendingErr, view.updateQueued
	view.mx.Unlock()
	assert.Nil(t, result)
	assert.NoError(t, err)
	assert.False(t, queued)
}

// A partial-data refresh fires NetPolGraphChanged immediately followed by
// NetPolGraphFailed. Coalescing them into one slot let the failure discard the
// evaluated result, so the panels either never populated or froze on stale data.
func TestNetworkPolicyGraphPartialDataKeepsTheResult(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.app = NewApp(config.NewConfig(nil))
	require.False(t, view.haveResult)

	// Exactly the model's ordering: the drain cannot run in between.
	view.NetPolGraphChanged(*multiRuleSubjectResult())
	view.NetPolGraphFailed(errors.New("network policy snapshot is incomplete"))
	view.drainPendingUpdate()

	require.True(t, view.haveResult, "the evaluated result must survive the partial-data failure")
	assert.Greater(t, view.panels[netpol.Ingress].GetRowCount(), 0, "panels must be populated")
	assert.Empty(t, view.panels[netpol.Ingress].SelectedID())
	assert.Empty(t, view.panels[netpol.Egress].SelectedID())
	detail, ok := view.detailItem.(*ui.RuleDetails)
	require.True(t, ok)
	assert.True(t, view.detailShown.effective)
	assert.Equal(t, " Effective Applicability (Ingress) ", detail.Applicability.GetTitle())
	require.Error(t, view.lastError)
	assert.Contains(t, view.subjectInfo.SummaryText(), "ERROR: network policy snapshot is incomplete")
}

// Repeated refresh requests must not queue an unbounded number of full-cluster snapshots.
func TestNetworkPolicyGraphCollapsesRepeatedRefreshRequests(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.app = NewApp(config.NewConfig(nil))
	graph, ok := view.model.(*fakeNetPolGraphModel)
	require.True(t, ok)

	for range 10 {
		view.Refresh()
	}
	assert.Eventually(t, func() bool {
		view.mx.Lock()
		defer view.mx.Unlock()
		return !view.refreshing
	}, 5*time.Second, 10*time.Millisecond)
	assert.LessOrEqual(t, graph.refreshCount(), 2, "presses collapse into at most one follow-up refresh")
}

// Toggling to a pane without an applicability table while that table has focus
// must not strand tview on the detached widget: a Flex only reports focus for
// its current items, so the whole view would drop out of the focus chain and
// every key binding would silently stop working.
func TestNetworkPolicyGraphFocusFallsBackWhenTheTableDisappears(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := testSubjectResult()
	view.applyResult(result)
	view.switchMode()
	selectPrimitive(t, view, result, netpol.Ingress, netpol.PrimitivePod, 0)
	view.switchMode()
	view.focusDirection(netpol.Ingress)
	selectRule(t, view, result, netpol.Ingress, 0)
	require.Nil(t, view.enterCmd(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone)))
	require.Equal(t, focusApplicability, view.focusTarget)

	// Primitives mode renders a plain text pane with no applicability table.
	view.switchMode()
	require.Equal(t, ui.PrimitivesProjection, view.mode)
	_, isRuleDetails := view.detailItem.(*ui.RuleDetails)
	require.False(t, isRuleDetails)
	assert.Equal(t, focusDetails, view.focusTarget, "focus must follow the rebuilt pane")

	// Hiding both directions removes the detail content entirely.
	view.toggleDirection(netpol.Ingress)
	view.toggleDirection(netpol.Egress)
	assert.Contains(t, []reachabilityFocus{focusIngress, focusEgress}, view.focusTarget,
		"focus must return to the view when there is nothing to focus")
}

// Subject changes return focus to Subject. Kind changes return to a direction,
// while Search stays on the panel it filters.
func TestNetworkPolicyGraphDialogsResetTheFocusTarget(t *testing.T) {
	cases := []struct {
		name     string
		act      func(*NetworkPolicyGraph)
		expected []reachabilityFocus
	}{
		{
			name:     "search",
			act:      func(v *NetworkPolicyGraph) { v.applySearch("") },
			expected: []reachabilityFocus{focusApplicability},
		},
		{
			name: "subject",
			act: func(v *NetworkPolicyGraph) {
				v.applySubject(netpol.SubjectRef{
					Kind: netpol.SubjectNamespace, Name: "other", UID: types.UID("other-uid"),
				})
			},
			expected: []reachabilityFocus{focusSubject},
		},
		{
			name: "kinds",
			act: func(v *NetworkPolicyGraph) {
				v.kinds = sets.New(netpol.PrimitivePod)
				v.loadPanel(netpol.Ingress)
				v.updateDetails(v.focus)
				v.focusActiveDirection()
			},
			expected: []reachabilityFocus{focusIngress, focusEgress},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A fresh view per case: the dialogs mutate shared view state.
			view := newTestNetworkPolicyGraph()
			view.applyResult(testSubjectResult())
			view.applyFocusTarget(focusApplicability)
			require.Equal(t, focusApplicability, view.focusTarget)

			tc.act(view)
			assert.Contains(t, tc.expected, view.focusTarget)
		})
	}
}

// Changing subject must leave the pane explaining that an evaluation is
// pending, not prompting for a selection that cannot exist yet.
func TestNetworkPolicyGraphSubjectChangeShowsPendingMessage(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())

	view.applySubject(netpol.SubjectRef{
		Kind: netpol.SubjectNamespace, Name: "other", UID: types.UID("other-uid"),
	})

	text, ok := view.detailItem.(*tview.TextView)
	require.True(t, ok)
	assert.Contains(t, text.GetText(true), "Waiting for NetworkPolicy evaluation")
}

// With both directions hidden the panels leave the widget tree. Focusing one
// anyway drops the view out of tview's focus chain, which silently kills every
// key binding, so focus must land on the placeholder instead.
func TestNetworkPolicyGraphHiddenDirectionsKeepFocusAttached(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.app = NewApp(config.NewConfig(nil))
	view.applyResult(testSubjectResult())

	view.toggleDirection(netpol.Ingress)
	view.toggleDirection(netpol.Egress)
	require.NotNil(t, view.placeholder, "both directions hidden renders the placeholder")
	assert.Equal(t, tview.Primitive(view.placeholder), view.app.GetFocus())

	// The subject picker is reachable while both directions are hidden, and its
	// accept and cancel paths both restore focus.
	view.applySubject(netpol.SubjectRef{
		Kind: netpol.SubjectNamespace, Name: "other", UID: types.UID("other-uid"),
	})
	assert.Equal(t, tview.Primitive(view.subjectInfo.Table), view.app.GetFocus())

	view.focusActiveDirection()
	assert.Equal(t, tview.Primitive(view.placeholder), view.app.GetFocus())

	// Restoring a direction hands focus back to a real panel.
	view.toggleDirection(netpol.Ingress)
	require.Nil(t, view.placeholder)
	assert.Equal(t, tview.Primitive(view.panels[netpol.Ingress]), view.app.GetFocus())
}

// Re-focusing the graph -- what PageStack.StackTop does after a pushed view is
// popped -- must land on the pane focusTarget names. tview.Flex would otherwise
// always delegate to the item flagged at AddItem time, so the user would come
// back to a highlighted subject panel while "o" and "y" still acted on the
// direction panel they left.
func TestNetworkPolicyGraphRefocusHonorsFocusTarget(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.app = NewApp(config.NewConfig(nil))
	view.applyResult(testSubjectResult())

	uu := map[string]struct {
		focus func()
		want  func() tview.Primitive
	}{
		"subject": {
			focus: func() { view.applyFocusTarget(focusSubject) },
			// SubjectInfo is a Flex, so tview descends into its workload table.
			want: func() tview.Primitive { return view.subjectInfo.Table },
		},
		"ingress": {
			focus: func() { view.focusDirection(netpol.Ingress) },
			want:  func() tview.Primitive { return view.panels[netpol.Ingress] },
		},
		"egress": {
			focus: func() { view.focusDirection(netpol.Egress) },
			want:  func() tview.Primitive { return view.panels[netpol.Egress] },
		},
		"details": {
			focus: func() {
				view.focusDirection(netpol.Ingress)
				view.applyFocusTarget(focusDetails)
			},
			want: func() tview.Primitive { return view.detailItem.(*ui.RuleDetails).Text },
		},
		"applicability": {
			focus: func() {
				view.focusDirection(netpol.Ingress)
				view.applyFocusTarget(focusApplicability)
			},
			want: func() tview.Primitive { return view.detailItem.(*ui.RuleDetails).Applicability },
		},
	}
	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			u.focus()
			want := u.want()
			require.Equal(t, want, view.app.GetFocus(), "precondition: focus lands on the target")

			// Focus something else, then re-focus the view the way the page
			// stack does when the pushed view is popped.
			view.app.SetFocus(tview.NewBox())
			view.app.SetFocus(view)

			assert.Equal(t, want, view.app.GetFocus())
		})
	}
}

// With both directions hidden the panels leave the widget tree, so a re-focus
// has to land on the placeholder rather than a detached panel.
func TestNetworkPolicyGraphRefocusWithBothDirectionsHidden(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.app = NewApp(config.NewConfig(nil))
	view.applyResult(testSubjectResult())
	view.toggleDirection(netpol.Ingress)
	view.toggleDirection(netpol.Egress)
	require.NotNil(t, view.placeholder)

	view.app.SetFocus(tview.NewBox())
	view.app.SetFocus(view)

	assert.Equal(t, tview.Primitive(view.placeholder), view.app.GetFocus())
}

// Enter is the first key a user is likely to press on the default focus, so it
// has to lead into the graph instead of doing nothing.
func TestNetworkPolicyGraphEnterFromSubjectFocusesDirection(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())
	require.Equal(t, focusSubject, view.focusTarget)

	assert.Nil(t, view.enterCmd(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone)))
	assert.Equal(t, focusIngress, view.focusTarget)
	assert.Equal(t, netpol.Ingress, view.focus)
}

// Focus parked on a pane that left the ring must not make Shift-Tab leap across
// the whole ring to its far end.
func TestNetworkPolicyGraphCycleFocusFromAStopThatVanished(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := testSubjectResult()
	view.applyResult(result)
	stops := view.focusStops()
	require.Len(t, stops, 7)

	view.switchMode()
	selectPrimitive(t, view, result, netpol.Ingress, netpol.PrimitivePod, 0)
	selectPrimitive(t, view, result, netpol.Egress, netpol.PrimitivePod, 0)
	view.switchMode()
	selectRule(t, view, result, netpol.Ingress, 0)

	// Primitives mode drops every applicability stop, stranding focusTarget.
	view.focusDirection(netpol.Ingress)
	view.applyFocusTarget(focusApplicability)
	view.switchMode()
	view.focusTarget = focusApplicability
	require.Equal(t, -1, view.currentStopIndex(view.focusStops()))

	view.cycleFocus(true)
	assert.Equal(t, focusDetails, view.focusTarget, "reverse enters at the last stop")
	assert.Equal(t, netpol.Egress, view.focus)

	view.focusTarget = focusApplicability
	view.focus = netpol.Ingress
	view.cycleFocus(false)
	assert.Equal(t, focusSubject, view.focusTarget, "forward enters at the first stop")
}

func TestSolveSectionHeights(t *testing.T) {
	uu := map[string]struct {
		total     int
		remainder int
		requests  []sectionRequest
		e         []int
	}{
		"content fits": {
			total: 60, remainder: 8,
			requests: []sectionRequest{
				{desired: 5, min: 3, max: 15},
				{desired: 12, min: 3, max: 24},
			},
			e: []int{5, 12},
		},
		"capped at the maximum share": {
			total: 60, remainder: 8,
			requests: []sectionRequest{
				{desired: 40, min: 3, max: 15},
				{desired: 90, min: 3, max: 24},
			},
			e: []int{15, 24},
		},
		"never below the minimum": {
			total: 60, remainder: 8,
			requests: []sectionRequest{
				{desired: 0, min: 3, max: 15},
				{desired: 1, min: 3, max: 24},
			},
			e: []int{3, 3},
		},
		"remainder wins over content": {
			total: 30, remainder: 8,
			requests: []sectionRequest{
				{desired: 12, min: 3, max: 30},
				{desired: 18, min: 3, max: 30},
			},
			// 30 - 8 = 22 for both sections: the lower one gives up first.
			e: []int{12, 10},
		},
		"lower section shrinks to its minimum before the upper one": {
			total: 20, remainder: 8,
			requests: []sectionRequest{
				{desired: 12, min: 3, max: 20},
				{desired: 12, min: 3, max: 20},
			},
			e: []int{9, 3},
		},
		"too small for the minimums drops the lower sections": {
			total: 4, remainder: 8,
			requests: []sectionRequest{
				{desired: 5, min: 3, max: 20},
				{desired: 5, min: 3, max: 20},
			},
			e: []int{3, 1},
		},
		"zero height yields zero sections": {
			total: 0, remainder: 8,
			requests: []sectionRequest{{desired: 5, min: 3, max: 20}},
			e:        []int{0},
		},
		"single section leaves the remainder": {
			total: 20, remainder: 5,
			requests: []sectionRequest{{desired: 40, min: 3, max: 7}},
			e:        []int{7},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, solveSectionHeights(u.total, u.remainder, u.requests))
		})
	}
}

// drawGraph paints the view onto a simulation screen so the flex assigns real
// rects to every section.
func drawGraph(t *testing.T, view *NetworkPolicyGraph, width, height int) {
	t.Helper()
	screen := tcell.NewSimulationScreen("UTF-8")
	require.NoError(t, screen.Init())
	t.Cleanup(screen.Fini)
	screen.SetSize(width, height)
	view.SetRect(0, 0, width, height)
	view.Draw(screen)
}

func sectionHeight(p tview.Primitive) int {
	_, _, _, height := p.GetRect()
	return height
}

// Sections are sized to their own content so the applicability table keeps
// everything that is left over.
func TestNetworkPolicyGraphLayoutIsContentDriven(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())
	drawGraph(t, view, 120, 60)

	subject := sectionHeight(view.subjectInfo)
	directions := sectionHeight(view.directions)
	details := sectionHeight(view.details)

	assert.Equal(t, view.subjectInfo.ContentHeight(), subject, "one workload-less subject needs no more")
	assert.Equal(t, view.directionsContentHeight(), directions, "a single rule needs no more")
	assert.Equal(t, 60, subject+directions+details)
	assert.Greater(t, details, subject+directions, "the leftover space goes to the details pane")

	detail, ok := view.detailItem.(*ui.RuleDetails)
	require.True(t, ok)
	text := sectionHeight(detail.Text)
	applicability := sectionHeight(detail.Applicability)
	assert.Equal(t, details, text+applicability)
	assert.GreaterOrEqual(t, applicability, minApplicabilityHeight)
	assert.LessOrEqual(t, text, percentOf(60, detailTextMaxPercent), "the detail text is capped")
}

// A subject or direction with far more content than fits is clamped so the
// applicability table is never squeezed off the screen.
func TestNetworkPolicyGraphLayoutCapsOversizedSections(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := multiRuleSubjectResult()
	for index := range 40 {
		result.Ingress.Rules = append(result.Ingress.Rules, netpol.RuleResult{
			ID: netpol.RuleID{
				PolicyNamespace: "payments", PolicyName: "bulk-" + strconv.Itoa(index),
				Direction: netpol.Ingress, Index: index,
			},
			SubjectPodCount: 1, SubjectMatchCount: 1, PeerSummary: "peer",
		})
	}
	view.applyResult(result)
	workloads := make([]ui.SubjectWorkload, 0, 40)
	for index := range 40 {
		workloads = append(workloads, ui.SubjectWorkload{
			Kind: "Pod", Namespace: "payments", Name: "api-" + strconv.Itoa(index), Status: "Running",
		})
	}
	view.workloads = workloads
	view.updateSubject()
	drawGraph(t, view, 120, 60)

	assert.LessOrEqual(t, sectionHeight(view.subjectInfo), percentOf(60, subjectMaxPercent))
	assert.LessOrEqual(t, sectionHeight(view.directions), percentOf(60, directionMaxPercent))
	assert.GreaterOrEqual(t, sectionHeight(view.details), minDetailsHeight)

	detail, ok := view.detailItem.(*ui.RuleDetails)
	require.True(t, ok)
	assert.LessOrEqual(t, sectionHeight(detail.Text), percentOf(60, detailTextMaxPercent))
	// Content that wants the whole screen must not starve the applicability
	// table: it keeps its reserved share no matter how much the rest asks for.
	assert.GreaterOrEqual(t, sectionHeight(detail.Applicability), percentOf(60, applicabilityPercent))
}

// A terminal too small for every minimum must still paint without panicking.
func TestNetworkPolicyGraphLayoutSurvivesTinyTerminals(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())
	for _, size := range [][2]int{{0, 0}, {10, 1}, {20, 6}, {40, 12}} {
		drawGraph(t, view, size[0], size[1])
		total := sectionHeight(view.subjectInfo) + sectionHeight(view.directions) + sectionHeight(view.details)
		assert.LessOrEqual(t, total, max(0, size[1]), "sections never overflow the viewport")
	}
}

// YAML follows whatever the focused section has selected.
func TestNetworkPolicyGraphYAMLTargetFollowsFocus(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := multiPrimitiveSubjectResult()
	view.applyResult(result)
	view.workloads = []ui.SubjectWorkload{
		{Kind: "Deployment", Namespace: "payments", Name: "api", Status: "1/1"},
	}
	view.updateSubject()

	view.focusDirection(netpol.Ingress)
	selectRule(t, view, result, netpol.Ingress, 0)
	gvr, path, ok := view.yamlTarget()
	require.True(t, ok, "a rule resolves to its NetworkPolicy")
	assert.Equal(t, client.NpGVR, gvr)
	assert.Equal(t, "payments/allow-api", path)

	view.applyFocusTarget(focusSubject)
	gvr, path, ok = view.yamlTarget()
	require.True(t, ok, "a subject workload resolves to its own manifest")
	assert.Equal(t, client.DpGVR, gvr)
	assert.Equal(t, "payments/api", path)

	view.focusDirection(netpol.Ingress)
	view.switchMode()
	require.Equal(t, ui.PrimitivesProjection, view.mode)
	selectPrimitive(t, view, result, netpol.Ingress, netpol.PrimitivePod, 0)
	selected, ok := view.selectedPrimitive(netpol.Ingress, view.panels[netpol.Ingress].SelectedID())
	require.True(t, ok)
	eGVR, ePath, ok := primitiveGVR(&selected.Ref)
	require.True(t, ok)
	gvr, path, ok = view.yamlTarget()
	require.True(t, ok, "a primitive resolves to its own resource")
	assert.Equal(t, eGVR, gvr)
	assert.Equal(t, ePath, path)
}

// Selections with no manifest hide the key rather than flashing an error.
func TestNetworkPolicyGraphYAMLHiddenWithoutAManifest(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := testSubjectResult()
	result.Ingress.Rules = []netpol.RuleResult{{
		ID:        netpol.RuleID{Direction: netpol.Ingress, SyntheticKind: "default-deny"},
		Synthetic: true, SubjectPodCount: 1, SubjectMatchCount: 1, PeerSummary: "none",
	}}
	view.applyResult(result)
	view.focusDirection(netpol.Ingress)
	selectRule(t, view, result, netpol.Ingress, 0)

	_, _, ok := view.yamlTarget()
	assert.False(t, ok, "a synthetic rule has no manifest")
	_, ok = view.actions.Get(ui.KeyY)
	assert.False(t, ok)

	// An empty selection has nothing to show either.
	view.applyResult(testSubjectResult())
	view.panels[netpol.Ingress].ClearSelection()
	view.syncActions()
	_, _, ok = view.yamlTarget()
	assert.False(t, ok)
	_, ok = view.actions.Get(ui.KeyY)
	assert.False(t, ok)
}

// CIDR applicability rows are not Kubernetes resources, so moving onto one
// retracts the YAML key.
func TestNetworkPolicyGraphYAMLTracksApplicabilityCursor(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := multiPrimitiveSubjectResult()
	id := result.Ingress.Rules[0].ID
	result.Ingress.Primitives[netpol.PrimitiveCIDR] = []netpol.PrimitiveResult{{
		Ref:          netpol.PrimitiveRef{Kind: netpol.PrimitiveCIDR, CIDR: "10.0.0.0/8"},
		State:        netpol.AccessAllowed,
		AllowedPairs: 1,
		TotalPairs:   1,
		Evidence:     []netpol.PolicyEvidence{{RuleID: id, Summary: "cidr evidence"}},
		PairDecisions: []netpol.PairDecision{{
			Source:      netpol.PodRef{Namespace: "payments", Name: "api"},
			Destination: netpol.PodRef{Name: "10.0.0.0/8"},
			Decision: netpol.Decision{
				State:    netpol.AccessAllowed,
				Evidence: []netpol.PolicyEvidence{{RuleID: id, Summary: "Ingress evidence"}},
			},
		}},
	}}
	view.applyResult(result)
	view.applyFocusTarget(focusApplicability)
	detail, ok := view.detailItem.(*ui.RuleDetails)
	require.True(t, ok)

	cidrID := result.Ingress.Primitives[netpol.PrimitiveCIDR][0].StableID()
	require.True(t, detail.SelectApplicabilityID(cidrID))
	_, _, found := view.yamlTarget()
	assert.False(t, found, "a CIDR row has no manifest")
	_, found = view.actions.Get(ui.KeyY)
	assert.False(t, found, "moving onto a CIDR row retracts the key")

	podID := result.Ingress.Primitives[netpol.PrimitivePod][0].StableID()
	require.True(t, detail.SelectApplicabilityID(podID))
	gvr, path, found := view.yamlTarget()
	require.True(t, found)
	assert.Equal(t, client.PodGVR, gvr)
	assert.Equal(t, "payments/peer", path)
	_, found = view.actions.Get(ui.KeyY)
	assert.True(t, found)
}

func TestWorkloadAndPrimitiveGVRs(t *testing.T) {
	uu := map[string]*client.GVR{
		"Pod":         client.PodGVR,
		"Deployment":  client.DpGVR,
		"ReplicaSet":  client.RsGVR,
		"StatefulSet": client.StsGVR,
		"DaemonSet":   client.DsGVR,
		"Job":         client.JobGVR,
	}
	for kind, e := range uu {
		gvr, ok := workloadGVR(kind)
		require.True(t, ok, kind)
		assert.Equal(t, e, gvr)
	}
	_, ok := workloadGVR("CronJob")
	assert.False(t, ok, "the collector never emits unmapped kinds")

	gvr, path, ok := primitiveGVR(&netpol.PrimitiveRef{
		Kind: netpol.PrimitiveNamespace, Name: "payments",
	})
	require.True(t, ok)
	assert.Equal(t, client.NsGVR, gvr)
	assert.Equal(t, "payments", path)

	_, _, ok = primitiveGVR(&netpol.PrimitiveRef{Kind: netpol.PrimitiveCIDR, CIDR: "10.0.0.0/8"})
	assert.False(t, ok)
}

// The applicability table is what this view exists to show, so a long rule
// detail text must not push it down to its bare minimum.
func TestNetworkPolicyGraphApplicabilityKeepsItsShare(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(multiPrimitiveSubjectResult())
	detail, ok := view.detailItem.(*ui.RuleDetails)
	require.True(t, ok)
	detail.Text.SetText(strings.Repeat("a long rule detail line\n", 200))

	for _, height := range []int{24, 40, 50, 60, 80} {
		drawGraph(t, view, 120, height)
		applicability := sectionHeight(detail.Applicability)
		assert.GreaterOrEqual(t, applicability, percentOf(height, applicabilityPercent),
			"height %d starves the applicability table", height)
		assert.GreaterOrEqual(t, applicability, minApplicabilityHeight)
	}
}

// Workloads arrive asynchronously. Focusing the Subject panel before they land
// retracts the YAML key, so the publish has to put it back.
func TestNetworkPolicyGraphWorkloadArrivalRestoresYAML(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.app = NewApp(config.NewConfig(nil))
	view.collectWorkloads = func(netpol.SubjectRef, []netpol.PodRef) ([]ui.SubjectWorkload, []string) {
		return nil, nil
	}
	view.applyResult(testSubjectResult())

	// Focus the Subject panel while collection is still in flight.
	view.workloads, view.workloadsLoading = nil, true
	view.updateSubject()
	view.applyFocusTarget(focusSubject)
	_, ok := view.actions.Get(ui.KeyY)
	require.False(t, ok, "there is nothing to show yet")

	// Replay what the collection callback does when the rows land.
	view.workloads, view.workloadNotes, view.workloadsLoading = []ui.SubjectWorkload{
		{Kind: "Deployment", Namespace: "payments", Name: "api", Status: "1/1"},
	}, nil, false
	view.updateSubject()
	view.syncActions()

	gvr, path, found := view.yamlTarget()
	require.True(t, found)
	assert.Equal(t, client.DpGVR, gvr)
	assert.Equal(t, "payments/api", path)
	_, ok = view.actions.Get(ui.KeyY)
	assert.True(t, ok, "the key must come back once the rows land")

	// The reverse transition retracts it again.
	view.workloads = nil
	view.updateSubject()
	view.syncActions()
	_, ok = view.actions.Get(ui.KeyY)
	assert.False(t, ok)
}

// A skin change has to reach the panels, or synthetic rows keep rendering in
// the previous skin's foreground color.
func TestNetworkPolicyGraphStylesChangedReachesPanels(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := testSubjectResult()
	result.Ingress.Rules = []netpol.RuleResult{{
		ID:        netpol.RuleID{Direction: netpol.Ingress, SyntheticKind: "default-deny"},
		Synthetic: true, SubjectPodCount: 1, SubjectMatchCount: 1, PeerSummary: "none",
	}}
	view.applyResult(result)

	styles := config.NewStyles()
	styles.K9s.Body.FgColor = config.Color("hotpink")
	view.StylesChanged(styles)

	panel := view.panels[netpol.Ingress]
	assert.Equal(t, styles.FgColor(), panel.GetCell(0, 1).Color,
		"the synthetic row follows the skin foreground")
}

// Primitives render no applicability table, so Enter on the detail pane is the
// only route to the resource behind the selection.
func TestNetworkPolicyGraphEnterOpensSelectedPrimitive(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := testSubjectResult()
	view.applyResult(result)
	view.switchMode()
	view.focusDirection(netpol.Ingress)
	require.Equal(t, ui.PrimitivesProjection, view.mode)
	selectPrimitive(t, view, result, netpol.Ingress, netpol.PrimitivePod, 0)

	enter := tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone)
	require.Nil(t, view.enterCmd(enter))
	require.Equal(t, focusDetails, view.focusTarget, "primitives have no applicability table")

	// A second Enter routes to the primitive rather than dead-ending. With no
	// app wired it falls through instead of navigating.
	assert.Equal(t, enter, view.enterCmd(enter))
	primitive, ok := view.selectedPrimitive(netpol.Ingress, view.panels[netpol.Ingress].SelectedID())
	require.True(t, ok)
	command, path := primitiveCommand(&primitive.Ref)
	assert.Equal(t, "pods", command)
	assert.Equal(t, "payments/peer", path)

	// Rules mode keeps Enter on the applicability table instead.
	view.focusDirection(netpol.Ingress)
	view.switchMode()
	require.Equal(t, ui.RulesProjection, view.mode)
	assert.Equal(t, enter, view.openPrimitiveCmd(enter), "Rules mode has no primitive to open")
}

// CIDR primitives are not Kubernetes resources, so Enter reports that rather
// than silently swallowing the key.
func TestNetworkPolicyGraphEnterReportsCIDRPrimitive(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.app = NewApp(config.NewConfig(nil))
	result := testSubjectResult()
	result.Ingress.Primitives = map[netpol.PrimitiveKind][]netpol.PrimitiveResult{
		netpol.PrimitiveCIDR: {{
			Ref:          netpol.PrimitiveRef{Kind: netpol.PrimitiveCIDR, CIDR: "10.0.0.0/8"},
			State:        netpol.AccessAllowed,
			AllowedPairs: 1,
			TotalPairs:   1,
		}},
	}
	view.applyResult(result)
	view.switchMode()
	view.focusDirection(netpol.Ingress)
	require.Equal(t, ui.PrimitivesProjection, view.mode)
	selectPrimitive(t, view, result, netpol.Ingress, netpol.PrimitiveCIDR, 0)

	enter := tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone)
	require.Nil(t, view.enterCmd(enter))
	require.Equal(t, focusDetails, view.focusTarget)
	assert.Nil(t, view.enterCmd(enter), "the key must be consumed, not silently ignored")
	message := <-view.app.Flash().Channel()
	assert.Contains(t, message.Text, "not Kubernetes resources")
}

// The direction panels no longer badge a rule's state, so the detail pane
// points at the line that explains it.
func TestNetworkPolicyGraphHighlightsPartialStateLine(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := testSubjectResult()
	// One of two subject pods matches: a partial rule.
	result.Subject.Pods = append(result.Subject.Pods, netpol.PodRef{Namespace: "payments", Name: "api-2"})
	result.Ingress.Rules[0].SubjectPodCount = 2
	result.Ingress.Rules[0].SubjectMatchCount = 1
	view.applyResult(result)
	selectRule(t, view, result, netpol.Ingress, 0)

	detail, ok := view.detailItem.(*ui.RuleDetails)
	require.True(t, ok)
	raw := detail.Text.GetText(false)
	assert.Contains(t, raw, "[yellow::b]State: Partial", "the state line is highlighted")
	assert.NotContains(t, raw, "[yellow::b]Direction:", "only the state line is highlighted")

	// A fully matched rule has nothing to explain.
	result = testSubjectResult()
	view.applyResult(result)
	selectRule(t, view, result, netpol.Ingress, 0)
	detail, ok = view.detailItem.(*ui.RuleDetails)
	require.True(t, ok)
	assert.NotContains(t, detail.Text.GetText(false), "[yellow::b]")
}

// Rule detail bodies carry YAML and selectors with square brackets, which the
// dynamic-color TextView must not eat.
func TestNetworkPolicyGraphDetailTextSurvivesBrackets(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	result := testSubjectResult()
	result.Ingress.Rules[0].Peers = []string{"ipBlock=10.0.0.0/8 except [10.1.0.0/16]"}
	result.Ingress.Rules[0].YAML = "ingress:\n  - ports: []\n"
	view.applyResult(result)
	selectRule(t, view, result, netpol.Ingress, 0)

	detail, ok := view.detailItem.(*ui.RuleDetails)
	require.True(t, ok)
	text := detail.Text.GetText(true)
	assert.Contains(t, text, "except [10.1.0.0/16]")
	assert.Contains(t, text, "ports: []")
}
