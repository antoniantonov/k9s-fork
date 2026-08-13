// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package view

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

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
	view.applyResult(testSubjectResult())
	ingress := view.panels[netpol.Ingress]
	ruleID := ingress.SelectedID()
	require.NotEmpty(t, ruleID)

	view.applySearch("allow-api")
	view.savePanelState(netpol.Ingress)
	view.switchMode(netpol.Ingress)
	assert.Equal(t, ui.PrimitivesProjection, view.state[netpol.Ingress].mode)
	assert.Empty(t, ingress.Filter())

	view.applySearch("peer")
	primitiveID := ingress.SelectedID()
	view.switchMode(netpol.Ingress)
	assert.Equal(t, ui.RulesProjection, view.state[netpol.Ingress].mode)
	assert.Equal(t, "allow-api", ingress.Filter())
	assert.Equal(t, ruleID, ingress.SelectedID())

	view.switchMode(netpol.Ingress)
	assert.Equal(t, "peer", ingress.Filter())
	assert.Equal(t, primitiveID, ingress.SelectedID())
	assert.Equal(t, ui.RulesProjection, view.state[netpol.Egress].mode)
}

func TestNetworkPolicyGraphGlobalKindsAndEmptySelection(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())

	view.kinds = sets.New[netpol.PrimitiveKind]()
	view.loadPanel(netpol.Ingress)
	view.updateDetails(netpol.Ingress)
	assert.NotContains(t, view.panels[netpol.Ingress].PanelTitle(), "kinds:")
	assert.Contains(t, view.panels[netpol.Ingress].GetCell(0, 1).Text, "allow-api", "rules remain visible")
	ruleDetails, ok := view.detailItem.(*ui.RuleDetails)
	require.True(t, ok)
	assert.Equal(t, 1, ruleDetails.Applicability.GetRowCount(), "global kind filters constrain applicability")

	view.switchMode(netpol.Ingress)
	assert.Contains(t, view.panels[netpol.Ingress].GetCell(0, 0).Text, "No primitive kinds selected")
	assert.True(t, view.panels[netpol.Ingress].GetCell(0, 0).NotSelectable)
	view.switchMode(netpol.Egress)
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
	view.switchMode(netpol.Ingress)
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
	assert.Equal(t, ui.PrimitivesProjection, view.state[netpol.Ingress].mode)
	// Shift-M propagates the focused mode; it must not toggle it first.
	assert.Nil(t, view.keyboard(tcell.NewEventKey(tcell.KeyRune, 'M', tcell.ModShift)))
	assert.Equal(t, ui.PrimitivesProjection, view.state[netpol.Ingress].mode)
	assert.Equal(t, ui.PrimitivesProjection, view.state[netpol.Egress].mode)

	// Applicability focus only exists in Rules mode, so return both panels to it
	// before exercising the focus cycle below.
	assert.Nil(t, view.keyboard(tcell.NewEventKey(tcell.KeyRune, 'm', tcell.ModNone)))
	assert.Nil(t, view.keyboard(tcell.NewEventKey(tcell.KeyRune, 'M', tcell.ModShift)))
	assert.Equal(t, ui.RulesProjection, view.state[netpol.Ingress].mode)
	assert.Equal(t, ui.RulesProjection, view.state[netpol.Egress].mode)

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
	assert.Nil(t, view.keyboard(tcell.NewEventKey(tcell.KeyBacktab, 0, tcell.ModShift)))
	assert.Equal(t, focusIngress, view.focusTarget)
	assert.Nil(t, view.keyboard(tcell.NewEventKey(tcell.KeyBacktab, 0, tcell.ModShift)))
	assert.Equal(t, focusSubject, view.focusTarget)
	assert.Nil(t, view.keyboard(tcell.NewEventKey(tcell.KeyTAB, 0, tcell.ModNone)))
	assert.Equal(t, netpol.Ingress, view.focus)
	assert.Equal(t, focusIngress, view.focusTarget)

	view.focusDirection(netpol.Ingress)
	assert.Nil(t, view.keyboard(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone)))
	assert.Equal(t, focusDetails, view.focusTarget)
	assert.Nil(t, view.keyboard(tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone)))
	assert.Equal(t, focusApplicability, view.focusTarget)

	assert.Nil(t, view.keyboard(tcell.NewEventKey(tcell.KeyRune, 'i', tcell.ModNone)))
	assert.False(t, view.state[netpol.Ingress].visible)
	assert.Equal(t, netpol.Egress, view.focus)
	assert.NotNil(t, view.keyboard(tcell.NewEventKey(tcell.KeyUp, 0, tcell.ModNone)))
}

func TestNetworkPolicyGraphShiftMDoesNotModifyHiddenPanelMode(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())
	view.toggleDirection(netpol.Egress)

	view.switchMode(netpol.Ingress)
	view.switchVisibleModesFromFocus()
	assert.Equal(t, ui.PrimitivesProjection, view.state[netpol.Ingress].mode)
	assert.Equal(t, ui.RulesProjection, view.state[netpol.Egress].mode)
}

func TestNetworkPolicyGraphShiftMPropagatesFocusedModeWithoutToggling(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.applyResult(testSubjectResult())

	view.switchMode(netpol.Ingress)
	require.Equal(t, ui.PrimitivesProjection, view.state[netpol.Ingress].mode)

	view.switchVisibleModesFromFocus()
	assert.Equal(t, ui.PrimitivesProjection, view.state[netpol.Ingress].mode,
		"the focused panel must keep its mode")
	assert.Equal(t, ui.PrimitivesProjection, view.state[netpol.Egress].mode,
		"the other visible panel must adopt the focused mode")
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
	modeState := state.states[state.mode]
	modeState.scroll = ui.ReachabilityScrollState{SelectedID: result.Ingress.Rules[0].StableID()}
	state.states[state.mode] = modeState

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
