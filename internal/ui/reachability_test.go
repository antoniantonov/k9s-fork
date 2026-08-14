// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package ui

import (
	"testing"

	"github.com/derailed/k9s/internal/config"
	"github.com/derailed/k9s/internal/netpol"
	"github.com/derailed/tcell/v2"
	"github.com/derailed/tview"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"
)

func TestDirectionPanelRendersMultiRowBlocksAndTrailingSeparators(t *testing.T) {
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetRules(testRules())

	require.Equal(t, 9, panel.GetRowCount())
	assert.Equal(t, testRules()[0].StableID(), panel.GetCell(0, 0).GetReference())
	assert.Equal(t, testRules()[0].StableID(), panel.GetCell(1, 1).GetReference())
	assert.True(t, panel.GetCell(2, 0).NotSelectable)
	assert.True(t, panel.GetCell(8, 2).NotSelectable, "the final item must have a separator")
	assert.Contains(t, panel.GetCell(2, 0).Text, "─")
}

func TestDirectionPanelASCIISeparators(t *testing.T) {
	panel := NewDirectionPanel(netpol.Ingress, true)
	panel.SetRules(testRules()[:1])

	assert.Equal(t, "------------", panel.GetCell(2, 0).Text)
	panel.SetASCII(false)
	assert.Equal(t, "────────────", panel.GetCell(2, 0).Text)
}

func TestDirectionPanelProjectionTitleAndFilter(t *testing.T) {
	panel := NewDirectionPanel(netpol.Egress)
	panel.SetData(testRules(), testPrimitives())
	assert.Equal(t, " Egress · Rules ", panel.PanelTitle())

	panel.SetProjection(PrimitivesProjection).SetFilter("database")
	assert.Len(t, panel.blocks, 1)
	assert.Contains(t, panel.GetCell(0, 1).Text, "database")
	assert.Equal(t, " Egress · Primitives · filter: database ", panel.PanelTitle())

	panel.SetFilter("TCP/all")
	assert.Len(t, panel.blocks, 1, "filtering includes permission text")
}

func TestDirectionPanelAccessLabelsAndColors(t *testing.T) {
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetProjection(PrimitivesProjection).SetPrimitives(testPrimitives())

	assert.Equal(t, "Allowed", panel.GetCell(0, 0).Text)
	assert.Equal(t, reachabilityAllowedColor, panel.GetCell(0, 0).Color)
	assert.True(t, panel.GetCell(0, 0).Transparent)
	assert.Equal(t, "[PARTIAL 1/2]", panel.GetCell(3, 0).Text)
	assert.Equal(t, reachabilityDisallowedColor, panel.GetCell(3, 0).Color)
	assert.True(t, panel.GetCell(3, 0).Transparent)
	assert.Equal(t, "Unknown", panel.GetCell(6, 0).Text)
	assert.Equal(t, "[EMPTY]", panel.GetCell(9, 0).Text)
	assert.Equal(t, "Partial Data", panel.GetCell(12, 0).Text)
	assert.Equal(t, reachabilityPartialColor, panel.GetCell(12, 0).Color)
	assert.True(t, panel.GetCell(12, 0).Transparent)

	style := config.Reachability{
		AllowedColor:     config.Color("green"),
		DisallowedColor:  config.Color("red"),
		PartialDataColor: config.Color("orange"),
		FocusColor:       config.Color("orange"),
	}
	panel.SetReachabilityStyle(style)
	assert.Equal(t, style.AllowedColor.Color(), panel.GetCell(0, 0).Color)
	assert.Equal(t, style.DisallowedColor.Color(), panel.GetCell(3, 0).Color)
	assert.Equal(t, style.PartialDataColor.Color(), panel.GetCell(12, 0).Color)
}

func TestDirectionPanelNavigationSkipsSeparators(t *testing.T) {
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetRules(testRules())
	panel.SetRect(0, 0, 80, 5)
	panel.Select(1, 0)

	panel.captureInput(tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone))
	row, _ := panel.GetSelection()
	assert.Equal(t, 3, row)

	panel.captureInput(tcell.NewEventKey(tcell.KeyUp, 0, tcell.ModNone))
	row, _ = panel.GetSelection()
	assert.Equal(t, 0, row)

	panel.captureInput(tcell.NewEventKey(tcell.KeyEnd, 0, tcell.ModNone))
	row, _ = panel.GetSelection()
	assert.Equal(t, 6, row)

	panel.captureInput(tcell.NewEventKey(tcell.KeyHome, 0, tcell.ModNone))
	row, _ = panel.GetSelection()
	assert.Equal(t, 0, row)

	panel.captureInput(tcell.NewEventKey(tcell.KeyPgDn, 0, tcell.ModNone))
	row, _ = panel.GetSelection()
	assert.Equal(t, 3, row)
	panel.captureInput(tcell.NewEventKey(tcell.KeyPgUp, 0, tcell.ModNone))
	row, _ = panel.GetSelection()
	assert.Equal(t, 0, row)
}

func TestDirectionPanelClearSelection(t *testing.T) {
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetRules(testRules())
	require.True(t, panel.HasSelection())
	require.NotEmpty(t, panel.SelectedID())

	panel.ClearSelection()

	assert.Empty(t, panel.SelectedID())
	assert.False(t, panel.HasSelection())
}

func TestDirectionPanelClearSelectionBeforeDataKeepsClearedState(t *testing.T) {
	panel := NewDirectionPanel(netpol.Ingress)
	require.False(t, panel.HasSelection())

	panel.ClearSelection()
	panel.SetData(testRules(), testPrimitives())

	assert.Empty(t, panel.SelectedID())
	assert.False(t, panel.HasSelection())
	assert.True(t, panel.ScrollState().Cleared)
}

func TestDirectionPanelClearSelectionNotifiesEmptyID(t *testing.T) {
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetRules(testRules())
	selected := "unchanged"
	panel.SetSelectionChangedFunc(func(id string) { selected = id })

	panel.ClearSelection()

	assert.Empty(t, selected)
}

func TestDirectionPanelClearSelectionCallbackIsIdempotent(t *testing.T) {
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetRules(testRules())
	var calls int
	panel.SetSelectionChangedFunc(func(string) { calls++ })

	panel.ClearSelection()
	panel.ClearSelection()

	assert.Equal(t, 1, calls)
}

func TestDirectionPanelClearedSelectionSurvivesRebuilds(t *testing.T) {
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetData(testRules(), testPrimitives())
	panel.ClearSelection()

	panel.SetData(testRules(), testPrimitives())
	assert.Empty(t, panel.SelectedID())
	assert.False(t, panel.HasSelection())

	panel.SetFilter("allow")
	assert.Empty(t, panel.SelectedID())
	assert.False(t, panel.HasSelection())

	panel.SetProjection(PrimitivesProjection)
	assert.Empty(t, panel.SelectedID())
	assert.False(t, panel.HasSelection())
}

func TestDirectionPanelClearedSelectionSurvivesEmptyFilterAndReturn(t *testing.T) {
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetRules(testRules())
	panel.ClearSelection()

	panel.SetFilter("does-not-match-anything")
	assert.Empty(t, panel.SelectedID())
	assert.False(t, panel.HasSelection())
	assert.Zero(t, len(panel.blocks))

	panel.SetFilter("")
	assert.Empty(t, panel.SelectedID())
	assert.False(t, panel.HasSelection())
	assert.Len(t, panel.blocks, len(testRules()))
}

func TestDirectionPanelClearedSelectionSurvivesDifferentDataUntilExplicitSelect(t *testing.T) {
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetRules(testRules())
	panel.ClearSelection()

	changed := []netpol.RuleResult{{
		ID:              netpol.RuleID{PolicyNamespace: "other", PolicyName: "allow-other", Direction: netpol.Ingress, Index: 9},
		SubjectPodCount: 1, SubjectMatchCount: 1,
	}}
	panel.SetRules(changed)
	validID := changed[0].StableID()

	assert.Empty(t, panel.SelectedID())
	assert.False(t, panel.HasSelection())
	assert.False(t, panel.SelectID("missing"))
	assert.Empty(t, panel.SelectedID())
	assert.True(t, panel.SelectID(validID))
	assert.Equal(t, validID, panel.SelectedID())
	assert.True(t, panel.HasSelection())
}

func TestDirectionPanelRestoresStableSelectionAndNearestFallback(t *testing.T) {
	rules := testRules()
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetRules(rules)
	require.True(t, panel.SelectID(rules[1].StableID()))
	panel.SetOffset(2, 1)

	panel.SetRules([]netpol.RuleResult{rules[2], rules[1], rules[0]})
	assert.Equal(t, rules[1].StableID(), panel.SelectedID())
	row, _ := panel.GetSelection()
	assert.Equal(t, 3, row)

	panel.SetRules([]netpol.RuleResult{rules[2], rules[0]})
	assert.Equal(t, rules[0].StableID(), panel.SelectedID(), "missing selection falls back to nearest index")
}

func TestDirectionPanelScrollStateRestoresClearedSelection(t *testing.T) {
	rules := testRules()
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetRules(rules)
	panel.ClearSelection()
	state := panel.ScrollState()
	require.True(t, state.Cleared)
	require.Empty(t, state.SelectedID)

	restored := NewDirectionPanel(netpol.Ingress)
	restored.SetRules(rules)
	restored.RestoreScrollState(state)
	assert.Empty(t, restored.SelectedID())
	assert.False(t, restored.HasSelection())

	state.Cleared = false
	state.SelectedID = rules[1].StableID()
	restored.RestoreScrollState(state)
	assert.Equal(t, rules[1].StableID(), restored.SelectedID())
	assert.True(t, restored.HasSelection())
}

func TestDirectionPanelScrollStateHelpers(t *testing.T) {
	rules := testRules()
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetRules(rules)
	panel.SelectID(rules[2].StableID())
	panel.SetOffset(4, 2)
	state := panel.ScrollState()

	restored := NewDirectionPanel(netpol.Ingress)
	restored.SetRules(rules)
	restored.RestoreScrollState(state)
	assert.Equal(t, rules[2].StableID(), restored.SelectedID())
	row, column := restored.GetOffset()
	assert.Equal(t, 4, row)
	assert.Equal(t, 2, column)

	state.SelectedID = "gone"
	state.Row = 3
	state.SelectedRow = 3
	restored.RestoreScrollState(state)
	assert.Equal(t, rules[1].StableID(), restored.SelectedID())
}

func TestDirectionPanelNavigationReselectsAfterClear(t *testing.T) {
	rules := testRules()
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetRules(rules)

	panel.ClearSelection()
	require.Nil(t, panel.captureInput(tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone)))
	assert.Equal(t, rules[0].StableID(), panel.SelectedID())
	assert.True(t, panel.HasSelection())

	panel.ClearSelection()
	require.Nil(t, panel.captureInput(tcell.NewEventKey(tcell.KeyUp, 0, tcell.ModNone)))
	assert.Equal(t, rules[2].StableID(), panel.SelectedID())
	assert.True(t, panel.HasSelection())
}

func TestDirectionPanelNavigationWhileClearedAndEmptyFallsThrough(t *testing.T) {
	panel := NewDirectionPanel(netpol.Ingress)
	panel.ClearSelection()

	for _, key := range []tcell.Key{tcell.KeyDown, tcell.KeyUp, tcell.KeyPgDn, tcell.KeyPgUp, tcell.KeyHome, tcell.KeyEnd} {
		event := tcell.NewEventKey(key, 0, tcell.ModNone)
		assert.Equal(t, event, panel.captureInput(event), key)
		assert.Empty(t, panel.SelectedID())
		assert.False(t, panel.HasSelection())
	}
}

func TestDirectionPanelClearedSelectionSurvivesStyleRebuilds(t *testing.T) {
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetRules(testRules())
	panel.ClearSelection()

	panel.SetASCII(true)
	panel.SetStyles(config.NewStyles())
	panel.SetReachabilityStyle(config.Reachability{
		AllowedColor:     config.Color("green"),
		DisallowedColor:  config.Color("red"),
		PartialDataColor: config.Color("orange"),
	})

	assert.Empty(t, panel.SelectedID())
	assert.False(t, panel.HasSelection())
}

func TestDirectionPanelSelectionCallbackAndStyleKeepsResultAsTextColor(t *testing.T) {
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetProjection(PrimitivesProjection).SetPrimitives(testPrimitives())
	var selected string
	panel.SetSelectionChangedFunc(func(id string) { selected = id })

	panel.captureInput(tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone))
	assert.Equal(t, testPrimitives()[1].StableID(), selected)
	assert.Equal(t, reachabilityDisallowedColor, panel.GetCell(3, 0).Color)
	assert.True(t, panel.GetCell(3, 0).Transparent)
}

func TestDirectionPanelSelectionStyleUsesTableCursorColors(t *testing.T) {
	styles := config.NewStyles()
	styles.K9s.Views.Table.CursorFgColor = config.Color("blue")
	styles.K9s.Views.Table.CursorBgColor = config.Color("yellow")
	panel := NewDirectionPanelWithStyle(netpol.Ingress, styles)
	panel.SetProjection(PrimitivesProjection).SetPrimitives(testPrimitives())
	panel.SelectID(testPrimitives()[1].StableID())

	fg, bg, attrs := panel.selectionStyle().Decompose()
	assert.Equal(t, styles.Table().CursorFgColor.Color(), fg)
	assert.Equal(t, styles.Table().CursorBgColor.Color(), bg)
	assert.Equal(t, tcell.AttrBold, attrs&tcell.AttrBold)
	assert.NotEqual(t, panel.GetCell(3, 0).Color, bg)
}

func TestRuleStateLabels(t *testing.T) {
	rules := testRules()
	state, label := ruleState(&rules[0])
	assert.Equal(t, netpol.AccessAllowed, state)
	assert.Equal(t, "Allowed", label)
	_, label = ruleState(&rules[1])
	assert.Equal(t, "[PARTIAL 1/2]", label)
	_, label = ruleState(&rules[2])
	assert.Equal(t, "[EMPTY]", label)
	rules[0].Warnings = []string{"incomplete"}
	_, label = ruleState(&rules[0])
	assert.Equal(t, "Partial Data", label)
}

func TestPrimitiveAndRuleDetails(t *testing.T) {
	primitive := testPrimitives()[0]
	primitive.Evidence = []netpol.PolicyEvidence{{Summary: "policy allows web"}}
	primitive.Warnings = []string{"snapshot incomplete"}
	primitive.PairDecisions = []netpol.PairDecision{{
		Source:      netpol.PodRef{Namespace: "ns", Name: "client"},
		Destination: netpol.PodRef{Namespace: "ns", Name: "server"},
		Decision:    netpol.Decision{State: netpol.AccessAllowed},
	}}
	text := PrimitiveDetailsText(primitive)
	assert.Contains(t, text, "Deployment ns/database")
	assert.Contains(t, text, "policy allows web")
	assert.Contains(t, text, "snapshot incomplete")
	assert.Contains(t, text, "client -> ns/server: Allowed")
	view := NewPrimitiveDetails(primitive)
	assert.Contains(t, view.GetText(true), "Pairs: 4/4")

	rule := testRules()[0]
	rule.ID.PolicyUID = "policy-uid"
	rule.PolicySelector = "app=server"
	rule.Peers = []string{"podSelector=role=client"}
	rule.YAML = "ingress:\n  from:\n    - podSelector: role=client"
	rule.Evidence = []netpol.PolicyEvidence{{Summary: "selected peer"}}
	details := NewRuleDetails(rule, []netpol.ApplicabilityRow{{
		Primitive:          primitive,
		PeerMatches:        true,
		OppositeSideAllows: false,
		EffectiveState:     netpol.AccessPartial,
		Permissions:        primitive.Permissions,
	}})
	assert.Contains(t, details.Text.GetText(true), "selected peer")
	assert.Contains(t, details.Text.GetText(true), "Policy: ns/allow-web")
	assert.Contains(t, details.Text.GetText(true), "Policy UID: policy-uid")
	assert.Contains(t, details.Text.GetText(true), "Policy pod selector: app=server")
	assert.Contains(t, details.Text.GetText(true), "podSelector=role=client")
	assert.Contains(t, details.Text.GetText(true), "Rule YAML:")
	assert.Equal(t, 2, details.Applicability.GetRowCount())
	assert.Equal(t, "Primitive", details.Applicability.GetCell(0, 0).Text)
	assert.Equal(t, "Partial", details.Applicability.GetCell(1, 3).Text)
	assert.Equal(t, reachabilityDisallowedColor, details.Applicability.GetCell(1, 0).Color)
	assert.True(t, details.Applicability.GetCell(1, 0).Transparent)
}

func TestNewEffectiveDetailsWithStyle(t *testing.T) {
	primitives := testPrimitives()
	rows := []netpol.ApplicabilityRow{
		{
			Primitive:          primitives[0],
			PeerMatches:        true,
			OppositeSideAllows: false,
			EffectiveState:     netpol.AccessAllowed,
			Permissions:        primitives[0].Permissions,
		},
		{
			Primitive:          primitives[1],
			PeerMatches:        false,
			OppositeSideAllows: true,
			EffectiveState:     netpol.AccessPartial,
		},
	}

	details := NewEffectiveDetailsWithStyle("effective body", rows, config.Reachability{
		AllowedColor:     config.Color("green"),
		DisallowedColor:  config.Color("red"),
		PartialDataColor: config.Color("orange"),
	})

	assert.Equal(t, "effective body", details.Text.GetText(true))
	assert.Equal(t, " Effective Details ", details.Text.GetTitle())
	assert.Equal(t, " Effective Applicability ", details.Applicability.GetTitle())
	assert.Equal(t, len(rows)+1, details.Applicability.GetRowCount())
}

func TestPrimitiveDetailsUsesNormalizedState(t *testing.T) {
	primitive := testPrimitives()[0]
	primitive.State = netpol.AccessAllowed
	primitive.Warnings = []string{"snapshot incomplete"}
	assert.Contains(t, PrimitiveDetailsText(primitive), "State: Partial Data")

	primitive.Warnings = nil
	primitive.AllowedPairs = 0
	primitive.TotalPairs = 0
	assert.Contains(t, PrimitiveDetailsText(primitive), "State: [EMPTY]")
}

func TestPartialAndEmptyLabelsAreSearchableAndRemainDisallowedColored(t *testing.T) {
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetRules(testRules()).SetFilter("[PARTIAL 1/2]")
	require.Equal(t, 3, panel.GetRowCount())
	assert.Equal(t, "[PARTIAL 1/2]", panel.GetCell(0, 0).Text)
	assert.Equal(t, reachabilityDisallowedColor, panel.GetCell(0, 0).Color)
	assert.True(t, panel.GetCell(0, 0).Transparent)

	panel.SetFilter("[EMPTY]")
	require.Equal(t, 3, panel.GetRowCount())
	assert.Equal(t, "[EMPTY]", panel.GetCell(0, 0).Text)
	assert.Equal(t, reachabilityDisallowedColor, panel.GetCell(0, 0).Color)
	assert.True(t, panel.GetCell(0, 0).Transparent)
}

func TestDirectionPanelEmptyMessageIsNonSelectable(t *testing.T) {
	panel := NewDirectionPanel(netpol.Ingress).
		SetEmptyMessage("No primitive kinds selected")

	require.Equal(t, 1, panel.GetRowCount())
	assert.Equal(t, "No primitive kinds selected", panel.GetCell(0, 0).Text)
	assert.True(t, panel.GetCell(0, 0).NotSelectable)
	assert.Empty(t, panel.SelectedID())
}

func TestApplicabilityCIDROppositeSideIsNotApplicable(t *testing.T) {
	table := NewApplicabilityTable([]netpol.ApplicabilityRow{{
		Primitive: netpol.PrimitiveResult{
			Ref:   netpol.PrimitiveRef{Kind: netpol.PrimitiveCIDR, CIDR: "10.0.0.0/8"},
			State: netpol.AccessAllowed,
		},
		PeerMatches:        true,
		OppositeSideAllows: true,
		EffectiveState:     netpol.AccessAllowed,
	}})

	assert.Equal(t, "n/a", table.GetCell(1, 2).Text)
}

func TestPrimitiveKindDialogOwnsStateAndCallbacks(t *testing.T) {
	original := sets.New(netpol.PrimitivePod)
	var applied sets.Set[netpol.PrimitiveKind]
	canceled := false
	dialog := NewPrimitiveKindDialog(original, func(kinds sets.Set[netpol.PrimitiveKind]) {
		applied = kinds
	}, func() {
		canceled = true
	})

	assert.Equal(t, 5, dialog.GetFormItemCount())
	assert.Equal(t, 2, dialog.GetButtonCount())
	pod := dialog.GetFormItemByLabel("Pod").(*tview.Checkbox)
	cidr := dialog.GetFormItemByLabel("CIDR").(*tview.Checkbox)
	pod.InputHandler()(tcell.NewEventKey(tcell.KeyRune, ' ', tcell.ModNone), nil)
	cidr.InputHandler()(tcell.NewEventKey(tcell.KeyRune, ' ', tcell.ModNone), nil)
	assert.True(t, original.Has(netpol.PrimitivePod), "caller state must not be mutated")

	dialog.Apply()
	assert.True(t, applied.Has(netpol.PrimitiveCIDR))
	assert.False(t, applied.Has(netpol.PrimitivePod))
	applied.Insert(netpol.PrimitiveJob)
	assert.False(t, dialog.SelectedKinds().Has(netpol.PrimitiveJob), "callback receives a clone")

	dialog.Cancel()
	assert.True(t, canceled)

	empty := NewPrimitiveKindDialog(nil, nil, nil)
	empty.GetFormItemByLabel("Job").(*tview.Checkbox).
		InputHandler()(tcell.NewEventKey(tcell.KeyRune, ' ', tcell.ModNone), nil)
	assert.True(t, empty.SelectedKinds().Has(netpol.PrimitiveJob))
}

func testRules() []netpol.RuleResult {
	return []netpol.RuleResult{
		{
			ID:                netpol.RuleID{PolicyNamespace: "ns", PolicyName: "allow-web", Direction: netpol.Ingress, Index: 0},
			SubjectPodCount:   2,
			SubjectMatchCount: 2,
			PeerSummary:       "app=web",
			Permissions:       []netpol.PortPermission{{All: true}},
		},
		{
			ID:                netpol.RuleID{PolicyNamespace: "ns", PolicyName: "allow-some", Direction: netpol.Ingress, Index: 1},
			SubjectPodCount:   2,
			SubjectMatchCount: 1,
			PeerSummary:       "app=client",
		},
		{
			ID:                netpol.RuleID{PolicyNamespace: "ns", PolicyName: "empty", Direction: netpol.Ingress, Index: 2},
			SubjectPodCount:   2,
			SubjectMatchCount: 0,
		},
	}
}

func testPrimitives() []netpol.PrimitiveResult {
	return []netpol.PrimitiveResult{
		{
			Ref:          netpol.PrimitiveRef{Kind: netpol.PrimitiveDeployment, Namespace: "ns", Name: "database"},
			State:        netpol.AccessAllowed,
			AllowedPairs: 4,
			TotalPairs:   4,
			Permissions:  []netpol.PortPermission{{All: true}},
			Explanation:  "all pairs allowed",
		},
		{
			Ref:          netpol.PrimitiveRef{Kind: netpol.PrimitivePod, Namespace: "ns", Name: "partial"},
			State:        netpol.AccessPartial,
			AllowedPairs: 1,
			TotalPairs:   2,
		},
		{
			Ref:        netpol.PrimitiveRef{Kind: netpol.PrimitiveNamespace, Name: "unknown"},
			State:      netpol.AccessUnknown,
			TotalPairs: 2,
		},
		{
			Ref:   netpol.PrimitiveRef{Kind: netpol.PrimitiveCIDR, CIDR: "10.0.0.0/8"},
			State: netpol.AccessDisallowed,
		},
		{
			Ref:        netpol.PrimitiveRef{Kind: netpol.PrimitiveJob, Namespace: "ns", Name: "incomplete"},
			State:      netpol.AccessPartialData,
			TotalPairs: 1,
		},
	}
}
