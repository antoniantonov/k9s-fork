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
	state, label = ruleState(&rules[2])
	assert.Equal(t, netpol.AccessAllowed, state)
	assert.Equal(t, "Allowed", label)
	rules[0].Warnings = []string{"incomplete"}
	_, label = ruleState(&rules[0])
	assert.Equal(t, "Partial Data", label)

	// A rule with no matching subjects is [EMPTY] regardless of projection
	// filtering, whether that is because no subject pod is selected or
	// because none of the selected pods matched a peer.
	empty := netpol.RuleResult{SubjectPodCount: 2, SubjectMatchCount: 0}
	_, label = ruleState(&empty)
	assert.Equal(t, "[EMPTY]", label)
	noPods := netpol.RuleResult{SubjectPodCount: 0, SubjectMatchCount: 0}
	_, label = ruleState(&noPods)
	assert.Equal(t, "[EMPTY]", label)
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

	// A non-synthetic [EMPTY] rule is now hidden from the Rules projection
	// entirely, so searching for its label no longer surfaces it.
	panel.SetFilter("[EMPTY]")
	assert.Zero(t, panel.GetRowCount())
	assert.Empty(t, panel.blocks)
}

func TestDirectionPanelHidesNonApplicableNonSyntheticRule(t *testing.T) {
	rules := []netpol.RuleResult{
		{
			ID:                netpol.RuleID{PolicyNamespace: "ns", PolicyName: "allow-web", Direction: netpol.Ingress, Index: 0},
			SubjectPodCount:   2,
			SubjectMatchCount: 2,
		},
		{
			ID:                netpol.RuleID{PolicyNamespace: "ns", PolicyName: "no-match", Direction: netpol.Ingress, Index: 1},
			SubjectPodCount:   2,
			SubjectMatchCount: 0,
		},
	}
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetRules(rules)

	require.Len(t, panel.blocks, 1, "a non-synthetic rule with no matching subjects must be filtered out")
	assert.Equal(t, rules[0].StableID(), panel.blocks[0].id)
	assert.False(t, panel.SelectID(rules[1].StableID()), "the hidden rule must not be reachable by ID")
}

func TestDirectionPanelKeepsSyntheticEmptyRuleVisible(t *testing.T) {
	rules := []netpol.RuleResult{{
		ID:                netpol.RuleID{Direction: netpol.Ingress, Index: -1, SyntheticKind: "default-deny"},
		Synthetic:         true,
		SubjectPodCount:   2,
		SubjectMatchCount: 0,
		PeerSummary:       "default-deny",
	}}
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetRules(rules)

	require.Len(t, panel.blocks, 1, "a synthetic rule must stay visible even when it has no matching subjects")
	assert.True(t, panel.blocks[0].synthetic)
	assert.Equal(t, "[EMPTY]", panel.blocks[0].label)
	assert.Equal(t, "[EMPTY]", panel.GetCell(0, 0).Text, "synthetic rules still render their badge")
}

func TestDirectionPanelAllowedRuleBadgeIsBlankButStaysAllowedColoredAndSearchable(t *testing.T) {
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetRules(testRules()[:1])

	require.Equal(t, "Allowed", panel.blocks[0].label, "the label is preserved for color and search")
	assert.Empty(t, panel.GetCell(0, 0).Text, "the Allowed badge is redundant once only applicable rules are listed")
	assert.Equal(t, reachabilityAllowedColor, panel.GetCell(0, 0).Color)
	assert.True(t, panel.GetCell(0, 0).Transparent)

	panel.SetFilter("allowed")
	assert.Len(t, panel.blocks, 1, "the rule must remain searchable by its label even without a rendered badge")
}

func TestDirectionPanelPartialAndPartialDataBadgesStillRender(t *testing.T) {
	rules := testRules()
	rules[0].Warnings = []string{"incomplete"}
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetRules(rules)

	assert.Equal(t, "Partial Data", panel.GetCell(0, 0).Text)
	assert.Equal(t, "[PARTIAL 1/2]", panel.GetCell(3, 0).Text)
}

func TestDirectionPanelSyntheticRuleUsesNeutralColorAndFollowsSetStyles(t *testing.T) {
	rules := []netpol.RuleResult{{
		ID:                netpol.RuleID{Direction: netpol.Ingress, Index: -1, SyntheticKind: "unrestricted"},
		Synthetic:         true,
		SubjectPodCount:   2,
		SubjectMatchCount: 2,
		PeerSummary:       "unrestricted",
	}}
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetRules(rules)

	// Allowed + fully matched would normally color green, but synthetic rows
	// always render neutral instead.
	assert.Equal(t, tview.Styles.PrimaryTextColor, panel.GetCell(0, 0).Color)
	assert.NotEqual(t, reachabilityAllowedColor, panel.GetCell(0, 0).Color)

	styles := config.NewStyles()
	styles.K9s.Body.FgColor = config.Color("fuchsia")
	panel.SetStyles(styles)

	assert.Equal(t, styles.FgColor(), panel.GetCell(0, 0).Color, "SetStyles must make synthetic rows follow the skin foreground color")

	// SetReachabilityStyle alone (config.Reachability has no neutral field)
	// must preserve the neutral color set above rather than resetting it.
	panel.SetReachabilityStyle(config.Reachability{
		AllowedColor:     config.Color("green"),
		DisallowedColor:  config.Color("red"),
		PartialDataColor: config.Color("orange"),
	})
	assert.Equal(t, styles.FgColor(), panel.GetCell(0, 0).Color, "SetReachabilityStyle must preserve the existing neutral color")
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

func TestWrappedLineCount(t *testing.T) {
	assert.Equal(t, 1, WrappedLineCount("", 10), "an empty string still occupies one line")
	assert.Equal(t, 1, WrappedLineCount("hello", 10))
	assert.Equal(t, 3, WrappedLineCount("line one\nline two\nline three", 80), "multi-line text that fits on each line")
	assert.Equal(t, 6, WrappedLineCount("line one\nline two\nline three", 5), "each line wraps once at a narrow width")
	assert.Equal(t, 2, WrappedLineCount("aaaa bbbb cccc dddd", 9), "a long line wraps across more than one row")
	assert.Equal(t, 4, WrappedLineCount("multi\nline\n\nwith blank", 80), "a blank line still counts as one row")

	// width <= 0 falls back to counting newline-separated lines without wrapping.
	assert.Equal(t, 3, WrappedLineCount("a\nb\nc", 0))
	assert.Equal(t, 3, WrappedLineCount("a\nb\nc", -3))
	assert.Equal(t, 1, WrappedLineCount("", 0), "an empty string never returns less than one line")
}

func TestDirectionPanelContentHeight(t *testing.T) {
	panel := NewDirectionPanel(netpol.Ingress)
	assert.Equal(t, 3, panel.ContentHeight(), "border (2) plus one row reserved even with no blocks")

	panel.SetRules(testRules()[:1])
	assert.Equal(t, 5, panel.ContentHeight(), "border (2) plus 3 rows for a single block")

	panel.SetRules(testRules())
	assert.Equal(t, 11, panel.ContentHeight(), "border (2) plus 3 rows per block for every visible block")
}

func TestRuleDetailsTextHeight(t *testing.T) {
	details := NewRuleDetails(testRules()[0], nil)
	before := details.TextHeight(40)

	// The view mutates its text after construction; TextHeight must reflect
	// the live text rather than what NewRuleDetails originally rendered.
	details.Text.SetText("line one\nline two\nline three")
	assert.Equal(t, 5, details.TextHeight(40), "border (2) plus 3 wrapped lines at a width that needs no wrapping")
	assert.NotEqual(t, before, details.TextHeight(40))

	details.Text.SetText("aaaa bbbb cccc dddd")
	assert.Equal(t, 4, details.TextHeight(11), "the inner width excludes the 2 border columns")
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
			ID:                netpol.RuleID{PolicyNamespace: "ns", PolicyName: "allow-rest", Direction: netpol.Ingress, Index: 2},
			SubjectPodCount:   2,
			SubjectMatchCount: 2,
			PeerSummary:       "app=rest",
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
