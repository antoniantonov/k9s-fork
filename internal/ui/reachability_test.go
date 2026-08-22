// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package ui

import (
	"strings"
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
	assert.Equal(t, testRules()[0].StableID(), panel.GetCell(1, 0).GetReference())
	assert.True(t, panel.GetCell(2, 0).NotSelectable)
	assert.True(t, panel.GetCell(8, 1).NotSelectable, "the final item must have a separator")
	assert.Contains(t, panel.GetCell(2, 0).Text, "─")
}

// Rules drop the leading state column: the row color carries the state, so the
// column would be dead space on every applicable rule.
func TestDirectionPanelRulesHaveNoStateColumn(t *testing.T) {
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetRules(testRules())

	assert.Equal(t, formatRuleName(&testRules()[0]), panel.GetCell(0, 0).Text)
	assert.Equal(t, formatPermissions(testRules()[0].Permissions), panel.GetCell(0, 1).Text)
	assert.Equal(t, 2, panel.GetColumnCount(), "rules render two columns")

	// Primitives keep theirs: it is never blank there.
	panel.SetProjection(PrimitivesProjection).SetPrimitives(testPrimitives())
	assert.Equal(t, allowedLabel, panel.GetCell(0, 0).Text)
	assert.Equal(t, 3, panel.GetColumnCount(), "primitives keep the state column")
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
	assert.Equal(t, reachabilityPartialStateColor, panel.GetCell(3, 0).Color,
		"a partial result is neither an allow nor a deny")
	assert.True(t, panel.GetCell(3, 0).Transparent)
	assert.Equal(t, "Unknown", panel.GetCell(6, 0).Text)
	assert.Equal(t, reachabilityUnknownStateColor, panel.GetCell(6, 0).Color,
		"an unevaluable result is neither a partial allow nor a deny")
	// A peer with no concrete pod pairs could not be evaluated at all, so it
	// reads Unknown here exactly as it does in the applicability tables.
	assert.Equal(t, "Unknown", panel.GetCell(9, 0).Text)
	assert.Equal(t, reachabilityUnknownStateColor, panel.GetCell(9, 0).Color)
	assert.Equal(t, "Partial Data", panel.GetCell(12, 0).Text)
	assert.Equal(t, reachabilityPartialColor, panel.GetCell(12, 0).Color)
	assert.True(t, panel.GetCell(12, 0).Transparent)

	style := config.Reachability{
		AllowedColor:     config.Color("green"),
		DisallowedColor:  config.Color("red"),
		PartialDataColor: config.Color("orange"),
		PartialColor:     config.Color("yellow"),
		UnknownColor:     config.Color("white"),
		FocusColor:       config.Color("orange"),
	}
	panel.SetReachabilityStyle(style)
	assert.Equal(t, style.AllowedColor.Color(), panel.GetCell(0, 0).Color)
	assert.Equal(t, style.PartialDataColor.Color(), panel.GetCell(12, 0).Color)
	assert.Equal(t, style.PartialColor.Color(), panel.GetCell(3, 0).Color)
	assert.Equal(t, style.UnknownColor.Color(), panel.GetCell(9, 0).Color)
}

// A denied peer keeps the disallowed color: only the unevaluable zero-pair case
// moved to Unknown.
func TestDirectionPanelDisallowedPrimitiveStaysDisallowed(t *testing.T) {
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetProjection(PrimitivesProjection).SetPrimitives([]netpol.PrimitiveResult{{
		Ref:        netpol.PrimitiveRef{Kind: netpol.PrimitiveCIDR, CIDR: "10.0.0.0/8"},
		State:      netpol.AccessDisallowed,
		TotalPairs: 3,
	}})

	assert.Equal(t, "Disallowed", panel.GetCell(0, 0).Text)
	assert.Equal(t, reachabilityDisallowedColor, panel.GetCell(0, 0).Color)

	panel.SetReachabilityStyle(config.Reachability{DisallowedColor: config.Color("maroon")})
	assert.Equal(t, config.Color("maroon").Color(), panel.GetCell(0, 0).Color)
}

// The stock skin carries the partial and unknown colors, so the whole
// skin-to-panel chain must land on yellow and white without any local default.
func TestDirectionPanelStockSkinColorsPartialAndUnknown(t *testing.T) {
	panel := NewDirectionPanelWithStyle(netpol.Ingress, config.NewStyles())
	panel.SetProjection(PrimitivesProjection).SetPrimitives(testPrimitives())

	assert.Equal(t, "[PARTIAL 1/2]", panel.GetCell(3, 0).Text)
	assert.Equal(t, config.Color("yellow").Color(), panel.GetCell(3, 0).Color)
	assert.Equal(t, "Unknown", panel.GetCell(6, 0).Text)
	assert.Equal(t, config.Color("white").Color(), panel.GetCell(6, 0).Color)
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
	assert.Equal(t, reachabilityPartialStateColor, panel.GetCell(3, 0).Color)
	assert.True(t, panel.GetCell(3, 0).Transparent)
}

func TestDirectionPanelSelectionStyleUsesTableCursorColors(t *testing.T) {
	styles := config.NewStyles()
	styles.K9s.Views.Table.CursorFgColor = config.Color("blue")
	// Deliberately not a reachability state color: the assertion below checks
	// that a row keeps its own state color, which a collision would mask.
	styles.K9s.Views.Table.CursorBgColor = config.Color("aqua")
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
	assert.Equal(t, reachabilityPartialStateColor, details.Applicability.GetCell(1, 0).Color)
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

	details := NewEffectiveDetailsWithStyle("effective body", rows, netpol.Egress, config.Reachability{
		AllowedColor:     config.Color("green"),
		DisallowedColor:  config.Color("red"),
		PartialDataColor: config.Color("orange"),
	})

	assert.Equal(t, "effective body", details.Text.GetText(true))
	assert.Equal(t, " Effective Details ", details.Text.GetTitle())
	// Enter moves focus off the direction panel, so the title has to say which
	// direction the table explains.
	assert.Equal(t, " Effective Applicability (Egress) ", details.Applicability.GetTitle())
	assert.Equal(t, len(rows)+1, details.Applicability.GetRowCount())
	assert.Equal(t, reachabilityPartialStateColor, details.Applicability.GetCell(2, 3).Color,
		"a partial row falls back to yellow when the skin leaves the color unset")
}

// The applicability tables paint Partial yellow and Unknown white so neither is
// mistaken for a clean allow or a clean deny.
func TestApplicabilityTableColorsPartialAndUnknown(t *testing.T) {
	primitives := testPrimitives()
	rows := []netpol.ApplicabilityRow{
		{Primitive: primitives[0], EffectiveState: netpol.AccessAllowed},
		{Primitive: primitives[1], EffectiveState: netpol.AccessPartial},
		{Primitive: primitives[2], EffectiveState: netpol.AccessUnknown},
		{Primitive: primitives[3], EffectiveState: netpol.AccessDisallowed},
	}

	table := NewApplicabilityTableWithStyle(rows, config.Reachability{
		AllowedColor:     config.Color("green"),
		DisallowedColor:  config.Color("red"),
		PartialDataColor: config.Color("orange"),
		PartialColor:     config.Color("yellow"),
		UnknownColor:     config.Color("white"),
	})

	assert.Equal(t, config.Color("green").Color(), table.GetCell(1, 3).Color)
	assert.Equal(t, config.Color("yellow").Color(), table.GetCell(2, 3).Color)
	assert.Equal(t, config.Color("white").Color(), table.GetCell(3, 3).Color)
	assert.Equal(t, config.Color("red").Color(), table.GetCell(4, 3).Color)
}

// A peer with no concrete pod pairs was never evaluated, so the columns that
// would otherwise read a definite "false" must not claim one.
func TestApplicabilityTableReportsUnevaluatedColumnsAsNotApplicable(t *testing.T) {
	primitives := testPrimitives()
	rows := []netpol.ApplicabilityRow{
		{
			Primitive:      primitives[0],
			PeerMatches:    true,
			EffectiveState: netpol.AccessAllowed,
			Permissions:    primitives[0].Permissions,
		},
		{
			// primitives[3] is a CIDR peer with TotalPairs == 0.
			Primitive:      primitives[3],
			EffectiveState: netpol.AccessUnknown,
		},
	}

	table := NewApplicabilityTable(rows)

	require.Equal(t, len(rows)+1, table.GetRowCount())
	assert.Equal(t, "true", table.GetCell(1, 1).Text, "an evaluated row still reports its peer match")
	assert.Equal(t, "TCP/all", table.GetCell(1, 4).Text)

	assert.Equal(t, "Unknown", table.GetCell(2, 3).Text)
	for column, header := range map[int]string{1: "Peer", 2: "Opposite", 4: "Ports"} {
		assert.Equal(t, "n/a", table.GetCell(2, column).Text,
			"%s must not report a negative that was never evaluated", header)
	}
}

// The rule applicability title names the rule's own direction.
func TestRuleDetailsApplicabilityTitleCarriesDirection(t *testing.T) {
	rule := testRules()[0]
	rule.ID.Direction = netpol.Ingress
	assert.Equal(t, " Applicability (Ingress) ", NewRuleDetails(rule, nil).Applicability.GetTitle())

	rule.ID.Direction = netpol.Egress
	assert.Equal(t, " Applicability (Egress) ",
		NewRuleDetailsWithStyle(rule, nil, config.Reachability{}).Applicability.GetTitle())
}

func TestPrimitiveDetailsUsesNormalizedState(t *testing.T) {
	primitive := testPrimitives()[0]
	primitive.State = netpol.AccessAllowed
	primitive.Warnings = []string{"snapshot incomplete"}
	assert.Contains(t, PrimitiveDetailsText(primitive), "State: Partial Data")

	primitive.Warnings = nil
	primitive.AllowedPairs = 0
	primitive.TotalPairs = 0
	assert.Contains(t, PrimitiveDetailsText(primitive), "State: Unknown")
}

func TestPartialAndEmptyLabelsAreSearchableAndPartialColored(t *testing.T) {
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetRules(testRules()).SetFilter("[PARTIAL 1/2]")
	require.Equal(t, 3, panel.GetRowCount())
	require.Len(t, panel.blocks, 1)
	assert.Equal(t, "[PARTIAL 1/2]", panel.blocks[0].label, "the label still drives search and color")
	assert.Equal(t, reachabilityPartialStateColor, panel.GetCell(0, 0).Color)
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
	assert.Equal(t, "default-deny #-1", panel.GetCell(0, 0).Text, "rules lead with their name, not a badge")
}

func TestDirectionPanelAllowedRuleHasNoBadgeButStaysColoredAndSearchable(t *testing.T) {
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetRules(testRules()[:1])

	require.Equal(t, "Allowed", panel.blocks[0].label, "the label is preserved for color and search")
	assert.Equal(t, formatRuleName(&testRules()[0]), panel.GetCell(0, 0).Text, "no badge column is rendered")
	assert.Equal(t, reachabilityAllowedColor, panel.GetCell(0, 0).Color)
	assert.True(t, panel.GetCell(0, 0).Transparent)

	panel.SetFilter("allowed")
	assert.Len(t, panel.blocks, 1, "the rule must remain searchable by its label even without a rendered badge")
}

// Rules no longer spend a column on their state: the row color carries it.
func TestDirectionPanelRuleStatesAreColorCodedNotBadged(t *testing.T) {
	rules := testRules()
	rules[0].Warnings = []string{"incomplete"}
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetRules(rules)

	assert.Equal(t, formatRuleName(&rules[0]), panel.GetCell(0, 0).Text)
	assert.Equal(t, reachabilityPartialColor, panel.GetCell(0, 0).Color, "partial data keeps its own color")
	assert.Equal(t, formatRuleName(&rules[1]), panel.GetCell(3, 0).Text)
	assert.Equal(t, reachabilityPartialStateColor, panel.GetCell(3, 0).Color, "a partial rule is yellow")
	assert.Equal(t, reachabilityAllowedColor, panel.GetCell(6, 0).Color, "a fully matched rule stays green")
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

func TestPrimitiveKindDialogRect(t *testing.T) {
	form := NewPrimitiveKindDialog(nil, nil, nil).Form
	tests := []struct {
		name          string
		width, height int
		want          DialogRect
	}{
		{
			name:   "standard terminal",
			width:  80,
			height: 24,
			want:   DialogRect{X: 25, Y: 5, Width: 30, Height: 13},
		},
		{
			name:   "wide terminal",
			width:  120,
			height: 40,
			want:   DialogRect{X: 38, Y: 13, Width: 44, Height: 13},
		},
		{
			name:   "exact content size",
			width:  26,
			height: 13,
			want:   DialogRect{Width: 26, Height: 13},
		},
		{
			name:   "small terminal clamps both dimensions",
			width:  20,
			height: 8,
			want:   DialogRect{Width: 20, Height: 8},
		},
		{
			name:   "single cell terminal",
			width:  1,
			height: 1,
			want:   DialogRect{Width: 1, Height: 1},
		},
		{
			name:   "invalid terminal dimensions",
			width:  -10,
			height: -5,
			want:   DialogRect{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, PrimitiveKindDialogRect(form, tt.width, tt.height))
		})
	}
}

func TestSizePrimitiveKindDialogAppliesRectAndPreservesFormContract(t *testing.T) {
	applied := false
	dialog := NewPrimitiveKindDialog(nil, func(sets.Set[netpol.PrimitiveKind]) {
		applied = true
	}, nil)
	modal := tview.NewModalForm("<Primitive Kinds (global)>", dialog.Form)

	rect := SizePrimitiveKindDialog(modal, dialog.Form, 80, 24)

	assert.Equal(t, 5, dialog.GetFormItemCount())
	assert.Equal(t, 2, dialog.GetButtonCount())
	x, y, width, height := modal.GetRect()
	assert.Equal(t, []int{rect.X, rect.Y, rect.Width, rect.Height}, []int{x, y, width, height})
	dialog.GetFormItemByLabel("CIDR").(*tview.Checkbox).SetChecked(true)
	dialog.Apply()
	assert.True(t, applied, "sizing must not replace the form callbacks")

	screen := tcell.NewSimulationScreen("UTF-8")
	require.NoError(t, screen.Init())
	t.Cleanup(screen.Fini)

	screen.SetSize(20, 8)
	modal.Draw(screen)
	x, y, width, height = modal.GetRect()
	assert.Equal(t, []int{0, 0, 20, 8}, []int{x, y, width, height},
		"draw-time sizing must stay clamped after ModalForm recalculates its rectangle")

	screen.SetSize(80, 24)
	dialog.SetFocus(dialog.GetFormItemCount())
	modal.Draw(screen)
	firstX, firstY, _, _ := dialog.GetFormItem(0).GetRect()
	_, lastY, _, _ := dialog.GetFormItem(dialog.GetFormItemCount() - 1).GetRect()
	buttonX, buttonY, _, _ := dialog.GetButton(0).GetRect()
	assert.GreaterOrEqual(t, firstX, rect.X)
	assert.GreaterOrEqual(t, firstY, rect.Y)
	assert.GreaterOrEqual(t, buttonX, rect.X)
	assert.Equal(t, lastY+2, buttonY, "the button row follows the five compact checkbox rows")
	assert.Less(t, buttonY, rect.Y+rect.Height)
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

// The rule detail pane renders with dynamic colors, so square brackets in YAML
// and selectors have to survive verbatim.
func TestHighlightRuleStateEscapesBodyAndPaintsOnlyPartialStates(t *testing.T) {
	body := "Rule index: 0\nState: Partial ([PARTIAL 1/2])\nPeers:\n  - ipBlock=10.0.0.0/8\n  ports: []"

	allowed := &netpol.RuleResult{SubjectPodCount: 2, SubjectMatchCount: 2}
	assert.Equal(t, tview.Escape(body), HighlightRuleState(body, allowed),
		"an allowed rule has nothing to look into")

	partial := &netpol.RuleResult{SubjectPodCount: 2, SubjectMatchCount: 1}
	painted := HighlightRuleState(body, partial)
	assert.Contains(t, painted, "[yellow::b]State: Partial (")
	assert.Contains(t, painted, "[-::-]")
	assert.NotContains(t, painted, "[yellow::b]Rule index", "only the State line is painted")
	assert.NotContains(t, painted, "[yellow::b]Peers")

	// Denied and partial-data rules are left alone: the panel color says it.
	denied := &netpol.RuleResult{SubjectPodCount: 2, SubjectMatchCount: 0}
	assert.NotContains(t, HighlightRuleState(body, denied), "[yellow::b]")
	warned := &netpol.RuleResult{SubjectPodCount: 2, SubjectMatchCount: 2, Warnings: []string{"x"}}
	assert.NotContains(t, HighlightRuleState(body, warned), "[yellow::b]")
	assert.Equal(t, tview.Escape(body), HighlightRuleState(body, nil))
}

// The detail pane and the direction panel must agree on what a partial rule
// looks like, so the State line follows the skin's partial color rather than
// the built-in yellow.
func TestHighlightRuleStateWithStyleUsesSkinPartialColor(t *testing.T) {
	body := "Rule index: 0\nState: Partial ([PARTIAL 1/2])\nPeers:"
	partial := &netpol.RuleResult{SubjectPodCount: 2, SubjectMatchCount: 1}

	// A skin color resolves to a true color, which has no tcell name, so the
	// tag carries its hex form. tview accepts either.
	painted := HighlightRuleStateWithStyle(body, partial, config.Reachability{PartialColor: config.Color("fuchsia")})
	assert.Contains(t, painted, "[#ff00ff::b]State: Partial (")
	assert.NotContains(t, painted, "[yellow::b]")

	// An unset skin key still falls back to the built-in partial color.
	assert.Contains(t, HighlightRuleStateWithStyle(body, partial, config.Reachability{}), "[yellow::b]State: Partial (")

	allowed := &netpol.RuleResult{SubjectPodCount: 2, SubjectMatchCount: 2}
	assert.Equal(t, tview.Escape(body),
		HighlightRuleStateWithStyle(body, allowed, config.Reachability{PartialColor: config.Color("fuchsia")}),
		"an allowed rule is left alone whatever the skin says")
}

// A painted body must still read back as the original text.
func TestRuleDetailsTextRoundTripsThroughDynamicColors(t *testing.T) {
	body := "State: Partial ([PARTIAL 1/2])\n  ports: []\n  peer: [10.0.0.0/8]"
	details := NewRuleDetails(testRules()[1], nil)
	details.Text.SetText(HighlightRuleState(body, &netpol.RuleResult{SubjectPodCount: 2, SubjectMatchCount: 2}))

	assert.Equal(t, body, details.Text.GetText(true), "escaped brackets survive verbatim")
}

func TestColorNameRoundTrip(t *testing.T) {
	assert.Equal(t, "yellow", colorName(tcell.ColorYellow))
	assert.Equal(t, "red", colorName(tcell.ColorRed))
	assert.Equal(t, "#123456", colorName(tcell.NewHexColor(0x123456)))
}

// A color tag is only honored by tview in its full "[fg:bg:attr]" form, so this
// asserts what actually reaches the screen rather than what is in the string.
func TestHighlightedStateLineRendersInColor(t *testing.T) {
	rule := &netpol.RuleResult{SubjectPodCount: 2, SubjectMatchCount: 1}
	details := NewRuleDetails(*rule, nil)
	details.Text.SetText(HighlightRuleState("Direction: Ingress\nState: Partial ([PARTIAL 1/2])\n  ports: []", rule))

	screen := tcell.NewSimulationScreen("UTF-8")
	require.NoError(t, screen.Init())
	defer screen.Fini()
	screen.SetSize(60, 8)
	details.Text.SetRect(0, 0, 60, 8)
	details.Text.Draw(screen)

	readRow := func(row int) (string, map[tcell.Color]int) {
		text, colors := "", map[tcell.Color]int{}
		for column := range 60 {
			r, _, style, _ := screen.GetContent(column, row)
			text += string(r)
			if r != ' ' && r != '│' {
				fg, _, _ := style.Decompose()
				colors[fg]++
			}
		}
		return strings.TrimRight(text, " "), colors
	}

	direction, directionColors := readRow(1)
	state, stateColors := readRow(2)
	ports, _ := readRow(3)

	assert.Contains(t, state, "State: Partial ([PARTIAL 1/2])", "the tag itself must not be printed")
	assert.NotContains(t, state, "yellow")
	assert.Positive(t, stateColors[reachabilityPartialStateColor], "the state line renders yellow")
	assert.Zero(t, directionColors[reachabilityPartialStateColor], "neighbouring lines are untouched")
	assert.Contains(t, direction, "Direction: Ingress")
	assert.Contains(t, ports, "ports: []", "square brackets survive the dynamic-color pass")
}
