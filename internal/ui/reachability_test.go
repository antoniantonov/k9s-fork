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
	assert.Contains(t, panel.PanelTitle(), "Egress")
	assert.Contains(t, panel.PanelTitle(), "Rules")

	panel.SetProjection(PrimitivesProjection).SetFilter("database")
	assert.Len(t, panel.blocks, 1)
	assert.Contains(t, panel.GetCell(0, 1).Text, "database")
	assert.Contains(t, panel.PanelTitle(), "Primitives")
	assert.Contains(t, panel.PanelTitle(), "filter: database")

	panel.SetFilter("TCP/all")
	assert.Len(t, panel.blocks, 1, "filtering includes permission text")
}

func TestDirectionPanelAccessLabelsAndBackgrounds(t *testing.T) {
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetProjection(PrimitivesProjection).SetPrimitives(testPrimitives())

	assert.Equal(t, "Allowed", panel.GetCell(0, 0).Text)
	assert.Equal(t, reachabilityAllowedBackground, panel.GetCell(0, 0).BackgroundColor)
	assert.Equal(t, "[PARTIAL 1/2]", panel.GetCell(3, 0).Text)
	assert.Equal(t, reachabilityDeniedBackground, panel.GetCell(3, 0).BackgroundColor)
	assert.Equal(t, "Unknown", panel.GetCell(6, 0).Text)
	assert.Equal(t, "[EMPTY]", panel.GetCell(9, 0).Text)
	assert.Equal(t, "Partial Data", panel.GetCell(12, 0).Text)
	assert.Equal(t, reachabilityPartialBackground, panel.GetCell(12, 0).BackgroundColor)

	style := config.Reachability{
		AllowedColor:     config.Color("green"),
		DisallowedColor:  config.Color("red"),
		PartialDataColor: config.Color("orange"),
	}
	panel.SetReachabilityStyle(style)
	assert.Equal(t, style.AllowedColor.Color(), panel.GetCell(0, 0).BackgroundColor)
	assert.Equal(t, style.DisallowedColor.Color(), panel.GetCell(3, 0).BackgroundColor)
	assert.Equal(t, style.PartialDataColor.Color(), panel.GetCell(12, 0).BackgroundColor)
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

func TestDirectionPanelSelectionCallbackAndStylePreserveBackground(t *testing.T) {
	panel := NewDirectionPanel(netpol.Ingress)
	panel.SetProjection(PrimitivesProjection).SetPrimitives(testPrimitives())
	var selected string
	panel.SetSelectionChangedFunc(func(id string) { selected = id })

	panel.captureInput(tcell.NewEventKey(tcell.KeyDown, 0, tcell.ModNone))
	assert.Equal(t, testPrimitives()[1].StableID(), selected)
	assert.Equal(t, reachabilityDeniedBackground, panel.GetCell(3, 0).BackgroundColor)
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
	assert.Equal(t, reachabilityDeniedBackground, details.Applicability.GetCell(1, 0).BackgroundColor)
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
	assert.Equal(t, reachabilityDeniedBackground, panel.GetCell(0, 0).BackgroundColor)

	panel.SetFilter("[EMPTY]")
	require.Equal(t, 3, panel.GetRowCount())
	assert.Equal(t, "[EMPTY]", panel.GetCell(0, 0).Text)
	assert.Equal(t, reachabilityDeniedBackground, panel.GetCell(0, 0).BackgroundColor)
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
