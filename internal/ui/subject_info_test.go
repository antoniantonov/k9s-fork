// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package ui

import (
	"testing"

	"github.com/derailed/k9s/internal/netpol"
	"github.com/stretchr/testify/require"
)

func TestSubjectInfoRendersSummary(t *testing.T) {
	info := NewSubjectInfo().SetSummary("Deployment netpol-demo-app/api · 3 pods · Ingress on")

	require.Equal(t, "Deployment netpol-demo-app/api · 3 pods · Ingress on", info.SummaryText())
}

func TestSubjectInfoContentHeight(t *testing.T) {
	info := NewSubjectInfo()
	require.Equal(t, 4, info.ContentHeight(), "border (2) + summary (1) + the empty-state row")

	info.SetWorkloads([]SubjectWorkload{
		{Kind: "Pod", Namespace: "demo", Name: "a", Status: "Running"},
		{Kind: "Pod", Namespace: "demo", Name: "b", Status: "Running"},
		{Kind: "Pod", Namespace: "demo", Name: "c", Status: "Running"},
	})
	require.Equal(t, 7, info.ContentHeight(), "border (2) + summary (1) + header row + 3 workload rows")

	info.SetWorkloads(nil)
	require.Equal(t, 4, info.ContentHeight(), "the empty state never collapses the box below one content row")
}

func TestSubjectInfoRendersWorkloadRowsInOrder(t *testing.T) {
	info := NewSubjectInfo().SetSummary("summary").SetWorkloads([]SubjectWorkload{
		{Kind: "Deployment", Namespace: "netpol-demo-app", Name: "api", Status: "3/3 ready"},
		{Kind: "Pod", Namespace: "netpol-demo-app", Name: "api-123", Status: "Running"},
	})

	require.Equal(t, "KIND", info.Table.GetCell(0, 0).Text)
	require.Equal(t, "NAMESPACE", info.Table.GetCell(0, 1).Text)
	require.Equal(t, "NAME", info.Table.GetCell(0, 2).Text)
	require.Equal(t, "STATUS", info.Table.GetCell(0, 3).Text)
	requireSubjectInfoRow(t, info, 1, SubjectWorkload{
		Kind:      "Deployment",
		Namespace: "netpol-demo-app",
		Name:      "api",
		Status:    "3/3 ready",
	})
	requireSubjectInfoRow(t, info, 2, SubjectWorkload{
		Kind:      "Pod",
		Namespace: "netpol-demo-app",
		Name:      "api-123",
		Status:    "Running",
	})
}

func TestSubjectInfoEmptyWorkloadsReplaceRowsWithEmptyState(t *testing.T) {
	info := NewSubjectInfo().SetWorkloads([]SubjectWorkload{
		{Kind: "Pod", Namespace: "netpol-demo-app", Name: "api-123", Status: "Running"},
	})

	info.SetWorkloads(nil)

	require.Equal(t, 1, info.Table.GetRowCount())
	require.Equal(t, subjectInfoEmptyMessage, info.Table.GetCell(0, 0).Text)
	require.Empty(t, info.Table.GetCell(0, 1).Text)
	require.Empty(t, info.Table.GetCell(1, 0).Text)
}

func TestSubjectInfoSetWorkloadsReplacesRatherThanAppends(t *testing.T) {
	info := NewSubjectInfo().SetWorkloads([]SubjectWorkload{
		{Kind: "Pod", Namespace: "netpol-demo-app", Name: "old", Status: "Running"},
		{Kind: "Job", Namespace: "netpol-demo-app", Name: "batch", Status: "Complete"},
	})

	info.SetWorkloads([]SubjectWorkload{
		{Kind: "Deployment", Namespace: "netpol-demo-app", Name: "api", Status: "3/3 ready"},
	})

	require.Equal(t, 2, info.Table.GetRowCount())
	requireSubjectInfoRow(t, info, 1, SubjectWorkload{
		Kind:      "Deployment",
		Namespace: "netpol-demo-app",
		Name:      "api",
		Status:    "3/3 ready",
	})
	require.Empty(t, info.Table.GetCell(2, 0).Text)
}

func TestSubjectInfoSetSubjectWithoutSummaryRendersDefaultSummary(t *testing.T) {
	info := NewSubjectInfo().SetSubject(netpol.SubjectRef{
		Kind:      netpol.SubjectDeployment,
		Namespace: "netpol-demo-app",
		Name:      "api",
	}, 3)

	require.Equal(t, "Deployment netpol-demo-app/api · 3 pods", info.SummaryText())
}

func TestSubjectInfoKeepsSelectionWhenWorkloadsAreReordered(t *testing.T) {
	workloads := []SubjectWorkload{
		{Kind: "Pod", Namespace: "demo", Name: "a", Status: "Running"},
		{Kind: "Pod", Namespace: "demo", Name: "b", Status: "Running"},
		{Kind: "Pod", Namespace: "demo", Name: "c", Status: "Running"},
	}
	info := NewSubjectInfo().SetWorkloads(workloads)
	require.True(t, info.SelectID("Pod/demo/c"))
	require.Equal(t, "Pod/demo/c", info.SelectedID())

	// A refresh may hand back the same workloads in informer cache order.
	info.SetWorkloads([]SubjectWorkload{workloads[2], workloads[0], workloads[1]})

	require.Equal(t, "Pod/demo/c", info.SelectedID(), "selection must follow the workload, not the row")
	row, _ := info.Table.GetSelection()
	require.Equal(t, 1, row)
}

func TestSubjectInfoKeepsSelectionAcrossStatusOnlyRefresh(t *testing.T) {
	info := NewSubjectInfo().SetWorkloads([]SubjectWorkload{
		{Kind: "Pod", Namespace: "demo", Name: "a", Status: "Running"},
		{Kind: "Pod", Namespace: "demo", Name: "b", Status: "Running"},
	})
	require.True(t, info.SelectID("Pod/demo/b"))

	info.SetSummary("refreshed").SetWorkloads([]SubjectWorkload{
		{Kind: "Pod", Namespace: "demo", Name: "a", Status: "Running"},
		{Kind: "Pod", Namespace: "demo", Name: "b", Status: "1/1 ready"},
	})

	require.Equal(t, "Pod/demo/b", info.SelectedID())
	requireSubjectInfoRow(t, info, 2, SubjectWorkload{
		Kind: "Pod", Namespace: "demo", Name: "b", Status: "1/1 ready",
	})
}

func TestSubjectInfoFallsBackToFirstRowWhenSelectionDisappears(t *testing.T) {
	info := NewSubjectInfo().SetWorkloads([]SubjectWorkload{
		{Kind: "Pod", Namespace: "demo", Name: "a"},
		{Kind: "Pod", Namespace: "demo", Name: "b"},
	})
	require.True(t, info.SelectID("Pod/demo/b"))

	info.SetWorkloads([]SubjectWorkload{{Kind: "Pod", Namespace: "demo", Name: "a"}})

	require.Equal(t, "Pod/demo/a", info.SelectedID())
}

func TestSubjectInfoFiltersVisibleWorkloads(t *testing.T) {
	info := NewSubjectInfo().SetWorkloads([]SubjectWorkload{
		{Kind: "Deployment", Namespace: "demo", Name: "api", Status: "2/2 ready"},
		{Kind: "Pod", Namespace: "demo", Name: "api-123", Status: "Running"},
		{Kind: "Job", Namespace: "ops", Name: "cleanup", Status: "Complete"},
	})

	info.SetFilter("complete")

	require.Equal(t, "complete", info.Filter())
	require.Equal(t, " Subject · filter: complete ", info.GetTitle())
	require.Equal(t, 2, info.Table.GetRowCount())
	requireSubjectInfoRow(t, info, 1, SubjectWorkload{
		Kind: "Job", Namespace: "ops", Name: "cleanup", Status: "Complete",
	})
	require.Equal(t, "Job/ops/cleanup", info.SelectedID())

	info.SetFilter("")

	require.Equal(t, " Subject ", info.GetTitle())
	require.Equal(t, 4, info.Table.GetRowCount())
}

func TestSubjectInfoFilterShowsEmptyState(t *testing.T) {
	info := NewSubjectInfo().SetWorkloads([]SubjectWorkload{{
		Kind: "Pod", Namespace: "demo", Name: "api", Status: "Running",
	}})

	info.SetFilter("missing")

	require.Equal(t, 1, info.Table.GetRowCount())
	require.Equal(t, "No subject workloads match the active filter.", info.Table.GetCell(0, 0).Text)
	require.Empty(t, info.SelectedID())
}

func requireSubjectInfoRow(t *testing.T, info *SubjectInfo, row int, expected SubjectWorkload) {
	t.Helper()

	require.Equal(t, expected.Kind, info.Table.GetCell(row, 0).Text)
	require.Equal(t, expected.Namespace, info.Table.GetCell(row, 1).Text)
	require.Equal(t, expected.Name, info.Table.GetCell(row, 2).Text)
	require.Equal(t, expected.Status, info.Table.GetCell(row, 3).Text)
}
