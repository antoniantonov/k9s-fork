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

func requireSubjectInfoRow(t *testing.T, info *SubjectInfo, row int, expected SubjectWorkload) {
	t.Helper()

	require.Equal(t, expected.Kind, info.Table.GetCell(row, 0).Text)
	require.Equal(t, expected.Namespace, info.Table.GetCell(row, 1).Text)
	require.Equal(t, expected.Name, info.Table.GetCell(row, 2).Text)
	require.Equal(t, expected.Status, info.Table.GetCell(row, 3).Text)
}
