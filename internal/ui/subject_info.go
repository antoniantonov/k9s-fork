// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package ui

import (
	"fmt"
	"slices"

	"github.com/derailed/k9s/internal/config"
	"github.com/derailed/k9s/internal/netpol"
	"github.com/derailed/tcell/v2"
	"github.com/derailed/tview"
)

const subjectInfoEmptyMessage = "No workloads found for this subject."

// SubjectWorkload is a single row in the subject workload table.
type SubjectWorkload struct {
	Kind      string // Pod, Deployment, ReplicaSet, Job, StatefulSet, DaemonSet
	Namespace string
	Name      string
	Status    string // "3/3 ready", "Running", "Complete", ...
}

// SubjectInfo renders subject identity, a status summary and subject workloads.
// The summary lives in its own text line rather than a table cell so that a long
// summary cannot widen the workload columns.
type SubjectInfo struct {
	*tview.Flex

	// Table holds the workload rows.
	Table   *tview.Table
	summary *tview.TextView

	ref         netpol.SubjectRef
	podCount    int
	summaryTxt  string
	summarySet  bool
	workloads   []SubjectWorkload
	styles      *config.Styles
	borderColor tcell.Color
	focusColor  tcell.Color
}

// NewSubjectInfo creates a subject information box.
func NewSubjectInfo() *SubjectInfo {
	s := &SubjectInfo{
		Flex:    tview.NewFlex().SetDirection(tview.FlexRow),
		Table:   tview.NewTable(),
		summary: tview.NewTextView().SetDynamicColors(true),
		styles:  config.NewStyles(),
	}
	s.borderColor = s.styles.Frame().Border.FgColor.Color()
	s.focusColor = s.styles.Reachability().FocusColor.Color()
	s.SetBorder(true)
	s.SetTitle(" Subject ")
	s.Table.SetSelectable(true, false)
	s.Table.SetFixed(1, 0)
	s.AddItem(s.summary, 1, 0, false)
	s.AddItem(s.Table, 0, 1, true)
	s.SetStyles(s.styles)
	s.rebuild()
	return s
}

// SetSubject updates the subject reference and pod count.
func (s *SubjectInfo) SetSubject(ref netpol.SubjectRef, podCount int) *SubjectInfo {
	s.ref = ref
	s.podCount = podCount
	s.rebuild()
	return s
}

// SetSummary updates the rendered status summary.
func (s *SubjectInfo) SetSummary(summary string) *SubjectInfo {
	s.summaryTxt = summary
	s.summarySet = true
	s.rebuild()
	return s
}

// SummaryText returns the currently rendered summary line.
func (s *SubjectInfo) SummaryText() string {
	return s.summaryText()
}

// SetBorderFocusColor records the color used for the border while the box holds
// focus. Focus is delegated to the inner table, so tview never flags the outer
// flex as focused and the color has to be applied at draw time.
func (s *SubjectInfo) SetBorderFocusColor(color tcell.Color) *SubjectInfo {
	s.focusColor = color
	return s
}

// Draw paints the box, highlighting the border when the table holds focus.
func (s *SubjectInfo) Draw(screen tcell.Screen) {
	if s.HasFocus() {
		s.Flex.SetBorderColor(s.focusColor)
		s.Flex.SetBorderAttributes(tcell.AttrBold)
	} else {
		s.Flex.SetBorderColor(s.borderColor)
		s.Flex.SetBorderAttributes(tcell.AttrNone)
	}
	s.Flex.Draw(screen)
}

// Focus delegates focus to the workload table so it scrolls with the keyboard.
func (s *SubjectInfo) Focus(delegate func(tview.Primitive)) {
	delegate(s.Table)
}

// HasFocus reports whether the workload table holds focus.
func (s *SubjectInfo) HasFocus() bool {
	return s.Table.HasFocus()
}

// InputHandler forwards key events to the workload table.
func (s *SubjectInfo) InputHandler() func(*tcell.EventKey, func(tview.Primitive)) {
	return s.Table.InputHandler()
}

// SetWorkloads updates the rendered subject workloads.
func (s *SubjectInfo) SetWorkloads(items []SubjectWorkload) *SubjectInfo {
	s.workloads = slices.Clone(items)
	s.rebuild()
	return s
}

// SetStyles applies configured k9s table colors.
func (s *SubjectInfo) SetStyles(styles *config.Styles) *SubjectInfo {
	if styles == nil {
		return s
	}
	s.styles = styles
	table := styles.Table()
	s.SetBackgroundColor(table.BgColor.Color())
	s.borderColor = styles.Frame().Border.FgColor.Color()
	s.SetBorderColor(s.borderColor)
	s.Table.SetBackgroundColor(table.BgColor.Color())
	s.summary.SetBackgroundColor(table.BgColor.Color())
	s.summary.SetTextColor(styles.FgColor())
	s.Table.SetSelectedStyle(
		tcell.StyleDefault.Foreground(table.CursorFgColor.Color()).
			Background(table.CursorBgColor.Color()).Bold(true))
	s.rebuild()
	return s
}

func (s *SubjectInfo) rebuild() {
	s.summary.SetText(s.summaryText())
	row, column := s.Table.GetSelection()
	s.Table.Clear()
	if len(s.workloads) == 0 {
		s.Table.SetCell(0, 0, s.emptyCell())
		s.Table.SetOffset(0, 0)
		return
	}
	s.setHeader(0)
	for index, item := range s.workloads {
		s.setWorkload(1+index, item)
	}
	// Keep the caller's position across refreshes, but never land on the
	// header or past the end of a shrunken list.
	if row < 1 || row >= s.Table.GetRowCount() {
		row, column = 1, 0
		s.Table.SetOffset(0, 0)
	}
	s.Table.Select(row, column)
}

func (s *SubjectInfo) setHeader(row int) {
	for column, text := range []string{"KIND", "NAMESPACE", "NAME", "STATUS"} {
		cell := tview.NewTableCell(text).
			SetTextColor(s.headerFgColor()).
			SetBackgroundColor(s.headerBgColor()).
			SetExpansion(1).
			SetSelectable(false)
		cell.Transparent = false
		s.Table.SetCell(row, column, cell)
	}
}

func (s *SubjectInfo) setWorkload(row int, item SubjectWorkload) {
	values := []string{item.Kind, item.Namespace, item.Name, item.Status}
	for column, text := range values {
		cell := tview.NewTableCell(text).
			SetTextColor(s.fgColor()).
			SetBackgroundColor(s.bgColor()).
			SetExpansion(1)
		s.Table.SetCell(row, column, cell)
	}
}

func (s *SubjectInfo) emptyCell() *tview.TableCell {
	return tview.NewTableCell(subjectInfoEmptyMessage).
		SetTextColor(s.fgColor()).
		SetBackgroundColor(s.bgColor()).
		SetExpansion(1).
		SetSelectable(false)
}

func (s *SubjectInfo) summaryText() string {
	if s.summarySet {
		return s.summaryTxt
	}
	return fmt.Sprintf("%s %s · %d %s", s.ref.Kind, namespacedName(s.ref.Namespace, s.ref.Name), s.podCount, pluralize("pod", s.podCount))
}

func (s *SubjectInfo) fgColor() tcell.Color {
	if s.styles == nil {
		return tview.Styles.PrimaryTextColor
	}
	return s.styles.FgColor()
}

func (s *SubjectInfo) bgColor() tcell.Color {
	if s.styles == nil {
		return tview.Styles.PrimitiveBackgroundColor
	}
	return s.styles.BgColor()
}

func (s *SubjectInfo) headerFgColor() tcell.Color {
	if s.styles == nil {
		return tview.Styles.PrimaryTextColor
	}
	return s.styles.Table().Header.FgColor.Color()
}

func (s *SubjectInfo) headerBgColor() tcell.Color {
	if s.styles == nil {
		return tview.Styles.PrimitiveBackgroundColor
	}
	return s.styles.Table().Header.BgColor.Color()
}

func namespacedName(namespace, name string) string {
	switch {
	case namespace == "":
		return name
	case name == "":
		return namespace
	default:
		return namespace + "/" + name
	}
}

func pluralize(word string, count int) string {
	if count == 1 {
		return word
	}
	return word + "s"
}
