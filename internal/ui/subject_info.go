// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package ui

import (
	"fmt"
	"slices"
	"strings"

	"github.com/derailed/k9s/internal/config"
	"github.com/derailed/k9s/internal/netpol"
	"github.com/derailed/tcell/v2"
	"github.com/derailed/tview"
	"k8s.io/apimachinery/pkg/types"
)

const subjectInfoEmptyMessage = "No workloads found for this subject."

// SubjectWorkload is a single row in the subject workload table.
type SubjectWorkload struct {
	Kind      string // Pod, Deployment, ReplicaSet, Job, StatefulSet, DaemonSet
	Namespace string
	Name      string
	UID       types.UID
	Status    string // "3/3 ready", "Running", "Complete", ...
}

// ID returns a stable identity used to preserve the selection across refreshes.
func (w SubjectWorkload) ID() string {
	return w.Kind + "/" + w.Namespace + "/" + w.Name
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
	visible     []SubjectWorkload
	filter      string
	selectedID  string
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
	s.Table.SetSelectionChangedFunc(func(row, _ int) {
		s.selectedID = s.workloadIDAtRow(row)
	})
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

// ContentHeight returns the height the box needs to render the summary line
// and every workload row without scrolling, including its border.
func (s *SubjectInfo) ContentHeight() int {
	return 2 + 1 + max(1, s.Table.GetRowCount())
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

// SetFilter applies a case-insensitive text filter to the workload rows.
func (s *SubjectInfo) SetFilter(filter string) *SubjectInfo {
	if s.filter != filter {
		s.filter = filter
		s.rebuild()
	}
	return s
}

// Filter returns the current workload filter.
func (s *SubjectInfo) Filter() string {
	return s.filter
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
	s.visible = s.filteredWorkloads()
	s.SetTitle(s.panelTitle())
	// Preserve the selection by workload identity: the informer cache can hand
	// back rows in a different order, so a row index alone silently jumps the
	// cursor onto an unrelated workload.
	selectedID := s.selectedID
	row, column := s.Table.GetSelection()
	offsetRow, offsetColumn := s.Table.GetOffset()
	s.Table.Clear()
	if len(s.visible) == 0 {
		s.Table.SetCell(0, 0, s.emptyCell())
		s.Table.SetOffset(0, 0)
		return
	}
	s.setHeader(0)
	for index, item := range s.visible {
		s.setWorkload(1+index, item)
	}
	if index := s.indexOf(selectedID); index >= 0 {
		s.Table.Select(1+index, max(0, column))
		s.Table.SetOffset(offsetRow, offsetColumn)
		return
	}
	// The previously selected workload is gone: fall back to the old row, but
	// never land on the header or past the end of a shrunken list.
	if row < 1 || row >= s.Table.GetRowCount() {
		row, column = 1, 0
		offsetRow, offsetColumn = 0, 0
	}
	s.Table.Select(row, column)
	s.Table.SetOffset(offsetRow, offsetColumn)
}

// SelectedID returns the identity of the selected workload, if any.
func (s *SubjectInfo) SelectedID() string {
	row, _ := s.Table.GetSelection()
	return s.workloadIDAtRow(row)
}

// SelectID selects the workload matching id. It reports whether it was found.
func (s *SubjectInfo) SelectID(id string) bool {
	index := s.indexOf(id)
	if index < 0 {
		return false
	}
	s.Table.Select(1+index, 0)
	return true
}

func (s *SubjectInfo) workloadIDAtRow(row int) string {
	if row < 1 || row > len(s.visible) {
		return ""
	}
	return s.visible[row-1].ID()
}

func (s *SubjectInfo) indexOf(id string) int {
	if id == "" {
		return -1
	}
	return slices.IndexFunc(s.visible, func(item SubjectWorkload) bool {
		return item.ID() == id
	})
}

func (s *SubjectInfo) filteredWorkloads() []SubjectWorkload {
	filter := strings.ToLower(strings.TrimSpace(s.filter))
	if filter == "" {
		return slices.Clone(s.workloads)
	}
	items := make([]SubjectWorkload, 0, len(s.workloads))
	for _, item := range s.workloads {
		text := strings.Join([]string{item.Kind, item.Namespace, item.Name, item.Status}, " ")
		if strings.Contains(strings.ToLower(text), filter) {
			items = append(items, item)
		}
	}
	return items
}

func (s *SubjectInfo) panelTitle() string {
	title := " Subject "
	if s.filter != "" {
		title = strings.TrimSuffix(title, " ") + fmt.Sprintf(" · filter: %s ", s.filter)
	}
	return title
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
	message := subjectInfoEmptyMessage
	if len(s.workloads) > 0 && strings.TrimSpace(s.filter) != "" {
		message = "No subject workloads match the active filter."
	}
	return tview.NewTableCell(message).
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
