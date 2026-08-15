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
	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	reachabilityAllowedColor    = tcell.ColorGreen
	reachabilityDisallowedColor = tcell.ColorRed
	reachabilityPartialColor    = tcell.ColorOrange
	partialDataLabel            = "Partial Data"
	emptyLabel                  = "[EMPTY]"
	allowedLabel                = "Allowed"
)

// ReachabilityProjection identifies the data shown by a DirectionPanel.
type ReachabilityProjection uint8

const (
	RulesProjection ReachabilityProjection = iota
	PrimitivesProjection
)

func (p ReachabilityProjection) String() string {
	if p == PrimitivesProjection {
		return "Primitives"
	}
	return "Rules"
}

// ReachabilityScrollState is enough state to restore a panel after rebuilding it.
type ReachabilityScrollState struct {
	Row         int
	Column      int
	SelectedRow int
	SelectedID  string
	Cleared     bool
}

type reachabilityBlock struct {
	id        string
	search    string
	state     netpol.AccessState
	label     string
	badge     string
	synthetic bool
	primary   string
	secondary string
	detail    string
}

type reachabilityColors struct {
	allowed     tcell.Color
	disallowed  tcell.Color
	partialData tcell.Color
	neutral     tcell.Color
}

// DirectionPanel displays either rules or primitives as selectable row blocks.
type DirectionPanel struct {
	*tview.Table

	direction  netpol.Direction
	projection ReachabilityProjection
	rules      []netpol.RuleResult
	primitives []netpol.PrimitiveResult
	filter     string
	emptyText  string
	ascii      bool
	blocks     []reachabilityBlock
	blockRows  []int
	selected   func(string)
	changing   bool
	cleared    bool
	colors     reachabilityColors
	cursorFg   tcell.Color
	cursorBg   tcell.Color
}

// NewDirectionPanel creates a direction panel. Pass true as the optional
// argument for an ASCII-only separator.
func NewDirectionPanel(direction netpol.Direction, ascii ...bool) *DirectionPanel {
	p := &DirectionPanel{
		Table:     tview.NewTable(),
		direction: direction,
		colors:    defaultReachabilityColors(),
		cursorFg:  config.NewStyles().Table().CursorFgColor.Color(),
		cursorBg:  config.NewStyles().Table().CursorBgColor.Color(),
	}
	if len(ascii) > 0 {
		p.ascii = ascii[0]
	}
	p.SetSelectable(true, false)
	p.SetBorder(true)
	p.SetInputCapture(p.captureInput)
	p.Table.SetSelectionChangedFunc(p.selectionChanged)
	p.rebuild()
	return p
}

// NewDirectionPanelWithStyle creates a direction panel using configured styles.
func NewDirectionPanelWithStyle(direction netpol.Direction, styles *config.Styles, ascii ...bool) *DirectionPanel {
	return NewDirectionPanel(direction, ascii...).SetStyles(styles)
}

// SetStyles applies the configured table cursor and reachability styles.
func (p *DirectionPanel) SetStyles(styles *config.Styles) *DirectionPanel {
	if styles == nil {
		return p
	}
	p.cursorFg = styles.Table().CursorFgColor.Color()
	p.cursorBg = styles.Table().CursorBgColor.Color()
	// Set before SetReachabilityStyle so its preserve-then-rebuild keeps this
	// value instead of an earlier default, without triggering a second rebuild.
	p.colors.neutral = styles.FgColor()
	p.SetReachabilityStyle(styles.Reachability())
	p.applySelectionStyle()
	return p
}

// SetReachabilityStyle applies the configured reachability result colors.
func (p *DirectionPanel) SetReachabilityStyle(style config.Reachability) *DirectionPanel {
	p.colors = reachabilityColors{
		allowed:     style.AllowedColor.Color(),
		disallowed:  style.DisallowedColor.Color(),
		partialData: style.PartialDataColor.Color(),
		// config.Reachability has no neutral field; preserve the existing value.
		neutral: p.colors.neutral,
	}
	p.rebuild()
	return p
}

// SetBorderFocusColor applies the focused border color and makes the border
// visually stronger when focus is rendered.
func (p *DirectionPanel) SetBorderFocusColor(color tcell.Color) *DirectionPanel {
	p.Table.SetBorderFocusColor(color)
	p.SetBorderAttributes(tcell.AttrBold)
	return p
}

// SetDirection changes the direction represented by the panel.
func (p *DirectionPanel) SetDirection(direction netpol.Direction) *DirectionPanel {
	p.direction = direction
	p.updateTitle()
	return p
}

// Direction returns the represented direction.
func (p *DirectionPanel) Direction() netpol.Direction {
	return p.direction
}

// SetProjection switches between the Rules and Primitives projections.
func (p *DirectionPanel) SetProjection(projection ReachabilityProjection) *DirectionPanel {
	if p.projection != projection {
		p.projection = projection
		p.rebuild()
	}
	return p
}

// SetMode is an alias for SetProjection.
func (p *DirectionPanel) SetMode(projection ReachabilityProjection) *DirectionPanel {
	return p.SetProjection(projection)
}

// Projection returns the active projection.
func (p *DirectionPanel) Projection() ReachabilityProjection {
	return p.projection
}

// SetRules supplies the Rules projection.
func (p *DirectionPanel) SetRules(rules []netpol.RuleResult) *DirectionPanel {
	p.rules = slices.Clone(rules)
	if p.projection == RulesProjection {
		p.rebuild()
	}
	return p
}

// SetPrimitives supplies the Primitives projection.
func (p *DirectionPanel) SetPrimitives(primitives []netpol.PrimitiveResult) *DirectionPanel {
	p.primitives = slices.Clone(primitives)
	if p.projection == PrimitivesProjection {
		p.rebuild()
	}
	return p
}

// SetData supplies both projections in one operation.
func (p *DirectionPanel) SetData(rules []netpol.RuleResult, primitives []netpol.PrimitiveResult) *DirectionPanel {
	p.rules = slices.Clone(rules)
	p.primitives = slices.Clone(primitives)
	p.rebuild()
	return p
}

// SetFilter applies a case-insensitive text filter to all rendered fields.
func (p *DirectionPanel) SetFilter(filter string) *DirectionPanel {
	if p.filter != filter {
		p.filter = filter
		p.rebuild()
	}
	return p
}

// SetEmptyMessage configures the message rendered when the projection is empty.
func (p *DirectionPanel) SetEmptyMessage(message string) *DirectionPanel {
	p.emptyText = message
	p.rebuild()
	return p
}

// Filter returns the current text filter.
func (p *DirectionPanel) Filter() string {
	return p.filter
}

// SetASCII controls whether separators use ASCII or semigraphics.
func (p *DirectionPanel) SetASCII(ascii bool) *DirectionPanel {
	if p.ascii != ascii {
		p.ascii = ascii
		p.rebuild()
	}
	return p
}

// SetSelectionChangedFunc registers a stable-ID selection callback.
func (p *DirectionPanel) SetSelectionChangedFunc(callback func(string)) *DirectionPanel {
	p.selected = callback
	return p
}

// ClearSelection leaves the panel with no selected block.
func (p *DirectionPanel) ClearSelection() {
	p.clearSelection(true)
}

// HasSelection reports whether a block is currently selected.
func (p *DirectionPanel) HasSelection() bool {
	return !p.cleared && len(p.blocks) > 0
}

// SelectedID returns the stable ID of the selected block.
func (p *DirectionPanel) SelectedID() string {
	if p.cleared {
		return ""
	}
	row, _ := p.GetSelection()
	index := p.blockIndexAtRow(row)
	if index < 0 {
		return ""
	}
	return p.blocks[index].id
}

// SelectID selects a block by stable ID.
func (p *DirectionPanel) SelectID(id string) bool {
	for index := range p.blocks {
		if p.blocks[index].id == id {
			p.selectBlock(index, true)
			return true
		}
	}
	return false
}

// ScrollState captures panel offset and selection.
func (p *DirectionPanel) ScrollState() ReachabilityScrollState {
	row, column := p.GetOffset()
	selectedRow, _ := p.GetSelection()
	return ReachabilityScrollState{
		Row:         row,
		Column:      column,
		SelectedRow: selectedRow,
		SelectedID:  p.SelectedID(),
		Cleared:     p.cleared,
	}
}

// RestoreScrollState restores offset and stable-ID selection. If the ID is no
// longer present, the nearest block to the old row is selected.
func (p *DirectionPanel) RestoreScrollState(state ReachabilityScrollState) {
	p.SetOffset(max(0, state.Row), max(0, state.Column))
	if state.Cleared {
		p.clearSelection(false)
		return
	}
	if state.SelectedID != "" && p.SelectID(state.SelectedID) {
		return
	}
	if len(p.blocks) == 0 {
		return
	}
	index := p.nearestBlockForRow(state.SelectedRow)
	p.selectBlock(index, false)
}

// PanelTitle returns the title generated from direction, mode, and filter.
func (p *DirectionPanel) PanelTitle() string {
	title := fmt.Sprintf(" %s · %s ", p.direction, p.projection)
	if p.filter != "" {
		title = strings.TrimSuffix(title, " ") + fmt.Sprintf(" · filter: %s ", p.filter)
	}
	return title
}

// ContentHeight returns the height the panel needs to render every block
// without scrolling, including its border.
func (p *DirectionPanel) ContentHeight() int {
	rows := len(p.blocks) * 3
	if rows == 0 {
		rows = 1
	}
	return rows + 2
}

func (p *DirectionPanel) rebuild() {
	old := p.ScrollState()
	p.blocks = p.project()
	p.blockRows = p.blockRows[:0]
	p.Clear()

	for index, block := range p.blocks {
		row := index * 3
		p.blockRows = append(p.blockRows, row)
		color := reachabilityColor(block.state, block.label, p.colors)
		if block.synthetic {
			// Synthetic default-deny/unrestricted rows are not real
			// NetworkPolicy rules, so they render in a neutral color.
			color = p.colors.neutral
		}
		p.setBlockCell(row, 0, block.badge, block.id, color, false)
		p.setBlockCell(row, 1, block.primary, block.id, color, true)
		p.setBlockCell(row, 2, block.secondary, block.id, color, true)
		p.setBlockCell(row+1, 0, "", block.id, color, false)
		p.setBlockCell(row+1, 1, block.detail, block.id, color, true)
		p.setBlockCell(row+1, 2, "", block.id, color, true)

		separator := strings.Repeat(p.separator(), 12)
		cell := tview.NewTableCell(separator).
			SetExpansion(1).
			SetTextColor(tview.Styles.GraphicsColor).
			SetSelectable(false)
		p.SetCell(row+2, 0, cell)
		p.SetCell(row+2, 1, tview.NewTableCell(separator).SetExpansion(1).SetTextColor(tview.Styles.GraphicsColor).SetSelectable(false))
		p.SetCell(row+2, 2, tview.NewTableCell(separator).SetExpansion(1).SetTextColor(tview.Styles.GraphicsColor).SetSelectable(false))
	}

	p.updateTitle()
	if len(p.blocks) == 0 {
		if old.Cleared {
			p.clearSelection(false)
		}
		if p.emptyText != "" {
			p.SetCell(0, 0, tview.NewTableCell(p.emptyText).
				SetTextColor(tview.Styles.SecondaryTextColor).
				SetSelectable(false).
				SetExpansion(1))
		}
		return
	}
	if old.Cleared {
		p.clearSelection(false)
		p.SetOffset(old.Row, old.Column)
		return
	}
	if old.SelectedID != "" {
		for index := range p.blocks {
			if p.blocks[index].id == old.SelectedID {
				p.selectBlock(index, false)
				p.SetOffset(old.Row, old.Column)
				return
			}
		}
	}
	p.selectBlock(p.nearestBlockForRow(old.SelectedRow), false)
	p.SetOffset(old.Row, old.Column)
}

func (p *DirectionPanel) setBlockCell(row, column int, text, id string, color tcell.Color, expand bool) {
	cell := tview.NewTableCell(text).
		SetReference(id).
		SetTextColor(color)
	cell.Transparent = true
	if expand {
		cell.SetExpansion(1)
	}
	p.SetCell(row, column, cell)
}

func (p *DirectionPanel) project() []reachabilityBlock {
	var blocks []reachabilityBlock
	if p.projection == RulesProjection {
		for index := range p.rules {
			rule := &p.rules[index]
			state, label := ruleState(rule)
			// Non-applicable rules are noise unless they are synthetic
			// (default-deny/unrestricted), which must always stay visible.
			if label == emptyLabel && !rule.Synthetic {
				continue
			}
			permissions := formatPermissions(rule.Permissions)
			badge := label
			if label == allowedLabel {
				// Redundant now that only applicable rules are listed.
				badge = ""
			}
			block := reachabilityBlock{
				id:        rule.StableID(),
				state:     state,
				label:     label,
				badge:     badge,
				synthetic: rule.Synthetic,
				primary:   formatRuleName(rule),
				secondary: permissions,
				detail:    fmt.Sprintf("subjects %d/%d · peer %s", rule.SubjectMatchCount, rule.SubjectPodCount, valueOrDash(rule.PeerSummary)),
			}
			block.search = strings.Join([]string{block.label, block.primary, block.secondary, block.detail, strings.Join(rule.Warnings, " ")}, " ")
			if matchesReachabilityFilter(block.search, p.filter) {
				blocks = append(blocks, block)
			}
		}
		return blocks
	}

	for index := range p.primitives {
		primitive := &p.primitives[index]
		state, label := primitiveState(primitive)
		block := reachabilityBlock{
			id:        primitive.StableID(),
			state:     state,
			label:     label,
			badge:     label,
			synthetic: false,
			primary:   formatPrimitiveName(&primitive.Ref),
			secondary: formatPermissions(primitive.Permissions),
			detail:    fmt.Sprintf("pairs %d/%d · %s", primitive.AllowedPairs, primitive.TotalPairs, valueOrDash(primitive.Explanation)),
		}
		block.search = strings.Join([]string{block.label, block.primary, block.secondary, block.detail, strings.Join(primitive.Warnings, " ")}, " ")
		if matchesReachabilityFilter(block.search, p.filter) {
			blocks = append(blocks, block)
		}
	}
	return blocks
}

func (p *DirectionPanel) separator() string {
	if p.ascii {
		return "-"
	}
	return "─"
}

func (p *DirectionPanel) updateTitle() {
	p.SetTitle(p.PanelTitle())
}

func (p *DirectionPanel) selectionChanged(row, _ int) {
	if p.changing || p.cleared || len(p.blocks) == 0 {
		return
	}
	index := p.blockIndexAtRow(row)
	if index < 0 {
		index = p.nearestBlockForRow(row)
	}
	p.selectBlock(index, true)
}

func (p *DirectionPanel) selectBlock(index int, notify bool) {
	if index < 0 || index >= len(p.blocks) {
		return
	}
	p.changing = true
	p.cleared = false
	p.SetSelectable(true, false)
	row := p.blockRows[index]
	p.Select(row, 0)
	p.applySelectionStyle()
	p.changing = false
	if notify && p.selected != nil {
		p.selected(p.blocks[index].id)
	}
}

func (p *DirectionPanel) clearSelection(notify bool) {
	if p.cleared {
		p.SetSelectable(false, false)
		return
	}
	p.changing = true
	p.cleared = true
	p.SetSelectable(false, false)
	p.changing = false
	if notify && p.selected != nil {
		p.selected("")
	}
}

func (p *DirectionPanel) applySelectionStyle() {
	p.SetSelectedStyle(p.selectionStyle())
}

func (p *DirectionPanel) selectionStyle() tcell.Style {
	return tcell.StyleDefault.Foreground(p.cursorFg).Background(p.cursorBg).Bold(true)
}

func (p *DirectionPanel) blockIndexAtRow(row int) int {
	if row < 0 {
		return -1
	}
	index := row / 3
	if index < 0 || index >= len(p.blocks) || row%3 == 2 {
		return -1
	}
	return index
}

func (p *DirectionPanel) nearestBlockForRow(row int) int {
	if len(p.blocks) == 0 {
		return -1
	}
	return min(max(0, (row+1)/3), len(p.blocks)-1)
}

func (p *DirectionPanel) captureInput(event *tcell.EventKey) *tcell.EventKey {
	if len(p.blocks) == 0 {
		return event
	}
	if p.cleared {
		switch event.Key() {
		case tcell.KeyDown, tcell.KeyPgDn, tcell.KeyHome:
			p.selectBlock(0, true)
			return nil
		case tcell.KeyUp, tcell.KeyPgUp, tcell.KeyEnd:
			p.selectBlock(len(p.blocks)-1, true)
			return nil
		default:
			return event
		}
	}
	row, _ := p.GetSelection()
	current := p.blockIndexAtRow(row)
	if current < 0 {
		current = p.nearestBlockForRow(row)
	}
	target := current
	switch event.Key() {
	case tcell.KeyUp:
		target--
	case tcell.KeyDown:
		target++
	case tcell.KeyPgUp:
		target -= p.pageBlocks()
	case tcell.KeyPgDn:
		target += p.pageBlocks()
	case tcell.KeyHome:
		target = 0
	case tcell.KeyEnd:
		target = len(p.blocks) - 1
	default:
		return event
	}
	p.selectBlock(min(max(target, 0), len(p.blocks)-1), true)
	return nil
}

func (p *DirectionPanel) pageBlocks() int {
	_, _, _, height := p.GetInnerRect()
	return max(1, height/3)
}

func matchesReachabilityFilter(text, filter string) bool {
	return strings.Contains(strings.ToLower(text), strings.ToLower(strings.TrimSpace(filter)))
}

func ruleState(rule *netpol.RuleResult) (state netpol.AccessState, label string) {
	if len(rule.Warnings) > 0 {
		return netpol.AccessPartialData, partialDataLabel
	}
	if rule.SubjectPodCount == 0 || rule.SubjectMatchCount == 0 {
		return netpol.AccessDisallowed, emptyLabel
	}
	if rule.SubjectMatchCount < rule.SubjectPodCount {
		return netpol.AccessPartial, fmt.Sprintf("[PARTIAL %d/%d]", rule.SubjectMatchCount, rule.SubjectPodCount)
	}
	return netpol.AccessAllowed, allowedLabel
}

func primitiveState(primitive *netpol.PrimitiveResult) (state netpol.AccessState, label string) {
	if primitive.State == netpol.AccessPartialData || len(primitive.Warnings) > 0 {
		return netpol.AccessPartialData, partialDataLabel
	}
	if primitive.TotalPairs == 0 {
		return netpol.AccessDisallowed, "[EMPTY]"
	}
	if primitive.State == netpol.AccessPartial {
		return primitive.State, fmt.Sprintf("[PARTIAL %d/%d]", primitive.AllowedPairs, primitive.TotalPairs)
	}
	return primitive.State, primitive.State.String()
}

func reachabilityColor(state netpol.AccessState, label string, colors reachabilityColors) tcell.Color {
	if state == netpol.AccessAllowed && label == allowedLabel {
		return colors.allowed
	}
	if state == netpol.AccessPartialData || label == partialDataLabel {
		return colors.partialData
	}
	return colors.disallowed
}

func defaultReachabilityColors() reachabilityColors {
	return reachabilityColors{
		allowed:     reachabilityAllowedColor,
		disallowed:  reachabilityDisallowedColor,
		partialData: reachabilityPartialColor,
		neutral:     tview.Styles.PrimaryTextColor,
	}
}

func formatRuleName(rule *netpol.RuleResult) string {
	name := rule.ID.PolicyName
	if rule.ID.PolicyNamespace != "" {
		name = rule.ID.PolicyNamespace + "/" + name
	}
	if name == "" {
		name = valueOrDash(rule.ID.SyntheticKind)
	}
	return fmt.Sprintf("%s #%d", name, rule.ID.Index)
}

func formatPrimitiveName(ref *netpol.PrimitiveRef) string {
	if ref.Kind == netpol.PrimitiveCIDR {
		if len(ref.CIDRExcept) == 0 {
			return "CIDR " + valueOrDash(ref.CIDR)
		}
		return fmt.Sprintf("CIDR %s (except %s)", valueOrDash(ref.CIDR), strings.Join(ref.CIDRExcept, ", "))
	}
	name := ref.Name
	if ref.Namespace != "" {
		name = ref.Namespace + "/" + name
	}
	return ref.Kind.String() + " " + valueOrDash(name)
}

func formatPermissions(permissions []netpol.PortPermission) string {
	if len(permissions) == 0 {
		return "no ports"
	}
	values := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		values = append(values, permission.String())
	}
	return strings.Join(values, ", ")
}

func valueOrDash(value string) string {
	if value == "" {
		return "—"
	}
	return value
}

// WrappedLineCount returns the number of display lines text occupies when
// wrapped at width. It never returns less than 1.
func WrappedLineCount(text string, width int) int {
	lines := strings.Split(text, "\n")
	if width < 1 {
		return max(1, len(lines))
	}
	total := 0
	for _, line := range lines {
		total += max(1, len(tview.WordWrap(line, width)))
	}
	return max(1, total)
}

// PrimitiveDetailsText renders all primitive detail fields as plain text.
//
//nolint:gocritic // Value parameter preserves the public UI helper API.
func PrimitiveDetailsText(primitive netpol.PrimitiveResult) string {
	var b strings.Builder
	_, state := primitiveState(&primitive)
	fmt.Fprintf(&b, "%s\nState: %s\nPairs: %d/%d\nPorts: %s\n",
		formatPrimitiveName(&primitive.Ref), state, primitive.AllowedPairs, primitive.TotalPairs,
		formatPermissions(primitive.Permissions))
	if primitive.Explanation != "" {
		fmt.Fprintf(&b, "Explanation: %s\n", primitive.Explanation)
	}
	appendEvidence(&b, primitive.Evidence)
	appendWarnings(&b, primitive.Warnings)
	if len(primitive.PairDecisions) > 0 {
		b.WriteString("\nPair decisions:\n")
		for _, pair := range primitive.PairDecisions {
			fmt.Fprintf(&b, "  %s/%s -> %s/%s: %s\n",
				pair.Source.Namespace, pair.Source.Name,
				pair.Destination.Namespace, pair.Destination.Name,
				pair.Decision.State)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// NewPrimitiveDetails returns a bordered, scrollable primitive details view.
//
//nolint:gocritic // Value parameter preserves the public constructor API.
func NewPrimitiveDetails(primitive netpol.PrimitiveResult) *tview.TextView {
	text := tview.NewTextView().
		SetText(PrimitiveDetailsText(primitive)).
		SetScrollable(true).
		SetWrap(true)
	text.SetBorder(true).SetTitle(" Primitive Details ")
	return text
}

// RuleDetails contains a scrollable rule summary and its applicability table.
type RuleDetails struct {
	*tview.Flex
	Text          *tview.TextView
	Applicability *tview.Table
}

// SelectedApplicabilityID returns the stable primitive ID of the selected
// applicability row, if any.
func (d *RuleDetails) SelectedApplicabilityID() string {
	row, _ := d.Applicability.GetSelection()
	if row < 1 || row >= d.Applicability.GetRowCount() {
		return ""
	}
	cell := d.Applicability.GetCell(row, 0)
	if cell == nil {
		return ""
	}
	id, _ := cell.GetReference().(string)
	return id
}

// SelectApplicabilityID selects the applicability row for the given stable
// primitive ID. It reports whether the row was found.
func (d *RuleDetails) SelectApplicabilityID(id string) bool {
	if id == "" {
		return false
	}
	for row := 1; row < d.Applicability.GetRowCount(); row++ {
		cell := d.Applicability.GetCell(row, 0)
		if cell == nil {
			continue
		}
		if current, _ := cell.GetReference().(string); current == id {
			d.Applicability.Select(row, 0)
			return true
		}
	}
	return false
}

// SetApplicabilityChangedFunc registers a callback invoked with the stable
// primitive ID of the newly selected applicability row. It chains after the
// table's own selection styling, so callers do not have to reimplement it.
func (d *RuleDetails) SetApplicabilityChangedFunc(callback func(id string)) *RuleDetails {
	table := d.Applicability
	table.SetSelectionChangedFunc(func(row, _ int) {
		if row < 1 || row >= table.GetRowCount() {
			if callback != nil {
				callback("")
			}
			return
		}
		applyApplicabilitySelectionStyle(table)
		if callback != nil {
			callback(d.SelectedApplicabilityID())
		}
	})
	return d
}

// TextHeight returns the height the rule detail text needs at the given total
// width, including its border.
func (d *RuleDetails) TextHeight(width int) int {
	// Read the live text: the view mutates it after construction.
	text := d.Text.GetText(true)
	return 2 + WrappedLineCount(text, width-2)
}

// NewRuleDetails renders rule details and an applicability table.
//
//nolint:gocritic // Value parameter preserves the public constructor API.
func NewRuleDetails(rule netpol.RuleResult, applicability []netpol.ApplicabilityRow) *RuleDetails {
	return newRuleDetails(&rule, applicability, defaultReachabilityColors())
}

// NewRuleDetailsWithStyle renders rule details using configured result colors.
//
//nolint:gocritic // Value parameter preserves the public constructor API.
func NewRuleDetailsWithStyle(
	rule netpol.RuleResult,
	applicability []netpol.ApplicabilityRow,
	style config.Reachability,
) *RuleDetails {
	return newRuleDetailsWithTitle(&rule, applicability, reachabilityColors{
		allowed:     style.AllowedColor.Color(),
		disallowed:  style.DisallowedColor.Color(),
		partialData: style.PartialDataColor.Color(),
	}, " Rule Details ")
}

func newRuleDetails(
	rule *netpol.RuleResult,
	applicability []netpol.ApplicabilityRow,
	colors reachabilityColors,
) *RuleDetails {
	return newRuleDetailsWithTitle(rule, applicability, colors, " Rule Details ")
}

func newRuleDetailsWithTitle(
	rule *netpol.RuleResult,
	applicability []netpol.ApplicabilityRow,
	colors reachabilityColors,
	title string,
) *RuleDetails {
	return newRuleDetailsFromText(RuleDetailsText(*rule), applicability, colors, title, " Applicability ")
}

func newRuleDetailsFromText(
	body string,
	applicability []netpol.ApplicabilityRow,
	colors reachabilityColors,
	textTitle string,
	applicabilityTitle string,
) *RuleDetails {
	text := tview.NewTextView().
		SetText(body).
		SetScrollable(true).
		SetWrap(true)
	text.SetBorder(true).SetTitle(textTitle)
	table := newApplicabilityTableWithTitle(applicability, colors, applicabilityTitle)
	flex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(text, 0, 1, true).
		AddItem(table, 0, 1, false)
	return &RuleDetails{Flex: flex, Text: text, Applicability: table}
}

// NewEffectiveDetailsWithStyle renders the effective applicability of an entire
// direction: the primitive states after every rule has been applied.
//
//nolint:gocritic // Value parameter preserves the public constructor API.
func NewEffectiveDetailsWithStyle(
	text string,
	rows []netpol.ApplicabilityRow,
	style config.Reachability,
) *RuleDetails {
	return newRuleDetailsFromText(text, rows, reachabilityColors{
		allowed:     style.AllowedColor.Color(),
		disallowed:  style.DisallowedColor.Color(),
		partialData: style.PartialDataColor.Color(),
	}, " Effective Details ", " Effective Applicability ")
}

// RuleDetailsText renders the non-tabular rule detail fields.
//
//nolint:gocritic // Value parameter preserves the public UI helper API.
func RuleDetailsText(rule netpol.RuleResult) string {
	var b strings.Builder
	state, label := ruleState(&rule)
	fmt.Fprintf(&b, "Policy: %s/%s\nPolicy UID: %s\nDirection: %s\nRule index: %d\nState: %s (%s)\nPolicy pod selector: %s\nSubjects: %d/%d\nPeers:\n",
		valueOrDash(rule.ID.PolicyNamespace), valueOrDash(rule.ID.PolicyName), valueOrDash(string(rule.ID.PolicyUID)),
		rule.ID.Direction, rule.ID.Index, state, label, valueOrDash(rule.PolicySelector),
		rule.SubjectMatchCount, rule.SubjectPodCount)
	if len(rule.Peers) == 0 {
		fmt.Fprintf(&b, "  - %s\n", valueOrDash(rule.PeerSummary))
	}
	for index, peer := range rule.Peers {
		fmt.Fprintf(&b, "  - peer %d: %s\n", index, peer)
	}
	fmt.Fprintf(&b, "Ports: %s\n", formatPermissions(rule.Permissions))
	if rule.YAML != "" {
		fmt.Fprintf(&b, "Rule YAML:\n%s\n", rule.YAML)
	}
	appendEvidence(&b, rule.Evidence)
	appendWarnings(&b, rule.Warnings)
	return strings.TrimRight(b.String(), "\n")
}

// NewApplicabilityTable creates a scrollable rule applicability table.
func NewApplicabilityTable(rows []netpol.ApplicabilityRow) *tview.Table {
	return newApplicabilityTable(rows, defaultReachabilityColors())
}

// NewApplicabilityTableWithStyle creates an applicability table using configured colors.
func NewApplicabilityTableWithStyle(rows []netpol.ApplicabilityRow, style config.Reachability) *tview.Table {
	return newApplicabilityTable(rows, reachabilityColors{
		allowed:     style.AllowedColor.Color(),
		disallowed:  style.DisallowedColor.Color(),
		partialData: style.PartialDataColor.Color(),
	})
}

func newApplicabilityTable(rows []netpol.ApplicabilityRow, colors reachabilityColors) *tview.Table {
	return newApplicabilityTableWithTitle(rows, colors, " Applicability ")
}

func newApplicabilityTableWithTitle(
	rows []netpol.ApplicabilityRow,
	colors reachabilityColors,
	title string,
) *tview.Table {
	table := tview.NewTable().
		SetSelectable(true, false).
		SetFixed(1, 0)
	table.SetBorder(true).SetTitle(title)
	headers := []string{"Primitive", "Peer", "Opposite", "State", "Ports"}
	for column, header := range headers {
		table.SetCell(0, column, tview.NewTableCell(header).
			SetTextColor(tcell.ColorAqua).
			SetAttributes(tcell.AttrBold).
			SetSelectable(false).
			SetExpansion(1))
	}
	for index := range rows {
		row := &rows[index]
		color := reachabilityColor(row.EffectiveState, row.EffectiveState.String(), colors)
		opposite := fmt.Sprintf("%t", row.OppositeSideAllows)
		if row.Primitive.Ref.Kind == netpol.PrimitiveCIDR {
			opposite = "n/a"
		}
		values := []string{
			formatPrimitiveName(&row.Primitive.Ref),
			fmt.Sprintf("%t", row.PeerMatches),
			opposite,
			row.EffectiveState.String(),
			formatPermissions(row.Permissions),
		}
		id := row.Primitive.StableID()
		for column, value := range values {
			cell := tview.NewTableCell(value).
				SetTextColor(color).
				SetExpansion(1).
				SetReference(id)
			cell.Transparent = true
			table.SetCell(index+1, column, cell)
		}
	}
	table.SetSelectionChangedFunc(func(row, _ int) {
		if row < 1 || row >= table.GetRowCount() {
			return
		}
		applyApplicabilitySelectionStyle(table)
	})
	if len(rows) > 0 {
		table.Select(1, 0)
		applyApplicabilitySelectionStyle(table)
	}
	return table
}

func applyApplicabilitySelectionStyle(table *tview.Table) {
	styles := config.NewStyles().Table()
	table.SetSelectedStyle(tcell.StyleDefault.
		Foreground(styles.CursorFgColor.Color()).
		Background(styles.CursorBgColor.Color()).
		Bold(true))
}

func appendEvidence(b *strings.Builder, evidence []netpol.PolicyEvidence) {
	if len(evidence) == 0 {
		return
	}
	b.WriteString("Evidence:\n")
	for index := range evidence {
		item := &evidence[index]
		summary := item.Summary
		if summary == "" {
			summary = item.RuleID.String()
		}
		fmt.Fprintf(b, "  - %s\n", summary)
	}
}

func appendWarnings(b *strings.Builder, warnings []string) {
	if len(warnings) == 0 {
		return
	}
	b.WriteString("Warnings:\n")
	for _, warning := range warnings {
		fmt.Fprintf(b, "  - %s\n", warning)
	}
}

// PrimitiveKindDialog is a caller-owned primitive-kind multi-select form.
type PrimitiveKindDialog struct {
	*tview.Form
	selected sets.Set[netpol.PrimitiveKind]
	apply    func(sets.Set[netpol.PrimitiveKind])
	cancel   func()
}

// NewPrimitiveKindDialog creates a selector for all five primitive kinds. The
// supplied set is cloned and is never mutated.
func NewPrimitiveKindDialog(
	selected sets.Set[netpol.PrimitiveKind],
	apply func(sets.Set[netpol.PrimitiveKind]),
	cancel func(),
) *PrimitiveKindDialog {
	d := &PrimitiveKindDialog{
		Form:     tview.NewForm(),
		selected: clonePrimitiveKinds(selected),
		apply:    apply,
		cancel:   cancel,
	}
	d.SetBorder(true).SetTitle(" Primitive Kinds ")
	for _, kind := range primitiveKinds() {
		d.AddCheckbox(kind.String(), d.selected.Has(kind), func(_ string, checked bool) {
			if checked {
				d.selected.Insert(kind)
			} else {
				d.selected.Delete(kind)
			}
		})
	}
	d.AddButton("Apply", d.Apply)
	d.AddButton("Cancel", d.Cancel)
	d.SetCancelFunc(d.Cancel)
	return d
}

// SelectedKinds returns a clone of the dialog's current independent state.
func (d *PrimitiveKindDialog) SelectedKinds() sets.Set[netpol.PrimitiveKind] {
	return d.selected.Clone()
}

// SetSelectedKinds replaces the dialog state without retaining the caller's set.
func (d *PrimitiveKindDialog) SetSelectedKinds(selected sets.Set[netpol.PrimitiveKind]) *PrimitiveKindDialog {
	d.selected = clonePrimitiveKinds(selected)
	for index, kind := range primitiveKinds() {
		if checkbox, ok := d.GetFormItem(index).(*tview.Checkbox); ok {
			checkbox.SetChecked(d.selected.Has(kind))
		}
	}
	return d
}

// Apply invokes the apply callback with a clone of the current state.
func (d *PrimitiveKindDialog) Apply() {
	if d.apply != nil {
		d.apply(d.selected.Clone())
	}
}

// Cancel invokes the cancel callback without applying changes.
func (d *PrimitiveKindDialog) Cancel() {
	if d.cancel != nil {
		d.cancel()
	}
}

func primitiveKinds() []netpol.PrimitiveKind {
	return []netpol.PrimitiveKind{
		netpol.PrimitiveCIDR,
		netpol.PrimitivePod,
		netpol.PrimitiveNamespace,
		netpol.PrimitiveDeployment,
		netpol.PrimitiveJob,
	}
}

func clonePrimitiveKinds(kinds sets.Set[netpol.PrimitiveKind]) sets.Set[netpol.PrimitiveKind] {
	if kinds == nil {
		return sets.New[netpol.PrimitiveKind]()
	}
	return kinds.Clone()
}
