// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package ui

import (
	"fmt"
	"sort"

	"github.com/derailed/k9s/internal/config"
	"github.com/derailed/k9s/internal/netpol"
	"github.com/derailed/tcell/v2"
	"github.com/derailed/tview"
)

// SubjectLoader loads selectable subjects for a subject kind.
type SubjectLoader func(netpol.SubjectKind) ([]netpol.SubjectRef, error)

// SubjectPicker is a centered two-pane subject selector.
type SubjectPicker struct {
	*tview.Box

	frame        *tview.Frame
	flex         *tview.Flex
	kindList     *tview.List
	instanceList *tview.List
	kinds        []netpol.SubjectKind
	instances    []netpol.SubjectRef
	load         SubjectLoader
	accept       func(netpol.SubjectRef)
	cancel       func()
	focusKinds   bool
}

// NewSubjectPicker creates a Kubernetes-decoupled subject selector.
func NewSubjectPicker(
	styles *config.Dialog,
	kinds []netpol.SubjectKind,
	load SubjectLoader,
	accept func(netpol.SubjectRef),
	cancel func(),
) *SubjectPicker {
	p := &SubjectPicker{
		Box:          tview.NewBox(),
		kinds:        append([]netpol.SubjectKind(nil), kinds...),
		load:         load,
		accept:       accept,
		cancel:       cancel,
		focusKinds:   true,
		kindList:     newSubjectPickerList(styles, " Kinds "),
		instanceList: newSubjectPickerList(styles, " Subjects "),
	}
	p.kindList.SetChangedFunc(func(index int, _ string, _ string, _ rune) {
		if index >= 0 && index < len(p.kinds) {
			p.reloadInstances(p.kinds[index])
		}
	})
	p.instanceList.SetSelectedFunc(func(_ int, _ string, _ string, _ rune) { p.Accept() })
	for _, kind := range p.kinds {
		p.kindList.AddItem(kind.String(), "", 0, nil)
	}
	p.flex = tview.NewFlex().
		AddItem(p.kindList, 24, 0, true).
		AddItem(p.instanceList, 0, 1, false)
	p.frame = tview.NewFrame(p.flex).SetBorders(0, 0, 1, 0, 0, 0)
	p.frame.SetBorder(true).SetBorderPadding(1, 1, 1, 1).SetTitle(" <Subject> ")
	if styles != nil {
		p.frame.SetBackgroundColor(styles.BgColor.Color())
		p.kindList.SetBackgroundColor(styles.BgColor.Color())
		p.instanceList.SetBackgroundColor(styles.BgColor.Color())
	}
	p.switchPane(true)
	return p
}

func newSubjectPickerList(styles *config.Dialog, title string) *tview.List {
	list := tview.NewList().
		ShowSecondaryText(false).
		SetWrapAround(false).
		SetHighlightFullLine(true)
	list.SetBorder(true).SetTitle(title)
	if styles != nil {
		list.SetMainTextColor(styles.FieldFgColor.Color()).
			SetSelectedTextColor(styles.ButtonFocusFgColor.Color()).
			SetSelectedBackgroundColor(styles.ButtonFocusBgColor.Color())
	}
	return list
}

func (p *SubjectPicker) reloadInstances(kind netpol.SubjectKind) {
	p.instances = nil
	p.instanceList.Clear()
	if p.load == nil {
		return
	}
	instances, err := p.load(kind)
	if err != nil {
		p.instanceList.AddItem("Error: "+err.Error(), "", 0, nil)
		return
	}
	// Sort by the displayed value so entries group by namespace.
	sort.Slice(instances, func(i, j int) bool {
		if instances[i].Namespace == instances[j].Namespace {
			return instances[i].Name < instances[j].Name
		}
		return instances[i].Namespace < instances[j].Namespace
	})
	p.instances = instances
	if len(instances) == 0 {
		p.instanceList.AddItem("No subjects found", "", 0, nil)
		return
	}
	for _, ref := range instances {
		p.instanceList.AddItem(subjectDisplay(ref), "", 0, nil)
	}
}

func subjectDisplay(ref netpol.SubjectRef) string {
	if ref.Kind == netpol.SubjectNamespace || ref.Namespace == "" {
		return ref.Name
	}
	return fmt.Sprintf("%s/%s", ref.Namespace, ref.Name)
}

// Accept accepts the highlighted instance.
func (p *SubjectPicker) Accept() {
	index := p.instanceList.GetCurrentItem()
	if index < 0 || index >= len(p.instances) {
		return
	}
	if p.accept != nil {
		p.accept(p.instances[index])
	}
}

func (p *SubjectPicker) switchPane(focusKinds bool) {
	p.focusKinds = focusKinds
	p.kindList.SetBorderColor(tcell.ColorDefault)
	p.instanceList.SetBorderColor(tcell.ColorDefault)
	if p.focusKinds {
		p.kindList.SetBorderColor(tcell.ColorAqua)
		return
	}
	p.instanceList.SetBorderColor(tcell.ColorAqua)
}

// Draw draws this primitive onto the screen.
func (p *SubjectPicker) Draw(screen tcell.Screen) {
	screenWidth, screenHeight := screen.Size()
	width, height := min(96, screenWidth-4), min(24, screenHeight-4)
	if width < 40 {
		width = screenWidth
	}
	if height < 10 {
		height = screenHeight
	}
	x, y := (screenWidth-width)/2, (screenHeight-height)/2
	p.SetRect(x, y, width, height)
	p.frame.SetRect(x, y, width, height)
	p.frame.Draw(screen)
}

// Focus is called when this primitive receives focus.
func (p *SubjectPicker) Focus(delegate func(tview.Primitive)) {
	p.Box.Focus(delegate)
}

// HasFocus returns whether this primitive has focus.
func (p *SubjectPicker) HasFocus() bool {
	return p.Box.HasFocus()
}

// InputHandler returns the keyboard handler.
func (p *SubjectPicker) InputHandler() func(*tcell.EventKey, func(tview.Primitive)) {
	return p.WrapInputHandler(func(event *tcell.EventKey, setFocus func(tview.Primitive)) {
		switch event.Key() {
		case tcell.KeyEscape:
			if p.cancel != nil {
				p.cancel()
			}
			return
		case tcell.KeyLeft:
			p.switchPane(true)
			return
		case tcell.KeyRight:
			p.switchPane(false)
			return
		case tcell.KeyTab:
			p.switchPane(!p.focusKinds)
			return
		case tcell.KeyEnter:
			p.Accept()
			return
		}
		target := p.instanceList
		if p.focusKinds {
			target = p.kindList
		}
		if handler := target.InputHandler(); handler != nil {
			handler(event, setFocus)
		}
	})
}
