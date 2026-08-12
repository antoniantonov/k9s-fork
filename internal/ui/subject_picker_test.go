// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package ui

import (
	"errors"
	"testing"

	"github.com/derailed/k9s/internal/netpol"
	"github.com/derailed/tcell/v2"
	"github.com/derailed/tview"
	"github.com/stretchr/testify/require"
)

func TestSubjectPickerPaneNavigation(t *testing.T) {
	picker := newTestSubjectPicker(nil, nil)

	sendPickerKey(picker, tcell.KeyDown)
	require.Equal(t, 1, picker.kindList.GetCurrentItem())

	sendPickerKey(picker, tcell.KeyRight)
	sendPickerKey(picker, tcell.KeyDown)
	require.Equal(t, 1, picker.instanceList.GetCurrentItem())

	sendPickerKey(picker, tcell.KeyLeft)
	sendPickerKey(picker, tcell.KeyUp)
	require.Equal(t, 0, picker.kindList.GetCurrentItem())

	sendPickerKey(picker, tcell.KeyTab)
	sendPickerKey(picker, tcell.KeyDown)
	require.Equal(t, 1, picker.instanceList.GetCurrentItem())
}

func TestSubjectPickerKindSwitchReloadsInstances(t *testing.T) {
	var loaded []netpol.SubjectKind
	picker := newTestSubjectPicker(func(kind netpol.SubjectKind) ([]netpol.SubjectRef, error) {
		loaded = append(loaded, kind)
		if kind == netpol.SubjectDeployment {
			return []netpol.SubjectRef{
				{Kind: kind, Namespace: "b", Name: "zeta"},
				{Kind: kind, Namespace: "a", Name: "alpha"},
			}, nil
		}
		return testSubjects(kind), nil
	}, nil)

	require.Equal(t, []netpol.SubjectKind{netpol.SubjectPod}, loaded)
	sendPickerKey(picker, tcell.KeyDown)

	require.Equal(t, []netpol.SubjectKind{netpol.SubjectPod, netpol.SubjectDeployment}, loaded)
	require.Equal(t, 2, picker.instanceList.GetItemCount())
	main, _ := picker.instanceList.GetItemText(0)
	require.Equal(t, "a/alpha", main)
}

func TestSubjectPickerGroupsInstancesByNamespace(t *testing.T) {
	picker := newTestSubjectPicker(func(kind netpol.SubjectKind) ([]netpol.SubjectRef, error) {
		return []netpol.SubjectRef{
			{Kind: kind, Namespace: "zeta", Name: "aaa"},
			{Kind: kind, Namespace: "alpha", Name: "zzz"},
			{Kind: kind, Namespace: "alpha", Name: "bbb"},
		}, nil
	}, nil)

	var got []string
	for i := range picker.instanceList.GetItemCount() {
		main, _ := picker.instanceList.GetItemText(i)
		got = append(got, main)
	}

	require.Equal(t, []string{"alpha/bbb", "alpha/zzz", "zeta/aaa"}, got)
}

func TestSubjectPickerAcceptCallback(t *testing.T) {
	var accepted netpol.SubjectRef
	picker := newTestSubjectPicker(nil, func(ref netpol.SubjectRef) { accepted = ref })

	sendPickerKey(picker, tcell.KeyRight)
	sendPickerKey(picker, tcell.KeyDown)
	sendPickerKey(picker, tcell.KeyEnter)

	require.Equal(t, netpol.SubjectRef{Kind: netpol.SubjectPod, Namespace: "ns-a", Name: "pod-b"}, accepted)
}

func TestSubjectPickerEscapeCancels(t *testing.T) {
	cancelled := false
	picker := newTestSubjectPicker(nil, nil)
	picker.cancel = func() { cancelled = true }

	sendPickerKey(picker, tcell.KeyEscape)

	require.True(t, cancelled)
}

func TestSubjectPickerKeepsApplicationFocus(t *testing.T) {
	picker := newTestSubjectPicker(nil, nil)
	app := tview.NewApplication()

	app.SetFocus(picker)

	require.Same(t, picker, app.GetFocus())
	require.True(t, picker.HasFocus())
}

func TestSubjectPickerIsTopDialog(t *testing.T) {
	pages := NewPages()
	pages.AddPage("subject", newTestSubjectPicker(nil, nil), false, true)

	require.True(t, pages.IsTopDialog())
}

func TestSubjectPickerLoaderErrorDoesNotAccept(t *testing.T) {
	accepted := false
	picker := newTestSubjectPicker(func(netpol.SubjectKind) ([]netpol.SubjectRef, error) {
		return nil, errors.New("boom")
	}, func(netpol.SubjectRef) { accepted = true })

	sendPickerKey(picker, tcell.KeyRight)
	sendPickerKey(picker, tcell.KeyEnter)

	require.False(t, accepted)
}

func newTestSubjectPicker(
	loader SubjectLoader,
	accept func(netpol.SubjectRef),
) *SubjectPicker {
	if loader == nil {
		loader = func(kind netpol.SubjectKind) ([]netpol.SubjectRef, error) { return testSubjects(kind), nil }
	}
	return NewSubjectPicker(nil, []netpol.SubjectKind{
		netpol.SubjectPod,
		netpol.SubjectDeployment,
		netpol.SubjectJob,
		netpol.SubjectNamespace,
	}, loader, accept, nil)
}

func testSubjects(kind netpol.SubjectKind) []netpol.SubjectRef {
	if kind == netpol.SubjectNamespace {
		return []netpol.SubjectRef{{Kind: kind, Name: "ns-a"}, {Kind: kind, Name: "ns-b"}}
	}
	return []netpol.SubjectRef{
		{Kind: kind, Namespace: "ns-a", Name: "pod-a"},
		{Kind: kind, Namespace: "ns-a", Name: "pod-b"},
	}
}

func sendPickerKey(picker *SubjectPicker, key tcell.Key) {
	picker.InputHandler()(tcell.NewEventKey(key, 0, tcell.ModNone), func(tview.Primitive) {})
}
