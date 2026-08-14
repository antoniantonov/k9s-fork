// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package ui

import (
	"errors"
	"testing"
	"time"

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

// Listing subjects blocks on RBAC checks and informer cache syncs. With a
// publisher installed the picker must load in the background so the UI stays
// responsive while the dialog is open.
func TestSubjectPickerLoadsAsynchronously(t *testing.T) {
	release := make(chan struct{})
	picker := newTestSubjectPicker(func(kind netpol.SubjectKind) ([]netpol.SubjectRef, error) {
		// The constructor loads the first kind synchronously, before a
		// publisher exists; only stall the kind under test.
		if kind == netpol.SubjectDeployment {
			<-release
		}
		return testSubjects(kind), nil
	}, nil)

	published := make(chan func(), 4)
	picker.SetPublisher(func(apply func()) { published <- apply })

	done := make(chan struct{})
	go func() {
		defer close(done)
		picker.reloadInstances(netpol.SubjectDeployment)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the picker blocked the caller while loading subjects")
	}
	require.Equal(t, 1, picker.instanceList.GetItemCount())
	loading, _ := picker.instanceList.GetItemText(0)
	require.Equal(t, "Loading...", loading)
	require.Empty(t, picker.instances)

	close(release)
	select {
	case apply := <-published:
		apply()
	case <-time.After(10 * time.Second):
		t.Fatal("the loaded subjects were never published")
	}
	require.Equal(t, testSubjects(netpol.SubjectDeployment), picker.instances)
}

// A response for a superseded kind must not repaint the list.
func TestSubjectPickerDiscardsStaleLoads(t *testing.T) {
	picker := newTestSubjectPicker(nil, nil)
	published := make(chan func(), 4)
	picker.SetPublisher(func(apply func()) { published <- apply })

	picker.reloadInstances(netpol.SubjectDeployment)
	stale := picker.loadSeq
	picker.reloadInstances(netpol.SubjectJob)

	// Drain both background publishes. The sequence guard, not arrival order,
	// decides which one is allowed to repaint.
	for range 2 {
		select {
		case apply := <-published:
			apply()
		case <-time.After(10 * time.Second):
			t.Fatal("a load was never published")
		}
	}
	require.Equal(t, testSubjects(netpol.SubjectJob), picker.instances)

	// Replaying the superseded response must leave the list untouched.
	picker.renderInstances(stale, testSubjects(netpol.SubjectDeployment), nil)
	require.Equal(t, testSubjects(netpol.SubjectJob), picker.instances)
}

// The constructor selects the first kind, which triggers a load. With a
// publisher supplied up front even that initial load must stay off the caller's
// goroutine, otherwise opening the dialog freezes the UI.
func TestSubjectPickerInitialLoadIsAsynchronous(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	published := make(chan func(), 4)

	built := make(chan *SubjectPicker, 1)
	go func() {
		built <- NewSubjectPickerWithPublisher(nil, []netpol.SubjectKind{
			netpol.SubjectPod,
			netpol.SubjectDeployment,
		}, func(kind netpol.SubjectKind) ([]netpol.SubjectRef, error) {
			<-release
			return testSubjects(kind), nil
		}, func(apply func()) { published <- apply }, nil, nil)
	}()

	select {
	case picker := <-built:
		require.NotNil(t, picker)
	case <-time.After(10 * time.Second):
		t.Fatal("the picker constructor blocked on the initial subject load")
	}
}
