// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package view

import (
	"errors"
	"testing"
	"time"

	"github.com/derailed/k9s/internal/config"
	"github.com/derailed/k9s/internal/model"
	"github.com/derailed/k9s/internal/netpol"
	"github.com/derailed/k9s/internal/ui"
	"github.com/derailed/tcell/v2"
	"github.com/derailed/tview"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
)

func TestNetworkPolicyGraphSubjectChangeDiscardsQueuedNotifications(t *testing.T) {
	for _, notification := range []string{"result", "failure", "partial result"} {
		t.Run(notification, func(t *testing.T) {
			view := newTestNetworkPolicyGraph()
			view.app = NewApp(config.NewConfig(nil))
			view.autoRefresh = true
			view.updateQueued = true // Hold the UI drain until after the subject changes.
			previous := testSubjectResult()
			view.model.(*fakeNetPolGraphModel).refresh = model.NetPolGraphRefresh{
				Subject: previous.Subject.Ref,
			}
			if notification != "failure" {
				view.NetPolGraphChanged(*previous)
			}
			if notification != "result" {
				view.NetPolGraphFailed(errors.New("previous subject failed"))
			}
			next := netpol.SubjectRef{Kind: netpol.SubjectPod, Namespace: "payments", Name: "next"}
			view.applySubject(next)
			view.drainPendingUpdate()

			assert.Equal(t, next, view.subject)
			assert.False(t, view.haveResult)
			require.NoError(t, view.lastError)
			assert.Empty(t, view.panels[netpol.Ingress].SelectedID())
			assert.Empty(t, view.panels[netpol.Egress].SelectedID())
			details, ok := view.detailItem.(*tview.TextView)
			require.True(t, ok)
			assert.Equal(t, "Waiting for NetworkPolicy evaluation...", details.GetText(true))
			assert.NotContains(t, view.subjectInfo.SummaryText(), "ERROR:")
		})
	}
}

func TestNetworkPolicyGraphLateResultCannotReplaceCurrentSubject(t *testing.T) {
	for _, change := range []string{"name", "UID"} {
		for _, queued := range []bool{false, true} {
			mode := map[bool]string{false: "immediate", true: "queued"}[queued]
			t.Run(change+"/"+mode, func(t *testing.T) {
				view := newTestNetworkPolicyGraph()
				previous := testSubjectResult()
				next := testSubjectResult()
				if change == "name" {
					next.Subject.Ref.Name = "next"
				} else {
					next.Subject.Ref.UID = types.UID("replacement-uid")
				}
				view.applySubject(next.Subject.Ref)
				view.applyResult(next)
				generation := view.dataGen
				if queued {
					view.app = NewApp(config.NewConfig(nil))
					view.updateQueued = true
				}

				view.NetPolGraphChanged(*previous)
				if queued {
					view.drainPendingUpdate()
				}

				assert.Equal(t, next.Subject.Ref, view.result.Subject.Ref)
				assert.Equal(t, generation, view.dataGen, "a rejected notification must not rebuild projections")
				require.NoError(t, view.lastError)
			})
		}
	}
}

func TestNetworkPolicyGraphAcceptsResolvedSubjectUID(t *testing.T) {
	for _, configured := range []netpol.SubjectRef{
		{Kind: netpol.SubjectNamespace, Name: "payments", Namespace: "payments"},
		{Kind: netpol.SubjectNamespace, Namespace: "payments"},
	} {
		resolved := netpol.SubjectRef{Kind: netpol.SubjectNamespace, Name: "payments", UID: "namespace-uid"}
		assert.True(t, matchesNetPolSubject(configured, resolved), "namespace identity is canonicalized by the evaluator")
		resolved.Name = "other"
		assert.False(t, matchesNetPolSubject(configured, resolved))
	}
	for _, queued := range []bool{false, true} {
		t.Run(map[bool]string{false: "immediate", true: "queued"}[queued], func(t *testing.T) {
			view := newTestNetworkPolicyGraph()
			resolved := testSubjectResult()
			configured := resolved.Subject.Ref
			configured.UID = ""
			view.applySubject(configured)
			if queued {
				view.app = NewApp(config.NewConfig(nil))
				view.updateQueued = true
			}

			view.NetPolGraphChanged(*resolved)
			if queued {
				view.drainPendingUpdate()
			}

			require.True(t, view.haveResult)
			assert.Equal(t, resolved.Subject.Ref, view.result.Subject.Ref)
			require.NoError(t, view.lastError)
		})
	}
}

func TestNetworkPolicyGraphSuccessfulUpdateClearsQueuedFailure(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	view.app = NewApp(config.NewConfig(nil))
	view.updateQueued = true
	view.NetPolGraphFailed(errors.New("previous refresh failed"))
	view.NetPolGraphChanged(*testSubjectResult())
	view.drainPendingUpdate()

	require.True(t, view.haveResult)
	require.NoError(t, view.lastError)
	assert.NotContains(t, view.subjectInfo.SummaryText(), "ERROR:")
}

func TestNetworkPolicyGraphLateFailureCannotAnnotateCurrentSubject(t *testing.T) {
	for _, queued := range []bool{false, true} {
		t.Run(map[bool]string{false: "immediate", true: "queued"}[queued], func(t *testing.T) {
			view := newTestNetworkPolicyGraph()
			previous := testSubjectResult()
			view.model.(*fakeNetPolGraphModel).refresh.Subject = previous.Subject.Ref
			next := previous.Subject.Ref
			next.Name = "next"
			view.applySubject(next)
			if queued {
				view.app = NewApp(config.NewConfig(nil))
				view.updateQueued = true
			}

			view.NetPolGraphFailed(errors.New("late old subject failure"))
			if queued {
				view.drainPendingUpdate()
			}

			require.NoError(t, view.lastError)
			assert.NotContains(t, view.subjectInfo.SummaryText(), "ERROR:")
			details, ok := view.detailItem.(*tview.TextView)
			require.True(t, ok)
			assert.Equal(t, "Waiting for NetworkPolicy evaluation...", details.GetText(true))
		})
	}
}

func TestNetworkPolicyGraphSubjectChangeIgnoresPreviousRefreshWarnings(t *testing.T) {
	view := newTestNetworkPolicyGraph()
	previous := testSubjectResult()
	view.model.(*fakeNetPolGraphModel).refresh = model.NetPolGraphRefresh{
		Subject: previous.Subject.Ref,
		Incomplete: map[string]error{
			"ciliumnetworkpolicies": errors.New("old subject list failed"),
		},
	}
	view.applyResult(previous)
	require.Contains(t, view.subjectInfo.SummaryText(), "PARTIAL DATA")

	next := previous.Subject.Ref
	next.Name = "next"
	view.applySubject(next)

	assert.NotContains(t, view.subjectInfo.SummaryText(), "PARTIAL DATA")
	assert.NotContains(t, view.subjectInfo.SummaryText(), "old subject list failed")
	var result netpol.SubjectResult
	result.Subject.Ref = next
	view.applyResult(&result)
	details, ok := view.detailItem.(*ui.RuleDetails)
	require.True(t, ok)
	assert.NotContains(t, details.Text.GetText(true), "old subject list failed")
}

func TestNetworkPolicyGraphDelayedWorkloadsCannotReplaceNewSubject(t *testing.T) {
	type request struct {
		subject netpol.SubjectRef
		pods    []netpol.PodRef
		reply   chan []ui.SubjectWorkload
	}
	type frame struct {
		subject netpol.SubjectRef
		summary string
		path    string
		loading bool
	}
	requests := make(chan request, 2)
	frames := make(chan frame, 8)
	cancelCollection := make(chan struct{})
	view := newTestNetworkPolicyGraph()
	view.app = NewApp(config.NewConfig(nil))
	view.autoRefresh = true
	view.collectWorkloads = func(subject netpol.SubjectRef, pods []netpol.PodRef) ([]ui.SubjectWorkload, []string) {
		reply := make(chan []ui.SubjectWorkload, 1)
		requests <- request{subject: subject, pods: pods, reply: reply}
		select {
		case workloads := <-reply:
			return workloads, []string{subject.Name + " collection"}
		case <-cancelCollection:
			return nil, nil
		}
	}
	screen := tcell.NewSimulationScreen("UTF-8")
	require.NoError(t, screen.Init())
	screen.SetSize(120, 40)
	app := view.app.Application
	app.SetScreen(screen).SetRoot(tview.NewBox(), true).SetAfterDrawFunc(func(tcell.Screen) {
		_, path, _ := view.yamlTarget()
		select {
		case frames <- frame{
			subject: view.subject, summary: view.subjectInfo.SummaryText(),
			path: path, loading: view.workloadsLoading,
		}:
		default:
		}
	})
	done := make(chan error, 1)
	go func() { done <- app.Run() }()
	t.Cleanup(func() {
		close(cancelCollection)
		app.Stop()
		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Error("simulation UI did not stop")
		}
	})
	nextFrame := func() frame {
		t.Helper()
		select {
		case got := <-frames:
			return got
		case <-time.After(5 * time.Second):
			t.Fatal("workload callback did not repaint")
			return frame{}
		}
	}
	nextRequest := func() request {
		t.Helper()
		select {
		case got := <-requests:
			return got
		case <-time.After(5 * time.Second):
			t.Fatal("workload collection did not start")
			return request{}
		}
	}
	nextFrame()
	previous := testSubjectResult()
	app.QueueUpdate(func() { view.applyResult(previous) })
	oldRequest := nextRequest()
	assert.Equal(t, previous.Subject.Ref, oldRequest.subject)
	assert.Equal(t, previous.Subject.Pods, oldRequest.pods)

	current := testSubjectResult()
	current.Subject.Ref.Name = "next"
	current.Subject.Pods[0].Name = "next"
	app.QueueUpdate(func() {
		view.applySubject(current.Subject.Ref)
		view.applyResult(current)
	})
	newRequest := nextRequest()
	assert.Equal(t, current.Subject.Ref, newRequest.subject)
	assert.Equal(t, current.Subject.Pods, newRequest.pods)
	newRequest.reply <- []ui.SubjectWorkload{{Kind: "Pod", Namespace: "payments", Name: "next"}}
	var latest frame
	for latest.path != "payments/next" || latest.loading {
		latest = nextFrame()
	}
	assert.Contains(t, latest.summary, "next collection")

	oldRequest.reply <- []ui.SubjectWorkload{{Kind: "Pod", Namespace: "payments", Name: "api"}}
	afterStale := nextFrame()
	assert.Equal(t, current.Subject.Ref, afterStale.subject)
	assert.Equal(t, "payments/next", afterStale.path)
	assert.False(t, afterStale.loading)
	assert.Contains(t, afterStale.summary, "next collection")
	assert.NotContains(t, afterStale.summary, "api collection")
}
