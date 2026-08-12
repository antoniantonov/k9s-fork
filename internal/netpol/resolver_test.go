// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestResolveSubjects(t *testing.T) {
	controller := true
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}}
	snapshot := Snapshot{
		Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "ns"}}},
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "api", UID: "dep"},
			Spec:       appsv1.DeploymentSpec{Selector: selector},
		}},
		ReplicaSets: []appsv1.ReplicaSet{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "api-rs", UID: "rs", OwnerReferences: []metav1.OwnerReference{
				{Kind: "Deployment", Name: "api", UID: "dep", Controller: &controller},
			}},
		}},
		Jobs: []batchv1.Job{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "worker", UID: "job"},
			Spec:       batchv1.JobSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"job": "worker"}}},
		}},
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "owned-dep", UID: "p1", Labels: map[string]string{"app": "api"}, OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", UID: "rs", Controller: &controller}}}},
			{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "owned-job", UID: "p2", Labels: map[string]string{"job": "worker"}, OwnerReferences: []metav1.OwnerReference{{Kind: "Job", UID: "job", Controller: &controller}}}},
		},
	}
	x := newSnapshotIndex(&snapshot)
	tests := []struct {
		name string
		ref  SubjectRef
		pods []string
	}{
		{"pod", SubjectRef{Kind: SubjectPod, Namespace: "ns", Name: "owned-dep"}, []string{"owned-dep"}},
		{"namespace", SubjectRef{Kind: SubjectNamespace, Name: "ns"}, []string{"owned-dep", "owned-job"}},
		{"deployment owner chain", SubjectRef{Kind: SubjectDeployment, Namespace: "ns", Name: "api"}, []string{"owned-dep"}},
		{"job owner", SubjectRef{Kind: SubjectJob, Namespace: "ns", Name: "worker"}, []string{"owned-job"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			subject, warnings, err := x.resolveSubject(test.ref)
			require.NoError(t, err)
			require.Empty(t, warnings)
			var names []string
			for _, pod := range subject.Pods {
				names = append(names, pod.Name)
			}
			require.Equal(t, test.pods, names)
		})
	}
}

func TestResolveDeploymentSelectorFallbackWarning(t *testing.T) {
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}}
	x := newSnapshotIndex(&Snapshot{
		Deployments: []appsv1.Deployment{{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "api", UID: "dep"}, Spec: appsv1.DeploymentSpec{Selector: selector}}},
		Pods:        []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod", Labels: map[string]string{"app": "api"}}}},
		Incomplete:  map[string]error{"replicasets": errors.New("forbidden")},
	})
	subject, warnings, err := x.resolveSubject(SubjectRef{Kind: SubjectDeployment, Namespace: "ns", Name: "api"})
	require.NoError(t, err)
	require.Len(t, subject.Pods, 1)
	require.Contains(t, warnings[0], "selector fallback")
}

func TestResolveSelectorDoesNotInventMembershipWhenOwnersComplete(t *testing.T) {
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}}
	snapshot := Snapshot{
		Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "api", UID: "dep"},
			Spec:       appsv1.DeploymentSpec{Selector: selector},
		}},
		Jobs: []batchv1.Job{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "worker", UID: "job"},
			Spec:       batchv1.JobSpec{Selector: selector},
		}},
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "ns", Name: "unowned", Labels: map[string]string{"app": "api"},
			},
		}},
	}
	x := newSnapshotIndex(&snapshot)
	for _, ref := range []SubjectRef{
		{Kind: SubjectDeployment, Namespace: "ns", Name: "api"},
		{Kind: SubjectJob, Namespace: "ns", Name: "worker"},
	} {
		subject, warnings, err := x.resolveSubject(ref)
		require.NoError(t, err)
		require.Empty(t, subject.Pods)
		require.Empty(t, warnings)
	}
}
