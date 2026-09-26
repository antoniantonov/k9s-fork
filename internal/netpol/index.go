// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	"fmt"
	"slices"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type snapshotIndex struct {
	pods                map[string]*corev1.Pod
	namespaces          map[string]*corev1.Namespace
	policies            map[string][]*normalizedPolicy
	globalPolicies      []*normalizedPolicy
	deployments         map[string]*appsv1.Deployment
	replicaSets         map[types.UID]*appsv1.ReplicaSet
	jobs                map[string]*batchv1.Job
	incomplete          []string
	incompleteResources map[string]struct{}
}

func newSnapshotIndex(snapshot *Snapshot) *snapshotIndex {
	x := &snapshotIndex{
		pods:                make(map[string]*corev1.Pod, len(snapshot.Pods)),
		namespaces:          make(map[string]*corev1.Namespace, len(snapshot.Namespaces)),
		policies:            make(map[string][]*normalizedPolicy),
		deployments:         make(map[string]*appsv1.Deployment, len(snapshot.Deployments)),
		replicaSets:         make(map[types.UID]*appsv1.ReplicaSet, len(snapshot.ReplicaSets)),
		jobs:                make(map[string]*batchv1.Job, len(snapshot.Jobs)),
		incompleteResources: make(map[string]struct{}, len(snapshot.Incomplete)),
	}
	for i := range snapshot.Pods {
		p := &snapshot.Pods[i]
		x.pods[key(p.Namespace, p.Name)] = p
	}
	for i := range snapshot.Namespaces {
		ns := &snapshot.Namespaces[i]
		x.namespaces[ns.Name] = ns
	}
	policies, policyFailures := normalizeSnapshotPolicies(snapshot)
	for i := range policies {
		policy := &policies[i]
		if policy.ClusterScoped {
			x.globalPolicies = append(x.globalPolicies, policy)
		} else {
			x.policies[policy.Namespace] = append(x.policies[policy.Namespace], policy)
		}
	}
	for i := range snapshot.Deployments {
		d := &snapshot.Deployments[i]
		x.deployments[key(d.Namespace, d.Name)] = d
	}
	for i := range snapshot.ReplicaSets {
		rs := &snapshot.ReplicaSets[i]
		x.replicaSets[rs.UID] = rs
	}
	for i := range snapshot.Jobs {
		j := &snapshot.Jobs[i]
		x.jobs[key(j.Namespace, j.Name)] = j
	}
	for resource, err := range snapshot.Incomplete {
		x.incompleteResources[resource] = struct{}{}
		if err == nil {
			x.incomplete = append(x.incomplete, fmt.Sprintf("snapshot resource %q is incomplete", resource))
		} else {
			x.incomplete = append(x.incomplete, fmt.Sprintf("snapshot resource %q is incomplete: %v", resource, err))
		}
	}
	for resource, err := range policyFailures {
		x.incompleteResources[resource] = struct{}{}
		x.incomplete = append(x.incomplete, fmt.Sprintf("snapshot resource %q could not be fully evaluated: %v", resource, err))
	}
	slices.Sort(x.incomplete)
	for ns := range x.policies {
		sortNormalizedPolicies(x.policies[ns])
	}
	sortNormalizedPolicies(x.globalPolicies)
	return x
}

func (x *snapshotIndex) resourceIncomplete(resource string) bool {
	_, ok := x.incompleteResources[resource]
	return ok
}

func (x *snapshotIndex) policiesForPod(pod *corev1.Pod) []*normalizedPolicy {
	out := make([]*normalizedPolicy, 0, len(x.policies[pod.Namespace])+len(x.globalPolicies))
	out = append(out, x.policies[pod.Namespace]...)
	out = append(out, x.globalPolicies...)
	return out
}

func sortNormalizedPolicies(policies []*normalizedPolicy) {
	slices.SortFunc(policies, func(a, b *normalizedPolicy) int {
		if a.Type != b.Type {
			return cmpString(a.Type.String(), b.Type.String())
		}
		if a.Namespace != b.Namespace {
			return cmpString(a.Namespace, b.Namespace)
		}
		if a.Name != b.Name {
			return cmpString(a.Name, b.Name)
		}
		return a.SpecIndex - b.SpecIndex
	})
}

func key(namespace, name string) string {
	return namespace + "\x00" + name
}

func podRef(p *corev1.Pod) PodRef {
	return PodRef{Namespace: p.Namespace, Name: p.Name, UID: p.UID}
}

func ownerByKind(owners []metav1.OwnerReference, kind string) *metav1.OwnerReference {
	for i := range owners {
		if owners[i].Kind == kind && (owners[i].Controller == nil || *owners[i].Controller) {
			return &owners[i]
		}
	}
	return nil
}
