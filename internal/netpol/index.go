// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	"fmt"
	"net/netip"
	"slices"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
)

type snapshotIndex struct {
	pods                map[string]*corev1.Pod
	namespaces          map[string]*corev1.Namespace
	policies            map[string][]*normalizedPolicy
	globalPolicies      []*normalizedPolicy
	ciliumHostPolicies  bool
	deployments         map[string]*appsv1.Deployment
	replicaSets         map[types.UID]*appsv1.ReplicaSet
	jobs                map[string]*batchv1.Job
	incomplete          []string
	incompleteResources map[string]struct{}

	infos           map[*corev1.Pod]*podInfo
	namespaceLabels map[string]labels.Set
	pairs           map[pairKey]pairResult
	uncertainty     map[string]struct{}
}

// podInfo caches per-pod data used by every pair evaluation.
type podInfo struct {
	pod             *corev1.Pod
	ref             string
	namespaceLabels labels.Set
	accountLabels   labels.Set
	addresses       []netip.Addr
	mesh            meshEnrollment
	identity        istioIdentity
	selection       *podSelection
}

type pairKey struct {
	source, destination *corev1.Pod
}

func newSnapshotIndex(snapshot *Snapshot) *snapshotIndex {
	return buildSnapshotIndex(snapshot, nil)
}

func buildSnapshotIndex(snapshot *Snapshot, cache *normalizationCache) *snapshotIndex {
	x := &snapshotIndex{
		pods:                make(map[string]*corev1.Pod, len(snapshot.Pods)),
		namespaces:          make(map[string]*corev1.Namespace, len(snapshot.Namespaces)),
		policies:            make(map[string][]*normalizedPolicy),
		deployments:         make(map[string]*appsv1.Deployment, len(snapshot.Deployments)),
		replicaSets:         make(map[types.UID]*appsv1.ReplicaSet, len(snapshot.ReplicaSets)),
		jobs:                make(map[string]*batchv1.Job, len(snapshot.Jobs)),
		incompleteResources: make(map[string]struct{}, len(snapshot.Incomplete)),
		infos:               make(map[*corev1.Pod]*podInfo, len(snapshot.Pods)),
		namespaceLabels:     make(map[string]labels.Set, len(snapshot.Namespaces)),
		pairs:               make(map[pairKey]pairResult),
		uncertainty:         make(map[string]struct{}),
	}
	for i := range snapshot.Pods {
		p := &snapshot.Pods[i]
		x.pods[key(p.Namespace, p.Name)] = p
	}
	for i := range snapshot.Namespaces {
		ns := &snapshot.Namespaces[i]
		x.namespaces[ns.Name] = ns
	}
	for _, policy := range normalizeSnapshotPolicies(snapshot, cache) {
		switch {
		case policy.State == policyInert:
			x.ciliumHostPolicies = x.ciliumHostPolicies || policy.HostPolicy
		case policy.ClusterScoped:
			x.globalPolicies = append(x.globalPolicies, policy)
		default:
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

// info returns the cached per-pod data, building it on first use.
func (x *snapshotIndex) info(pod *corev1.Pod) *podInfo {
	if info, ok := x.infos[pod]; ok {
		return info
	}
	namespace := x.namespaces[pod.Namespace]
	serviceAccount := pod.Spec.ServiceAccountName
	if serviceAccount == "" {
		serviceAccount = defaultServiceAccount
	}
	info := &podInfo{
		pod:             pod,
		ref:             pod.Namespace + "/" + pod.Name,
		namespaceLabels: x.labelsForNamespace(pod.Namespace),
		accountLabels:   labels.Set{"name": serviceAccount},
		addresses:       podAddresses(pod),
		mesh:            podMeshEnrollment(pod, namespace),
	}
	info.identity = istioPodIdentity(pod, info.mesh)
	x.infos[pod] = info
	return info
}

// labelsForNamespace returns the namespace labels including the immutable
// kubernetes.io/metadata.name label, which also identifies namespaces missing
// from the snapshot.
func (x *snapshotIndex) labelsForNamespace(name string) labels.Set {
	if set, ok := x.namespaceLabels[name]; ok {
		return set
	}
	set := labels.Set{metadataNameLabel: name}
	if namespace := x.namespaces[name]; namespace != nil {
		for key, value := range namespace.Labels {
			set[key] = value
		}
	}
	x.namespaceLabels[name] = set
	return set
}

func podAddresses(pod *corev1.Pod) []netip.Addr {
	values := make([]string, 0, len(pod.Status.PodIPs)+1)
	if pod.Status.PodIP != "" {
		values = append(values, pod.Status.PodIP)
	}
	for _, item := range pod.Status.PodIPs {
		values = append(values, item.IP)
	}
	var addresses []netip.Addr
	for _, value := range uniqueStrings(values) {
		if address, err := netip.ParseAddr(value); err == nil {
			addresses = append(addresses, address)
		}
	}
	return addresses
}

// noteUncertainty records reasons that made an evaluated pair partial.
func (x *snapshotIndex) noteUncertainty(reasons []string) {
	for _, reason := range reasons {
		x.uncertainty[reason] = struct{}{}
	}
}

func (x *snapshotIndex) uncertaintyWarnings() []string {
	return uniqueStrings(mapsKeys(x.uncertainty))
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
