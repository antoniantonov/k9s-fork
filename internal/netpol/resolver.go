// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	"fmt"
	"slices"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func (x *snapshotIndex) resolveSubject(ref SubjectRef) (Subject, []string, error) {
	subject := Subject{Ref: ref}
	var warnings []string
	switch ref.Kind {
	case SubjectPod:
		p := x.pods[key(ref.Namespace, ref.Name)]
		if p == nil || (ref.UID != "" && p.UID != ref.UID) {
			return subject, nil, fmt.Errorf("pod %s/%s not found", ref.Namespace, ref.Name)
		}
		subject.Ref.UID = p.UID
		subject.Pods = []PodRef{podRef(p)}
	case SubjectNamespace:
		name := ref.Name
		if name == "" {
			name = ref.Namespace
		}
		ns, ok := x.namespaces[name]
		if !ok || (ref.UID != "" && ns.UID != ref.UID) {
			return subject, nil, fmt.Errorf("namespace %s not found", name)
		}
		subject.Ref.Name, subject.Ref.Namespace, subject.Ref.UID = name, "", ns.UID
		for _, p := range x.pods {
			if p.Namespace == name {
				subject.Pods = append(subject.Pods, podRef(p))
			}
		}
	case SubjectDeployment:
		d := x.deployments[key(ref.Namespace, ref.Name)]
		if d == nil || (ref.UID != "" && d.UID != ref.UID) {
			return subject, nil, fmt.Errorf("deployment %s/%s not found", ref.Namespace, ref.Name)
		}
		subject.Ref.UID = d.UID
		pods, fallback := x.podsForDeployment(d.Namespace, d.UID, d.Spec.Selector)
		for _, p := range pods {
			subject.Pods = append(subject.Pods, podRef(p))
		}
		if fallback {
			warnings = append(warnings, fmt.Sprintf("deployment %s/%s pods resolved by uncertain selector fallback; owner UID chain data is incomplete", d.Namespace, d.Name))
		}
	case SubjectJob:
		j := x.jobs[key(ref.Namespace, ref.Name)]
		if j == nil || (ref.UID != "" && j.UID != ref.UID) {
			return subject, nil, fmt.Errorf("job %s/%s not found", ref.Namespace, ref.Name)
		}
		subject.Ref.UID = j.UID
		pods, fallback := x.podsForJob(j.Namespace, j.UID, j.Spec.Selector)
		for _, p := range pods {
			subject.Pods = append(subject.Pods, podRef(p))
		}
		if fallback {
			warnings = append(warnings, fmt.Sprintf("job %s/%s pods resolved by uncertain selector fallback; owner UID data is incomplete", j.Namespace, j.Name))
		}
	default:
		return subject, nil, fmt.Errorf("unsupported subject kind %d", ref.Kind)
	}
	slices.SortFunc(subject.Pods, func(a, b PodRef) int {
		if a.Namespace != b.Namespace {
			return cmpString(a.Namespace, b.Namespace)
		}
		return cmpString(a.Name, b.Name)
	})
	return subject, warnings, nil
}

func (x *snapshotIndex) podDeploymentUID(p *corev1.Pod) types.UID {
	if owner := ownerByKind(p.OwnerReferences, "Deployment"); owner != nil {
		return owner.UID
	}
	rsOwner := ownerByKind(p.OwnerReferences, "ReplicaSet")
	if rsOwner == nil {
		return ""
	}
	rs := x.replicaSets[rsOwner.UID]
	if rs == nil {
		return ""
	}
	owner := ownerByKind(rs.OwnerReferences, "Deployment")
	if owner == nil {
		return ""
	}
	return owner.UID
}

func (x *snapshotIndex) podsForDeployment(namespace string, uid types.UID, selector *metav1.LabelSelector) ([]*corev1.Pod, bool) {
	var pods []*corev1.Pod
	for _, p := range x.pods {
		if x.podDeploymentUID(p) == uid {
			pods = append(pods, p)
		}
	}
	if len(pods) > 0 {
		return pods, false
	}
	if !x.deploymentOwnershipIncomplete() {
		return nil, false
	}
	for _, p := range x.pods {
		if p.Namespace == namespace && matchesSelectorPtr(selector, p.Labels) {
			pods = append(pods, p)
		}
	}
	return pods, len(pods) > 0
}

func (x *snapshotIndex) deploymentOwnershipIncomplete() bool {
	return x.resourceIncomplete("pods") || x.resourceIncomplete("replicasets")
}

func (x *snapshotIndex) podsForJob(namespace string, uid types.UID, selector *metav1.LabelSelector) ([]*corev1.Pod, bool) {
	var pods []*corev1.Pod
	for _, p := range x.pods {
		if owner := ownerByKind(p.OwnerReferences, "Job"); owner != nil && owner.UID == uid {
			pods = append(pods, p)
		}
	}
	if len(pods) > 0 {
		return pods, false
	}
	if !x.jobOwnershipIncomplete() {
		return nil, false
	}
	for _, p := range x.pods {
		if p.Namespace == namespace && matchesSelectorPtr(selector, p.Labels) {
			pods = append(pods, p)
		}
	}
	return pods, len(pods) > 0
}

func (x *snapshotIndex) jobOwnershipIncomplete() bool {
	return x.resourceIncomplete("pods")
}

func cmpString(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
