// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// meshState is a pod's Istio data-plane enrollment.
type meshState uint8

const (
	meshNotEnrolled meshState = iota
	meshEnrolled
	meshUnknown
)

const (
	istioProxyContainer               = "istio-proxy"
	istioSidecarStatusAnnotation      = "sidecar.istio.io/status"
	istioInjectLabel                  = "sidecar.istio.io/inject"
	istioRevisionLabel                = "istio.io/rev"
	istioInjectionNamespaceLabel      = "istio-injection"
	istioDataplaneModeLabel           = "istio.io/dataplane-mode"
	istioAmbientRedirectionAnnotation = "ambient.istio.io/redirection"
	istioDataplaneModeAmbient         = "ambient"
	istioDataplaneModeNone            = "none"
	istioAmbientEnrollment            = "Istio ambient mode"
)

// meshEnrollment explains whether Istio enforces AuthorizationPolicy for a pod.
type meshEnrollment struct {
	state  meshState
	reason string
}

// podMeshEnrollment detects sidecar or ambient enrollment from the pod and its
// namespace. AuthorizationPolicy only applies to workloads in the mesh, so a
// pod that is definitely outside the mesh is not subject to it. Conflicting
// signals leave enrollment unknown rather than guessing.
func podMeshEnrollment(pod *corev1.Pod, namespace *corev1.Namespace) meshEnrollment {
	ref := pod.Namespace + "/" + pod.Name
	if hasIstioProxy(pod) {
		return meshEnrollment{state: meshEnrolled, reason: "Istio sidecar"}
	}
	if pod.Spec.HostNetwork {
		return meshEnrollment{reason: fmt.Sprintf("hostNetwork pod %s is not captured by the mesh", ref)}
	}
	switch pod.Labels[istioDataplaneModeLabel] {
	case istioDataplaneModeNone:
		return meshEnrollment{reason: fmt.Sprintf("pod %s opts out with %s=none", ref, istioDataplaneModeLabel)}
	case istioDataplaneModeAmbient:
		return meshEnrollment{state: meshEnrolled, reason: istioAmbientEnrollment}
	}
	if pod.Annotations[istioAmbientRedirectionAnnotation] == "enabled" {
		return meshEnrollment{state: meshEnrolled, reason: istioAmbientEnrollment}
	}
	if _, ok := pod.Annotations[istioSidecarStatusAnnotation]; ok {
		return meshEnrollment{state: meshUnknown, reason: fmt.Sprintf(
			"pod %s has the %s annotation but no %s container", ref, istioSidecarStatusAnnotation, istioProxyContainer,
		)}
	}
	if namespace == nil {
		return meshEnrollment{state: meshUnknown, reason: fmt.Sprintf(
			"namespace %s is missing from the snapshot, so ambient and injection labels are unknown", pod.Namespace,
		)}
	}
	if namespace.Labels[istioDataplaneModeLabel] == istioDataplaneModeAmbient {
		return meshEnrollment{state: meshEnrolled, reason: istioAmbientEnrollment}
	}
	inject := pod.Annotations[istioInjectLabel]
	if value, present := pod.Labels[istioInjectLabel]; present {
		inject = value
	}
	optOut := strings.EqualFold(inject, "false")
	injection := namespace.Labels[istioInjectionNamespaceLabel]
	expected := strings.EqualFold(inject, "true") || pod.Labels[istioRevisionLabel] != "" ||
		injection == "enabled" || (namespace.Labels[istioRevisionLabel] != "" && injection != "disabled")
	if expected && !optOut {
		return meshEnrollment{state: meshUnknown, reason: fmt.Sprintf(
			"sidecar injection is enabled for pod %s, but it has no %s container", ref, istioProxyContainer,
		)}
	}
	return meshEnrollment{reason: fmt.Sprintf("pod %s has no Istio sidecar or ambient enrollment", ref)}
}

func hasIstioProxy(pod *corev1.Pod) bool {
	for index := range pod.Spec.Containers {
		if pod.Spec.Containers[index].Name == istioProxyContainer {
			return true
		}
	}
	for index := range pod.Spec.InitContainers {
		container := &pod.Spec.InitContainers[index]
		if container.Name == istioProxyContainer && container.RestartPolicy != nil &&
			*container.RestartPolicy == corev1.ContainerRestartPolicyAlways {
			return true
		}
	}
	return false
}

// istioPodIdentity is the peer identity a destination proxy sees for a
// source pod. Pods outside the mesh present no mTLS identity.
func istioPodIdentity(pod *corev1.Pod, enrollment meshEnrollment) istioIdentity {
	identity := istioIdentity{state: enrollment.state}
	if enrollment.state != meshEnrolled {
		return identity
	}
	serviceAccount := pod.Spec.ServiceAccountName
	if serviceAccount == "" {
		serviceAccount = defaultServiceAccount
	}
	identity.namespace = pod.Namespace
	identity.serviceAccount = serviceAccount
	identity.principal = istioTrustDomain + "/ns/" + pod.Namespace + "/sa/" + serviceAccount
	return identity
}
