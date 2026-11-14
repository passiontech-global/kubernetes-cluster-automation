// linkerd_test.go — unit tests for PodIsMeshed across regular and native
// initContainer sidecar placements.
package kube

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestPodIsMeshed(t *testing.T) {
	t.Parallel()

	if PodIsMeshed(&corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}) {
		t.Error("plain pod should not be meshed")
	}
	if !PodIsMeshed(&corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}, {Name: LinkerdProxyContainer}}}) {
		t.Error("pod with linkerd-proxy container should be meshed")
	}
	if !PodIsMeshed(&corev1.PodSpec{InitContainers: []corev1.Container{{Name: LinkerdProxyContainer}}}) {
		t.Error("pod with linkerd-proxy native initContainer should be meshed")
	}
}
