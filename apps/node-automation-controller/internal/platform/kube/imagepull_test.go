// imagepull_test.go — the image-pull-storm-gate/maintenance-hold-stale stall predicate and cluster
// census: only CURRENT container waiting states count, all three
// container slots are scanned, and the census counts pods and
// distinct namespaces.
package kube

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// pullStalledPod builds a pod with one container status waiting in
// `reason` in the given slot ("" = regular containers).
func pullStalledPod(ns, name, reason, slot string) *corev1.Pod {
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
	st := corev1.ContainerStatus{
		Name: "app",
		State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
			Reason: reason}},
	}
	switch slot {
	case "init":
		p.Status.InitContainerStatuses = []corev1.ContainerStatus{st}
	case "ephemeral":
		p.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{st}
	default:
		p.Status.ContainerStatuses = []corev1.ContainerStatus{st}
	}
	return p
}

func TestImagePullStallReasonSlots(t *testing.T) {
	for _, slot := range []string{"", "init", "ephemeral"} {
		p := pullStalledPod("apps", "p", "ImagePullBackOff", slot)
		if got := ImagePullStallReason(p); got != "ImagePullBackOff" {
			t.Fatalf("slot %q: reason = %q, want ImagePullBackOff", slot, got)
		}
		if !PodImagePullStalled(p) {
			t.Fatalf("slot %q: pod must read as stalled", slot)
		}
	}
}

func TestImagePullStallReasonIgnoresHealthyAndOtherReasons(t *testing.T) {
	// A running container and non-pull waiting reasons are not stalls.
	running := &corev1.Pod{}
	running.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name:  "app",
		State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
	}}
	if got := ImagePullStallReason(running); got != "" {
		t.Fatalf("running container read as stall %q", got)
	}
	crash := pullStalledPod("apps", "p", "CrashLoopBackOff", "")
	if got := ImagePullStallReason(crash); got != "" {
		t.Fatalf("CrashLoopBackOff read as stall %q", got)
	}
	// A RECOVERED pull failure (last termination state only) is not
	// a current stall.
	recovered := &corev1.Pod{}
	recovered.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name: "app",
		LastTerminationState: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
			Reason: "ImagePullBackOff"}},
		State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
	}}
	if got := ImagePullStallReason(recovered); got != "" {
		t.Fatalf("recovered pull failure read as stall %q", got)
	}
}

func TestCountImagePullStalledPods(t *testing.T) {
	cs := fake.NewSimpleClientset(
		pullStalledPod("apps", "a", "ImagePullBackOff", ""),
		pullStalledPod("apps", "b", "ErrImagePull", ""),
		pullStalledPod("db", "c", "ImagePullBackOff", "init"),
		pullStalledPod("db", "healthy", "CrashLoopBackOff", ""),
		pullStalledPod("kube-system", "fine", "", ""),
	)
	pods, namespaces, err := CountImagePullStalledPods(t.Context(), cs)
	if err != nil {
		t.Fatal(err)
	}
	if pods != 3 {
		t.Fatalf("podCount = %d, want 3", pods)
	}
	if namespaces != 2 {
		t.Fatalf("namespaceCount = %d, want 2", namespaces)
	}
}
