// pods_test.go — the pod-level helpers: the API-side verdicts
// (PVC consumer, mirror pod, Ready condition) and the verified
// force-delete with its NPD-contract log line.
package wdeps_test

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// TestPodHasPVC — PVC AND generic ephemeral volumes both count
// (same dual-mount risk class).
func TestPodHasPVC(t *testing.T) {
	pvcPod := &corev1.Pod{Spec: corev1.PodSpec{Volumes: []corev1.Volume{{
		Name: "data",
		VolumeSource: corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "pvc"},
		},
	}}}}
	if !wdeps.PodHasPVC(pvcPod) {
		t.Fatal("PVC consumer reported clean")
	}
	ephemeralPod := &corev1.Pod{Spec: corev1.PodSpec{Volumes: []corev1.Volume{{
		Name: "scratch",
		VolumeSource: corev1.VolumeSource{
			Ephemeral: &corev1.EphemeralVolumeSource{},
		},
	}}}}
	if !wdeps.PodHasPVC(ephemeralPod) {
		t.Fatal("ephemeral consumer reported clean")
	}
	plain := &corev1.Pod{Spec: corev1.PodSpec{Volumes: []corev1.Volume{{
		Name: "cfg",
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{},
		},
	}}}}
	if wdeps.PodHasPVC(plain) {
		t.Fatal("configmap-only pod reported as PVC consumer")
	}
	if wdeps.PodHasPVC(&corev1.Pod{}) {
		t.Fatal("volume-less pod reported as PVC consumer")
	}
}

// TestIsMirrorPod — kubelet-static mirror pods carry the config
// annotation.
func TestIsMirrorPod(t *testing.T) {
	mirror := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Annotations: map[string]string{"kubernetes.io/config.mirror": "abc"},
	}}
	if !wdeps.IsMirrorPod(mirror) {
		t.Fatal("mirror pod not detected")
	}
	if wdeps.IsMirrorPod(&corev1.Pod{}) {
		t.Fatal("plain pod detected as mirror")
	}
}

// TestPodReady — the Ready condition verdict, absent conditions are
// not ready.
func TestPodReady(t *testing.T) {
	ready := &corev1.Pod{Status: corev1.PodStatus{Conditions: []corev1.PodCondition{
		{Type: corev1.PodReady, Status: corev1.ConditionTrue},
	}}}
	if !wdeps.PodReady(ready) {
		t.Fatal("Ready=True pod reported not ready")
	}
	notReady := &corev1.Pod{Status: corev1.PodStatus{Conditions: []corev1.PodCondition{
		{Type: corev1.PodReady, Status: corev1.ConditionFalse},
	}}}
	if wdeps.PodReady(notReady) {
		t.Fatal("Ready=False pod reported ready")
	}
	other := &corev1.Pod{Status: corev1.PodStatus{Conditions: []corev1.PodCondition{
		{Type: corev1.PodInitialized, Status: corev1.ConditionTrue},
	}}}
	if wdeps.PodReady(other) {
		t.Fatal("no Ready condition must read not ready")
	}
	if wdeps.PodReady(&corev1.Pod{}) {
		t.Fatal("condition-less pod reported ready")
	}
}

// TestForceDeletePod — the API delete carries grace 0 + Background
// propagation, and the NPD-contract log line lands with the
// termination age off the seams clock.
func TestForceDeletePod(t *testing.T) {
	e := fixture(t)
	p := e.TerminatingPod("stuck", "default", wdepstest.UIDA, 20*time.Minute)
	p.UID = types.UID(wdepstest.UIDA)
	if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	if err := e.D.ForceDeletePod(context.Background(), p); err != nil {
		t.Fatalf("ForceDeletePod: %v", err)
	}
	deletes := wdepstest.DeleteActions(e.CS)
	if len(deletes) != 1 {
		t.Fatalf("deletes=%d want 1", len(deletes))
	}
	opts := deletes[0].GetDeleteOptions()
	if opts.GracePeriodSeconds == nil || *opts.GracePeriodSeconds != 0 {
		t.Fatalf("grace=%v want 0", opts.GracePeriodSeconds)
	}
	if opts.PropagationPolicy == nil || *opts.PropagationPolicy != metav1.DeletePropagationBackground {
		t.Fatalf("propagation=%v want Background", opts.PropagationPolicy)
	}
	if deletes[0].GetName() != "stuck" {
		t.Fatalf("deleted name=%q", deletes[0].GetName())
	}
	log := e.LogLines(t)
	if !strings.Contains(log, "POD-TEARDOWN-FORCE-DELETE: force-delete pod default/stuck (uid 11111111)") ||
		!strings.Contains(log, "- Terminating 1200s, zero live tasks") {
		t.Fatalf("missing contract log line:\n%s", log)
	}
}
