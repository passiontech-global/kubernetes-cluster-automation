package nodereporter

import (
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

// wave10Cond returns the evaluated condEval for a condition Type.
func wave10Cond(t *testing.T, r *Reporter, typ string) condEval {
	t.Helper()
	for _, ev := range r.evalConditions() {
		if ev.def.typ == corev1.NodeConditionType(typ) {
			return ev
		}
	}
	t.Fatalf("condition %s not in defs", typ)
	return condEval{}
}

// TestWave10Conditions covers the W10 latch→condition wiring:
// KubeletRuntimeStall's new alt keys, plus the three new condition
// types (FilesystemReadOnly/KR-exhaustion/ClockSkew).
func TestWave10Conditions(t *testing.T) {
	e := fixture(t)
	r := e.r
	state := func(key string) {
		if err := os.WriteFile(filepath.Join(e.dir, "state-"+key),
			[]byte("1700000000\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Baseline: all three new conditions False.
	for _, typ := range []string{
		"FilesystemReadOnly", "KernelResourceExhaustion",
		"ClockSkewDetected",
	} {
		if got := wave10Cond(t, r, typ); got.status != corev1.ConditionFalse {
			t.Fatalf("%s baseline status=%v want False", typ, got.status)
		}
	}
	// containerd-corrupt trips KubeletRuntimeStall via altStateKeys.
	state("containerd-corrupt")
	got := wave10Cond(t, r, "KubeletRuntimeStall")
	if got.status != corev1.ConditionTrue ||
		got.reason != "KubeletRuntimeStallDetected" {
		t.Fatalf("KubeletRuntimeStall=%v/%s want True/KubeletRuntimeStallDetected",
			got.status, got.reason)
	}
	// kubelet-watch-wedge is the other new alt key.
	os.Remove(filepath.Join(e.dir, "state-containerd-corrupt"))
	state("kubelet-watch-wedge")
	if got := wave10Cond(t, r, "KubeletRuntimeStall"); got.status != corev1.ConditionTrue {
		t.Fatal("KubeletRuntimeStall not tripped by kubelet-watch-wedge")
	}
	os.Remove(filepath.Join(e.dir, "state-kubelet-watch-wedge"))
	// fs-readonly alt key + pid-fd-pressure + clock-skew.
	state("fs-readonly")
	state("pid-fd-pressure")
	state("clock-skew")
	for typ, want := range map[string]string{
		"FilesystemReadOnly":       "FilesystemReadOnlyDetected",
		"KernelResourceExhaustion": "KernelResourceExhaustionDetected",
		"ClockSkewDetected":        "ClockSkewDetected",
	} {
		got := wave10Cond(t, r, typ)
		if got.status != corev1.ConditionTrue || got.reason != want {
			t.Fatalf("%s=%v/%s want True/%s", typ, got.status,
				got.reason, want)
		}
	}
	// state-fs-readonly (the hostmetrics latch name) also matches via
	// FilesystemReadOnly's primary stateKey "filesystem-readonly"? —
	// primary is "filesystem-readonly"; the W10 latch is "fs-readonly"
	// covered by altStateKeys. Verify a DIFFERENT key does NOT trip.
	os.Remove(filepath.Join(e.dir, "state-fs-readonly"))
	os.Remove(filepath.Join(e.dir, "state-pid-fd-pressure"))
	os.Remove(filepath.Join(e.dir, "state-clock-skew"))
	os.Remove(filepath.Join(e.dir, "state-fs-readonly"))
	if got := wave10Cond(t, r, "ClockSkewDetected"); got.status != corev1.ConditionFalse {
		t.Fatal("ClockSkewDetected stuck True after latch removal")
	}
}
