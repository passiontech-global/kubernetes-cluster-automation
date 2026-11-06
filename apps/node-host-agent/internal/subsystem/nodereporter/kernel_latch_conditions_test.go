package nodereporter

import (
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

// condEvalFor returns the evaluated condEval for a condition Type.
func condEvalFor(t *testing.T, r *Reporter, typ string) condEval {
	t.Helper()
	for _, ev := range r.evalConditions() {
		if ev.def.typ == corev1.NodeConditionType(typ) {
			return ev
		}
	}
	t.Fatalf("condition %s not in defs", typ)
	return condEval{}
}

// TestKernelLatchConditions covers the W10 latch→condition wiring:
// KubeletRuntimeStall's new alt keys, plus the three new condition
// types (FilesystemReadOnly/KR-exhaustion/ClockSkew).
func TestKernelLatchConditions(t *testing.T) {
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
		if got := condEvalFor(t, r, typ); got.status != corev1.ConditionFalse {
			t.Fatalf("%s baseline status=%v want False", typ, got.status)
		}
	}
	// containerd-corrupt trips KubeletRuntimeStall via altStateKeys.
	state("containerd-corrupt")
	got := condEvalFor(t, r, "KubeletRuntimeStall")
	if got.status != corev1.ConditionTrue ||
		got.reason != "KubeletRuntimeStallDetected" {
		t.Fatalf("KubeletRuntimeStall=%v/%s want True/KubeletRuntimeStallDetected",
			got.status, got.reason)
	}
	// kubelet-watch-wedge is the other new alt key.
	_ = os.Remove(filepath.Join(e.dir, "state-containerd-corrupt"))
	state("kubelet-watch-wedge")
	if got := condEvalFor(t, r, "KubeletRuntimeStall"); got.status != corev1.ConditionTrue {
		t.Fatal("KubeletRuntimeStall not tripped by kubelet-watch-wedge")
	}
	_ = os.Remove(filepath.Join(e.dir, "state-kubelet-watch-wedge"))
	// fs-readonly alt key + pid-fd-pressure + clock-skew.
	state("fs-readonly")
	state("pid-fd-pressure")
	state("clock-skew")
	for typ, want := range map[string]string{
		"FilesystemReadOnly":       "FilesystemReadOnlyDetected",
		"KernelResourceExhaustion": "KernelResourceExhaustionDetected",
		"ClockSkewDetected":        "ClockSkewDetected",
	} {
		got := condEvalFor(t, r, typ)
		if got.status != corev1.ConditionTrue || got.reason != want {
			t.Fatalf("%s=%v/%s want True/%s", typ, got.status,
				got.reason, want)
		}
	}
	// state-fs-readonly (the hostmetrics latch name) also matches via
	// FilesystemReadOnly's primary stateKey "filesystem-readonly"? —
	// primary is "filesystem-readonly"; the W10 latch is "fs-readonly"
	// covered by altStateKeys. Verify a DIFFERENT key does NOT trip.
	_ = os.Remove(filepath.Join(e.dir, "state-fs-readonly"))
	_ = os.Remove(filepath.Join(e.dir, "state-pid-fd-pressure"))
	_ = os.Remove(filepath.Join(e.dir, "state-clock-skew"))
	_ = os.Remove(filepath.Join(e.dir, "state-fs-readonly"))
	if got := condEvalFor(t, r, "ClockSkewDetected"); got.status != corev1.ConditionFalse {
		t.Fatal("ClockSkewDetected stuck True after latch removal")
	}
}

// TestHygieneLatchConditions covers the remaining registered
// latches — each maps 1:1 to its permanent NodeCondition:
// kubeconfig-cert-expiring (controllerhygiene cert-expiry),
// cpu-steal-pressure (hostmetrics steal guard), cgroup-dying-leak
// and systemd-session-bloat (workerhygiene hygiene checks).
func TestHygieneLatchConditions(t *testing.T) {
	e := fixture(t)
	r := e.r
	state := func(key string) {
		if err := os.WriteFile(filepath.Join(e.dir, "state-"+key),
			[]byte("1700000000\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	latches := map[string][2]string{
		"kubeconfig-cert-expiring": {"KubeconfigCertExpiring", "KubeconfigCertExpiringDetected"},
		"cpu-steal-pressure":       {"CPUStealPressure", "CPUStealPressureDetected"},
		"cgroup-dying-leak":        {"CgroupDyingLeak", "CgroupDyingLeakDetected"},
		"systemd-session-bloat":    {"SystemdSessionBloat", "SystemdSessionBloatDetected"},
	}
	// Baseline: every condition False with its default reason.
	for _, want := range latches {
		got := condEvalFor(t, r, want[0])
		if got.status != corev1.ConditionFalse {
			t.Fatalf("%s baseline status=%v want False", want[0], got.status)
		}
	}
	for latch, want := range latches {
		state(latch)
		got := condEvalFor(t, r, want[0])
		if got.status != corev1.ConditionTrue || got.reason != want[1] {
			t.Fatalf("latch %s: %s=%v/%s want True/%s",
				latch, want[0], got.status, got.reason, want[1])
		}
		if wantMsg := "watchdog state " + latch + " active since 1700000000"; got.message != wantMsg {
			t.Fatalf("latch %s: message=%q want %q", latch, got.message, wantMsg)
		}
		_ = os.Remove(filepath.Join(e.dir, "state-"+latch))
	}
	// All latches cleared → every condition back to False.
	for _, want := range latches {
		if got := condEvalFor(t, r, want[0]); got.status != corev1.ConditionFalse {
			t.Fatalf("%s stuck True after latch removal", want[0])
		}
	}
}

// TestKernelHungTasksEvidenceLatches covers the
// kernel-softlockup-monitor wiring: the kernel monitor's
// soft-lockup/RCU-stall evidence latches (state-kernel-softlockup /
// state-kernel-rcu-stall, written by processKernelLine) raise
// KernelHungTasks through altStateKeys — the same hang class as the
// d-state-storm primary latch.
func TestKernelHungTasksEvidenceLatches(t *testing.T) {
	for _, latch := range []string{"kernel-softlockup", "kernel-rcu-stall"} {
		t.Run(latch, func(t *testing.T) {
			e := fixture(t)
			if err := os.WriteFile(filepath.Join(e.dir, "state-"+latch),
				[]byte("1700000007\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			got := condEvalFor(t, e.r, "KernelHungTasks")
			if got.status != corev1.ConditionTrue ||
				got.reason != "KernelHungTasksDetected" {
				t.Fatalf("KernelHungTasks=%v/%s want True/KernelHungTasksDetected",
					got.status, got.reason)
			}
			wantMsg := "watchdog state " + latch + " active since 1700000007"
			if got.message != wantMsg {
				t.Fatalf("message=%q want %q", got.message, wantMsg)
			}
		})
	}
}
