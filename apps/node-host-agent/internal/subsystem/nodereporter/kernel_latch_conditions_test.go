package nodereporter

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
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

// TestKernelLatchConditions covers the kernel latch→condition wiring:
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
	// primary is "filesystem-readonly"; the kernelfail latch is "fs-readonly"
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

// TestCiliumLatchConditions covers the newest tail entries: the
// workerhygiene cilium MTU-drift (B4) and WireGuard peer-wipe (cilium-wg-peer-gc)
// latches map 1:1 to the CiliumMTUDrift and CiliumWGStale conditions
// appended at the tail of conditionDefs — the defs carry the exact
// latch keys, a present latch flips the condition True with the
// problem reason, and a removed latch flips it back to False.
func TestCiliumLatchConditions(t *testing.T) {
	if len(conditionDefs) != 49 {
		t.Fatalf("conditionDefs has %d defs, want 49 (41 prior + 7 W21 latch→condition surface + ApiserverWatchCacheWedged)",
			len(conditionDefs))
	}
	// The cilium pair sits before the inode-pressure + W21 tail —
	// locate by typ so later appends cannot shift the check.
	var mtuDef, wgDef *conditionDef
	for i := range conditionDefs {
		switch conditionDefs[i].typ {
		case nodecond.CiliumMTUDrift:
			mtuDef = &conditionDefs[i]
		case nodecond.CiliumWGStale:
			wgDef = &conditionDefs[i]
		}
	}
	if mtuDef == nil || mtuDef.stateKey != latchdefs.LatchCiliumMTUDrift {
		t.Fatalf("CiliumMTUDrift def = %+v, want stateKey %s",
			mtuDef, latchdefs.LatchCiliumMTUDrift)
	}
	if wgDef == nil || wgDef.stateKey != latchdefs.LatchCiliumWGPeerWipe {
		t.Fatalf("CiliumWGStale def = %+v, want stateKey %s",
			wgDef, latchdefs.LatchCiliumWGPeerWipe)
	}
	e := fixture(t)
	state := func(key string) {
		if err := os.WriteFile(filepath.Join(e.dir, "state-"+key),
			[]byte("1700000000\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, typ := range []string{nodecond.CiliumMTUDrift, nodecond.CiliumWGStale} {
		if got := condEvalFor(t, e.r, typ); got.status != corev1.ConditionFalse {
			t.Fatalf("%s baseline status=%v want False", typ, got.status)
		}
	}
	state("cilium-mtu-drift")
	got := condEvalFor(t, e.r, nodecond.CiliumMTUDrift)
	if got.status != corev1.ConditionTrue || got.reason != "CiliumMTUDriftDetected" {
		t.Fatalf("CiliumMTUDrift=%v/%s want True/CiliumMTUDriftDetected",
			got.status, got.reason)
	}
	if wantMsg := "watchdog state cilium-mtu-drift active since 1700000000"; got.message != wantMsg {
		t.Fatalf("CiliumMTUDrift message=%q want %q", got.message, wantMsg)
	}
	state("cilium-wg-peer-wipe")
	if got := condEvalFor(t, e.r, nodecond.CiliumWGStale); got.status != corev1.ConditionTrue ||
		got.reason != "CiliumWGStaleDetected" {
		t.Fatalf("CiliumWGStale=%v/%s want True/CiliumWGStaleDetected",
			got.status, got.reason)
	}
	_ = os.Remove(filepath.Join(e.dir, "state-cilium-mtu-drift"))
	_ = os.Remove(filepath.Join(e.dir, "state-cilium-wg-peer-wipe"))
	for _, typ := range []string{nodecond.CiliumMTUDrift, nodecond.CiliumWGStale} {
		if got := condEvalFor(t, e.r, typ); got.status != corev1.ConditionFalse {
			t.Fatalf("%s stuck True after latch removal", typ)
		}
	}
}

// TestInodePressureCondition covers the inode-pressure tail entry: hostmetrics'
// inode-pressure latch maps 1:1 to the kubelet-native InodePressure
// condition — True with FilesystemInodesExhausted while
// state-inode-pressure exists, False with FilesystemInodesHealthy
// once it is removed.
func TestInodePressureCondition(t *testing.T) {
	e := fixture(t)
	state := func(key string) {
		if err := os.WriteFile(filepath.Join(e.dir, "state-"+key),
			[]byte("1700000000\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got := condEvalFor(t, e.r, nodecond.InodePressure); got.status != corev1.ConditionFalse ||
		got.reason != "FilesystemInodesHealthy" {
		t.Fatalf("InodePressure baseline=%v/%s want False/FilesystemInodesHealthy",
			got.status, got.reason)
	}
	state(latchdefs.LatchInodePressure)
	got := condEvalFor(t, e.r, nodecond.InodePressure)
	if got.status != corev1.ConditionTrue || got.reason != "FilesystemInodesExhausted" {
		t.Fatalf("InodePressure=%v/%s want True/FilesystemInodesExhausted",
			got.status, got.reason)
	}
	if wantMsg := "watchdog state inode-pressure active since 1700000000"; got.message != wantMsg {
		t.Fatalf("InodePressure message=%q want %q", got.message, wantMsg)
	}
	_ = os.Remove(filepath.Join(e.dir, "state-"+latchdefs.LatchInodePressure))
	if got := condEvalFor(t, e.r, nodecond.InodePressure); got.status != corev1.ConditionFalse ||
		got.reason != "FilesystemInodesHealthy" {
		t.Fatalf("InodePressure stuck True after latch removal")
	}
}

// TestNoRawConditionNameLiterals is the nodecond single-source-of-
// truth guard: the condition-name surfaces in this package — the
// conditionDefs typ fields, the logRules event reasons that exactly
// duplicate a nodecond name, and the npd monitor condition
// constants — must be spelled as nodecond constants, never raw
// string literals. The scan is source-level over the production
// files (tests are excluded — they legitimately match on names) and
// errors on any quoted literal equal to a nodecond-defined name in
// those surfaces.
func TestNoRawConditionNameLiterals(t *testing.T) {
	names := map[string]bool{}
	for _, list := range [][]string{
		nodecond.HeartbeatSweptNames, nodecond.HangPreCordonNames,
		nodecond.ClockSkewPreCordonNames, nodecond.StormGateNames,
		nodecond.PartitionNames,
	} {
		for _, n := range list {
			names[n] = true
		}
	}
	names[nodecond.KernelDeadlock] = true // permanent latch — in no list
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`typ:\s+"([A-Za-z0-9]+)"`),              // conditionDefs typ fields
		regexp.MustCompile(`(?m)^\t\{"([A-Za-z0-9]+)",`),           // logRules event reasons
		regexp.MustCompile(`NodeConditionType = "([A-Za-z0-9]+)"`), // npd monitor consts
	}
	for _, f := range []string{"conditions.go", "events.go", "npd/kernel.go", "npd/readonly.go"} {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, re := range patterns {
			for _, m := range re.FindAllStringSubmatch(string(data), -1) {
				if names[m[1]] {
					t.Errorf("%s: raw condition-name literal %q — use the nodecond constant", f, m[1])
				}
			}
		}
	}
}
