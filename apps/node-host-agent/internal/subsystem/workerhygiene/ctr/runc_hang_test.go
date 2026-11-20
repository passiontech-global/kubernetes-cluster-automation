// runc_hang_test.go — coverage for the P1.5 hung-OCI-runtime
// reaper: comm/state/age qualification, the consecutive-cycle
// confirm streak, the per-cycle kill cap, the kill-enable gate
// (detect-only posture), and the EventNamespace-routed event.
package ctr_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/nodecoord"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/ctr"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// ageProc backdates a fixture proc dir so FS.Age reports `d` — the
// shell `stat -c %Y` parity the check relies on.
func ageProc(t *testing.T, e *env, pid int, d time.Duration) {
	t.Helper()
	old := e.Now.Add(-d)
	if err := os.Chtimes(filepath.Join(e.ProcDir, strconv.Itoa(pid)), old, old); err != nil {
		t.Fatal(err)
	}
}

func hungEnv(t *testing.T, confirm int) *env {
	t.Helper()
	e := fixture(t)
	e.H.Cfg.Wave2.HungRuncAgeSec = 180
	e.H.Cfg.Wave2.HungRuncConfirmCycles = confirm
	e.H.Cfg.Wave2.HungRuncMaxKillsPerCycle = 4
	e.H.Cfg.Wave2.HungRuncKillEnabled = true
	return e
}

func hungCheck(e *env) *ctr.HungRuncCheck {
	return wdepstest.Check[*ctr.HungRuncCheck](e.H, wdeps.CheckHungRunc)
}

func cycleEnv() *wdeps.CycleEnv {
	return &wdeps.CycleEnv{WorkerActive: true, APIOK: true}
}

// TestHungRuncConfirmThenKill pins the detection ladder: an aged
// runc in S state is only a suspect on cycle 1, confirmed on
// cycle N, and only then does the bounded SIGKILL + event fire.
func TestHungRuncConfirmThenKill(t *testing.T) {
	e := hungEnv(t, 2)
	e.MkStatProc(t, 7100, "runc", "S", "do_wait")
	ageProc(t, e, 7100, 10*time.Minute)
	chk := hungCheck(e)
	ctx := context.Background()

	chk.Run(ctx, cycleEnv()) // cycle 1 — suspect, no kill
	if len(e.Kills) != 0 {
		t.Fatalf("cycle-1 kills=%v want none (confirm pending)", e.Kills)
	}
	chk.Run(ctx, cycleEnv()) // cycle 2 — confirmed → kill + event
	if len(e.Kills) != 1 || e.Kills[0].PID != 7100 {
		t.Fatalf("kills=%v want one SIGKILL on 7100", e.Kills)
	}
	evs, err := e.CS.EventsV1().Events(e.H.Cfg.Host.EventNamespace).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs.Items) != 1 || evs.Items[0].Reason != "OCIRuntimeProcessHung" {
		t.Fatalf("events=%+v want one OCIRuntimeProcessHung", evs.Items)
	}
	if evs.Items[0].Regarding.Name != e.H.Cfg.NodeName {
		t.Fatalf("event regarding=%q want the node", evs.Items[0].Regarding.Name)
	}
	if !strings.Contains(evs.Items[0].Note, "pid=7100") {
		t.Fatalf("event note=%q missing pid identity", evs.Items[0].Note)
	}
}

// TestHungRuncQualificationFilters pins the scan filters: non-runtime
// comms, non-S states, and too-young procs never enter the streak.
func TestHungRuncQualificationFilters(t *testing.T) {
	e := hungEnv(t, 1)
	// Wrong comm — an aged S-state sleep is not a runtime.
	e.MkStatProc(t, 7200, "sleep", "S", "hrtimer_nanosleep")
	ageProc(t, e, 7200, 10*time.Minute)
	// Right comm, wrong state — a running runc is healthy.
	e.MkStatProc(t, 7201, "runc", "R", "-")
	ageProc(t, e, 7201, 10*time.Minute)
	// Right comm+state, too young — a just-spawned runc gets grace.
	e.MkStatProc(t, 7202, "runc", "S", "do_wait")
	// No wchan file at all is fine (wchan "" is recorded).
	chk := hungCheck(e)
	chk.Run(context.Background(), cycleEnv())
	if len(e.Kills) != 0 {
		t.Fatalf("kills=%v want none — nothing qualified", e.Kills)
	}
}

// TestHungRuncKillDisabledDetectOnly pins the remediation gate:
// detection + streak still run, but no SIGKILL leaves the box.
func TestHungRuncKillDisabledDetectOnly(t *testing.T) {
	e := hungEnv(t, 1)
	e.H.Cfg.Wave2.HungRuncKillEnabled = false
	e.MkStatProc(t, 7300, "crun", "S", "futex_wait")
	ageProc(t, e, 7300, 10*time.Minute)
	chk := hungCheck(e)
	chk.Run(context.Background(), cycleEnv())
	if len(e.Kills) != 0 {
		t.Fatalf("kills=%v want none — kill gate off", e.Kills)
	}
}

// TestHungRuncKillCap pins the per-cycle blast-radius bound: five
// confirmed pids with a cap of 2 produce exactly two kills.
func TestHungRuncKillCap(t *testing.T) {
	e := hungEnv(t, 1)
	e.H.Cfg.Wave2.HungRuncMaxKillsPerCycle = 2
	for i, pid := range []int{7400, 7401, 7402, 7403, 7404} {
		e.MkStatProc(t, pid, "runc", "S", "do_wait")
		ageProc(t, e, pid, time.Duration(10+i)*time.Minute)
	}
	chk := hungCheck(e)
	chk.Run(context.Background(), cycleEnv())
	if len(e.Kills) != 2 {
		t.Fatalf("kills=%d want 2 (cap)", len(e.Kills))
	}
}

// writeFullStat plants a /proc/<pid>/stat carrying >=20 post-comm
// fields so Fields[19] (starttime) parses — MkStatProc's short form
// leaves the streak key on the -1 sentinel.
func writeFullStat(t *testing.T, e *env, pid int, comm, state string,
	starttime int64) {
	t.Helper()
	// state + 18 filler fields + starttime at index 19.
	fields := state
	for i := 0; i < 18; i++ {
		fields += " 0"
	}
	fields += " " + strconv.FormatInt(starttime, 10)
	wdepstest.WriteFile(t,
		filepath.Join(e.ProcDir, strconv.Itoa(pid), "stat"),
		strconv.Itoa(pid)+" ("+comm+") "+fields+"\n")
}

// TestHungRuncPidReuseResetsStreak is the PID-reuse regression: the
// same pid recycled onto a NEW runtime process (different
// starttime) must not inherit the dead one's confirmation streak —
// it re-earns the full confirm window before any SIGKILL.
func TestHungRuncPidReuseResetsStreak(t *testing.T) {
	e := hungEnv(t, 2)
	writeFullStat(t, e, 7500, "runc", "S", 111111)
	ageProc(t, e, 7500, 10*time.Minute)
	chk := hungCheck(e)
	ctx := context.Background()

	chk.Run(ctx, cycleEnv()) // old process: streak 1
	// PID reuse: same pid dir, NEW starttime — a different process.
	writeFullStat(t, e, 7500, "runc", "S", 222222)
	chk.Run(ctx, cycleEnv()) // new process: streak restarts at 1
	if len(e.Kills) != 0 {
		t.Fatalf("recycled pid killed on inherited streak: %v", e.Kills)
	}
	chk.Run(ctx, cycleEnv()) // new process: streak 2 → confirmed
	if len(e.Kills) != 1 || e.Kills[0].PID != 7500 {
		t.Fatalf("kills=%v want one SIGKILL on 7500", e.Kills)
	}
}

// TestHungRuncExcludesExecAndRunAndDState verifies Wave 1.5:
// - `runc exec` and `runc run` are never SIGKILLed
// - D-state runc processes are logged only (never SIGKILLed)
// - `runc:[2:INIT]` in S state IS SIGKILLed after confirm cycles.
func TestHungRuncExcludesExecAndRunAndDState(t *testing.T) {
	e := hungEnv(t, 1)
	// PID 7601: `runc exec` in S state
	e.MkStatProc(t, 7601, "runc", "S", "futex_wait")
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "7601", "cmdline"),
		"runc\x00--root\x00/run/runc\x00exec\x00-t\x00cid\x00sh\x00")
	ageProc(t, e, 7601, 10*time.Minute)

	// PID 7602: `runc run` in S state
	e.MkStatProc(t, 7602, "runc", "S", "do_wait")
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "7602", "cmdline"),
		"runc\x00run\x00cid\x00")
	ageProc(t, e, 7602, 10*time.Minute)

	// PID 7603: `runc` lifecycle create in D state (uninterruptible)
	e.MkStatProc(t, 7603, "runc", "D", "ext4_sync")
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "7603", "cmdline"),
		"runc\x00create\x00cid\x00")
	ageProc(t, e, 7603, 10*time.Minute)

	// PID 7604: `runc:[2:INIT]` in S state (ppid=1 by MkStatProc)
	e.MkStatProc(t, 7604, "runc:[2:INIT]", "S", "pipe_read")
	ageProc(t, e, 7604, 10*time.Minute)

	chk := hungCheck(e)
	chk.Run(context.Background(), cycleEnv())
	if len(e.Kills) != 1 || e.Kills[0].PID != 7604 {
		t.Fatalf("kills=%v want only PID 7604 (runc:[2:INIT] S)", e.Kills)
	}
	if !strings.Contains(e.LogLines(t), "uninterruptible D-state") {
		t.Fatalf("expected D-state log entry:\n%s", e.LogLines(t))
	}
}

// TestHungRuncDStateSkipsCmdlineAndRequiresShimParent verifies P0-5:
// D-state runc processes never open /proc/<pid>/cmdline (avoiding
// mm->mmap_lock deadlock), qualify via containerd-shim ancestry, and
// ignore D-state runc under non-shim parents.
func TestHungRuncDStateSkipsCmdlineAndRequiresShimParent(t *testing.T) {
	e := hungEnv(t, 1)
	// Parent 7700: containerd-shim-runc-v2.
	e.MkStatProc(t, 7700, "containerd-shim", "S", "")
	// Child 7701: D-state runc under shim 7700 with unreadable (chmod 000) cmdline.
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "7701", "stat"),
		"7701 (runc) D 7700 0 0\n")
	cmdPath := filepath.Join(e.ProcDir, "7701", "cmdline")
	wdepstest.WriteFile(t, cmdPath, "runc\x00exec\x00cid\x00")
	if err := os.Chmod(cmdPath, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(cmdPath, 0o644) })
	ageProc(t, e, 7701, 10*time.Minute)

	// Child 7702: D-state runc under shim 7700 with missing cmdline.
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "7702", "stat"),
		"7702 (runc) D 7700 0 0\n")
	ageProc(t, e, 7702, 10*time.Minute)

	// Parent 7710: non-shim bash; Child 7711: D-state runc under bash -> ignored.
	e.MkStatProc(t, 7710, "bash", "S", "")
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "7711", "stat"),
		"7711 (runc) D 7710 0 0\n")
	ageProc(t, e, 7711, 10*time.Minute)

	chk := hungCheck(e)
	chk.Run(context.Background(), cycleEnv())
	if len(e.Kills) != 0 {
		t.Fatalf("kills=%v want none for D-state processes", e.Kills)
	}
	logs := e.LogLines(t)
	if !strings.Contains(logs, "pid=7701") || !strings.Contains(logs, "pid=7702") {
		t.Fatalf("expected D-state logs for 7701 and 7702:\n%s", logs)
	}
	if strings.Contains(logs, "pid=7711") {
		t.Fatalf("D-state runc under non-shim parent 7710 should be ignored:\n%s", logs)
	}
}

func TestHungRuncMidCycleTransitionToDAbortsKill(t *testing.T) {
	e := hungEnv(t, 1)
	writeFullStat(t, e, 7801, "runc", "S", 11111)
	ageProc(t, e, 7801, 10*time.Minute)
	e.H.Cfg.Coord = &nodecoord.Coord{
		Now: func() time.Time { return e.Now },
		GetAnnos: func(context.Context) (map[string]string, error) {
			// Simulate mid-cycle S -> D transition during HoldEmergencyHeal.
			writeFullStat(t, e, 7801, "runc", "D", 11111)
			return map[string]string{}, nil
		},
	}

	hungCheck(e).Run(context.Background(), cycleEnv())
	if len(e.Kills) != 0 {
		t.Fatalf("SIGKILLed PID 7801 after mid-cycle S->D transition: %v", e.Kills)
	}
	if !strings.Contains(e.LogLines(t), "uninterruptible D-state") {
		t.Fatalf("expected uninterruptible D-state log after S->D transition:\n%s", e.LogLines(t))
	}
}

func TestHungRuncMidCyclePIDReuseAbortsKill(t *testing.T) {
	e := hungEnv(t, 1)
	writeFullStat(t, e, 7802, "runc", "S", 11111)
	ageProc(t, e, 7802, 10*time.Minute)
	e.H.Cfg.Coord = &nodecoord.Coord{
		Now: func() time.Time { return e.Now },
		GetAnnos: func(context.Context) (map[string]string, error) {
			// Simulate mid-cycle PID reuse (starttime changed) during HoldEmergencyHeal.
			writeFullStat(t, e, 7802, "runc", "S", 99999)
			return map[string]string{}, nil
		},
	}

	hungCheck(e).Run(context.Background(), cycleEnv())
	if len(e.Kills) != 0 {
		t.Fatalf("SIGKILLed PID 7802 after mid-cycle PID reuse: %v", e.Kills)
	}
}

func TestHungRuncPidsOKFalseAndProcErrorPreserveStreak(t *testing.T) {
	e := hungEnv(t, 2)
	e.MkStatProc(t, 7810, "runc", "S", "do_wait")
	ageProc(t, e, 7810, 10*time.Minute)
	chk := hungCheck(e)
	ctx := context.Background()

	// Cycle 1: builds confirmation streak = 1.
	chk.Run(ctx, &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        true,
		PidsOnce:     func() []int { return []int{7810} },
		PidsOK:       func() bool { return true },
	})
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckHungRunc, "ok")); got != 1 {
		t.Fatalf("ok cycles=%v want 1", got)
	}
	if len(e.Kills) != 0 {
		t.Fatalf("cycle 1 kills=%v want 0", e.Kills)
	}

	// PidsOnce() == nil + PidsOK() == false must abort "inconclusive" and preserve streak.
	chk.Run(ctx, &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        true,
		PidsOnce:     func() []int { return nil },
		PidsOK:       func() bool { return false },
	})
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckHungRunc, "inconclusive")); got != 1 {
		t.Fatalf("inconclusive cycles=%v want 1", got)
	}

	// PidsOnce == nil + Proc.PIDs() error must also abort "inconclusive" and preserve streak.
	e.H.Deps.Proc = procfs.New(filepath.Join(t.TempDir(), "missing-proc"))
	chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true, APIOK: true})
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckHungRunc, "inconclusive")); got != 2 {
		t.Fatalf("inconclusive cycles=%v want 2", got)
	}
	if len(e.Kills) != 0 {
		t.Fatalf("kills during inconclusive cycles=%v want 0", e.Kills)
	}

	// Recovery cycle: streak=1 was preserved, so this second valid cycle immediately confirms & kills.
	e.H.Deps.Proc = procfs.New(e.ProcDir)
	chk.Run(ctx, &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        true,
		PidsOnce:     func() []int { return []int{7810} },
		PidsOK:       func() bool { return true },
	})
	if len(e.Kills) != 1 || e.Kills[0].PID != 7810 {
		t.Fatalf("kills=%v want SIGKILL on 7810 on preserved streak=2", e.Kills)
	}
}
