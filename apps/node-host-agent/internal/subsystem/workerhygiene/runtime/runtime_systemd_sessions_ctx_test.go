// runtime_systemd_sessions_ctx_test.go — regression coverage for the
// false-reboot guard: an expired cycle ctx must abort the PID 1 D-Bus
// probe (no LatchSystemdUnresponsive, no SIGCONT), and the session
// check must still run when k0sworker is inactive but its unit file
// exists (it gates on the unit file + WD_SIG, not on workerActive).
package runtime_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/runtime"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func sigContSent(e *env) bool {
	for _, k := range e.Kills {
		if k.PID == 1 && k.Sig == syscall.SIGCONT {
			return true
		}
	}
	return false
}

// plantStaleSessions puts n abandoned session files old enough to
// trip the bloat latch into the check's sessions dir.
func plantStaleSessions(t *testing.T, e *env, dir string, n int) {
	t.Helper()
	old := e.Now.Add(-3 * time.Hour)
	for i := 1; i <= n; i++ {
		p := filepath.Join(dir, strconv.Itoa(i))
		wdepstest.WriteFile(t, p, "STATE=abandoned\n")
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
}

// TestSystemdSessionExpiredCtxAborts pins the P0 guard: when earlier
// checks have already drained the shared CycleTimeout, the round
// aborts with cycles{check,"abort"} before touching D-Bus, PID 1 or
// the latches — a fast DeadlineExceeded is OUR deadline, not a frozen
// init, and must never drive NHC into rebooting a healthy node.
func TestSystemdSessionExpiredCtxAborts(t *testing.T) {
	e := fixture(t)
	h := e.H
	h.Cfg.Runtime.SessionsDir = t.TempDir()
	e.SDReply["kill -CONT 1"] = ""
	// Even a probe that WOULD look like a timeout must not run.
	e.SDHook = func(joined string) {
		if strings.Contains(joined, "is-system-running") {
			e.Now = e.Now.Add(11 * time.Second)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	wdepstest.Check[*runtime.SystemdSessionCheck](h, wdeps.CheckSystemdSessions).
		Run(ctx, &wdeps.CycleEnv{WorkerActive: true})

	if got := promtestutil.ToFloat64(h.Cycles.WithLabelValues(
		wdeps.CheckSystemdSessions, "abort")); got != 1 {
		t.Fatalf("abort=%v want 1", got)
	}
	if e.SDRan("is-system-running") {
		t.Fatal("D-Bus probe ran with an already-expired ctx")
	}
	for _, latch := range []string{
		"state-systemd-unresponsive", "state-systemd-session-bloat",
	} {
		if _, err := os.Stat(filepath.Join(e.StateDir, latch)); !os.IsNotExist(err) {
			t.Fatalf("%s set on an aborted round (err=%v)", latch, err)
		}
	}
	if sigContSent(e) {
		t.Fatal("SIGCONT sent to PID 1 on an aborted round")
	}
}

// TestSystemdSessionParentCancelDuringProbeNoLatch covers the race:
// the parent ctx is cancelled WHILE the D-Bus read is in flight. The
// elapsed time crosses the probe budget, so the old code counted a
// timeout and built the unresponsive latch; the cancellation is ours,
// so it must be ignored instead.
func TestSystemdSessionParentCancelDuringProbeNoLatch(t *testing.T) {
	e := fixture(t)
	h := e.H
	h.Cfg.Runtime.SessionsDir = t.TempDir()
	e.SDReply["kill -CONT 1"] = ""
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.SDHook = func(joined string) {
		if strings.Contains(joined, "is-system-running") {
			cancel() // the cycle, not PID 1, ran out of time
			e.Now = e.Now.Add(11 * time.Second)
		}
	}
	chk := wdepstest.Check[*runtime.SystemdSessionCheck](h, wdeps.CheckSystemdSessions)

	chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true}) // in-flight cancel
	for _, latch := range []string{
		"state-systemd-unresponsive", "state-systemd-session-bloat",
	} {
		if _, err := os.Stat(filepath.Join(e.StateDir, latch)); !os.IsNotExist(err) {
			t.Fatalf("%s set on a parent-cancelled probe (err=%v)", latch, err)
		}
	}
	// The in-flight cancellation must abort the round immediately —
	// before the unresponsive/session-bloat latch tails or any
	// loginctl/reset-failed on the dead ctx.
	if got := promtestutil.ToFloat64(h.Cycles.WithLabelValues(
		wdeps.CheckSystemdSessions, "abort")); got != 1 {
		t.Fatalf("abort=%v want 1 after in-flight cancel", got)
	}

	chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true}) // now expired → abort at top
	if _, err := os.Stat(filepath.Join(e.StateDir,
		"state-systemd-unresponsive")); !os.IsNotExist(err) {
		t.Fatal("unresponsive latch set after ctx expiry")
	}
	if sigContSent(e) {
		t.Fatal("SIGCONT sent to PID 1 for a cancelled cycle")
	}
	if got := promtestutil.ToFloat64(h.Cycles.WithLabelValues(
		wdeps.CheckSystemdSessions, "abort")); got != 2 {
		t.Fatalf("abort=%v want 2 after two cancelled rounds", got)
	}
}

// TestSystemdSessionRunsWhenWorkerInactive pins the gate contract at
// the subsystem level: with the k0sworker unit file present but the
// unit reporting "inactive", this check still probes PID 1 and can
// latch session bloat — the frozen-init detector must not vanish
// with a downed worker. The unit file itself remains a hard gate.
func TestSystemdSessionRunsWhenWorkerInactive(t *testing.T) {
	e := fixture(t)
	h := e.H
	dir := t.TempDir()
	h.Cfg.Runtime.SessionsDir = dir
	plantStaleSessions(t, e, dir, 25)
	e.SDReply["systemctl is-active k0sworker.service"] = "inactive\n"
	e.SDReply["loginctl terminate-session"] = ""
	e.SDReply["systemctl reset-failed"] = ""

	if _, err := os.Stat(e.UnitFile); err != nil {
		t.Fatalf("fixture unit file missing: %v", err)
	}
	e.H.Cycle(context.Background())

	if !e.SDRan("is-system-running") {
		t.Fatal("session probe skipped while unit is inactive")
	}
	if _, err := os.Stat(filepath.Join(e.StateDir,
		"state-systemd-session-bloat")); err != nil {
		t.Fatalf("session-bloat latch missing with unit inactive: %v", err)
	}
	if got := promtestutil.ToFloat64(h.Cycles.WithLabelValues(
		wdeps.CheckSystemdSessions, "gated")); got != 0 {
		t.Fatalf("gated=%v want 0 (workerActive must not gate this check)", got)
	}
	if got := promtestutil.ToFloat64(h.Cycles.WithLabelValues(
		wdeps.CheckSystemdSessions, "ok")); got != 1 {
		t.Fatalf("ok=%v want 1", got)
	}
}

// The remaining gate is the WD_SIG kill switch: with the unit file
// present and inactive, switching WD_SIG_SYSTEMD_SESSION_HYGIENE=off
// (the normalized "systemd-session-hygiene" key) must still skip it.
func TestSystemdSessionWDSigDisablesEvenWhenInactive(t *testing.T) {
	e := fixture(t)
	h := e.H
	dir := t.TempDir()
	h.Cfg.Runtime.SessionsDir = dir
	plantStaleSessions(t, e, dir, 25)
	e.SDReply["systemctl is-active k0sworker.service"] = "inactive\n"
	h.Cfg.Watchdog = &watchdogconf.Config{
		Disabled: map[string]bool{wdeps.CheckSystemdSessions: true},
	}

	e.H.Cycle(context.Background())

	if e.SDRan("is-system-running") {
		t.Fatal("session probe ran with its WD_SIG switched off")
	}
	if got := promtestutil.ToFloat64(h.Cycles.WithLabelValues(
		wdeps.CheckSystemdSessions, "disabled")); got != 1 {
		t.Fatalf("disabled=%v want 1", got)
	}
}
