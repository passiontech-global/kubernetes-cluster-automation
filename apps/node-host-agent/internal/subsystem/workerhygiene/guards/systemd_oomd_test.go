// systemd_oomd_test.go — external tests for Wave-4 #9 systemd-oomd guard.
package guards_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func journalJSONLine(ts time.Time, cursor, unit, msg string) string {
	return fmt.Sprintf(
		`{"__REALTIME_TIMESTAMP":"%d","__CURSOR":%q,"_SYSTEMD_UNIT":%q,"MESSAGE":%q}`+"\n",
		ts.UnixMicro(), cursor, unit, msg,
	)
}

func runSystemdOOMD(e *env, ctx context.Context) {
	e.H.Check(wdeps.CheckSystemdOOMD).Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
}

func cycleCount(e *env, result string) float64 {
	return testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckSystemdOOMD, result))
}

func TestSystemdOOMDInactiveOrMissingSkipsAndClearsLatch(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()

	// Pre-arm latch to verify inactive systemd-oomd clears stale latch.
	e.H.State.Enter(latchdefs.LatchSystemdOOMDKill, "stale")
	journalCalled := false
	e.JournalExec = func(context.Context, ...string) (string, error) {
		journalCalled = true
		return "", nil
	}

	runSystemdOOMD(e, ctx)

	if journalCalled {
		t.Fatal("expected JournalExecFn not to be called when systemd-oomd.service is inactive")
	}
	if e.H.State.Exists(latchdefs.LatchSystemdOOMDKill) {
		t.Fatal("expected inactive systemd-oomd.service to clear pre-existing LatchSystemdOOMDKill")
	}
	if got := cycleCount(e, "gated"); got != 1 {
		t.Fatalf("gated cycles = %v, want 1", got)
	}
	if !strings.Contains(e.LogLines(t), "STATE-EXIT: systemd-oomd-kill") {
		t.Fatalf("expected STATE-EXIT in log:\n%s", e.LogLines(t))
	}
}

func TestSystemdOOMDNilSystemdAndCanceledCtx(t *testing.T) {
	e := fixture(t)
	e.H.State.Enter(latchdefs.LatchSystemdOOMDKill, "held")

	e.H.Cfg.Systemd = nil
	runSystemdOOMD(e, context.Background())
	if got := cycleCount(e, "gated"); got != 1 {
		t.Fatalf("nil systemd gated cycles = %v, want 1", got)
	}
	if !e.H.State.Exists(latchdefs.LatchSystemdOOMDKill) {
		t.Fatal("nil systemd must gate without clearing existing latch")
	}

	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	runSystemdOOMD(e, cctx)
	if got := cycleCount(e, "abort"); got != 1 {
		t.Fatalf("canceled ctx abort cycles = %v, want 1", got)
	}
	if !e.H.State.Exists(latchdefs.LatchSystemdOOMDKill) {
		t.Fatal("canceled ctx must preserve existing latch")
	}
}

func TestSystemdOOMDErrorsAbortAndPreserveState(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()

	e.H.State.Enter(latchdefs.LatchSystemdOOMDKill, "held")
	e.H.SystemdOOMDKills = 3

	// Active check failure (no reply for systemd-oomd.service).
	delete(e.SDReply, "systemctl is-active systemd-oomd.service")
	runSystemdOOMD(e, ctx)
	if got := cycleCount(e, "abort"); got != 1 {
		t.Fatalf("active error abort cycles = %v, want 1", got)
	}
	if !e.H.State.Exists(latchdefs.LatchSystemdOOMDKill) || e.H.SystemdOOMDKills != 3 {
		t.Fatal("active check error must preserve latch and counter")
	}

	// Active succeeds, journalctl fails.
	e.SDReply["systemctl is-active systemd-oomd.service"] = "active\n"
	e.JournalExec = func(context.Context, ...string) (string, error) {
		return "", errors.New("journalctl boom")
	}
	runSystemdOOMD(e, ctx)
	if got := cycleCount(e, "abort"); got != 2 {
		t.Fatalf("journal error abort cycles = %v, want 2", got)
	}
	if !e.H.State.Exists(latchdefs.LatchSystemdOOMDKill) || e.H.SystemdOOMDKills != 3 {
		t.Fatal("journal poll error must preserve latch and counter")
	}
}

func TestSystemdOOMDIgnoresNonKubeKillsAndNonKillLines(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	e.SDReply["systemctl is-active systemd-oomd.service"] = "active\n"

	now := e.Now
	e.JournalExec = func(context.Context, ...string) (string, error) {
		return journalJSONLine(now.Add(-time.Minute), "c1", "systemd-oomd.service",
			"Killed /user.slice/user-1000.slice/session-2.scope due to memory pressure for /user.slice used 512M") +
			journalJSONLine(now.Add(-30*time.Second), "c2", "systemd-oomd.service",
				"Considering /kubepods.slice/kubepods-besteffort.slice, memory pressure normal"), nil
	}

	runSystemdOOMD(e, ctx)

	if e.H.State.Exists(latchdefs.LatchSystemdOOMDKill) {
		t.Fatal("expected non-kube kill and non-kill lines not to arm LatchSystemdOOMDKill")
	}
	if e.H.SystemdOOMDKills != 0 {
		t.Fatalf("SystemdOOMDKills = %d, want 0", e.H.SystemdOOMDKills)
	}
	if got := cycleCount(e, "ok"); got != 1 {
		t.Fatalf("ok cycles = %v, want 1", got)
	}
}

func TestSystemdOOMDDetectsKubeAndK0sKillsDetectOnlyAndPromMetric(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	e.SDReply["systemctl is-active systemd-oomd.service"] = "active\n"
	textDir := t.TempDir()
	e.H.Cfg.TextfileDir = textDir

	var gotArgs []string
	e.JournalExec = func(_ context.Context, args ...string) (string, error) {
		gotArgs = append([]string(nil), args...)
		return journalJSONLine(e.Now.Add(-2*time.Minute), "cur-1", "systemd-oomd.service",
			"Killed /kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod123.slice/cri-containerd-abc.scope due to memory pressure for /kubepods.slice used 2.0G") +
			journalJSONLine(e.Now.Add(-1*time.Minute), "cur-2", "systemd-oomd.service",
				"Killed /system.slice/k0sworker.service due to swap usage"), nil
	}

	runSystemdOOMD(e, ctx)
	e.H.WriteNodeAgentPromTextfile()

	if !slices.Contains(gotArgs, "_SYSTEMD_UNIT=systemd-oomd.service") {
		t.Fatalf("expected _SYSTEMD_UNIT=systemd-oomd.service in journalctl args: %v", gotArgs)
	}
	if !e.H.State.Exists(latchdefs.LatchSystemdOOMDKill) {
		t.Fatal("expected LatchSystemdOOMDKill to be armed")
	}
	if e.H.SystemdOOMDKills != 2 {
		t.Fatalf("SystemdOOMDKills = %d, want 2", e.H.SystemdOOMDKills)
	}
	if !strings.Contains(e.LogLines(t), "STATE-ENTER: systemd-oomd-kill") {
		t.Fatalf("expected STATE-ENTER: systemd-oomd-kill in log:\n%s", e.LogLines(t))
	}
	if e.SDRan("restart") {
		t.Fatalf("detect-only guard must never restart units, got SDCmds=%v", e.SDCmds)
	}
	events, err := e.CS.EventsV1().Events("").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events.Items) != 0 {
		t.Fatalf("expected zero direct EventsV1 emits (nodereporter events_rules owns STATE-ENTER), got %d", len(events.Items))
	}
	promBytes, err := os.ReadFile(filepath.Join(textDir, "node-agent-hygiene.prom"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(promBytes), "node_agent_systemd_oomd_kills_total 2") {
		t.Fatalf("expected node_agent_systemd_oomd_kills_total 2 in prom output:\n%s", string(promBytes))
	}
}

func TestSystemdOOMDDeduplicationAndWindowExpiry(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	e.SDReply["systemctl is-active systemd-oomd.service"] = "active\n"

	killAt := e.Now.Add(-5 * time.Minute)
	staleAt := e.Now.Add(-31 * time.Minute)

	// Poll 1: 1 stale (>30m) + 1 fresh cursor + 1 cursor-less entry at same TSUS.
	// Poll 2: stub replays identical entries -> must NOT double-count!
	//         plus a 2nd cursor at the exact same microsecond -> MUST count!
	poll := 0
	e.JournalExec = func(context.Context, ...string) (string, error) {
		poll++
		switch poll {
		case 1:
			return journalJSONLine(staleAt, "cur-stale", "systemd-oomd.service",
				"Killed /kubepods.slice/old.slice due to memory pressure") +
				journalJSONLine(killAt, "cur-a", "systemd-oomd.service",
					"Killed /kubepods.slice/pod-a.slice due to memory pressure") +
				journalJSONLine(killAt, "", "systemd-oomd.service",
					"Killed /kubepods.slice/cri-containerd-nocursor.scope due to memory pressure"), nil
		case 2:
			return journalJSONLine(killAt, "cur-a", "systemd-oomd.service",
				"Killed /kubepods.slice/pod-a.slice due to memory pressure") +
				journalJSONLine(killAt, "", "systemd-oomd.service",
					"Killed /kubepods.slice/cri-containerd-nocursor.scope due to memory pressure") +
				journalJSONLine(killAt, "cur-b", "systemd-oomd.service",
					"Killed /kubepods.slice/pod-b.slice due to memory pressure"), nil
		default:
			return "", nil
		}
	}

	runSystemdOOMD(e, ctx)
	if e.H.SystemdOOMDKills != 2 {
		t.Fatalf("poll 1 SystemdOOMDKills = %d, want 2 (stale ignored)", e.H.SystemdOOMDKills)
	}
	if !e.H.State.Exists(latchdefs.LatchSystemdOOMDKill) {
		t.Fatal("expected LatchSystemdOOMDKill after poll 1")
	}

	runSystemdOOMD(e, ctx)
	if e.H.SystemdOOMDKills != 3 {
		t.Fatalf("poll 2 SystemdOOMDKills = %d, want 3 (duplicates ignored, new cursor at same µs counted)", e.H.SystemdOOMDKills)
	}
	if count := strings.Count(e.LogLines(t), "STATE-ENTER: systemd-oomd-kill"); count != 1 {
		t.Fatalf("STATE-ENTER count = %d, want 1", count)
	}

	// Advance 20m -> killAt is 25m ago (still inside 30m window): stays latched.
	e.Now = e.Now.Add(20 * time.Minute)
	runSystemdOOMD(e, ctx)
	if !e.H.State.Exists(latchdefs.LatchSystemdOOMDKill) {
		t.Fatal("expected LatchSystemdOOMDKill to remain held at 25m")
	}

	// Advance another 6m -> killAt is 31m ago (past 30m window): exits cleanly.
	e.Now = e.Now.Add(6 * time.Minute)
	runSystemdOOMD(e, ctx)
	if e.H.State.Exists(latchdefs.LatchSystemdOOMDKill) {
		t.Fatal("expected LatchSystemdOOMDKill to clear past 30m window")
	}
	if !strings.Contains(e.LogLines(t), "STATE-EXIT: systemd-oomd-kill") {
		t.Fatalf("expected STATE-EXIT: systemd-oomd-kill after 30m expiry:\n%s", e.LogLines(t))
	}
}

func TestSystemdOOMDLateBindingAndWDSigGate(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	e.SDReply["systemctl is-active systemd-oomd.service"] = "active\n"

	// Re-stubbing JournalExecFn directly post-New works via late binding.
	e.H.Cfg.Seams.Host.JournalExecFn = func(context.Context, ...string) (string, error) {
		return journalJSONLine(e.Now.Add(-time.Minute), "late-1", "systemd-oomd.service",
			"Killed /kubepods.slice/pod-late.slice due to memory pressure"), nil
	}
	runSystemdOOMD(e, ctx)
	if !e.H.State.Exists(latchdefs.LatchSystemdOOMDKill) || e.H.SystemdOOMDKills != 1 {
		t.Fatalf("late-bound JournalExecFn failed: latch=%v kills=%d",
			e.H.State.Exists(latchdefs.LatchSystemdOOMDKill), e.H.SystemdOOMDKills)
	}

	// WD_SIG_SYSTEMD_OOMD=off in watchdog.conf disables via subframe kill switch.
	confPath := filepath.Join(t.TempDir(), "node-watchdog.conf")
	wdepstest.WriteFile(t, confPath, "WD_SIG_SYSTEMD_OOMD=off\n")
	e.H.Cfg.WatchdogSrc = watchdogconf.NewReloader(confPath, nil)
	e.H.Cfg.MountinfoFile = filepath.Join(t.TempDir(), "mountinfo")
	wdepstest.WriteFile(t, e.H.Cfg.MountinfoFile, "1 1 0:1 / / rw - ext4 /dev/vda1 rw\n")
	e.H.Cfg.Seams.Host.JournalExecFn = func(context.Context, ...string) (string, error) {
		return "", errors.New("must not run when WD_SIG_SYSTEMD_OOMD=off")
	}
	e.H.Cycle(ctx)
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckSystemdOOMD, "disabled")); got != 1 {
		t.Fatalf("disabled cycles = %v, want 1", got)
	}
}
