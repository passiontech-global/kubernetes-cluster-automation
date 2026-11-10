// feeder_test.go — watchdog feeder loop, the G1..G6 remediate gates, and systemd-timestamp parsing.

package feeder_test

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/feeder"

	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// --- Guard d: feeder + remediate ---

// runFeederSteps drives the feeder for n probe iterations. The real
// loop waits on a hoisted Timer reset at end-of-work — tests step it
// through runFeederOnce-style control: we expose the body via a
// context cancelled after n feeds.
func TestFeederGraceThenFail(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Feeder.Enabled = true
	e.H.Cfg.Feeder.Interval = time.Millisecond
	e.Props["k0scontroller.service:MainPID"] = "4242"
	e.Active["k0scontroller.service"] = "active"
	// G3 passes: unit started long ago.
	e.SetUnitStart("k0scontroller.service", time.Hour)
	e.Alive[e.H.Cfg.Feeder.ProbeURL] = false

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { e.H.Feeder().Run(ctx); close(done) }()
	// Grace period: probe fails but feeder keeps feeding
	// (ever_ok=0). Wait for >=1 notification then inspect.
	deadline := time.After(5 * time.Second)
	for e.NotifN() == 0 {
		select {
		case <-deadline:
			t.Fatal("feeder never fed during startup grace")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if e.NotifN() == 0 || e.NotifAt(0) != "WATCHDOG=1" {
		t.Fatalf("unexpected notify payload: %d", e.NotifN())
	}
	// Let the grace fails run out (8) → remediate triggers: probe
	// still dead → G1 fails → G2 active → G3 passes → G5 fresh
	// budget → G6 restart.
	deadline = time.After(5 * time.Second)
	for e.RstN() == 0 && !strings.Contains(e.LogLines(), "remediate:") {
		select {
		case <-deadline:
			t.Fatal("remediate never ran")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	<-done
}

func remediateLogged(e *env) bool {
	b, _ := os.ReadFile(filepath.Join(filepath.Dir(e.State), "watchdog.log"))
	return strings.Contains(string(b), "remediate:")
}

func TestFeederFailPathRestarts(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Feeder.Enabled = true
	e.H.Cfg.Feeder.Interval = time.Millisecond
	e.Props["k0scontroller.service:MainPID"] = "4242"
	e.Active["k0scontroller.service"] = "active"
	e.SetUnitStart("k0scontroller.service", time.Hour)
	e.Alive[e.H.Cfg.Feeder.ProbeURL] = false

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.H.Feeder().Run(ctx); close(done) }()
	deadline := time.After(5 * time.Second)
	for e.RstN() == 0 {
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatal("remediate did not restart after grace fails")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
	if e.RstAt(0) != "k0scontroller.service" {
		t.Fatalf("wrong unit restarted: %v", e.RstAt(0))
	}
}

func TestFeederFeedsWhileAlive(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Feeder.Enabled = true
	e.H.Cfg.Feeder.Interval = time.Millisecond
	e.Props["k0scontroller.service:MainPID"] = "4242"
	e.Active["k0scontroller.service"] = "active"
	e.Alive[e.H.Cfg.Feeder.ProbeURL] = true

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.H.Feeder().Run(ctx); close(done) }()
	deadline := time.After(5 * time.Second)
	for e.NotifN() < 3 {
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatalf("feeder starved: %d", e.NotifN())
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
	if e.RstN() != 0 {
		t.Fatal("restart triggered while apiserver alive")
	}
}

func TestRemediateG1PassNoRestart(t *testing.T) {
	e := fixture(t)
	e.Active["k0scontroller.service"] = "active"
	e.Alive[e.H.Cfg.Feeder.ProbeURL] = true // re-probe says alive
	e.H.Feeder().RunRemediate(context.Background())
	if e.RstN() != 0 {
		t.Fatal("G1 false-alarm still restarted")
	}
}

func TestRemediateG5RateLimited(t *testing.T) {
	e := fixture(t)
	e.Active["k0scontroller.service"] = "active"
	e.SetUnitStart("k0scontroller.service", time.Hour)
	e.Alive[e.H.Cfg.Feeder.ProbeURL] = false
	// Fresh budget: last restart just now.
	h := e.H
	h.State.WriteEpochFile(filepath.Join(e.FState, cdeps.FileFeederLastRst),
		h.Cfg.Clock.Now().Unix())
	e.H.Feeder().RunRemediate(context.Background())
	if e.RstN() != 0 {
		t.Fatal("G5 rate-limit bypassed")
	}
}

func TestPeerAPIServerCRLF(t *testing.T) {
	e := fixture(t)
	// A CRLF peer file must not leave '\r' glued to the URL — the
	// peer probe against the garbage URL always read dead.
	testutil.WriteFile(t, e.H.Cfg.Feeder.RemediatePeerFile,
		"PEER_APISERVER=\"https://10.0.0.2:6443\"\r\n")
	if got := e.H.Feeder().PeerAPIServer(); got != "https://10.0.0.2:6443" {
		t.Fatalf("peerAPIServer=%q want https://10.0.0.2:6443", got)
	}
}

func TestParseSystemdTimestampZones(t *testing.T) {
	// A Local-known abbrev resolves exactly — the normal same-host
	// case: the zone systemd stamped IS the agent's zone (whatever
	// the test host's TZ is).
	want := time.Date(2026, 1, 5, 10, 0, 0, 0, time.Local)
	got, err := feeder.ParseSystemdTimestamp(want.Format(feeder.SystemdTimestampLayout))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(want) {
		t.Fatalf("local-abbrev parse=%v want %v", got, want)
	}

	// A foreign abbrev must NOT leak Go's fabricated zero-offset
	// zone: "XXX" is no Local zone and no IANA zone either, so the
	// UTC fallback applies — the wall fields read as UTC under an
	// honest UTC location (the documented bounded residual error).
	got, err = feeder.ParseSystemdTimestamp("Mon 2026-01-05 10:00:00 XXX")
	if err != nil {
		t.Fatal(err)
	}
	if got.Location() != time.UTC {
		t.Fatalf("fabricated zone leaked: location=%v want UTC", got.Location())
	}
	if !got.Equal(time.Date(2026, 1, 5, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("UTC fallback instant=%v want 10:00Z", got)
	}

	// A foreign-but-real zone name recovers the offset fabrication
	// would drop: "CET" exists in the tz database, so 10:00 CET
	// parses as 09:00Z even on a TZ=UTC agent.
	if _, err := time.LoadLocation("CET"); err != nil {
		t.Skip("no tzdata — IANA-name fallback untestable")
	}
	got, err = feeder.ParseSystemdTimestamp("Mon 2026-01-05 10:00:00 CET")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(time.Date(2026, 1, 5, 9, 0, 0, 0, time.UTC)) {
		t.Fatalf("CET parse=%v want 09:00Z", got)
	}
}

func TestRemediateMarksBudgetBeforeRestart(t *testing.T) {
	e := fixture(t)
	e.Active["k0scontroller.service"] = "active"
	e.SetUnitStart("k0scontroller.service", time.Hour)
	e.Alive[e.H.Cfg.Feeder.ProbeURL] = false
	// The restart exec asserts the G5 budget file ALREADY exists when
	// the restart runs — a mid-restart kill must not leave it unspent.
	// HostExecFn is the one exec seam now: intercept the restart argv,
	// delegate everything else to the fixture dispatch.
	e.H.Cfg.HostExecFn = func(ctx context.Context, combined bool,
		budget time.Duration, name string, args ...string) (string, error) {
		if name == "systemctl" && len(args) >= 2 && args[0] == "restart" {
			if _, err := os.Stat(filepath.Join(e.FState, cdeps.FileFeederLastRst)); err != nil {
				t.Errorf("G5 budget not marked before restart: %v", err)
			}
			e.Mu.Lock()
			defer e.Mu.Unlock()
			e.Rst = append(e.Rst, args[1])
			return "", nil
		}
		return e.HostExec(ctx, combined, budget, name, args...)
	}
	e.H.Feeder().RunRemediate(context.Background())
	if e.RstN() != 1 {
		t.Fatal("restart did not run")
	}
}

func TestRemediateCreatesFeederStateDir(t *testing.T) {
	e := fixture(t)
	e.Active["k0scontroller.service"] = "active"
	e.SetUnitStart("k0scontroller.service", time.Hour)
	e.Alive[e.H.Cfg.Feeder.ProbeURL] = false
	if err := os.RemoveAll(e.FState); err != nil {
		t.Fatal(err)
	}
	e.H.Feeder().RunRemediate(context.Background())
	if e.RstN() != 1 {
		t.Fatal("restart blocked by absent FeederStateDir")
	}
	if _, err := os.Stat(filepath.Join(e.FState, cdeps.FileFeederLastRst)); err != nil {
		t.Fatal("budget file not written into created dir")
	}
}

// --- Uncovered-path guards: Run loop branches ---

func TestFeederRunReturnsWhenMainPIDNeverAppears(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Feeder.Enabled = true
	e.H.Cfg.Feeder.Interval = time.Millisecond
	// No Props["k0scontroller.service:MainPID"] — every systemctl
	// show errors, so waitMainPID keeps polling (unitProp error
	// parity: a transient systemctl failure is never a MainPID).

	// A pre-cancelled context returns without a single notify — the
	// shell's exit-0 retry loop folded into the ctx check.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.H.Feeder().Run(ctx)
	if e.NotifN() != 0 || e.RstN() != 0 {
		t.Fatalf("acted with no MainPID: notif=%d rst=%d", e.NotifN(), e.RstN())
	}

	// A live context polls until cancellation: the interval timer
	// re-arms between polls and ctx.Done cuts the wait short.
	ctx2, cancel2 := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.H.Feeder().Run(ctx2); close(done) }()
	time.Sleep(20 * time.Millisecond)
	cancel2()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel while MainPID unreadable")
	}
	if e.NotifN() != 0 {
		t.Fatalf("fed while MainPID unreadable: %d", e.NotifN())
	}
}

func TestFeederMainPIDDriftReArmsGrace(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Feeder.Enabled = true
	e.H.Cfg.Feeder.Interval = time.Millisecond
	e.Active["k0scontroller.service"] = "active"
	e.Alive[e.H.Cfg.Feeder.ProbeURL] = true

	// The tracked MainPID flips mid-run — the instance we watched
	// ended (PartOf restart parity). The show answers come from a
	// counting stub so the flip needs no map write racing the loop.
	var shows atomic.Int64
	e.H.Cfg.HostExecFn = func(ctx context.Context, combined bool,
		budget time.Duration, name string, args ...string) (string, error) {
		if name == "systemctl" && len(args) >= 4 && args[0] == "show" && args[3] == "MainPID" {
			pid := "4242"
			if shows.Add(1) > 5 {
				pid = "5555"
			}
			return pid, nil
		}
		return e.HostExec(ctx, combined, budget, name, args...)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { e.H.Feeder().Run(ctx); close(done) }()
	deadline := time.After(5 * time.Second)
	for e.CountLogLines("instance ended") == 0 {
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatal("MainPID drift never logged")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
	if e.RstN() != 0 {
		t.Fatal("instance change triggered a restart")
	}
	// Re-armed grace: feeding continues on the new instance.
	if e.NotifN() == 0 {
		t.Fatal("feeding stopped after instance re-arm")
	}
}

func TestFeederNotifyFailRunsRemediate(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Feeder.Enabled = true
	e.H.Cfg.Feeder.Interval = time.Millisecond
	e.Props["k0scontroller.service:MainPID"] = "4242"
	e.Active["k0scontroller.service"] = "active"
	e.Alive[e.H.Cfg.Feeder.ProbeURL] = true
	// sd_notify fails every time — loud death: the failure path runs
	// inline instead of masking the watchdog timeout.
	e.H.Cfg.NotifyFn = func(string) error { return errors.New("notify socket gone") }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { e.H.Feeder().Run(ctx); close(done) }()
	deadline := time.After(5 * time.Second)
	for e.CountLogLines("sd_notify FAIL") == 0 {
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatal("notify failure never logged")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
	if e.RstN() != 0 {
		t.Fatal("restart ran although the apiserver answers (G1 false alarm)")
	}
	if e.CountLogLines("remediate:") == 0 {
		t.Fatal("remediation gates did not run on notify failure")
	}
}

// --- Uncovered-path guards: remediate gates ---

func TestRemediateG2UnitNotActive(t *testing.T) {
	e := fixture(t)
	e.Active["k0scontroller.service"] = "inactive"
	e.Alive[e.H.Cfg.Feeder.ProbeURL] = false
	e.H.Feeder().RunRemediate(context.Background())
	if e.RstN() != 0 {
		t.Fatal("restarted although the unit is already being restarted")
	}
	if e.CountLogLines("G2 PASS") == 0 {
		t.Fatal("G2 gate did not stop the restart")
	}
}

func TestRemediateG3UnreadableTimestamp(t *testing.T) {
	e := fixture(t)
	e.Active["k0scontroller.service"] = "active"
	e.Props["k0scontroller.service:ActiveEnterTimestamp"] = "n/a"
	e.Alive[e.H.Cfg.Feeder.ProbeURL] = false
	e.H.Feeder().RunRemediate(context.Background())
	if e.RstN() != 0 {
		t.Fatal("restarted blind on an unreadable ActiveEnterTimestamp")
	}
	if e.CountLogLines("G3 PASS: unreadable") == 0 {
		t.Fatal("unreadable timestamp did not stop the restart")
	}
}

func TestRemediateG3FreshStartGrace(t *testing.T) {
	e := fixture(t)
	e.Active["k0scontroller.service"] = "active"
	// 10s old, well inside the 90s WDREM_FRESH_GRACE_S grace.
	e.SetUnitStart("k0scontroller.service", 10*time.Second)
	e.Alive[e.H.Cfg.Feeder.ProbeURL] = false
	e.H.Feeder().RunRemediate(context.Background())
	if e.RstN() != 0 {
		t.Fatal("restarted during the fresh-start grace")
	}
	if e.CountLogLines("started 10s ago") == 0 {
		t.Fatal("fresh-start grace did not stop the restart")
	}
}

func TestRemediateG4PeerAliveRestarts(t *testing.T) {
	e := fixture(t)
	peer := "https://10.0.0.2:6443"
	testutil.WriteFile(t, e.H.Cfg.Feeder.RemediatePeerFile,
		"PEER_APISERVER=\""+peer+"\"\n")
	e.Active["k0scontroller.service"] = "active"
	e.SetUnitStart("k0scontroller.service", time.Hour)
	e.Alive[e.H.Cfg.Feeder.ProbeURL] = false
	e.Alive[peer] = true
	e.H.Feeder().RunRemediate(context.Background())
	if e.RstN() != 1 {
		t.Fatal("peer fence blocked the restart (G4 is WARN-only)")
	}
	if e.CountLogLines("G4: peer") == 0 {
		t.Fatal("peer-alive fence not logged")
	}
}

func TestRemediateG4PeerDeadWarnsAndRestarts(t *testing.T) {
	e := fixture(t)
	peer := "https://10.0.0.2:6443"
	testutil.WriteFile(t, e.H.Cfg.Feeder.RemediatePeerFile,
		"PEER_APISERVER=\""+peer+"\"\n")
	e.Active["k0scontroller.service"] = "active"
	e.SetUnitStart("k0scontroller.service", time.Hour)
	// Both apiservers dead — warn, then restart the local one anyway
	// (a dead local apiserver is not made worse by restarting it).
	e.Alive[e.H.Cfg.Feeder.ProbeURL] = false
	e.Alive[peer] = false
	e.H.Feeder().RunRemediate(context.Background())
	if e.RstN() != 1 {
		t.Fatal("dead peer blocked the restart")
	}
	if e.CountLogLines("G4 WARNING") == 0 {
		t.Fatal("dead-peer warning not logged")
	}
}

func TestRemediateG6MkdirFailSkipsRestart(t *testing.T) {
	e := fixture(t)
	e.Active["k0scontroller.service"] = "active"
	e.SetUnitStart("k0scontroller.service", time.Hour)
	e.Alive[e.H.Cfg.Feeder.ProbeURL] = false
	// StateDir occupied by a regular file — the mkdir -p parity fails
	// (ENOTDIR regardless of uid) and the restart must not run blind.
	if err := os.RemoveAll(e.FState); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, e.FState, "not a dir")
	e.H.Feeder().RunRemediate(context.Background())
	if e.RstN() != 0 {
		t.Fatal("restarted although the budget dir is unwritable")
	}
	if e.CountLogLines("restart skipped") == 0 {
		t.Fatal("mkdir failure not logged")
	}
}

func TestRemediateG6RestartFailSpendsBudget(t *testing.T) {
	e := fixture(t)
	e.Active["k0scontroller.service"] = "active"
	e.SetUnitStart("k0scontroller.service", time.Hour)
	e.Alive[e.H.Cfg.Feeder.ProbeURL] = false
	// The restart exec fails after the gates — the budget was spent
	// BEFORE the restart call (shell stamp-on-success parity fix), so
	// a second remediate inside the window stays rate-limited.
	e.H.Cfg.HostExecFn = func(ctx context.Context, combined bool,
		budget time.Duration, name string, args ...string) (string, error) {
		if name == "systemctl" && len(args) >= 2 && args[0] == "restart" {
			return "", errors.New("systemctl: restart job failed")
		}
		return e.HostExec(ctx, combined, budget, name, args...)
	}
	e.H.Feeder().RunRemediate(context.Background())
	if e.RstN() != 0 {
		t.Fatal("restart recorded although systemctl failed")
	}
	if _, err := os.Stat(filepath.Join(e.FState, cdeps.FileFeederLastRst)); err != nil {
		t.Fatalf("budget not spent before the failing restart: %v", err)
	}
	if e.CountLogLines("budget spent") == 0 {
		t.Fatal("restart failure not logged")
	}
}

func TestPeerAPIServerNoMatch(t *testing.T) {
	e := fixture(t)
	// A peer file without the PEER_APISERVER line reads as no peer —
	// the G4 fence is skipped, not probed against a garbage URL.
	testutil.WriteFile(t, e.H.Cfg.Feeder.RemediatePeerFile,
		"OTHER=1\nPEER_IGNORED=2\n")
	if got := e.H.Feeder().PeerAPIServer(); got != "" {
		t.Fatalf("peerAPIServer=%q want empty (no PEER_APISERVER line)", got)
	}
}

// --- Uncovered-path guards: systemd timestamp parsing ---

func TestParseSystemdTimestampErrors(t *testing.T) {
	for _, v := range []string{
		"",    // missing property
		"   ", // whitespace-only
		"n/a", // systemd's never-active value
		"garbage",
		"Mon 2026-01-05 10:00", // layout demands seconds + zone
	} {
		if _, err := feeder.ParseSystemdTimestamp(v); err == nil {
			t.Fatalf("ParseSystemdTimestamp(%q) accepted a non-timestamp", v)
		}
	}
}

func TestParseSystemdTimestampLocalAbbrevExact(t *testing.T) {
	// Swap Local for a named zone so the "abbrev defined in Local"
	// exact path is deterministic on any host: on a TZ=UTC agent the
	// literal "UTC" abbrev short-circuits into the UTC location and
	// never exercises the Local one.
	old := time.Local
	time.Local = time.FixedZone("CET", 3600)
	defer func() { time.Local = old }()

	got, err := feeder.ParseSystemdTimestamp("Mon 2026-01-05 10:00:00 CET")
	if err != nil {
		t.Fatal(err)
	}
	if got.Location() != time.Local {
		t.Fatalf("local-abbrev parse drifted out of Local: %v", got.Location())
	}
	if !got.Equal(time.Date(2026, 1, 5, 9, 0, 0, 0, time.UTC)) {
		t.Fatalf("local-abbrev instant=%v want 09:00Z", got)
	}
}
