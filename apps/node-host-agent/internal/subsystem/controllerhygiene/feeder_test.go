// feeder_test.go — watchdog feeder loop, the G1..G6 remediate gates, and systemd-timestamp parsing.

package controllerhygiene

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- Guard d: feeder + remediate ---

// runFeederSteps drives the feeder for n probe iterations. The real
// loop uses time.After — tests step it through runFeederOnce-style
// control: we expose the body via a context cancelled after n feeds.
func TestFeederGraceThenFail(t *testing.T) {
	e := fixture(t)
	e.h.cfg.Feeder.Enabled = true
	e.h.cfg.Feeder.Interval = time.Millisecond
	e.props["k0scontroller.service:MainPID"] = "4242"
	e.active["k0scontroller.service"] = "active"
	// G3 passes: unit started long ago.
	e.setUnitStart("k0scontroller.service", time.Hour)
	e.alive[e.h.cfg.Feeder.ProbeURL] = false

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { e.h.runFeeder(ctx); close(done) }()
	// Grace period: probe fails but feeder keeps feeding
	// (ever_ok=0). Wait for >=1 notification then inspect.
	deadline := time.After(5 * time.Second)
	for e.notifN() == 0 {
		select {
		case <-deadline:
			t.Fatal("feeder never fed during startup grace")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if e.notifN() == 0 || e.notifAt(0) != "WATCHDOG=1" {
		t.Fatalf("unexpected notify payload: %d", e.notifN())
	}
	// Let the grace fails run out (8) → remediate triggers: probe
	// still dead → G1 fails → G2 active → G3 passes → G5 fresh
	// budget → G6 restart.
	deadline = time.After(5 * time.Second)
	for e.rstN() == 0 && !remediateLogged(e) {
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
	b, _ := os.ReadFile(filepath.Join(filepath.Dir(e.state), "watchdog.log"))
	return strings.Contains(string(b), "remediate:")
}

func TestFeederFailPathRestarts(t *testing.T) {
	e := fixture(t)
	e.h.cfg.Feeder.Enabled = true
	e.h.cfg.Feeder.Interval = time.Millisecond
	e.props["k0scontroller.service:MainPID"] = "4242"
	e.active["k0scontroller.service"] = "active"
	e.setUnitStart("k0scontroller.service", time.Hour)
	e.alive[e.h.cfg.Feeder.ProbeURL] = false

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.h.runFeeder(ctx); close(done) }()
	deadline := time.After(5 * time.Second)
	for e.rstN() == 0 {
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
	if e.rstAt(0) != "k0scontroller.service" {
		t.Fatalf("wrong unit restarted: %v", e.rstAt(0))
	}
}

func TestFeederFeedsWhileAlive(t *testing.T) {
	e := fixture(t)
	e.h.cfg.Feeder.Enabled = true
	e.h.cfg.Feeder.Interval = time.Millisecond
	e.props["k0scontroller.service:MainPID"] = "4242"
	e.active["k0scontroller.service"] = "active"
	e.alive[e.h.cfg.Feeder.ProbeURL] = true

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.h.runFeeder(ctx); close(done) }()
	deadline := time.After(5 * time.Second)
	for e.notifN() < 3 {
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatalf("feeder starved: %d", e.notifN())
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
	if e.rstN() != 0 {
		t.Fatal("restart triggered while apiserver alive")
	}
}

func TestRemediateG1PassNoRestart(t *testing.T) {
	e := fixture(t)
	e.active["k0scontroller.service"] = "active"
	e.alive[e.h.cfg.Feeder.ProbeURL] = true // re-probe says alive
	e.h.runRemediate(context.Background())
	if e.rstN() != 0 {
		t.Fatal("G1 false-alarm still restarted")
	}
}

func TestRemediateG5RateLimited(t *testing.T) {
	e := fixture(t)
	e.active["k0scontroller.service"] = "active"
	e.setUnitStart("k0scontroller.service", time.Hour)
	e.alive[e.h.cfg.Feeder.ProbeURL] = false
	// Fresh budget: last restart just now.
	h := e.h
	h.state.WriteEpochFile(filepath.Join(e.fstate, fileFeederLastRst),
		h.cfg.nowFn().Unix())
	e.h.runRemediate(context.Background())
	if e.rstN() != 0 {
		t.Fatal("G5 rate-limit bypassed")
	}
}

func TestPeerAPIServerCRLF(t *testing.T) {
	e := fixture(t)
	// A CRLF peer file must not leave '\r' glued to the URL — the
	// peer probe against the garbage URL always read dead.
	writeFile(t, e.h.cfg.Feeder.RemediatePeerFile,
		"PEER_APISERVER=\"https://10.0.0.2:6443\"\r\n")
	if got := e.h.peerAPIServer(); got != "https://10.0.0.2:6443" {
		t.Fatalf("peerAPIServer=%q want https://10.0.0.2:6443", got)
	}
}

func TestParseSystemdTimestampZones(t *testing.T) {
	// A Local-known abbrev resolves exactly — the normal same-host
	// case: the zone systemd stamped IS the agent's zone (whatever
	// the test host's TZ is).
	want := time.Date(2026, 1, 5, 10, 0, 0, 0, time.Local)
	got, err := parseSystemdTimestamp(want.Format(systemdTimestampLayout))
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
	got, err = parseSystemdTimestamp("Mon 2026-01-05 10:00:00 XXX")
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
	got, err = parseSystemdTimestamp("Mon 2026-01-05 10:00:00 CET")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(time.Date(2026, 1, 5, 9, 0, 0, 0, time.UTC)) {
		t.Fatalf("CET parse=%v want 09:00Z", got)
	}
}

func TestRemediateMarksBudgetBeforeRestart(t *testing.T) {
	e := fixture(t)
	e.active["k0scontroller.service"] = "active"
	e.setUnitStart("k0scontroller.service", time.Hour)
	e.alive[e.h.cfg.Feeder.ProbeURL] = false
	// restartFn asserts the G5 budget file ALREADY exists when the
	// restart executes — a mid-restart kill must not leave it unspent.
	e.h.cfg.restartFn = func(_ context.Context, unit string) error {
		if _, err := os.Stat(filepath.Join(e.fstate, fileFeederLastRst)); err != nil {
			t.Errorf("G5 budget not marked before restart: %v", err)
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		e.rst = append(e.rst, unit)
		return nil
	}
	e.h.runRemediate(context.Background())
	if e.rstN() != 1 {
		t.Fatal("restart did not run")
	}
}

func TestRemediateCreatesFeederStateDir(t *testing.T) {
	e := fixture(t)
	e.active["k0scontroller.service"] = "active"
	e.setUnitStart("k0scontroller.service", time.Hour)
	e.alive[e.h.cfg.Feeder.ProbeURL] = false
	if err := os.RemoveAll(e.fstate); err != nil {
		t.Fatal(err)
	}
	e.h.runRemediate(context.Background())
	if e.rstN() != 1 {
		t.Fatal("restart blocked by absent FeederStateDir")
	}
	if _, err := os.Stat(filepath.Join(e.fstate, fileFeederLastRst)); err != nil {
		t.Fatal("budget file not written into created dir")
	}
}
