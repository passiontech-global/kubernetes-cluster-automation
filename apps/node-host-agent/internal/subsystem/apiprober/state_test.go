// state_test.go — watchdog state files (gap file + stale latch
// hysteresis + prune) and in-memory stale-backend/metric-series
// pruning on discovery changes.
package apiprober

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// --- watchdog state files (module 34 backward-compat contract) ---

// gapFilePath/staleFilePath name the compat files for a backend addr.
func gapFilePath(dir, addr string) string {
	return filepath.Join(dir, "apibe-gap-"+dashedIP(addr))
}
func staleFilePath(dir, addr string) string {
	return filepath.Join(dir, "state-apiserver-backend-stale-"+dashedIP(addr))
}

func fileContent(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func TestWatchdogGapFileWritten(t *testing.T) {
	stub := newAPIStub(t)
	ha := newFakeHAProxy(t, [2]string{"hub1", stub.addr()})
	p := fixture(t, ha, ModeDryRun, nil)
	p.cfg.WatchdogStateDir = t.TempDir()

	stub.set(100, 900) // gap 800 — fresh (under GapMin)
	p.Cycle(context.Background())

	if got := fileContent(t, gapFilePath(p.cfg.WatchdogStateDir, stub.addr())); got != "800\n" {
		t.Fatalf("gap file=%q want %q", got, "800\n")
	}
	if _, err := os.Stat(staleFilePath(p.cfg.WatchdogStateDir, stub.addr())); !os.IsNotExist(err) {
		t.Fatal("stale latch exists on a fresh backend")
	}

	// Next cycle with a different gap → file tracks the latest probe.
	stub.set(200, 600)
	p.Cycle(context.Background())
	if got := fileContent(t, gapFilePath(p.cfg.WatchdogStateDir, stub.addr())); got != "400\n" {
		t.Fatalf("gap file=%q want %q", got, "400\n")
	}
}

func TestWatchdogStaleLatchEnterExit(t *testing.T) {
	bad := newAPIStub(t)
	ha := newFakeHAProxy(t, [2]string{"hub1", bad.addr()})
	p := fixture(t, ha, ModeDryRun, nil)
	dir := t.TempDir()
	p.cfg.WatchdogStateDir = dir
	latch := staleFilePath(dir, bad.addr())

	// gap > GapMin for FailCycles cycles → stale → latch created
	// (latching is independent of the dry-run drain fence).
	bad.set(100, 5000)
	p.Cycle(context.Background())
	p.Cycle(context.Background())
	fi, err := os.Stat(latch)
	if err != nil {
		t.Fatalf("stale latch not created: %v", err)
	}
	if fi.Size() == 0 {
		t.Fatal("stale latch empty — want epoch content")
	}
	if _, err := strconv.ParseInt(strings.TrimSpace(fileContent(t, latch)), 10, 64); err != nil {
		t.Fatalf("stale latch content not an epoch: %v", err)
	}

	// Fresh cycles < RecoverCycles → latch survives (shell hysteresis:
	// state_exit only after RECOVER_CYCLES consecutive fresh runs —
	// one lucky probe must not unblock 06's upstream gate).
	bad.set(60, 60)
	p.Cycle(context.Background())
	p.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatal("stale latch cleared before RecoverCycles fresh cycles")
	}
	// Third consecutive fresh cycle (== default RecoverCycles) → exit.
	p.Cycle(context.Background())
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("stale latch not cleared after RecoverCycles fresh cycles")
	}
}

func TestWatchdogLatchNotClearedOnInconclusive(t *testing.T) {
	bad := newAPIStub(t)
	ha := newFakeHAProxy(t, [2]string{"hub1", bad.addr()})
	p := fixture(t, ha, ModeDryRun, nil)
	dir := t.TempDir()
	p.cfg.WatchdogStateDir = dir
	latch := staleFilePath(dir, bad.addr())

	bad.set(100, 5000)
	p.Cycle(context.Background())
	p.Cycle(context.Background()) // stale → latch
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("stale latch not created: %v", err)
	}

	// TCP-unreachable cycle is inconclusive — the latch must survive
	// (hysteresis: no exit on an indeterminate probe).
	p.cfg.TCPCheck = func(_ context.Context, _ string) error {
		return errors.New("connect refused")
	}
	p.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatal("stale latch cleared on an inconclusive cycle")
	}

	// Query-fail-but-under-threshold is also inconclusive.
	p.cfg.TCPCheck = nil
	p.states["hub1"].qfail = 0 // reset to under-threshold
	bad.setFail(true)
	p.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatal("stale latch cleared on an inconclusive query-fail cycle")
	}
}

func TestWatchdogPruneRemovesRetiredBackends(t *testing.T) {
	good := newAPIStub(t)
	ha := newFakeHAProxy(t, [2]string{"hub2", good.addr()})
	p := fixture(t, ha, ModeDryRun, nil)
	dir := t.TempDir()
	p.cfg.WatchdogStateDir = dir

	// Files from a backend that left api-local-lb discovery.
	oldGap := gapFilePath(dir, "10.9.9.9:6443")
	oldLatch := staleFilePath(dir, "10.9.9.9:6443")
	for _, f := range []string{oldGap, oldLatch} {
		if err := os.WriteFile(f, []byte("1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	good.set(50, 50)
	p.Cycle(context.Background())

	for _, f := range []string{oldGap, oldLatch} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Fatalf("file for retired backend not pruned: %s", f)
		}
	}
	// The discovered backend's own gap file survives.
	if _, err := os.Stat(gapFilePath(dir, good.addr())); err != nil {
		t.Fatalf("gap file for live backend pruned: %v", err)
	}
}

func TestWatchdogNoPruneOnEmptyDiscovery(t *testing.T) {
	// Discovery returned zero rows — never prune (a failed/empty scan
	// must not wipe latches other watchdog consumers still read).
	ha := newFakeHAProxy(t) // no servers
	p := fixture(t, ha, ModeDryRun, nil)
	dir := t.TempDir()
	p.cfg.WatchdogStateDir = dir
	f := staleFilePath(dir, "10.9.9.9:6443")
	if err := os.WriteFile(f, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p.Cycle(context.Background())
	if _, err := os.Stat(f); err != nil {
		t.Fatal("latch pruned on an empty backend list")
	}
}

func TestWatchdogFilesSkippedWhenDirUnsetOrMissing(t *testing.T) {
	for _, tc := range []struct {
		name string
		wdir string
	}{
		{"empty", ""},
		{"missing", filepath.Join(t.TempDir(), "no-such-dir")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := newAPIStub(t)
			ha := newFakeHAProxy(t, [2]string{"hub1", bad.addr()})
			p := fixture(t, ha, ModeDryRun, nil)
			p.cfg.WatchdogStateDir = tc.wdir

			bad.set(100, 5000)
			p.Cycle(context.Background())
			p.Cycle(context.Background()) // stale — must not create the dir or panic
			if tc.wdir != "" {
				if _, err := os.Stat(tc.wdir); !os.IsNotExist(err) {
					t.Fatal("missing watchdog dir was created by file ops")
				}
			}
		})
	}
}

func TestDashedIP(t *testing.T) {
	if got := dashedIP("10.0.0.1:6443"); got != "10-0-0-1" {
		t.Fatalf("dashedIP=%q want 10-0-0-1", got)
	}
	// Raw addr without port — fallback keeps the host as-is.
	if got := dashedIP("10.0.0.1"); got != "10-0-0-1" {
		t.Fatalf("dashedIP=%q want 10-0-0-1", got)
	}
}

// --- stale-backend pruning (p.states + per-backend metric series) ---
// Series counts go through testutil.CollectAndCount rather than
// ToFloat64 — a WithLabelValues probe would re-create the very series
// the prune is supposed to have deleted.

func TestPruneStaleBackendsRemovesStateAndSeries(t *testing.T) {
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	// One healthy cycle seeds rvGap{hub1}/enabled{hub1}; then query
	// failures wedge hub1 → probeFailures{hub1,query},
	// actions{hub1,disable} and a drained states entry.
	bad.set(100, 900)
	good.set(50, 50)
	p.Cycle(context.Background())
	bad.setFail(true)
	p.Cycle(context.Background())
	p.Cycle(context.Background()) // qfail #2 → DEAD → disable

	if _, ok := p.states["hub1"]; !ok {
		t.Fatal("hub1 states entry missing before retire")
	}
	if testutil.CollectAndCount(p.probeFailures) != 1 ||
		testutil.CollectAndCount(p.actions) != 1 {
		t.Fatal("expected one hub1 probeFailures/actions series before retire")
	}

	// Retire hub1 from api-local-lb — the next discovery sees hub2 only.
	ha.mu.Lock()
	delete(ha.servers, "hub1")
	ha.order = []string{"hub2"}
	ha.mu.Unlock()
	p.Cycle(context.Background())

	if _, ok := p.states["hub1"]; ok {
		t.Fatal("stale hub1 states entry survived prune")
	}
	if got := testutil.CollectAndCount(p.rvGap); got != 1 {
		t.Fatalf("rvGap series=%d want 1 (hub2 only)", got)
	}
	if got := testutil.CollectAndCount(p.enabled); got != 1 {
		t.Fatalf("enabled series=%d want 1 (hub2 only)", got)
	}
	// The two-label vecs must lose every series whose backend label
	// matches — DeletePartialMatch coverage.
	if got := testutil.CollectAndCount(p.probeFailures); got != 0 {
		t.Fatalf("probeFailures series=%d want 0 after prune", got)
	}
	if got := testutil.CollectAndCount(p.actions); got != 0 {
		t.Fatalf("actions series=%d want 0 after prune", got)
	}
}

func TestPruneStaleBackendsSkippedOnEmptyOrFailedDiscovery(t *testing.T) {
	// A transient socket error or an empty scan must not wipe state the
	// next good cycle still needs — the len(backends)>0 gate.
	seed := func(p *Prober) {
		p.states["gone"] = &backendState{drained: true}
		p.rvGap.WithLabelValues("gone").Set(7)
		p.enabled.WithLabelValues("gone").Set(0)
		p.probeFailures.WithLabelValues("gone", "query").Inc()
		p.actions.WithLabelValues("gone", "disable").Inc()
	}
	assertKept := func(t *testing.T, p *Prober) {
		t.Helper()
		if _, ok := p.states["gone"]; !ok {
			t.Fatal("states entry pruned on a non-discovery cycle")
		}
		for name, vec := range map[string]prometheus.Collector{
			"rvGap":         p.rvGap,
			"enabled":       p.enabled,
			"probeFailures": p.probeFailures,
			"actions":       p.actions,
		} {
			if got := testutil.CollectAndCount(vec); got != 1 {
				t.Fatalf("%s series=%d want 1 kept", name, got)
			}
		}
	}

	t.Run("empty discovery", func(t *testing.T) {
		ha := newFakeHAProxy(t) // header only — zero kube_apiserver rows
		p := fixture(t, ha, ModeDryRun, nil)
		seed(p)
		p.Cycle(context.Background())
		assertKept(t, p)
	})

	t.Run("failed discovery", func(t *testing.T) {
		p, err := New(Config{
			DialSocket: func(context.Context, string) (net.Conn, error) {
				return nil, errors.New("admin socket gone")
			},
			HTTPClient: newAPIStub(t).srv.Client(),
		}, prometheus.NewRegistry())
		if err != nil {
			t.Fatal(err)
		}
		seed(p)
		p.Cycle(context.Background())
		assertKept(t, p)
	})
}

func TestPruneStaleBackendsKeepsVIP(t *testing.T) {
	// *_lb VIP entries are part of the live discovery set — pruning on
	// direct backends only (the pruneWatchdogFiles filter) would drop
	// the VIP's drained flag and enabled series every cycle.
	ctrl := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"api_datahub_ctrl", ctrl.addr()},
		[2]string{"api_datahub_lb", "127.0.0.1:1"},
	)
	p := fixture(t, ha, ModeDryRun, nil)

	ctrl.set(50, 50)
	p.Cycle(context.Background())

	if _, ok := p.states["api_datahub_lb"]; !ok {
		t.Fatal("VIP states entry pruned while still in discovery")
	}
	if got := testutil.CollectAndCount(p.enabled); got != 2 {
		t.Fatalf("enabled series=%d want 2 (ctrl + VIP)", got)
	}
}
