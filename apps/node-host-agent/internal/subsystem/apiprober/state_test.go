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
	"time"

	"github.com/prometheus/client_golang/prometheus"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
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
		testutil.WriteFile(t, f, "1\n")
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
	testutil.WriteFile(t, f, "1\n")
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
// Series counts go through promtest.CollectAndCount rather than
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
	if promtest.CollectAndCount(p.probeFailures) != 1 ||
		promtest.CollectAndCount(p.actions) != 1 {
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
	if got := promtest.CollectAndCount(p.rvGap); got != 1 {
		t.Fatalf("rvGap series=%d want 1 (hub2 only)", got)
	}
	if got := promtest.CollectAndCount(p.enabled); got != 1 {
		t.Fatalf("enabled series=%d want 1 (hub2 only)", got)
	}
	// The two-label vecs must lose every series whose backend label
	// matches — DeletePartialMatch coverage.
	if got := promtest.CollectAndCount(p.probeFailures); got != 0 {
		t.Fatalf("probeFailures series=%d want 0 after prune", got)
	}
	if got := promtest.CollectAndCount(p.actions); got != 0 {
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
			if got := promtest.CollectAndCount(vec); got != 1 {
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
	if got := promtest.CollectAndCount(p.enabled); got != 2 {
		t.Fatalf("enabled series=%d want 2 (ctrl + VIP)", got)
	}
}

// TestLatchStaleRefreshesHeldMtime: re-latching an already-latched
// backend refreshes the latch mtime (BUG-H6 — the janitor reaps
// state-* files older than 24h and a multi-day wedged backend must
// keep its latch) without rewriting the epoch content.
func TestLatchStaleRefreshesHeldMtime(t *testing.T) {
	dir := t.TempDir()
	p := &Prober{}
	b := backend{Name: "hub1", Addr: "10.0.0.1:6443"}

	p.latchStale(dir, b)
	f := dir + "/" + latchdefs.LatchFilePrefix +
		latchdefs.LatchAPIServerBackendStalePrefix + "10-0-0-1"
	if got, err := os.ReadFile(f); err != nil || len(got) == 0 {
		t.Fatalf("latch not created: %v", err)
	}
	first := testutil.ReadFile(t, f)

	// Age the latch 48h, then re-latch — mtime moves to ~now,
	// content stays the entry epoch.
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(f, old, old); err != nil {
		t.Fatal(err)
	}
	p.latchStale(dir, b)
	fi, err := os.Stat(f)
	if err != nil {
		t.Fatal(err)
	}
	if fi.ModTime().Before(time.Now().Add(-time.Minute)) {
		t.Fatalf("held latch mtime = %v, want refreshed to ~now", fi.ModTime())
	}
	if got := testutil.ReadFile(t, f); got != first {
		t.Fatalf("latch content changed on re-latch: %q → %q", first, got)
	}
}

// --- best-effort file faults: logged, never fatal ---

// The gap file write is best-effort: an unwritable target dir warns
// and moves on (the probe verdict must not depend on watchdog files).
func TestWriteGapFileWriteFailureTolerated(t *testing.T) {
	buf := captureSlog(t)
	p := &Prober{}
	p.writeGapFile(filepath.Join(t.TempDir(), "absent"), // dir never created
		backend{Name: "hub1", Addr: "10.0.0.1:6443"}, 5)
	if !strings.Contains(buf.String(), "gap file write failed") {
		t.Fatalf("write failure not logged:\n%s", buf.String())
	}
}

// clearStale tolerates a remove failure (read-only state dir) —
// state_exit must not crash the cycle, the latch simply survives.
func TestClearStaleRemoveFailureTolerated(t *testing.T) {
	buf := captureSlog(t)
	dir := t.TempDir()
	b := backend{Name: "hub1", Addr: "10.0.0.1:6443"}
	p := &Prober{}
	p.latchStale(dir, b)
	f := staleFilePath(dir, b.Addr)
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	p.clearStale(dir, b)
	if !strings.Contains(buf.String(), "stale latch remove failed") {
		t.Fatalf("remove failure not logged:\n%s", buf.String())
	}
	if _, err := os.Stat(f); err != nil {
		t.Fatalf("latch removed despite read-only dir: %v", err)
	}
}

// pruneWatchdogFiles: a missing state dir warns once and skips the
// prune (the dir is created lazily by the first latch/gap write).
func TestPruneWatchdogFilesScanFailureTolerated(t *testing.T) {
	buf := captureSlog(t)
	p := &Prober{}
	p.pruneWatchdogFiles(filepath.Join(t.TempDir(), "absent"),
		[]backend{{Name: "hub1", Addr: "10.0.0.1:6443"}})
	if !strings.Contains(buf.String(), "state dir scan failed") {
		t.Fatalf("scan failure not logged:\n%s", buf.String())
	}
}

// A matching file that cannot be removed (a retired backend's stale
// latch now a non-empty directory) logs the fault and lets the rest
// of the prune carry on.
func TestPruneWatchdogFilesRemoveFailureTolerated(t *testing.T) {
	buf := captureSlog(t)
	dir := t.TempDir()
	kept := []backend{{Name: "hub1", Addr: "10.0.0.1:6443"}}
	testutil.WriteFile(t, filepath.Join(dir, "apibe-gap-9-9-9-9"), "1\n")
	wedged := staleFilePath(dir, "8.8.8.8:6443")
	if err := os.Mkdir(wedged, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(wedged, "child"), "x")

	p := &Prober{}
	p.pruneWatchdogFiles(dir, kept)

	if !strings.Contains(buf.String(), "stale file prune failed") {
		t.Fatalf("prune failure not logged:\n%s", buf.String())
	}
	if _, err := os.Stat(wedged); err != nil {
		t.Fatalf("wedged latch removed after all: %v", err)
	}
	// The plain retired gap file still went, and the live backend's
	// files survive.
	if _, err := os.Stat(filepath.Join(dir, "apibe-gap-9-9-9-9")); !os.IsNotExist(err) {
		t.Fatalf("retired gap file not pruned: %v", err)
	}
	if _, err := os.Stat(gapFilePath(dir, "10.0.0.1:6443")); err == nil {
		t.Fatal("kept backend's (absent) gap file should not exist")
	}
}

// The stale latch create is best-effort too — an unwritable target
// dir warns and the cycle carries on (state_enter must not crash).
func TestLatchStaleWriteFailureTolerated(t *testing.T) {
	buf := captureSlog(t)
	p := &Prober{}
	p.latchStale(filepath.Join(t.TempDir(), "absent"),
		backend{Name: "hub1", Addr: "10.0.0.1:6443"})
	if !strings.Contains(buf.String(), "stale latch write failed") {
		t.Fatalf("latch write failure not logged:\n%s", buf.String())
	}
}

// The apibe-* state family shares the best-effort contract: a write
// into an absent dir and a remove that fails for a real reason (the
// path is a non-empty directory) warn and move on.
func TestStateFileWriteRemoveFailuresTolerated(t *testing.T) {
	p := &Prober{}

	buf := captureSlog(t)
	p.writeStateFile(filepath.Join(t.TempDir(), "absent", "apibe-ok-hub1"), "3")
	if !strings.Contains(buf.String(), "state file write failed") {
		t.Fatalf("state write failure not logged:\n%s", buf.String())
	}

	buf = captureSlog(t)
	wedged := filepath.Join(t.TempDir(), "apibe-ok-hub1")
	if err := os.Mkdir(wedged, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(wedged, "child"), "x")
	p.removeStateFile(wedged)
	if !strings.Contains(buf.String(), "state file remove failed") {
		t.Fatalf("state remove failure not logged:\n%s", buf.String())
	}
}

// loadState: the loaded/dir gates short-circuit (RAM authoritative,
// watchdog disabled), and a folded load restores the prevcache
// baseline (hasPrev) plus the drained marker alongside the counters.
func TestLoadStateGatesAndPrevCacheRestore(t *testing.T) {
	dir := t.TempDir()
	key := "hub1"
	testutil.WriteFile(t, filepath.Join(dir, "apibe-qfail-"+key), "3\n")
	testutil.WriteFile(t, filepath.Join(dir, "apibe-prevcache-"+key), "777\n")
	testutil.WriteFile(t, filepath.Join(dir, "apibe-drained-"+key), "1700000000\n")
	p := &Prober{}

	// Already-loaded state is never re-folded (RAM authoritative).
	st := &backendState{loaded: true}
	p.loadState(dir, key, st)
	if st.qfail != 0 || !st.loaded {
		t.Fatalf("re-load mutated a loaded state: %+v", st)
	}

	// Watchdog disabled ("" dir) is a pure no-op — not even the
	// loaded flag flips (the callers' dir != "" gate does the work).
	stDisabled := &backendState{}
	p.loadState("", key, stDisabled)
	if stDisabled.loaded || stDisabled.qfail != 0 {
		t.Fatalf("empty-dir load wrong: %+v", stDisabled)
	}

	// Fresh load folds the whole family in.
	stFull := &backendState{}
	p.loadState(dir, key, stFull)
	if stFull.qfail != 3 || !stFull.drained {
		t.Fatalf("counters/drained not restored: %+v", stFull)
	}
	if !stFull.hasPrev || stFull.prevCache != 777 {
		t.Fatalf("prevcache baseline not restored: %+v", stFull)
	}
}
