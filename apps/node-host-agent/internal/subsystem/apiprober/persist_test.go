// persist_test.go — the apibe-* restart witness: per-backend
// counters mirrored to the watchdog state dir, restored by a NEW
// Prober on the same dir (agent-restart parity), zero-counter file
// deletion, departed-backend file pruning, the deferred flush on a
// cancelled cycle, and the empty-dir pure-RAM path.
package apiprober

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// beFile names one persisted per-backend state file.
func beFile(dir, prefix, name string) string {
	return filepath.Join(dir, prefix+name)
}

func TestPersistStreaksResumeAcrossRestart(t *testing.T) {
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	dir := t.TempDir()
	p := fixture(t, ha, ModeEnforce, nil)
	p.cfg.WatchdogStateDir = dir

	// One failing cycle: hub1 qfail=1 — one short of DEAD — and
	// hub2 ok=1 with its frozen baseline.
	bad.setFail(true)
	good.set(50, 50)
	p.Cycle(context.Background())
	if p.states["hub1"].qfail != 1 || p.states["hub2"].ok != 1 {
		t.Fatalf("seed state qfail=%d ok=%d want 1/1",
			p.states["hub1"].qfail, p.states["hub2"].ok)
	}
	// The witness files landed at cycle end.
	if got := fileContent(t, beFile(dir, "apibe-qfail-", "hub1")); got != "1\n" {
		t.Fatalf("apibe-qfail-hub1=%q want %q", got, "1\n")
	}
	if got := fileContent(t, beFile(dir, "apibe-ok-", "hub2")); got != "1\n" {
		t.Fatalf("apibe-ok-hub2=%q want %q", got, "1\n")
	}
	if got := fileContent(t, beFile(dir, "apibe-prevcache-", "hub2")); got != "50\n" {
		t.Fatalf("apibe-prevcache-hub2=%q want %q", got, "50\n")
	}

	// "Restart": a fresh Prober on the same dir — the qfail streak
	// resumes at 1, so THIS cycle reaches FailCycles and drains.
	p2 := fixture(t, ha, ModeEnforce, nil)
	p2.cfg.WatchdogStateDir = dir
	p2.Cycle(context.Background())

	if !hasCmd(ha.commands(), "disable server kube_apiserver/hub1") {
		t.Fatalf("no disable after restart — qfail streak not resumed, cmds=%v",
			ha.commands())
	}
	if !p2.states["hub1"].drained {
		t.Fatal("hub1 not drained after the resumed streak reached FailCycles")
	}
	if !p2.states["hub1"].loaded || !p2.states["hub2"].loaded {
		t.Fatal("loaded latch not set after the witness fold-in")
	}
	if _, err := os.Stat(beFile(dir, "apibe-drained-", "hub1")); err != nil {
		t.Fatalf("drained marker not persisted: %v", err)
	}
}

func TestPersistDrainedMarkerAndOkResumeToEnable(t *testing.T) {
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	dir := t.TempDir()
	p := fixture(t, ha, ModeEnforce, nil)
	p.cfg.WatchdogStateDir = dir

	// Frozen wedge → hub1 drains.
	bad.set(100, 200)
	good.set(50, 50)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if !p.states["hub1"].drained {
		t.Fatal("hub1 not drained after the wedge")
	}

	// Recovery: two fresh cycles → ok=2, one short of RecoverCycles.
	bad.set(300, 300)
	for i := 0; i < 2; i++ {
		p.Cycle(context.Background())
	}
	if p.states["hub1"].ok != 2 {
		t.Fatalf("ok=%d want 2 before restart", p.states["hub1"].ok)
	}

	// Restart: the loaded marker keeps hub1 on the recovery path
	// and the persisted ok=2 resumes — ONE more fresh cycle reaches
	// RecoverCycles and enables. Without the witness it would take
	// three fresh post-restart cycles.
	p2 := fixture(t, ha, ModeEnforce, nil)
	p2.cfg.WatchdogStateDir = dir
	p2.Cycle(context.Background())

	if !hasCmd(ha.commands(), "enable server kube_apiserver/hub1") {
		t.Fatalf("no enable after restart — ok streak not resumed, cmds=%v",
			ha.commands())
	}
	if p2.states["hub1"].drained {
		t.Fatal("drained flag still set after the resumed recovery")
	}
	if _, err := os.Stat(beFile(dir, "apibe-drained-", "hub1")); !os.IsNotExist(err) {
		t.Fatal("drained marker not removed after the enable")
	}
}

func TestPersistDrainedMarkerReAppliesAfterDoubleRestart(t *testing.T) {
	// Agent restart + HAProxy restart together: HAProxy forgot the
	// runtime disable (reports UP) AND the agent's RAM is gone —
	// only the on-disk marker remembers the drain, so the re-apply
	// pass disables again on the FIRST post-restart cycle even
	// though the backend now probes fresh.
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	dir := t.TempDir()
	p := fixture(t, ha, ModeEnforce, nil)
	p.cfg.WatchdogStateDir = dir

	bad.set(100, 200) // frozen wedge → drain
	good.set(50, 50)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if got := countCmd(ha.commands(), "disable server kube_apiserver/hub1"); got != 1 {
		t.Fatalf("disables=%d want 1, cmds=%v", got, ha.commands())
	}

	// HAProxy restart forgets the disable; the apiserver recovers.
	ha.mu.Lock()
	ha.disabled["hub1"] = false
	ha.mu.Unlock()
	bad.set(300, 300)

	p2 := fixture(t, ha, ModeEnforce, nil)
	p2.cfg.WatchdogStateDir = dir
	p2.Cycle(context.Background())

	// The loaded marker sends the backend through the re-apply pass
	// (drained && discovered && UP) — disable #2 lands on cycle 1.
	if got := countCmd(ha.commands(), "disable server kube_apiserver/hub1"); got != 2 {
		t.Fatalf("re-applied disables=%d want 2 — drained marker not loaded, cmds=%v",
			got, ha.commands())
	}
	if !p2.states["hub1"].drained {
		t.Fatal("drained flag not restored from the marker")
	}
}

func TestPersistVIPDrainedMarkerRestored(t *testing.T) {
	// The load happens BEFORE the vip() continue — a *_lb entry's
	// drained marker must survive a restart like a direct
	// backend's, and the VIP phase must not re-issue the disable.
	ctrl1 := newAPIStub(t)
	ctrl2 := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"api_datahub_ctrl", ctrl1.addr()},
		[2]string{"api_datahub_lb", "127.0.0.1:1"},
		[2]string{"api_contabo_ctrl", ctrl2.addr()},
	)
	dir := t.TempDir()
	p := fixture(t, ha, ModeEnforce, nil)
	p.cfg.WatchdogStateDir = dir

	// ctrl2 wedges while ctrl1 stays fresh → VIP disabled alongside.
	ctrl1.set(500, 500)
	ctrl2.set(100, 3000)
	for i := 0; i < 2; i++ {
		p.Cycle(context.Background())
	}
	if !p.states["api_datahub_lb"].drained {
		t.Fatal("VIP not drained alongside the wedged controller")
	}
	if _, err := os.Stat(beFile(dir, "apibe-drained-", "api_datahub_lb")); err != nil {
		t.Fatalf("VIP drained marker not persisted: %v", err)
	}

	// Restart with the wedge still active: the restored marker must
	// keep the VIP drained WITHOUT re-issuing the socket command —
	// re-deriving drained in-cycle would produce a second disable.
	p2 := fixture(t, ha, ModeEnforce, nil)
	p2.cfg.WatchdogStateDir = dir
	p2.Cycle(context.Background())
	if !p2.states["api_datahub_lb"].drained {
		t.Fatal("VIP drained flag lost across restart")
	}
	if got := countCmd(ha.commands(),
		"disable server kube_apiserver/api_datahub_lb"); got != 1 {
		t.Fatalf("VIP disables=%d want 1 — marker not loaded, disable re-issued, cmds=%v",
			got, ha.commands())
	}
}

func TestPersistZeroCountersLeaveNoFiles(t *testing.T) {
	stub := newAPIStub(t)
	ha := newFakeHAProxy(t, [2]string{"hub1", stub.addr()})
	dir := t.TempDir()
	p := fixture(t, ha, ModeDryRun, nil)
	p.cfg.WatchdogStateDir = dir

	stub.set(100, 900) // healthy: gap under GapMin
	p.Cycle(context.Background())

	// Zero-value counters must not exist as files — absent IS 0.
	for _, f := range []string{
		"apibe-qfail-hub1", "apibe-frozen-hub1", "apibe-fail-hub1",
		"apibe-drained-hub1",
	} {
		if _, err := os.Stat(filepath.Join(dir, f)); !os.IsNotExist(err) {
			t.Fatalf("%s exists for a zero value", f)
		}
	}
	if got := fileContent(t, beFile(dir, "apibe-ok-", "hub1")); got != "1\n" {
		t.Fatalf("apibe-ok-hub1=%q want %q", got, "1\n")
	}
	if got := fileContent(t, beFile(dir, "apibe-prevcache-", "hub1")); got != "100\n" {
		t.Fatalf("apibe-prevcache-hub1=%q want %q", got, "100\n")
	}

	// A failing cycle zeroes ok and raises qfail — the files must
	// swap, not accumulate.
	stub.setFail(true)
	p.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(dir, "apibe-ok-hub1")); !os.IsNotExist(err) {
		t.Fatal("apibe-ok-hub1 survived its counter resetting to 0")
	}
	if got := fileContent(t, beFile(dir, "apibe-qfail-", "hub1")); got != "1\n" {
		t.Fatalf("apibe-qfail-hub1=%q want %q", got, "1\n")
	}
	// The outage path clears hasPrev → the baseline file is gone.
	if _, err := os.Stat(filepath.Join(dir, "apibe-prevcache-hub1")); !os.IsNotExist(err) {
		t.Fatal("apibe-prevcache-hub1 survived hasPrev=false")
	}
}

func TestPersistDepartedBackendFilesPruned(t *testing.T) {
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	dir := t.TempDir()
	p := fixture(t, ha, ModeDryRun, nil)
	p.cfg.WatchdogStateDir = dir

	bad.set(100, 5000) // gap wedge under threshold → fail counter file
	good.set(50, 50)
	p.Cycle(context.Background())
	for _, f := range []string{"apibe-fail-hub1", "apibe-prevcache-hub1"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("%s missing before retire: %v", f, err)
		}
	}

	// hub1 leaves api-local-lb — the next cycle prunes its RAM
	// state AND its apibe-* files; hub2's survive.
	ha.mu.Lock()
	delete(ha.servers, "hub1")
	ha.order = []string{"hub2"}
	ha.mu.Unlock()
	p.Cycle(context.Background())

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), "-hub1") {
			t.Fatalf("departed backend file survived prune: %s", e.Name())
		}
	}
	if _, err := os.Stat(beFile(dir, "apibe-prevcache-", "hub2")); err != nil {
		t.Fatal("live backend's state file pruned")
	}
}

func TestPersistFlushCoversCancelledCycle(t *testing.T) {
	// A cycle cancelled mid-loop still flushes the partial round's
	// counters via the deferred flush — a shutdown must not drop a
	// wedge streak one cycle from firing.
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	dir := t.TempDir()
	p := fixture(t, ha, ModeEnforce, nil)
	p.cfg.WatchdogStateDir = dir

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel during hub1's processing: its queries then fail
	// ctx.Canceled → transport class → apiserver-side → qfail++ —
	// and hub2's iteration bails on the ctx.Err() check.
	p.cfg.TCPCheck = func(_ context.Context, addr string) error {
		if addr == bad.addr() {
			cancel()
		}
		return nil
	}
	p.Cycle(ctx)

	if p.states["hub1"].qfail != 1 {
		t.Fatalf("hub1 qfail=%d want 1 — cancelled cycle counted no failure",
			p.states["hub1"].qfail)
	}
	if got := fileContent(t, beFile(dir, "apibe-qfail-", "hub1")); got != "1\n" {
		t.Fatalf("apibe-qfail-hub1=%q want %q — deferred flush missed the early return",
			got, "1\n")
	}
	// hub2 never got a state entry — nothing persisted for it.
	if _, err := os.Stat(beFile(dir, "apibe-prevcache-", "hub2")); !os.IsNotExist(err) {
		t.Fatal("hub2 file written although its iteration never ran")
	}
}

func TestPersistGarbageFilesReadAsZero(t *testing.T) {
	// A hand-edited or torn counter file loses the streak rather
	// than inventing one — the hoststate "garbage → 0" parity.
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	dir := t.TempDir()
	testutil.WriteFile(t, filepath.Join(dir, "apibe-qfail-hub1"), "garbage\n")
	testutil.WriteFile(t, filepath.Join(dir, "apibe-prevcache-hub2"), "not-a-number")

	p := fixture(t, ha, ModeEnforce, nil)
	p.cfg.WatchdogStateDir = dir

	bad.setFail(true)
	good.set(50, 50)
	p.Cycle(context.Background())
	if p.states["hub1"].qfail != 1 {
		t.Fatalf("qfail=%d want 1 — garbage file must read as 0, not a streak",
			p.states["hub1"].qfail)
	}
	// Garbage prevcache → no baseline → hasPrev stays false this
	// cycle (the first probe only SETS the baseline).
	p.Cycle(context.Background())
	if !hasCmd(ha.commands(), "disable server kube_apiserver/hub1") {
		t.Fatalf("no disable on the real second failure, cmds=%v", ha.commands())
	}
}

func TestPersistDisabledWithoutWatchdogDir(t *testing.T) {
	// wdir="" disables every file op — pure-RAM behavior: the
	// streak still fires and load never runs.
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)
	p.cfg.WatchdogStateDir = ""

	bad.setFail(true)
	good.set(50, 50)
	p.Cycle(context.Background())
	p.Cycle(context.Background())

	if !p.states["hub1"].drained {
		t.Fatal("hub1 not drained — the RAM streak must work without a state dir")
	}
	if p.states["hub1"].loaded || p.states["hub2"].loaded {
		t.Fatal("loaded latched without a watchdog dir")
	}
}

func TestStateFileKeySanitizes(t *testing.T) {
	// Backend names land in filenames — chars outside
	// [A-Za-z0-9._-] must not reach the path.
	for in, want := range map[string]string{
		"api_datahub_lb":  "api_datahub_lb",
		"hub1":            "hub1",
		"10.0.0.1:6443":   "10.0.0.1-6443",
		"weird name/x:y":  "weird-name-x-y",
		"trail[ing]":      "trail-ing-",
		"under_score.d-1": "under_score.d-1",
	} {
		if got := stateFileKey(in); got != want {
			t.Fatalf("stateFileKey(%q)=%q want %q", in, got, want)
		}
	}
}
