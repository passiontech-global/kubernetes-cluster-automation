package janitor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// jenv is the janitor fixture: tempdir state dir + fake procfs + a
// recording systemd runner + a controllable clock. All seams are
// in-memory — no real processes, units or signals are touched.
type jenv struct {
	j       *Janitor
	state   string
	proc    string
	logFile string
	now     time.Time
	sd      *testutil.FakeExec
	kills   []killRecord
	live    map[int]bool // pids that answer signal-0
}

func jfixture(t *testing.T) *jenv {
	t.Helper()
	root := t.TempDir()
	e := &jenv{
		now:  time.Now(),
		live: map[int]bool{},
		// Mutating systemctl verbs succeed silently — only the READ
		// side (list-units) needs a canned reply; anything else a
		// test did not stub reads as an absent unit.
		sd: testutil.NewFakeExec(
			testutil.ExecRule{Substr: "systemctl reset-failed"},
			testutil.ExecRule{Substr: "systemctl stop"},
		).Miss(syscall.ENOENT),
	}
	e.state = filepath.Join(root, "watchdog")
	e.proc = filepath.Join(root, "proc")
	e.logFile = filepath.Join(root, "watchdog.log")
	for _, d := range []string{e.state, e.proc} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sd := systemd.New(systemd.Config{HostRoot: "/", RunCmd: e.sd.Run},
		systemd.WithProcUptimeFile(filepath.Join(e.proc, "uptime")))
	j, err := New(Config{
		Interval:         time.Hour,
		WatchdogStateDir: e.state,
		WatchdogLogFile:  e.logFile,
		ProcRoot:         e.proc,
		LatchMaxAge:      24 * time.Hour,
		Systemd:          sd,
	}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	j.cfg.killFn = func(pid int, sig syscall.Signal) error {
		if sig == 0 {
			if e.live[pid] {
				return nil
			}
			return syscall.ESRCH
		}
		e.kills = append(e.kills, killRecord{pid, sig})
		return nil
	}
	j.cfg.Clock.Set(func() time.Time { return e.now })
	e.j = j
	return e
}

// sdClient rebuilds the systemd client bound to e.sd — tests that
// construct a second Janitor inline (alternate ProcRoot, fresh
// registry) reuse the same recording runner.
func (e *jenv) sdClient() *systemd.Client {
	return systemd.New(systemd.Config{HostRoot: "/", RunCmd: e.sd.Run},
		systemd.WithProcUptimeFile(filepath.Join(e.proc, "uptime")))
}

// mkProc plants a fake process: <proc>/<pid>/cmdline (NUL-joined) and
// <proc>/<pid>/stat carrying the given ppid in field 4.
func (e *jenv) mkProc(t *testing.T, pid, ppid int, argv ...string) {
	t.Helper()
	e.live[pid] = true
	dir := filepath.Join(e.proc, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(dir, "cmdline"),
		strings.Join(argv, "\x00")+"\x00")
	// "pid (comm) state ppid ..." — ppid is the first field after the
	// state char following the last ')'.
	testutil.WriteFile(t, filepath.Join(dir, "stat"),
		fmt.Sprintf("%d (%s) S %d 0 0 0 -1 4194304 100 0 0 0 0 0 0 0 20 0 1 0 50 0 0 0\n",
			pid, filepath.Base(argv[0]), ppid))
}

// ageFile rewinds a file's mtime so the reaper sees it as old.
func ageFile(t *testing.T, path string, age time.Duration) {
	t.Helper()
	old := time.Now().Add(-age)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
}

func (e *jenv) logContains(t *testing.T, sub string) bool {
	t.Helper()
	data, err := os.ReadFile(e.logFile)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), sub)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// killRecord mirrors workerhygiene's private test helper (that dir's
// fakes are out of scope; the shared fs/exec helpers live in
// internal/testutil).
type killRecord struct {
	pid int
	sig syscall.Signal
}

// --- A: latch reaper ---

func TestReapsUnknownLatchAfterMaxAge(t *testing.T) {
	e := jfixture(t)
	// Name no current check produces — the removed/renamed-check
	// case. FRESH unknowns survive the sweep: a foreign-schema
	// writer (retired legacy unit, old binary) would flap on an
	// instant reap — its rewrites keep the mtime young, and the
	// orphan is only reaped once it has stayed stale for max-age.
	fresh := filepath.Join(e.state, "state-tinc-route-lost")
	testutil.WriteFile(t, fresh, "1\n")
	e.j.Sweep(context.Background())
	if !fileExists(fresh) {
		t.Fatal("fresh unknown latch reaped — age floor broken")
	}
	ageFile(t, fresh, 25*time.Hour)
	e.j.Sweep(context.Background())
	if fileExists(fresh) {
		t.Fatal("aged unknown latch survived sweep")
	}
	if !e.logContains(t, "ACTION: reaped stale latch state-tinc-route-lost") {
		t.Fatal("missing ACTION reaped log line")
	}
}

func TestKnownLatchAgeGated(t *testing.T) {
	e := jfixture(t)
	fresh := filepath.Join(e.state, "state-node-overloaded")
	stale := filepath.Join(e.state, "state-conntrack-pressure")
	testutil.WriteFile(t, fresh, "1\n")
	testutil.WriteFile(t, stale, "1\n")
	ageFile(t, stale, 25*time.Hour) // the ~11h field case, past 24h

	e.j.Sweep(context.Background())

	if !fileExists(fresh) {
		t.Fatal("fresh known latch reaped — age gate broken")
	}
	if fileExists(stale) {
		t.Fatal("stale known latch (>maxage) survived")
	}
	if !e.logContains(t, "ACTION: reaped stale latch state-conntrack-pressure") {
		t.Fatal("missing ACTION reaped log line")
	}
}

func TestParameterizedPrefixLatch(t *testing.T) {
	e := jfixture(t)
	fresh := filepath.Join(e.state, "state-apiserver-backend-stale-10-0-0-1")
	stale := filepath.Join(e.state, "state-apiserver-backend-stale-10-0-0-2")
	testutil.WriteFile(t, fresh, "1\n")
	testutil.WriteFile(t, stale, "1\n")
	ageFile(t, stale, 48*time.Hour)

	e.j.Sweep(context.Background())

	if !fileExists(fresh) {
		t.Fatal("fresh parameterized latch reaped")
	}
	if fileExists(stale) {
		t.Fatal("aged parameterized latch survived")
	}
}

func TestPreservesNonStateFiles(t *testing.T) {
	e := jfixture(t)
	keep := []string{
		"last-restart",          // rate budget — deleting bypasses cooldowns
		"last-cilium-restart",   // rate budget
		"last-run",              // reporter heartbeat
		"installed",             // watchdog-installed marker
		"egress-state-10.1.2.3", // egress relay committed state
		"egress-ctr-10.1.2.3",   // egress hit counter
		"consecutive-sig13-gap", // consecutive counter
		"wedged-seen-deadbeef",  // ctr wedge marker
		"oomloop-seen",          // controllerhygiene marker
		"dnsfb-pin-8.8.8.8",     // dns fallback pin record
		".tmp-state-x",          // in-flight stateEnter tmp
		"apibe-gap-10-0-0-1",    // apiprober rv gap file
		"fail2ban-banned",       // jail counts for hostmetrics
	}
	for _, n := range keep {
		p := filepath.Join(e.state, n)
		testutil.WriteFile(t, p, "1\n")
		ageFile(t, p, 96*time.Hour) // even very old non-state files stay
	}
	e.j.Sweep(context.Background())
	for _, n := range keep {
		if !fileExists(filepath.Join(e.state, n)) {
			t.Fatalf("non-state file %s removed", n)
		}
	}
}

func TestSkipsStateDirectory(t *testing.T) {
	e := jfixture(t)
	dir := filepath.Join(e.state, "state-weird-dir")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	e.j.Sweep(context.Background())
	if !fileExists(dir) {
		t.Fatal("state-* directory removed")
	}
	if !e.logContains(t, "suspect: state dir entry state-weird-dir is a directory") {
		t.Fatal("missing suspect log for state dir entry")
	}
}

func TestMissingStateDirAbortsCleanly(t *testing.T) {
	e := jfixture(t)
	if err := os.RemoveAll(e.state); err != nil {
		t.Fatal(err)
	}
	e.j.Sweep(context.Background()) // must not panic
	got := promtest.ToFloat64(
		e.j.cycles.WithLabelValues(checkLatchReaper, "abort"))
	if got != 1 {
		t.Fatalf("latch-reaper abort=%v want 1", got)
	}
}

func TestMetricsBumpOnReap(t *testing.T) {
	e := jfixture(t)
	p := filepath.Join(e.state, "state-bogus-old-check")
	testutil.WriteFile(t, p, "1\n")
	ageFile(t, p, 25*time.Hour) // unknown names reap past max-age too
	e.j.Sweep(context.Background())
	if got := promtest.ToFloat64(
		e.j.actions.WithLabelValues(checkLatchReaper, "reap")); got != 1 {
		t.Fatalf("reap action count=%v want 1", got)
	}
}

// --- B: ghost systemd units ---

func TestResetFailedGhostUnits(t *testing.T) {
	e := jfixture(t)
	e.sd.On("systemctl list-units", ""+
		"k0sworker.service              loaded    active   running k0s worker\n"+
		"node-watchdog.service          not-found failed   failed  node-watchdog.service\n"+
		"node-watchdog.timer            not-found failed   failed  node-watchdog.timer\n"+
		"nebula-route-guard.service     not-found active   running route guard\n"+
		"node-config-agent.service      not-found failed   failed  node-config-agent.service\n"+
		"unrelated-svc.service          not-found failed   failed  unrelated-svc.service\n"+
		"other.timer                    loaded    active   waiting other timer\n")

	e.j.Sweep(context.Background())

	for _, u := range []string{
		"node-watchdog.service", "node-watchdog.timer",
		"node-config-agent.service", "nebula-route-guard.service",
	} {
		if !e.sd.Ran("systemctl reset-failed " + u) {
			t.Fatalf("reset-failed missing for ghost unit %s (cmds=%v)", u, e.sd.Cmds())
		}
	}
	// The not-found-but-active ghost must be STOPPED (retired code
	// still running), then its residue cleared.
	if !e.sd.Ran("systemctl stop nebula-route-guard.service") {
		t.Fatalf("stop missing for active ghost unit (cmds=%v)", e.sd.Cmds())
	}
	// Non-legacy units are never touched — not even failed ones.
	if e.sd.Ran("reset-failed unrelated-svc.service") ||
		e.sd.Ran("stop unrelated-svc.service") {
		t.Fatalf("non-legacy unit touched (cmds=%v)", e.sd.Cmds())
	}
	if e.sd.Ran("k0sworker") && !e.sd.Ran("list-units") {
		t.Fatal("unrelated command ran")
	}
	if !e.logContains(t, "ACTION: reset-failed ghost unit node-watchdog.service") {
		t.Fatal("missing reset-failed ACTION log")
	}
	if !e.logContains(t, "ACTION: stopped ghost unit nebula-route-guard.service") {
		t.Fatal("missing stopped-ghost ACTION log")
	}
}

func TestUnitsSweepNoGhosts(t *testing.T) {
	e := jfixture(t)
	e.sd.On("systemctl list-units",
		"k0sworker.service loaded active running k0s worker\n"+
			"kubelet.service   loaded active running kubelet\n")

	e.j.Sweep(context.Background())

	if e.sd.Ran("reset-failed") || e.sd.Ran(" stop ") {
		t.Fatalf("ghost actions on a clean host (cmds=%v)", e.sd.Cmds())
	}
}

func TestUnitsSweepGatedWithoutSystemd(t *testing.T) {
	e := jfixture(t)
	j, err := New(Config{
		WatchdogStateDir: e.state,
		WatchdogLogFile:  e.logFile,
		ProcRoot:         e.proc,
		Systemd:          nil,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.j = j
	p := filepath.Join(e.state, "state-ghost-from-old-check")
	testutil.WriteFile(t, p, "1\n")
	ageFile(t, p, 25*time.Hour) // past max-age — reaps unknown names too

	e.j.Sweep(context.Background())

	// The units sweep gates but the latch sweep still works.
	if fileExists(filepath.Join(e.state, "state-ghost-from-old-check")) {
		t.Fatal("latch sweep skipped when systemd unwired")
	}
	if got := promtest.ToFloat64(
		e.j.cycles.WithLabelValues(checkLegacyUnits, "gated")); got != 1 {
		t.Fatalf("legacy-units gated=%v want 1", got)
	}
	if len(e.sd.Cmds()) != 0 {
		t.Fatalf("systemd commands ran with nil client: %v", e.sd.Cmds())
	}
}

// --- B: orphan `ip monitor` ---

func TestKillsOrphanIPMonitor(t *testing.T) {
	e := jfixture(t)
	// The field case: `ip -ts monitor` reparented to init after the
	// retired route-guard unit was pruned.
	e.mkProc(t, 4242, 1, "/sbin/ip", "-ts", "monitor", "rule", "route")

	e.j.Sweep(context.Background())

	if len(e.kills) != 1 || e.kills[0].pid != 4242 || e.kills[0].sig != syscall.SIGKILL {
		t.Fatalf("kills=%v want one SIGKILL on pid 4242", e.kills)
	}
	if !e.logContains(t, "ACTION: killed orphan ip monitor pid=4242") {
		t.Fatal("missing orphan-kill ACTION log")
	}
}

func TestKillsLegacyScriptTree(t *testing.T) {
	e := jfixture(t)
	// The retired script itself still loops → kill the loop AND the
	// monitor so it can't respawn.
	e.mkProc(t, 5555, 1, "/bin/sh", "/usr/local/sbin/nebula-route-guard.sh")
	e.mkProc(t, 4343, 5555, "/usr/sbin/ip", "-ts", "monitor", "rule", "route")

	e.j.Sweep(context.Background())

	if len(e.kills) != 2 {
		t.Fatalf("kills=%v want 2 (parent + monitor)", e.kills)
	}
	got := map[int]bool{}
	for _, k := range e.kills {
		got[k.pid] = true
	}
	if !got[5555] || !got[4343] {
		t.Fatalf("kills=%v want pids 5555+4343", e.kills)
	}
}

func TestSkipsIPMonitorWithForeignParent(t *testing.T) {
	e := jfixture(t)
	// Ambiguous ownership → suspect, never kill.
	e.mkProc(t, 6666, 1, "/usr/sbin/NetworkManager", "--no-daemon")
	e.mkProc(t, 4444, 6666, "/sbin/ip", "monitor", "address")

	e.j.Sweep(context.Background())

	if len(e.kills) != 0 {
		t.Fatalf("kills=%v want none (foreign parent)", e.kills)
	}
	if !e.logContains(t, "suspect: ip monitor pid=4444 has non-legacy parent pid=6666") {
		t.Fatal("missing suspect log for foreign-parent monitor")
	}
}

func TestIgnoresNonMonitorIPCommands(t *testing.T) {
	e := jfixture(t)
	// `ip netns monitor` is a different subcommand — first non-flag
	// arg is "netns", not "monitor".
	e.mkProc(t, 4545, 1, "ip", "netns", "monitor", "/var/run/netns")
	e.mkProc(t, 4646, 1, "ip", "-o", "link", "show")
	// Not ip at all.
	e.mkProc(t, 4747, 1, "/usr/sbin/sshd", "-D")

	e.j.Sweep(context.Background())

	if len(e.kills) != 0 {
		t.Fatalf("kills=%v want none (no monitor processes)", e.kills)
	}
}

// The base latches (A4/B1/B4/A2) must be registered in
// knownLatchNames — sweepLatches deletes unregistered state-* files
// immediately, so a missing entry would eat the latch the moment a
// check writes it.
func TestRuntimeDatapathLatchesAreKnown(t *testing.T) {
	e := jfixture(t)
	for _, n := range []string{
		"kubelet-syncloop-down", "containerd-sock-down",
		"cilium-envoy-down", "cilium-mtu-drift", "zombie-storm",
	} {
		testutil.WriteFile(t, filepath.Join(e.state, "state-"+n), "1\n")
	}
	e.j.Sweep(context.Background())
	for _, n := range []string{
		"kubelet-syncloop-down", "containerd-sock-down",
		"cilium-envoy-down", "cilium-mtu-drift", "zombie-storm",
	} {
		if !fileExists(filepath.Join(e.state, "state-"+n)) {
			t.Fatalf("registered latch state-%s was reaped as unknown", n)
		}
	}
}

// The infra latches must be registered in knownLatchNames —
// sweepLatches deletes unregistered state-* files immediately, so a
// missing entry would eat the latch the moment a check writes it.
func TestPressureFleetLatchesAreKnown(t *testing.T) {
	e := jfixture(t)
	names := []string{
		"cilium-bpf-map-pressure", "psi-memory-thrash",
		"kernel-keys-pressure", "cp-cert-reload-stale",
		// Latches whose owners live in other subsystems but which
		// the janitor must know too (already registered — guard
		// against regression).
		"nebula-isolated", "nebula-degraded", "cilium-envoy-down",
		"cilium-ipam-exhausted", "spegel-mirror-degraded",
		"calico-veth-leak", "calico-felix-down", "fail2ban-down",
		"conntrack-pressure",
	}
	for _, n := range names {
		testutil.WriteFile(t, filepath.Join(e.state, "state-"+n), "1\n")
	}
	e.j.Sweep(context.Background())
	for _, n := range names {
		if !fileExists(filepath.Join(e.state, "state-"+n)) {
			t.Fatalf("registered latch state-%s was reaped as unknown", n)
		}
	}
}

// The leak-pressure latches must be registered in knownLatchNames —
// sweepLatches deletes unregistered state-* files immediately, so a
// missing entry would eat the latch the moment a check writes it.
func TestClockKernelNebulaLatchesAreKnown(t *testing.T) {
	e := jfixture(t)
	names := []string{
		"clock-unsync", "kernel-slab-leak", "nebula-pmtu-blackhole",
	}
	for _, n := range names {
		testutil.WriteFile(t, filepath.Join(e.state, "state-"+n), "1\n")
	}
	e.j.Sweep(context.Background())
	for _, n := range names {
		if !fileExists(filepath.Join(e.state, "state-"+n)) {
			t.Fatalf("registered latch state-%s was reaped as unknown", n)
		}
	}
}

// --- Name + Run contracts ---

func TestNameIdentifiesJanitor(t *testing.T) {
	if got := jfixture(t).j.Name(); got != "janitor" {
		t.Fatalf("Name()=%q want janitor", got)
	}
}

func TestRunSweepsOnceThenReturnsOnCancelledContext(t *testing.T) {
	e := jfixture(t)
	// One stale latch past LatchMaxAge — the sweep must reap it.
	latch := filepath.Join(e.state, "state-tinc-route-lost")
	testutil.WriteFile(t, latch, "1\n")
	ageFile(t, latch, 48*time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cycle.Run executes the sweep once, then sees ctx done
	e.j.Run(ctx)
	if fileExists(latch) {
		t.Fatal("Run must execute one sweep before honouring cancellation")
	}
}

// --- Config defaults + construction ---

// Zero-valued knobs must fall back to the host-fs defaults — a
// caller that forgets a path silently sweeping /host/var/lib/
// node-watchdog on a dev box would be worse than failing.
func TestApplyDefaults(t *testing.T) {
	j, err := New(Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := j.cfg
	if cfg.Interval != defaultInterval {
		t.Fatalf("Interval=%v want %v", cfg.Interval, defaultInterval)
	}
	if cfg.WatchdogStateDir != defaultWatchdogStateDir {
		t.Fatalf("WatchdogStateDir=%q want %q", cfg.WatchdogStateDir, defaultWatchdogStateDir)
	}
	if cfg.WatchdogLogFile != defaultWatchdogLogFile {
		t.Fatalf("WatchdogLogFile=%q want %q", cfg.WatchdogLogFile, defaultWatchdogLogFile)
	}
	if cfg.ProcRoot != defaultProcRoot {
		t.Fatalf("ProcRoot=%q want %q", cfg.ProcRoot, defaultProcRoot)
	}
	if cfg.LatchMaxAge != latchMaxAge {
		t.Fatalf("LatchMaxAge=%v want %v", cfg.LatchMaxAge, latchMaxAge)
	}
	if cfg.killFn == nil {
		t.Fatal("killFn seam not defaulted")
	}
	// The default killFn is the real syscall — probe with signal 0
	// (existence check, no delivery): our own pid exists, and a pid
	// above kernel pid_max can never.
	if err := cfg.killFn(os.Getpid(), 0); err != nil {
		t.Fatalf("killFn(self, 0)=%v want nil", err)
	}
	if err := cfg.killFn(9999999, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("killFn(nonexistent, 0)=%v want ESRCH", err)
	}
	if cfg.Clock == nil {
		t.Fatal("Clock not defaulted")
	}
}

// A second New on the same registry collides on the shared metric
// names — the constructor must report it instead of panicking in
// RegisterAll.
func TestNewRejectsDuplicateMetricRegistration(t *testing.T) {
	e := jfixture(t)
	cfg := Config{
		Interval:         time.Hour,
		WatchdogStateDir: e.state,
		WatchdogLogFile:  e.logFile,
		ProcRoot:         e.proc,
		Systemd:          e.sdClient(),
	}
	reg := prometheus.NewRegistry()
	if _, err := New(cfg, reg); err != nil {
		t.Fatalf("first New on a fresh registry failed: %v", err)
	}
	if _, err := New(cfg, reg); err == nil {
		t.Fatal("second New must fail on duplicate metric registration")
	}
}

// --- A: latch reaper failure paths ---

// A stale latch that cannot be unlinked (read-only state dir) must
// be logged suspect and left in place — never counted as reaped.
func TestStaleLatchRemoveFailureSuspects(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores dir write-bit — cannot simulate unlink failure")
	}
	e := jfixture(t)
	stale := filepath.Join(e.state, "state-tinc-route-lost")
	testutil.WriteFile(t, stale, "1\n")
	ageFile(t, stale, 25*time.Hour)
	if err := os.Chmod(e.state, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(e.state, 0o755) })

	e.j.Sweep(context.Background())

	if !fileExists(stale) {
		t.Fatal("stale latch vanished despite unlink failure")
	}
	if !e.logContains(t, "suspect: rm stale latch state-tinc-route-lost") {
		t.Fatal("missing suspect log for failed unlink")
	}
	if got := promtest.ToFloat64(
		e.j.actions.WithLabelValues(checkLatchReaper, "reap")); got != 0 {
		t.Fatalf("reap action count=%v want 0", got)
	}
}

// --- B: ghost unit remedy failures ---

// A ghost that is still running retired code but refuses to stop is
// suspect — and reset-failed must NOT run for it (the stop is the
// precondition: clearing failure state under a live unit would
// just re-fail it).
func TestStopGhostUnitFailureSuspects(t *testing.T) {
	e := jfixture(t)
	e.sd.On("systemctl list-units",
		"nebula-route-guard.service not-found active running route guard\n")
	e.sd.FailOn("systemctl stop", errors.New("systemctl bus unavailable"))

	e.j.Sweep(context.Background())

	if !e.logContains(t, "suspect: stop ghost unit nebula-route-guard.service") {
		t.Fatal("missing suspect log for failed stop")
	}
	if got := promtest.ToFloat64(
		e.j.actions.WithLabelValues(checkLegacyUnits, "stop")); got != 0 {
		t.Fatalf("stop action count=%v want 0", got)
	}
	if e.sd.Ran("reset-failed nebula-route-guard.service") {
		t.Fatal("reset-failed ran despite failed stop")
	}
}

// A failed ghost whose reset-failed call errors is suspect and
// uncounted — systemd keeps the failed record for the next sweep.
func TestResetFailedFailureSuspects(t *testing.T) {
	e := jfixture(t)
	e.sd.On("systemctl list-units",
		"node-watchdog.service not-found failed failed node-watchdog.service\n")
	e.sd.FailOn("systemctl reset-failed", errors.New("bus unavailable"))

	e.j.Sweep(context.Background())

	if !e.logContains(t, "suspect: reset-failed node-watchdog.service") {
		t.Fatal("missing suspect log for failed reset-failed")
	}
	if got := promtest.ToFloat64(
		e.j.actions.WithLabelValues(checkLegacyUnits, "reset_failed")); got != 0 {
		t.Fatalf("reset_failed action count=%v want 0", got)
	}
}

// --- B: orphan `ip monitor` edge cases ---

// A monitor whose /proc/<pid>/stat is unreadable has unknown
// ownership — skipping is the only safe move.
func TestMonitorPPIDUnreadableSkips(t *testing.T) {
	e := jfixture(t)
	dir := filepath.Join(e.proc, "4242")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(dir, "cmdline"),
		"/sbin/ip\x00-ts\x00monitor\x00") // no stat file → PPID fails

	e.j.Sweep(context.Background())

	if len(e.kills) != 0 {
		t.Fatalf("kills=%v want none (ppid unreadable)", e.kills)
	}
	if !e.logContains(t, "suspect: ip monitor pid=4242") ||
		!e.logContains(t, "ppid unreadable") {
		t.Fatal("missing suspect log for unreadable ppid")
	}
}

// The parent existed at stat time but its cmdline read fails (it
// died mid-scan): skip — the kernel reparents the monitor to init
// and the NEXT sweep reaps it as ppid==1.
func TestMonitorParentVanishedMidScanSkips(t *testing.T) {
	e := jfixture(t)
	e.mkProc(t, 4343, 5555, "/usr/sbin/ip", "-ts", "monitor", "rule", "route")
	// Parent 5555: stat present (so PPID resolves) but no cmdline.
	pdir := filepath.Join(e.proc, "5555")
	if err := os.MkdirAll(pdir, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(pdir, "stat"),
		"5555 (dying) S 1 0 0 0 -1 4194304 100 0 0 0 0 0 0 0 20 0 1 0 50 0 0 0\n")

	e.j.Sweep(context.Background())

	if len(e.kills) != 0 {
		t.Fatalf("kills=%v want none (parent vanished)", e.kills)
	}
	if !e.logContains(t, "ppid=5555 vanished mid-scan") {
		t.Fatal("missing suspect log for vanished parent")
	}
}

// A monitor spawned by the agent itself must stay hands-off — the
// live route guard is in-process, so this is "should never happen";
// if it ever does, log suspect, kill nothing.
func TestMonitorParentedByAgentSkips(t *testing.T) {
	e := jfixture(t)
	e.mkProc(t, 7000, 1, "/usr/local/bin/node-host-agent", "--standalone")
	e.mkProc(t, 4444, 7000, "/sbin/ip", "monitor", "address")

	e.j.Sweep(context.Background())

	if len(e.kills) != 0 {
		t.Fatalf("kills=%v want none (agent parent)", e.kills)
	}
	if !e.logContains(t, "parented by agent pid=7000") {
		t.Fatal("missing suspect log for agent parent")
	}
}

// Every kill is best-effort — a failed SIGKILL (e.g. EPERM) is
// logged suspect for BOTH the legacy loop and the monitor instead
// of surfacing.
func TestKillFailuresLogSuspect(t *testing.T) {
	e := jfixture(t)
	e.j.cfg.killFn = func(int, syscall.Signal) error {
		return syscall.EPERM
	}
	e.mkProc(t, 5555, 1, "/bin/sh", "/usr/local/sbin/nebula-route-guard.sh")
	e.mkProc(t, 4343, 5555, "/usr/sbin/ip", "-ts", "monitor", "rule", "route")

	e.j.Sweep(context.Background())

	if len(e.kills) != 0 {
		t.Fatalf("kills=%v want none (all kills fail)", e.kills)
	}
	if !e.logContains(t, "suspect: kill legacy script pid=5555") {
		t.Fatal("missing suspect log for failed legacy-script kill")
	}
	if !e.logContains(t, "suspect: kill orphan ip monitor pid=4343") {
		t.Fatal("missing suspect log for failed monitor kill")
	}
}

// An argv that is ip + flags but no subcommand is not a monitor.
func TestIPMonitorFlagsOnlyArgvNoKill(t *testing.T) {
	e := jfixture(t)
	e.mkProc(t, 4848, 1, "ip", "-ts")

	e.j.Sweep(context.Background())

	if len(e.kills) != 0 {
		t.Fatalf("kills=%v want none (flags-only argv)", e.kills)
	}
}

// An unreadable proc root must not make the monitor sweep no-op
// silently — the skip is logged and the cycle still counts.
func TestProcRootUnreadableSkipsMonitorSweep(t *testing.T) {
	e := jfixture(t)
	j, err := New(Config{
		Interval:         time.Hour,
		WatchdogStateDir: e.state,
		WatchdogLogFile:  e.logFile,
		ProcRoot:         filepath.Join(e.proc, "absent"),
		Systemd:          e.sdClient(),
	}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	e.j = j

	e.j.Sweep(context.Background())

	if !e.logContains(t, "proc root") || !e.logContains(t, "ip monitor sweep skipped") {
		t.Fatal("missing unreadable-proc-root skip log")
	}
	if got := promtest.ToFloat64(
		e.j.cycles.WithLabelValues(checkIPMonitor, "abort")); got != 1 {
		t.Fatalf("ip-monitor abort cycles=%v want 1", got)
	}
}
