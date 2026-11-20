// workerhygiene_test.go — the orchestration suite that stays at the
// parent package: the worker/uptime/WD_SIG gates, the lazy
// once-per-cycle shared env (tasksOnce), the state-store plumbing
// and Run/Name/New contracts. The fixture is the shared
// wdepstest.Fixture — domain check tests live beside their checks
// in the per-domain packages' external test files.
package workerhygiene

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/netlinkx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// env pairs the shared wdepstest fixture with a real *Hygiene —
// wdepstest can't build the Hygiene itself (importing workerhygiene
// would cycle back into this test package). Every consuming test
// package declares this same thin wrapper. In-package tests reach
// check state through Hygiene.Check/wdepstest.Check like the
// domain packages' external test files do.
type env struct {
	*wdepstest.Fixture
	H *Hygiene
}

// fixture builds the shared test environment — the same builder the
// domain packages' fixture wrappers use, plus New + Bind here.
func fixture(t *testing.T, objs ...runtime.Object) *env {
	t.Helper()
	f := wdepstest.New(t, objs...)
	h, err := New(f.Cfg, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	f.Bind(h.Deps)
	return &env{Fixture: f, H: h}
}

// --- worker gate ---

func TestWorkerGateNoUnitNoOp(t *testing.T) {
	e := fixture(t)
	if err := os.Remove(e.UnitFile); err != nil {
		t.Fatal(err)
	}
	// A terminating pod that WOULD be force-deleted if the gate were off.
	p := e.TerminatingPod("stuck", "default", wdepstest.UIDA, 20*time.Minute)
	if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if n := len(wdepstest.DeleteActions(e.CS)); n != 0 {
		t.Fatalf("deletes=%d want 0 on controller gate", n)
	}
	if entries, _ := os.ReadDir(e.StateDir); len(entries) != 0 {
		t.Fatalf("state files written on gated cycle: %v", entries)
	}
}

// --- plumbing ---

func TestStateEnterExitTransitionLogsOnce(t *testing.T) {
	e := fixture(t)
	e.H.State.Enter("test-state", "extra=1")
	e.H.State.Enter("test-state", "extra=1") // idempotent — one log line
	if got := strings.Count(e.LogLines(t), "STATE-ENTER: test-state"); got != 1 {
		t.Fatalf("STATE-ENTER lines=%d want 1", got)
	}
	content, err := os.ReadFile(filepath.Join(e.StateDir, "state-test-state"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Sscanf(strings.TrimSpace(string(content)), "%d", new(int64)); err != nil {
		t.Fatalf("state file content=%q want epoch", content)
	}
	e.H.State.Exit("test-state", nil)
	e.H.State.Exit("test-state", nil)
	if got := strings.Count(e.LogLines(t), "STATE-EXIT: test-state"); got != 1 {
		t.Fatalf("STATE-EXIT lines=%d want 1", got)
	}
}

func TestRateOKSpend(t *testing.T) {
	e := fixture(t)
	name := "last-test"
	if !e.H.State.RateOK(name, 30*time.Minute) {
		t.Fatal("rateOK on absent file want true")
	}
	e.H.State.RateSpend(name)
	if e.H.State.RateOK(name, 30*time.Minute) {
		t.Fatal("rateOK right after spend want false")
	}
	e.Now = e.Now.Add(31 * time.Minute)
	if !e.H.State.RateOK(name, 30*time.Minute) {
		t.Fatal("rateOK after interval want true")
	}
	// Garbage content → 0 → ok (shell parity).
	wdepstest.WriteFile(t, filepath.Join(e.StateDir, name), "garbage\n")
	if !e.H.State.RateOK(name, 30*time.Minute) {
		t.Fatal("rateOK on garbage file want true")
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Interval = time.Hour // only the immediate cycle runs
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.H.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestName(t *testing.T) {
	e := fixture(t)
	if e.H.Name() != "workerhygiene" {
		t.Fatalf("Name()=%q want workerhygiene", e.H.Name())
	}
}

// TestNewRequiresClient: a nil Clientset would nil-pointer panic on
// the first Cycle LIST — New must reject it (never-panic contract).
func TestNewRequiresClient(t *testing.T) {
	if _, err := New(wdeps.Config{}, nil); err == nil {
		t.Fatal("New accepted a nil Client")
	}
}

// --- lazy shared task map (tasksOnce) ---

func TestTaskMapBuiltOnceSharedAcrossChecks(t *testing.T) {
	e := fixture(t)
	e.MkProc(t, 8001, "S", "", "")
	e.MkTask(t, wdepstest.UIDA, "pause", 8001)

	// checkPodTeardown needs the map: a Terminating pod exists
	// (too young to delete — the build is gated on Terminating alone).
	p := e.TerminatingPod("stuck", "default", wdepstest.UIDB, 5*time.Minute)
	if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	// checkDNSResolvDrift needs it too: hostNS set + a Running dns pod.
	wdepstest.WriteFile(t, e.ResolvConf, "nameserver 10.96.0.10\n")
	d := e.DNSPod("node-local-dns-abc12", wdepstest.UIDA)
	if _, err := e.CS.CoreV1().Pods("kube-system").Create(context.Background(), d, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	e.H.Cycle(context.Background())

	if e.H.TaskMapBuilds != 1 {
		t.Fatalf("task map builds=%d want 1 (built once, "+
			"shared between teardown and dns checks)", e.H.TaskMapBuilds)
	}
	if n := len(wdepstest.DeleteActions(e.CS)); n != 0 {
		t.Fatalf("deletes=%d want 0 (terminating pod too young)", n)
	}
}

func TestTaskMapNotBuiltWithoutTriggers(t *testing.T) {
	e := fixture(t)
	e.MkProc(t, 8001, "S", "", "")
	e.MkTask(t, wdepstest.UIDA, "pause", 8001)
	wdepstest.WriteFile(t, e.ResolvConf, "nameserver 10.96.0.10\n")
	// A Running pod that is neither Terminating nor a dns-pod name —
	// the common idle cycle: the task map must stay unbuilt.
	ordinary := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ordinary-app", Namespace: "default", UID: types.UID(wdepstest.UIDB),
		},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), ordinary, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	e.H.Cycle(context.Background())

	// The cilium family pulls the shared snapshot every cycle —
	// builds==1 proves the once-per-cycle ceiling (the old code
	// re-scanned the task roots per check).
	if e.H.TaskMapBuilds != 1 {
		t.Fatalf("task map builds=%d want 1 (one shared build for the cilium checks)", e.H.TaskMapBuilds)
	}
}

func TestTaskMapNotBuiltWhenHostResolvEmpty(t *testing.T) {
	e := fixture(t)
	e.MkProc(t, 8001, "S", "", "")
	e.MkTask(t, wdepstest.UIDA, "pause", 8001)
	// resolv.conf absent → hostNS empty → the dns check never reaches
	// the pause-pid lookup even with a Running dns pod.
	d := e.DNSPod("node-local-dns-abc12", wdepstest.UIDA)
	if _, err := e.CS.CoreV1().Pods("kube-system").Create(context.Background(), d, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	e.H.Cycle(context.Background())

	// Still exactly one build — the dns check's pause-pid lookup
	// shares the cilium family's snapshot.
	if e.H.TaskMapBuilds != 1 {
		t.Fatalf("task map builds=%d want 1 (shared once-per-cycle build)", e.H.TaskMapBuilds)
	}
}

// --- atomic stateEnter tmp naming ---

func TestStateEnterAtomicTmpLeavesNoResidue(t *testing.T) {
	e := fixture(t)
	// A stale tmp file from a crashed earlier write shares the
	// ".tmp-" prefix. Staging names are now unique per writer
	// (.tmp-<base>-<rand>), so a crashed predecessor's file can
	// never be reclaimed by name reuse — it stays as benign crash
	// residue the janitor owns, while the NEW write must leave no
	// tmp of its own. The old "state-<n>.tmp" shape would have
	// surfaced as a phantom hostmetrics watchdog_state series.
	wdepstest.WriteFile(t, filepath.Join(e.StateDir, ".tmp-state-x"), "stale\n")

	e.H.State.Enter("x", "")

	entries, err := os.ReadDir(e.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, en := range entries {
		names = append(names, en.Name())
	}
	slices.Sort(names)
	want := []string{".tmp-state-x", "state-x"}
	if !slices.Equal(names, want) {
		t.Fatalf("state dir after stateEnter=%v want %v "+
			"(stale crash residue kept, no new tmp leaked)", names, want)
	}
}

// SystemdSessionCheck is the deliberate exception: with the worker unit
// inactive it still runs (gated by unit-file + WD_SIG existence) so PID 1
// unresponsiveness stays observable. The healing checks below must gate.
func TestWorkerInactiveGatesHealingChecks(t *testing.T) {
	e := fixture(t)
	e.SDReply["systemctl is-active k0sworker.service"] = "inactive\n"
	e.Probes[wdeps.DefaultKubeletHealthzURL] = errors.New("refused")
	e.H.Cycle(context.Background())
	if e.SDRan("restart k0sworker.service") {
		t.Fatal("checks ran while k0sworker intentionally down")
	}
	for _, chk := range []string{wdeps.CheckStall, wdeps.CheckTeardown, wdeps.CheckKonn, wdeps.CheckDNS} {
		if got := e.H.Cycles.WithLabelValues(chk, "gated"); testutil.ToFloat64(got) != 1 {
			t.Fatalf("%s gated=%v want 1", chk, testutil.ToFloat64(got))
		}
	}
}

func TestSignalDisabledSkipsCheck(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Watchdog = &watchdogconf.Config{Disabled: map[string]bool{"cilium": true}}
	e.MkTask(t, wdepstest.UIDA, "cilium-agent", 0)
	e.Probes[wdeps.DefaultCiliumHealthzURL] = errors.New("refused")
	e.H.Cycle(context.Background())
	if got := e.H.Cycles.WithLabelValues(wdeps.CheckCilium, "disabled"); testutil.ToFloat64(got) != 1 {
		t.Fatalf("cilium disabled=%v want 1", testutil.ToFloat64(got))
	}
}

// TestRateTrySpendAtomic: the shared last-* budgets are checked and
// spent by BOTH the feeder goroutine and Cycle — check+spend under
// the hoststate store mutex means exactly one winner per window.
func TestRateTrySpendAtomic(t *testing.T) {
	e := fixture(t)
	const n = 8
	var wins atomic.Int64
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			if e.H.State.RateTrySpend("last-restart", e.H.Cfg.MinRestartInterval) {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	if got := wins.Load(); got != 1 {
		t.Fatalf("rateTrySpend wins=%d want 1 (check+spend must be atomic)", got)
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "last-restart")); err != nil {
		t.Fatal("budget file not written by the winner")
	}
}

// --- cycle deadline (controllerhygiene runCycle parity) ---

// TestRunCycleDeadlineAbortsStall: a hung systemd is-active probe
// blocks its exec seam until the cycle ctx dies — the per-cycle
// deadline (Config.CycleTimeout) must interrupt the stall, propagate
// into the child call, log the degraded cycle, and leave the loop
// free to start the next tick.
func TestRunCycleDeadlineAbortsStall(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.CycleTimeout = 60 * time.Millisecond
	var calls atomic.Int64
	started := make(chan struct{}, 2)
	sd := systemd.New(systemd.Config{
		HostRoot: "/",
		RunCmd: func(ctx context.Context, _ []string) (string, error) {
			calls.Add(1)
			select {
			case started <- struct{}{}:
			default:
			}
			<-ctx.Done()
			return "", ctx.Err()
		},
		RunCmdCombined: func(ctx context.Context, argv []string) (string, error) {
			return "", ctx.Err()
		},
	}, systemd.WithProcUptimeFile(filepath.Join(e.ProcDir, "uptime")))
	e.H.Cfg.Systemd = sd

	// Cycle one: the stall is aborted at the deadline and logged.
	start := time.Now()
	e.H.runCycle(context.Background())
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("cycle ran %s — deadline did not abort the stall", took)
	}
	<-started // runCycle returned → the seam was called and released
	if log := e.LogLines(t); !strings.Contains(log, "cycle deadline") {
		t.Fatalf("cycle deadline not logged:\n%s", log)
	}

	// The loop keeps running: the next tick reaches the seam again
	// (the hung exec did not wedge the orchestrator silently).
	e.H.runCycle(context.Background())
	if n := calls.Load(); n < 2 {
		t.Fatalf("seam calls=%d — loop did not reach the next cycle", n)
	}
}

// TestRunLoopTicksPastHungCycle drives Run itself (not just one
// runCycle): with a perma-hung is-active probe, Interval-sized ticks
// still fire after the first deadline abort.
func TestRunLoopTicksPastHungCycle(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Interval = 20 * time.Millisecond
	e.H.Cfg.CycleTimeout = 40 * time.Millisecond
	var calls atomic.Int64
	sd := systemd.New(systemd.Config{
		HostRoot: "/",
		RunCmd: func(ctx context.Context, _ []string) (string, error) {
			calls.Add(1)
			<-ctx.Done()
			return "", ctx.Err()
		},
		RunCmdCombined: func(ctx context.Context, _ []string) (string, error) {
			<-ctx.Done()
			return "", ctx.Err()
		},
	}, systemd.WithProcUptimeFile(filepath.Join(e.ProcDir, "uptime")))
	e.H.Cfg.Systemd = sd

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); e.H.Run(ctx) }()
	// Wait until the seam has been entered at least twice (two ticks
	// through the deadline), then tear Run down.
	deadline := time.After(5 * time.Second)
	for calls.Load() < 2 {
		select {
		case <-deadline:
			t.Fatal("Run never ticked past the first hung cycle")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	<-done
}

// --- pidsOnce nil-cache ---

// TestPidsOnceErrorNotCached: a failed PIDs() read must NOT cache a
// nil slice for the rest of the cycle — later pidsOnce calls retry,
// and once the read succeeds the real pid list comes through.
func TestPidsOnceErrorNotCached(t *testing.T) {
	e := fixture(t)
	e.MkProc(t, 4242, "S", "", "")
	// Point the /proc view at a missing root: UptimeSeconds errors
	// (uptime gate opens on read error) and PIDs() fails.
	missing := filepath.Join(t.TempDir(), "proc-gone")
	orig := e.H.Deps.Proc
	e.H.Deps.Proc = procfs.New(missing)
	e.H.Cycle(context.Background())

	env := *e.H.envCell
	if p := env.PidsOnce(); p != nil {
		t.Fatalf("pidsOnce on unreadable root returned %v — error must not resolve to pids", p)
	}
	if p := env.PidsOnce(); p != nil {
		t.Fatalf("second pidsOnce call returned %v — the error was cached", p)
	}
	if n := strings.Count(e.LogLines(t), "proc pid listing failed"); n != 1 {
		t.Fatalf("PIDs failure logged %dx, want exactly 1 per cycle:\n%s", n, e.LogLines(t))
	}

	// Root back: the SAME cycle's closure retries and returns the
	// real listing (no cached nil), stably across further calls.
	e.H.Deps.Proc = orig
	for i := 0; i < 3; i++ {
		p := env.PidsOnce()
		if len(p) != 1 || p[0] != 4242 {
			t.Fatalf("pidsOnce after recovery = %v, want [4242]", p)
		}
	}
}

// --- ConfigFromEnv forwarding + Feeder accessor ---

func TestConfigFromEnvForwardsToWdeps(t *testing.T) {
	d := wdeps.EnvDeps{}
	d.NodeName = "node-fwd"
	d.WatchdogStateDir = "/tmp/fwd-watchdog"
	d.JournalDirs = []string{"/var/log/journal"}
	cs := k8sfake.NewSimpleClientset()
	d.Client = cs
	cfg := ConfigFromEnv(d)
	if cfg.NodeName != "node-fwd" {
		t.Fatalf("NodeName=%q want node-fwd", cfg.NodeName)
	}
	if cfg.Client != cs {
		t.Fatal("Client not forwarded")
	}
	if cfg.Base.WatchdogStateDir != "/tmp/fwd-watchdog" {
		t.Fatalf("Base.WatchdogStateDir=%q want /tmp/fwd-watchdog", cfg.Base.WatchdogStateDir)
	}
	if len(cfg.Journal.Dirs) != 1 || cfg.Journal.Dirs[0] != "/var/log/journal" {
		t.Fatalf("Journal.Dirs=%v want [/var/log/journal]", cfg.Journal.Dirs)
	}
}

func TestFeederAccessorReturnsWiredFeeder(t *testing.T) {
	e := fixture(t)
	if e.H.Feeder() == nil {
		t.Fatal("Feeder() must return the wired kubelet watchdog feeder")
	}
}

func TestMountinfoOnceCachesPerCycleAndAllCallersConsumeIt(t *testing.T) {
	e := fixture(t)
	miPath := filepath.Join(t.TempDir(), "mountinfo")
	wdepstest.WriteFile(t, miPath, "1 1 0:1 / / rw - ext4 /dev/vda1 rw\n")
	e.H.Cfg.MountinfoFile = miPath

	// Cycle 1: MountinfoOnce caches the read even if the file changes mid-cycle.
	e.H.Cycle(context.Background())
	wdepstest.WriteFile(t, miPath, "1 1 0:1 / /other rw - ext4 /dev/vda2 rw\n")
	got1, err := e.H.envCell.MountinfoOnce()
	if err != nil || !strings.Contains(string(got1), "/dev/vda1") {
		t.Fatalf("Cycle 1 MountinfoOnce=%q err=%v, want cached /dev/vda1", got1, err)
	}

	// Cycle 2: MountinfoOnce resets and reads the updated file.
	e.H.Cycle(context.Background())
	got2, err := e.H.envCell.MountinfoOnce()
	if err != nil || !strings.Contains(string(got2), "/dev/vda2") {
		t.Fatalf("Cycle 2 MountinfoOnce=%q err=%v, want fresh /dev/vda2", got2, err)
	}

	// Verify all 4 mountinfo callers consume CycleEnv.MountinfoOnce (never raw MountinfoFile).
	e.H.Cfg.MountinfoFile = filepath.Join(t.TempDir(), "missing-on-disk")
	e.DiskUsed = 0.90
	e.H.Cfg.Disk.WLayerSnapshotsDir = filepath.Join(t.TempDir(), "snapshots")
	snapDir := filepath.Join(e.H.Cfg.Disk.WLayerSnapshotsDir, "1", "fs")
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(snapDir, "f"), "data")
	orphanDir := filepath.Join(e.KubepodsDir, wdepstest.UIDA)
	if err := os.MkdirAll(orphanDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stale := e.Now.Add(-2 * time.Hour)
	_ = os.Chtimes(orphanDir, stale, stale)

	onceCalls := 0
	var once sync.Once
	ce := &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        true,
		TasksOnce: func() (map[string][]wdeps.CtrTask, bool) {
			return map[string][]wdeps.CtrTask{}, true
		},
		MountinfoOnce: func() ([]byte, error) {
			once.Do(func() { onceCalls++ })
			return []byte("1 1 0:1 / / rw - ext4 /dev/vda1 rw\n"), nil
		},
	}
	for _, name := range []string{
		wdeps.CheckMountinfo,
		wdeps.CheckWritableLayer,
		wdeps.CheckDiskBloat,
		wdeps.CheckOrphanPodVols,
	} {
		e.H.Check(name).Run(context.Background(), ce)
	}
	if onceCalls != 1 {
		t.Fatalf("MountinfoOnce underlying read=%d want 1 across 4 callers", onceCalls)
	}
	if strings.Contains(e.LogLines(t), "missing-on-disk") {
		t.Fatalf("a check bypassed MountinfoOnce and read MountinfoFile directly:\n%s", e.LogLines(t))
	}
}

func TestCiliumHealthzOnceCallsUnixGetOncePerCycleAndResets(t *testing.T) {
	e := fixture(t)
	e.MkCiliumTask(t, 4242)
	e.MkProc(t, 4243, "S", "", "")
	e.MkTask(t, wdepstest.UIDB, "cilium-envoy", 4243)
	if err := os.MkdirAll(filepath.Join(e.SysNet, "cilium_wg0"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.H.Cfg.Seams.Cilium.WGDump = func(context.Context, *systemd.Client) (string, error) {
		return "pub1\tpsk\t12.0.0.9:51820\t10.0.0.2/32\t1800000000\t100\t200\t25\n", nil
	}
	e.UnixBody = []byte(`{"ipam":{"ipv4":{"used":2,"available":10}},"cluster":{"nodes":[{}]}}`)

	origGet := e.H.Cfg.Seams.Cilium.UnixGet
	healthzCalls := 0
	e.H.Cfg.Seams.Cilium.UnixGet = func(ctx context.Context, sock, path string) ([]byte, error) {
		if path == "/v1/healthz" {
			healthzCalls++
		}
		return origGet(ctx, sock, path)
	}

	e.H.Cycle(context.Background())
	if healthzCalls != 1 {
		t.Fatalf("Cycle 1 /v1/healthz calls=%d want 1 across ipam+envoy+wg", healthzCalls)
	}

	e.H.Cycle(context.Background())
	if healthzCalls != 2 {
		t.Fatalf("Cycle 2 /v1/healthz calls=%d want 2 (cache must reset per cycle)", healthzCalls)
	}
}

// TestInotifyCycleWarmSharedFDCacheProcChmod0111KeepsLatch verifies that
// a transient /proc ReadDir failure (0o111 traverse-only) inside the 60s
// SharedFDCache TTL aborts inotify-pressure-hygiene instead of filtering
// snap.Inotify down to an empty allowed map and clearing LatchInotifyPressure.
func TestInotifyCycleWarmSharedFDCacheProcChmod0111KeepsLatch(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0o111 does not restrict ReadDir under UID 0")
	}
	e := fixture(t)
	e.H.Cfg.Pressure.InotifyMaxInstancesCeiling = 100
	e.H.Cfg.Pressure.InotifyEvictRunawayPod = false
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "sys", "fs", "inotify", "max_user_instances"), "100\n")
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "sys", "fs", "inotify", "max_user_watches"), "8192\n")

	plantInotify := func(instances int) {
		pidDir := filepath.Join(e.ProcDir, "100")
		_ = os.RemoveAll(pidDir)
		fdDir := filepath.Join(pidDir, "fd")
		fiDir := filepath.Join(pidDir, "fdinfo")
		if err := os.MkdirAll(fdDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(fiDir, 0o755); err != nil {
			t.Fatal(err)
		}
		for i := 1; i <= instances; i++ {
			name := fmt.Sprintf("%d", i)
			if err := os.Symlink("anon_inode:inotify", filepath.Join(fdDir, name)); err != nil {
				t.Fatal(err)
			}
			wdepstest.WriteFile(t, filepath.Join(fiDir, name), "")
		}
		wdepstest.WriteFile(t, filepath.Join(pidDir, "cgroup"), "0::/user.slice/session-1.scope\n")
	}

	plantInotify(96)
	ctx := context.Background()
	e.H.Cycle(ctx) // cycle 1 — pending
	e.H.Cycle(ctx) // cycle 2 — arms LatchInotifyPressure
	if !e.H.Deps.State.Exists(latchdefs.LatchInotifyPressure) {
		t.Fatal("expected LatchInotifyPressure to be armed after 2 cycles")
	}

	// Within the 60s SharedFDCache TTL, make /proc ReadDir fail while
	// keeping sysctls and uptime traversable (0o111).
	e.Now = e.Now.Add(10 * time.Second)
	if err := os.Chmod(e.ProcDir, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(e.ProcDir, 0o755) })

	e.H.Cycle(ctx)
	if !e.H.Deps.State.Exists(latchdefs.LatchInotifyPressure) {
		t.Fatalf("transient /proc ReadDir failure inside SharedFDCache TTL cleared LatchInotifyPressure:\n%s",
			e.LogLines(t))
	}
	if strings.Contains(e.LogLines(t), "STATE-EXIT: inotify-pressure") {
		t.Fatalf("unexpected STATE-EXIT: inotify-pressure on /proc ReadDir failure:\n%s",
			e.LogLines(t))
	}

	// Restore /proc, drop usage below clear ratio, advance past 60s TTL -> exits cleanly.
	if err := os.Chmod(e.ProcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	plantInotify(4)
	e.Now = e.Now.Add(61 * time.Second)
	e.H.Cycle(ctx)
	if e.H.Deps.State.Exists(latchdefs.LatchInotifyPressure) {
		t.Fatal("expected LatchInotifyPressure to clear once /proc recovered and usage dropped")
	}
}

func TestAllChecksNilAndHandBuiltCycleEnvDoNotPanic(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	for _, chk := range e.H.checks {
		t.Run(chk.Name(), func(t *testing.T) {
			chk.Run(ctx, nil)
			chk.Run(ctx, &wdeps.CycleEnv{})
			chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
			chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true, APIOK: true})
		})
	}
}

func TestCycleProcChmod0111InconclusiveAcrossFiveChecks(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0o111 does not restrict ReadDir under UID 0")
	}
	e := fixture(t)
	e.H.Cfg.Wave2.HungRuncAgeSec = 180
	e.H.Cfg.Wave2.HungRuncConfirmCycles = 3
	e.H.Cfg.Wave2.HungRuncKillEnabled = true
	e.H.Cfg.Wave2.NetfilterGuardIntervalSec = 0
	e.H.Cfg.Wave2.NetfilterGuardHungCmdSec = 60
	e.H.Cfg.Wave2.NetfilterGuardStuckCycles = 3
	e.H.Cfg.Wave2.NetfilterGuardKillEnabled = true
	e.H.Cfg.Wave2.NetfilterGuardLegacyProbe = false
	e.DiskUsed = 0.90

	// 1. EphemeralPorts: pod netns pid 500 pressured, pid 1 healthy.
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "sys", "net", "ipv4", "ip_local_port_range"),
		"32768 60999\n")
	for _, pair := range []struct {
		pid int
		ns  string
	}{
		{1, "net:[1001]"},
		{500, "net:[5000]"},
	} {
		nsDir := filepath.Join(e.ProcDir, fmt.Sprintf("%d", pair.pid), "ns")
		if err := os.MkdirAll(nsDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(pair.ns, filepath.Join(nsDir, "net")); err != nil {
			t.Fatal(err)
		}
	}
	e.H.Cfg.Seams.Host.TCPTablesFn = func(pid int) (netlinkx.TCPCensus, error) {
		if pid == 500 {
			return netlinkx.TCPCensus{States: map[uint8]int{8: 6000}}, nil
		}
		return netlinkx.TCPCensus{States: map[uint8]int{1: 10}}, nil
	}

	// 2. CtrMeta: orphan shim pid 9550 (ppid=1, aged 16m, dead init).
	e.H.Cfg.CtrTaskRoot = filepath.Join(filepath.Dir(e.CtrDir), "k8s.io")
	orphanID := strings.Repeat("a", 64)
	e.MkStatProc(t, 9550, "containerd-shim", "S", "")
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "9550", "cmdline"),
		"containerd-shim-runc-v2\x00-id\x00"+orphanID+"\x00-namespace\x00k8s.io\x00-address\x00/run/k0s/containerd.sock\x00")
	old16m := e.Now.Add(-16 * time.Minute)
	_ = os.Chtimes(filepath.Join(e.ProcDir, "9550"), old16m, old16m)
	taskDir := filepath.Join(e.H.Cfg.CtrTaskRoot, orphanID)
	wdepstest.WriteFile(t, filepath.Join(taskDir, "init.pid"), "99999\n")
	_ = os.Chtimes(taskDir, old16m, old16m)

	// 3. UnlinkedOpenFiles: 256MiB deleted regular file on pid 4242.
	e.MkStatProc(t, 4242, "app", "S", "")
	fdDir := filepath.Join(e.ProcDir, "4242", "fd")
	if err := os.MkdirAll(fdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/var/log/leaked.log (deleted)", filepath.Join(fdDir, "3")); err != nil {
		t.Fatal(err)
	}
	e.H.Cfg.Seams.Host.DeletedFDStatFn = func(path string) (uint64, uint64, int64, bool) {
		if strings.HasSuffix(path, filepath.Join("4242", "fd", "3")) {
			return 100, 11, int64(256) << 20, true
		}
		return 0, 0, 0, false
	}

	// 4. HungRunc (pid 7100) + 5. NetfilterGuard (pid 6101) with 3-cycle confirm.
	e.MkStatProc(t, 7100, "runc", "S", "do_wait")
	_ = os.Chtimes(filepath.Join(e.ProcDir, "7100"), old16m, old16m)
	e.MkStatProc(t, 6101, "iptables", "S", "")
	_ = os.Chtimes(filepath.Join(e.ProcDir, "6101"), old16m, old16m)

	ctx := context.Background()
	e.H.Cycle(ctx) // cycle 1
	e.H.Cycle(ctx) // cycle 2 -> latches armed, streaks at 2/3

	if !e.H.Deps.State.Exists(latchdefs.LatchEphemeralPortPressure) {
		t.Fatal("setup: LatchEphemeralPortPressure not armed")
	}
	if !e.H.Deps.State.Exists(latchdefs.LatchContainerdCorrupt) {
		t.Fatal("setup: LatchContainerdCorrupt not armed")
	}
	if e.H.UnlinkedOpenFileBytes != int64(256)<<20 || e.H.UnlinkedOpenFileCount != 1 {
		t.Fatalf("setup: unlinked gauges=%d/%d want 256MiB/1",
			e.H.UnlinkedOpenFileBytes, e.H.UnlinkedOpenFileCount)
	}
	if len(e.Kills) != 0 {
		t.Fatalf("setup: unexpected kills before confirm cycle 3: %v", e.Kills)
	}

	// Advance past BloatScanInterval and break /proc ReadDir with 0o111.
	e.Now = e.Now.Add(16 * time.Minute)
	if err := os.Chmod(e.ProcDir, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(e.ProcDir, 0o755) })

	e.H.Cycle(ctx)

	for _, name := range []string{
		wdeps.CheckHungRunc,
		wdeps.CheckNetfilterGuard,
		wdeps.CheckCtrMeta,
		wdeps.CheckEphemeralPorts,
		wdeps.CheckUnlinkedOpenFiles,
	} {
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(name, "inconclusive")); got != 1 {
			t.Fatalf("%s inconclusive cycles=%v want 1", name, got)
		}
	}
	if !e.H.Deps.State.Exists(latchdefs.LatchEphemeralPortPressure) {
		t.Fatal("LatchEphemeralPortPressure cleared during /proc 0o111 cycle")
	}
	if !e.H.Deps.State.Exists(latchdefs.LatchContainerdCorrupt) {
		t.Fatal("LatchContainerdCorrupt cleared during /proc 0o111 cycle")
	}
	if e.H.UnlinkedOpenFileBytes != int64(256)<<20 || e.H.UnlinkedOpenFileCount != 1 {
		t.Fatalf("unlinked gauges clobbered during /proc 0o111 cycle: %d/%d",
			e.H.UnlinkedOpenFileBytes, e.H.UnlinkedOpenFileCount)
	}

	// Restore /proc: cycle 3 confirms HungRunc (7100) and NetfilterGuard (6101)
	// immediately, proving both streaks were preserved across the 0o111 cycle.
	if err := os.Chmod(e.ProcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(ctx)
	killedPIDs := map[int]bool{}
	for _, k := range e.Kills {
		killedPIDs[k.PID] = true
	}
	if !killedPIDs[7100] || !killedPIDs[6101] {
		t.Fatalf("streaks lost across 0o111 cycle: kills=%v want pids 7100 and 6101", e.Kills)
	}
}

func TestCycleVMAPressureAndInotifyColdFDCacheProcChmod0111Recovery(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0111 does not block root")
	}
	e := fixture(t)
	ctx := context.Background()

	// Seed VMA pressure fixture (90/100 = 0.90) with ceiling=100 so max_map_count stays 100.
	e.H.Cfg.Wave3.VMAMaxCeiling = 100
	if err := os.MkdirAll(filepath.Join(e.H.Cfg.Runtime.CgroupRoot, "kubepods.slice"), 0o755); err != nil {
		t.Fatal(err)
	}
	sysVM := filepath.Join(e.ProcDir, "sys", "vm")
	if err := os.MkdirAll(sysVM, 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(sysVM, "max_map_count"), "100\n")

	// Seed Inotify sysctls as well so InotifyPressureCheck reaches scanInotify.
	sysInotify := filepath.Join(e.ProcDir, "sys", "fs", "inotify")
	if err := os.MkdirAll(sysInotify, 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(sysInotify, "max_user_instances"), "128\n")
	wdepstest.WriteFile(t, filepath.Join(sysInotify, "max_user_watches"), "8192\n")

	pidDir := filepath.Join(e.ProcDir, "400")
	if err := os.MkdirAll(filepath.Join(pidDir, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	fields := make([]string, 21)
	fields[0] = "S"
	for i := 1; i < 20; i++ {
		fields[i] = "0"
	}
	fields[20] = "1048576"
	wdepstest.WriteFile(t, filepath.Join(pidDir, "stat"), "400 (app) "+strings.Join(fields, " ")+"\n")
	var mapsBuf strings.Builder
	for i := range 90 {
		fmt.Fprintf(&mapsBuf, "%08x-%08x r--p 00000000 00:00 0\n", i*4096, (i+1)*4096)
	}
	wdepstest.WriteFile(t, filepath.Join(pidDir, "maps"), mapsBuf.String())

	// Cycle 1: warm VMA ratio to 0.90, then make /proc 0o111 BEFORE InotifyPressureCheck runs?
	// Run a separate fresh ProcRoot for cold SharedFDCache, or test VMA preservation here and
	// cold SharedFDCache recovery on a dedicated Cycle!
	e.H.Cycle(ctx)
	if e.H.Series.VMAMaxUtilRatio != 0.90 {
		t.Fatalf("Cycle 1 VMAMaxUtilRatio=%v want 0.90", e.H.Series.VMAMaxUtilRatio)
	}

	// Cycle 2: /proc 0o111 -> VMAMaxUtilRatio must remain 0.90 (not clobbered to 0).
	if err := os.Chmod(e.ProcDir, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(e.ProcDir, 0o755) })
	e.H.Cycle(ctx)
	if e.H.Series.VMAMaxUtilRatio != 0.90 {
		t.Fatalf("Cycle 2 (/proc 0o111) clobbered VMAMaxUtilRatio=%v want 0.90", e.H.Series.VMAMaxUtilRatio)
	}

	// Separate fixture so SharedFDCache starts genuinely cold on 0o111 /proc.
	e2 := fixture(t)
	sysInotify2 := filepath.Join(e2.ProcDir, "sys", "fs", "inotify")
	if err := os.MkdirAll(sysInotify2, 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(sysInotify2, "max_user_instances"), "128\n")
	wdepstest.WriteFile(t, filepath.Join(sysInotify2, "max_user_watches"), "8192\n")
	if err := os.MkdirAll(filepath.Join(e2.ProcDir, "400", "fd"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(e2.ProcDir, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(e2.ProcDir, 0o755) })
	e2.H.Cycle(ctx) // cold SharedFDCache caches ProcOK=false
	if got := testutil.ToFloat64(e2.H.Cycles.WithLabelValues(wdeps.CheckInotifyHygiene, "abort")); got != 1 {
		t.Fatalf("Inotify abort cycles=%v want 1", got)
	}

	// Restore /proc to 0o755 and advance +10s (< 60s TTL): Inotify must recover immediately to "ok".
	if err := os.Chmod(e2.ProcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	e2.Now = e2.Now.Add(10 * time.Second)
	e2.H.Cycle(ctx)
	if got := testutil.ToFloat64(e2.H.Cycles.WithLabelValues(wdeps.CheckInotifyHygiene, "ok")); got != 1 {
		t.Fatalf("Inotify ok cycles=%v want 1 at +10s recovery", got)
	}

	// Verify statsOnce retry semantics when /proc recovers mid-cycle.
	if err := os.Chmod(e2.ProcDir, 0o111); err != nil {
		t.Fatal(err)
	}
	e2.H.Cycle(ctx)
	e2.H.envCell.StatsOnce()
	if e2.H.envCell.PidsOK() {
		t.Fatal("expected PidsOK=false on 0o111 /proc")
	}
	if err := os.Chmod(e2.ProcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(e2.ProcDir, "400", "stat"), "400 (app) "+strings.Join(fields, " ")+"\n")
	gotStats := e2.H.envCell.StatsOnce()
	if !e2.H.envCell.PidsOK() || len(gotStats) == 0 {
		t.Fatalf("statsOnce did not retry after /proc recovery: pidsOK=%v stats=%v", e2.H.envCell.PidsOK(), gotStats)
	}
}

func TestCycleCiliumSysClassNetChmod0000AndENOENTRecovery(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	e := fixture(t)
	ctx := context.Background()

	// Seed cilium-mtu drift latch (neb1=1300, cilium_net=1500),
	// cilium_wg0 peer wipe latch, and cilium_host for LRP.
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "neb1", "mtu"), "1300\n")
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "cilium_net", "mtu"), "1500\n")
	if err := os.MkdirAll(filepath.Join(e.SysNet, "cilium_wg0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(e.SysNet, "cilium_host"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.MkStatProc(t, 4242, "cilium-agent", "S", "")
	e.MkTask(t, wdepstest.UIDB, "cilium-agent", 4242)
	e.UnixBody = []byte(`{"cluster":{"nodes":[{},{}]}}`)
	e.H.Cfg.Seams.Cilium.WGDump = func(_ context.Context, _ *systemd.Client) (string, error) {
		return "pubA\tpsk\t12.0.0.9:51820\t(none)\t0\t0\t0\t25\n", nil
	}

	e.H.Cycle(ctx)
	e.H.Cycle(ctx) // arms LatchCiliumMTUDrift and LatchCiliumWGPeerWipe
	if !e.H.State.Exists(latchdefs.LatchCiliumMTUDrift) {
		t.Fatal("setup: LatchCiliumMTUDrift not armed")
	}
	if !e.H.State.Exists(latchdefs.LatchCiliumWGPeerWipe) {
		t.Fatal("setup: LatchCiliumWGPeerWipe not armed")
	}

	// SysClassNet 0o000 -> all 3 cilium checks must abort without clearing latches.
	if err := os.Chmod(e.SysNet, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(e.SysNet, 0o755) })
	e.H.Cycle(ctx)

	for _, chkName := range []string{wdeps.CheckCiliumWG, wdeps.CheckCiliumMTU, wdeps.CheckCiliumLRP} {
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(chkName, "abort")); got != 1 {
			t.Fatalf("%s abort cycles=%v want 1 on SysClassNet 0o000", chkName, got)
		}
	}
	if !e.H.State.Exists(latchdefs.LatchCiliumMTUDrift) {
		t.Fatal("LatchCiliumMTUDrift exited during SysClassNet 0o000")
	}
	if !e.H.State.Exists(latchdefs.LatchCiliumWGPeerWipe) {
		t.Fatal("LatchCiliumWGPeerWipe exited during SysClassNet 0o000")
	}

	// Restore SysClassNet and remove interfaces (ENOENT) -> latches clear cleanly.
	if err := os.Chmod(e.SysNet, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"neb1", "cilium_wg0", "cilium_host"} {
		if err := os.RemoveAll(filepath.Join(e.SysNet, dir)); err != nil {
			t.Fatal(err)
		}
	}
	e.H.Cycle(ctx)
	if e.H.State.Exists(latchdefs.LatchCiliumMTUDrift) {
		t.Fatal("LatchCiliumMTUDrift should exit on ENOENT")
	}
	if e.H.State.Exists(latchdefs.LatchCiliumWGPeerWipe) {
		t.Fatal("LatchCiliumWGPeerWipe should exit on ENOENT")
	}
}
