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

func TestWorkerInactiveGatesAllChecks(t *testing.T) {
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
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e.H.State.RateTrySpend("last-restart", e.H.Cfg.MinRestartInterval) {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := wins.Load(); got != 1 {
		t.Fatalf("rateTrySpend wins=%d want 1 (check+spend must be atomic)", got)
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "last-restart")); err != nil {
		t.Fatal("budget file not written by the winner")
	}
}
