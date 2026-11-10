// guards_run_internal_test.go — package-internal coverage for the
// guards-domain Check.Run cycles (psi_thrash.go, spegel.go,
// calico.go, dstate_scopes.go): the fixture drives each Run through
// its full decision tree — gating, aborts, streak confirmations,
// latch entry/exit and the budgeted remedies — against the shared
// wdepstest fake host tree.
package guards

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8stesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// runEnv builds the CycleEnv an active worker cycle hands to checks.
func runEnv(pods ...corev1.Pod) *wdeps.CycleEnv {
	return &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        true,
		Pods:         pods,
		PidsOnce:     wdepstest.PidsOf(),
	}
}

// deleteUIDPrecondition installs a fall-through "delete pods"
// reactor that captures the UID precondition the guard hands the
// fake clientset ("" when the DeleteOptions carry no Preconditions).
// The false return lets the default tracker reaction run, so the
// delete still lands and every existing post-delete assertion holds.
// This is the regression assert for the four grace-0 pod remedies
// (calico felix/wireguard, spegel stale-sock/not-ready): a listing→
// delete race recycling the pod name must 409 on the apiserver, and
// it can only do that when the delete carries Preconditions{UID}.
func deleteUIDPrecondition(f *wdepstest.Fixture) *types.UID {
	var got types.UID
	f.CS.PrependReactor("delete", "pods",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			if del, ok := action.(k8stesting.DeleteAction); ok {
				if pre := del.GetDeleteOptions().Preconditions; pre != nil &&
					pre.UID != nil {
					got = *pre.UID
				}
			}
			return false, nil, nil
		})
	return &got
}

// latchPath is the watchdog state file behind a latch name.
func latchPath(t *testing.T, d *wdeps.Deps, name string) string {
	t.Helper()
	return filepath.Join(d.Cfg.WatchdogStateDir, "state-"+name)
}

// requireLatch asserts the latch file exists (or not).
func requireLatch(t *testing.T, d *wdeps.Deps, name string, want bool) {
	t.Helper()
	_, err := os.Stat(latchPath(t, d, name))
	if want && err != nil {
		t.Fatalf("state-%s latch missing: %v", name, err)
	}
	if !want && !os.IsNotExist(err) {
		t.Fatalf("state-%s latch must be absent, err=%v", name, err)
	}
}

// --- psi_thrash.go Run ---

// psiProcFiles writes the pressure/memory + meminfo pair the check
// reads; slabUnrecKB=0 leaves SUnreclaim out (no slab leak).
func psiProcFiles(t *testing.T, d *wdeps.Deps, fullAvg60 float64, availKB, totalKB, slabUnrecKB int) {
	t.Helper()
	wdepstest.WriteFile(t, filepath.Join(d.Cfg.ProcRoot, "pressure", "memory"),
		"some avg10=1.00 avg60=1.00 avg300=1.00 total=1\n"+
			"full avg10=1.00 avg60="+strconv.FormatFloat(fullAvg60, 'f', 2, 64)+
			" avg300=1.00 total=1\n")
	mem := "MemTotal: " + strconv.Itoa(totalKB) + " kB\n" +
		"MemAvailable: " + strconv.Itoa(availKB) + " kB\n"
	if slabUnrecKB > 0 {
		mem += "SUnreclaim: " + strconv.Itoa(slabUnrecKB) + " kB\n"
	}
	mem += "PageTables: 1000 kB\n"
	wdepstest.WriteFile(t, filepath.Join(d.Cfg.ProcRoot, "meminfo"), mem)
	// drop_caches write target — present on every real host.
	wdepstest.WriteFile(t, filepath.Join(d.Cfg.ProcRoot, "sys", "vm", "drop_caches"), "0\n")
}

func TestPSIThrashRunAborts(t *testing.T) {
	ctx := context.Background()

	// meminfo unreadable → inconclusive abort (streak untouched).
	d, _ := gDeps(t)
	c := &PSIThrashCheck{d: d}
	psiProcFiles(t, d, 90, 800, 100000, 0)
	if err := os.Remove(filepath.Join(d.Cfg.ProcRoot, "meminfo")); err != nil {
		t.Fatal(err)
	}
	c.Run(ctx, runEnv())
	requireLatch(t, d, latchdefs.LatchPSIMemoryThrash, false)

	// PSI file missing (PSI-less kernel) → abort, but the slab
	// guard still published the page-table footprint.
	d2, _ := gDeps(t)
	c2 := &PSIThrashCheck{d: d2}
	psiProcFiles(t, d2, 90, 800, 100000, 0)
	if err := os.Remove(filepath.Join(d2.Cfg.ProcRoot, "pressure", "memory")); err != nil {
		t.Fatal(err)
	}
	c2.Run(ctx, runEnv())
	if d2.PageTablesBytes != 1000*1024 {
		t.Fatalf("PageTablesBytes=%d want 1000KiB published despite PSI abort",
			d2.PageTablesBytes)
	}
	requireLatch(t, d2, latchdefs.LatchPSIMemoryThrash, false)
}

func TestPSIThrashRunQuietClearsStreak(t *testing.T) {
	ctx := context.Background()
	d, _ := gDeps(t)
	c := &PSIThrashCheck{d: d}
	psiProcFiles(t, d, 1.0, 50000, 100000, 0)

	// A pre-existing latch from an earlier episode is exited.
	wdepstest.WriteFile(t, latchPath(t, d, latchdefs.LatchPSIMemoryThrash), "old\n")
	c.Run(ctx, runEnv())
	requireLatch(t, d, latchdefs.LatchPSIMemoryThrash, false)
	if c.fails != 0 {
		t.Fatalf("quiet cycle fails=%d want 0", c.fails)
	}

	// Arming thrash then going quiet resets the streak before it
	// confirms.
	c.fails = 1
	c.Run(ctx, runEnv())
	if c.fails != 0 {
		t.Fatalf("quiet cycle after armed streak fails=%d want 0", c.fails)
	}
}

func TestPSIThrashRunStreakThenLatchNoVictim(t *testing.T) {
	ctx := context.Background()
	d, f := gDeps(t)
	c := &PSIThrashCheck{d: d}
	psiProcFiles(t, d, 90, 800, 100000, 0)
	e := runEnv() // no pods → no victim above the floor

	// Cycle 1: streak pending (ConsecNeeded=2), latch untouched.
	c.Run(ctx, e)
	requireLatch(t, d, latchdefs.LatchPSIMemoryThrash, false)
	if c.fails != 1 {
		t.Fatalf("first thrash cycle fails=%d want 1", c.fails)
	}

	// Cycle 2: confirmed — latch entered + the NPD action-entry line
	// logged once; no victim → kernel OOM verdict stands.
	c.Run(ctx, e)
	requireLatch(t, d, latchdefs.LatchPSIMemoryThrash, true)
	log := f.LogLines(t)
	if !strings.Contains(log, "ACTION: psi-memory-thrash latched") &&
		!strings.Contains(log, latchdefs.ActionEntryPrefix(latchdefs.LatchPSIMemoryThrash)) {
		t.Fatalf("want latch-entry evidence line, log=%q", log)
	}
}

func TestPSIThrashRunAPIUnreachableSkipsEvict(t *testing.T) {
	ctx := context.Background()
	d, f := gDeps(t)
	c := &PSIThrashCheck{d: d}
	psiProcFiles(t, d, 90, 800, 100000, 0)
	e := runEnv()
	e.APIOK = false

	c.Run(ctx, e) // streak pending
	c.Run(ctx, e) // confirmed → latch → API unreachable skip
	requireLatch(t, d, latchdefs.LatchPSIMemoryThrash, true)
	if log := f.LogLines(t); !strings.Contains(log,
		"psi-memory-thrash but API unreachable") {
		t.Fatalf("want API-unreachable skip line, log=%q", log)
	}
}

func TestPSIThrashRunSlabLeakSuppressesEvict(t *testing.T) {
	ctx := context.Background()
	d, f := gDeps(t)
	c := &PSIThrashCheck{d: d}
	// SUnreclaim 400/1000 = 0.40 > 0.35 enter ratio → slab latch.
	psiProcFiles(t, d, 90, 800, 100000, 40000)
	e := runEnv()

	c.Run(ctx, e) // arms thrash streak AND the slab-leak latch
	requireLatch(t, d, latchdefs.LatchKernelSlabLeak, true)
	c.Run(ctx, e) // confirmed thrash → evict suppressed by slab guard
	if log := f.LogLines(t); !strings.Contains(log,
		"pod evict suppressed - kernel-slab-leak latched") {
		t.Fatalf("want slab-leak suppression line, log=%q", log)
	}
	requireLatch(t, d, latchdefs.LatchPSIMemoryThrash, true)
}

func TestPSIThrashRunEvictsVictimThenCooldown(t *testing.T) {
	ctx := context.Background()
	d, f := gDeps(t)
	c := &PSIThrashCheck{d: d}
	psiProcFiles(t, d, 90, 800, 100000, 0)

	// 1 GiB-RSS Burstable pod attributed via its /proc cgroup line.
	victim := psiPod("hog", "app", wdepstest.UIDA, string(corev1.PodQOSBurstable))
	mkRSSProc(t, d, 500, wdepstest.UIDA, 1<<20)
	e := runEnv(victim)
	e.PidsOnce = wdepstest.PidsOf(500)

	c.Run(ctx, e) // streak pending
	c.Run(ctx, e) // confirmed → evict (budget fresh)
	evicted := wdepstest.EvictActions(f.CS)
	if len(evicted) != 1 || evicted[0] != "hog" {
		t.Fatalf("evicted=%v want [hog]", evicted)
	}
	if log := f.LogLines(t); !strings.Contains(log,
		"ACTION: psi-memory-thrash evicted pod app/hog") {
		t.Fatalf("want ACTION evict line, log=%q", log)
	}

	// Still thrashing inside the 15m evict budget → cooldown skip,
	// no second eviction.
	c.Run(ctx, e)
	if got := wdepstest.EvictActions(f.CS); len(got) != 1 {
		t.Fatalf("cooldown cycle evicted %v, want no second evict", got)
	}
	if log := f.LogLines(t); !strings.Contains(log,
		"victim app/hog rss=") || !strings.Contains(log, "in evict cooldown") {
		t.Fatalf("want cooldown skip line, log=%q", log)
	}

	// Budget expired → the victim is evicted again.
	f.Now = f.Now.Add(30 * time.Minute)
	c.Run(ctx, e)
	if got := wdepstest.EvictActions(f.CS); len(got) != 2 {
		t.Fatalf("after budget expiry evicted=%v want a second evict", got)
	}
}

// --- spegel.go Run ---

// spegelPod builds a Running spegel mirror pod created `age` ago.
func spegelPod(f *wdepstest.Fixture, ready bool) corev1.Pod {
	p := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "spegel-abcde",
			Namespace:         "spegel",
			CreationTimestamp: metav1.NewTime(f.Now.Add(-10 * time.Minute)),
		},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	if ready {
		cond := corev1.PodCondition{
			Type:   corev1.PodReady,
			Status: corev1.ConditionTrue,
		}
		p.Status.Conditions = append(p.Status.Conditions, cond)
	}
	return p
}

func TestSpegelRunAbortsAndClears(t *testing.T) {
	ctx := context.Background()

	// Gate: worker down → verdict is skip, nothing runs.
	d0, _ := gDeps(t)
	c0 := &SpegelCheck{d: d0}
	c0.Run(ctx, &wdeps.CycleEnv{WorkerActive: false})
	requireLatch(t, d0, latchdefs.LatchSpegelMirrorDegraded, false)

	// API flake with a degraded pod on the node → abort, streak kept.
	d1, f1 := gDeps(t)
	f1.Now = f1.Now.Add(time.Hour)
	c1 := &SpegelCheck{d: d1, Fails: 1}
	e := runEnv(spegelPod(f1, false))
	e.APIOK = false
	c1.Run(ctx, e)
	if c1.Fails != 1 {
		t.Fatalf("abort cycle must keep the streak, fails=%d", c1.Fails)
	}

	// No spegel pod on the node → stale evidence cleared.
	d2, f2 := gDeps(t)
	f2.Now = f2.Now.Add(time.Hour)
	c2 := &SpegelCheck{d: d2, Fails: 1}
	wdepstest.WriteFile(t, latchPath(t, d2, latchdefs.LatchSpegelMirrorDegraded), "old\n")
	c2.Run(ctx, runEnv())
	requireLatch(t, d2, latchdefs.LatchSpegelMirrorDegraded, false)
	if c2.Fails != 0 {
		t.Fatalf("no-pod cycle must clear the streak, fails=%d", c2.Fails)
	}

	// Ready pod + fresh socket → healthy, evidence cleared.
	d3, f3 := gDeps(t)
	f3.Now = f3.Now.Add(time.Hour)
	c3 := &SpegelCheck{d: d3, Fails: 1}
	c3.Run(ctx, runEnv(spegelPod(f3, true)))
	if c3.Fails != 0 {
		t.Fatalf("healthy pod must clear the streak, fails=%d", c3.Fails)
	}
}

func TestSpegelRunStreakThenDelete(t *testing.T) {
	ctx := context.Background()
	d, f := gDeps(t)
	f.Now = f.Now.Add(time.Hour) // pod age gate: created 10m before Now
	c := &SpegelCheck{d: d}
	sp := spegelPod(f, false)
	// The remedy delete must carry the pod's UID as its precondition
	// (reactor-captured below) — same name-reuse race as the calico
	// remedies.
	sp.UID = types.UID("uid-spegel")
	if _, err := f.CS.CoreV1().Pods("spegel").Create(
		ctx, &sp, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	gotUID := deleteUIDPrecondition(f)
	e := runEnv(sp)

	// Too young (created 1m ago) → not our spegel candidate.
	young := spegelPod(f, false)
	young.CreationTimestamp = metav1.NewTime(f.Now.Add(-time.Minute))
	c.Run(ctx, runEnv(young))
	if c.Fails != 0 {
		t.Fatalf("young pod must be skipped, fails=%d", c.Fails)
	}

	c.Run(ctx, e) // streak pending
	if c.Fails != 1 {
		t.Fatalf("first Ready=False cycle fails=%d want 1", c.Fails)
	}
	c.Run(ctx, e) // confirmed → latch + budgeted delete
	requireLatch(t, d, latchdefs.LatchSpegelMirrorDegraded, true)
	if log := f.LogLines(t); !strings.Contains(log,
		"ACTION: spegel-mirror deleted pod spegel/spegel-abcde") {
		t.Fatalf("want ACTION delete line, log=%q", log)
	}
	if got := wdepstest.DeleteActions(f.CS); len(got) != 1 || got[0].GetName() != "spegel-abcde" {
		t.Fatalf("delete actions=%v want spegel-abcde", got)
	}
	if gotUID == nil || *gotUID != types.UID("uid-spegel") {
		t.Fatalf("spegel delete precondition UID=%v want uid-spegel", gotUID)
	}
	if c.Fails != 0 {
		t.Fatalf("successful delete must clear the streak, fails=%d", c.Fails)
	}

	// Restart budget spent → the next confirmed streak skips with a
	// cooldown line instead of a second delete.
	f.Now = f.Now.Add(10 * time.Minute)
	c.Run(ctx, e)
	c.Run(ctx, e)
	if got := wdepstest.DeleteActions(f.CS); len(got) != 1 {
		t.Fatalf("cooldown cycle deleted %v, want no second delete", got)
	}
	if log := f.LogLines(t); !strings.Contains(log,
		"Ready=False 2x but restart in cooldown") {
		t.Fatalf("want cooldown skip line, log=%q", log)
	}
}

// TestSpegelRunStaleSockDeleteUID exercises the W20-KR3 stale-socket
// remedy — the one grace-0 delete no other test reaches (the const
// host socket path doesn't exist in tests). The StatFn seam points
// the staleness read at a temp file freshly recreated AFTER pod
// start + margin, exactly the k0sworker-restart-under-pod evidence.
func TestSpegelRunStaleSockDeleteUID(t *testing.T) {
	ctx := context.Background()
	d, f := gDeps(t)
	f.Now = f.Now.Add(time.Hour) // pod age gate: created 10m before Now
	c := &SpegelCheck{d: d}
	sp := spegelPod(f, true) // even a Ready pod dies on a stale socket
	sp.UID = types.UID("uid-spegel-stale")
	if _, err := f.CS.CoreV1().Pods("spegel").Create(
		ctx, &sp, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	gotUID := deleteUIDPrecondition(f)

	// Point the seam's const-path stat at a temp socket recreated
	// after podCreated + spegelSockStaleMargin — the stale inode.
	sock := filepath.Join(t.TempDir(), "containerd.sock")
	if err := os.WriteFile(sock, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(sock, f.Now, f.Now); err != nil {
		t.Fatal(err)
	}
	d.Cfg.Seams.Host.StatFn = func(path string) (os.FileInfo, error) {
		if path == spegelContainerdSock {
			return os.Stat(sock)
		}
		return os.Stat(path)
	}

	c.Run(ctx, runEnv(sp))
	if log := f.LogLines(t); !strings.Contains(log,
		"ACTION: spegel-mirror deleted pod spegel/spegel-abcde - stale containerd.sock inode") {
		t.Fatalf("want stale-sock ACTION delete line, log=%q", log)
	}
	if got := wdepstest.DeleteActions(f.CS); len(got) != 1 || got[0].GetName() != "spegel-abcde" {
		t.Fatalf("delete actions=%v want spegel-abcde", got)
	}
	if gotUID == nil || *gotUID != types.UID("uid-spegel-stale") {
		t.Fatalf("stale-sock delete precondition UID=%v want uid-spegel-stale", gotUID)
	}

	// The inconclusive leg: a stat MISS is never a delete — the same
	// fixture without the seam override stats the real (absent)
	// /run/k0s/containerd.sock and must take the healthy exit.
	d2, f2 := gDeps(t)
	f2.Now = f2.Now.Add(time.Hour)
	c2 := &SpegelCheck{d: d2, Fails: 1}
	sp2 := spegelPod(f2, true)
	c2.Run(ctx, runEnv(sp2))
	if got := wdepstest.DeleteActions(f2.CS); len(got) != 0 {
		t.Fatalf("missing socket must not delete, actions=%v", got)
	}
	if c2.Fails != 0 {
		t.Fatalf("healthy exit must clear the streak, fails=%d", c2.Fails)
	}
}

// --- calico.go Run ---

// mkCalicoIface creates a cali* sysfs dir carrying the given carrier.
func mkCalicoIface(t *testing.T, d *wdeps.Deps, name, carrier string) {
	t.Helper()
	dir := filepath.Join(d.Cfg.SysClassNet, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(dir, "carrier"), carrier+"\n")
}

func TestCalicoRunDormantPaths(t *testing.T) {
	ctx := context.Background()

	// Cilium node (cilium_host present) → every calico verdict
	// belongs to the cilium family; streaks cleared, latch exited.
	d0, _ := gDeps(t)
	c0 := &CalicoCheck{d: d0, VethFails: 1, felixFails: 1, wgFails: 1}
	wdepstest.WriteFile(t, filepath.Join(d0.Cfg.SysClassNet, "cilium_host"), "")
	wdepstest.WriteFile(t, latchPath(t, d0, latchdefs.LatchCalicoVethLeak), "old\n")
	c0.Run(ctx, runEnv())
	requireLatch(t, d0, latchdefs.LatchCalicoVethLeak, false)
	if c0.VethFails != 0 || c0.felixFails != 0 || c0.wgFails != 0 {
		t.Fatal("cilium node must clear every calico streak")
	}

	// No cali* ifaces at all → not a calico node, quiet ok.
	d1, _ := gDeps(t)
	c1 := &CalicoCheck{d: d1}
	c1.Run(ctx, runEnv())
	requireLatch(t, d1, latchdefs.LatchCalicoVethLeak, false)
	requireLatch(t, d1, latchdefs.LatchCalicoFelixDown, false)

	// cali ifaces + API flake → the pod-count baseline is invalid →
	// inconclusive abort, streaks kept.
	d2, _ := gDeps(t)
	c2 := &CalicoCheck{d: d2, VethFails: 1}
	mkCalicoIface(t, d2, "cali1", "1")
	e := runEnv()
	e.APIOK = false
	c2.Run(ctx, e)
	if c2.VethFails != 1 {
		t.Fatalf("abort cycle must keep the veth streak, fails=%d", c2.VethFails)
	}
}

func TestCalicoRunVethLeakLatch(t *testing.T) {
	ctx := context.Background()
	d, _ := gDeps(t)
	c := &CalicoCheck{d: d}
	// 51 cali* ifaces against 0 pods → way past the 50 headroom.
	for i := range 51 {
		mkCalicoIface(t, d, "cali"+strconv.Itoa(i), "1")
	}
	e := runEnv()

	c.Run(ctx, e)
	requireLatch(t, d, latchdefs.LatchCalicoVethLeak, false)
	c.Run(ctx, e)
	requireLatch(t, d, latchdefs.LatchCalicoVethLeak, true)

	// Churn drops under the headroom → latch exited, streak cleared.
	for i := range 51 {
		if err := os.RemoveAll(filepath.Join(d.Cfg.SysClassNet,
			"cali"+strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	c.Run(ctx, e)
	requireLatch(t, d, latchdefs.LatchCalicoVethLeak, false)
	if c.VethFails != 0 {
		t.Fatalf("recovered cycle VethFails=%d want 0", c.VethFails)
	}
}

func TestCalicoRunFelixDownRestart(t *testing.T) {
	ctx := context.Background()
	d, f := gDeps(t)
	c := &CalicoCheck{d: d}
	mkCalicoIface(t, d, "cali9", "1")
	felix := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-node-x7k9p",
			Namespace: "kube-system",
			UID:       types.UID("uid-felix"),
		},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	if _, err := f.CS.CoreV1().Pods("kube-system").Create(
		ctx, &felix, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	// The remedy delete must carry the pod's UID as its precondition
	// — a name-recycling DaemonSet churn would otherwise let the
	// grace-0 delete kill an unrelated replacement pod.
	gotUID := deleteUIDPrecondition(f)
	e := runEnv(felix)
	// The felix readiness probe answers 503 (probe healthy shape is 200).
	url := d.Cfg.Calico.FelixReadyURL
	f.Status[url] = http.StatusServiceUnavailable

	// Cycles 1+2 arm the streak; cycle 3 (CalicoFelixRestartFails)
	// spends the restart budget and deletes the pod.
	c.Run(ctx, e)
	requireLatch(t, d, latchdefs.LatchCalicoFelixDown, false)
	c.Run(ctx, e)
	requireLatch(t, d, latchdefs.LatchCalicoFelixDown, true)
	c.Run(ctx, e)
	if log := f.LogLines(t); !strings.Contains(log,
		"ACTION: calico-hygiene deleted pod kube-system/calico-node-x7k9p - felix readiness down 3x") {
		t.Fatalf("want ACTION delete line, log=%q", log)
	}
	if gotUID == nil || *gotUID != types.UID("uid-felix") {
		t.Fatalf("felix remedy delete precondition UID=%v want uid-felix", gotUID)
	}
	if _, err := f.CS.CoreV1().Pods("kube-system").Get(
		ctx, "calico-node-x7k9p", metav1.GetOptions{}); err == nil {
		t.Fatal("calico-node pod must be deleted after the felix wedge")
	}

	// Budget spent → the next confirmed wedge hits the cooldown skip.
	f.Now = f.Now.Add(10 * time.Minute)
	c.Run(ctx, e)
	if log := f.LogLines(t); !strings.Contains(log,
		"calico-felix-down 4x but pod restart in cooldown") {
		t.Fatalf("want cooldown skip line, log=%q", log)
	}

	// A healthy probe clears the latch and the streak.
	f.Status[url] = http.StatusOK
	c.Run(ctx, e)
	requireLatch(t, d, latchdefs.LatchCalicoFelixDown, false)
	if c.felixFails != 0 {
		t.Fatalf("healthy probe felixFails=%d want 0", c.felixFails)
	}

	// Node overloaded → the remedy is skipped even with a fresh budget.
	wdepstest.WriteFile(t, latchPath(t, d, latchdefs.LatchNodeOverloaded), "1\n")
	f.Status[url] = http.StatusServiceUnavailable
	c.felixFails = CalicoFelixRestartFails - 1 // one more cycle confirms
	f.Now = f.Now.Add(time.Hour)
	c.Run(ctx, e)
	if log := f.LogLines(t); !strings.Contains(log,
		"3x but node overloaded — skip pod restart") {
		t.Fatalf("want overload skip line, log=%q", log)
	}
}

// --- dstate_scopes.go: DstateCheck.Run ---

func TestDstateRunQuietAndStorm(t *testing.T) {
	ctx := context.Background()

	// No D-state tasks → quiet ok, latch exited.
	d0, _ := gDeps(t)
	c0 := &DstateCheck{d: d0}
	wdepstest.WriteFile(t, latchPath(t, d0, latchdefs.LatchDStateStorm), "old\n")
	c0.Run(ctx, runEnv())
	requireLatch(t, d0, latchdefs.LatchDStateStorm, false)

	// Runtime-critical D-state storm: 2 runc tasks in D (≥ the
	// runtime-min path) with wchan triage hints. Two cycles → latch.
	d1, f1 := gDeps(t)
	c1 := &DstateCheck{d: d1}
	f1.MkStatProc(t, 71, "runc", "D", "wait_transaction_locked")
	f1.MkStatProc(t, 72, "kubelet", "D", "blk_mq_get_tag")
	e := &wdeps.CycleEnv{WorkerActive: true, PidsOnce: wdepstest.PidsOf(71, 72, 73)}
	f1.MkStatProc(t, 73, "bash", "S", "")

	c1.Run(ctx, e)
	requireLatch(t, d1, latchdefs.LatchDStateStorm, false)
	c1.Run(ctx, e)
	requireLatch(t, d1, latchdefs.LatchDStateStorm, true)
	log := f1.LogLines(t)
	if !strings.Contains(log, "count=2 runtime=2") {
		t.Fatalf("want storm latch line with counts, log=%q", log)
	}
	if !strings.Contains(log, "runc=wait_transaction_locked") {
		t.Fatalf("want wchan triage sample in the latch line, log=%q", log)
	}

	// Storm drains (no D procs any more) → latch exited.
	f1.MkStatProc(t, 71, "runc", "S", "")
	f1.MkStatProc(t, 72, "kubelet", "S", "")
	c1.Run(ctx, e)
	requireLatch(t, d1, latchdefs.LatchDStateStorm, false)
	if c1.fails != 0 {
		t.Fatalf("quiet cycle fails=%d want 0", c1.fails)
	}
}

// --- dstate_scopes.go: ScopesCheck.Run ---

func TestScopesRunSweepAndReset(t *testing.T) {
	ctx := context.Background()

	// No systemd client → gated.
	d0, _ := gDeps(t)
	c0 := &ScopesCheck{d: d0}
	c0.Run(ctx, runEnv())

	d, f := gDeps(t)
	c := &ScopesCheck{d: d}
	e := runEnv()

	// list-units fails (nothing stubbed) → abort AND no scan stamp:
	// the next Run must retry the exec instead of sleeping 30m.
	c.Run(ctx, e)
	c.Run(ctx, e)
	if n := countSD(f, "list-units"); n < 2 {
		t.Fatalf("failed sweeps must not stamp the scan interval, ran %dx", n)
	}

	// Successful sweep with failed scopes → reset-failed ACTION.
	f.SDReply["state=failed"] =
		"cri-containerd-abc.scope loaded failed failed\n" +
			"cri-containerd-def.scope loaded failed failed\n" +
			"noise.service loaded failed failed\n"
	f.SDReply["reset-failed"] = ""
	c.Run(ctx, e)
	if !f.SDRan("reset-failed cri-containerd-*.scope") {
		t.Fatal("failed scopes must be reset via systemctl reset-failed")
	}
	if log := f.LogLines(t); !strings.Contains(log,
		"ACTION: systemd-scopes reset-failed count=2") {
		t.Fatalf("non-.scope lines must not count, log=%q", log)
	}

	// The scan stamp now suppresses the second sweep inside 30m.
	c.Run(ctx, e)
	if n := countSD(f, "list-units"); n != 3 {
		t.Fatalf("interval must suppress the 2nd sweep, list-units ran %dx", n)
	}

	// Clock advanced past the interval → the sweep runs again.
	f.Now = f.Now.Add(time.Hour)
	c.Run(ctx, e)
	if n := countSD(f, "list-units"); n != 4 {
		t.Fatalf("post-interval sweep must run, list-units ran %dx", n)
	}

	// reset-failed failing is logged as suspect, never counted.
	f.SDReply["state=failed"] = "cri-containerd-xyz.scope loaded failed failed\n"
	delete(f.SDReply, "reset-failed")
	f.Now = f.Now.Add(time.Hour)
	c.Run(ctx, e)
	if log := f.LogLines(t); !strings.Contains(log,
		"reset-failed failed: ") {
		t.Fatalf("want reset-failed failure line, log=%q", log)
	}
}

// countSD counts recorded systemd argvs containing sub.
func countSD(f *wdepstest.Fixture, sub string) int {
	n := 0
	for _, argv := range f.SDCmds {
		if strings.Contains(strings.Join(argv, " "), "state=failed") {
			n++
		}
	}
	return n
}

// --- cni_netns.go: helper-level coverage ---

func TestNetnsInodeHelpers(t *testing.T) {
	d, _ := gDeps(t)
	netnsDir := t.TempDir()
	d.Cfg.Net.NetnsDir = netnsDir
	p := filepath.Join(netnsDir, "cni-x")
	wdepstest.WriteFile(t, p, "")
	ino, ok := netnsInode(p)
	if !ok || ino == 0 {
		t.Fatalf("netnsInode=%d,%v want a real inode", ino, ok)
	}
	if _, ok := netnsInode(filepath.Join(netnsDir, "gone")); ok {
		t.Fatal("missing netns file must report !ok")
	}

	// liveNetnsInodes: a pid whose ns/net shares the inode counts,
	// an unreadable pid is skipped.
	nsdir := filepath.Join(d.Cfg.ProcRoot, "4242", "ns")
	if err := os.MkdirAll(nsdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(p, filepath.Join(nsdir, "net")); err != nil {
		t.Fatal(err)
	}
	live := liveNetnsInodes(d, []int{4242, 4243})
	if !live[ino] || len(live) != 1 {
		t.Fatalf("liveNetnsInodes=%v want only pid 4242's inode", live)
	}

	// netnsHeldByLiveTask: only a LIVE task matching the inode holds.
	tasks := map[string][]wdeps.CtrTask{
		"u1": {{UID: "u1", PID: 4242, Live: true}},
		"u2": {{UID: "u2", PID: 4243, Live: true}}, // unreadable ns
		"u3": {{UID: "u3", PID: 4242, Live: false}},
	}
	if !netnsHeldByLiveTask(d, tasks, ino) {
		t.Fatal("live task inside the netns must hold it")
	}
	if netnsHeldByLiveTask(d, tasks, ino+999) {
		t.Fatal("unrelated inode must not be held")
	}
}

func TestReapCNINetnsGuards(t *testing.T) {
	ctx := context.Background()

	// No systemd client → skip umount, marker kept for a retry.
	d0, _ := gDeps(t)
	d0.Cfg.Net.NetnsDir = t.TempDir()
	m0 := filepath.Join(d0.Cfg.WatchdogStateDir, "cni-netns-seen-cni-a")
	wdepstest.WriteFile(t, m0, "1\n")
	reapCNINetns(d0, ctx, "cni-a")
	if _, err := os.Stat(m0); err != nil {
		t.Fatal("no-systemd skip must keep the confirmation marker")
	}

	// umount failure → suspect line, marker kept.
	d1, f1 := gDeps(t)
	d1.Cfg.Net.NetnsDir = t.TempDir()
	m1 := filepath.Join(d1.Cfg.WatchdogStateDir, "cni-netns-seen-cni-b")
	wdepstest.WriteFile(t, m1, "1\n")
	reapCNINetns(d1, ctx, "cni-b")
	if log := f1.LogLines(t); !strings.Contains(log, "umount /run/netns/cni-b failed") {
		t.Fatalf("want umount failure suspect line, log=%q", log)
	}
	if _, err := os.Stat(m1); err != nil {
		t.Fatal("failed umount must keep the marker")
	}

	// Successful umount but an undetectable rm target (a dir where
	// the file should be) → mount half done, file-remains suspect,
	// marker still dropped.
	d2, f2 := gDeps(t)
	d2.Cfg.Net.NetnsDir = t.TempDir()
	wdepstest.WriteFile(t, filepath.Join(d2.Cfg.Net.NetnsDir, "cni-c", "inner"), "")
	f2.SDReply["umount"] = ""
	reapCNINetns(d2, ctx, "cni-c")
	if log := f2.LogLines(t); !strings.Contains(log, "file remains") ||
		!strings.Contains(log, "ACTION: cni-netns-gc reaped orphan netns cni-c") {
		t.Fatalf("want reaped ACTION + rm-failure line, log=%q", log)
	}
	if _, err := os.Stat(filepath.Join(d2.Cfg.WatchdogStateDir,
		"cni-netns-seen-cni-c")); !os.IsNotExist(err) {
		t.Fatal("marker must be dropped once the umount succeeded")
	}
}

func TestPodUIDForPIDAndPruneMarkers(t *testing.T) {
	d, _ := gDeps(t)

	// Missing pid and a non-pod cgroup line → "unknown".
	if got := podUIDForPID(d, 999999); got != "unknown" {
		t.Fatalf("missing pid podUIDForPID=%q want unknown", got)
	}
	pdir := filepath.Join(d.Cfg.ProcRoot, "77")
	if err := os.MkdirAll(pdir, 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(pdir, "cgroup"), "0::/system.slice/sshd.service\n")
	if got := podUIDForPID(d, 77); got != "unknown" {
		t.Fatalf("non-pod cgroup podUIDForPID=%q want unknown", got)
	}

	// pruneCNINetnsMarkers: seen-and-present markers survive,
	// markers whose netns file vanished are dropped.
	netns := t.TempDir()
	d.Cfg.Net.NetnsDir = netns
	wdepstest.WriteFile(t, filepath.Join(netns, "cni-keep"), "")
	keep := filepath.Join(d.Cfg.WatchdogStateDir, "cni-netns-seen-cni-keep")
	gone := filepath.Join(d.Cfg.WatchdogStateDir, "cni-netns-seen-cni-gone")
	wdepstest.WriteFile(t, keep, "1\n")
	wdepstest.WriteFile(t, gone, "1\n")
	pruneCNINetnsMarkers(d, map[string]bool{"cni-keep": true})
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("seen marker for a live netns file must survive the prune")
	}
	if _, err := os.Stat(gone); !os.IsNotExist(err) {
		t.Fatal("marker for a vanished netns file must be pruned")
	}
}

// TestCNINetnsRunScanError: a netns dir that cannot be read at all
// (permission, not absence) is an inconclusive abort — markers are
// kept and nothing is reaped.
func TestCNINetnsRunScanError(t *testing.T) {
	ctx := context.Background()
	d, _ := gDeps(t)
	dir := filepath.Join(t.TempDir(), "netns")
	if err := os.MkdirAll(filepath.Join(dir, "cni-x"), 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(d.Cfg.WatchdogStateDir,
		"cni-netns-seen-cni-x"), "1\n")
	d.Cfg.Net.NetnsDir = dir
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0o755) }() // restore for cleanup
	NewCNINetns(d).Run(ctx, runEnv())
	if _, err := os.Stat(filepath.Join(d.Cfg.WatchdogStateDir,
		"cni-netns-seen-cni-x")); err != nil {
		t.Fatal("abort cycle must keep confirmation markers")
	}
	if log := LogLinesOf(t, d); !strings.Contains(log, "suspect: cni-netns-gc read") {
		t.Fatalf("want scan-error suspect line, log=%q", log)
	}
}

// LogLinesOf reads the watchdog log through the fixture's helper.
func LogLinesOf(t *testing.T, d *wdeps.Deps) string {
	t.Helper()
	data, err := os.ReadFile(d.Cfg.WatchdogLogFile)
	if err != nil {
		return ""
	}
	return string(data)
}

// TestPSIThrashRunZeroTotalMeminfo: a parsed meminfo whose
// MemAvailable is missing is reparsed per cycle — already covered
// upstream; here the thrash verdict with an exactly-at-threshold
// PSI value must NOT latch (strict > on both rails).
func TestPSIThrashRunThresholdBoundaries(t *testing.T) {
	ctx := context.Background()
	d, _ := gDeps(t)
	c := &PSIThrashCheck{d: d}
	// avg60 = 25.0 (== PSIFullAvg60 default) → strict > keeps it quiet
	// even with zero free memory.
	psiProcFiles(t, d, 25.0, 0, 100000, 0)
	c.Run(ctx, runEnv())
	requireLatch(t, d, latchdefs.LatchPSIMemoryThrash, false)

	// Free memory exactly at the floor (0.08) is also quiet: the
	// thrash conjunction needs free < floor.
	psiProcFiles(t, d, 90, 8000, 100000, 0)
	c.Run(ctx, runEnv())
	requireLatch(t, d, latchdefs.LatchPSIMemoryThrash, false)
	if c.fails != 0 {
		t.Fatalf("boundary cycles fails=%d want 0", c.fails)
	}
}

// TestSpegelRunDeleteFailure: a pod that vanished between the LIST
// and the delete logs the suspect line, keeps the latch evidence.
func TestSpegelRunDeleteFailure(t *testing.T) {
	ctx := context.Background()
	d, f := gDeps(t)
	f.Now = f.Now.Add(time.Hour)
	c := &SpegelCheck{d: d}
	e := runEnv(spegelPod(f, false)) // NOT seeded in the clientset
	c.Run(ctx, e)
	c.Run(ctx, e)
	requireLatch(t, d, latchdefs.LatchSpegelMirrorDegraded, true)
	if log := LogLinesOf(t, d); !strings.Contains(log,
		"suspect: spegel-mirror delete spegel/spegel-abcde failed") {
		t.Fatalf("want delete-failure suspect line, log=%q", log)
	}
}
