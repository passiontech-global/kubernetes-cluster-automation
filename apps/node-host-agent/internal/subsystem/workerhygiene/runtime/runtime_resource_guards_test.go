// runtime_resource_guards_test.go — coverage for the six
// runtime-resource guards (runtime/runtime_<name>.go) and the
// orphan-hostpath early return.
package runtime_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/runtime"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// runActive invokes one check the way Cycle does on an active worker.
func runActive(c wdeps.Check, e *wdeps.CycleEnv) {
	c.Run(context.Background(), e)
}

// --- cgroup-dying-reclaim ---

func TestCgroupDyingReclaim(t *testing.T) {
	e := fixture(t)
	h := e.H
	cg := t.TempDir()
	h.Cfg.Runtime.CgroupRoot = cg
	wdepstest.WriteFile(t, filepath.Join(cg, "cgroup.stat"),
		"nr_descendants 10\nnr_dying_descendants 7000\nnr_delegate 0\n")
	wdepstest.WriteFile(t, filepath.Join(cg, "kubepods.slice", "cgroup.stat"),
		"nr_dying_descendants 300\n")
	// On a real host /proc/sys/vm always exists — the check writes
	// the sysctl, it does not mkdir it.
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "sys", "vm", "drop_caches"), "0\n")
	env := &wdeps.CycleEnv{WorkerActive: true}
	latch := filepath.Join(e.StateDir, "state-cgroup-dying-leak")

	runActive(wdepstest.Check[*runtime.CgroupDyingCheck](h, wdeps.CheckCgroupDying), env)
	if h.CgroupDyingDescendants != 7000 {
		t.Fatalf("descendants=%d want 7000 (max of the two files)",
			h.CgroupDyingDescendants)
	}
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("latch set before ConsecNeeded")
	}
	runActive(wdepstest.Check[*runtime.CgroupDyingCheck](h, wdeps.CheckCgroupDying), env)
	if _, err := os.Stat(latch); err != nil {
		t.Fatal("cgroup-dying-leak latch missing after 2 high cycles")
	}
	if got := nhReadFile(t, filepath.Join(e.ProcDir, "sys", "vm", "drop_caches")); got != "2\n" {
		t.Fatalf("drop_caches=%q want \"2\\n\"", got)
	}
	for _, p := range []string{
		filepath.Join(cg, "memory.reclaim"),
		filepath.Join(cg, "kubepods.slice", "memory.reclaim"),
	} {
		if got := nhReadFile(t, p); got != "256M\n" {
			t.Fatalf("%s=%q want \"256M\\n\"", p, got)
		}
	}
	if h.CgroupReclaimRuns != 1 {
		t.Fatalf("reclaimRuns=%d want 1", h.CgroupReclaimRuns)
	}
	// Cooldown: a third high cycle must not reclaim again.
	runActive(wdepstest.Check[*runtime.CgroupDyingCheck](h, wdeps.CheckCgroupDying), env)
	if h.CgroupReclaimRuns != 1 {
		t.Fatalf("reclaimRuns=%d want 1 (30m cooldown held)", h.CgroupReclaimRuns)
	}
}

func TestCgroupDyingBelowThresholdNoLatch(t *testing.T) {
	e := fixture(t)
	h := e.H
	cg := t.TempDir()
	h.Cfg.Runtime.CgroupRoot = cg
	wdepstest.WriteFile(t, filepath.Join(cg, "cgroup.stat"), "nr_dying_descendants 10\n")
	runActive(wdepstest.Check[*runtime.CgroupDyingCheck](h, wdeps.CheckCgroupDying), &wdeps.CycleEnv{WorkerActive: true})
	runActive(wdepstest.Check[*runtime.CgroupDyingCheck](h, wdeps.CheckCgroupDying), &wdeps.CycleEnv{WorkerActive: true})
	if _, err := os.Stat(filepath.Join(e.StateDir, "state-cgroup-dying-leak")); !os.IsNotExist(err) {
		t.Fatal("latch set below threshold")
	}
	if h.CgroupReclaimRuns != 0 {
		t.Fatal("reclaim ran below threshold")
	}
}

// --- systemd-session-hygiene ---

func TestSystemdSessionReaper(t *testing.T) {
	e := fixture(t)
	h := e.H
	ctx := context.Background()
	dir := t.TempDir()
	h.Cfg.Runtime.SessionsDir = dir
	old := e.Now.Add(-3 * time.Hour)
	for i := 1; i <= 25; i++ {
		p := filepath.Join(dir, strconv.Itoa(i))
		wdepstest.WriteFile(t, p, "# This is private data\nSTATE=abandoned\n")
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	// An active session and a .ref companion must not count.
	wdepstest.WriteFile(t, filepath.Join(dir, "100"), "STATE=active\n")
	wdepstest.WriteFile(t, filepath.Join(dir, "100.ref"), "1\n")
	e.SDReply["loginctl terminate-session"] = ""
	e.SDReply["systemctl reset-failed"] = ""

	wdepstest.Check[*runtime.SystemdSessionCheck](h, wdeps.CheckSystemdSessions).Run(ctx, &wdeps.CycleEnv{WorkerActive: true})

	if h.SystemdSessionsTotal != 26 {
		t.Fatalf("sessionsTotal=%d want 26 (.ref excluded)",
			h.SystemdSessionsTotal)
	}
	if h.SystemdSessionsStale != 25 {
		t.Fatalf("sessionsStale=%d want 25", h.SystemdSessionsStale)
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "state-systemd-session-bloat")); err != nil {
		t.Fatal("session-bloat latch missing")
	}
	if !e.SDRan("loginctl terminate-session") {
		t.Fatal("no terminate-session ran")
	}
	if h.SystemdSessionsReaped != 20 {
		t.Fatalf("reaped=%d want 20 (per-cycle cap)", h.SystemdSessionsReaped)
	}
	if !e.SDRan("systemctl reset-failed") {
		t.Fatal("reset-failed did not run")
	}
}

func TestSystemdSessionDbusLatencyLatch(t *testing.T) {
	e := fixture(t)
	h := e.H
	ctx := context.Background()
	h.Cfg.Runtime.SessionsDir = t.TempDir() // no stale sessions at all
	e.SDReply["systemctl is-system-running"] = "running\n"
	// The D-Bus round trip eats 4s — above the 3s bar.
	e.SDHook = func(joined string) {
		if strings.Contains(joined, "is-system-running") {
			e.Now = e.Now.Add(4 * time.Second)
		}
	}
	e.SDReply["systemctl reset-failed"] = ""

	wdepstest.Check[*runtime.SystemdSessionCheck](h, wdeps.CheckSystemdSessions).Run(ctx, &wdeps.CycleEnv{WorkerActive: true})

	if h.SystemdDbusLatencySec < 3.5 {
		t.Fatalf("dbus latency=%.2f want ~4s", h.SystemdDbusLatencySec)
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "state-systemd-session-bloat")); err != nil {
		t.Fatal("session-bloat latch missing on slow D-Bus")
	}
}

// --- overlayfs-stale-mount ---

func staleOverlayPod(e *env, name, uid string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: "default", UID: types.UID(uid),
		},
		Spec: corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:  "app",
				Image: "nginx:1.25",
				State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
					Reason:  "CreateContainerError",
					Message: "failed to mount overlay: no such file or directory",
				}},
			}},
		},
	}
}

func TestOverlayFSStaleMount(t *testing.T) {
	e := fixture(t)
	h := e.H
	ctx := context.Background()
	p := staleOverlayPod(e, "stale-app", wdepstest.UIDA)
	env := &wdeps.CycleEnv{
		Pods:         []corev1.Pod{*p},
		APIOK:        true,
		WorkerActive: true,
	}
	wdepstest.Check[*runtime.OverlayFSStaleCheck](h, wdeps.CheckOverlayFSStale).Run(ctx, env)
	if e.SDRan("images rm") {
		t.Fatal("image rm before ConsecNeeded cycles")
	}
	wdepstest.Check[*runtime.OverlayFSStaleCheck](h, wdeps.CheckOverlayFSStale).Run(ctx, env)
	if !e.SDRan("images rm --sync docker.io/library/nginx:1.25") {
		t.Fatalf("expected normalized image rm, sdcmds=%v", e.SDCmds)
	}
	if h.OverlayFSStaleMounts < 1 {
		t.Fatal("stale-mount counter not incremented")
	}
}

func TestOverlayFSStaleMountSkipsUnmatched(t *testing.T) {
	e := fixture(t)
	h := e.H
	ctx := context.Background()
	p := staleOverlayPod(e, "plain-crash", wdepstest.UIDB)
	p.Status.ContainerStatuses[0].State.Waiting.Message = "back-off restarting failed container"
	env := &wdeps.CycleEnv{
		Pods:         []corev1.Pod{*p},
		APIOK:        true,
		WorkerActive: true,
	}
	wdepstest.Check[*runtime.OverlayFSStaleCheck](h, wdeps.CheckOverlayFSStale).Run(ctx, env)
	wdepstest.Check[*runtime.OverlayFSStaleCheck](h, wdeps.CheckOverlayFSStale).Run(ctx, env)
	if e.SDRan("images rm") {
		t.Fatal("image rm on a non-overlay Waiting message")
	}
	if h.OverlayFSStaleMounts != 0 {
		t.Fatal("counter incremented on unmatched pod")
	}
}

// --- io-pressure-throttler ---

func TestIOPressureThrottler(t *testing.T) {
	e := fixture(t)
	h := e.H
	ctx := context.Background()
	// Quiet PSI io on the baseline cycle — pressure must come from
	// the diskstats delta in the second cycle (plus a PSI bump).
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "pressure", "io"),
		"some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"+
			"full avg10=1.00 avg60=5.00 avg300=3.00 total=0\n")
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "diskstats"),
		"   8       0 sda 1000 200 8000 500 300 100 6000 4000 0 2000 5000\n"+
			"   8       1 sda1 500 100 4000 250 50 50 3000 2000 0 1000 3000\n")
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "4242", "comm"), "kopia\n")
	var reniced, ioniced []int
	h.Cfg.Seams.Host.ReniceFn = func(pid int) error { reniced = append(reniced, pid); return nil }
	h.Cfg.Seams.Host.IoniceIdleFn = func(pid int) error { ioniced = append(ioniced, pid); return nil }
	env := &wdeps.CycleEnv{
		WorkerActive: true,
		PidsOnce:     func() []int { return []int{4242} },
	}

	wdepstest.Check[*runtime.IOPressureCheck](h, wdeps.CheckIOPressure).Run(ctx, env) // baseline cycle — seeds diskstats
	if h.IOThrottledProcs != 0 {
		t.Fatal("throttled on the baseline cycle")
	}
	e.Now = e.Now.Add(time.Minute)
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "pressure", "io"),
		"some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"+
			"full avg10=1.00 avg60=30.00 avg300=26.00 total=0\n")
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "diskstats"),
		"   8       0 sda 1000 200 8000 500 400 100 6000 34000 0 32000 5000\n"+
			"   8       1 sda1 500 100 4000 250 60 50 3000 4000 0 2000 3000\n")
	wdepstest.Check[*runtime.IOPressureCheck](h, wdeps.CheckIOPressure).Run(ctx, env)

	if h.DiskWriteAwaitMs != 300 {
		t.Fatalf("writeAwait=%v want 300ms", h.DiskWriteAwaitMs)
	}
	if h.DiskIOUtilRatio != 0.5 {
		t.Fatalf("ioUtil=%v want 0.5", h.DiskIOUtilRatio)
	}
	if h.IOPSIFullAvg60 != 30 || h.IOPSIFullAvg300 != 26 {
		t.Fatalf("psi avgs=%v/%v want 30/26", h.IOPSIFullAvg60, h.IOPSIFullAvg300)
	}
	if len(reniced) != 1 || reniced[0] != 4242 {
		t.Fatalf("reniced=%v want [4242]", reniced)
	}
	if len(ioniced) != 1 || ioniced[0] != 4242 {
		t.Fatalf("ioniced=%v want [4242]", ioniced)
	}
	if h.IOThrottledProcs != 1 {
		t.Fatalf("throttled=%d want 1", h.IOThrottledProcs)
	}
	// The same pid must not be re-throttled while pressure persists.
	wdepstest.Check[*runtime.IOPressureCheck](h, wdeps.CheckIOPressure).Run(ctx, env)
	if len(reniced) != 1 {
		t.Fatalf("pid re-throttled: reniced=%v", reniced)
	}
	if h.IOThrottledProcs != 1 {
		t.Fatalf("throttled=%d want 1 (dedupe)", h.IOThrottledProcs)
	}
}

// --- conntrack-tcp-liberal-guard ---

func TestConntrackLiberalGuard(t *testing.T) {
	e := fixture(t)
	h := e.H
	ctx := context.Background()
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "neb1", "mtu"), "1300\n")
	sysctl := filepath.Join(e.ProcDir, "sys", "net", "netfilter",
		"nf_conntrack_tcp_be_liberal")
	wdepstest.WriteFile(t, sysctl, "0\n")

	wdepstest.Check[*runtime.ConntrackLiberalCheck](h, wdeps.CheckConntrackLiberal).Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
	if got := nhReadFile(t, sysctl); got != "1\n" {
		t.Fatalf("be_liberal=%q want \"1\\n\"", got)
	}
	if h.ConntrackLiberalFixes != 1 {
		t.Fatalf("fixes=%d want 1", h.ConntrackLiberalFixes)
	}
	// Idempotent: already 1 → no second fix.
	wdepstest.Check[*runtime.ConntrackLiberalCheck](h, wdeps.CheckConntrackLiberal).Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
	if h.ConntrackLiberalFixes != 1 {
		t.Fatalf("fixes=%d want 1 (idempotent)", h.ConntrackLiberalFixes)
	}
}

func TestConntrackLiberalGuardNeedsNeb1(t *testing.T) {
	e := fixture(t)
	h := e.H
	ctx := context.Background()
	// No neb1 under sysnet — the guard must not touch the sysctl.
	sysctl := filepath.Join(e.ProcDir, "sys", "net", "netfilter",
		"nf_conntrack_tcp_be_liberal")
	wdepstest.WriteFile(t, sysctl, "0\n")
	wdepstest.Check[*runtime.ConntrackLiberalCheck](h, wdeps.CheckConntrackLiberal).Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
	if got := nhReadFile(t, sysctl); got != "0\n" {
		t.Fatalf("be_liberal=%q want \"0\\n\" without neb1", got)
	}
	if h.ConntrackLiberalFixes != 0 {
		t.Fatal("fix written without neb1")
	}
}

// --- clock-jump-session-healer ---

func konnPodOnNode(uid string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "konnectivity-agent-abc12", Namespace: "kube-system",
			UID: types.UID(uid),
		},
		Spec: corev1.PodSpec{NodeName: "node-a"},
	}
}

func TestClockJumpSessionHealer(t *testing.T) {
	e := fixture(t)
	h := e.H
	ctx := context.Background()
	konn := konnPodOnNode(wdepstest.UIDC)
	if _, err := e.CS.CoreV1().Pods("kube-system").Create(ctx, konn,
		metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	logs := t.TempDir()
	h.Cfg.Disk.PodLogsDir = logs
	wdepstest.WriteFile(t, filepath.Join(logs,
		"kube-system_konnectivity-agent-abc12_"+wdepstest.UIDC,
		"konnectivity-agent", "0.log"),
		"E0101 dial tcp: konnectivity-server: x509: certificate has expired or is not yet valid\n")
	wdepstest.WriteFile(t, filepath.Join(e.StateDir, "clock-stepped-at"),
		fmt.Sprintf("%d\n", e.Now.Unix()))
	env := &wdeps.CycleEnv{
		Pods:         []corev1.Pod{*konn},
		APIOK:        true,
		WorkerActive: true,
	}
	wdepstest.Check[*runtime.ClockJumpCheck](h, wdeps.CheckClockJump).Run(ctx, env)
	if n := len(wdepstest.DeleteActions(e.CS)); n != 1 {
		t.Fatalf("deletes=%d want 1 (konnectivity recreated)", n)
	}
	// Cooldown: same cycle evidence → still one delete.
	wdepstest.Check[*runtime.ClockJumpCheck](h, wdeps.CheckClockJump).Run(ctx, env)
	if n := len(wdepstest.DeleteActions(e.CS)); n != 1 {
		t.Fatalf("deletes=%d want 1 (30m cooldown held)", n)
	}
}

func TestClockJumpSessionHealerNeedsFreshMarker(t *testing.T) {
	e := fixture(t)
	h := e.H
	ctx := context.Background()
	konn := konnPodOnNode(wdepstest.UIDC)
	if _, err := e.CS.CoreV1().Pods("kube-system").Create(ctx, konn,
		metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	logs := t.TempDir()
	h.Cfg.Disk.PodLogsDir = logs
	wdepstest.WriteFile(t, filepath.Join(logs,
		"kube-system_konnectivity-agent-abc12_"+wdepstest.UIDC,
		"konnectivity-agent", "0.log"),
		"x509: certificate has expired\n")
	// Marker from 2h ago — outside the 10m attribution window.
	wdepstest.WriteFile(t, filepath.Join(e.StateDir, "clock-stepped-at"),
		fmt.Sprintf("%d\n", e.Now.Add(-2*time.Hour).Unix()))
	wdepstest.Check[*runtime.ClockJumpCheck](h, wdeps.CheckClockJump).Run(ctx, &wdeps.CycleEnv{
		Pods: []corev1.Pod{*konn}, APIOK: true, WorkerActive: true})
	if n := len(wdepstest.DeleteActions(e.CS)); n != 0 {
		t.Fatalf("deletes=%d want 0 on a stale marker", n)
	}
}

// --- orphan-hostpath early return ---

func TestOrphanHostPathEarlyReturnSkipsPVList(t *testing.T) {
	e := fixture(t)
	h := e.H
	ctx := context.Background()
	h.Cfg.Disk.OrphanHostPathDirs = []string{t.TempDir()} // no pvc-* dirs
	// Pretend a previous cycle left counts behind — the early
	// return must still zero them.
	h.OrphanHostPathDirs = 7
	h.OrphanHostPathBytes = 999

	wdepstest.Check[*runtime.OrphanHPCheck](h, wdeps.CheckOrphanHP).Run(ctx, &wdeps.CycleEnv{WorkerActive: true})

	for _, a := range e.CS.Actions() {
		if a.GetResource().Resource == "persistentvolumes" {
			t.Fatalf("PV list ran with zero candidates: %v", a)
		}
	}
	if h.OrphanHostPathDirs != 0 || h.OrphanHostPathBytes != 0 {
		t.Fatalf("stale gauges kept: dirs=%d bytes=%d",
			h.OrphanHostPathDirs, h.OrphanHostPathBytes)
	}
	// Sanity: with a real pvc-* dir the PV list must still run.
	prov := t.TempDir()
	if err := os.MkdirAll(filepath.Join(prov, "pvc-x"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.Cfg.Disk.OrphanHostPathDirs = []string{prov}
	wdepstest.Check[*runtime.OrphanHPCheck](h, wdeps.CheckOrphanHP).Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
	sawPVList := false
	for _, a := range e.CS.Actions() {
		if a.GetVerb() == "list" &&
			a.GetResource().Resource == "persistentvolumes" {
			sawPVList = true
		}
	}
	if !sawPVList {
		t.Fatal("PV list skipped while candidates exist")
	}
}

// nhReadFile mirrors testutil.ReadFile without the import cycle risk —
// the suite already has writeFile; keep a local read helper.
func nhReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
