// runtime_resource_guards_test.go — coverage for the six
// runtime-resource guards in runtime_resource_guards.go and the
// orphan-hostpath early return.
package workerhygiene

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
)

// runActive invokes one check the way Cycle does on an active worker.
func runActive(c Check, e *cycleEnv) {
	c.Run(context.Background(), e)
}

// --- cgroup-dying-reclaim ---

func TestCgroupDyingReclaim(t *testing.T) {
	e := fixture(t)
	h := e.h
	cg := t.TempDir()
	h.cfg.Runtime.CgroupRoot = cg
	writeFile(t, filepath.Join(cg, "cgroup.stat"),
		"nr_descendants 10\nnr_dying_descendants 7000\nnr_delegate 0\n")
	writeFile(t, filepath.Join(cg, "kubepods.slice", "cgroup.stat"),
		"nr_dying_descendants 300\n")
	// On a real host /proc/sys/vm always exists — the check writes
	// the sysctl, it does not mkdir it.
	writeFile(t, filepath.Join(e.proc, "sys", "vm", "drop_caches"), "0\n")
	env := &cycleEnv{workerActive: true}
	latch := filepath.Join(e.state, "state-cgroup-dying-leak")

	runActive(h.cgroupDying, env)
	if h.cgroupDyingDescendants != 7000 {
		t.Fatalf("descendants=%d want 7000 (max of the two files)",
			h.cgroupDyingDescendants)
	}
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("latch set before ConsecNeeded")
	}
	runActive(h.cgroupDying, env)
	if _, err := os.Stat(latch); err != nil {
		t.Fatal("cgroup-dying-leak latch missing after 2 high cycles")
	}
	if got := nhReadFile(t, filepath.Join(e.proc, "sys", "vm", "drop_caches")); got != "2\n" {
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
	if h.cgroupReclaimRuns != 1 {
		t.Fatalf("reclaimRuns=%d want 1", h.cgroupReclaimRuns)
	}
	// Cooldown: a third high cycle must not reclaim again.
	runActive(h.cgroupDying, env)
	if h.cgroupReclaimRuns != 1 {
		t.Fatalf("reclaimRuns=%d want 1 (30m cooldown held)", h.cgroupReclaimRuns)
	}
}

func TestCgroupDyingBelowThresholdNoLatch(t *testing.T) {
	e := fixture(t)
	h := e.h
	cg := t.TempDir()
	h.cfg.Runtime.CgroupRoot = cg
	writeFile(t, filepath.Join(cg, "cgroup.stat"), "nr_dying_descendants 10\n")
	runActive(h.cgroupDying, &cycleEnv{workerActive: true})
	runActive(h.cgroupDying, &cycleEnv{workerActive: true})
	if _, err := os.Stat(filepath.Join(e.state, "state-cgroup-dying-leak")); !os.IsNotExist(err) {
		t.Fatal("latch set below threshold")
	}
	if h.cgroupReclaimRuns != 0 {
		t.Fatal("reclaim ran below threshold")
	}
}

// --- systemd-session-hygiene ---

func TestSystemdSessionReaper(t *testing.T) {
	e := fixture(t)
	h := e.h
	ctx := context.Background()
	dir := t.TempDir()
	h.cfg.Runtime.SessionsDir = dir
	old := e.now.Add(-3 * time.Hour)
	for i := 1; i <= 25; i++ {
		p := filepath.Join(dir, strconv.Itoa(i))
		writeFile(t, p, "# This is private data\nSTATE=abandoned\n")
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	// An active session and a .ref companion must not count.
	writeFile(t, filepath.Join(dir, "100"), "STATE=active\n")
	writeFile(t, filepath.Join(dir, "100.ref"), "1\n")
	e.sdReply["loginctl terminate-session"] = ""
	e.sdReply["systemctl reset-failed"] = ""

	h.systemdSessions.Run(ctx, &cycleEnv{workerActive: true})

	if h.systemdSessionsTotal != 26 {
		t.Fatalf("sessionsTotal=%d want 26 (.ref excluded)",
			h.systemdSessionsTotal)
	}
	if h.systemdSessionsStale != 25 {
		t.Fatalf("sessionsStale=%d want 25", h.systemdSessionsStale)
	}
	if _, err := os.Stat(filepath.Join(e.state, "state-systemd-session-bloat")); err != nil {
		t.Fatal("session-bloat latch missing")
	}
	if !e.sdRan("loginctl terminate-session") {
		t.Fatal("no terminate-session ran")
	}
	if h.systemdSessionsReaped != 20 {
		t.Fatalf("reaped=%d want 20 (per-cycle cap)", h.systemdSessionsReaped)
	}
	if !e.sdRan("systemctl reset-failed") {
		t.Fatal("reset-failed did not run")
	}
}

func TestSystemdSessionDbusLatencyLatch(t *testing.T) {
	e := fixture(t)
	h := e.h
	ctx := context.Background()
	h.cfg.Runtime.SessionsDir = t.TempDir() // no stale sessions at all
	e.sdReply["systemctl is-system-running"] = "running\n"
	// The D-Bus round trip eats 4s — above the 3s bar.
	e.sdHook = func(joined string) {
		if strings.Contains(joined, "is-system-running") {
			e.now = e.now.Add(4 * time.Second)
		}
	}
	e.sdReply["systemctl reset-failed"] = ""

	h.systemdSessions.Run(ctx, &cycleEnv{workerActive: true})

	if h.systemdDbusLatencySec < 3.5 {
		t.Fatalf("dbus latency=%.2f want ~4s", h.systemdDbusLatencySec)
	}
	if _, err := os.Stat(filepath.Join(e.state, "state-systemd-session-bloat")); err != nil {
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
	h := e.h
	ctx := context.Background()
	p := staleOverlayPod(e, "stale-app", uidA)
	env := &cycleEnv{
		pods:         []corev1.Pod{*p},
		apiOK:        true,
		workerActive: true,
	}
	h.overlayFSStale.Run(ctx, env)
	if e.sdRan("images rm") {
		t.Fatal("image rm before ConsecNeeded cycles")
	}
	h.overlayFSStale.Run(ctx, env)
	if !e.sdRan("images rm --sync docker.io/library/nginx:1.25") {
		t.Fatalf("expected normalized image rm, sdcmds=%v", e.sdcmds)
	}
	if h.overlayfsStaleMounts < 1 {
		t.Fatal("stale-mount counter not incremented")
	}
}

func TestOverlayFSStaleMountSkipsUnmatched(t *testing.T) {
	e := fixture(t)
	h := e.h
	ctx := context.Background()
	p := staleOverlayPod(e, "plain-crash", uidB)
	p.Status.ContainerStatuses[0].State.Waiting.Message = "back-off restarting failed container"
	env := &cycleEnv{
		pods:         []corev1.Pod{*p},
		apiOK:        true,
		workerActive: true,
	}
	h.overlayFSStale.Run(ctx, env)
	h.overlayFSStale.Run(ctx, env)
	if e.sdRan("images rm") {
		t.Fatal("image rm on a non-overlay Waiting message")
	}
	if h.overlayfsStaleMounts != 0 {
		t.Fatal("counter incremented on unmatched pod")
	}
}

// --- io-pressure-throttler ---

func TestIOPressureThrottler(t *testing.T) {
	e := fixture(t)
	h := e.h
	ctx := context.Background()
	// Quiet PSI io on the baseline cycle — pressure must come from
	// the diskstats delta in the second cycle (plus a PSI bump).
	writeFile(t, filepath.Join(e.proc, "pressure", "io"),
		"some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"+
			"full avg10=1.00 avg60=5.00 avg300=3.00 total=0\n")
	writeFile(t, filepath.Join(e.proc, "diskstats"),
		"   8       0 sda 1000 200 8000 500 300 100 6000 4000 0 2000 5000\n"+
			"   8       1 sda1 500 100 4000 250 50 50 3000 2000 0 1000 3000\n")
	writeFile(t, filepath.Join(e.proc, "4242", "comm"), "kopia\n")
	var reniced, ioniced []int
	h.cfg.Seams.reniceFn = func(pid int) error { reniced = append(reniced, pid); return nil }
	h.cfg.Seams.ioniceIdleFn = func(pid int) error { ioniced = append(ioniced, pid); return nil }
	env := &cycleEnv{
		workerActive: true,
		pidsOnce:     func() []int { return []int{4242} },
	}

	h.ioPressure.Run(ctx, env) // baseline cycle — seeds diskstats
	if h.ioThrottledProcs != 0 {
		t.Fatal("throttled on the baseline cycle")
	}
	e.now = e.now.Add(time.Minute)
	writeFile(t, filepath.Join(e.proc, "pressure", "io"),
		"some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"+
			"full avg10=1.00 avg60=30.00 avg300=26.00 total=0\n")
	writeFile(t, filepath.Join(e.proc, "diskstats"),
		"   8       0 sda 1000 200 8000 500 400 100 6000 34000 0 32000 5000\n"+
			"   8       1 sda1 500 100 4000 250 60 50 3000 4000 0 2000 3000\n")
	h.ioPressure.Run(ctx, env)

	if h.diskWriteAwaitMs != 300 {
		t.Fatalf("writeAwait=%v want 300ms", h.diskWriteAwaitMs)
	}
	if h.diskIOUtilRatio != 0.5 {
		t.Fatalf("ioUtil=%v want 0.5", h.diskIOUtilRatio)
	}
	if h.ioPSIFullAvg60 != 30 || h.ioPSIFullAvg300 != 26 {
		t.Fatalf("psi avgs=%v/%v want 30/26", h.ioPSIFullAvg60, h.ioPSIFullAvg300)
	}
	if len(reniced) != 1 || reniced[0] != 4242 {
		t.Fatalf("reniced=%v want [4242]", reniced)
	}
	if len(ioniced) != 1 || ioniced[0] != 4242 {
		t.Fatalf("ioniced=%v want [4242]", ioniced)
	}
	if h.ioThrottledProcs != 1 {
		t.Fatalf("throttled=%d want 1", h.ioThrottledProcs)
	}
	// The same pid must not be re-throttled while pressure persists.
	h.ioPressure.Run(ctx, env)
	if len(reniced) != 1 {
		t.Fatalf("pid re-throttled: reniced=%v", reniced)
	}
	if h.ioThrottledProcs != 1 {
		t.Fatalf("throttled=%d want 1 (dedupe)", h.ioThrottledProcs)
	}
}

// --- conntrack-tcp-liberal-guard ---

func TestConntrackLiberalGuard(t *testing.T) {
	e := fixture(t)
	h := e.h
	ctx := context.Background()
	writeFile(t, filepath.Join(e.sysnet, "neb1", "mtu"), "1300\n")
	sysctl := filepath.Join(e.proc, "sys", "net", "netfilter",
		"nf_conntrack_tcp_be_liberal")
	writeFile(t, sysctl, "0\n")

	h.conntrackLiberal.Run(ctx, &cycleEnv{workerActive: true})
	if got := nhReadFile(t, sysctl); got != "1\n" {
		t.Fatalf("be_liberal=%q want \"1\\n\"", got)
	}
	if h.conntrackLiberalFixes != 1 {
		t.Fatalf("fixes=%d want 1", h.conntrackLiberalFixes)
	}
	// Idempotent: already 1 → no second fix.
	h.conntrackLiberal.Run(ctx, &cycleEnv{workerActive: true})
	if h.conntrackLiberalFixes != 1 {
		t.Fatalf("fixes=%d want 1 (idempotent)", h.conntrackLiberalFixes)
	}
}

func TestConntrackLiberalGuardNeedsNeb1(t *testing.T) {
	e := fixture(t)
	h := e.h
	ctx := context.Background()
	// No neb1 under sysnet — the guard must not touch the sysctl.
	sysctl := filepath.Join(e.proc, "sys", "net", "netfilter",
		"nf_conntrack_tcp_be_liberal")
	writeFile(t, sysctl, "0\n")
	h.conntrackLiberal.Run(ctx, &cycleEnv{workerActive: true})
	if got := nhReadFile(t, sysctl); got != "0\n" {
		t.Fatalf("be_liberal=%q want \"0\\n\" without neb1", got)
	}
	if h.conntrackLiberalFixes != 0 {
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
	h := e.h
	ctx := context.Background()
	konn := konnPodOnNode(uidC)
	if _, err := e.cs.CoreV1().Pods("kube-system").Create(ctx, konn,
		metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	logs := t.TempDir()
	h.cfg.Disk.PodLogsDir = logs
	writeFile(t, filepath.Join(logs,
		"kube-system_konnectivity-agent-abc12_"+uidC,
		"konnectivity-agent", "0.log"),
		"E0101 dial tcp: konnectivity-server: x509: certificate has expired or is not yet valid\n")
	writeFile(t, filepath.Join(e.state, "clock-stepped-at"),
		fmt.Sprintf("%d\n", e.now.Unix()))
	env := &cycleEnv{
		pods:         []corev1.Pod{*konn},
		apiOK:        true,
		workerActive: true,
	}
	h.clockJump.Run(ctx, env)
	if n := len(deleteActions(e.cs)); n != 1 {
		t.Fatalf("deletes=%d want 1 (konnectivity recreated)", n)
	}
	// Cooldown: same cycle evidence → still one delete.
	h.clockJump.Run(ctx, env)
	if n := len(deleteActions(e.cs)); n != 1 {
		t.Fatalf("deletes=%d want 1 (30m cooldown held)", n)
	}
}

func TestClockJumpSessionHealerNeedsFreshMarker(t *testing.T) {
	e := fixture(t)
	h := e.h
	ctx := context.Background()
	konn := konnPodOnNode(uidC)
	if _, err := e.cs.CoreV1().Pods("kube-system").Create(ctx, konn,
		metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	logs := t.TempDir()
	h.cfg.Disk.PodLogsDir = logs
	writeFile(t, filepath.Join(logs,
		"kube-system_konnectivity-agent-abc12_"+uidC,
		"konnectivity-agent", "0.log"),
		"x509: certificate has expired\n")
	// Marker from 2h ago — outside the 10m attribution window.
	writeFile(t, filepath.Join(e.state, "clock-stepped-at"),
		fmt.Sprintf("%d\n", e.now.Add(-2*time.Hour).Unix()))
	h.clockJump.Run(ctx, &cycleEnv{
		pods: []corev1.Pod{*konn}, apiOK: true, workerActive: true})
	if n := len(deleteActions(e.cs)); n != 0 {
		t.Fatalf("deletes=%d want 0 on a stale marker", n)
	}
}

// --- orphan-hostpath early return ---

func TestOrphanHostPathEarlyReturnSkipsPVList(t *testing.T) {
	e := fixture(t)
	h := e.h
	ctx := context.Background()
	h.cfg.Disk.OrphanHostPathDirs = []string{t.TempDir()} // no pvc-* dirs
	// Pretend a previous cycle left counts behind — the early
	// return must still zero them.
	h.orphanHostPathDirs = 7
	h.orphanHostPathBytes = 999

	h.orphanHP.Run(ctx, &cycleEnv{workerActive: true})

	for _, a := range e.cs.Actions() {
		if a.GetResource().Resource == "persistentvolumes" {
			t.Fatalf("PV list ran with zero candidates: %v", a)
		}
	}
	if h.orphanHostPathDirs != 0 || h.orphanHostPathBytes != 0 {
		t.Fatalf("stale gauges kept: dirs=%d bytes=%d",
			h.orphanHostPathDirs, h.orphanHostPathBytes)
	}
	// Sanity: with a real pvc-* dir the PV list must still run.
	prov := t.TempDir()
	if err := os.MkdirAll(filepath.Join(prov, "pvc-x"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.cfg.Disk.OrphanHostPathDirs = []string{prov}
	h.orphanHP.Run(ctx, &cycleEnv{workerActive: true})
	sawPVList := false
	for _, a := range e.cs.Actions() {
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
