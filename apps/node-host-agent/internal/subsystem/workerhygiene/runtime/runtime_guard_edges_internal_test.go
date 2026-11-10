// runtime_guard_edges_internal_test.go — package-internal coverage
// for the disk-bloat eviction cycle, the dev-shm gauge branches, the
// sa-token-ttl stall/nudge path, the kernel-net-shim helpers and the
// WD_SIG gate head of every runtime check.
package runtime

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// rtDeps builds a minimal *wdeps.Deps over the shared fixture — the
// same shape disk_bloat_internal_test.go uses.
func rtDeps(t *testing.T) (*wdeps.Deps, *wdepstest.Fixture) {
	t.Helper()
	f := wdepstest.New(t)
	cfg := f.Cfg
	cfg.ApplyDefaults()
	d := &wdeps.Deps{
		Cfg:  cfg,
		Proc: procfs.New(cfg.ProcRoot),
		State: subframe.StoreAt(cfg.WatchdogStateDir, cfg.WatchdogLogFile,
			cfg.Seams.Host.Clock,
			func() *slog.Logger {
				return slog.New(slog.NewTextHandler(io.Discard, nil))
			}),
	}
	d.Cycles, d.Actions = subframe.Counters("runtime-edge-test",
		"test cycles", "test actions")
	f.Bind(d)
	return d, f
}

func rtLatchPath(t *testing.T, d *wdeps.Deps, name string) string {
	t.Helper()
	return filepath.Join(d.Cfg.WatchdogStateDir, "state-"+name)
}

func rtRequireLatch(t *testing.T, d *wdeps.Deps, name string, want bool) {
	t.Helper()
	_, err := os.Stat(rtLatchPath(t, d, name))
	if want && err != nil {
		t.Fatalf("state-%s latch missing: %v", name, err)
	}
	if !want && !os.IsNotExist(err) {
		t.Fatalf("state-%s latch must be absent, err=%v", name, err)
	}
}

func rtLog(t *testing.T, f *wdepstest.Fixture) string {
	t.Helper()
	return f.LogLines(t)
}

// fullStatfs answers every statfs with a 100-block fs, 2 free —
// used=0.98, above the 0.85 warn and 0.92 critical watermarks.
func fullStatfs(d *wdeps.Deps) {
	d.Cfg.Seams.Host.StatfsFn = func(_ string, st *unix.Statfs_t) error {
		st.Blocks = 100
		st.Bavail = 2
		return nil
	}
}

// --- disk_bloat.go: DiskBloatCheck.Run ---

func TestDiskBloatRunAbortAndQuiet(t *testing.T) {
	ctx := context.Background()

	// statfs garbage → inconclusive abort, latch kept.
	d, _ := rtDeps(t)
	c := NewDiskBloat(d)
	d.Cfg.Seams.Host.StatfsFn = func(_ string, st *unix.Statfs_t) error {
		return os.ErrPermission
	}
	wdepstest.WriteFile(t, rtLatchPath(t, d, latchdefs.LatchDiskBloat), "old\n")
	c.Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
	rtRequireLatch(t, d, latchdefs.LatchDiskBloat, true)

	// Under the watermark → latch exited, quiet ok.
	d2, _ := rtDeps(t)
	c2 := NewDiskBloat(d2)
	d2.Cfg.Seams.Host.StatfsFn = func(_ string, st *unix.Statfs_t) error {
		st.Blocks = 100
		st.Bavail = 90
		return nil
	}
	c2.Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
	rtRequireLatch(t, d2, latchdefs.LatchDiskBloat, false)

	// Blocks=0 garbage → abort.
	d2.Cfg.Seams.Host.StatfsFn = func(_ string, st *unix.Statfs_t) error {
		st.Blocks = 0
		return nil
	}
	c2.Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
}

func TestDiskBloatRunScanEvictCooldown(t *testing.T) {
	ctx := context.Background()
	d, f := rtDeps(t)
	c := NewDiskBloat(d)
	// Shrink the scan interval so every advance below re-runs the
	// walk while the 15m evict budget still gates; statfs starts at
	// 0.90 — above the warn watermark (scan + latch + ACTION lines)
	// but under the 0.92 critical band, so the first cycles never
	// spend the evict budget.
	d.Cfg.Disk.BloatScanInterval = time.Minute
	d.Cfg.Disk.BloatPodThresholdBytes = 10 // tiny: every real dir is a hit
	d.Cfg.Disk.PodLogsDir = filepath.Join(f.Cfg.K0sDataDir, "podlogs")
	d.Cfg.Seams.Host.StatfsFn = func(_ string, st *unix.Statfs_t) error {
		st.Blocks = 100
		st.Bavail = 10 // used=0.90
		return nil
	}

	// (1) emptyDir volume billed to pod uid-a (100 bytes).
	vol := filepath.Join(d.Cfg.PodsDir, wdepstest.UIDA,
		"volumes", "kubernetes.io~empty-dir", "scratch")
	wdepstest.WriteFile(t, filepath.Join(vol, "data"), strings.Repeat("x", 100))
	// (2) unresolved containerd snapshot (hits-only, no pod billing).
	snap := filepath.Join(d.Cfg.K0sDataDir, "containerd",
		"io.containerd.snapshotter.v1.overlayfs", "snapshots", "7", "fs")
	wdepstest.WriteFile(t, filepath.Join(snap, "layer"), strings.Repeat("y", 60))
	// (3) pod stdout log dir billed to uid-b via the dir name.
	logDir := filepath.Join(d.Cfg.Disk.PodLogsDir, "default_web_"+wdepstest.UIDB)
	wdepstest.WriteFile(t, filepath.Join(logDir, "0.log"), strings.Repeat("z", 80))

	// Pods: an evictable hog plus three over-threshold protected pods.
	victim := f.AssignedPod("hog", wdepstest.UIDA, time.Hour)
	victim.Namespace = "app"
	sys := f.AssignedPod("sys", wdepstest.UIDC, time.Hour)
	sys.Namespace = "kube-system"
	sts := f.AssignedPod("sts", wdepstest.UIDD, time.Hour)
	sts.OwnerReferences = []metav1.OwnerReference{{Kind: "StatefulSet"}}
	term := f.TerminatingPod("term", "app", wdepstest.UIDE, time.Hour)
	e := &wdeps.CycleEnv{WorkerActive: true, APIOK: true,
		Pods:     []corev1.Pod{*victim, *sys, *sts, *term},
		PidsOnce: wdepstest.PidsOf()}

	// First above-watermark cycle: scan runs → latch + ACTION lines.
	c.Run(ctx, e)
	rtRequireLatch(t, d, latchdefs.LatchDiskBloat, true)
	log := rtLog(t, f)
	if !strings.Contains(log, "target=pod app/hog volume scratch") ||
		!strings.Contains(log, "target=snapshot 7") ||
		!strings.Contains(log, "target=pod-logs default_web_"+wdepstest.UIDB) {
		t.Fatalf("want all three hit classes in ACTION lines, log=%q", log)
	}

	// Inside the scan interval the walk is skipped entirely.
	c.Run(ctx, e)

	// Past the interval at 0.98 used (> critical) and APIOK → the
	// hog (largest non-protected total) is evicted.
	// The eviction goes through the real clientset — seed the pods.
	for _, p := range []*corev1.Pod{victim, sys, sts, term} {
		if _, err := f.CS.CoreV1().Pods(p.Namespace).Create(
			ctx, p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	fullStatfs(d)
	f.Now = f.Now.Add(2 * time.Minute)
	c.Run(ctx, e)
	evicted := wdepstest.EvictActions(f.CS)
	if len(evicted) == 0 {
		t.Fatal("the disk-bloat victim must be evicted")
	}
	for _, n := range evicted {
		if n != "hog" {
			t.Fatalf("evicted=%v want only hog", evicted)
		}
	}
	if !strings.Contains(rtLog(t, f),
		"ACTION: disk-bloat evicted pod app/hog") {
		t.Fatalf("want ACTION evict line, log=%q", rtLog(t, f))
	}

	// Next scan inside the evict budget → cooldown skip, no 2nd evict.
	f.Now = f.Now.Add(2 * time.Minute)
	c.Run(ctx, e)
	if got := wdepstest.EvictActions(f.CS); len(got) != len(evicted) {
		t.Fatalf("cooldown cycle evicted %v, want no second evict", got)
	}
	if !strings.Contains(rtLog(t, f), "in evict cooldown") {
		t.Fatalf("want cooldown skip line, log=%q", rtLog(t, f))
	}

	// Budget expired → evicted again.
	f.Now = f.Now.Add(20 * time.Minute)
	c.Run(ctx, e)
	if got := wdepstest.EvictActions(f.CS); len(got) <= len(evicted) {
		t.Fatalf("post-budget evicted=%v want a second evict", got)
	}

	// Churn drains the dirs → scan finds no hits → latch exited.
	if err := os.RemoveAll(vol); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(snap); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(logDir); err != nil {
		t.Fatal(err)
	}
	f.Now = f.Now.Add(2 * time.Minute)
	c.Run(ctx, e)
	rtRequireLatch(t, d, latchdefs.LatchDiskBloat, false)
}

// --- dev_shm.go: measureDevShm branches ---

func TestMeasureDevShmBranches(t *testing.T) {
	d, _ := rtDeps(t)
	c := NewDevShm(d)

	// statfs failure → keep the last gauge, never fake a 0.
	d.DevShmUsedRatio = 0.42
	d.Cfg.Seams.Host.StatfsFn = func(_ string, st *unix.Statfs_t) error {
		return os.ErrPermission
	}
	c.measureDevShm()
	if d.DevShmUsedRatio != 0.42 {
		t.Fatalf("failed statfs ratio=%v want kept 0.42", d.DevShmUsedRatio)
	}

	// Zero blocks → unmeasurable.
	d.Cfg.Seams.Host.StatfsFn = func(_ string, st *unix.Statfs_t) error {
		st.Blocks = 0
		return nil
	}
	c.measureDevShm()
	if d.DevShmUsedRatio != 0.42 {
		t.Fatalf("zero-block statfs ratio=%v want kept 0.42", d.DevShmUsedRatio)
	}

	// Byte fill 90/100 → 0.10.
	d.Cfg.Seams.Host.StatfsFn = func(_ string, st *unix.Statfs_t) error {
		st.Blocks, st.Bavail = 100, 10
		return nil
	}
	c.measureDevShm()
	if d.DevShmUsedRatio != 0.90 {
		t.Fatalf("ratio=%v want 0.90", d.DevShmUsedRatio)
	}

	// Inode exhaustion worse than byte fill → the max wins.
	d.Cfg.Seams.Host.StatfsFn = func(_ string, st *unix.Statfs_t) error {
		st.Blocks, st.Bavail = 100, 50
		st.Files, st.Ffree = 100, 5
		return nil
	}
	c.measureDevShm()
	if d.DevShmUsedRatio != 0.95 {
		t.Fatalf("inode-pressured ratio=%v want 0.95", d.DevShmUsedRatio)
	}
}

// --- runtime_sa_token_ttl.go ---

func b64JWT(t *testing.T, payload string) string {
	t.Helper()
	return "hdr." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
}

func TestJWTExpUnix(t *testing.T) {
	if _, ok := jwtExpUnix("not-a-jwt"); ok {
		t.Fatal("malformed token must not parse")
	}
	if _, ok := jwtExpUnix("a.###.c"); ok {
		t.Fatal("bad base64 payload must not parse")
	}
	if _, ok := jwtExpUnix(b64JWT(t, `{"sub":"x"}`)); ok {
		t.Fatal("missing exp must not parse")
	}
	exp, ok := jwtExpUnix(b64JWT(t, `{"exp":1770000000}`))
	if !ok || exp != 1770000000 {
		t.Fatalf("jwtExpUnix=%d,%v want 1770000000,true", exp, ok)
	}
}

func TestProjectedTokenFiles(t *testing.T) {
	dir := t.TempDir()
	if got := projectedTokenFiles(dir); len(got) != 0 {
		t.Fatalf("empty pod dir files=%v want none", got)
	}
	vol := filepath.Join(dir, "volumes", "kubernetes.io~projected", "kube-api")
	wdepstest.WriteFile(t, filepath.Join(vol, "token"), "tok")
	wdepstest.WriteFile(t, filepath.Join(vol, "namespace"), "ns")
	got := projectedTokenFiles(dir)
	if len(got) != 1 || !strings.HasSuffix(got[0], "token") {
		t.Fatalf("projectedTokenFiles=%v want the one token", got)
	}
}

func TestSATokenTTLRunStallAndDedupe(t *testing.T) {
	ctx := context.Background()
	d, f := rtDeps(t)
	c := NewSATokenTTL(d)
	now := time.Unix(1770000000, 0)
	f.Now = now

	// A Running pod on this node holding a token that expires in
	// 100s (< 600s floor) — plus a Succeeded pod with the same
	// staleness (counted in the gauge, never nudged) and a pod with
	// a garbage token (skipped).
	running := f.AssignedPod("stale", wdepstest.UIDA, time.Hour)
	if _, err := f.CS.CoreV1().Pods("default").Create(
		ctx, running, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	done := f.AssignedPod("done", wdepstest.UIDB, time.Hour)
	done.Status.Phase = corev1.PodSucceeded
	tokVol := func(uid string) string {
		return filepath.Join(d.Cfg.PodsDir, uid,
			"volumes", "kubernetes.io~projected", "kube-api")
	}
	wdepstest.WriteFile(t, filepath.Join(tokVol(wdepstest.UIDA), "token"),
		b64JWT(t, `{"exp":1770000100}`)+"\n")
	wdepstest.WriteFile(t, filepath.Join(tokVol(wdepstest.UIDB), "token"),
		b64JWT(t, `{"exp":1770000100}`))
	wdepstest.WriteFile(t, filepath.Join(tokVol(wdepstest.UIDC), "token"), "garbage")

	e := &wdeps.CycleEnv{WorkerActive: true, APIOK: true,
		Pods:     []corev1.Pod{*running, *done},
		PidsOnce: wdepstest.PidsOf()}
	c.Run(ctx, e)

	if d.SATokenMinTTLSec != 100 {
		t.Fatalf("SATokenMinTTLSec=%v want 100", d.SATokenMinTTLSec)
	}
	if !strings.Contains(rtLog(t, f),
		"ACTION: sa-token-ttl nudged default/stale") {
		t.Fatalf("want nudge ACTION line, log=%q", rtLog(t, f))
	}
	live, err := f.CS.CoreV1().Pods("default").Get(
		ctx, "stale", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	stamp := live.Annotations["passiontech.dev/token-resync-at"]
	if stamp == "" {
		t.Fatal("resync annotation missing on the nudged pod")
	}
	if _, err := f.CS.CoreV1().Events("default").List(
		ctx, metav1.ListOptions{}); err != nil {
		t.Fatal(err)
	}

	// The annotation dedupes: a second cycle inside the 15m window
	// must not nudge again (mtime of the ACTION line count stays 1).
	c.Run(ctx, e)
	if n := strings.Count(rtLog(t, f), "ACTION: sa-token-ttl nudged"); n != 1 {
		t.Fatalf("nudge lines=%d want 1 (annotation dedupe)", n)
	}

	// Past the cooldown the pod is nudged again.
	f.Now = now.Add(16 * time.Minute)
	c.Run(ctx, e)
	if n := strings.Count(rtLog(t, f), "ACTION: sa-token-ttl nudged"); n != 2 {
		t.Fatalf("nudge lines=%d want 2 after the cooldown", n)
	}
}

// --- runtime_kernel_net_shim.go helpers ---

func TestKernelShimHelpers(t *testing.T) {
	d, f := rtDeps(t)

	// isContainerdShim: comm + argv[0] basename, not substrings.
	f.MkProc(t, 700, "S",
		"/usr/bin/containerd-shim-runc-v2\x00-namespace\x00k8s.io\x00-id\x00task7", "")
	wdepstest.WriteFile(t, filepath.Join(d.Cfg.ProcRoot, "700", "comm"),
		"containerd-shim\n")
	if !isContainerdShim(d, 700) {
		t.Fatal("shim comm + matching argv[0] must classify as shim")
	}
	wdepstest.WriteFile(t, filepath.Join(d.Cfg.ProcRoot, "700", "comm"),
		"containerd-shim-runc-v2\n")
	if !isContainerdShim(d, 700) {
		t.Fatal("full shim comm must also classify")
	}
	// A pod process carrying the string in its argv is NOT a shim.
	f.MkProc(t, 701, "S", "pod-containerd-shim-runc-v2-simulator", "")
	wdepstest.WriteFile(t, filepath.Join(d.Cfg.ProcRoot, "701", "comm"),
		"fakeproc\n")
	if isContainerdShim(d, 701) {
		t.Fatal("wrong comm must not classify")
	}
	if isContainerdShim(d, 702) {
		t.Fatal("missing proc must not classify")
	}

	// shimRSSBytes: VmRSS kB → bytes; unreadable → 0.
	wdepstest.WriteFile(t, filepath.Join(d.Cfg.ProcRoot, "700", "status"),
		"Name:\tx\nVmRSS:\t2048 kB\n")
	if got := shimRSSBytes(d, 700); got != 2048<<10 {
		t.Fatalf("shimRSSBytes=%d want 2MiB", got)
	}
	if got := shimRSSBytes(d, 702); got != 0 {
		t.Fatalf("missing pid shimRSSBytes=%d want 0", got)
	}

	// shimTaskID: the -id argv pair; absent → "unknown".
	if got := shimTaskID(d, 700); got != "task7" {
		t.Fatalf("shimTaskID=%q want task7", got)
	}
	if got := shimTaskID(d, 701); got != "unknown" {
		t.Fatalf("no -id shimTaskID=%q want unknown", got)
	}

	// readProcInt: readable sysctl trimmed; unreadable → "?".
	wdepstest.WriteFile(t, filepath.Join(d.Cfg.ProcRoot, "sys", "net", "ipv4", "tcp"),
		" 42 \n")
	if got := readProcInt(d.Cfg.ProcRoot, filepath.Join("sys", "net", "ipv4", "tcp")); got != "42" {
		t.Fatalf("readProcInt=%q want 42", got)
	}
	if got := readProcInt(d.Cfg.ProcRoot, "sys/nope"); got != "?" {
		t.Fatalf("unreadable readProcInt=%q want ?", got)
	}
}

// --- checks.go + every Run's gate head ---

// TestRuntimeChecksGated drives every runtime check with the worker
// down — the WD_SIG gate head each Run shares must answer
// "gated, not healthy" without touching any host state.
func TestRuntimeChecksGated(t *testing.T) {
	ctx := context.Background()
	d, _ := rtDeps(t)
	e := &wdeps.CycleEnv{WorkerActive: false}
	checks := []wdeps.Check{
		NewDiskBloat(d), NewDevShm(d), NewRunTmpfs(d),
		NewLocalPVQuota(d), NewCoredumpGC(d), NewWritableLayer(d),
		NewCgroupDying(d), NewSystemdSession(d), NewOverlayFSStale(d),
		NewIOPressure(d), NewConntrackLiberal(d), NewClockJump(d),
		NewUnlinkedOpenFiles(d), NewCgroupSwap(d), NewCgroupThrottle(d),
		NewSubprocOOM(d), NewSATokenTTL(d), NewKernelNetShim(d),
		NewHostOOM(d), NewOrphanHP(d),
	}
	for _, c := range checks {
		c.Run(ctx, e)
	}
	data, err := os.ReadFile(d.Cfg.WatchdogLogFile)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "ACTION:") {
		t.Fatalf("gated cycle must take no action, log=%q", string(data))
	}
}

// --- host_oom.go: compactMemory ---

func TestHostOOMCompactMemory(t *testing.T) {
	d, f := rtDeps(t)
	c := NewHostOOM(d)
	sysctl := filepath.Join(d.Cfg.ProcRoot, "sys", "vm", "compact_memory")

	// Latch not held → nothing happens even with the sysctl there.
	wdepstest.WriteFile(t, sysctl, "0\n")
	c.compactMemory()

	// Latch held + sysctl present → write 1, exit the latch, bump.
	wdepstest.WriteFile(t, rtLatchPath(t, d, latchdefs.LatchPageAllocFailure), "1\n")
	c.compactMemory()
	if data := readFileT(t, sysctl); data != "1" {
		t.Fatalf("compact_memory=%q want 1", data)
	}
	rtRequireLatch(t, d, latchdefs.LatchPageAllocFailure, false)
	if c.d.MemoryCompactionRuns != 1 {
		t.Fatalf("compaction runs=%d want 1", c.d.MemoryCompactionRuns)
	}

	// Budget spent → no second compaction inside 30m.
	wdepstest.WriteFile(t, rtLatchPath(t, d, latchdefs.LatchPageAllocFailure), "1\n")
	c.compactMemory()
	if c.d.MemoryCompactionRuns != 1 || readFileT(t, sysctl) != "1" {
		t.Fatal("budgeted compaction must not re-run")
	}

	// After the budget it compacts again.
	f.Now = f.Now.Add(time.Hour)
	c.compactMemory()
	if c.d.MemoryCompactionRuns != 2 {
		t.Fatalf("compaction runs=%d want 2 after the budget", c.d.MemoryCompactionRuns)
	}

	// Sysctl missing (unmounted proc) → quiet no-op.
	d2, _ := rtDeps(t)
	c2 := NewHostOOM(d2)
	wdepstest.WriteFile(t, rtLatchPath(t, d2, latchdefs.LatchPageAllocFailure), "1\n")
	c2.compactMemory()
	if c2.d.MemoryCompactionRuns != 0 {
		t.Fatal("missing sysctl must be a quiet no-op")
	}
}

func readFileT(t *testing.T, p string) string {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

// --- runtime_conntrack_liberal.go Run branches ---

func TestConntrackRunBranches(t *testing.T) {
	ctx := context.Background()

	// No nebula iface → kernel default left alone, quiet ok.
	d0, _ := rtDeps(t)
	NewConntrackLiberal(d0).Run(ctx, &wdeps.CycleEnv{WorkerActive: true})

	// Nebula iface present, sysctl absent → dormant abort.
	d1, _ := rtDeps(t)
	wdepstest.WriteFile(t, filepath.Join(d1.Cfg.SysClassNet, d1.Cfg.NebulaIface), "")
	NewConntrackLiberal(d1).Run(ctx, &wdeps.CycleEnv{WorkerActive: true})

	// sysctl already 1 → nothing to do.
	d2, _ := rtDeps(t)
	wdepstest.WriteFile(t, filepath.Join(d2.Cfg.SysClassNet, d2.Cfg.NebulaIface), "")
	wdepstest.WriteFile(t, filepath.Join(d2.Cfg.ProcRoot, "sys", "net",
		"netfilter", "nf_conntrack_tcp_be_liberal"), "1\n")
	NewConntrackLiberal(d2).Run(ctx, &wdeps.CycleEnv{WorkerActive: true})

	// sysctl 0 → the neb1 fix is written, counted and logged.
	d3, f3 := rtDeps(t)
	wdepstest.WriteFile(t, filepath.Join(d3.Cfg.SysClassNet, d3.Cfg.NebulaIface), "")
	sysctl := filepath.Join(d3.Cfg.ProcRoot, "sys", "net", "netfilter",
		"nf_conntrack_tcp_be_liberal")
	wdepstest.WriteFile(t, sysctl, "0\n")
	NewConntrackLiberal(d3).Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
	if readFileT(t, sysctl) != "1" {
		t.Fatal("be_liberal=0 with a nebula iface must be fixed to 1")
	}
	if d3.ConntrackLiberalFixes != 1 ||
		!strings.Contains(rtLog(t, f3), "ACTION: conntrack-tcp-liberal-guard set") {
		t.Fatal("fix must be counted and logged")
	}

	// The write failing (read-only sysctl) logs suspect, no count.
	d4, f4 := rtDeps(t)
	wdepstest.WriteFile(t, filepath.Join(d4.Cfg.SysClassNet, d4.Cfg.NebulaIface), "")
	sysctl4 := filepath.Join(d4.Cfg.ProcRoot, "sys", "net", "netfilter",
		"nf_conntrack_tcp_be_liberal")
	wdepstest.WriteFile(t, sysctl4, "0\n")
	if err := os.Chmod(sysctl4, 0o444); err != nil {
		t.Fatal(err)
	}
	NewConntrackLiberal(d4).Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
	if d4.ConntrackLiberalFixes != 0 ||
		!strings.Contains(rtLog(t, f4), "suspect: conntrack-tcp-liberal-guard write") {
		t.Fatal("failed sysctl write must log suspect without counting")
	}
}

// --- runtime_overlayfs_stale.go: pod-level failed-phase match ---

func TestOverlayFSStalePodLevelMessage(t *testing.T) {
	ctx := context.Background()
	d, f := rtDeps(t)
	c := NewOverlayFSStale(d)
	// API flake → abort before any verdict.
	d.Cfg.Seams.Host.Clock.Now() // clock wired via the fixture
	e := &wdeps.CycleEnv{WorkerActive: true, APIOK: false}
	c.Run(ctx, e)

	// A pod that exhausted retries reports the stale-mount failure at
	// pod level (Failed phase, pod Status.Message) — same remedy as
	// the container-level Waiting message.
	pod := f.AssignedPod("stale", wdepstest.UIDA, time.Hour)
	pod.Status.Phase = corev1.PodFailed
	pod.Status.Message = "failed to mount overlay: stale file handle"
	if _, err := f.CS.CoreV1().Pods("default").Create(
		ctx, pod, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e2 := &wdeps.CycleEnv{WorkerActive: true, APIOK: true,
		Pods: []corev1.Pod{*pod}, PidsOnce: wdepstest.PidsOf()}
	c.Run(ctx, e2)
	if !strings.Contains(rtLog(t, f), "overlayfs-stale") {
		t.Fatalf("want overlayfs-stale evidence, log=%q", rtLog(t, f))
	}
}

// --- localpv_quota.go: the full over-quota throttle cycle ---

func TestLocalPVQuotaThrottleCycle(t *testing.T) {
	ctx := context.Background()
	d, f := rtDeps(t)
	c := NewLocalPVQuota(d)
	fullStatfs(d) // 98% used — above the disk-pressure watermark

	pvName := "pvc-LocalPVQuotaCycle"
	quotaDir := filepath.Join(t.TempDir(), "localpv")
	pvcDir := filepath.Join(quotaDir, pvName)
	wdepstest.WriteFile(t, filepath.Join(pvcDir, "data"),
		strings.Repeat("q", 4000))
	d.Cfg.Disk.LocalPVQuotaDir = quotaDir

	pod := f.AssignedPod("pvuser", wdepstest.UIDA, time.Hour)
	pod.Spec.Volumes = []corev1.Volume{{
		Name: "data",
		VolumeSource: corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: "claim-a",
			},
		},
	}}
	pv := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: pvName},
		Spec: corev1.PersistentVolumeSpec{
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse("1Ki"), // 1024B cap
			},
		}}
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "claim-a", Namespace: "default"},
		Spec:       corev1.PersistentVolumeClaimSpec{VolumeName: pvName},
	}
	if _, err := f.CS.CoreV1().PersistentVolumes().Create(ctx, pv, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.CS.CoreV1().PersistentVolumeClaims("default").
		Create(ctx, pvc, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.CS.CoreV1().Pods("default").Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	// A live task for the pod → renice+ionice land on it; the pod
	// slice with an io.weight file gets the weight drop.
	f.Live[9001] = true
	f.MkProc(t, 9001, "S", "", "")
	d.Cfg.Runtime.CgroupRoot = t.TempDir()
	kubepods := filepath.Join(d.Cfg.Runtime.CgroupRoot, "kubepods.slice")
	podSlice := filepath.Join(kubepods, "kubepods-burstable.slice",
		"kubepods-burstable-pod"+strings.ReplaceAll(wdepstest.UIDA, "-", "_")+".slice")
	wdepstest.WriteFile(t, filepath.Join(podSlice, "io.weight"), "100\n")
	scope := filepath.Join(podSlice, "cri-containerd-x.scope")
	wdepstest.WriteFile(t, filepath.Join(scope, "io.weight"), "100\n")

	reniced := 0
	d.Cfg.Seams.Host.ReniceFn = func(pid int) error {
		if pid == 9001 {
			reniced++
		}
		return nil
	}
	d.Cfg.Seams.Host.IoniceIdleFn = func(pid int) error {
		if pid == 9001 {
			reniced++
		}
		return nil
	}

	e := &wdeps.CycleEnv{WorkerActive: true, APIOK: true,
		Pods:     []corev1.Pod{*pod},
		PidsOnce: wdepstest.PidsOf(),
		TasksOnce: func() (map[string][]wdeps.CtrTask, bool) {
			return map[string][]wdeps.CtrTask{
				wdepstest.UIDA: {{UID: wdepstest.UIDA, PID: 9001, Live: true}},
			}, true
		},
	}
	c.Run(ctx, e)
	if reniced != 2 {
		t.Fatalf("renice+ionice calls=%d want 2", reniced)
	}
	if readFileT(t, filepath.Join(podSlice, "io.weight")) != "1" ||
		readFileT(t, filepath.Join(scope, "io.weight")) != "1" {
		t.Fatal("pod + container io.weight must drop to 1")
	}
	if c.d.LocalPVQuotaThrottled != 1 {
		t.Fatalf("throttled=%d want 1", c.d.LocalPVQuotaThrottled)
	}
	if !strings.Contains(rtLog(t, f), "ACTION: LocalPVQuotaExceeded") ||
		!strings.Contains(rtLog(t, f), "1 tasks deprioritized") {
		t.Fatalf("want quota-exceeded ACTION, log=%q", rtLog(t, f))
	}

	// The throttled dir is remembered — the next cycle skips it.
	c.Run(ctx, e)
	if c.d.LocalPVQuotaThrottled != 1 {
		t.Fatalf("repeat cycle throttled=%d want still 1", c.d.LocalPVQuotaThrottled)
	}

	// No candidates on disk → the cluster-wide PV/PVC lists are skipped.
	d2, _ := rtDeps(t)
	c2 := NewLocalPVQuota(d2)
	d2.Cfg.Disk.LocalPVQuotaDir = t.TempDir()
	c2.Run(ctx, &wdeps.CycleEnv{WorkerActive: true, APIOK: true})

	// API flake → the quota scan is inconclusive, never acts.
	c2.Run(ctx, &wdeps.CycleEnv{WorkerActive: true, APIOK: false})
}
