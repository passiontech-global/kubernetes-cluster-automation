// kernelfail_test.go — the W10 latch-contract coverage that used
// to be kernel_failure_latches_test.go: the kmsg classification +
// cursor resume, the pid/fd pressure streaks, clock-skew makestep +
// latch, and the ro-mount / kmsg-marker fs-readonly evidence.
package kernelfail

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// --- W10-KR1: kmsg classification ---

func TestKmsgFSAndConntrack(t *testing.T) {
	f := kfixture(t)
	kmsgFixture(t, f.deps,
		"EXT4-fs error (device sda1): ext4_journal_check_start: "+
			"detected aborted journal",
		"nf_conntrack: table full, dropping packet",
		"nf_conntrack: table full, dropping packet",
		"random unrelated kernel line")
	// Conntrack max file for the sysctl-bump path.
	testutil.WriteFile(t, f.deps.ConntrackMaxFile, "262144\n")
	f.r.checkKernelDmesg()
	if _, err := os.Stat(filepath.Join(f.deps.StateDir,
		kmsgFsErrorFile)); err != nil {
		t.Fatal("kmsg-fs-error marker missing")
	}
	got := strings.TrimSpace(testutil.ReadFile(t,
		filepath.Join(f.deps.StateDir, kmsgConntrackDropsFile)))
	if got != "2" {
		t.Fatalf("conntrack drops=%q want 2", got)
	}
	// Second drain must not double-count — the fd sits at EOF.
	f.r.checkKernelDmesg()
	got = strings.TrimSpace(testutil.ReadFile(t,
		filepath.Join(f.deps.StateDir, kmsgConntrackDropsFile)))
	if got != "2" {
		t.Fatalf("conntrack drops after re-drain=%q want 2", got)
	}
}

func TestKmsgOOMClassification(t *testing.T) {
	f := kfixture(t)
	kmsgFixture(t, f.deps,
		"oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),"+
			"cpuset=cri-containerd-abc.scope,mems_allowed=0,"+
			"oom_memcg=/kubepods.slice/pod123,task_memcg=/kubepods.slice/pod123,"+
			"task=web-server,pid=1234,uid=0",
		"Out of memory: Killed process 1234 (web-server) total-vm:1kB",
		"oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),"+
			"cpuset=/,oom_memcg=/system.slice,task=containerd-shim,pid=99",
		"Out of memory: Killed process 99 (containerd-shim) total-vm:2kB",
		"oom-kill:constraint=CONSTRAINT_NONE,task=somepod,pid=55",
		"Out of memory: Killed process 55 (somepod) total-vm:3kB",
		// Memcg OOM variant — the kernel's COMMON cgroup form must
		// classify identically to the global "Out of memory:" line.
		"oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),"+
			"oom_memcg=/system.slice,task_memcg=/system.slice,"+
			"task=kubelet,pid=88",
		"Memory cgroup out of memory: Killed process 88 (kubelet) total-vm:5kB")
	f.r.checkKernelDmesg()
	victim := strings.TrimSpace(testutil.ReadFile(t, filepath.Join(
		f.deps.StateDir, kmsgOOMVictimFile)))
	if !strings.Contains(victim, "kubelet") {
		t.Fatalf("host OOM victim=%q want kubelet (last host kill)", victim)
	}
	count := strings.TrimSpace(testutil.ReadFile(t, filepath.Join(
		f.deps.StateDir, kmsgOOMCountFile)))
	if count != "2" {
		t.Fatalf("host oom count=%q want 2 (pod kills excluded)", count)
	}
}

func TestKmsgFirstOpenPrimesBacklog(t *testing.T) {
	f := kfixture(t)
	// NO cursor — first open must discard the retained backlog.
	bootDir := filepath.Join(f.deps.ProcRoot, "sys", "kernel", "random")
	_ = os.MkdirAll(bootDir, 0o755)
	testutil.WriteFile(t, filepath.Join(bootDir, "boot_id"), "testboot\n")
	devDir := filepath.Dir(f.deps.KmsgDevicePaths(f.deps.HostRoot)[0])
	_ = os.MkdirAll(devDir, 0o755)
	testutil.WriteFile(t, f.deps.KmsgDevicePaths(f.deps.HostRoot)[0],
		"6,1,1000,0;EXT4-fs error old history\n")
	f.r.checkKernelDmesg()
	if _, err := os.Stat(filepath.Join(f.deps.StateDir,
		kmsgFsErrorFile)); !os.IsNotExist(err) {
		t.Fatal("backlog record classified on first open")
	}
}

// --- W10-KR2: pid/thread/fd pressure ---

func TestKernelProcRatios(t *testing.T) {
	f := kfixture(t)
	// Inconclusive when nothing parses.
	if _, _, _, _, _, _, ok := f.r.kernelProcRatios(); ok {
		t.Fatal("empty proc reported ok")
	}
	// file-nr only → fd ratio.
	testutil.WriteFile(t, f.deps.FileNRFile, "900 100 1000\n")
	_, _, fd, _, _, fdOK, ok := f.r.kernelProcRatios()
	if !ok || !fdOK || fd != 0.9 {
		t.Fatalf("fd ratio=%v ok=%v fdOK=%v want 0.9", fd, ok, fdOK)
	}
	// pids: 5 pid dirs / pid_max 10.
	for _, p := range []string{"1", "2", "3", "4", "5"} {
		if err := os.MkdirAll(filepath.Join(f.deps.ProcRoot, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{
		"sys/kernel/pid_max", "sys/kernel/threads-max", "loadavg"} {
		if err := os.MkdirAll(filepath.Join(f.deps.ProcRoot,
			filepath.Dir(file)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	testutil.WriteFile(t, filepath.Join(f.deps.ProcRoot, "sys/kernel/pid_max"), "10\n")
	testutil.WriteFile(t, filepath.Join(f.deps.ProcRoot, "sys/kernel/threads-max"), "100\n")
	testutil.WriteFile(t, filepath.Join(f.deps.ProcRoot, "loadavg"),
		"0.5 0.4 0.3 95/200 1234\n")
	pids, threads, _, pOK, tOK, _, ok := f.r.kernelProcRatios()
	if !ok || !pOK || !tOK {
		t.Fatalf("ratios not ok: pids=%v threads=%v", pids, threads)
	}
	if pids != 0.5 {
		t.Fatalf("pids ratio=%v want 0.5", pids)
	}
	if threads != 2.0 {
		t.Fatalf("threads ratio=%v want 2.0 (loadavg total 200 / threads-max 100)", threads)
	}
}

func TestPidFDPressureLatch(t *testing.T) {
	f := kfixture(t)
	testutil.WriteFile(t, f.deps.FileNRFile, "950 50 1000\n") // 0.95 > 0.90
	for i := 0; i < kernelProcPressureNeeded-1; i++ {
		f.r.updatePidFDPressure()
		if _, err := os.Stat(filepath.Join(f.deps.StateDir,
			"state-pid-fd-pressure")); !os.IsNotExist(err) {
			t.Fatalf("latch set early at tick %d", i+1)
		}
	}
	f.r.updatePidFDPressure()
	if _, err := os.Stat(filepath.Join(f.deps.StateDir,
		"state-pid-fd-pressure")); err != nil {
		t.Fatal("pid-fd-pressure latch missing after 3 ticks")
	}
	// Below threshold clears.
	testutil.WriteFile(t, f.deps.FileNRFile, "100 900 1000\n")
	f.r.updatePidFDPressure()
	if _, err := os.Stat(filepath.Join(f.deps.StateDir,
		"state-pid-fd-pressure")); !os.IsNotExist(err) {
		t.Fatal("latch not cleared below threshold")
	}
	// Textfile gauge emitted.
	textfileDirOverride = t.TempDir()
	f.r.updatePidFDPressure()
	b, err := os.ReadFile(filepath.Join(textfileDirOverride,
		"node-agent-kernel.prom"))
	if err != nil {
		t.Fatalf("kernel prom missing: %v", err)
	}
	if !strings.Contains(string(b),
		"node_agent_file_nr_utilization_ratio 0.1") {
		t.Fatalf("file-nr gauge missing/wrong:\n%s", b)
	}
}

// --- W10-KR5: clock skew ---

func TestParseChronycTracking(t *testing.T) {
	off, synced, ok := parseChronycTracking(
		"Reference ID    : A29FC87B (time.cloudflare.com)\n" +
			"System time     : 0.0012 seconds fast of NTP time\n" +
			"Leap status     : Normal\n")
	if !ok || !synced || off != 0.0012 {
		t.Fatalf("off=%v synced=%v ok=%v", off, synced, ok)
	}
	off, synced, ok = parseChronycTracking(
		"System time     : 3.5 seconds slow of NTP time\n" +
			"Leap status     : Not synchronised\n")
	if !ok || synced || off != -3.5 {
		t.Fatalf("off=%v synced=%v ok=%v", off, synced, ok)
	}
	if _, _, ok := parseChronycTracking("garbage\n"); ok {
		t.Fatal("garbage parsed ok")
	}
}

func TestClockSkew(t *testing.T) {
	f := kfixture(t)
	// chronyc stub: 3s fast + unsynchronised → step + latch path.
	orig := f.r.deps.RunHostCmd
	defer func() { f.r.deps.RunHostCmd = orig }()
	var stepped bool
	f.r.deps.RunHostCmd = func(ctx context.Context, argv ...string) (string, error) {
		if len(argv) > 1 && argv[1] == "makestep" {
			stepped = true
			return "", nil
		}
		return "System time     : 3.0 seconds fast of NTP time\n" +
			"Leap status     : Not synchronised\n", nil
	}
	for i := 0; i < clockSkewLatchNeeded; i++ {
		f.r.checkClockSkew()
	}
	if !stepped {
		t.Fatal("chronyc makestep not attempted")
	}
	if _, err := os.Stat(filepath.Join(f.deps.StateDir,
		"state-clock-skew")); err != nil {
		t.Fatal("clock-skew latch missing")
	}
}

// --- W10-ST1: ro mounts ---

// The parser itself is covered in platform/procfs — this pins the
// consumer-side contract (ro opt lookup) the evidence scan relies
// on.
func TestParseProcMounts(t *testing.T) {
	ms := procfs.ParseMounts([]byte(
		"/dev/sda1 /var/openebs/local/pvc-abc ext4 rw,relatime 0 0\n" +
			"/dev/sdb1 /var/openebs/local/pvc-def xfs ro,relatime 0 0\n" +
			"tmpfs /var/openebs/local/pvc-ghi tmpfs ro 0 0\n" +
			"bad line\n"))
	if len(ms) != 3 {
		t.Fatalf("parsed %d mounts want 3", len(ms))
	}
	if !ms[1].Opts["ro"] || ms[0].Opts["ro"] {
		t.Fatal("ro flag wrong")
	}
}

func TestROPVCMounts(t *testing.T) {
	f := kfixture(t)
	proc1 := filepath.Join(f.deps.ProcRoot, "1")
	if err := os.MkdirAll(proc1, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(proc1, "mounts"),
		"/dev/sda1 /var/openebs/local/pvc-abc ext4 rw,relatime 0 0\n"+
			"/dev/sdb1 /var/openebs/local/pvc-def xfs ro,relatime 0 0\n"+
			"/dev/sdc1 /opt/local-path-provisioner/pvc-ghi ext4 ro 0 0\n"+
			"/dev/sdd1 /var/lib/k0s/kubelet/pods/pod1/volumes/"+
			"kubernetes.io~secret-token ext4 ro 0 0\n"+
			"/dev/sde1 /etc/other xfs ro 0 0\n")
	ros := f.r.roPVCMounts()
	if len(ros) != 2 {
		t.Fatalf("roPVCMounts=%v want 2 (secret excluded, /etc excluded)", ros)
	}
	f.r.updateFSReadonlyEvidence()
	if _, err := os.Stat(filepath.Join(f.deps.StateDir,
		"state-fs-readonly")); err != nil {
		t.Fatal("fs-readonly latch missing")
	}
	// Fresh kmsg fs-error marker alone also latches.
	f2 := kfixture(t)
	testutil.WriteFile(t, filepath.Join(f2.deps.StateDir, kmsgFsErrorFile),
		strconv.FormatInt(time.Now().Unix(), 10)+" ext4 died\n")
	f2.r.updateFSReadonlyEvidence()
	if _, err := os.Stat(filepath.Join(f2.deps.StateDir,
		"state-fs-readonly")); err != nil {
		t.Fatal("fs-readonly latch missing from kmsg marker")
	}
}

// --- clock-warp: wall-clock jump detector ---

// TestClockWarpDetection drives the detector through the WarpDelta
// seam: the public time API cannot synthesize two stamps whose
// monotonic advance differs from their wall advance (both must come
// from real clock reads), so a fake clock can only ever produce a
// zero warp — the controlled gaps are injected, and warpDelta's own
// fallback behavior is pinned separately below.
func TestClockWarpDetection(t *testing.T) {
	f := kfixture(t)
	textfileDirOverride = t.TempDir()
	t.Cleanup(func() { textfileDirOverride = "" })
	now := time.Now()
	f.deps.Clock.Set(func() time.Time { return now })

	// Controlled wall-vs-mono gap: 0 on quiet ticks, ±10s/5s on the
	// incident ticks.
	gap := time.Duration(0)
	f.r.deps.WarpDelta = func(now, prev time.Time) time.Duration {
		return gap
	}

	// First tick primes the baseline — no warp on a zero prev.
	f.r.checkClockWarp()
	if f.r.warp.events != 0 {
		t.Fatal("first tick counted a warp")
	}

	// A tick that fires on cadence (mono advance == wall advance)
	// is clean.
	f.r.checkClockWarp()
	if f.r.warp.events != 0 {
		t.Fatal("on-cadence tick counted a warp")
	}

	// A 10s wall-vs-monotonic gap (VM pause / live-migration): wall
	// jumps forward on resume while the frozen monotonic clock saw
	// only the tick. Marker, counter, watchdog ACTION line and the
	// textfile series must all fire.
	gap = 10 * time.Second
	f.r.checkClockWarp()
	if f.r.warp.events != 1 {
		t.Fatalf("warp events=%d want 1", f.r.warp.events)
	}
	marker := filepath.Join(f.deps.StateDir, clockSteppedMarkerFile)
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("clock-stepped-at marker missing after warp")
	}
	log := f.log
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "ACTION clock-warp: delta=10.0s") {
		t.Fatalf("watchdog log missing clock-warp ACTION:\n%s", data)
	}
	prom, err := os.ReadFile(filepath.Join(
		textfileDirOverride, "node-agent-clockwarp.prom"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(prom), "node_agent_clock_warp_events_total 1") {
		t.Fatalf("textfile missing warp counter:\n%s", prom)
	}

	// A NEGATIVE gap (clock stepped backward / NTP step) warps too —
	// |delta| is symmetric.
	gap = -5 * time.Second
	f.r.checkClockWarp()
	if f.r.warp.events != 2 {
		t.Fatalf("early-tick warp not counted: events=%d want 2", f.r.warp.events)
	}
}

// TestWarpDeltaSyntheticClockStaysZero: two stamps without
// monotonic readings (or only one carrying one) make Sub fall back
// to wall for BOTH halves — the wall-minus-monotonic gap collapses
// to 0, so a synthetic/fake clock reports no warp instead of a false
// positive; and two REAL clock reads paired back sit far under the
// threshold.
func TestWarpDeltaSyntheticClockStaysZero(t *testing.T) {
	base := time.Unix(1700000000, 0) // wall-only synthetic stamp
	if got := warpDelta(base.Add(35*time.Second), base); got != 0 {
		t.Fatalf("synthetic pair warp = %v, want exactly 0", got)
	}
	// One real (mono-carrying) + one synthetic — fallback again.
	if got := warpDelta(time.Now(), base); got > clockWarpThreshold {
		t.Fatalf("mixed pair warp = %v, must stay under the threshold", got)
	}
	// Real paired reads: mono advance == wall advance in-process, so
	// the gap is noise-level.
	if got := warpDelta(time.Now(), time.Now()); got > clockWarpThreshold {
		t.Fatalf("real pair warp = %v, must stay under the threshold", got)
	}
}

// TestEnsureStateLatchRefreshesHeldMtime: ensureStateLatch is
// create-once — a re-occurring kmsg signature against a HELD latch
// must refresh the mtime (janitor's 24h reap) without rewriting the
// entry epoch or repeating the STATE-ENTER line.
func TestEnsureStateLatchRefreshesHeldMtime(t *testing.T) {
	f := kfixture(t)
	fixed := time.Unix(1760000000, 0)
	f.r.deps.Clock.Set(func() time.Time { return fixed })

	p := filepath.Join(f.deps.StateDir,
		latchdefs.LatchFilePrefix+latchdefs.LatchPageAllocFailure)
	testutil.WriteFile(t, p, "1700000000\n")
	old := fixed.Add(-48 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}

	f.r.ensureStateLatch(p,
		latchdefs.LatchFilePrefix+latchdefs.LatchPageAllocFailure,
		"order=3 zone=normal")

	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.ModTime().Equal(fixed) {
		t.Fatalf("held latch mtime = %v, want the clock %v", fi.ModTime(), fixed)
	}
	if got := testutil.ReadFile(t, p); got != "1700000000\n" {
		t.Fatalf("held latch content rewritten: %q", got)
	}
	// The held-latch path appends nothing — the log may not even
	// exist yet; absence equals silence here.
	if b, rerr := os.ReadFile(f.log); rerr == nil &&
		strings.Contains(string(b), "STATE-ENTER: page-alloc-failure") {
		t.Fatal("held latch re-logged STATE-ENTER")
	}
}

// TestKmsgEmptyFirstOpenWritesNoCursor — a first-ever open onto an
// EMPTY ring (or one with no parseable record) has no tail to park
// at: writing the cursor at seq=0 would make the post-restart open
// RESUME from 0 instead of re-priming the backlog gate on the then-
// populated ring. The cursor is persisted only once a parsed record
// anchors it; until then the session stays First-gated.
func TestKmsgEmptyFirstOpenWritesNoCursor(t *testing.T) {
	f := kfixture(t)
	bootDir := filepath.Join(f.deps.ProcRoot, "sys", "kernel", "random")
	_ = os.MkdirAll(bootDir, 0o755)
	testutil.WriteFile(t, filepath.Join(bootDir, "boot_id"), "testboot\n")
	dev := f.deps.KmsgDevicePaths(f.deps.HostRoot)[0]
	_ = os.MkdirAll(filepath.Dir(dev), 0o755)
	// Ring holds only an UNPARSEABLE line — no cursor-eligible seq.
	testutil.WriteFile(t, dev, "not-a-kmsg-record\n")
	f.r.checkKernelDmesg()
	if _, err := os.Stat(filepath.Join(f.deps.StateDir,
		kmsgCursorFile)); !os.IsNotExist(err) {
		t.Fatal("cursor written despite no parsed record on first open")
	}
	// The same session's next drain must still gate nothing: a fresh
	// record arriving after the empty first open IS news.
	testutil.WriteFile(t, dev, "not-a-kmsg-record\n6,7,2000,0;"+
		"Out of memory: Killed process 7 (kubelet) total-vm:2kB\n")
	f.r.checkKernelDmesg()
	b, err := os.ReadFile(filepath.Join(f.deps.StateDir, kmsgCursorFile))
	if err != nil {
		t.Fatalf("cursor never anchored after parsed record: %v", err)
	}
	if !strings.Contains(string(b), "kmsg testboot 7 ") {
		t.Fatalf("cursor=%q want seq 7", b)
	}
}
