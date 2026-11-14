// kernelfail_test.go — the kernelfail latch-contract coverage that used
// to be kernel_failure_latches_test.go: the kmsg classification +
// cursor resume, the pid/fd pressure streaks, clock-skew makestep +
// latch, and the ro-mount / kmsg-marker fs-readonly evidence.
package kernelfail

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// --- kernel-dmesg: kmsg classification ---

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
	f.r.checkKernelDmesg(context.Background())
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
	f.r.checkKernelDmesg(context.Background())
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
	f.r.checkKernelDmesg(context.Background())
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
	f.r.checkKernelDmesg(context.Background())
	if _, err := os.Stat(filepath.Join(f.deps.StateDir,
		kmsgFsErrorFile)); !os.IsNotExist(err) {
		t.Fatal("backlog record classified on first open")
	}
}

// --- pid-fd-pressure: pid/thread/fd pressure ---

func TestKernelProcRatios(t *testing.T) {
	f := kfixture(t)
	// Inconclusive when nothing parses.
	if _, _, _, _, _, _, _, _, ok := f.r.kernelProcRatios(); ok {
		t.Fatal("empty proc reported ok")
	}
	// file-nr only → fd ratio.
	testutil.WriteFile(t, f.deps.FileNRFile, "900 100 1000\n")
	_, _, fd, _, _, _, fdOK, _, ok := f.r.kernelProcRatios()
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
	pids, threads, _, _, pOK, tOK, _, _, ok := f.r.kernelProcRatios()
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
	td := t.TempDir()
	f.r.deps.TextfileDir = td
	f.r.updatePidFDPressure()
	b, err := os.ReadFile(filepath.Join(td,
		"node-agent-kernel.prom"))
	if err != nil {
		t.Fatalf("kernel prom missing: %v", err)
	}
	if !strings.Contains(string(b),
		"node_agent_file_nr_utilization_ratio 0.1") {
		t.Fatalf("file-nr gauge missing/wrong:\n%s", b)
	}
}

// --- clock-skew: clock skew ---

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
		f.r.checkClockSkew(context.Background())
	}
	if !stepped {
		t.Fatal("chronyc makestep not attempted")
	}
	if _, err := os.Stat(filepath.Join(f.deps.StateDir,
		"state-clock-skew")); err != nil {
		t.Fatal("clock-skew latch missing")
	}
}

// --- fs-readonly: ro mounts ---

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
	if !ms[1].HasOpt("ro") || ms[0].HasOpt("ro") {
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
	td := t.TempDir()
	f.r.deps.TextfileDir = td
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
		td, "node-agent-clockwarp.prom"))
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
	f.r.checkKernelDmesg(context.Background())
	if _, err := os.Stat(filepath.Join(f.deps.StateDir,
		kmsgCursorFile)); !os.IsNotExist(err) {
		t.Fatal("cursor written despite no parsed record on first open")
	}
	// The same session's next drain must still gate nothing: a fresh
	// record arriving after the empty first open IS news.
	testutil.WriteFile(t, dev, "not-a-kmsg-record\n6,7,2000,0;"+
		"Out of memory: Killed process 7 (kubelet) total-vm:2kB\n")
	f.r.checkKernelDmesg(context.Background())
	b, err := os.ReadFile(filepath.Join(f.deps.StateDir, kmsgCursorFile))
	if err != nil {
		t.Fatalf("cursor never anchored after parsed record: %v", err)
	}
	if !strings.Contains(string(b), "kmsg testboot 7 ") {
		t.Fatalf("cursor=%q want seq 7", b)
	}
}

// TestCheckKernelDmesgFallsBackToDmesg: an unopenable /dev/kmsg
// drops the session and drains `dmesg -T` on the SAME tick — the
// fallback must not wait for the next one, and the failed session
// must not leak.
func TestCheckKernelDmesgFallsBackToDmesg(t *testing.T) {
	f := kfixture(t) // no kmsgFixture — the device path is missing
	t1 := time.Now().Truncate(time.Second)
	f.deps.RunHostCmd = func(_ context.Context, argv ...string) (string, error) {
		if len(argv) > 1 && argv[1] == "-T" {
			return dmesgLine(t1, "EXT4-fs error (dev sda1) in x"), nil
		}
		return "", errors.New("plain dmesg unexpected")
	}
	f.r.deps.RunHostCmd = f.deps.RunHostCmd

	f.r.checkKernelDmesg(context.Background())
	// Tick 1 only PRIMES the dmesg cursor (the retained ring is
	// history, not news) and drops the failed kmsg session.
	if f.r.kscan.sess != nil {
		t.Fatal("kmsg session kept after the read failure")
	}
	b, err := os.ReadFile(f.r.statePath(kmsgCursorFile))
	if err != nil {
		t.Fatalf("cursor not primed by the fallback: %v", err)
	}
	if !strings.HasPrefix(string(b), "dmesgT ") {
		t.Fatalf("cursor=%q want a dmesgT anchor", b)
	}
	if _, err := os.Stat(f.r.statePath(kmsgFsErrorFile)); !os.IsNotExist(err) {
		t.Fatalf("history classified on the priming tick (err=%v)", err)
	}

	// Tick 2: a fresh fs-error line past the anchor classifies.
	t2 := t1.Add(time.Minute)
	f.r.deps.RunHostCmd = func(_ context.Context, argv ...string) (string, error) {
		if len(argv) > 1 && argv[1] == "-T" {
			return dmesgLine(t1, "routine") + "\n" + dmesgLine(t2, "EXT4-fs error (dev sda1) in x"), nil
		}
		return "", errors.New("plain dmesg unexpected")
	}
	f.r.checkKernelDmesg(context.Background())
	if _, err := os.Stat(f.r.statePath(kmsgFsErrorFile)); err != nil {
		t.Fatalf("fs-error marker missing after the dmesg fallback: %v", err)
	}
}

// TestReadKmsgCursorShapes pins every cursor generation the state
// file carries: kmsg/dmesgT/dmesgRaw parse (including the legacy
// two-field dmesgT shape), while empty, short and unknown modes are
// unusable — the drain then re-primes instead of resuming.
func TestReadKmsgCursorShapes(t *testing.T) {
	f := kfixture(t)
	if f.r.readKmsgCursor() != nil {
		t.Fatal("cursor parsed from a missing file")
	}
	write := func(content string) {
		testutil.WriteFile(t, f.r.statePath(kmsgCursorFile), content)
	}
	for _, garbage := range []string{"", "\n", "bogus 1 2", "kmsg boot 5"} {
		write(garbage)
		if cur := f.r.readKmsgCursor(); cur != nil {
			t.Fatalf("cursor %q parsed to %+v", garbage, cur)
		}
	}

	write("kmsg boot 5 1234\n")
	cur := f.r.readKmsgCursor()
	if cur == nil || cur.mode != "kmsg" || cur.bootID != "boot" ||
		cur.seq != 5 || cur.usec != 1234 {
		t.Fatalf("kmsg cursor = %+v", cur)
	}

	write("dmesgT 1700000000\n")
	cur = f.r.readKmsgCursor()
	if cur == nil || cur.unixTS != 1700000000 || cur.lines != -1 {
		t.Fatalf("legacy dmesgT cursor = %+v, want lines -1", cur)
	}

	write("dmesgT 1700000000 7\n")
	cur = f.r.readKmsgCursor()
	if cur == nil || cur.unixTS != 1700000000 || cur.lines != 7 {
		t.Fatalf("dmesgT cursor = %+v", cur)
	}

	write("dmesgRaw 3\n")
	cur = f.r.readKmsgCursor()
	if cur == nil || cur.lines != 3 || cur.hash != 0 {
		t.Fatalf("dmesgRaw cursor = %+v", cur)
	}

	write("dmesgRaw 3 99\n")
	cur = f.r.readKmsgCursor()
	if cur == nil || cur.lines != 3 || cur.hash != 99 {
		t.Fatalf("dmesgRaw cursor = %+v", cur)
	}
}

// TestMaybeBumpConntrackMaxBounds pins the bump's guards: the
// ceiling stops growth, doubling caps at the ceiling, the rate
// budget allows one bump per window, and a failed sysctl write
// neither spends the budget nor rewrites.
func TestMaybeBumpConntrackMaxBounds(t *testing.T) {
	// At the ceiling: no write at all.
	f := kfixture(t)
	testutil.WriteFile(t, f.deps.ConntrackMaxFile, "4194304\n")
	f.r.maybeBumpConntrackMax()
	if got := strings.TrimSpace(testutil.ReadFile(t, f.deps.ConntrackMaxFile)); got != "4194304" {
		t.Fatalf("ceiling value rewritten: %q", got)
	}

	// Doubling past the ceiling caps at conntrackMaxCeiling.
	f2 := kfixture(t)
	testutil.WriteFile(t, f2.deps.ConntrackMaxFile, "3000000\n")
	f2.r.maybeBumpConntrackMax()
	if got := strings.TrimSpace(testutil.ReadFile(t, f2.deps.ConntrackMaxFile)); got != "4194304" {
		t.Fatalf("capped bump=%q want %d", got, conntrackMaxCeiling)
	}

	// The rate budget blocks an immediate second bump.
	f2.r.maybeBumpConntrackMax()
	if got := strings.TrimSpace(testutil.ReadFile(t, f2.deps.ConntrackMaxFile)); got != "4194304" {
		t.Fatalf("rate-limited bump rewrote: %q", got)
	}

	// A failed write leaves the value and does not spend the budget.
	// os.WriteFile targets the sysctl file directly — write access to
	// the FILE is what it needs, so strip the file's write bits.
	f3 := kfixture(t)
	roFile := f3.deps.ConntrackMaxFile
	testutil.WriteFile(t, roFile, "262144\n")
	if err := os.Chmod(roFile, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(roFile, 0o644) })
	f3.r.maybeBumpConntrackMax()
	if got := strings.TrimSpace(testutil.ReadFile(t, roFile)); got != "262144" {
		t.Fatalf("failed bump rewrote: %q", got)
	}
}

// TestNewSeamDefaults: a bare Deps gets the exec/device defaults and
// the tick interval — New itself performs no host I/O.
func TestNewSeamDefaults(t *testing.T) {
	r := New(Deps{})
	if r.deps.RunHostCmd == nil || r.deps.KmsgDevicePaths == nil {
		t.Fatal("seam defaults not applied")
	}
	if r.deps.TickInterval != defaultTickInterval {
		t.Fatalf("TickInterval=%v want %v", r.deps.TickInterval, defaultTickInterval)
	}
	if got := r.deps.KmsgDevicePaths("/host"); len(got) != 2 {
		t.Fatalf("default device candidates = %v", got)
	}
}

// TestKmsgEvidenceTruncation: the 200-byte evidence cap keeps a
// flooded kernel ring from writing unbounded marker/latch evidence.
func TestKmsgEvidenceTruncation(t *testing.T) {
	f := kfixture(t)
	long := strings.Repeat("x", 500)

	f.r.noteKernelFsError(long) // a single 500-byte token
	b, err := os.ReadFile(f.r.statePath(kmsgFsErrorFile))
	if err != nil {
		t.Fatal(err)
	}
	detail := strings.Fields(string(b))
	if len(detail) != 2 || len(detail[1]) != 200 {
		t.Fatalf("fs-error evidence fields=%d len=%d want 2 fields, 200-byte detail",
			len(detail), len(detail[1]))
	}

	f2 := kfixture(t)
	pageMsg := "page allocation failure: " + long
	f2.r.notePageAllocFailure(pageMsg)
	logData, err := os.ReadFile(f2.log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logData), pageMsg[:200]) ||
		strings.Contains(string(logData), pageMsg[:201]) {
		t.Fatalf("page-alloc evidence not capped at 200 bytes:\n%s", logData)
	}

	f3 := kfixture(t)
	clockMsg := "clocksource unstable: " + long
	f3.r.noteClocksourceUnstable(clockMsg)
	logData, err = os.ReadFile(f3.log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logData), clockMsg[:200]) ||
		strings.Contains(string(logData), clockMsg[:201]) {
		t.Fatalf("clocksource evidence not capped at 200 bytes:\n%s", logData)
	}
}

// TestEnsureStateLatchWriteFailure: an unwritable latch path is a
// silent no-op — the next tick retries, nothing panics or logs a
// STATE-ENTER for a latch that does not exist.
func TestEnsureStateLatchWriteFailure(t *testing.T) {
	f := kfixture(t)
	blocker := filepath.Join(t.TempDir(), "file")
	testutil.WriteFile(t, blocker, "x\n")
	f.r.ensureStateLatch(filepath.Join(blocker, "state-x"),
		latchdefs.LatchFilePrefix+"x", "evidence")
	if _, err := os.Stat(filepath.Join(blocker, "state-x")); err == nil {
		t.Fatal("latch materialized under a regular file")
	}
	if logData, err := os.ReadFile(f.log); err == nil &&
		strings.Contains(string(logData), "STATE-ENTER") {
		t.Fatalf("STATE-ENTER logged for a latch that was never written:\n%s", logData)
	}
}

// TestKernelUtilPromPartialSources: only the ratios whose sources
// parsed land in the node-exporter textfile — no fake zeros for the
// missing loadavg/file-nr/pty sysctls.
func TestKernelUtilPromPartialSources(t *testing.T) {
	f := kfixture(t)
	dir := t.TempDir()
	f.r.deps.TextfileDir = dir

	// pid dirs 7 and 9 + pid_max → only the pids ratio parses.
	for _, pid := range []string{"7", "9"} {
		if err := os.MkdirAll(filepath.Join(f.deps.ProcRoot, pid), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sysDir := filepath.Join(f.deps.ProcRoot, "sys", "kernel")
	if err := os.MkdirAll(sysDir, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(sysDir, "pid_max"), "100\n")

	f.r.updatePidFDPressure()
	b, err := os.ReadFile(filepath.Join(dir, "node-agent-kernel.prom"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, "node_agent_pids_utilization_ratio 0.02") {
		t.Fatalf("pids ratio missing/wrong:\n%s", text)
	}
	for _, absent := range []string{
		"node_agent_threads_utilization_ratio",
		"node_agent_file_nr_utilization_ratio",
		"node_agent_pty_utilization_ratio",
	} {
		if strings.Contains(text, absent) {
			t.Fatalf("%s emitted without its source:\n%s", absent, text)
		}
	}
}

// TestClockSkewAdjtimexFallback: no chronyc on the host → the
// read-only adjtimex still yields offset + sync state. A FAILED
// makestep writes no clock-stepped marker — it stepped nothing —
// and the over-threshold offset still feeds the latch streak.
func TestClockSkewAdjtimexFallback(t *testing.T) {
	f := kfixture(t)
	f.deps.RunHostCmd = func(context.Context, ...string) (string, error) {
		return "", errors.New("chronyc missing")
	}
	f.r.deps.RunHostCmd = f.deps.RunHostCmd
	f.deps.Adjtimex = func(tx *unix.Timex) (int, error) {
		tx.Offset = 3_000_000 // µs — 3s, over both step and latch bounds
		tx.Status = 0         // STA_UNSYNC clear → synchronised
		return 0, nil
	}
	f.r.deps.Adjtimex = f.deps.Adjtimex

	f.r.checkClockSkew(context.Background())
	if _, err := os.Stat(f.r.statePath(clockSteppedMarkerFile)); !os.IsNotExist(err) {
		t.Fatal("clock-stepped marker written for a failed makestep")
	}
	b, err := os.ReadFile(f.r.statePath(clockSkewCountFile))
	if err != nil {
		t.Fatalf("skew count not armed: %v", err)
	}
	if strings.TrimSpace(string(b)) != "1" {
		t.Fatalf("skew count=%q want 1", b)
	}
	// Inconclusive probes (adjtimex failing too) leave everything.
	f.r.deps.Adjtimex = func(*unix.Timex) (int, error) { return 0, unix.ENOSYS }
	f.r.checkClockSkew(context.Background())
	b, _ = os.ReadFile(f.r.statePath(clockSkewCountFile))
	if strings.TrimSpace(string(b)) != "1" {
		t.Fatalf("inconclusive probe moved the count: %q", b)
	}
}

// TestClockWarpPromInstallFailure: a failed textfile install is a
// Warn — the detector keeps running and the event count stays put.
func TestClockWarpPromInstallFailure(t *testing.T) {
	f := kfixture(t)
	blocker := filepath.Join(t.TempDir(), "file")
	testutil.WriteFile(t, blocker, "x\n")
	f.r.deps.TextfileDir = filepath.Join(blocker, "textfile")

	now := time.Now()
	f.deps.Clock.Set(func() time.Time { return now })
	f.r.checkClockWarp() // first tick: primes prev, prom write fails
	if f.r.warp.events != 0 {
		t.Fatalf("warp events = %d on a quiet first tick", f.r.warp.events)
	}
	f.r.checkClockWarp() // second tick: still no warp, still no panic
	if f.r.warp.events != 0 {
		t.Fatalf("warp events = %d without a wall-vs-mono gap", f.r.warp.events)
	}
}

// TestFSReadonlyEvidenceEdges: a TTL-expired kmsg marker is pruned
// (not latched), while a fresh marker AND an ro PVC mount combine
// into one evidence line.
func TestFSReadonlyEvidenceEdges(t *testing.T) {
	f := kfixture(t)
	old := f.deps.Clock.Now().Add(-fsErrorLatchTTL - time.Minute).Unix()
	testutil.WriteFile(t, f.r.statePath(kmsgFsErrorFile),
		strconv.FormatInt(old, 10)+" ancient\n")
	f.r.updateFSReadonlyEvidence()
	if _, err := os.Stat(f.r.statePath(kmsgFsErrorFile)); !os.IsNotExist(err) {
		t.Fatal("TTL-expired kmsg marker not pruned")
	}
	if _, err := os.Stat(f.deps.Store.Path(latchdefs.LatchFSReadonly)); !os.IsNotExist(err) {
		t.Fatal("expired marker latched fs-readonly")
	}

	// Fresh marker + ro PVC mount → combined evidence, one latch.
	f2 := kfixture(t)
	now := f2.deps.Clock.Now().Unix()
	testutil.WriteFile(t, f2.r.statePath(kmsgFsErrorFile),
		strconv.FormatInt(now, 10)+" fresh\n")
	proc1 := filepath.Join(f2.deps.ProcRoot, "1")
	if err := os.MkdirAll(proc1, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(proc1, "mounts"),
		"/dev/vda1 / ext4 rw,relatime 0 0\n"+
			"/dev/sdb1 /var/openebs/local/pvc-def xfs ro,relatime 0 0\n")
	f2.r.updateFSReadonlyEvidence()
	logData, err := os.ReadFile(f2.log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logData),
		"STATE-ENTER: fs-readonly (kernel-fs-error + ro-mount: /var/openebs/local/pvc-def (xfs))") {
		t.Fatalf("combined evidence line missing:\n%s", logData)
	}
}

// TestUnwritableStateDirKeepsDraining: a read-only state dir fails
// the cursor + marker writes silently — the drain still runs, no
// panic, and the next writable tick retries.
func TestUnwritableStateDirKeepsDraining(t *testing.T) {
	f := kfixture(t)
	kmsgFixture(t, f.deps, "EXT4-fs error (dev sda1): aborted journal")
	if err := os.Chmod(f.deps.StateDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(f.deps.StateDir, 0o755) })

	f.r.checkKernelDmesg(context.Background()) // classify runs; cursor + marker writes fail

	if _, err := os.Stat(f.r.statePath(kmsgFsErrorFile)); !os.IsNotExist(err) {
		t.Fatalf("marker materialized through a read-only state dir: %v", err)
	}
	if got := strings.TrimSpace(testutil.ReadFile(t,
		filepath.Join(f.deps.StateDir, kmsgCursorFile))); got != "kmsg testboot 0 0" {
		t.Fatalf("cursor rewritten through a read-only state dir: %q", got)
	}
}

// TestKernelPromWritersSurviveBrokenTextfileDir: the node-exporter
// textfile writers log their install failures and keep the latch
// logic running.
func TestKernelPromWritersSurviveBrokenTextfileDir(t *testing.T) {
	f := kfixture(t)
	blocker := filepath.Join(t.TempDir(), "file")
	testutil.WriteFile(t, blocker, "x\n")
	f.r.deps.TextfileDir = filepath.Join(blocker, "textfile")

	// pid/fd domain: one parsed source walks the writer; entropy
	// parses for the steal domain — both textfile installs fail.
	sysDir := filepath.Join(f.deps.ProcRoot, "sys", "kernel", "random")
	if err := os.MkdirAll(sysDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(f.deps.ProcRoot, "7"), 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(f.deps.ProcRoot, "sys/kernel/pid_max"), "10\n")
	testutil.WriteFile(t, filepath.Join(sysDir, "entropy_avail"), "256\n")
	f.r.updatePidFDPressure() // pids ratio parses → textfile install fails
	f.r.updateStealEntropy()  // entropy parses → textfile install fails
}
