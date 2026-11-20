// runtime_inotify_pressure_test.go — the inotify-pressure-hygiene
// check: the tier-1 sysctl auto-bump (85%, 30m budget, ceilings +
// the watches RAM budget), the tier-2 two-cycle latch at ceiling
// (95%, 80% release) and the runaway-pod evictor's share floor +
// eviction rails + cooldown.
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

	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// inotifySysctlDir is the fixture's fs/inotify sysctl dir.
func inotifySysctlDir(e *env) string {
	return filepath.Join(e.ProcDir, "sys", "fs", "inotify")
}

func writeInotifySysctls(t *testing.T, e *env, inst, watches int64) {
	t.Helper()
	dir := inotifySysctlDir(e)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(dir, "max_user_instances"),
		fmt.Sprintf("%d\n", inst))
	wdepstest.WriteFile(t, filepath.Join(dir, "max_user_watches"),
		fmt.Sprintf("%d\n", watches))
}

func readSysctl(t *testing.T, e *env, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(inotifySysctlDir(e), name))
	if err != nil {
		t.Fatalf("read sysctl %s: %v", name, err)
	}
	return strings.TrimSpace(string(data))
}

// mkInotifyPID plants a fake /proc/<pid> holding `instances`
// anon_inode:inotify fds carrying `watches` fdinfo wd: lines each,
// plus one ordinary fd (the readlink filter's negative case) and a
// cgroup file attributing the pid to pod uid ("" → a non-pod
// cgroup line). Re-calling it replaces the pid's fd tree.
func mkInotifyPID(t *testing.T, e *env, pid int, instances, watches int, uid string) {
	t.Helper()
	pidDir := filepath.Join(e.ProcDir, strconv.Itoa(pid))
	if err := os.RemoveAll(pidDir); err != nil {
		t.Fatal(err)
	}
	fdDir := filepath.Join(pidDir, "fd")
	fiDir := filepath.Join(pidDir, "fdinfo")
	for _, d := range []string{fdDir, fiDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/etc/hosts", filepath.Join(fdDir, "0")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < instances; i++ {
		n := strconv.Itoa(i + 1)
		if err := os.Symlink("anon_inode:inotify", filepath.Join(fdDir, n)); err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		for w := 0; w < watches; w++ {
			fmt.Fprintf(&b, "inotify wd:%d ino:%d sdev:1 mask:fce\n", w+1, w+1)
		}
		wdepstest.WriteFile(t, filepath.Join(fiDir, n), b.String())
	}
	cg := "0::/user.slice/user-1000.slice/session-3.scope\n"
	if uid != "" {
		cg = fmt.Sprintf(
			"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod%s.slice/crio-abc.scope\n",
			strings.ReplaceAll(uid, "-", "_"))
	}
	wdepstest.WriteFile(t, filepath.Join(pidDir, "cgroup"), cg)
}

// inotifyRun drives one check round with the given pid sweep.
func inotifyRun(e *env, pids ...int) {
	e.H.Check(wdeps.CheckInotifyHygiene).Run(context.Background(),
		&wdeps.CycleEnv{
			WorkerActive: true,
			APIOK:        true,
			PidsOnce:     wdepstest.PidsOf(pids...),
		})
}

func inotifyLatched(e *env) bool {
	return e.H.Deps.State.Exists(latchdefs.LatchInotifyPressure)
}

func TestInotifyIdleNoAction(t *testing.T) {
	e := fixture(t)
	writeInotifySysctls(t, e, 128, 8192)
	mkInotifyPID(t, e, 100, 4, 5, "")
	inotifyRun(e, 100)
	if inotifyLatched(e) {
		t.Fatal("idle usage armed the inotify-pressure latch")
	}
	if got := readSysctl(t, e, "max_user_instances"); got != "128" {
		t.Fatalf("sysctl rewritten at idle: %s", got)
	}
}

func TestInotifyBumpAt85Percent(t *testing.T) {
	e := fixture(t)
	writeInotifySysctls(t, e, 128, 8192)
	// 120/128 = 94% instances — past the bump line, under the latch.
	mkInotifyPID(t, e, 100, 120, 0, "")
	inotifyRun(e, 100)
	if got := readSysctl(t, e, "max_user_instances"); got != "256" {
		t.Fatalf("max_user_instances=%s want 256 (doubled)", got)
	}
	if got := readSysctl(t, e, "max_user_watches"); got != "8192" {
		t.Fatalf("max_user_watches=%s want unchanged 8192", got)
	}
	if !strings.Contains(e.LogLines(t),
		"ACTION: inotify-pressure-hygiene raised max_user_instances 128 -> 256") {
		t.Fatalf("missing bump ACTION line:\n%s", e.LogLines(t))
	}
	if inotifyLatched(e) {
		t.Fatal("sub-latch pressure armed the latch")
	}
}

func TestInotifyBumpBothResourcesOneSpend(t *testing.T) {
	e := fixture(t)
	writeInotifySysctls(t, e, 128, 100)
	// instances 120/128 and watches 120/100 — both past 85%, one
	// 30m budget spend covers both writes.
	mkInotifyPID(t, e, 100, 120, 1, "")
	inotifyRun(e, 100)
	if got := readSysctl(t, e, "max_user_instances"); got != "256" {
		t.Fatalf("max_user_instances=%s want 256", got)
	}
	if got := readSysctl(t, e, "max_user_watches"); got != "200" {
		t.Fatalf("max_user_watches=%s want 200", got)
	}
}

func TestInotifyBumpCooldown(t *testing.T) {
	e := fixture(t)
	writeInotifySysctls(t, e, 128, 8192)
	mkInotifyPID(t, e, 100, 120, 0, "")
	inotifyRun(e, 100) // spends last-inotify-bump → 256
	if got := readSysctl(t, e, "max_user_instances"); got != "256" {
		t.Fatalf("first bump failed: %s", got)
	}
	// Usage grows past 85% of the NEW ceiling inside the 30m window;
	// advance past the 60s SharedFDCache TTL so the mutated /proc fd dir is re-read.
	e.Now = e.Now.Add(2 * time.Minute)
	mkInotifyPID(t, e, 100, 230, 0, "")
	inotifyRun(e, 100)
	if got := readSysctl(t, e, "max_user_instances"); got != "256" {
		t.Fatalf("cooldown bypassed: max_user_instances=%s want still 256", got)
	}
	if !strings.Contains(e.LogLines(t), "in 30m cooldown") {
		t.Fatalf("missing cooldown suspect line:\n%s", e.LogLines(t))
	}
	// 30m later (32m total > 30m budget) the budget reopens and the next doubling lands.
	e.Now = e.Now.Add(30 * time.Minute)
	inotifyRun(e, 100)
	if got := readSysctl(t, e, "max_user_instances"); got != "512" {
		t.Fatalf("post-cooldown bump failed: %s want 512", got)
	}
}

func TestInotifyWatchesRAMBudgetCapsCeiling(t *testing.T) {
	e := fixture(t)
	// 50 MiB MemTotal → 2% = ~1MiB → ~1024 watches of 1KiB each.
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "meminfo"),
		"MemTotal: 51200 kB\nMemAvailable: 40000 kB\n")
	// sysctl already ABOVE the RAM-budget ceiling (2048 > 1024):
	// no bump may fire, but 97% usage still counts as at-ceiling.
	writeInotifySysctls(t, e, 128, 2048)
	mkInotifyPID(t, e, 100, 4, 500, "") // 4×500 = 2000 watches
	inotifyRun(e, 100)
	if got := readSysctl(t, e, "max_user_watches"); got != "2048" {
		t.Fatalf("watches bumped past the RAM budget: %s", got)
	}
	// 2000/2048 = 97.6% >= 95% and watchCur >= watchCeiling → the
	// tier-2 latch arms after the two-cycle pending.
	inotifyRun(e, 100)
	if !inotifyLatched(e) {
		t.Fatal("watches at RAM-budget ceiling did not arm the latch")
	}
}

func TestInotifyLatchEvictsRunawayPod(t *testing.T) {
	e := fixture(t)
	// Pin both ceilings small so fixture usage reaches them.
	e.H.Cfg.Pressure.InotifyMaxInstancesCeiling = 100
	e.H.Cfg.Pressure.InotifyEvictRunawayPod = true
	writeInotifySysctls(t, e, 100, 8192)
	uid := "123e4567-e89b-12d3-a456-426614174000"
	isCtrl := true
	leaky := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "app", Name: "leaky", UID: types.UID(uid),
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "leaky-rs", UID: "rs-uid-1", Controller: &isCtrl,
		}},
	}}
	// leaky pod pid: 96 instances + 96×5=480 watches; a host pid
	// holds the remaining 4 instances — leaky share ≈ 99%.
	mkInotifyPID(t, e, 100, 96, 5, uid)
	mkInotifyPID(t, e, 101, 4, 0, "")

	runWithPods := func() {
		e.H.Check(wdeps.CheckInotifyHygiene).Run(context.Background(),
			&wdeps.CycleEnv{
				WorkerActive: true,
				APIOK:        true,
				Pods:         []corev1.Pod{*leaky},
				PidsOnce:     wdepstest.PidsOf(100, 101),
			})
	}
	// The fake clientset needs the pod object for the delete to
	// succeed — create it through the API first.
	if _, err := e.CS.CoreV1().Pods("app").Create(context.Background(),
		leaky, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	runWithPods() // cycle 1 — pending
	if inotifyLatched(e) {
		t.Fatal("latch armed before the two-cycle confirm")
	}
	runWithPods() // cycle 2 — confirmed: latch + evict
	if !inotifyLatched(e) {
		t.Fatal("confirmed pressure did not arm state-inotify-pressure")
	}
	if !strings.Contains(e.LogLines(t),
		"ACTION: inotify-pressure-hygiene evicted pod app/leaky") {
		t.Fatalf("missing evict ACTION line:\n%s", e.LogLines(t))
	}
	deletes := wdepstest.DeleteActions(e.CS)
	if len(deletes) != 1 || deletes[0].GetName() != "leaky" {
		t.Fatalf("expected one delete of app/leaky, got %+v", deletes)
	}
}

func TestInotifyLatchExitAt80Percent(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Pressure.InotifyMaxInstancesCeiling = 100
	e.H.Cfg.Pressure.InotifyEvictRunawayPod = false // isolate the latch
	writeInotifySysctls(t, e, 100, 8192)
	mkInotifyPID(t, e, 100, 96, 0, "")
	inotifyRun(e, 100)
	inotifyRun(e, 100)
	if !inotifyLatched(e) {
		t.Fatal("latch did not arm")
	}
	// Usage collapses → advance past 60s SharedFDCache TTL so the next cycle sees 4 and exits the latch.
	e.Now = e.Now.Add(2 * time.Minute)
	mkInotifyPID(t, e, 100, 4, 0, "")
	inotifyRun(e, 100)
	if inotifyLatched(e) {
		t.Fatal("latch held after usage fell to ~4%")
	}
	if !strings.Contains(e.LogLines(t), "STATE-EXIT: inotify-pressure") {
		t.Fatalf("missing STATE-EXIT line:\n%s", e.LogLines(t))
	}
}

func TestInotifyEvictProtectedNamespace(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Pressure.InotifyMaxInstancesCeiling = 100
	e.H.Cfg.Pressure.InotifyEvictRunawayPod = true
	writeInotifySysctls(t, e, 100, 8192)
	uid := "123e4567-e89b-12d3-a456-426614174001"
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "kube-system", Name: "critical", UID: types.UID(uid)}}
	mkInotifyPID(t, e, 100, 96, 0, uid)
	if _, err := e.CS.CoreV1().Pods("kube-system").Create(context.Background(),
		pod, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		e.H.Check(wdeps.CheckInotifyHygiene).Run(context.Background(),
			&wdeps.CycleEnv{
				WorkerActive: true, APIOK: true,
				Pods:     []corev1.Pod{*pod},
				PidsOnce: wdepstest.PidsOf(100),
			})
	}
	if !inotifyLatched(e) {
		t.Fatal("latch did not arm")
	}
	if n := len(wdepstest.DeleteActions(e.CS)); n != 0 {
		t.Fatalf("protected-namespace pod deleted: %d actions", n)
	}
	if !strings.Contains(e.LogLines(t), "protected by eviction rails") {
		t.Fatalf("missing protection suspect line:\n%s", e.LogLines(t))
	}
}

func TestInotifyEvictBelowShare(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Pressure.InotifyMaxInstancesCeiling = 100
	e.H.Cfg.Pressure.InotifyEvictRunawayPod = true
	writeInotifySysctls(t, e, 100, 8192)
	uidA := "123e4567-e89b-12d3-a456-426614174002"
	uidB := "123e4567-e89b-12d3-a456-426614174003"
	podA := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "app", Name: "a", UID: types.UID(uidA)}}
	podB := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "app", Name: "b", UID: types.UID(uidB)}}
	// 45 + 45 pod instances + 10 host = 100 total; top share 45%.
	mkInotifyPID(t, e, 100, 45, 0, uidA)
	mkInotifyPID(t, e, 101, 45, 0, uidB)
	mkInotifyPID(t, e, 102, 10, 0, "")
	for _, p := range []*corev1.Pod{podA, podB} {
		if _, err := e.CS.CoreV1().Pods(p.Namespace).Create(context.Background(),
			p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		e.H.Check(wdeps.CheckInotifyHygiene).Run(context.Background(),
			&wdeps.CycleEnv{
				WorkerActive: true, APIOK: true,
				Pods:     []corev1.Pod{*podA, *podB},
				PidsOnce: wdepstest.PidsOf(100, 101, 102),
			})
	}
	if !inotifyLatched(e) {
		t.Fatal("latch did not arm")
	}
	if n := len(wdepstest.DeleteActions(e.CS)); n != 0 {
		t.Fatalf("diffuse-pressure pods deleted: %d actions", n)
	}
	if !strings.Contains(e.LogLines(t), "diffuse pressure") {
		t.Fatalf("missing share-floor suspect line:\n%s", e.LogLines(t))
	}
}

// The mixed-unit regression: instances (ceiling ~8k) and watches
// (ceiling ~512k) are different scales — summing them picks the
// WRONG victim. Here pod B leaks 90 inotify instances (the binding
// axis, ~93% of node instances) while pod A legitimately holds 4000
// watches (the unpressured axis). The old aggregate math would kill
// A (4001 aggregate > 90); the per-axis math must kill B.
func TestInotifyEvictPicksPressuredAxisVictim(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Pressure.InotifyMaxInstancesCeiling = 100
	e.H.Cfg.Pressure.InotifyEvictRunawayPod = true
	writeInotifySysctls(t, e, 100, 8192)
	uidA := "123e4567-e89b-12d3-a456-426614174010"
	uidB := "123e4567-e89b-12d3-a456-426614174011"
	isCtrl := true
	owners := []metav1.OwnerReference{{
		APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs", UID: "rs-uid-2", Controller: &isCtrl,
	}}
	podA := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "app", Name: "watcher-a", UID: types.UID(uidA), OwnerReferences: owners}}
	podB := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "app", Name: "leaky-b", UID: types.UID(uidB), OwnerReferences: owners}}
	// B: 90 instances, 0 watches — the instance-axis leaker.
	// A: 1 instance, 4000 watches — aggregate 4001, instances share ~1%.
	// Host pid: 6 instances. Node: 97 inst (97% of ceiling), 4000 watches (49%).
	mkInotifyPID(t, e, 100, 90, 0, uidB)
	mkInotifyPID(t, e, 101, 1, 4000, uidA)
	mkInotifyPID(t, e, 102, 6, 0, "")
	for _, p := range []*corev1.Pod{podA, podB} {
		if _, err := e.CS.CoreV1().Pods(p.Namespace).Create(context.Background(),
			p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		e.H.Check(wdeps.CheckInotifyHygiene).Run(context.Background(),
			&wdeps.CycleEnv{
				WorkerActive: true, APIOK: true,
				Pods:     []corev1.Pod{*podA, *podB},
				PidsOnce: wdepstest.PidsOf(100, 101, 102),
			})
	}
	if !inotifyLatched(e) {
		t.Fatal("instance-axis pressure did not arm the latch")
	}
	deletes := wdepstest.DeleteActions(e.CS)
	if len(deletes) != 1 || deletes[0].GetName() != "leaky-b" {
		t.Fatalf("expected leaky-b (instance-axis leaker) deleted, got %+v", deletes)
	}
	if _, err := e.CS.CoreV1().Pods("app").Get(context.Background(),
		"watcher-a", metav1.GetOptions{}); err != nil {
		t.Fatalf("healthy high-watch pod killed by aggregate math: %v", err)
	}
}

func TestInotifySysctlsMissingAborts(t *testing.T) {
	e := fixture(t)
	// No sysctl files at all — inconclusive, never a latch.
	mkInotifyPID(t, e, 100, 500, 0, "")
	inotifyRun(e, 100)
	if inotifyLatched(e) {
		t.Fatal("unreadable sysctls armed the latch")
	}
}

// mkProcStatus plants a minimal /proc/<pid>/status carrying the
// Uid: line procRealUID parses — the ucounts charging identity.
func mkProcStatus(t *testing.T, e *env, pid int, ruid int64) {
	t.Helper()
	wdepstest.WriteFile(t,
		filepath.Join(e.ProcDir, strconv.Itoa(pid), "status"),
		fmt.Sprintf("Name:\tfake\nUid:\t%d\t%d\t%d\t%d\n", ruid, ruid, ruid, ruid))
}

// TestInotifyUcountsPerUID is the P0-13 ucounts regression: the
// sysctls are PER-REAL-UID budgets, so node-wide usage spread
// across uids must NOT flag even when the aggregate dwarfs the
// per-uid limit. Two uids at 60/100 each = 120% of the limit
// node-wide but 60% per-uid — healthy.
func TestInotifyUcountsPerUID(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Pressure.InotifyMaxInstancesCeiling = 100
	writeInotifySysctls(t, e, 100, 8192)
	mkInotifyPID(t, e, 100, 60, 0, "")
	mkInotifyPID(t, e, 101, 60, 0, "")
	mkProcStatus(t, e, 100, 1000)
	mkProcStatus(t, e, 101, 1001)
	inotifyRun(e, 100, 101)
	inotifyRun(e, 100, 101)
	if inotifyLatched(e) {
		t.Fatal("multi-uid aggregate false-positived the ucounts latch")
	}
	// Same usage concentrated on ONE uid IS pressure — the
	// per-uid ratio is what the kernel actually enforces.
	mkProcStatus(t, e, 101, 1000) // both pids now share uid 1000
	inotifyRun(e, 100, 101)
	inotifyRun(e, 100, 101)
	if !inotifyLatched(e) {
		t.Fatal("single-uid 120/100 usage did not arm the latch")
	}
}

// TestInotifyOFDedupForkShared is the P0-13 fork-dedup regression:
// N processes holding ONE inotify open file description (fork
// inheritance) is ONE ucounts charge — the census must not
// multiply it. The InotifyFDIno seam plays the kernel's inode.
func TestInotifyOFDedupForkShared(t *testing.T) {
	e := fixture(t)
	writeInotifySysctls(t, e, 100, 8192)
	// Parent opened 2 inotify instances; the forked child shares
	// BOTH (same fd names → same ino via the stub).
	mkInotifyPID(t, e, 100, 2, 0, "")
	mkInotifyPID(t, e, 101, 2, 0, "")
	mkProcStatus(t, e, 100, 0)
	mkProcStatus(t, e, 101, 0)
	e.H.Cfg.Seams.Host.InotifyFDIno = func(pid int, fd string) (uint64, bool) {
		// ino keyed on fd NAME only — pid 100/fd "1" and pid
		// 101/fd "1" are the same OFD (fork inheritance).
		n, _ := strconv.Atoi(fd)
		return uint64(5000 + n), true
	}
	inotifyRun(e, 100, 101)
	// 2 unique OFDs, not 4 — usage reads 2/100 = 2%, nowhere near
	// the 85% bump line; without dedup it would read 4%… still
	// under. Use a tighter limit to make the distinction real:
	writeInotifySysctls(t, e, 3, 8192)
	inotifyRun(e, 100, 101)
	if got := readSysctl(t, e, "max_user_instances"); got != "3" {
		t.Fatalf("deduped 2 OFDs bumped sysctl: %s", got)
	}
	// Sanity: without the seam (stat fails → per-pid fallback)
	// the same fixture counts 4 and DOES bump.
	e2 := fixture(t)
	writeInotifySysctls(t, e2, 3, 8192)
	mkInotifyPID(t, e2, 100, 2, 0, "")
	mkInotifyPID(t, e2, 101, 2, 0, "")
	mkProcStatus(t, e2, 100, 0)
	mkProcStatus(t, e2, 101, 0)
	inotifyRun(e2, 100, 101)
	if got := readSysctl(t, e2, "max_user_instances"); got != "6" {
		t.Fatalf("un-deduped fallback did not count 4 OFDs: %s", got)
	}
}

// TestInotifyFrozenSysctlArmsLatch is the P0-13 EROFS regression:
// a read-only /proc/sys can never reach the configured ceiling —
// the failed bump must freeze the axis at its current value so
// tier-2 still arms instead of waiting forever.
func TestInotifyFrozenSysctlArmsLatch(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Pressure.InotifyMaxInstancesCeiling = 1000
	writeInotifySysctls(t, e, 100, 8192)
	// 96/100 = 96% >= 95% latch ratio but cur(100) << ceil(1000) —
	// only the frozen flag can arm this.
	mkInotifyPID(t, e, 100, 96, 0, "")
	mkProcStatus(t, e, 100, 0)
	// Read-only sysctl: the tier-1 bump write fails EROFS/EACCES.
	sysctl := filepath.Join(inotifySysctlDir(e), "max_user_instances")
	if err := os.Chmod(sysctl, 0o444); err != nil {
		t.Fatal(err)
	}
	inotifyRun(e, 100) // cycle 1 — bump fails → frozen
	inotifyRun(e, 100) // cycle 2 — latch arms on frozen axis
	if !inotifyLatched(e) {
		t.Fatal("read-only sysctl pinned the latch false forever")
	}
}

func TestInotifySameOFDKcmpDedupAndSingletonAnonInode(t *testing.T) {
	e := fixture(t)
	writeInotifySysctls(t, e, 3, 8192)
	mkInotifyPID(t, e, 100, 2, 0, "")
	mkInotifyPID(t, e, 101, 2, 0, "")
	mkProcStatus(t, e, 100, 0)
	mkProcStatus(t, e, 101, 0)
	// Same OFD across forked children proved by InotifySameOFDFn (kcmp seam).
	e.H.Cfg.Seams.Host.InotifySameOFDFn = func(pidA, fdA, pidB, fdB int) bool {
		return fdA == fdB
	}
	inotifyRun(e, 100, 101)
	if got := readSysctl(t, e, "max_user_instances"); got != "3" {
		t.Fatalf("kcmp-deduped 2 OFDs bumped sysctl: %s", got)
	}
}

func TestInotifyEvictRailsNakedPVCAndMirror(t *testing.T) {
	isCtrl := true
	owners := []metav1.OwnerReference{{
		APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs", UID: "rs-uid-rails", Controller: &isCtrl,
	}}
	cases := []struct {
		name string
		pod  *corev1.Pod
	}{
		{
			name: "naked_pod",
			pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Namespace: "app", Name: "naked", UID: "123e4567-e89b-12d3-a456-426614174020",
			}},
		},
		{
			name: "pvc_pod",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "app", Name: "db", UID: "123e4567-e89b-12d3-a456-426614174021",
					OwnerReferences: owners,
				},
				Spec: corev1.PodSpec{Volumes: []corev1.Volume{{
					Name:         "data",
					VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "db-pvc"}},
				}}},
			},
		},
		{
			name: "mirror_pod",
			pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Namespace: "app", Name: "mirror", UID: "123e4567-e89b-12d3-a456-426614174022",
				OwnerReferences: owners,
				Annotations:     map[string]string{"kubernetes.io/config.mirror": "abc"},
			}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := fixture(t)
			e.H.Cfg.Pressure.InotifyMaxInstancesCeiling = 100
			e.H.Cfg.Pressure.InotifyEvictRunawayPod = true
			writeInotifySysctls(t, e, 100, 8192)
			mkInotifyPID(t, e, 100, 96, 0, string(tc.pod.UID))
			if _, err := e.CS.CoreV1().Pods(tc.pod.Namespace).Create(context.Background(), tc.pod, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				e.H.Check(wdeps.CheckInotifyHygiene).Run(context.Background(), &wdeps.CycleEnv{
					WorkerActive: true, APIOK: true,
					Pods: []corev1.Pod{*tc.pod}, PidsOnce: wdepstest.PidsOf(100),
				})
			}
			if n := len(wdepstest.DeleteActions(e.CS)); n != 0 {
				t.Fatalf("%s deleted despite eviction rail", tc.name)
			}
			if !strings.Contains(e.LogLines(t), "protected by eviction rails") {
				t.Fatalf("%s missing protection suspect log:\n%s", tc.name, e.LogLines(t))
			}
		})
	}
}

func TestInotifySharedFDCacheTTLAndProcUnreadableAbort(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Pressure.InotifyMaxInstancesCeiling = 100
	e.H.Cfg.Pressure.InotifyEvictRunawayPod = false
	writeInotifySysctls(t, e, 100, 8192)
	mkInotifyPID(t, e, 100, 96, 0, "")

	// Latch after 2 cycles.
	inotifyRun(e, 100)
	inotifyRun(e, 100)
	if !inotifyLatched(e) {
		t.Fatal("latch did not arm")
	}

	// Mutate /proc/100/fd down to 4 WITHOUT advancing e.Now past 60s ->
	// SharedFDCache serves the cached 96 snapshot, so latch stays armed.
	mkInotifyPID(t, e, 100, 4, 0, "")
	e.Now = e.Now.Add(30 * time.Second)
	inotifyRun(e, 100)
	if !inotifyLatched(e) {
		t.Fatal("expected SharedFDCache 60s TTL reuse to keep cached snapshot")
	}

	// Advance past 60s -> cache expires, re-scans /proc, sees 4, exits latch.
	e.Now = e.Now.Add(31 * time.Second)
	inotifyRun(e, 100)
	if inotifyLatched(e) {
		t.Fatal("expected latch to exit after SharedFDCache 60s TTL expired")
	}

	// Re-arm latch on a second fixture, then remove ProcDir pid dirs ->
	// wait: sysctls are still read from ProcDir, so point ProcRoot after
	// reading? No, if ProcDir itself is unreadable, readSysctls aborts too;
	// if we test !snap.ProcOK specifically, keep sysctls in ProcDir? Wait:
	// SharedFDCache lists ProcRoot; if ProcRoot doesn't exist, readSysctls
	// fails first. Both abort cleanly without exiting the latch!
	e2 := fixture(t)
	e2.H.Cfg.Pressure.InotifyMaxInstancesCeiling = 100
	e2.H.Cfg.Pressure.InotifyEvictRunawayPod = false
	writeInotifySysctls(t, e2, 100, 8192)
	mkInotifyPID(t, e2, 100, 96, 0, "")
	inotifyRun(e2, 100)
	inotifyRun(e2, 100)
	if !inotifyLatched(e2) {
		t.Fatal("latch did not arm on e2")
	}
	// Remove /proc/100 only? No, empty /proc has ProcOK=true.
	// Remove ProcRoot entirely -> abort keeps latch intact!
	if err := os.RemoveAll(e2.ProcDir); err != nil {
		t.Fatal(err)
	}
	e2.Now = e2.Now.Add(2 * time.Minute)
	inotifyRun(e2, 100)
	if !inotifyLatched(e2) {
		t.Fatal("unreadable /proc must abort without clearing state-inotify-pressure")
	}
}

func TestInotifyWarmSharedFDCachePidsOKFalseAbortsAndKeepsLatch(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Pressure.InotifyMaxInstancesCeiling = 100
	e.H.Cfg.Pressure.InotifyEvictRunawayPod = false
	writeInotifySysctls(t, e, 100, 8192)
	mkInotifyPID(t, e, 100, 96, 0, "")

	inotifyRun(e, 100)
	inotifyRun(e, 100)
	if !inotifyLatched(e) {
		t.Fatal("latch did not arm")
	}

	// Within the 60s SharedFDCache TTL, simulate Proc.PIDs() failure via PidsOK=false.
	e.Now = e.Now.Add(10 * time.Second)
	chk := e.H.Check(wdeps.CheckInotifyHygiene)
	chk.Run(context.Background(), &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        true,
		PidsOnce:     func() []int { return nil },
		PidsOK:       func() bool { return false },
	})
	if !inotifyLatched(e) {
		t.Fatal("PidsOK=false inside SharedFDCache TTL falsely cleared LatchInotifyPressure")
	}
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckInotifyHygiene, "abort")); got != 1 {
		t.Fatalf("abort cycles=%v want 1", got)
	}

	// Contrast: genuine 0 PIDs (PidsOK=true) after TTL expires exits normally.
	e.Now = e.Now.Add(61 * time.Second)
	if err := os.RemoveAll(filepath.Join(e.ProcDir, "100")); err != nil {
		t.Fatal(err)
	}
	chk.Run(context.Background(), &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        true,
		PidsOnce:     wdepstest.PidsOf(),
		PidsOK:       func() bool { return true },
	})
	if inotifyLatched(e) {
		t.Fatal("genuine empty /proc with PidsOK=true did not clear LatchInotifyPressure")
	}
}

func TestInotifyColdSharedFDCacheProcChmod0111ImmediateRecovery(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0111 does not block root")
	}
	e := fixture(t)
	e.H.Cfg.Pressure.InotifyMaxInstancesCeiling = 100
	e.H.Cfg.Pressure.InotifyEvictRunawayPod = false
	writeInotifySysctls(t, e, 100, 8192)
	mkInotifyPID(t, e, 100, 4, 0, "")

	// Cold SharedFDCache while /proc is 0o111 (sysctls readable via +x, ReadDir fails EACCES).
	if err := os.Chmod(e.ProcDir, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(e.ProcDir, 0o755) })

	chk := e.H.Check(wdeps.CheckInotifyHygiene)
	chk.Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true, APIOK: true})
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckInotifyHygiene, "abort")); got != 1 {
		t.Fatalf("abort cycles=%v want 1 on 0o111 /proc", got)
	}

	// Restore /proc to 0o755 and advance only +10s (well within 60s SharedFDCache TTL).
	if err := os.Chmod(e.ProcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	e.Now = e.Now.Add(10 * time.Second)
	chk.Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true, APIOK: true})
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckInotifyHygiene, "ok")); got != 1 {
		t.Fatalf("ok cycles=%v want 1 at +10s recovery (pinned in abort by negative FDCache?)", got)
	}
}
