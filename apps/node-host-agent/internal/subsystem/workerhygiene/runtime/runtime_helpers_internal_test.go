// runtime_helpers_internal_test.go — package-internal coverage for
// the small pure/parse helpers the external suites only graze:
// clock-jump marker + log tail, subproc-oom scope parsers, the
// cgroup knob parsers, diskstats/PSI-io parsers and the removable
// orphan verdict.
package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// --- runtime_clock_jump.go ---

func TestClockSteppedAtMarkerShapes(t *testing.T) {
	d, _ := rtDeps(t)
	if _, ok := clockSteppedAt(d); ok {
		t.Fatal("missing marker must report !ok")
	}
	p := filepath.Join(d.Cfg.WatchdogStateDir, "clock-stepped-at")

	// Epoch content wins.
	wdepstest.WriteFile(t, p, "1700000000\n")
	got, ok := clockSteppedAt(d)
	if !ok || !got.Equal(time.Unix(1700000000, 0)) {
		t.Fatalf("epoch marker=%v,%v want 1700000000,true", got, ok)
	}

	// Non-numeric content falls back to the mtime.
	wdepstest.WriteFile(t, p, "not-an-epoch")
	got, ok = clockSteppedAt(d)
	if !ok || got.IsZero() {
		t.Fatalf("mtime fallback=%v,%v want a real time", got, ok)
	}
}

func TestTailFile(t *testing.T) {
	small := filepath.Join(t.TempDir(), "small.log")
	wdepstest.WriteFile(t, small, "abc")
	data, err := tailFile(small, 64<<10)
	if err != nil || string(data) != "abc" {
		t.Fatalf("small tail=%q,%v want abc", data, err)
	}
	big := filepath.Join(t.TempDir(), "big.log")
	body := strings.Repeat("x", 3000)
	wdepstest.WriteFile(t, big, body)
	data, err = tailFile(big, 1000)
	if err != nil || len(data) != 1000 || string(data) != body[2000:] {
		t.Fatalf("big tail len=%d err=%v want last 1000 bytes", len(data), err)
	}
	if _, err := tailFile(filepath.Join(t.TempDir(), "gone"), 10); err == nil {
		t.Fatal("missing file must error")
	}
}

func TestKonnPodLogSources(t *testing.T) {
	d, f := rtDeps(t)
	d.Cfg.Disk.PodLogsDir = t.TempDir()

	// PodLogFn fallback when no kubelet log file exists.
	d.Cfg.Seams.Probe.PodLogFn = func(_ context.Context, ns, name string, _ int64) (string, error) {
		return "api tail " + ns + "/" + name, nil
	}
	pod := &corev1.Pod{ObjectMeta: f.AssignedPod("konn-a", wdepstest.UIDA, time.Hour).
		ObjectMeta}
	if got := konnPodLog(d, context.Background(), pod); got != "api tail default/konn-a" {
		t.Fatalf("fallback log=%q", got)
	}

	// The kubelet file tail wins when present.
	dir := filepath.Join(d.Cfg.Disk.PodLogsDir,
		"default_konn-a_"+wdepstest.UIDA, "container")
	wdepstest.WriteFile(t, filepath.Join(dir, "0.log"), strings.Repeat("l", 80))
	if got := konnPodLog(d, context.Background(), pod); got != strings.Repeat("l", 80) {
		t.Fatalf("file tail=%q want the log file body", got)
	}

	// No source at all → "".
	d.Cfg.Seams.Probe.PodLogFn = func(_ context.Context, _, _ string, _ int64) (string, error) {
		return "", context.DeadlineExceeded
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if got := konnPodLog(d, context.Background(), pod); got != "" {
		t.Fatalf("no-source log=%q want empty", got)
	}
}

// --- runtime_subprocess_oom.go parsers ---

func TestSubprocOOMParsers(t *testing.T) {
	pod := t.TempDir()
	if got := containerScopeDirs(pod); len(got) != 0 {
		t.Fatalf("empty pod dir scopes=%v want none", got)
	}
	scope := filepath.Join(pod, "cri-containerd-abc.scope")
	if err := os.Mkdir(scope, 0o755); err != nil {
		t.Fatal(err)
	}
	got := containerScopeDirs(pod)
	if len(got) != 1 || got[0] != scope {
		t.Fatalf("containerScopeDirs=%v want the one scope", got)
	}

	// cgroupInitPID: missing file, empty file, first pid.
	if _, ok := cgroupInitPID(scope); ok {
		t.Fatal("missing cgroup.procs must report !ok")
	}
	wdepstest.WriteFile(t, filepath.Join(scope, "cgroup.procs"), "\n  \n")
	if _, ok := cgroupInitPID(scope); ok {
		t.Fatal("empty cgroup.procs must report !ok")
	}
	wdepstest.WriteFile(t, filepath.Join(scope, "cgroup.procs"), "41\n42\n")
	if pid, ok := cgroupInitPID(scope); !ok || pid != 41 {
		t.Fatalf("cgroupInitPID=%d,%v want 41,true", pid, ok)
	}

	// oomMemStatMiB: missing file → ""; rounding + zero defaults.
	if got := oomMemStatMiB(scope); got != "" {
		t.Fatalf("missing memory.stat breakdown=%q want empty", got)
	}
	wdepstest.WriteFile(t, filepath.Join(scope, "memory.stat"),
		"anon 1572864\nshmem 524288\njunk line\nfile\n")
	if got := oomMemStatMiB(scope); got != "anon=2MiB shmem=1MiB file=0MiB" {
		t.Fatalf("oomMemStatMiB=%q want rounded breakdown", got)
	}
}

// --- runtime_cgroup_throttle.go parsers ---

func TestCgroupKnobParsers(t *testing.T) {
	dir := t.TempDir()
	events := filepath.Join(dir, "memory.events")
	if _, ok := cgroupEventsValue(events, "high"); ok {
		t.Fatal("missing events file must report !ok")
	}
	wdepstest.WriteFile(t, events, "populated 3\nhigh 7\nhigh 9\noom 0\n")
	if v, ok := cgroupEventsValue(events, "high"); !ok || v != 7 {
		t.Fatalf("cgroupEventsValue=%d,%v want first high=7", v, ok)
	}
	if _, ok := cgroupEventsValue(events, "oom_kill"); ok {
		t.Fatal("absent key must report !ok")
	}

	pids := filepath.Join(dir, "pids.max")
	if _, ok := cgroupPidsLimit(pids); ok {
		t.Fatal("missing pids.max must report !ok")
	}
	wdepstest.WriteFile(t, pids, "max\n")
	if _, ok := cgroupPidsLimit(pids); ok {
		t.Fatal("max sentinel must report !ok (no ratio)")
	}
	wdepstest.WriteFile(t, pids, " 512 \n")
	if v, ok := cgroupPidsLimit(pids); !ok || v != 512 {
		t.Fatalf("cgroupPidsLimit=%d,%v want 512,true", v, ok)
	}

	if got := podUIDFromSlice("/sys/fs/cgroup/kubepods.slice/" +
		"kubepods-burstable-pod1111_2222.slice"); got != "1111-2222" {
		t.Fatalf("podUIDFromSlice=%q want dashes restored", got)
	}
	if got := podUIDFromSlice("/x/kubepods-podabcd.slice"); got != "abcd" {
		t.Fatalf("podUIDFromSlice=%q want abcd", got)
	}
	if got := podUIDFromSlice("/x/system.slice"); got != "system" {
		t.Fatalf("non-pod slice=%q want the base", got)
	}
}

// --- runtime_io_pressure.go + runtime_systemd_sessions.go ---

func TestIsWholeDisk(t *testing.T) {
	for name, want := range map[string]bool{
		"sda1": false, "nvme0n1p2": false, "vdb3": false, // partitions
		"loop0": false, "zram3": false, "dm-1": false, "md0": false,
		"nbd9": false, "sr0": false, "fd0": false, "pmem0": false,
		"vda": true, "vdb": true, "sdc": true, "xvdf": true, "nvme0n1": true,
	} {
		if got := isWholeDisk(name); got != want {
			t.Fatalf("isWholeDisk(%q)=%v want %v", name, got, want)
		}
	}
}

func TestPsiIOFullAvgs(t *testing.T) {
	d, _ := rtDeps(t)
	if _, _, ok := psiIOFullAvgs(d); ok {
		t.Fatal("missing pressure/io must report !ok")
	}
	wdepstest.WriteFile(t, filepath.Join(d.Cfg.ProcRoot, "pressure", "io"),
		"some avg10=1 avg60=2 avg300=3 total=1\n"+
			"full avg10=4 avg60=12.5 avg300=40 total=2\n")
	a60, a300, ok := psiIOFullAvgs(d)
	if !ok || a60 != 12.5 || a300 != 40 {
		t.Fatalf("psiIOFullAvgs=%v,%v,%v want 12.5,40,true", a60, a300, ok)
	}
	wdepstest.WriteFile(t, filepath.Join(d.Cfg.ProcRoot, "pressure", "io"),
		"full avg10=1 avg60=bogus avg300=3 total=2\n")
	if _, _, ok := psiIOFullAvgs(d); ok {
		t.Fatal("unparseable avg60 must report !ok")
	}
	wdepstest.WriteFile(t, filepath.Join(d.Cfg.ProcRoot, "pressure", "io"),
		"some avg10=1 avg60=2 avg300=3 total=1\n")
	if _, _, ok := psiIOFullAvgs(d); ok {
		t.Fatal("no full row must report !ok")
	}
}

func TestSessionState(t *testing.T) {
	data := "Name=session-7.scope\nSTATE=closing\nIdleHint=no\n"
	if got := sessionState([]byte(data)); got != "closing" {
		t.Fatalf("sessionState=%q want closing", got)
	}
	if got := sessionState([]byte("Name=x\n")); got != "" {
		t.Fatalf("no STATE line=%q want empty", got)
	}
	if got := sessionState([]byte("STATE=   active  \n")); got != "active" {
		t.Fatalf("untrimmed=%q want active", got)
	}
}

// --- coredump_gc.go / orphan_hostpath.go / unlinked_open_files.go ---

func TestPodDeclaresEphemeralStorage(t *testing.T) {
	if podDeclaresEphemeralStorage(nil) {
		t.Fatal("nil pod must report false")
	}
	bare := &corev1.Pod{}
	if podDeclaresEphemeralStorage(bare) {
		t.Fatal("no limits must report false")
	}
	limited := &corev1.Pod{Spec: corev1.PodSpec{
		Containers: []corev1.Container{{
			Resources: corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					corev1.ResourceEphemeralStorage: resource.MustParse("1Gi"),
				},
			},
		}},
	}}
	if !podDeclaresEphemeralStorage(limited) {
		t.Fatal("container ephemeral-storage limit must report true")
	}
	initLimited := &corev1.Pod{Spec: corev1.PodSpec{
		InitContainers: []corev1.Container{{
			Resources: corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					corev1.ResourceEphemeralStorage: resource.MustParse("1Gi"),
				},
			},
		}},
	}}
	if !podDeclaresEphemeralStorage(initLimited) {
		t.Fatal("init-container limit must report true")
	}
}

func TestOrphanHPRemovable(t *testing.T) {
	dir := t.TempDir()
	if ok, why := orphanHPRemovable(dir); !ok || why != "empty" {
		t.Fatalf("empty dir=%v,%q want true,empty", ok, why)
	}
	wdepstest.WriteFile(t, filepath.Join(dir, ".deleted"), "")
	if ok, why := orphanHPRemovable(dir); !ok || why != "deleted-marker" {
		t.Fatalf(".deleted tombstone=%v,%q want true,deleted-marker", ok, why)
	}
	wdepstest.WriteFile(t, filepath.Join(dir, "data.bin"), "x")
	if ok, _ := orphanHPRemovable(dir); ok {
		t.Fatal("real data must never be removable")
	}
	// A directory-shaped ".deleted" is not the regular tombstone.
	tomb := t.TempDir()
	if err := os.Mkdir(filepath.Join(tomb, ".deleted"), 0o755); err != nil {
		t.Fatal(err)
	}
	if ok, _ := orphanHPRemovable(tomb); ok {
		t.Fatal("directory .deleted must not count as the tombstone")
	}
	if _, why := orphanHPRemovable(filepath.Join(tomb, "gone")); !strings.HasPrefix(why, "unreadable") {
		t.Fatalf("missing dir why=%q want unreadable", why)
	}
}

func TestProcCommFallback(t *testing.T) {
	d, f := rtDeps(t)
	c := NewUnlinkedOpenFiles(d)
	// No comm file → stat comm fallback.
	f.MkProc(t, 55, "S", "", "")
	if got := c.procComm(55); got != "fakeproc" {
		t.Fatalf("stat fallback comm=%q want fakeproc", got)
	}
	// comm present → trimmed value.
	wdepstest.WriteFile(t, filepath.Join(d.Cfg.ProcRoot, "55", "comm"),
		"nginx \n")
	if got := c.procComm(55); got != "nginx" {
		t.Fatalf("comm=%q want nginx", got)
	}
	if got := c.procComm(999); got != "" {
		t.Fatalf("missing pid comm=%q want empty", got)
	}
}
