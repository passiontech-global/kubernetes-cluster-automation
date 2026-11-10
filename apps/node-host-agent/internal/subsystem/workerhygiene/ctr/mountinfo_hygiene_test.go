// mountinfo_hygiene_test.go — the mountinfo-hygiene check:
// the >1500-entry MountinfoTableBloat event, the orphan task-rootfs
// reaper (30m marker confirmation, umount through the systemd seam)
// and the orphan pod-volume reaper (pod gone from apiserver + ctr,
// pod dir stale >30m).
package ctr_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// mountinfoPath returns the fixture's /proc/1/mountinfo view (the
// default derives from ProcRoot: <ProcDir>/1/mountinfo).
func mountinfoPath(e *env) string {
	return filepath.Join(e.ProcDir, "1", "mountinfo")
}

// miLine renders one mountinfo row whose mount point (field 5) is
// mount — "36 35 98:0 / <mount> rw,... - overlay junk".
func miLine(mount string) string {
	return fmt.Sprintf("36 35 98:0 / %s rw,relatime - overlay junk:[1] /id\n", mount)
}

func writeMountinfo(t *testing.T, e *env, lines []string) {
	t.Helper()
	wdepstest.WriteFile(t, mountinfoPath(e), strings.Join(lines, ""))
}

func miCycle(e *env) {
	e.H.Cycle(context.Background())
}

// --- >1500 entries → MountinfoTableBloat event ---

func TestMountinfoBloatEvent(t *testing.T) {
	e := fixture(t)
	var lines []string
	for i := range 1501 {
		lines = append(lines, miLine(fmt.Sprintf("/mnt/filler%d", i)))
	}
	writeMountinfo(t, e, lines)
	miCycle(e)
	evs, err := e.CS.EventsV1().Events("default").List(context.Background(),
		metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs.Items) != 1 || evs.Items[0].Reason != "MountinfoTableBloat" {
		t.Fatalf("MountinfoTableBloat event missing: %+v", evs.Items)
	}
	// The hourly budget: a second cycle inside the window is quiet.
	miCycle(e)
	evs, _ = e.CS.EventsV1().Events("default").List(context.Background(),
		metav1.ListOptions{})
	if len(evs.Items) != 1 {
		t.Fatalf("bloat event re-emitted within the budget: %d", len(evs.Items))
	}

	// Below threshold → no event at all.
	e2 := fixture(t)
	lines = nil
	for i := range 1500 {
		lines = append(lines, miLine(fmt.Sprintf("/mnt/filler%d", i)))
	}
	writeMountinfo(t, e2, lines)
	miCycle(e2)
	evs, _ = e2.CS.EventsV1().Events("default").List(context.Background(),
		metav1.ListOptions{})
	if len(evs.Items) != 0 {
		t.Fatalf("event emitted at exactly-threshold count: %d", len(evs.Items))
	}
}

// --- orphan task rootfs (group 1) ---

func TestMountinfoTaskRootfsOrphanConfirmedThenReaped(t *testing.T) {
	e := fixture(t)
	id := strings.Repeat("a", 64)
	mount := filepath.Join(e.CtrDir, id, "rootfs")
	writeMountinfo(t, e, []string{miLine(mount)})
	e.SDReply["umount"] = ""

	miCycle(e) // first sighting: marker, no umount
	if e.SDRan("umount") {
		t.Fatal("umount ran on first sighting")
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "mi-task-seen-"+id)); err != nil {
		t.Fatal("confirmation marker not written")
	}
	e.Now = e.Now.Add(10 * time.Minute)
	miCycle(e)
	if e.SDRan("umount") {
		t.Fatal("umount inside the 30m confirmation window")
	}

	e.Now = e.Now.Add(21 * time.Minute) // 31m total
	miCycle(e)
	if !e.SDRan("umount -l " + mount) {
		t.Fatalf("no lazy umount of the orphan rootfs; sdcmds=%v", e.SDCmds)
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "mi-task-seen-"+id)); !os.IsNotExist(err) {
		t.Fatal("marker not dropped after the reap")
	}
	if !strings.Contains(e.LogLines(t), "mountinfo-hygiene umount -l orphan mount") {
		t.Fatalf("missing reap ACTION line:\n%s", e.LogLines(t))
	}
}

// mountinfoCapTestOrphans drives the reap-cap test past the
// production cap (10 — the check's internal mountinfoMaxReapPerCycle).
const mountinfoCapTestOrphans = 12

// --- reap cap: one suspect line per cycle, cap umounts ---

func TestMountinfoReapCapLogsOncePerCycle(t *testing.T) {
	e := fixture(t)
	const orphans = mountinfoCapTestOrphans // > mountinfoMaxReapPerCycle
	var lines []string
	for i := range orphans {
		id := fmt.Sprintf("%064x", i)
		lines = append(lines, miLine(filepath.Join(e.CtrDir, id, "rootfs")))
	}
	writeMountinfo(t, e, lines)
	e.SDReply["umount"] = ""

	miCycle(e) // arm the confirmation markers
	for i := range orphans {
		id := fmt.Sprintf("%064x", i)
		if _, err := os.Stat(filepath.Join(e.StateDir, "mi-task-seen-"+id)); err != nil {
			t.Fatalf("marker %d not armed: %v", i, err)
		}
	}
	e.Now = e.Now.Add(31 * time.Minute)
	miCycle(e)

	umounts := 0
	for _, c := range e.SDCmds {
		if strings.Contains(strings.Join(c, " "), "umount -l") {
			umounts++
		}
	}
	if umounts != 10 {
		t.Fatalf("umounts=%d want cap 10", umounts)
	}
	if n := strings.Count(e.LogLines(t), "reap cap"); n != 1 {
		t.Fatalf("reap-cap suspect lines=%d want exactly 1:\n%s",
			n, e.LogLines(t))
	}
}

func TestMountinfoTaskRootfsLiveTaskKept(t *testing.T) {
	e := fixture(t)
	// Task dir still listed → the ctr-tasks check owns it, the
	// mountinfo reaper must not umount under it.
	id := strings.Repeat("b", 64)
	taskDir := filepath.Join(e.CtrDir, id)
	wdepstest.WriteFile(t, filepath.Join(taskDir, "init.pid"), "9300")
	wdepstest.WriteFile(t, filepath.Join(taskDir, "config.json"), `{"annotations":{}}`)
	wdepstest.WriteFile(t, filepath.Join(taskDir, "log.json"), "{}\n")
	e.MkProc(t, 9300, "S", "", "")
	mount := filepath.Join(taskDir, "rootfs")
	writeMountinfo(t, e, []string{miLine(mount)})
	e.SDReply["umount"] = ""

	for i := 0; i < 3; i++ {
		miCycle(e)
		e.Now = e.Now.Add(31 * time.Minute)
	}
	if e.SDRan("umount") {
		t.Fatal("umount ran for a task dir that is still listed")
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "mi-task-seen-"+id)); !os.IsNotExist(err) {
		t.Fatal("marker armed for a listed task")
	}
}

// --- orphan pod volume (group 2) ---

func TestMountinfoPodVolumeOrphanReaped(t *testing.T) {
	e := fixture(t)
	uid := strings.Repeat("c", 36)
	podDir := filepath.Join(e.KubepodsDir, uid)
	wdepstest.WriteFile(t, filepath.Join(podDir, "volumes",
		"kubernetes.io~empty-dir", "cache", "junk"), "x")
	// Pod dir stale >30m.
	stale := e.Now.Add(-time.Hour)
	if err := os.Chtimes(podDir, stale, stale); err != nil {
		t.Fatal(err)
	}
	mount := filepath.Join(podDir, "volumes",
		"kubernetes.io~empty-dir", "cache")
	writeMountinfo(t, e, []string{miLine(mount)})
	e.SDReply["umount"] = ""

	miCycle(e) // apiserver has no such pod (empty CS), no ctr tasks
	if !e.SDRan("umount -l " + mount) {
		t.Fatalf("no umount of the orphan pod volume; sdcmds=%v", e.SDCmds)
	}
}

func TestMountinfoPodVolumeFreshDirNotReaped(t *testing.T) {
	e := fixture(t)
	uid := strings.Repeat("d", 36)
	podDir := filepath.Join(e.KubepodsDir, uid)
	wdepstest.WriteFile(t, filepath.Join(podDir, "volumes",
		"kubernetes.io~empty-dir", "cache", "junk"), "x")
	mount := filepath.Join(podDir, "volumes",
		"kubernetes.io~empty-dir", "cache")
	writeMountinfo(t, e, []string{miLine(mount)})
	e.SDReply["umount"] = ""

	miCycle(e) // pod dir mtime is fresh (< 30m)
	if e.SDRan("umount") {
		t.Fatal("umount ran for a fresh pod dir")
	}
}

func TestMountinfoPodVolumeLivePodNotReaped(t *testing.T) {
	e := fixture(t)
	uid := strings.Repeat("e", 36)
	podDir := filepath.Join(e.KubepodsDir, uid)
	wdepstest.WriteFile(t, filepath.Join(podDir, "volumes",
		"kubernetes.io~empty-dir", "cache", "junk"), "x")
	stale := e.Now.Add(-time.Hour)
	if err := os.Chtimes(podDir, stale, stale); err != nil {
		t.Fatal(err)
	}
	mount := filepath.Join(podDir, "volumes",
		"kubernetes.io~empty-dir", "cache")
	writeMountinfo(t, e, []string{miLine(mount)})
	e.SDReply["umount"] = ""

	// The pod IS on the node — drive Run directly with the pod in
	// the per-cycle LIST (fixture CS stays empty).
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "volpod", Namespace: "default", UID: types.UID(uid),
	}}
	pod.Spec.NodeName = "node-a"
	e.H.Check(wdeps.CheckMountinfo).Run(context.Background(), &wdeps.CycleEnv{
		Pods:         []corev1.Pod{*pod},
		APIOK:        true,
		WorkerActive: true,
		TasksOnce: func() (map[string][]wdeps.CtrTask, bool) {
			return map[string][]wdeps.CtrTask{}, true
		},
	})
	if e.SDRan("umount") {
		t.Fatal("umount ran for a pod that is still on the node")
	}
}

// --- failure tails and fail-closed gates ---

// TestMountinfoUmountFailureKeepsOrphan: a failed umount keeps the
// orphan AND its confirmation marker — the next cycle retries.
func TestMountinfoUmountFailureKeepsOrphan(t *testing.T) {
	e := fixture(t)
	// No SDReply["umount"] → the systemd fake fails the exec.
	id := strings.Repeat("1", 64)
	mount := filepath.Join(e.CtrDir, id, "rootfs")
	writeMountinfo(t, e, []string{miLine(mount)})

	miCycle(e) // arm the marker
	e.Now = e.Now.Add(31 * time.Minute)
	miCycle(e) // confirmed → umount attempt fails
	if !strings.Contains(e.LogLines(t), "umount -l "+mount+" failed") {
		t.Fatalf("missing umount-failure suspect line:\n%s", e.LogLines(t))
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "mi-task-seen-"+id)); err != nil {
		t.Fatal("confirmation marker dropped though the umount failed")
	}
	if strings.Contains(e.LogLines(t), "ACTION: mountinfo-hygiene umount") {
		t.Fatal("a failed umount must not log the reap ACTION")
	}
}

// TestMountinfoStaleMarkersPruned: mi-task-seen-* markers whose id is
// no longer an orphan candidate are swept (marker hygiene).
func TestMountinfoStaleMarkersPruned(t *testing.T) {
	e := fixture(t)
	gone := "mi-task-seen-" + strings.Repeat("9", 64)
	wdepstest.WriteFile(t, filepath.Join(e.StateDir, gone), "stale")
	writeMountinfo(t, e, []string{miLine("/mnt/ordinary")})
	e.SDReply["umount"] = ""
	miCycle(e)
	if _, err := os.Stat(filepath.Join(e.StateDir, gone)); !os.IsNotExist(err) {
		t.Fatal("stale marker survived the sweep")
	}
}

// TestMountinfoAPIUnreachableKeepsVolumes: an inconclusive apiserver
// LIST must never rehome a mounted volume — fail closed.
func TestMountinfoAPIUnreachableKeepsVolumes(t *testing.T) {
	e := fixture(t)
	uid := strings.Repeat("a", 36)
	podDir := filepath.Join(e.KubepodsDir, uid)
	wdepstest.WriteFile(t, filepath.Join(podDir, "volumes", "kubernetes.io~empty-dir", "cache", "junk"), "x")
	stale := e.Now.Add(-time.Hour)
	if err := os.Chtimes(podDir, stale, stale); err != nil {
		t.Fatal(err)
	}
	mount := filepath.Join(podDir, "volumes", "kubernetes.io~empty-dir", "cache")
	writeMountinfo(t, e, []string{miLine(mount)})
	e.SDReply["umount"] = ""
	e.H.Check(wdeps.CheckMountinfo).Run(context.Background(), &wdeps.CycleEnv{
		APIOK:        false,
		WorkerActive: true,
		TasksOnce: func() (map[string][]wdeps.CtrTask, bool) {
			return map[string][]wdeps.CtrTask{}, true
		},
	})
	if e.SDRan("umount") {
		t.Fatal("volume reaped while the apiserver verdict was unreadable")
	}
}

// TestMountinfoIncompleteTaskMapKeepsVolumes: an unlistable task root
// makes the pod-volume group unverifiable — fail closed.
func TestMountinfoIncompleteTaskMapKeepsVolumes(t *testing.T) {
	e := fixture(t)
	uid := strings.Repeat("b", 36)
	podDir := filepath.Join(e.KubepodsDir, uid)
	wdepstest.WriteFile(t, filepath.Join(podDir, "volumes", "kubernetes.io~empty-dir", "cache", "junk"), "x")
	stale := e.Now.Add(-time.Hour)
	if err := os.Chtimes(podDir, stale, stale); err != nil {
		t.Fatal(err)
	}
	mount := filepath.Join(podDir, "volumes", "kubernetes.io~empty-dir", "cache")
	writeMountinfo(t, e, []string{miLine(mount)})
	e.SDReply["umount"] = ""
	e.H.Check(wdeps.CheckMountinfo).Run(context.Background(), &wdeps.CycleEnv{
		APIOK:        true,
		WorkerActive: true,
		TasksOnce: func() (map[string][]wdeps.CtrTask, bool) {
			return nil, false // a root unlistable — ctr unreachable parity
		},
	})
	if e.SDRan("umount") {
		t.Fatal("volume reaped while the ctr verdict was unverifiable")
	}
}

// TestMountinfoEscapedMountPoints: the kernel's octal escapes decode
// before the path matchers — a volume name with spaces still reaps.
func TestMountinfoEscapedMountPoints(t *testing.T) {
	e := fixture(t)
	uid := strings.Repeat("c", 36)
	podDir := filepath.Join(e.KubepodsDir, uid)
	vol := filepath.Join(podDir, "volumes", "kubernetes.io~empty-dir", "my cache")
	wdepstest.WriteFile(t, filepath.Join(vol, "junk"), "x")
	stale := e.Now.Add(-time.Hour)
	if err := os.Chtimes(podDir, stale, stale); err != nil {
		t.Fatal(err)
	}
	escaped := strings.ReplaceAll(vol, " ", `\040`)
	writeMountinfo(t, e, []string{miLine(escaped)})
	e.SDReply["umount"] = ""
	miCycle(e)
	if !e.SDRan("umount -l " + vol) {
		t.Fatalf("escaped mount point not decoded for the reaper; sdcmds=%v", e.SDCmds)
	}
}

// TestMountinfoGatedAndExcludedShapes: the worker gate stands the
// check down; excluded mount shapes (rootfs with an empty id, a
// non-volume path under the pods dir, a task-referenced uid, a
// vanished pod dir) never reach the umount.
func TestMountinfoGatedAndExcludedShapes(t *testing.T) {
	// Worker gate down → no mountinfo read at all.
	e := fixture(t)
	e.H.Check(wdeps.CheckMountinfo).Run(context.Background(), &wdeps.CycleEnv{
		WorkerActive: false,
	})

	// Excluded shapes on an unreadable-file round (the fixture never
	// writes <ProcDir>/1/mountinfo here — the abort path returns).
	e = fixture(t)
	uid := strings.Repeat("d", 36)
	writeMountinfo(t, e, []string{
		// empty id: the mount point IS the task root's rootfs suffix
		miLine(filepath.Join(e.CtrDir, "rootfs")),
		// non-volume tree under the pods dir
		miLine(filepath.Join(e.KubepodsDir, uid, "not-volumes", "x")),
		// volume mount for a uid a live ctr task still references
		miLine(filepath.Join(e.KubepodsDir, uid, "volumes", "plugin", "vol")),
		// volume mount whose pod dir is gone entirely
		miLine(filepath.Join(e.KubepodsDir, strings.Repeat("e", 36),
			"volumes", "plugin", "vol")),
	})
	e.H.Check(wdeps.CheckMountinfo).Run(context.Background(), &wdeps.CycleEnv{
		APIOK:        true,
		WorkerActive: true,
		TasksOnce: func() (map[string][]wdeps.CtrTask, bool) {
			return map[string][]wdeps.CtrTask{
				uid: {{UID: uid, Name: "app", PID: 1, Live: true}},
			}, true
		},
	})
	if e.SDRan("umount") {
		t.Fatal("umount fired for an excluded mount shape")
	}
}

// TestMountinfoPodVolumeCapBoundsThePass: the reap cap applies to the
// pod-volume group too — 12 orphans drain at 10 per cycle with one
// cap suspect line.
func TestMountinfoPodVolumeCapBoundsThePass(t *testing.T) {
	e := fixture(t)
	var lines []string
	for i := range 12 {
		uid := fmt.Sprintf("%036x", i+7)
		podDir := filepath.Join(e.KubepodsDir, uid)
		wdepstest.WriteFile(t, filepath.Join(podDir, "volumes", "plugin", "vol", "junk"), "x")
		stale := e.Now.Add(-time.Hour)
		if err := os.Chtimes(podDir, stale, stale); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, miLine(filepath.Join(podDir, "volumes", "plugin", "vol")))
	}
	writeMountinfo(t, e, lines)
	e.SDReply["umount"] = ""
	miCycle(e)
	umounts := 0
	for _, c := range e.SDCmds {
		if strings.Contains(strings.Join(c, " "), "umount -l") {
			umounts++
		}
	}
	if umounts != 10 {
		t.Fatalf("pod-volume umounts=%d want cap 10", umounts)
	}
	if n := strings.Count(e.LogLines(t), "reap cap"); n != 1 {
		t.Fatalf("reap-cap lines=%d want 1", n)
	}
}
