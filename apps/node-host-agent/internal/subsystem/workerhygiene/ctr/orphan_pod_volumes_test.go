// orphan_pod_volumes_test.go — the orphan-pod-volumes check: the
// five fail-closed gates (API verdict, ctr task map, mountinfo,
// two-phase age confirm, volumes residue) and the per-cycle reap
// cap.
package ctr_test

import (
	"context"
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

// opvUIDs are distinct, well-formed pod UIDs (the check validates
// the 36-char dashed-hex dir name shape).
var opvUIDs = []string{
	"123e4567-e89b-12d3-a456-426614174000",
	"123e4567-e89b-12d3-a456-426614174001",
	"123e4567-e89b-12d3-a456-426614174002",
	"123e4567-e89b-12d3-a456-426614174003",
	"123e4567-e89b-12d3-a456-426614174004",
	"123e4567-e89b-12d3-a456-426614174005",
	"123e4567-e89b-12d3-a456-426614174006",
}

// mkOrphanPodDir plants <PodsDir>/<uid> with a CSI-skeleton volumes
// tree (empty dirs + vol_data.json metadata — the allowed residue)
// aged minAge+ε by mtime.
func mkOrphanPodDir(t *testing.T, e *env, uid string, age time.Duration) string {
	t.Helper()
	podDir := filepath.Join(e.KubepodsDir, uid)
	mnt := filepath.Join(podDir, "volumes", "kubernetes.io~csi", "pvc-abc", "mount")
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(podDir, "volumes",
		"kubernetes.io~csi", "pvc-abc", "vol_data.json"), "{}")
	wdepstest.WriteFile(t, filepath.Join(podDir, "etc-hosts"), "127.0.0.1 localhost\n")
	stale := e.Now.Add(-age)
	if err := os.Chtimes(podDir, stale, stale); err != nil {
		t.Fatal(err)
	}
	return podDir
}

// opvEnv builds the CycleEnv the check consumes: conclusive API,
// worker active, a complete empty task map and the given pods.
func opvEnv(e *env, apiOK bool, pods ...corev1.Pod) *wdeps.CycleEnv {
	return &wdeps.CycleEnv{
		WorkerActive: true,
		APIOK:        apiOK,
		Pods:         pods,
		TasksOnce: func() (map[string][]wdeps.CtrTask, bool) {
			return map[string][]wdeps.CtrTask{}, true
		},
	}
}

func opvRun(e *env, ce *wdeps.CycleEnv) {
	e.H.Check(wdeps.CheckOrphanPodVols).Run(context.Background(), ce)
}

// opvConfirm runs the two-phase confirm: first sight stamps the
// marker, then the clock advances past the min age and the second
// run reaches the reap gates.
func opvConfirm(e *env, ce *wdeps.CycleEnv) {
	opvRun(e, ce)                       // first sight — marker only
	e.Now = e.Now.Add(61 * time.Minute) // past the 60m confirm age
	opvRun(e, ce)                       // confirmed
}

func TestOrphanPodVolsReapsConfirmedOrphan(t *testing.T) {
	e := fixture(t)
	writeMountinfo(t, e, []string{miLine("/mnt/ordinary")})
	uid := opvUIDs[0]
	podDir := mkOrphanPodDir(t, e, uid, 61*time.Minute)
	opvConfirm(e, opvEnv(e, true))
	if _, err := os.Stat(podDir); !os.IsNotExist(err) {
		t.Fatal("confirmed orphan pod dir was not reaped")
	}
	if !strings.Contains(e.LogLines(t),
		"ACTION: orphan-pod-volumes removed orphan pod dir") {
		t.Fatalf("missing reap ACTION line:\n%s", e.LogLines(t))
	}
	// The confirm marker clears with the dir.
	if _, err := os.Stat(filepath.Join(e.StateDir, "opv-seen-"+uid)); !os.IsNotExist(err) {
		t.Fatal("opv-seen marker survived the reap")
	}
}

func TestOrphanPodVolsLivePodKept(t *testing.T) {
	e := fixture(t)
	writeMountinfo(t, e, []string{miLine("/mnt/ordinary")})
	uid := opvUIDs[0]
	podDir := mkOrphanPodDir(t, e, uid, 61*time.Minute)
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "live", Namespace: "app", UID: types.UID(uid)}}
	pod.Spec.NodeName = "node-a"
	opvConfirm(e, opvEnv(e, true, pod))
	if _, err := os.Stat(podDir); err != nil {
		t.Fatal("live pod's dir was reaped")
	}
}

func TestOrphanPodVolsAPIUnreachableKeepsAll(t *testing.T) {
	e := fixture(t)
	writeMountinfo(t, e, []string{miLine("/mnt/ordinary")})
	uid := opvUIDs[0]
	podDir := mkOrphanPodDir(t, e, uid, 61*time.Minute)
	opvConfirm(e, opvEnv(e, false))
	if _, err := os.Stat(podDir); err != nil {
		t.Fatal("dir reaped while the apiserver verdict was unreadable")
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "opv-seen-"+uid)); !os.IsNotExist(err) {
		t.Fatal("marker stamped on an inconclusive API verdict")
	}
}

func TestOrphanPodVolsTaskReferencedKept(t *testing.T) {
	e := fixture(t)
	writeMountinfo(t, e, []string{miLine("/mnt/ordinary")})
	uid := opvUIDs[0]
	podDir := mkOrphanPodDir(t, e, uid, 61*time.Minute)
	ce := opvEnv(e, true)
	ce.TasksOnce = func() (map[string][]wdeps.CtrTask, bool) {
		return map[string][]wdeps.CtrTask{
			uid: {{ID: "task-1", UID: uid}},
		}, true
	}
	opvConfirm(e, ce)
	if _, err := os.Stat(podDir); err != nil {
		t.Fatal("dir reaped while a containerd task still references the uid")
	}
}

func TestOrphanPodVolsIncompleteTaskMapKeepsAll(t *testing.T) {
	e := fixture(t)
	writeMountinfo(t, e, []string{miLine("/mnt/ordinary")})
	uid := opvUIDs[0]
	podDir := mkOrphanPodDir(t, e, uid, 61*time.Minute)
	ce := opvEnv(e, true)
	ce.TasksOnce = func() (map[string][]wdeps.CtrTask, bool) {
		return nil, false // a task root unlistable — unverifiable
	}
	opvConfirm(e, ce)
	if _, err := os.Stat(podDir); err != nil {
		t.Fatal("dir reaped while the task map was incomplete")
	}
}

func TestOrphanPodVolsMountedKept(t *testing.T) {
	e := fixture(t)
	uid := opvUIDs[0]
	podDir := mkOrphanPodDir(t, e, uid, 61*time.Minute)
	// A mount still sits under the pod dir — mountinfo-hygiene
	// owns the unmount; this check must defer.
	mount := filepath.Join(podDir, "volumes", "kubernetes.io~csi", "pvc-abc", "mount")
	writeMountinfo(t, e, []string{miLine("/mnt/ordinary"), miLine(mount)})
	opvConfirm(e, opvEnv(e, true))
	if _, err := os.Stat(podDir); err != nil {
		t.Fatal("mounted pod dir was reaped — mount gate failed")
	}
}

func TestOrphanPodVolsYoungDirKept(t *testing.T) {
	e := fixture(t)
	writeMountinfo(t, e, []string{miLine("/mnt/ordinary")})
	uid := opvUIDs[0]
	// Fresh mtime — inside the 60m age gate; the marker must not
	// even be stamped yet.
	podDir := mkOrphanPodDir(t, e, uid, time.Minute)
	opvRun(e, opvEnv(e, true))
	if _, err := os.Stat(podDir); err != nil {
		t.Fatal("young pod dir was reaped")
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "opv-seen-"+uid)); !os.IsNotExist(err) {
		t.Fatal("confirm marker stamped for a too-young dir")
	}
}

func TestOrphanPodVolsConfirmWindow(t *testing.T) {
	e := fixture(t)
	writeMountinfo(t, e, []string{miLine("/mnt/ordinary")})
	uid := opvUIDs[0]
	podDir := mkOrphanPodDir(t, e, uid, 61*time.Minute)
	opvRun(e, opvEnv(e, true)) // first sight — marker only
	if _, err := os.Stat(podDir); err != nil {
		t.Fatal("dir reaped on first sight — no confirm window")
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "opv-seen-"+uid)); err != nil {
		t.Fatal("confirm marker not stamped on first sight")
	}
	// Inside the window the marker exists but is not yet 60m old.
	opvRun(e, opvEnv(e, true))
	if _, err := os.Stat(podDir); err != nil {
		t.Fatal("dir reaped inside the confirm window")
	}
}

func TestOrphanPodVolsUserDataKept(t *testing.T) {
	e := fixture(t)
	writeMountinfo(t, e, []string{miLine("/mnt/ordinary")})
	uid := opvUIDs[0]
	podDir := mkOrphanPodDir(t, e, uid, 61*time.Minute)
	// A real user file inside volumes/ — fail closed, report only.
	wdepstest.WriteFile(t, filepath.Join(podDir, "volumes",
		"kubernetes.io~csi", "pvc-abc", "mount", "user-data.bin"), "payload")
	opvConfirm(e, opvEnv(e, true))
	if _, err := os.Stat(podDir); err != nil {
		t.Fatal("dir holding user volume data was reaped")
	}
	if !strings.Contains(e.LogLines(t), "holds volume data") {
		t.Fatalf("missing data-hold suspect line:\n%s", e.LogLines(t))
	}
}

func TestOrphanPodVolsSymlinkKept(t *testing.T) {
	e := fixture(t)
	writeMountinfo(t, e, []string{miLine("/mnt/ordinary")})
	uid := opvUIDs[0]
	podDir := mkOrphanPodDir(t, e, uid, 61*time.Minute)
	// A projected-volume ..data symlink is residue the allow-list
	// does not cover — fail closed.
	projDir := filepath.Join(podDir, "volumes", "kubernetes.io~projected", "cfg")
	if err := os.MkdirAll(projDir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(projDir, "..data")
	if err := os.Symlink("..2024_01_01_00_00_00.1", link); err != nil {
		t.Fatal(err)
	}
	opvConfirm(e, opvEnv(e, true))
	if _, err := os.Stat(podDir); err != nil {
		t.Fatal("dir with symlink residue was reaped")
	}
}

func TestOrphanPodVolsReapCap(t *testing.T) {
	e := fixture(t)
	writeMountinfo(t, e, []string{miLine("/mnt/ordinary")})
	var dirs []string
	for i := 0; i < 6; i++ {
		dirs = append(dirs, mkOrphanPodDir(t, e, opvUIDs[i], 61*time.Minute))
	}
	opvConfirm(e, opvEnv(e, true))
	reaped := 0
	for _, d := range dirs {
		if _, err := os.Stat(d); os.IsNotExist(err) {
			reaped++
		}
	}
	if reaped != 5 {
		t.Fatalf("reaped %d dirs, want the 5-per-cycle cap", reaped)
	}
	if !strings.Contains(e.LogLines(t), "reap cap 5 reached") {
		t.Fatalf("missing reap-cap suspect line:\n%s", e.LogLines(t))
	}
	// Next cycle drains the remainder.
	opvRun(e, opvEnv(e, true))
	remaining := 0
	for _, d := range dirs {
		if _, err := os.Stat(d); err == nil {
			remaining++
		}
	}
	if remaining != 0 {
		t.Fatalf("%d orphan dirs left after the follow-up cycle", remaining)
	}
}

func TestOrphanPodVolsMarkerPrunedWhenLive(t *testing.T) {
	e := fixture(t)
	writeMountinfo(t, e, []string{miLine("/mnt/ordinary")})
	uid := opvUIDs[0]
	podDir := mkOrphanPodDir(t, e, uid, 61*time.Minute)
	marker := filepath.Join(e.StateDir, "opv-seen-"+uid)
	opvRun(e, opvEnv(e, true)) // stamps the marker
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("marker not stamped")
	}
	// The pod reappears on the node — the orphan candidate is gone,
	// so its marker must be swept.
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "back", Namespace: "app", UID: types.UID(uid)}}
	pod.Spec.NodeName = "node-a"
	opvRun(e, opvEnv(e, true, pod))
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("stale opv-seen marker survived the pod's return")
	}
	if _, err := os.Stat(podDir); err != nil {
		t.Fatal("live pod's dir touched")
	}
}

func TestOrphanPodVolsNonUUIDDirsIgnored(t *testing.T) {
	e := fixture(t)
	writeMountinfo(t, e, []string{miLine("/mnt/ordinary")})
	// Non-UUID entries are not pod dirs — never candidates.
	stray := filepath.Join(e.KubepodsDir, "not-a-pod-uid")
	if err := os.MkdirAll(stray, 0o755); err != nil {
		t.Fatal(err)
	}
	opvConfirm(e, opvEnv(e, true))
	if _, err := os.Stat(stray); err != nil {
		t.Fatal("non-UUID dir was touched")
	}
}

// The transient-failure regression: a confirm marker stamped on a
// conclusive cycle must SURVIVE an inconclusive one — the old
// break-then-prune path wiped every opv-seen-<uid> stamp on a single
// ctr timeout, resetting the whole 60m confirm window.
func TestOrphanPodVolsIncompleteTasksKeepsMarkers(t *testing.T) {
	e := fixture(t)
	writeMountinfo(t, e, []string{miLine("/mnt/ordinary")})
	uid := opvUIDs[0]
	podDir := mkOrphanPodDir(t, e, uid, 61*time.Minute)
	marker := filepath.Join(e.StateDir, "opv-seen-"+uid)

	opvRun(e, opvEnv(e, true)) // conclusive — stamps the marker
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("marker not stamped on the conclusive cycle")
	}
	// Next cycle the task census is inconclusive — abort must leave
	// the marker (and the dir) untouched.
	ce := opvEnv(e, true)
	ce.TasksOnce = func() (map[string][]wdeps.CtrTask, bool) {
		return nil, false
	}
	opvRun(e, ce)
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("confirm marker pruned by an inconclusive task census")
	}
	if _, err := os.Stat(podDir); err != nil {
		t.Fatal("dir touched during the inconclusive cycle")
	}
}

// A pod dir whose volumes/ tree is already gone (pod had no volumes,
// or an earlier pass cleaned it) holds EMPTY residue — ENOENT is not
// a read failure and must not pin the dir forever.
func TestOrphanPodVolsMissingVolumesReaped(t *testing.T) {
	e := fixture(t)
	writeMountinfo(t, e, []string{miLine("/mnt/ordinary")})
	uid := opvUIDs[0]
	podDir := filepath.Join(e.KubepodsDir, uid)
	if err := os.MkdirAll(podDir, 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(podDir, "etc-hosts"), "127.0.0.1 localhost\n")
	stale := e.Now.Add(-61 * time.Minute)
	if err := os.Chtimes(podDir, stale, stale); err != nil {
		t.Fatal(err)
	}
	opvConfirm(e, opvEnv(e, true))
	if _, err := os.Stat(podDir); !os.IsNotExist(err) {
		t.Fatal("dir without volumes/ was not reaped — ENOENT treated as residue failure")
	}
}

func TestOrphanPodVolsMountinfoUnreadableKeepsAll(t *testing.T) {
	e := fixture(t)
	// No mountinfo file at all — gate 3 unverifiable → fail closed.
	uid := opvUIDs[0]
	podDir := mkOrphanPodDir(t, e, uid, 61*time.Minute)
	opvConfirm(e, opvEnv(e, true))
	if _, err := os.Stat(podDir); err != nil {
		t.Fatal("dir reaped while mountinfo was unreadable")
	}
}
