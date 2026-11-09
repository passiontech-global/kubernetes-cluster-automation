// disk_bloat_test.go — the disk side-guards on
// DiskBloatCheck: the watermark-gated stale coredump sweep and the
// interval-budgeted writable-layer runaway scan with its
// ContainerWritableLayerBloat event.
package runtime_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// --- Coredump-storm guard ---

func TestCoredumpGCSweepsStaleCoresAboveWatermark(t *testing.T) {
	e := fixture(t)
	dir := t.TempDir()
	e.H.Cfg.Disk.CoredumpDir = dir
	staleCore := filepath.Join(dir, "core.node-ops.1000.1234")
	wdepstest.WriteFile(t, staleCore, "ELF...")
	freshCore := filepath.Join(dir, "core.node-ops.1000.5678")
	wdepstest.WriteFile(t, freshCore, "ELF...") // mtime ≈ now — inside the min-age window
	old := e.Now.Add(-time.Hour)
	if err := os.Chtimes(staleCore, old, old); err != nil {
		t.Fatal(err)
	}
	e.DiskUsed = 0.90 // > the 0.85 bloat watermark

	e.H.Cycle(context.Background())
	if _, err := os.Stat(staleCore); !os.IsNotExist(err) {
		t.Fatal("stale core not removed above the watermark")
	}
	// The fresh core survives one cycle (in-progress core write).
	if _, err := os.Stat(freshCore); err != nil {
		t.Fatal("fresh core removed inside the min-age window")
	}
	if !strings.Contains(e.LogLines(t), "coredump sweep") {
		t.Fatalf("missing coredump ACTION line:\n%s", e.LogLines(t))
	}

	// Below the watermark nothing is swept.
	e2 := fixture(t)
	dir2 := t.TempDir()
	e2.H.Cfg.Disk.CoredumpDir = dir2
	keep := filepath.Join(dir2, "core.node-ops.1000.9999")
	wdepstest.WriteFile(t, keep, "ELF...")
	if err := os.Chtimes(keep, old, old); err != nil {
		t.Fatal(err)
	}
	e2.DiskUsed = 0.50
	e2.H.Cycle(context.Background())
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("core removed below the watermark")
	}
}

// TestCoredumpGCSweepCappedOldestFirst — a storm drains at the
// sweep cap per cycle, oldest mtime first, remainder next cycle.
func TestCoredumpGCSweepCappedOldestFirst(t *testing.T) {
	e := fixture(t)
	dir := t.TempDir()
	e.H.Cfg.Disk.CoredumpDir = dir
	const total = 74 // > the 64-per-cycle sweep cap
	for i := range total {
		p := filepath.Join(dir, fmt.Sprintf("core.node.1000.%04d", i))
		wdepstest.WriteFile(t, p, "ELF...")
		old := e.Now.Add(-2 * time.Hour).Add(time.Duration(i) * time.Minute)
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	e.DiskUsed = 0.90
	e.H.Cycle(context.Background())

	removed, remaining := 0, 0
	oldestGone := true
	newestKept := true
	for i := range total {
		p := filepath.Join(dir, fmt.Sprintf("core.node.1000.%04d", i))
		_, err := os.Stat(p)
		gone := os.IsNotExist(err)
		if gone {
			removed++
		} else {
			remaining++
		}
		if i < 64 && !gone {
			oldestGone = false
		}
		if i >= 64 && gone {
			newestKept = false
		}
	}
	if removed != 64 || remaining != 10 {
		t.Fatalf("removed=%d remaining=%d, want 64/10", removed, remaining)
	}
	if !oldestGone || !newestKept {
		t.Fatalf("cap not drained oldest-first: oldestGone=%v newestKept=%v",
			oldestGone, newestKept)
	}
	if !strings.Contains(e.LogLines(t), "cap 64 reached, 10 remaining drain next cycle") {
		t.Fatalf("missing drain-next-cycle note:\n%s", e.LogLines(t))
	}

	// Next cycle drains the remainder.
	e.DiskUsed = 0.90
	e.H.Cycle(context.Background())
	for i := 64; i < total; i++ {
		p := filepath.Join(dir, fmt.Sprintf("core.node.1000.%04d", i))
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("core %d not drained the next cycle", i)
		}
	}
}

// --- Writable-layer runaway scan ---

// wlayerPod builds a Running pod on node-a; lim=true adds a
// limits.ephemeral-storage entry on its only container.
func wlayerPod(name, uid string, lim bool) corev1.Pod {
	p := corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: name, Namespace: "default", UID: types.UID(uid),
	}}
	p.Spec.NodeName = "node-a"
	c := corev1.Container{Name: "main"}
	if lim {
		c.Resources.Limits = corev1.ResourceList{
			corev1.ResourceEphemeralStorage: *resource.NewQuantity(1<<30, resource.BinarySI),
		}
	}
	p.Spec.Containers = []corev1.Container{c}
	return p
}

func TestWLayerSnapshotBloatEmitsEvent(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Disk.WLayerBloatThresholdBytes = 100 // tiny threshold for the test
	snapRoot := t.TempDir()
	e.H.Cfg.Disk.WLayerSnapshotsDir = snapRoot
	// Orphan snapshot (no task dir resolves) over threshold →
	// node-scoped event.
	big := filepath.Join(snapRoot, "42", "fs", "var", "log")
	wdepstest.WriteFile(t, filepath.Join(big, "huge.log"), strings.Repeat("x", 200))
	small := filepath.Join(snapRoot, "43", "fs")
	wdepstest.WriteFile(t, filepath.Join(small, "tiny"), "x")

	chk := e.H.Check(wdeps.CheckWritableLayer)
	chk.Run(context.Background(), &wdeps.CycleEnv{
		Pods:  []corev1.Pod{wlayerPod("nolimit", "uid-aaaa", false)},
		APIOK: true, WorkerActive: true,
	})
	evs, err := e.CS.EventsV1().Events("default").List(context.Background(),
		metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs.Items) != 1 || evs.Items[0].Reason != "ContainerWritableLayerBloat" {
		t.Fatalf("ContainerWritableLayerBloat event missing: %+v", evs.Items)
	}
	if !strings.Contains(evs.Items[0].Regarding.Name, "node-a") {
		t.Fatalf("orphan snapshot not node-scoped: %+v", evs.Items[0].Regarding)
	}
	if !strings.Contains(e.LogLines(t), "ContainerWritableLayerBloat") {
		t.Fatalf("missing ACTION line:\n%s", e.LogLines(t))
	}
}

func TestWLayerPodScopedEventAndLimitExempt(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Disk.WLayerBloatThresholdBytes = 100
	snapRoot := t.TempDir()
	e.H.Cfg.Disk.WLayerSnapshotsDir = snapRoot
	// A snapshot resolvable to a pod WITHOUT the limit → pod event.
	uid := strings.Repeat("a", 36)
	id := "task-main-" + uid[:8]
	wdepstest.WriteFile(t, filepath.Join(e.CtrDir, id, "config.json"),
		`{"annotations":{"io.kubernetes.pod.uid":"`+uid+`"}}`)
	wdepstest.WriteFile(t, filepath.Join(snapRoot, id, "fs", "big"),
		strings.Repeat("x", 200))
	// A snapshot resolvable to a pod WITH the limit → exempt (its
	// writable layer is bounded by the kubelet eviction chain).
	limUID := strings.Repeat("b", 36)
	limID := "task-main-" + limUID[:8]
	wdepstest.WriteFile(t, filepath.Join(e.CtrDir, limID, "config.json"),
		`{"annotations":{"io.kubernetes.pod.uid":"`+limUID+`"}}`)
	wdepstest.WriteFile(t, filepath.Join(snapRoot, limID, "fs", "big"),
		strings.Repeat("x", 200))

	pod := wlayerPod("nolimit", uid, false)
	limPod := wlayerPod("limit", limUID, true)
	e.H.Check(wdeps.CheckWritableLayer).Run(context.Background(), &wdeps.CycleEnv{
		Pods:  []corev1.Pod{pod, limPod},
		APIOK: true, WorkerActive: true,
	})
	evs, _ := e.CS.EventsV1().Events("default").List(context.Background(),
		metav1.ListOptions{})
	if len(evs.Items) != 1 || evs.Items[0].Reason != "ContainerWritableLayerBloat" {
		t.Fatalf("want exactly one pod-scoped event: %+v", evs.Items)
	}
	if evs.Items[0].Regarding.Name != "nolimit" {
		t.Fatalf("event not on the nolimit pod: %+v", evs.Items[0].Regarding)
	}
}

func TestWLayerPodVolumeBloatEmitsEvent(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Disk.WLayerBloatThresholdBytes = 100
	uid := strings.Repeat("c", 36)
	vol := filepath.Join(e.KubepodsDir, uid, "volumes",
		"kubernetes.io~empty-dir", "cache")
	wdepstest.WriteFile(t, filepath.Join(vol, "big"), strings.Repeat("x", 200))

	e.H.Check(wdeps.CheckWritableLayer).Run(context.Background(), &wdeps.CycleEnv{
		Pods:  []corev1.Pod{wlayerPod("volpod", uid, false)},
		APIOK: true, WorkerActive: true,
	})
	evs, _ := e.CS.EventsV1().Events("default").List(context.Background(),
		metav1.ListOptions{})
	if len(evs.Items) != 1 || evs.Items[0].Reason != "ContainerWritableLayerBloat" {
		t.Fatalf("pod-volume event missing: %+v", evs.Items)
	}
	if !strings.Contains(evs.Items[0].Note, "volumes") {
		t.Fatalf("event note missing the volume dir:\n%s", evs.Items[0].Note)
	}
}

func TestWLayerScanIntervalBudgeted(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Disk.WLayerBloatThresholdBytes = 100
	snapRoot := t.TempDir()
	e.H.Cfg.Disk.WLayerSnapshotsDir = snapRoot
	wdepstest.WriteFile(t, filepath.Join(snapRoot, "42", "fs", "big"),
		strings.Repeat("x", 200))
	ce := &wdeps.CycleEnv{
		Pods:  []corev1.Pod{wlayerPod("nolimit", "uid-zzzz", false)},
		APIOK: true, WorkerActive: true,
	}
	e.H.Check(wdeps.CheckWritableLayer).Run(context.Background(), ce)
	e.H.Check(wdeps.CheckWritableLayer).Run(context.Background(), ce)
	evs, _ := e.CS.EventsV1().Events("default").List(context.Background(),
		metav1.ListOptions{})
	if len(evs.Items) != 1 {
		t.Fatalf("scan not interval-budgeted: %d events", len(evs.Items))
	}
	// Past the budget a fresh event is allowed again.
	e.Now = e.Now.Add(16 * time.Minute)
	e.H.Check(wdeps.CheckWritableLayer).Run(context.Background(), ce)
	evs, _ = e.CS.EventsV1().Events("default").List(context.Background(),
		metav1.ListOptions{})
	if len(evs.Items) != 2 {
		t.Fatalf("no re-scan after the budget: %d events", len(evs.Items))
	}
}
