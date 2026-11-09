// disk_bloat_internal_test.go — package-internal coverage for the
// podLogDirUID parser (the external runtime tests reach the check
// only through full Cycles).
package runtime

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestPodLogDirUID(t *testing.T) {
	for base, want := range map[string]string{
		"default_web_11111111-2222-3333-4444-555555555555": "11111111-2222-3333-4444-555555555555",
		"kube-system_coredns-abc_abcd1234":                 "abcd1234",
		"no-underscores":                                   "",
		"trailing-underscore_":                             "",
		"bare_":                                            "",
		"":                                                 "",
	} {
		if got := podLogDirUID(base); got != want {
			t.Fatalf("podLogDirUID(%q)=%q want %q", base, got, want)
		}
	}
}

// TestScanBloatAndWLayerShareWalkCache — one cycle's disk-bloat
// scan and writable-layer scan walk the same snapshot dirs; through
// the CycleEnv WalkOnce cache each path is walked exactly once.
func TestScanBloatAndWLayerShareWalkCache(t *testing.T) {
	f := wdepstest.New(t)
	cfg := f.Cfg
	cfg.ApplyDefaults()
	// Point both consumers at the same snapshot root — production
	// wiring derives both from the containerd snapshotter root.
	snaps := filepath.Join(cfg.K0sDataDir, "containerd",
		"io.containerd.snapshotter.v1.overlayfs", "snapshots")
	cfg.Disk.WLayerSnapshotsDir = snaps
	d := &wdeps.Deps{Cfg: cfg, Proc: procfs.New(cfg.ProcRoot)}
	d.State = subframe.StoreAt(cfg.WatchdogStateDir, cfg.WatchdogLogFile,
		cfg.Seams.Host.Clock, func() *slog.Logger { return slog.Default() })
	f.Bind(d)
	c := &DiskBloatCheck{d: d}
	w := &WritableLayerCheck{d: d}

	for _, id := range []string{"1", "2", "3"} {
		wdepstest.WriteFile(t,
			filepath.Join(snaps, id, "fs", "layer.bin"), "x")
	}

	cache := map[string][2]int64{}
	var walked []string
	e := &wdeps.CycleEnv{
		APIOK:        true,
		WorkerActive: true,
		// Mirror the production CycleEnv closure: cache per root,
		// count only real (uncached) walks.
		WalkOnce: func(root string) (int64, bool) {
			if v, ok := cache[root]; ok {
				return v[0], v[1] != 0
			}
			walked = append(walked, root)
			cache[root] = [2]int64{100, 0}
			return 100, false
		},
	}
	c.scanBloat(e, nil)
	w.writableLayerScan(context.Background(), e)

	seen := map[string]bool{}
	for _, root := range walked {
		if !strings.Contains(root, "/fs") || !strings.HasPrefix(root, snaps) {
			t.Fatalf("unexpected walk root %q", root)
		}
		if seen[root] {
			t.Fatalf("walk root %s walked more than once", root)
		}
		seen[root] = true
	}
	if len(walked) != 3 {
		t.Fatalf("real walks=%d, want 3 (one per snapshot dir, shared across both scans)", len(walked))
	}
}

// TestDiskBloatOwnedByStatefulSet — the critical-band rail: a pod
// owned by a StatefulSet holds identity-bound storage and must not
// be churned by disk-bloat eviction.
func TestDiskBloatOwnedByStatefulSet(t *testing.T) {
	p := &corev1.Pod{}
	if diskBloatOwnedByStatefulSet(p) {
		t.Fatal("no ownerReferences must be false")
	}
	p.OwnerReferences = []metav1.OwnerReference{
		{Kind: "ReplicaSet"}, {Kind: "Deployment"}}
	if diskBloatOwnedByStatefulSet(p) {
		t.Fatal("non-StatefulSet owners must be false")
	}
	p.OwnerReferences = append(p.OwnerReferences,
		metav1.OwnerReference{Kind: "StatefulSet"})
	if !diskBloatOwnedByStatefulSet(p) {
		t.Fatal("StatefulSet owner must be true")
	}
}
