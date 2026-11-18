// writable_layer_test.go — package-internal coverage for the
// writable-layer scan's disk-pressure gate: an unpressured snapshots
// disk skips the snapshot walk entirely (BUG nonprod-oom — the walk
// farm charged ~480MB of dentry/inode slab to the agent's own memcg
// and OOM-killed the pod), a pressured one runs it.
package runtime

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestWritableLayerScanGatedByDiskPressure(t *testing.T) {
	for _, tc := range []struct {
		name     string
		diskUsed float64
		wantWalk int
	}{
		// 0.3: below the 0.80 DiskUsageAboveWatermark bar — the
		// snapshot farm walk is pure waste, kubelet eviction owns
		// the early warning.
		{"unpressured", 0.3, 0},
		// 0.9: above the bar — the scan runs its snapshot walk.
		{"pressured", 0.9, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := wdepstest.New(t)
			cfg := f.Cfg
			cfg.ApplyDefaults()
			f.DiskUsed = tc.diskUsed
			snaps := filepath.Join(cfg.K0sDataDir, "containerd",
				"io.containerd.snapshotter.v1.overlayfs", "snapshots")
			cfg.Disk.WLayerSnapshotsDir = snaps
			wdepstest.WriteFile(t,
				filepath.Join(snaps, "7", "fs", "big.bin"), strings.Repeat("x", 4096))
			d := &wdeps.Deps{Cfg: cfg, Proc: procfs.New(cfg.ProcRoot)}
			d.State = subframe.StoreAt(cfg.WatchdogStateDir, cfg.WatchdogLogFile,
				cfg.Seams.Host.Clock, func() *slog.Logger { return slog.Default() })
			f.Bind(d)
			w := &WritableLayerCheck{d: d}

			var walked []string
			e := &wdeps.CycleEnv{
				APIOK:        true,
				WorkerActive: true,
				WalkOnce: func(root string) (int64, bool) {
					walked = append(walked, root)
					return 100, false
				},
			}
			w.writableLayerScan(context.Background(), e)

			// Only snapshot fs/ roots are gated; the fixture has no
			// kubelet pods dir, so any walk recorded is the gated one.
			for _, root := range walked {
				if !strings.HasSuffix(root, "/fs") {
					t.Fatalf("unexpected walk root %q", root)
				}
			}
			if len(walked) != tc.wantWalk {
				t.Fatalf("snapshot walks=%d want %d (diskUsed=%.1f)",
					len(walked), tc.wantWalk, tc.diskUsed)
			}
		})
	}
}
