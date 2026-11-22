// disk_bloat_internal_test.go — package-internal coverage for the
// podLogDirUID parser (the external runtime tests reach the check
// only through full Cycles).
package runtime

import (
	"context"
	"errors"
	"log/slog"
	"maps"
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
	// DiskUsageAboveWatermark must pass — the writable-layer scan
	// skips its snapshot walk on an unpressured disk now (the gate
	// under test in writable_layer_test.go), and this test pins the
	// shared WalkOnce dedup ACROSS the two scans.
	f.DiskUsed = 0.9
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
	if wdeps.OwnedByStatefulSet(p) {
		t.Fatal("no ownerReferences must be false")
	}
	p.OwnerReferences = []metav1.OwnerReference{
		{Kind: "ReplicaSet"}, {Kind: "Deployment"}}
	if wdeps.OwnedByStatefulSet(p) {
		t.Fatal("non-StatefulSet owners must be false")
	}
	p.OwnerReferences = append(p.OwnerReferences,
		metav1.OwnerReference{Kind: "StatefulSet"})
	if !wdeps.OwnedByStatefulSet(p) {
		t.Fatal("StatefulSet owner must be true")
	}
}

func TestSnapshotMountIDs(t *testing.T) {
	cases := []struct {
		name     string
		ctrRoot  string
		sbRoot   string
		snapRoot string
		envFn    func(t *testing.T, d *wdeps.Deps) *wdeps.CycleEnv
		want     map[string]string
	}{
		{
			name:     "read_mountinfo_error_via_once",
			ctrRoot:  "/host/run/k0s/tasks",
			sbRoot:   "/host/run/k0s/sandboxes",
			snapRoot: "/host/var/lib/k0s/snaps",
			envFn: func(_ *testing.T, _ *wdeps.Deps) *wdeps.CycleEnv {
				return &wdeps.CycleEnv{
					MountinfoOnce: func() ([]byte, error) {
						return nil, errors.New("mountinfo err")
					},
				}
			},
			want: nil,
		},
		{
			name:     "read_mountinfo_error_missing_file",
			ctrRoot:  "/host/run/k0s/tasks",
			sbRoot:   "/host/run/k0s/sandboxes",
			snapRoot: "/host/var/lib/k0s/snaps",
			envFn: func(t *testing.T, d *wdeps.Deps) *wdeps.CycleEnv {
				d.Cfg.MountinfoFile = filepath.Join(t.TempDir(), "missing-mountinfo")
				return nil
			},
			want: nil,
		},
		{
			name:     "malformed_lines_ignored",
			ctrRoot:  "/host/run/k0s/tasks",
			sbRoot:   "/host/run/k0s/sandboxes",
			snapRoot: "/host/var/lib/k0s/snaps",
			envFn: func(_ *testing.T, _ *wdeps.Deps) *wdeps.CycleEnv {
				body := strings.Join([]string{
					"no separator line",
					"1 2 3 /run/k0s/tasks/t1/rootfs - overlay overlay rw,upperdir=/var/lib/k0s/snaps/100/fs",
					"",
				}, "\n")
				return &wdeps.CycleEnv{
					MountinfoOnce: func() ([]byte, error) { return []byte(body), nil },
				}
			},
			want: map[string]string{},
		},
		{
			name:     "unescaped_octal_040_paths",
			ctrRoot:  "/host/run/my tasks",
			sbRoot:   "/host/run/k0s/sandboxes",
			snapRoot: "/host/var/lib/my snaps",
			envFn: func(_ *testing.T, _ *wdeps.Deps) *wdeps.CycleEnv {
				line := `10 1 0:50 / /run/my\040tasks/cid-space/rootfs rw,relatime - overlay overlay rw,lowerdir=/a,upperdir=/var/lib/my\040snaps/42/fs,workdir=/w` + "\n"
				return &wdeps.CycleEnv{
					MountinfoOnce: func() ([]byte, error) { return []byte(line), nil },
				}
			},
			want: map[string]string{"42": "cid-space"},
		},
		{
			name:     "ctr_task_and_sandbox_ctl_roots",
			ctrRoot:  "/host/run/k0s/tasks",
			sbRoot:   "/host/run/k0s/sandboxes",
			snapRoot: "/host/var/lib/k0s/snaps",
			envFn: func(_ *testing.T, _ *wdeps.Deps) *wdeps.CycleEnv {
				body := strings.Join([]string{
					"11 1 0:51 / /run/k0s/tasks/t1/rootfs rw - overlay overlay rw,upperdir=/var/lib/k0s/snaps/101/fs",
					"12 1 0:52 / /run/k0s/sandboxes/s1/rootfs rw - overlay overlay rw,upperdir=/var/lib/k0s/snaps/102/fs",
				}, "\n")
				return &wdeps.CycleEnv{
					MountinfoOnce: func() ([]byte, error) { return []byte(body), nil },
				}
			},
			want: map[string]string{"101": "t1", "102": "s1"},
		},
		{
			name:     "non_matching_roots_ignored",
			ctrRoot:  "/host/run/k0s/tasks",
			sbRoot:   "/host/run/k0s/sandboxes",
			snapRoot: "/host/var/lib/k0s/snaps",
			envFn: func(_ *testing.T, _ *wdeps.Deps) *wdeps.CycleEnv {
				body := strings.Join([]string{
					"13 1 0:53 / /var/lib/kubelet/pods/p1/rootfs rw - overlay overlay rw,upperdir=/var/lib/k0s/snaps/103/fs",
					"14 1 0:54 / /run/k0s/tasks/t1/other rw - overlay overlay rw,upperdir=/var/lib/k0s/snaps/104/fs",
					"15 1 0:55 / /run/k0s/tasks/t2/rootfs rw - overlay overlay rw,upperdir=/other/snaps/105/fs",
				}, "\n")
				return &wdeps.CycleEnv{
					MountinfoOnce: func() ([]byte, error) { return []byte(body), nil },
				}
			},
			want: map[string]string{},
		},
		{
			name:     "missing_upperdir_ignored",
			ctrRoot:  "/host/run/k0s/tasks",
			sbRoot:   "/host/run/k0s/sandboxes",
			snapRoot: "/host/var/lib/k0s/snaps",
			envFn: func(_ *testing.T, _ *wdeps.Deps) *wdeps.CycleEnv {
				line := "16 1 0:56 / /run/k0s/tasks/t1/rootfs rw - overlay overlay rw,lowerdir=/a,workdir=/w\n"
				return &wdeps.CycleEnv{
					MountinfoOnce: func() ([]byte, error) { return []byte(line), nil },
				}
			},
			want: map[string]string{},
		},
		{
			name:     "nested_slash_and_non_fs_rejected",
			ctrRoot:  "/host/run/k0s/tasks",
			sbRoot:   "/host/run/k0s/sandboxes",
			snapRoot: "/host/var/lib/k0s/snaps",
			envFn: func(_ *testing.T, _ *wdeps.Deps) *wdeps.CycleEnv {
				body := strings.Join([]string{
					"17 1 0:57 / /run/k0s/tasks/t1/rootfs rw - overlay overlay rw,upperdir=/var/lib/k0s/snaps/nested/104/fs",
					"18 1 0:58 / /run/k0s/tasks/t2/rootfs rw - overlay overlay rw,upperdir=/var/lib/k0s/snaps/105/work",
				}, "\n")
				return &wdeps.CycleEnv{
					MountinfoOnce: func() ([]byte, error) { return []byte(body), nil },
				}
			},
			want: map[string]string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, _ := rtDeps(t)
			d.Cfg.CtrTaskRoot = tc.ctrRoot
			d.Cfg.SandboxCtlRoot = tc.sbRoot
			d.Cfg.Disk.WLayerSnapshotsDir = tc.snapRoot
			e := tc.envFn(t, d)
			got := snapshotMountIDs(d, e)
			if (tc.want == nil) != (got == nil) || !maps.Equal(got, tc.want) {
				t.Fatalf("snapshotMountIDs=%#v want %#v", got, tc.want)
			}
		})
	}
}
