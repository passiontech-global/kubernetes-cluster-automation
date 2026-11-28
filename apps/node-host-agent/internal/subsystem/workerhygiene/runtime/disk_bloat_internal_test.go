// disk_bloat_internal_test.go — package-internal coverage for the
// podLogDirUID parser (the external runtime tests reach the check
// only through full Cycles).
package runtime

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/nodecoord"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
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

func TestDiskBloatWarnBandPreEviction(t *testing.T) {
	setup := func(t *testing.T) (*DiskBloatCheck, *wdeps.Deps, *wdepstest.Fixture, *fake.Clientset) {
		t.Helper()
		f := wdepstest.New(t)
		cfg := f.Cfg
		cfg.ApplyDefaults()
		cfg.Disk.BloatWatermark = 0.80
		cfg.Disk.BloatCriticalWatermark = 0.92
		cfg.Disk.BloatPodThresholdBytes = 100 << 20
		cfg.Disk.BloatScanInterval = time.Minute
		cfg.Disk.PodLogsDir = filepath.Join(t.TempDir(), "podlogs")
		cfg.Disk.WLayerSnapshotsDir = filepath.Join(t.TempDir(), "snaps")
		cs := fake.NewClientset()
		cfg.Client = cs
		d := &wdeps.Deps{Cfg: cfg, Proc: procfs.New(cfg.ProcRoot)}
		d.State = subframe.StoreAt(cfg.WatchdogStateDir, cfg.WatchdogLogFile,
			cfg.Seams.Host.Clock, func() *slog.Logger { return slog.Default() })
		d.Cycles, d.Actions = subframe.Counters("workerhygiene", "c", "a")
		f.Bind(d)
		d.Cfg.Seams.Host.StatfsFn = func(_ string, st *unix.Statfs_t) error {
			st.Blocks = 100
			st.Bavail = 17 // used = 0.83 (warn band: >0.80, <=0.92)
			return nil
		}
		return NewDiskBloat(d), d, f, cs
	}

	mkPod := func(ns, name, uid string, withEphemeralLimit bool) corev1.Pod {
		p := corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: ns, UID: types.UID(uid),
			},
		}
		c := corev1.Container{Name: "app"}
		if withEphemeralLimit {
			c.Resources.Limits = corev1.ResourceList{
				corev1.ResourceEphemeralStorage: *resource.NewQuantity(1<<30, resource.BinarySI),
			}
		}
		p.Spec.Containers = []corev1.Container{c}
		return p
	}

	t.Run("triggers_on_rapid_runaway_growth_without_ephemeral_limit", func(t *testing.T) {
		c, d, f, cs := setup(t)
		vol := filepath.Join(d.Cfg.PodsDir, wdepstest.UIDA,
			"volumes", "kubernetes.io~empty-dir", "scratch")
		wdepstest.WriteFile(t, filepath.Join(vol, "data"), "x")
		pod := mkPod("app", "runaway", wdepstest.UIDA, false)
		if _, err := cs.CoreV1().Pods("app").Create(context.Background(), &pod, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}

		size := int64(120 << 20)
		run := func() {
			c.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				APIOK:        true,
				Pods:         []corev1.Pod{pod},
				WalkOnce: func(root string) (int64, bool) {
					if root == vol {
						return size, false
					}
					return 0, false
				},
			})
		}

		// Scan 1: establishes prevPodBytes baseline, no pre-eviction yet.
		run()
		if got := wdepstest.EvictActions(cs); len(got) != 0 {
			t.Fatalf("unexpected eviction on baseline scan: %v", got)
		}

		// Scan 2: pod grew by +300 MiB (>=256 MiB) -> pre-evicts in warn band.
		f.Now = f.Now.Add(2 * time.Minute)
		size = 420 << 20
		run()
		if got := wdepstest.EvictActions(cs); len(got) != 1 || got[0] != "runaway" {
			t.Fatalf("evictions = %v, want [runaway]", got)
		}
		logBytes, _ := os.ReadFile(d.Cfg.WatchdogLogFile)
		if !strings.Contains(string(logBytes), "pre-DiskPressure") {
			t.Fatalf("missing pre-DiskPressure ACTION log:\n%s", string(logBytes))
		}
	})

	t.Run("skips_ephemeral_limit_protected_and_steady_pods", func(t *testing.T) {
		c, d, f, cs := setup(t)
		volLim := filepath.Join(d.Cfg.PodsDir, wdepstest.UIDA, "volumes", "kubernetes.io~empty-dir", "v")
		volSys := filepath.Join(d.Cfg.PodsDir, wdepstest.UIDB, "volumes", "kubernetes.io~empty-dir", "v")
		volSteady := filepath.Join(d.Cfg.PodsDir, wdepstest.UIDC, "volumes", "kubernetes.io~empty-dir", "v")
		for _, v := range []string{volLim, volSys, volSteady} {
			wdepstest.WriteFile(t, filepath.Join(v, "f"), "x")
		}
		podLim := mkPod("app", "limited", wdepstest.UIDA, true)
		podSys := mkPod("kube-system", "sys", wdepstest.UIDB, false)
		podSteady := mkPod("app", "steady", wdepstest.UIDC, false)

		sizes := map[string]int64{
			volLim:    50 << 20,
			volSys:    50 << 20,
			volSteady: 400 << 20,
		}
		run := func() {
			c.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				APIOK:        true,
				Pods:         []corev1.Pod{podLim, podSys, podSteady},
				WalkOnce: func(root string) (int64, bool) {
					return sizes[root], false
				},
			})
		}

		run()
		f.Now = f.Now.Add(2 * time.Minute)
		// limited and sys grow rapidly (>256 MiB), steady grows only +10 MiB.
		sizes[volLim] = 500 << 20
		sizes[volSys] = 500 << 20
		sizes[volSteady] = 410 << 20
		run()
		if got := wdepstest.EvictActions(cs); len(got) != 0 {
			t.Fatalf("expected 0 pre-evictions for limited/protected/steady pods, got %v", got)
		}
	})

	t.Run("skips_below_40pct_share_and_respects_hold_and_cooldown", func(t *testing.T) {
		c, d, f, cs := setup(t)
		volA := filepath.Join(d.Cfg.PodsDir, wdepstest.UIDA, "volumes", "kubernetes.io~empty-dir", "v")
		volB := filepath.Join(d.Cfg.PodsDir, wdepstest.UIDB, "volumes", "kubernetes.io~empty-dir", "v")
		wdepstest.WriteFile(t, filepath.Join(volA, "f"), "x")
		wdepstest.WriteFile(t, filepath.Join(volB, "f"), "x")
		podA := mkPod("app", "minor-grower", wdepstest.UIDA, false)
		podB := mkPod("app", "big-steady", wdepstest.UIDB, false)

		sizeA := int64(50 << 20)
		sizeB := int64(700 << 20)
		held := false
		d.Cfg.Coord = &nodecoord.Coord{
			Now: func() time.Time { return f.Now },
			GetAnnos: func(context.Context) (map[string]string, error) {
				if held {
					return map[string]string{nodecond.KuredLockAnno: `{"nodeID":"node-a"}`}, nil
				}
				return map[string]string{}, nil
			},
		}
		run := func() {
			c.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				APIOK:        true,
				Pods:         []corev1.Pod{podA, podB},
				WalkOnce: func(root string) (int64, bool) {
					if root == volA {
						return sizeA, false
					}
					if root == volB {
						return sizeB, false
					}
					return 0, false
				},
			})
		}

		// Baseline scan.
		run()
		// Scan 2: podA grows +300 MiB (total 350 MiB), but 350 / (350+700) = 33.3% < 40%.
		f.Now = f.Now.Add(2 * time.Minute)
		sizeA = 350 << 20
		run()
		if got := wdepstest.EvictActions(cs); len(got) != 0 {
			t.Fatalf("evicted pod with <40%% share: %v", got)
		}

		// Scan 3: podA grows another +300 MiB (total 650 MiB, 48% >= 40%) while held by maintenance.
		held = true
		f.Now = f.Now.Add(2 * time.Minute)
		sizeA = 650 << 20
		run()
		if got := wdepstest.EvictActions(cs); len(got) != 0 {
			t.Fatalf("evicted pod while held by maintenance: %v", got)
		}

		// Scan 4: hold lifted -> podA grows +300 MiB (950 MiB) -> pre-evicts podA once, then cooldown blocks next scan.
		held = false
		f.Now = f.Now.Add(nodecoord.CacheTTL + 2*time.Minute)
		sizeA = 950 << 20
		run()
		if got := wdepstest.EvictActions(cs); len(got) != 1 || got[0] != "minor-grower" {
			t.Fatalf("evictions = %v, want [minor-grower]", got)
		}
		f.Now = f.Now.Add(2 * time.Minute)
		sizeA = 1250 << 20
		run()
		if got := wdepstest.EvictActions(cs); len(got) != 1 {
			t.Fatalf("cooldown failed, got evictions=%v", got)
		}
	})

	t.Run("pre_evicts_when_init_or_sidecar_has_limit_but_main_container_lacks_limit", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			pod  func() corev1.Pod
			want []string
		}{
			{
				name: "init_limited_main_unlimited",
				pod: func() corev1.Pod {
					p := mkPod("app", "init-lim-only", wdepstest.UIDA, false)
					p.Spec.InitContainers = []corev1.Container{{
						Name: "init",
						Resources: corev1.ResourceRequirements{
							Limits: corev1.ResourceList{
								corev1.ResourceEphemeralStorage: *resource.NewQuantity(100<<20, resource.BinarySI),
							},
						},
					}}
					return p
				},
				want: []string{"init-lim-only"},
			},
			{
				name: "sidecar_limited_main_unlimited",
				pod: func() corev1.Pod {
					p := mkPod("app", "sidecar-lim-only", wdepstest.UIDA, false)
					p.Spec.Containers = append(p.Spec.Containers, corev1.Container{
						Name: "sidecar",
						Resources: corev1.ResourceRequirements{
							Limits: corev1.ResourceList{
								corev1.ResourceEphemeralStorage: *resource.NewQuantity(100<<20, resource.BinarySI),
							},
						},
					})
					return p
				},
				want: []string{"sidecar-lim-only"},
			},
			{
				name: "all_containers_limited_skipped",
				pod: func() corev1.Pod {
					p := mkPod("app", "all-limited", wdepstest.UIDA, true)
					p.Spec.InitContainers = []corev1.Container{{Name: "init"}}
					return p
				},
				want: nil,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c, d, f, cs := setup(t)
				vol := filepath.Join(d.Cfg.PodsDir, wdepstest.UIDA,
					"volumes", "kubernetes.io~empty-dir", "scratch")
				wdepstest.WriteFile(t, filepath.Join(vol, "data"), "x")
				pod := tc.pod()
				size := int64(120 << 20)
				run := func() {
					c.Run(context.Background(), &wdeps.CycleEnv{
						WorkerActive: true,
						APIOK:        true,
						Pods:         []corev1.Pod{pod},
						WalkOnce: func(root string) (int64, bool) {
							if root == vol {
								return size, false
							}
							return 0, false
						},
					})
				}
				run()
				f.Now = f.Now.Add(2 * time.Minute)
				size = 420 << 20
				run()
				got := wdepstest.EvictActions(cs)
				if len(got) != len(tc.want) || (len(got) == 1 && got[0] != tc.want[0]) {
					t.Fatalf("evictions = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("aggregates_multi_volume_pod_total_above_threshold", func(t *testing.T) {
		c, d, f, cs := setup(t)
		vol1 := filepath.Join(d.Cfg.PodsDir, wdepstest.UIDA, "volumes", "kubernetes.io~empty-dir", "v1")
		vol2 := filepath.Join(d.Cfg.PodsDir, wdepstest.UIDA, "volumes", "kubernetes.io~empty-dir", "v2")
		wdepstest.WriteFile(t, filepath.Join(vol1, "f"), "x")
		wdepstest.WriteFile(t, filepath.Join(vol2, "f"), "x")
		pod := mkPod("app", "split-bloat", wdepstest.UIDA, false)

		// Threshold is 100 MiB; each dir stays <= 90 MiB so per-dir hits are empty,
		// while their sum grows from 110 MiB -> 180 MiB? No, test +260 MiB growth
		// across 3 dirs (90+90+90=270? No, 3 vols of 90 MiB = 270 MiB -> +270 MiB!).
		vol3 := filepath.Join(d.Cfg.PodsDir, wdepstest.UIDA, "volumes", "kubernetes.io~empty-dir", "v3")
		vol4 := filepath.Join(d.Cfg.PodsDir, wdepstest.UIDA, "volumes", "kubernetes.io~empty-dir", "v4")
		wdepstest.WriteFile(t, filepath.Join(vol3, "f"), "x")
		wdepstest.WriteFile(t, filepath.Join(vol4, "f"), "x")

		perVol := int64(20 << 20) // baseline: 4 * 20 = 80 MiB
		run := func() {
			c.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				APIOK:        true,
				Pods:         []corev1.Pod{pod},
				WalkOnce: func(root string) (int64, bool) {
					switch root {
					case vol1, vol2, vol3, vol4:
						return perVol, false
					default:
						return 0, false
					}
				},
			})
		}
		run()
		f.Now = f.Now.Add(2 * time.Minute)
		perVol = 90 << 20 // 4 * 90 = 360 MiB (+280 MiB >= 256 MiB, each dir < 100 MiB threshold)
		run()
		if got := wdepstest.EvictActions(cs); len(got) != 1 || got[0] != "split-bloat" {
			t.Fatalf("multi-volume split bloat evictions = %v, want [split-bloat]", got)
		}
		if !d.State.Exists(latchdefs.LatchDiskBloat) {
			t.Fatal("LatchDiskBloat not entered for multi-volume split bloat")
		}
		logBytes, _ := os.ReadFile(d.Cfg.WatchdogLogFile)
		if !strings.Contains(string(logBytes), "pod app/split-bloat total") {
			t.Fatalf("missing synthetic pod-total hit in log:\n%s", string(logBytes))
		}
	})

	t.Run("evict_error_does_not_emit_ACTION_log", func(t *testing.T) {
		c, d, f, cs := setup(t)
		vol := filepath.Join(d.Cfg.PodsDir, wdepstest.UIDA,
			"volumes", "kubernetes.io~empty-dir", "scratch")
		wdepstest.WriteFile(t, filepath.Join(vol, "data"), "x")
		pod := mkPod("app", "pdb-protected", wdepstest.UIDA, false)
		cs.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, kruntime.Object, error) {
			if a.GetSubresource() == "eviction" {
				return true, nil, errors.New("429 Too Many Requests: Cannot evict pod as it would violate the pod's disruption budget")
			}
			return false, nil, nil
		})

		size := int64(120 << 20)
		run := func() {
			c.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				APIOK:        true,
				Pods:         []corev1.Pod{pod},
				WalkOnce: func(root string) (int64, bool) {
					if root == vol {
						return size, false
					}
					return 0, false
				},
			})
		}
		run()
		f.Now = f.Now.Add(2 * time.Minute)
		size = 420 << 20
		run()

		logBytes, _ := os.ReadFile(d.Cfg.WatchdogLogFile)
		logs := string(logBytes)
		if strings.Contains(logs, "ACTION: disk-bloat evicted pod") {
			t.Fatalf("ACTION line emitted despite Evict failure:\n%s", logs)
		}
		if !strings.Contains(logs, "suspect: disk-bloat evict app/pdb-protected failed") {
			t.Fatalf("missing suspect evict failure log:\n%s", logs)
		}
	})

	t.Run("scanErr_discards_partial_baseline_preventing_false_delta", func(t *testing.T) {
		c, d, f, cs := setup(t)
		// Create a steady pod with 400 MiB emptyDir AND a pod-logs hit, while
		// PodLogsDir is unreadable (non-dir file -> ENOTDIR -> scanErr=true) on scan 1?
		// Better: PodLogsDir has a hit AND PodsDir is a regular file (ENOTDIR -> scanErr=true)
		// on scan 1, then PodsDir is restored on scan 2 with steady 400 MiB emptyDir.
		logDir := filepath.Join(d.Cfg.Disk.PodLogsDir, "app_steady_"+wdepstest.UIDA)
		wdepstest.WriteFile(t, filepath.Join(logDir, "0.log"), "x")
		pod := mkPod("app", "steady-under-err", wdepstest.UIDA, false)

		origPodsDir := d.Cfg.PodsDir
		badPodsFile := filepath.Join(t.TempDir(), "not-a-dir")
		wdepstest.WriteFile(t, badPodsFile, "x")
		d.Cfg.PodsDir = badPodsFile

		vol := filepath.Join(origPodsDir, wdepstest.UIDA, "volumes", "kubernetes.io~empty-dir", "v")
		wdepstest.WriteFile(t, filepath.Join(vol, "data"), "x")

		run := func() {
			c.Run(context.Background(), &wdeps.CycleEnv{
				WorkerActive: true,
				APIOK:        true,
				Pods:         []corev1.Pod{pod},
				WalkOnce: func(root string) (int64, bool) {
					switch root {
					case logDir:
						return 110 << 20, false
					case vol:
						return 400 << 20, false
					default:
						return 0, false
					}
				},
			})
		}

		// Scan 1 has a logDir hit AND scanErr=true (PodsDir ENOTDIR): must NOT store
		// partial baseline {UIDA: 110 MiB}.
		run()
		// Scan 2 restores PodsDir (total=510 MiB, which would look like +400 MiB if
		// scan 1's partial baseline were kept): must treat scan 2 as baseline instead.
		d.Cfg.PodsDir = origPodsDir
		f.Now = f.Now.Add(2 * time.Minute)
		run()
		if got := wdepstest.EvictActions(cs); len(got) != 0 {
			t.Fatalf("partial scanErr baseline caused false delta eviction: %v", got)
		}
	})
}

func TestSnapshotPodUIDConsultsTasksOnceBeforeDisk(t *testing.T) {
	d, _ := rtDeps(t)
	d.Cfg.CtrTaskRoot = filepath.Join(t.TempDir(), "missing-ctr")
	d.Cfg.SandboxCtlRoot = filepath.Join(t.TempDir(), "missing-sb")
	d.Cfg.Disk.WLayerSnapshotsDir = filepath.Join(t.TempDir(), "snaps")
	// Snapshot 42 is bound in mountinfo to task "t-42", which exists ONLY in TasksOnce.
	ce := &wdeps.CycleEnv{
		MountinfoOnce: func() ([]byte, error) {
			line := "10 1 0:50 / " + d.Cfg.CtrTaskRoot + "/t-42/rootfs rw - overlay overlay rw,upperdir=" +
				d.Cfg.Disk.WLayerSnapshotsDir + "/42/fs\n"
			return []byte(line), nil
		},
		TasksOnce: func() (map[string][]wdeps.CtrTask, bool) {
			return map[string][]wdeps.CtrTask{
				wdepstest.UIDA: {{ID: "t-42", UID: wdepstest.UIDA}},
			}, true
		},
	}
	mountIDs := snapshotMountIDs(d, ce)
	taskUIDs := cycleTaskUIDs(ce)
	if got := snapshotPodUID(d, "42", mountIDs, taskUIDs); got != wdepstest.UIDA {
		t.Fatalf("snapshotPodUID = %q, want %q via TasksOnce", got, wdepstest.UIDA)
	}
}
