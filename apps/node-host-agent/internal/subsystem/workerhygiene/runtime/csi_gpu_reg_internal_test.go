// csi_gpu_reg_internal_test.go — internal tests for CSIGuardCheck.refused pruning
// and GPUGuardCheck.liveGPUs 0-GPU PCI scan caching.
package runtime

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

func TestCSIGuardRefusedPruning(t *testing.T) {
	mkSock := func(d *wdeps.Deps, drv string) string {
		dir := pluginsRegistryDir(d)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, drv+"-reg.sock")
		wdepstest.WriteFile(t, p, "stale")
		return p
	}
	mkCSINode := func(drivers ...string) *storagev1.CSINode {
		n := &storagev1.CSINode{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}}
		for _, drv := range drivers {
			n.Spec.Drivers = append(n.Spec.Drivers, storagev1.CSINodeDriver{Name: drv})
		}
		return n
	}

	t.Run("prune_paths", func(t *testing.T) {
		d, f := rtDeps(t)
		d.Cfg.Wave2.CSIGuardMode = envx.ModeOn
		d.Cfg.Wave2.CSIHealEnabled = false // keep refused entries until pruned
		chk := NewCSIGuard(d)
		ctx := context.Background()
		if _, err := f.CS.StorageV1().CSINodes().Create(ctx, mkCSINode(), metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true}

		sockA := mkSock(d, "drv.a")
		sockB := mkSock(d, "drv.b")
		sockC := mkSock(d, "drv.c")
		chk.Run(ctx, ce)
		if len(chk.refused) != 3 {
			t.Fatalf("refused=%v want 3 drivers", chk.refused)
		}

		// APIOK=false must preserve refused.
		chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true, APIOK: false})
		if len(chk.refused) != 3 {
			t.Fatalf("APIOK=false modified refused=%v", chk.refused)
		}

		// Remove drv.a socket externally and register drv.b in CSINode.
		if err := os.Remove(sockA); err != nil {
			t.Fatal(err)
		}
		if _, err := f.CS.StorageV1().CSINodes().Update(ctx, mkCSINode("drv.b"), metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		chk.Run(ctx, ce)
		if _, ok := chk.refused["drv.a"]; ok {
			t.Fatalf("expected drv.a pruned when socket disappeared, refused=%v", chk.refused)
		}
		if _, ok := chk.refused["drv.b"]; ok {
			t.Fatalf("expected drv.b pruned when registered in CSINode, refused=%v", chk.refused)
		}
		if chk.refused["drv.c"] != 2 {
			t.Fatalf("expected drv.c streak=2, refused=%v", chk.refused)
		}

		// Remove last socket (len(socks)==0 && len(pods)==0) -> clears remaining entries.
		if err := os.Remove(sockC); err != nil {
			t.Fatal(err)
		}
		_ = sockB
		chk.Run(ctx, ce)
		if len(chk.refused) != 0 {
			t.Fatalf("expected refused cleared when all socks+pods gone, got %v", chk.refused)
		}
	})

	t.Run("preserves_on_error", func(t *testing.T) {
		d, f := rtDeps(t)
		d.Cfg.Wave2.CSIGuardMode = envx.ModeOn
		d.Cfg.Wave2.CSIHealEnabled = false
		chk := NewCSIGuard(d)
		ctx := context.Background()
		if _, err := f.CS.StorageV1().CSINodes().Create(ctx, mkCSINode(), metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true}
		mkSock(d, "drv.a")
		chk.Run(ctx, ce)
		if chk.refused["drv.a"] != 1 {
			t.Fatalf("expected streak=1, got %v", chk.refused)
		}

		// CSINode GET error -> inconclusive, must not prune.
		f.CS.PrependReactor("get", "csinodes", func(_ k8stesting.Action) (bool, kruntime.Object, error) {
			return true, nil, context.DeadlineExceeded
		})
		chk.Run(ctx, ce)
		if chk.refused["drv.a"] != 1 {
			t.Fatalf("CSINode error pruned refused: %v", chk.refused)
		}
	})
}

func TestGPUGuardZeroGPUCacheAndInvalidation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	d, f := rtDeps(t)
	root := filepath.Dir(f.KubepodsDir)
	sysRoot := filepath.Join(root, "sys")
	d.Cfg.SysClassNet = filepath.Join(sysRoot, "class", "net")
	d.Cfg.Wave2.GPUGuardMode = envx.ModeAuto

	pciDir := filepath.Join(sysRoot, "bus", "pci", "devices")
	nonGPUDev := filepath.Join(sysRoot, "devices", "pci0000:00", "0000:00:01.0")
	wdepstest.WriteFile(t, filepath.Join(nonGPUDev, "vendor"), "0x8086\n")
	wdepstest.WriteFile(t, filepath.Join(nonGPUDev, "class"), "0x060000\n")
	if err := os.MkdirAll(pciDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(nonGPUDev, filepath.Join(pciDir, "0000:00:01.0")); err != nil {
		t.Fatal(err)
	}

	chk := NewGPUGuard(d)
	ctx := context.Background()
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true}

	// Cycle 1: full scan discovers 0 GPUs and caches result.
	chk.Run(ctx, ce)
	if chk.zeroPCIAt.IsZero() {
		t.Fatal("expected 0-GPU cache populated after first scan")
	}

	// chmod 0000 on non-GPU device vendor (without modifying pciDir mtime):
	// within TTL, liveGPUs uses cache and does NOT read vendor (no abort).
	vendorFile := filepath.Join(nonGPUDev, "vendor")
	if err := os.Chmod(vendorFile, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(vendorFile, 0o644) })

	f.Now = f.Now.Add(5 * time.Minute)
	chk.Run(ctx, ce)
	if chk.zeroPCIAt.IsZero() {
		t.Fatal("expected cache hit within TTL without re-reading vendor")
	}

	// Advance past TTL -> rescans and hits EACCES on vendorFile -> inconclusive.
	f.Now = f.Now.Add(gpuPCIZeroRescanTTL)
	chk.Run(ctx, ce)
	if !chk.zeroPCIAt.IsZero() {
		t.Fatal("expected cache cleared after rescan error on TTL expiry")
	}

	// Restore vendorFile, re-populate cache, then add a new GPU symlink (modifies pciDir mtime).
	if err := os.Chmod(vendorFile, 0o644); err != nil {
		t.Fatal(err)
	}
	chk.Run(ctx, ce)
	if chk.zeroPCIAt.IsZero() {
		t.Fatal("expected cache re-populated")
	}
	gpuDev := filepath.Join(sysRoot, "devices", "pci0000:00", "0000:01:00.0")
	wdepstest.WriteFile(t, filepath.Join(gpuDev, "vendor"), "0x10de\n")
	wdepstest.WriteFile(t, filepath.Join(gpuDev, "class"), "0x030000\n")
	if err := os.Symlink(gpuDev, filepath.Join(pciDir, "0000:01:00.0")); err != nil {
		t.Fatal(err)
	}
	// Ensure pciDir mtime is strictly distinct even on coarse filesystems.
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(pciDir, future, future)

	live, ok := chk.liveGPUs(true)
	if !ok || live != 1 {
		t.Fatalf("liveGPUs=(%d,%v) want (1,true) after pciDir mtime change", live, ok)
	}
	if !chk.zeroPCIAt.IsZero() {
		t.Fatal("expected zeroPCIAt cleared when live GPUs > 0")
	}
}

func TestCSINodeDrivers(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(t *testing.T, d *wdeps.Deps, f *wdepstest.Fixture)
		want   map[string]bool
		wantOK bool
	}{
		{
			name: "nil_client",
			setup: func(_ *testing.T, d *wdeps.Deps, _ *wdepstest.Fixture) {
				d.Cfg.Client = nil
			},
			want:   nil,
			wantOK: false,
		},
		{
			name: "csinode_get_success",
			setup: func(t *testing.T, _ *wdeps.Deps, f *wdepstest.Fixture) {
				n := &storagev1.CSINode{
					ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
					Spec: storagev1.CSINodeSpec{
						Drivers: []storagev1.CSINodeDriver{
							{Name: "ebs.csi.aws.com"},
							{Name: "efs.csi.aws.com"},
						},
					},
				}
				if _, err := f.CS.StorageV1().CSINodes().Create(context.Background(), n, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			},
			want:   map[string]bool{"ebs.csi.aws.com": true, "efs.csi.aws.com": true},
			wantOK: true,
		},
		{
			name: "forbidden_fallback_success",
			setup: func(t *testing.T, _ *wdeps.Deps, f *wdepstest.Fixture) {
				f.CS.PrependReactor("get", "csinodes", func(_ k8stesting.Action) (bool, kruntime.Object, error) {
					return true, nil, apierrors.NewForbidden(storagev1.Resource("csinodes"), "node-a", errors.New("forbidden"))
				})
				node := &corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node-a",
						Annotations: map[string]string{
							"csi.volume.kubernetes.io/nodeid": `{"cephfs.csi.ceph.com":"node-a","nfs.csi.k8s.io":"node-a"}`,
						},
					},
				}
				if _, err := f.CS.CoreV1().Nodes().Create(context.Background(), node, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			},
			want:   map[string]bool{"cephfs.csi.ceph.com": true, "nfs.csi.k8s.io": true},
			wantOK: true,
		},
		{
			name: "forbidden_fallback_empty_annotation",
			setup: func(t *testing.T, _ *wdeps.Deps, f *wdepstest.Fixture) {
				f.CS.PrependReactor("get", "csinodes", func(_ k8stesting.Action) (bool, kruntime.Object, error) {
					return true, nil, apierrors.NewForbidden(storagev1.Resource("csinodes"), "node-a", errors.New("forbidden"))
				})
				node := &corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "node-a",
						Annotations: map[string]string{"csi.volume.kubernetes.io/nodeid": "  \n\t "},
					},
				}
				if _, err := f.CS.CoreV1().Nodes().Create(context.Background(), node, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			},
			want:   map[string]bool{},
			wantOK: true,
		},
		{
			name: "forbidden_fallback_invalid_json",
			setup: func(t *testing.T, _ *wdeps.Deps, f *wdepstest.Fixture) {
				f.CS.PrependReactor("get", "csinodes", func(_ k8stesting.Action) (bool, kruntime.Object, error) {
					return true, nil, apierrors.NewForbidden(storagev1.Resource("csinodes"), "node-a", errors.New("forbidden"))
				})
				node := &corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "node-a",
						Annotations: map[string]string{"csi.volume.kubernetes.io/nodeid": "not-json"},
					},
				}
				if _, err := f.CS.CoreV1().Nodes().Create(context.Background(), node, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			},
			want:   nil,
			wantOK: false,
		},
		{
			name: "forbidden_fallback_node_get_error",
			setup: func(_ *testing.T, _ *wdeps.Deps, f *wdepstest.Fixture) {
				f.CS.PrependReactor("get", "csinodes", func(_ k8stesting.Action) (bool, kruntime.Object, error) {
					return true, nil, apierrors.NewForbidden(storagev1.Resource("csinodes"), "node-a", errors.New("forbidden"))
				})
			},
			want:   nil,
			wantOK: false,
		},
		{
			name: "non_403_error",
			setup: func(_ *testing.T, _ *wdeps.Deps, f *wdepstest.Fixture) {
				f.CS.PrependReactor("get", "csinodes", func(_ k8stesting.Action) (bool, kruntime.Object, error) {
					return true, nil, errors.New("apiserver down")
				})
			},
			want:   nil,
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, f := rtDeps(t)
			tc.setup(t, d, f)
			got, ok := NewCSIGuard(d).csiNodeDrivers(context.Background())
			if ok != tc.wantOK {
				t.Fatalf("ok=%v want %v (got=%v)", ok, tc.wantOK, got)
			}
			if (tc.want == nil) != (got == nil) || !maps.Equal(got, tc.want) {
				t.Fatalf("got=%#v want %#v", got, tc.want)
			}
		})
	}
}

func TestPodMatchesCSIDriver(t *testing.T) {
	cases := []struct {
		name string
		pod  *corev1.Pod
		drv  string
		want bool
	}{
		{
			name: "nil_pod",
			pod:  nil,
			drv:  "cephfs.csi.ceph.com",
			want: false,
		},
		{
			name: "empty_driver",
			pod:  &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "csi-cephfs"}},
			drv:  "",
			want: false,
		},
		{
			name: "name_match",
			pod:  &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "csi-cephfs-nodeplugin-abc"}},
			drv:  "cephfs",
			want: true,
		},
		{
			name: "hostpath_match",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "node-plugin"},
				Spec: corev1.PodSpec{
					Volumes: []corev1.Volume{{
						Name:         "plugin-dir",
						VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/kubelet/plugins/ebs.csi.aws.com"}},
					}},
				},
			},
			drv:  "ebs.csi.aws.com",
			want: true,
		},
		{
			name: "command_match",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "node-plugin"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:    "driver",
						Command: []string{"/bin/csi-node-driver", "--driver=nfs.csi.k8s.io"},
					}},
				},
			},
			drv:  "nfs.csi.k8s.io",
			want: true,
		},
		{
			name: "args_match",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "node-plugin"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "driver",
						Args: []string{"--endpoint=/csi/rook-ceph.csi.sock"},
					}},
				},
			},
			drv:  "rook-ceph.csi",
			want: true,
		},
		{
			name: "env_value_match",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "node-plugin"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "driver",
						Env:  []corev1.EnvVar{{Name: "CSI_ENDPOINT", Value: "unix:///var/lib/csi/longhorn.io/csi.sock"}},
					}},
				},
			},
			drv:  "longhorn.io",
			want: true,
		},
		{
			name: "case_insensitive_match",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "node-plugin"},
				Spec: corev1.PodSpec{
					Volumes: []corev1.Volume{{
						Name:         "plugin-dir",
						VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/kubelet/plugins/ebs.csi.aws.com"}},
					}},
				},
			},
			drv:  "EBS.CSI.AWS.COM",
			want: true,
		},
		{
			name: "miss",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "coredns"},
				Spec: corev1.PodSpec{
					Volumes: []corev1.Volume{
						{Name: "empty", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
						{Name: "hp", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log"}}},
					},
					Containers: []corev1.Container{{
						Name:    "coredns",
						Image:   "ebs.csi.aws.com/img:v1",
						Command: []string{"/coredns"},
						Args:    []string{"-conf", "/etc/coredns/Corefile"},
						Env:     []corev1.EnvVar{{Name: "ebs.csi.aws.com", Value: "unrelated"}},
					}},
				},
			},
			drv:  "ebs.csi.aws.com",
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := podMatchesCSIDriver(tc.pod, tc.drv); got != tc.want {
				t.Fatalf("podMatchesCSIDriver(%q)=%v want %v", tc.drv, got, tc.want)
			}
		})
	}
}
