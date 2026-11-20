// runtime_nil_once_test.go — regression coverage for hand-built
// CycleEnv calls with TasksOnce == nil / PidsOnce == nil in
// localpv-quota, io-pressure-throttler, and kernel-net-shim-hygiene.
package runtime_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestRuntimeNilOnceFallbacksAndInconclusiveAbort(t *testing.T) {
	ctx := context.Background()

	t.Run("localpv-quota", func(t *testing.T) {
		pv := &corev1.PersistentVolume{
			ObjectMeta: metav1.ObjectMeta{Name: "pvc-nilonce"},
			Spec: corev1.PersistentVolumeSpec{
				Capacity: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("1Gi")},
			},
		}
		pvc := &corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "default"},
			Spec:       corev1.PersistentVolumeClaimSpec{VolumeName: "pvc-nilonce"},
		}
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "hog", Namespace: "default", UID: types.UID(wdepstest.UIDA)},
			Spec: corev1.PodSpec{
				NodeName: "node-a",
				Volumes: []corev1.Volume{{
					Name: "data",
					VolumeSource: corev1.VolumeSource{
						PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data"},
					},
				}},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		}
		e := fixture(t, pv, pvc, pod)
		prov := t.TempDir()
		e.H.Cfg.Disk.LocalPVQuotaDir = prov
		pvcDir := filepath.Join(prov, "pvc-nilonce")
		if err := os.MkdirAll(pvcDir, 0o755); err != nil {
			t.Fatal(err)
		}
		f, err := os.Create(filepath.Join(pvcDir, "big.bin"))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(1717986918); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()

		e.Live[7778] = true
		e.MkTask(t, wdepstest.UIDA, "hog", 7778)
		e.DiskUsed = 0.85
		reniced := false
		ioniced := false
		e.H.Cfg.Seams.Host.ReniceFn = func(pid int) error {
			if pid == 7778 {
				reniced = true
			}
			return nil
		}
		e.H.Cfg.Seams.Host.IoniceIdleFn = func(pid int) error {
			if pid == 7778 {
				ioniced = true
			}
			return nil
		}

		chk := e.H.Check(wdeps.CheckLocalPVQuota)
		chk.Run(ctx, &wdeps.CycleEnv{
			WorkerActive: true,
			APIOK:        true,
			Pods:         []corev1.Pod{*pod},
			// TasksOnce intentionally nil -> falls back to BuildTaskMap().
		})
		if !reniced || !ioniced {
			t.Fatalf("TasksOnce nil fallback did not throttle task pid 7778: reniced=%v ioniced=%v", reniced, ioniced)
		}
	})

	t.Run("io-pressure-throttler", func(t *testing.T) {
		e := fixture(t)
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "diskstats"),
			"   8       0 sda 10 0 100 50 10 0 100 50 0 100 100\n")
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "pressure", "io"),
			"some avg10=50.00 avg60=50.00 avg300=50.00 total=100\n"+
				"full avg10=50.00 avg60=50.00 avg300=50.00 total=100\n")
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "4242", "comm"), "kopia\n")
		reniced := false
		e.H.Cfg.Seams.Host.ReniceFn = func(pid int) error {
			if pid == 4242 {
				reniced = true
			}
			return nil
		}

		chk := e.H.Check(wdeps.CheckIOPressure)
		chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
		if !reniced {
			t.Fatal("PidsOnce nil fallback did not throttle kopia pid 4242")
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckIOPressure, "ok")); got != 1 {
			t.Fatalf("ok cycles=%v want 1", got)
		}

		// PidsOK=false aborts inconclusive without panicking.
		chk.Run(ctx, &wdeps.CycleEnv{
			WorkerActive: true,
			PidsOnce:     func() []int { return nil },
			PidsOK:       func() bool { return false },
		})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckIOPressure, "inconclusive")); got != 1 {
			t.Fatalf("inconclusive cycles=%v want 1", got)
		}
	})

	t.Run("kernel-net-shim-hygiene", func(t *testing.T) {
		e := fixture(t)
		chk := e.H.Check(wdeps.CheckKernelNetShim)
		chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckKernelNetShim, "ok")); got != 1 {
			t.Fatalf("ok cycles=%v want 1", got)
		}

		e.H.Deps.State.Enter(latchdefs.LatchKernelNetShim, "test")
		e.H.Deps.Proc = procfs.New(filepath.Join(t.TempDir(), "missing-proc"))
		chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckKernelNetShim, "inconclusive")); got != 1 {
			t.Fatalf("inconclusive cycles=%v want 1", got)
		}
		if !e.H.Deps.State.Exists(latchdefs.LatchKernelNetShim) {
			t.Fatal("LatchKernelNetShim cleared on /proc error")
		}
	})
}
