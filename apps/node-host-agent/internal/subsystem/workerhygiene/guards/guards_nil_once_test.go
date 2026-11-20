// guards_nil_once_test.go — regression coverage for hand-built
// CycleEnv calls with PidsOnce == nil across all 5 guards checks that
// consume PIDs: zombie-storm, d-state-storm, pipe-write-freeze,
// psi-memory-thrash, and cni-netns-gc.
package guards_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestGuardsNilPidsOnceFallbacksAndInconclusiveAbort(t *testing.T) {
	ctx := context.Background()

	t.Run("zombie-storm", func(t *testing.T) {
		e := fixture(t)
		chk := e.H.Check(wdeps.CheckZombieStorm)
		chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckZombieStorm, "ok")); got != 1 {
			t.Fatalf("ok cycles=%v want 1", got)
		}
		e.H.Deps.State.Enter(latchdefs.LatchZombieStorm, "test")
		e.H.Deps.Proc = procfs.New(filepath.Join(t.TempDir(), "missing-proc"))
		chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckZombieStorm, "inconclusive")); got != 1 {
			t.Fatalf("inconclusive cycles=%v want 1", got)
		}
		if !e.H.Deps.State.Exists(latchdefs.LatchZombieStorm) {
			t.Fatal("LatchZombieStorm cleared on /proc error")
		}
	})

	t.Run("d-state-storm", func(t *testing.T) {
		e := fixture(t)
		chk := e.H.Check(wdeps.CheckDState)
		chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckDState, "ok")); got != 1 {
			t.Fatalf("ok cycles=%v want 1", got)
		}
		e.H.Deps.State.Enter(latchdefs.LatchDStateStorm, "test")
		e.H.Deps.Proc = procfs.New(filepath.Join(t.TempDir(), "missing-proc"))
		chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckDState, "inconclusive")); got != 1 {
			t.Fatalf("inconclusive cycles=%v want 1", got)
		}
		if !e.H.Deps.State.Exists(latchdefs.LatchDStateStorm) {
			t.Fatal("LatchDStateStorm cleared on /proc error")
		}
	})

	t.Run("pipe-write-freeze", func(t *testing.T) {
		e := fixture(t)
		chk := e.H.Check(wdeps.CheckPipeWrite)
		chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckPipeWrite, "ok")); got != 1 {
			t.Fatalf("ok cycles=%v want 1", got)
		}
		e.H.Deps.Proc = procfs.New(filepath.Join(t.TempDir(), "missing-proc"))
		chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckPipeWrite, "inconclusive")); got != 1 {
			t.Fatalf("inconclusive cycles=%v want 1", got)
		}
	})

	t.Run("psi-memory-thrash", func(t *testing.T) {
		e := fixture(t)
		wdepstest.WriteThrashFiles(t, e.Fixture, 50.0, 50000, 1000000)
		// Plant a running pod + cgroup memory.current above floor so highestRSSPod is exercised.
		isCtrl := true
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "hog", Namespace: "app", UID: types.UID(wdepstest.UIDA),
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "hog-rs", UID: "rs-uid", Controller: &isCtrl,
				}},
			},
			Spec:   corev1.PodSpec{NodeName: "node-a"},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		}
		e.MkProc(t, 4100, "S", "app", "")
		wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "4100", "cgroup"),
			"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod"+strings.ReplaceAll(wdepstest.UIDA, "-", "_")+".slice/c.scope\n")
		cgDir := filepath.Join(t.TempDir(), "cgroup")
		e.H.Cfg.Runtime.CgroupRoot = cgDir
		wdepstest.WriteFile(t, filepath.Join(cgDir, "kubepods.slice", "kubepods-burstable.slice",
			"kubepods-burstable-pod"+strings.ReplaceAll(wdepstest.UIDA, "-", "_")+".slice", "memory.current"),
			"600000000\n")

		chk := e.H.Check(wdeps.CheckPSIThrash)
		ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}
		// ConsecNeeded defaults to 2: cycle 1 pends, cycle 2 enters latch and calls CyclePIDs(e).
		chk.Run(ctx, ce)
		chk.Run(ctx, ce)
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckPSIThrash, "ok")); got != 2 {
			t.Fatalf("ok cycles=%v want 2", got)
		}
		if len(wdepstest.EvictActions(e.CS)) != 1 {
			t.Fatalf("expected 1 eviction via Proc.PIDs() fallback, got %v", wdepstest.EvictActions(e.CS))
		}

		// PidsOK=false aborts inconclusive without panicking or evicting.
		ceFail := &wdeps.CycleEnv{
			WorkerActive: true,
			APIOK:        true,
			Pods:         []corev1.Pod{*pod},
			PidsOnce:     func() []int { return nil },
			PidsOK:       func() bool { return false },
		}
		chk.Run(ctx, ceFail)
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckPSIThrash, "inconclusive")); got != 1 {
			t.Fatalf("inconclusive cycles=%v want 1", got)
		}
	})

	t.Run("cni-netns-gc", func(t *testing.T) {
		e := fixture(t)
		dir := filepath.Join(e.ProcDir, "netns")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		e.H.Cfg.Net.NetnsDir = dir
		netnsPath := filepath.Join(dir, "cni-live-or-unknown")
		wdepstest.WriteFile(t, netnsPath, "")
		old := e.Now.Add(-time.Hour)
		if err := os.Chtimes(netnsPath, old, old); err != nil {
			t.Fatal(err)
		}
		markerPath := filepath.Join(e.StateDir, "cni-netns-seen-cni-live-or-unknown")
		wdepstest.WriteFile(t, markerPath, fmt.Sprintf("%d\n", e.Now.Add(-time.Hour).Unix()))

		// Link the netns inode to PID 8001 so Proc.PIDs() fallback sees it as live.
		nsdir := filepath.Join(e.ProcDir, "8001", "ns")
		if err := os.MkdirAll(nsdir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(netnsPath, filepath.Join(nsdir, "net")); err != nil {
			t.Fatal(err)
		}

		chk := e.H.Check(wdeps.CheckCNINetns)
		chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCNINetns, "ok")); got != 1 {
			t.Fatalf("ok cycles=%v want 1", got)
		}
		if e.SDRan("umount") {
			t.Fatal("umount ran on live netns during Proc.PIDs() fallback")
		}

		// Re-arm marker, then point Proc at missing dir: must abort inconclusive, never reap or drop marker.
		wdepstest.WriteFile(t, markerPath, fmt.Sprintf("%d\n", e.Now.Add(-time.Hour).Unix()))
		e.SDReply["umount"] = ""
		e.H.Deps.Proc = procfs.New(filepath.Join(t.TempDir(), "missing-proc"))
		chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCNINetns, "inconclusive")); got != 1 {
			t.Fatalf("inconclusive cycles=%v want 1", got)
		}
		if e.SDRan("umount") {
			t.Fatal("umount ran when /proc PIDs listing failed")
		}
		if _, err := os.Stat(netnsPath); err != nil {
			t.Fatalf("cni netns file removed on inconclusive /proc scan: %v", err)
		}
		if _, err := os.Stat(markerPath); err != nil {
			t.Fatalf("cni-netns-seen marker dropped on inconclusive /proc scan: %v", err)
		}
	})
}
