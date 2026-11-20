package guards_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestR13PipeWriteEACCESPreservesStreakEventedAndGauge(t *testing.T) {
	setupBlockedPod := func(t *testing.T) (*env, *corev1.Pod, string) {
		t.Helper()
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ghost-pod",
				Namespace: "default",
				UID:       types.UID(wdepstest.UIDA),
			},
			Spec:   corev1.PodSpec{NodeName: "node-a"},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		}
		e := fixture(t, pod)
		e.MkStatProc(t, 1, "systemd", "S", "")
		pdir := filepath.Join(e.ProcDir, "700")
		wdepstest.WriteFile(t, filepath.Join(pdir, "stat"),
			"700 (myapp) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 777 0 0\n")
		wdepstest.WriteFile(t, filepath.Join(pdir, "wchan"), "pipe_write\n")
		wdepstest.WriteFile(t, filepath.Join(pdir, "cgroup"),
			"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod"+
				strings.ReplaceAll(wdepstest.UIDA, "-", "_")+".slice/cri-containerd-abc.scope\n")
		return e, pod, pdir
	}

	assertEventCount := func(t *testing.T, e *env, want int) {
		t.Helper()
		evs, err := e.CS.EventsV1().Events("default").List(context.Background(), metav1.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, ev := range evs.Items {
			if ev.Reason == "ContainerPipeWriteBlocked" {
				count++
			}
		}
		if count != want {
			t.Fatalf("ContainerPipeWriteBlocked events=%d want %d (all=%+v)", count, want, evs.Items)
		}
	}

	for _, tc := range []struct {
		name string
		elem string
	}{
		{name: "wchan_0000", elem: "wchan"},
		{name: "cgroup_0000", elem: "cgroup"},
		{name: "stat_0000", elem: "stat"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if os.Geteuid() == 0 {
				t.Skip("chmod 0000 does not block root")
			}
			e, _, pdir := setupBlockedPod(t)
			ctx := context.Background()
			target := filepath.Join(pdir, tc.elem)
			t.Cleanup(func() { _ = os.Chmod(target, 0o644) })

			// Cycle 1: streak=1 (pre-persist), PipeBlockedProcs=0, ok=1.
			e.H.Cycle(ctx)
			if e.H.PipeBlockedProcs != 0 {
				t.Fatalf("cycle 1 PipeBlockedProcs=%d want 0", e.H.PipeBlockedProcs)
			}
			if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckPipeWrite, "ok")); got != 1 {
				t.Fatalf("cycle 1 ok=%v want 1", got)
			}

			// Transient EACCES on target file: must abort and preserve streak=1.
			if err := os.Chmod(target, 0o000); err != nil {
				t.Fatal(err)
			}
			e.H.Cycle(ctx)
			if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckPipeWrite, "abort")); got != 1 {
				t.Fatalf("pre-persist %s EACCES abort=%v want 1", tc.elem, got)
			}
			if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckPipeWrite, "ok")); got != 1 {
				t.Fatalf("pre-persist %s EACCES ok=%v want 1", tc.elem, got)
			}
			if e.H.PipeBlockedProcs != 0 {
				t.Fatalf("pre-persist %s EACCES PipeBlockedProcs=%d want 0", tc.elem, e.H.PipeBlockedProcs)
			}
			assertEventCount(t, e, 0)

			// Restore permissions: preserved streak advances 1->2 immediately on recovery.
			if err := os.Chmod(target, 0o644); err != nil {
				t.Fatal(err)
			}
			e.H.Cycle(ctx)
			if e.H.PipeBlockedProcs != 1 {
				t.Fatalf("recovery PipeBlockedProcs=%d want 1 (streak was wiped)", e.H.PipeBlockedProcs)
			}
			if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckPipeWrite, "ok")); got != 2 {
				t.Fatalf("recovery ok=%v want 2", got)
			}
			assertEventCount(t, e, 1)

			// Post-persist EACCES: must abort, preserve PipeBlockedProcs=1, and preserve evented[uid].
			if err := os.Chmod(target, 0o000); err != nil {
				t.Fatal(err)
			}
			e.H.Cycle(ctx)
			if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckPipeWrite, "abort")); got != 2 {
				t.Fatalf("post-persist %s EACCES abort=%v want 2", tc.elem, got)
			}
			if e.H.PipeBlockedProcs != 1 {
				t.Fatalf("post-persist %s EACCES PipeBlockedProcs=%d want 1 preserved", tc.elem, e.H.PipeBlockedProcs)
			}
			assertEventCount(t, e, 1)

			// Restore permissions while still blocked: must NOT emit a duplicate Warning Event.
			if err := os.Chmod(target, 0o644); err != nil {
				t.Fatal(err)
			}
			e.Fixture.Now = e.Fixture.Now.Add(time.Minute)
			e.H.Cycle(ctx)
			if e.H.PipeBlockedProcs != 1 {
				t.Fatalf("post-recovery PipeBlockedProcs=%d want 1", e.H.PipeBlockedProcs)
			}
			if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckPipeWrite, "ok")); got != 3 {
				t.Fatalf("post-recovery ok=%v want 3", got)
			}
			assertEventCount(t, e, 1)
		})
	}

	t.Run("genuine_enoent_exited_pid_cleans_streak_evented_and_gauge", func(t *testing.T) {
		e, pod, pdir := setupBlockedPod(t)
		ctx := context.Background()

		// Cycles 1-2 arm PipeBlockedProcs=1 and emit 1 ContainerPipeWriteBlocked event.
		e.H.Cycle(ctx)
		e.H.Cycle(ctx)
		if e.H.PipeBlockedProcs != 1 {
			t.Fatalf("setup PipeBlockedProcs=%d want 1", e.H.PipeBlockedProcs)
		}
		assertEventCount(t, e, 1)

		// Simulate PID 700 exiting mid-sweep (ENOENT while PidsOnce still returns 700).
		if err := os.RemoveAll(pdir); err != nil {
			t.Fatal(err)
		}
		e.H.Check(wdeps.CheckPipeWrite).Run(ctx, &wdeps.CycleEnv{
			WorkerActive: true,
			APIOK:        true,
			Pods:         []corev1.Pod{*pod},
			PidsOnce:     func() []int { return []int{1, 700} },
			PidsOK:       func() bool { return true },
		})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckPipeWrite, "abort")); got != 0 {
			t.Fatalf("ENOENT abort=%v want 0", got)
		}
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckPipeWrite, "ok")); got != 3 {
			t.Fatalf("ENOENT ok=%v want 3", got)
		}
		if e.H.PipeBlockedProcs != 0 {
			t.Fatalf("ENOENT PipeBlockedProcs=%d want 0", e.H.PipeBlockedProcs)
		}

		// Re-create the frozen process on the same pod+pid: streak and evented were
		// dropped on ENOENT, so it must require 2 fresh cycles and emit a fresh event.
		e.Fixture.Now = e.Fixture.Now.Add(time.Minute)
		wdepstest.WriteFile(t, filepath.Join(pdir, "stat"),
			"700 (myapp) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 777 0 0\n")
		wdepstest.WriteFile(t, filepath.Join(pdir, "wchan"), "pipe_write\n")
		wdepstest.WriteFile(t, filepath.Join(pdir, "cgroup"),
			"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod"+
				strings.ReplaceAll(wdepstest.UIDA, "-", "_")+".slice/cri-containerd-abc.scope\n")

		e.H.Cycle(ctx)
		if e.H.PipeBlockedProcs != 0 {
			t.Fatalf("re-freeze cycle 1 PipeBlockedProcs=%d want 0 (streak not dropped on ENOENT)", e.H.PipeBlockedProcs)
		}
		assertEventCount(t, e, 1)

		e.H.Cycle(ctx)
		if e.H.PipeBlockedProcs != 1 {
			t.Fatalf("re-freeze cycle 2 PipeBlockedProcs=%d want 1", e.H.PipeBlockedProcs)
		}
		assertEventCount(t, e, 2)
	})
}
