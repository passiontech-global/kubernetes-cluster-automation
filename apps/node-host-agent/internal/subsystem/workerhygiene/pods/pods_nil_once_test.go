// pods_nil_once_test.go — regression coverage for hand-built CycleEnv
// calls with TasksOnce == nil / PidsOnce == nil in pod-teardown and
// konnectivity.
package pods_test

import (
	"context"
	"os"
	"path/filepath"
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

func TestPodsNilOnceFallbacksAndFailClosedAbort(t *testing.T) {
	ctx := context.Background()

	t.Run("pod-teardown", func(t *testing.T) {
		termTime := metav1.NewTime(time.Unix(1700000000, 0))
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "stuck",
				Namespace:         "app",
				UID:               types.UID(wdepstest.UIDA),
				DeletionTimestamp: &termTime,
			},
			Spec: corev1.PodSpec{NodeName: "node-a"},
		}
		e := fixture(t, pod)
		e.Now = termTime.Add(20 * time.Minute)
		// Plant a live task under CtrTaskRoot so TasksOnce == nil fallback finds it and does NOT force-delete!
		e.Live[5555] = true
		e.MkTask(t, wdepstest.UIDA, "app", 5555)

		chk := e.H.Check(wdeps.CheckTeardown)
		chk.Run(ctx, &wdeps.CycleEnv{
			WorkerActive: true,
			APIOK:        true,
			Pods:         []corev1.Pod{*pod},
			// TasksOnce intentionally nil -> falls back to BuildTaskMap().
		})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckTeardown, "ok")); got != 1 {
			t.Fatalf("ok cycles=%v want 1", got)
		}
		if len(wdepstest.DeleteActions(e.CS)) != 0 {
			t.Fatal("force-deleted pod despite live task discovered via BuildTaskMap fallback")
		}

		// Missing CtrTaskRoot -> BuildTaskMap returns complete=false -> aborts fail-closed!
		if err := os.RemoveAll(e.CtrDir); err != nil {
			t.Fatal(err)
		}
		chk.Run(ctx, &wdeps.CycleEnv{
			WorkerActive: true,
			APIOK:        true,
			Pods:         []corev1.Pod{*pod},
		})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckTeardown, "abort")); got != 1 {
			t.Fatalf("abort cycles=%v want 1", got)
		}
		if len(wdepstest.DeleteActions(e.CS)) != 0 {
			t.Fatal("force-deleted pod when CtrTaskRoot was unreadable")
		}
	})

	t.Run("konnectivity", func(t *testing.T) {
		e := fixture(t)
		chk := e.H.Check(wdeps.CheckKonn)
		chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true, APIOK: true})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckKonn, "ok")); got != 1 {
			t.Fatalf("ok cycles=%v want 1", got)
		}

		e.H.Deps.State.Enter(latchdefs.LatchKonnectivityIPMismatch, "test")
		e.H.Deps.Proc = procfs.New(filepath.Join(t.TempDir(), "missing-proc"))
		chk.Run(ctx, &wdeps.CycleEnv{WorkerActive: true, APIOK: true})
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckKonn, "inconclusive")); got != 1 {
			t.Fatalf("inconclusive cycles=%v want 1", got)
		}
		if !e.H.Deps.State.Exists(latchdefs.LatchKonnectivityIPMismatch) {
			t.Fatal("LatchKonnectivityIPMismatch cleared on /proc error")
		}
	})
}
