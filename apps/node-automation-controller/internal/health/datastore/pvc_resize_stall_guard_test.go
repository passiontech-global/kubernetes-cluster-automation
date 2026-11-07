// pvc_resize_stall_guard_test.go — coverage for the
// pvc-resize-stall-guard check: both stall condition types past and
// inside the window, the zero-timestamp ledger path, and the
// resolve-time series prune.
package datastore

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// pvcWithCondition builds a Bound PVC carrying one resize condition
// transitioned `age` ago (age<0 leaves lastTransitionTime zero — the
// can't-tell timestamp path).
func pvcWithCondition(ns, name string,
	condType corev1.PersistentVolumeClaimConditionType,
	age time.Duration) *corev1.PersistentVolumeClaim {

	c := corev1.PersistentVolumeClaimCondition{
		Type:   condType,
		Status: corev1.ConditionTrue,
	}
	if age >= 0 {
		c.LastTransitionTime = metav1.NewTime(time.Now().Add(-age))
	}
	return &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name,
			UID: types.UID("uid-" + ns + "-" + name),
		},
		Status: corev1.PersistentVolumeClaimStatus{
			Phase:      corev1.ClaimBound,
			Conditions: []corev1.PersistentVolumeClaimCondition{c},
		},
	}
}

// pvcStalledSeries reads the stall gauge without instantiating the
// tuple — the bool distinguishes "emitted 0" from "no series".
func pvcStalledSeries(t *testing.T, ns, pvc, cond string) (float64, bool) {
	t.Helper()
	return testutil.GaugeSeriesValue(t, "node_automation_pvc_resize_stalled",
		map[string]string{"namespace": ns, "pvc": pvc, "condition": cond})
}

// A FileSystemResizePending=True condition a hour old is wedged past
// the 30m window — the check fails and flags the series.
func TestPVCFileSystemResizePendingStalled(t *testing.T) {
	pvc := pvcWithCondition("db", "data-pg-0",
		corev1.PersistentVolumeClaimFileSystemResizePending, time.Hour)
	p := testProber(fake.NewSimpleClientset(pvc))
	res := probetest.MustCheck[*pvcResizeStallGuardCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("stalled resize must fail: %+v", res)
	}
	if !strings.Contains(res.Why, "FileSystemResizePending") {
		t.Fatalf("why missing the condition type: %q", res.Why)
	}
	if v, ok := pvcStalledSeries(t, "db", "data-pg-0",
		"FileSystemResizePending"); !ok || v != 1 {
		t.Fatalf("stalled series = %v,%v want 1,true", v, ok)
	}
}

// The control-plane Resizing=True marker flags on its own condition
// label once it holds past the window.
func TestPVCResizingConditionStalled(t *testing.T) {
	pvc := pvcWithCondition("data", "vol-1",
		corev1.PersistentVolumeClaimResizing, 45*time.Minute)
	p := testProber(fake.NewSimpleClientset(pvc))
	res := probetest.MustCheck[*pvcResizeStallGuardCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("stalled Resizing must fail: %+v", res)
	}
	if v, ok := pvcStalledSeries(t, "data", "vol-1",
		"Resizing"); !ok || v != 1 {
		t.Fatalf("stalled series = %v,%v want 1,true", v, ok)
	}
}

// Inside the window an expansion is still in-flight — no fail, no
// series. A resolved condition (False or gone) flags nothing either.
func TestPVCResizeInsideWindowPasses(t *testing.T) {
	fresh := pvcWithCondition("db", "fresh",
		corev1.PersistentVolumeClaimFileSystemResizePending, 10*time.Minute)
	// A False condition is a resolved resize — never a stall.
	done := pvcWithCondition("db", "done",
		corev1.PersistentVolumeClaimResizing, 2*time.Hour)
	done.Status.Conditions[0].Status = corev1.ConditionFalse
	p := testProber(fake.NewSimpleClientset(fresh, done))
	res := probetest.MustCheck[*pvcResizeStallGuardCheck](t, p).Run(ctx)
	if !res.Pass {
		t.Fatalf("in-window/resolved conditions must pass: %+v", res)
	}
	for _, tc := range [][3]string{
		{"db", "fresh", "FileSystemResizePending"},
		{"db", "done", "Resizing"},
	} {
		if _, ok := pvcStalledSeries(t, tc[0], tc[1], tc[2]); ok {
			t.Fatalf("%s/%s/%s produced a series", tc[0], tc[1], tc[2])
		}
	}
}

// A condition that carries NO lastTransitionTime cannot prove its
// age — the first-seen ledger measures it instead: first sight arms
// the clock (pass), a second sight past the window flags.
func TestPVCResizeZeroTimestampLedger(t *testing.T) {
	now := time.Now()
	pvc := pvcWithCondition("db", "notime",
		corev1.PersistentVolumeClaimResizing, -1)
	cs := fake.NewSimpleClientset(pvc)
	p := testProber(cs)
	chk := probetest.MustCheck[*pvcResizeStallGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, now)
	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("zero-timestamp condition must arm, not flag: %+v", res)
	}
	probetest.FreezeNow(p.Deps, now.Add(31*time.Minute))
	res := chk.Run(ctx)
	if res.Pass {
		t.Fatal("zero-timestamp condition held past the window must fail")
	}
	if v, ok := pvcStalledSeries(t, "db", "notime",
		"Resizing"); !ok || v != 1 {
		t.Fatalf("stalled series = %v,%v want 1,true", v, ok)
	}
}

// Resolving the condition prunes the series on the next sweep — a
// completed expansion must not keep the stall flag pinned.
func TestPVCResizeResolvedPrunesSeries(t *testing.T) {
	pvc := pvcWithCondition("db", "heals",
		corev1.PersistentVolumeClaimFileSystemResizePending, time.Hour)
	cs := fake.NewSimpleClientset(pvc)
	p := testProber(cs)
	chk := probetest.MustCheck[*pvcResizeStallGuardCheck](t, p)

	if res := chk.Run(ctx); res.Pass {
		t.Fatal("stalled condition must fail first")
	}
	if _, ok := pvcStalledSeries(t, "db", "heals",
		"FileSystemResizePending"); !ok {
		t.Fatal("stall series missing before the resolve")
	}

	u, err := cs.CoreV1().PersistentVolumeClaims("db").
		Get(ctx, "heals", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	u.Status.Conditions = nil
	if _, err := cs.CoreV1().PersistentVolumeClaims("db").
		UpdateStatus(ctx, u, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("resolved condition must pass: %+v", res)
	}
	if pvcResizeStalledGauge.DeleteLabelValues("db", "heals",
		"FileSystemResizePending") {
		t.Fatal("stall series kept after the condition resolved")
	}
}

// A terminating claim's lingering conditions are teardown noise —
// deleting PVCs flag nothing.
func TestPVCTerminatingClaimSkipped(t *testing.T) {
	pvc := pvcWithCondition("db", "dying",
		corev1.PersistentVolumeClaimResizing, 2*time.Hour)
	pvc.DeletionTimestamp = &metav1.Time{Time: time.Now().Add(-time.Minute)}
	p := testProber(fake.NewSimpleClientset(pvc))
	res := probetest.MustCheck[*pvcResizeStallGuardCheck](t, p).Run(ctx)
	if !res.Pass {
		t.Fatalf("terminating claim must not flag: %+v", res)
	}
}
