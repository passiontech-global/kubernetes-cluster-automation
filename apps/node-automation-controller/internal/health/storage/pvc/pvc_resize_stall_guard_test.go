// pvc_resize_stall_guard_test.go — coverage for the
// pvc-resize-stall-guard check: both stall condition types past and
// inside the window, the zero-timestamp ledger path, and the
// resolve-time series prune.
package pvc

import (
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
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
	res := probetest.MustCheck[*pvcResizeStallGuardCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
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
	res := probetest.MustCheck[*pvcResizeStallGuardCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
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
	res := probetest.MustCheck[*pvcResizeStallGuardCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
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
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("zero-timestamp condition must arm, not flag: %+v", res)
	}
	probetest.FreezeNow(p.Deps, now.Add(31*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
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

	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); res.Pass {
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

	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
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
	res := probetest.MustCheck[*pvcResizeStallGuardCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
	if !res.Pass {
		t.Fatalf("terminating claim must not flag: %+v", res)
	}
}

func makePVCStallPod(ns, name, pvcName string, owner *metav1.OwnerReference, annos map[string]string) *corev1.Pod {
	var owners []metav1.OwnerReference
	if owner != nil {
		owners = []metav1.OwnerReference{*owner}
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       ns,
			Name:            name,
			UID:             types.UID("uid-" + ns + "-" + name),
			OwnerReferences: owners,
			Annotations:     annos,
		},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{{
				Name: "data",
				VolumeSource: corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
						ClaimName: pvcName,
					},
				},
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func capturePVCStallEvictions(cs *fake.Clientset, react func(ev *policyv1.Eviction) (bool, error)) *[]string {
	var evicted []string
	cs.PrependReactor("create", "pods", func(action ktesting.Action) (bool, runtime.Object, error) {
		if action.GetSubresource() != "eviction" {
			return false, nil, nil
		}
		ev := action.(ktesting.CreateAction).GetObject().(*policyv1.Eviction)
		if react != nil {
			if handled, err := react(ev); handled {
				return true, nil, err
			}
		}
		evicted = append(evicted, ev.Namespace+"/"+ev.Name)
		return true, ev, nil
	})
	return &evicted
}

func TestPVCResizeBounceEnvAndAnnotationOptIn(t *testing.T) {
	base := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	ctrlTrue := true
	stsOwner := &metav1.OwnerReference{Kind: "StatefulSet", Name: "pg", UID: "sts-uid-1", Controller: &ctrlTrue}

	t.Run("env opt-in bounces at most 1 owned pod per PVC and skips standalone/kube-system/mirror/opt-out", func(t *testing.T) {
		pvcResizeStalledGauge.Reset()
		t.Setenv("NODE_AUTOMATION_PVC_RESIZE_BOUNCE_ENABLED", "true")

		pvc := pvcWithCondition("db", "data-pg-0", corev1.PersistentVolumeClaimFileSystemResizePending, time.Hour)
		pvc.Status.Conditions[0].LastTransitionTime = metav1.NewTime(base.Add(-time.Hour))

		pvcKS := pvcWithCondition("kube-system", "ks-pvc", corev1.PersistentVolumeClaimFileSystemResizePending, time.Hour)
		pvcKS.Status.Conditions[0].LastTransitionTime = metav1.NewTime(base.Add(-time.Hour))

		standalone := makePVCStallPod("db", "aaa-standalone", "data-pg-0", nil, nil)
		mirror := makePVCStallPod("db", "aab-mirror", "data-pg-0", stsOwner, map[string]string{
			"kubernetes.io/config.mirror": "node-1",
		})
		optedOut := makePVCStallPod("db", "aac-optout", "data-pg-0", stsOwner, map[string]string{
			pvcResizeBounceAnno: "false",
		})
		eligible1 := makePVCStallPod("db", "pg-0", "data-pg-0", stsOwner, nil)
		eligible2 := makePVCStallPod("db", "pg-1", "data-pg-0", stsOwner, nil)
		ksPod := makePVCStallPod("kube-system", "ks-0", "ks-pvc", stsOwner, nil)

		cs := fake.NewSimpleClientset(pvc, pvcKS, standalone, mirror, optedOut, eligible1, eligible2, ksPod)
		var gotUID types.UID
		evicted := capturePVCStallEvictions(cs, func(ev *policyv1.Eviction) (bool, error) {
			if ev.DeleteOptions != nil && ev.DeleteOptions.Preconditions != nil && ev.DeleteOptions.Preconditions.UID != nil {
				gotUID = *ev.DeleteOptions.Preconditions.UID
			}
			return false, nil
		})
		p := testProberDyn(cs, probetest.OpDyn())
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*pvcResizeStallGuardCheck](t, p)

		sctx := probetest.SweepCtx(ctx, chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)
		if res.Pass {
			t.Fatal("stalled PVC must still fail check")
		}
		if len(*evicted) != 1 || (*evicted)[0] != "db/pg-0" {
			t.Fatalf("evicted = %v, want [db/pg-0]", *evicted)
		}
		if gotUID != eligible1.UID {
			t.Fatalf("UID precondition = %q, want %q", gotUID, eligible1.UID)
		}
	})

	t.Run("annotation opt-in on PVC or Pod works when env is false", func(t *testing.T) {
		pvcResizeStalledGauge.Reset()
		t.Setenv("NODE_AUTOMATION_PVC_RESIZE_BOUNCE_ENABLED", "false")

		stsOwner2 := &metav1.OwnerReference{Kind: "StatefulSet", Name: "pg-2", UID: "sts-uid-2", Controller: &ctrlTrue}
		pvcAnno := pvcWithCondition("db", "pvc-anno", corev1.PersistentVolumeClaimFileSystemResizePending, time.Hour)
		pvcAnno.Annotations = map[string]string{pvcResizeBounceAnno: "true"}
		pod1 := makePVCStallPod("db", "app-0", "pvc-anno", stsOwner, nil)

		pvcPlain := pvcWithCondition("db", "pod-anno", corev1.PersistentVolumeClaimFileSystemResizePending, time.Hour)
		pod2 := makePVCStallPod("db", "app-1", "pod-anno", stsOwner2, map[string]string{pvcResizeBounceAnno: "true"})

		cs := fake.NewSimpleClientset(pvcAnno, pod1, pvcPlain, pod2)
		evicted := capturePVCStallEvictions(cs, nil)
		p := testProberDyn(cs, probetest.OpDyn())
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*pvcResizeStallGuardCheck](t, p)

		sctx := probetest.SweepCtx(ctx, chk.Deps)
		_ = chk.Run(sctx)
		probetest.VerifySweep(sctx)
		if len(*evicted) != 2 {
			t.Fatalf("evicted = %v, want 2 pods via PVC and Pod annotations", *evicted)
		}
	})
}

func TestPVCResizeBouncePDBCooldownAndHold(t *testing.T) {
	base := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	ctrlTrue := true
	stsOwner := &metav1.OwnerReference{Kind: "StatefulSet", Name: "pg", UID: "sts-uid-1", Controller: &ctrlTrue}

	t.Run("PDB 429 refunds budget and 30m per-PVC cooldown suppresses repeat bounce", func(t *testing.T) {
		pvcResizeStalledGauge.Reset()
		t.Setenv("NODE_AUTOMATION_PVC_RESIZE_BOUNCE_ENABLED", "true")
		heal.ConfigureBudget(1, time.Hour)
		t.Cleanup(func() { heal.ConfigureBudget(0, 0) })

		pvcA := pvcWithCondition("db", "a-pvc", corev1.PersistentVolumeClaimFileSystemResizePending, time.Hour)
		podA := makePVCStallPod("db", "a-0", "a-pvc", stsOwner, nil)
		pvcB := pvcWithCondition("db", "b-pvc", corev1.PersistentVolumeClaimFileSystemResizePending, time.Hour)
		podB := makePVCStallPod("db", "b-0", "b-pvc", &metav1.OwnerReference{
			Kind: "StatefulSet", Name: "pg-b", UID: "sts-uid-2", Controller: &ctrlTrue,
		}, nil)

		cs := fake.NewSimpleClientset(pvcA, podA, pvcB, podB)
		evicted := capturePVCStallEvictions(cs, func(ev *policyv1.Eviction) (bool, error) {
			if ev.Name == "a-0" {
				return true, apierrors.NewTooManyRequests("pdb blocked", 0)
			}
			return false, nil
		})
		p := testProberDyn(cs, probetest.OpDyn())
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*pvcResizeStallGuardCheck](t, p)

		// Sweep 1: a-0 gets 429 and refunds budget -> b-0 receives the single grant!
		sctx := probetest.SweepCtx(ctx, chk.Deps)
		_ = chk.Run(sctx)
		probetest.VerifySweep(sctx)
		if len(*evicted) != 1 || (*evicted)[0] != "db/b-0" {
			t.Fatalf("evicted = %v, want [db/b-0] (429 did not refund budget)", *evicted)
		}

		// Sweep 2 (+15m, inside 30m cooldown): b-pvc cooled down, no re-evict even with budget reset.
		heal.ConfigureBudget(5, time.Hour)
		probetest.FreezeNow(p.Deps, base.Add(15*time.Minute))
		// Re-create b-0 without 429 on a-0 -> only a-0 should bounce, b-0 cooled down!
		cs2 := fake.NewSimpleClientset(pvcB, podB)
		ev2 := capturePVCStallEvictions(cs2, nil)
		chk.Deps.CS = cs2
		sctx2 := probetest.SweepCtx(ctx, chk.Deps)
		_ = chk.Run(sctx2)
		probetest.VerifySweep(sctx2)
		if len(*ev2) != 0 {
			t.Fatalf("30m per-PVC cooldown did not suppress repeat bounce: %v", *ev2)
		}

		// Sweep 3 (+31m): cooldown expired -> b-0 bounces again.
		probetest.FreezeNow(p.Deps, base.Add(31*time.Minute))
		sctx3 := probetest.SweepCtx(ctx, chk.Deps)
		_ = chk.Run(sctx3)
		probetest.VerifySweep(sctx3)
		if len(*ev2) != 1 || (*ev2)[0] != "db/b-0" {
			t.Fatalf("post-cooldown bounce = %v, want [db/b-0]", *ev2)
		}
	})

	t.Run("maintenance hold skips eviction", func(t *testing.T) {
		pvcResizeStalledGauge.Reset()
		t.Setenv("NODE_AUTOMATION_PVC_RESIZE_BOUNCE_ENABLED", "true")

		pvc := pvcWithCondition("db", "hold-pvc", corev1.PersistentVolumeClaimFileSystemResizePending, time.Hour)
		pod := makePVCStallPod("db", "hold-0", "hold-pvc", stsOwner, nil)
		cs := fake.NewSimpleClientset(
			pvc, pod,
			&appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:   "kube-system",
					Name:        "kured",
					Annotations: map[string]string{"weave.works/kured-node-lock": "upgrade"},
				},
			},
		)
		evicted := capturePVCStallEvictions(cs, nil)
		p := testProberDyn(cs, probetest.OpDyn())
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*pvcResizeStallGuardCheck](t, p)

		sctx := probetest.SweepCtx(ctx, chk.Deps)
		_ = chk.Run(sctx)
		probetest.VerifySweep(sctx)
		if len(*evicted) != 0 {
			t.Fatalf("maintenance hold allowed eviction: %v", *evicted)
		}
	})
}
