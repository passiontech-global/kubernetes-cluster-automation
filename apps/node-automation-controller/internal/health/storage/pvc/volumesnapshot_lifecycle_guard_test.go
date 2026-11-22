// volumesnapshot_lifecycle_guard_test.go — table-driven unit and probetest
// coverage for volumesnapshot-lifecycle-guard (R6-K2).
package pvc

import (
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func makeVSObj(ns, name string, createdAt *time.Time, deletedAt *time.Time, finalizers []any, ready bool, statusErr any) *unstructured.Unstructured {
	metaMap := map[string]any{
		"namespace": ns,
		"name":      name,
		"uid":       string("uid-" + ns + "-" + name),
	}
	if createdAt != nil {
		metaMap["creationTimestamp"] = createdAt.UTC().Format(time.RFC3339)
	}
	if deletedAt != nil {
		metaMap["deletionTimestamp"] = deletedAt.UTC().Format(time.RFC3339)
	}
	if len(finalizers) > 0 {
		metaMap["finalizers"] = finalizers
	}
	status := map[string]any{"readyToUse": ready}
	if statusErr != nil {
		status["error"] = statusErr
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "snapshot.storage.k8s.io/v1",
		"kind":       "VolumeSnapshot",
		"metadata":   metaMap,
		"status":     status,
	}}
}

func makeVSCObj(name string, createdAt *time.Time, deletedAt *time.Time, finalizers []any, ready bool, statusErr any) *unstructured.Unstructured {
	metaMap := map[string]any{
		"name": name,
		"uid":  string("uid-vsc-" + name),
	}
	if createdAt != nil {
		metaMap["creationTimestamp"] = createdAt.UTC().Format(time.RFC3339)
	}
	if deletedAt != nil {
		metaMap["deletionTimestamp"] = deletedAt.UTC().Format(time.RFC3339)
	}
	if len(finalizers) > 0 {
		metaMap["finalizers"] = finalizers
	}
	status := map[string]any{"readyToUse": ready}
	if statusErr != nil {
		status["error"] = statusErr
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "snapshot.storage.k8s.io/v1",
		"kind":       "VolumeSnapshotContent",
		"metadata":   metaMap,
		"status":     status,
	}}
}

func makeSnapCtrlPod(ns, name, uid string, ready bool, age time.Duration, now time.Time, labels map[string]string, image string) *corev1.Pod {
	readyStatus := corev1.ConditionFalse
	if ready {
		readyStatus = corev1.ConditionTrue
	}
	ctrlTrue := true
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			UID:               types.UID(uid),
			Labels:            labels,
			CreationTimestamp: metav1.NewTime(now.Add(-age)),
			OwnerReferences: []metav1.OwnerReference{{
				Kind:       "ReplicaSet",
				Name:       "snap-ctrl-rs",
				UID:        "rs-uid",
				Controller: &ctrlTrue,
			}},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "ctrl", Image: image}},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{{
				Type:   corev1.PodReady,
				Status: readyStatus,
			}},
		},
	}
}

func TestVolumeSnapshotLifecycleRequireDyn(t *testing.T) {
	volumeSnapshotStuckGauge.Reset()
	cs := fake.NewSimpleClientset()
	p := testProberDyn(cs, probetest.OpDyn())
	chk := probetest.MustCheck[*volumeSnapshotLifecycleGuardCheck](t, p)
	chk.Dyn = nil

	sctx := probetest.SweepCtx(ctx, chk.Deps)
	res := chk.Run(sctx)
	probetest.VerifySweep(sctx)
	if res.Pass || res.Infra == nil {
		t.Fatalf("RequireDyn with Dyn=nil = %+v, want Pass=false Infra!=nil", res)
	}
}

func TestVolumeSnapshotLifecycleCRDAbsentAutoSkip(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{
			name: "404 NotFound",
			err:  apierrors.NewNotFound(schema.GroupResource{Group: "snapshot.storage.k8s.io", Resource: "volumesnapshots"}, ""),
		},
		{
			name: "NoResourceMatchError",
			err:  &meta.NoResourceMatchError{PartialResource: schema.GroupVersionResource{Group: "snapshot.storage.k8s.io", Version: "v1", Resource: "volumesnapshots"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			volumeSnapshotStuckGauge.Reset()
			cs := fake.NewSimpleClientset()
			cs.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("AllPods must not be called when snapshot CRDs are absent")
			})
			dyn := probetest.OpDyn()
			dyn.PrependReactor("list", "volumesnapshots", func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, tc.err
			})
			dyn.PrependReactor("list", "volumesnapshotcontents", func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, tc.err
			})

			p := testProberDyn(cs, dyn)
			chk := probetest.MustCheck[*volumeSnapshotLifecycleGuardCheck](t, p)
			sctx := probetest.SweepCtx(ctx, chk.Deps)
			res := chk.Run(sctx)
			probetest.VerifySweep(sctx)
			if !res.Pass || res.Infra != nil {
				t.Fatalf("CRD absent Run = %+v, want Pass=true Infra=nil", res)
			}
		})
	}
}

func TestVolumeSnapshotLifecycle403ForbiddenGraceful(t *testing.T) {
	volumeSnapshotStuckGauge.Reset()
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	old := now.Add(-30 * time.Minute)

	cs := fake.NewSimpleClientset()
	dyn := probetest.OpDyn(makeVSObj("apps", "snap-stuck", &old, nil, nil, false, nil))
	p := testProberDyn(cs, dyn)
	probetest.FreezeNow(p.Deps, now)
	chk := probetest.MustCheck[*volumeSnapshotLifecycleGuardCheck](t, p)

	sctx1 := probetest.SweepCtx(ctx, chk.Deps)
	res1 := chk.Run(sctx1)
	probetest.VerifySweep(sctx1)
	if res1.Pass {
		t.Fatal("expected initial stuck snapshot to FAIL")
	}

	// Next sweep gets 403 Forbidden -> must pass with Infra=nil and carry held tuple.
	dyn403 := probetest.OpDyn()
	dyn403.PrependReactor("list", "volumesnapshots", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "snapshot.storage.k8s.io", Resource: "volumesnapshots"}, "", errors.New("forbidden"))
	})
	chk.Dyn = dyn403
	before := probetest.CounterSnapshot(t, p.Deps.Name)
	sctx2 := probetest.SweepCtx(ctx, chk.Deps)
	res2 := chk.Run(sctx2)
	probetest.VerifySweep(sctx2)
	probetest.AssertCounterDelta(t, p.Deps.Name, before, 0)
	if !res2.Pass || res2.Infra != nil {
		t.Fatalf("403 Run = %+v, want Pass=true Infra=nil", res2)
	}
	if v, ok := testutil.GaugeSeriesValue(t, "node_automation_volumesnapshot_stuck",
		map[string]string{"kind": "VolumeSnapshot", "namespace": "apps", "name": "snap-stuck", "reason": vsReasonNotReady}); !ok || v != 1 {
		t.Fatalf("expected carried gauge series on 403, got v=%v ok=%v", v, ok)
	}
}

func TestVolumeSnapshotLifecycleDetectionAndRecovery(t *testing.T) {
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	old := now.Add(-30 * time.Minute)
	fresh := now.Add(-5 * time.Minute)

	cases := []struct {
		name       string
		objs       []runtime.Object
		wantPass   bool
		wantKind   string
		wantNS     string
		wantObj    string
		wantReason string
	}{
		{
			name:     "healthy ready VolumeSnapshot and VolumeSnapshotContent",
			objs:     []runtime.Object{makeVSObj("apps", "ok-vs", &old, nil, nil, true, nil), makeVSCObj("ok-vsc", &old, nil, nil, true, nil)},
			wantPass: true,
		},
		{
			name:     "fresh VolumeSnapshot under 15m passes",
			objs:     []runtime.Object{makeVSObj("apps", "fresh-vs", &fresh, nil, nil, false, nil)},
			wantPass: true,
		},
		{
			name:     "terminating VolumeSnapshot without finalizers ignored",
			objs:     []runtime.Object{makeVSObj("apps", "no-fin", &old, &old, nil, false, nil)},
			wantPass: true,
		},
		{
			name:       "non-terminating VolumeSnapshot not_ready",
			objs:       []runtime.Object{makeVSObj("apps", "stuck-vs", &old, nil, nil, false, nil)},
			wantPass:   false,
			wantKind:   "VolumeSnapshot",
			wantNS:     "apps",
			wantObj:    "stuck-vs",
			wantReason: vsReasonNotReady,
		},
		{
			name:       "non-terminating VolumeSnapshot status_error map",
			objs:       []runtime.Object{makeVSObj("apps", "err-vs", &old, nil, nil, false, map[string]any{"message": "csi timeout"})},
			wantPass:   false,
			wantKind:   "VolumeSnapshot",
			wantNS:     "apps",
			wantObj:    "err-vs",
			wantReason: vsReasonStatusError,
		},
		{
			name:       "non-terminating VolumeSnapshotContent not_ready",
			objs:       []runtime.Object{makeVSCObj("stuck-vsc", &old, nil, nil, false, nil)},
			wantPass:   false,
			wantKind:   "VolumeSnapshotContent",
			wantNS:     "",
			wantObj:    "stuck-vsc",
			wantReason: vsReasonNotReady,
		},
		{
			name:       "terminating VolumeSnapshot overdue with finalizer",
			objs:       []runtime.Object{makeVSObj("apps", "term-vs", &old, &old, []any{"snapshot.storage.kubernetes.io/volumesnapshot-as-source-protection"}, false, nil)},
			wantPass:   false,
			wantKind:   "VolumeSnapshot",
			wantNS:     "apps",
			wantObj:    "term-vs",
			wantReason: vsReasonTerminatingStuck,
		},
		{
			name:       "terminating VolumeSnapshotContent overdue with finalizer",
			objs:       []runtime.Object{makeVSCObj("term-vsc", &old, &old, []any{"snapshot.storage.kubernetes.io/volumesnapshotcontent-bound-protection"}, false, nil)},
			wantPass:   false,
			wantKind:   "VolumeSnapshotContent",
			wantNS:     "",
			wantObj:    "term-vsc",
			wantReason: vsReasonTerminatingStuck,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			volumeSnapshotStuckGauge.Reset()
			cs := fake.NewSimpleClientset()
			if tc.wantPass {
				cs.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("AllPods must not be called when no stuck snapshots exist")
				})
			}
			dyn := probetest.OpDyn(tc.objs...)
			p := testProberDyn(cs, dyn)
			probetest.FreezeNow(p.Deps, now)
			chk := probetest.MustCheck[*volumeSnapshotLifecycleGuardCheck](t, p)

			sctx := probetest.SweepCtx(ctx, chk.Deps)
			res := chk.Run(sctx)
			probetest.VerifySweep(sctx)
			if res.Pass != tc.wantPass || res.Infra != nil {
				t.Fatalf("Run = %+v, want Pass=%v Infra=nil", res, tc.wantPass)
			}
			if !tc.wantPass {
				v, ok := testutil.GaugeSeriesValue(t, "node_automation_volumesnapshot_stuck",
					map[string]string{"kind": tc.wantKind, "namespace": tc.wantNS, "name": tc.wantObj, "reason": tc.wantReason})
				if !ok || v != 1 {
					t.Fatalf("stuck gauge = (%v,%v), want (1,true)", v, ok)
				}
			}
		})
	}

	t.Run("recovery prunes gauge and zero creationTimestamp uses firstSeen fallback", func(t *testing.T) {
		volumeSnapshotStuckGauge.Reset()
		cs := fake.NewSimpleClientset()
		dyn := probetest.OpDyn(makeVSObj("apps", "no-ct", nil, nil, nil, false, nil))
		p := testProberDyn(cs, dyn)
		chk := probetest.MustCheck[*volumeSnapshotLifecycleGuardCheck](t, p)

		// T=0: stamps firstSeen, passes.
		probetest.FreezeNow(p.Deps, now)
		sctx1 := probetest.SweepCtx(ctx, chk.Deps)
		if res := chk.Run(sctx1); !res.Pass {
			t.Fatalf("T=0 Run = %+v, want Pass", res)
		}
		probetest.VerifySweep(sctx1)

		// T+16m: firstSeen threshold crossed -> FAIL.
		probetest.FreezeNow(p.Deps, now.Add(16*time.Minute))
		sctx2 := probetest.SweepCtx(ctx, chk.Deps)
		if res := chk.Run(sctx2); res.Pass {
			t.Fatal("T+16m Run must FAIL")
		}
		probetest.VerifySweep(sctx2)

		// Snapshot becomes ready -> PASS and gauge pruned.
		chk.Dyn = probetest.OpDyn(makeVSObj("apps", "no-ct", nil, nil, nil, true, nil))
		sctx3 := probetest.SweepCtx(ctx, chk.Deps)
		if res := chk.Run(sctx3); !res.Pass {
			t.Fatalf("recovered Run = %+v, want Pass", res)
		}
		probetest.VerifySweep(sctx3)
		if _, ok := testutil.GaugeSeriesValue(t, "node_automation_volumesnapshot_stuck",
			map[string]string{"kind": "VolumeSnapshot", "namespace": "apps", "name": "no-ct", "reason": vsReasonNotReady}); ok {
			t.Fatal("recovered VolumeSnapshot gauge series was not pruned")
		}
	})
}

func TestVolumeSnapshotLifecycleControllerBounceAndEventDedup(t *testing.T) {
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	old := now.Add(-30 * time.Minute)

	captureEvictions := func(cs *fake.Clientset, react func(ev *policyv1.Eviction) (bool, error)) *[]string {
		var evicted []string
		cs.PrependReactor("create", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
			if action.GetSubresource() != "eviction" {
				return false, nil, nil
			}
			ev := action.(k8stesting.CreateAction).GetObject().(*policyv1.Eviction)
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

	t.Run("evicts snapshot-controller, excludes webhook, honors cooldown, dedups events", func(t *testing.T) {
		volumeSnapshotStuckGauge.Reset()
		webhookPod := makeSnapCtrlPod("kube-system", "snapshot-validation-webhook-abc", "uid-wh", false, time.Hour, now,
			map[string]string{"app.kubernetes.io/name": "snapshot-controller"}, "registry.k8s.io/sig-storage/snapshot-validation-webhook:v8.0.0")
		ctrlPod := makeSnapCtrlPod("kube-system", "snapshot-controller-0", "uid-ctrl", true, time.Hour, now,
			map[string]string{"app.kubernetes.io/name": "snapshot-controller"}, "registry.k8s.io/sig-storage/snapshot-controller:v8.0.0")

		cs := fake.NewSimpleClientset(webhookPod, ctrlPod)
		evicted := captureEvictions(cs, nil)
		dyn := probetest.OpDyn(makeVSObj("apps", "snap-stuck", &old, nil, nil, false, nil))
		p := testProberDyn(cs, dyn)
		probetest.FreezeNow(p.Deps, now)
		chk := probetest.MustCheck[*volumeSnapshotLifecycleGuardCheck](t, p)

		before := ptestutil.ToFloat64(metrics.ControlPlanePodHealsTotal.WithLabelValues(CheckNameVolumeSnapshotLifecycleGuard))
		sctx1 := probetest.SweepCtx(ctx, chk.Deps)
		res1 := chk.Run(sctx1)
		probetest.VerifySweep(sctx1)
		if res1.Pass {
			t.Fatal("expected FAIL")
		}
		if len(*evicted) != 1 || (*evicted)[0] != "kube-system/snapshot-controller-0" {
			t.Fatalf("evicted = %v, want [kube-system/snapshot-controller-0] (webhook must be excluded)", *evicted)
		}
		after := ptestutil.ToFloat64(metrics.ControlPlanePodHealsTotal.WithLabelValues(CheckNameVolumeSnapshotLifecycleGuard))
		if after-before != 1 {
			t.Fatalf("ControlPlanePodHealsTotal delta = %v, want 1", after-before)
		}

		evs1, err := cs.EventsV1().Events("apps").List(ctx, metav1.ListOptions{})
		if err != nil || len(evs1.Items) != 1 || evs1.Items[0].Reason != volumeSnapshotEventReason {
			t.Fatalf("events = %+v (err=%v), want 1 VolumeSnapshotStuck event", evs1.Items, err)
		}

		// Immediate repeat at +5m: cooldown blocks both controller bounce and duplicate event.
		probetest.FreezeNow(p.Deps, now.Add(5*time.Minute))
		sctx2 := probetest.SweepCtx(ctx, chk.Deps)
		_ = chk.Run(sctx2)
		probetest.VerifySweep(sctx2)
		if len(*evicted) != 1 {
			t.Fatalf("expected cooldown to block second eviction, got %v", *evicted)
		}
		evs2, _ := cs.EventsV1().Events("apps").List(ctx, metav1.ListOptions{})
		if len(evs2.Items) != 1 {
			t.Fatalf("expected cooldown to dedup Warning Event, got %d", len(evs2.Items))
		}
	})

	t.Run("maintenance hold skips bounce and PDB 429 refunds grant", func(t *testing.T) {
		volumeSnapshotStuckGauge.Reset()
		ctrlPod := makeSnapCtrlPod("kube-system", "csi-snapshot-controller-0", "uid-ctrl-hold", true, time.Hour, now,
			map[string]string{"app": "csi-snapshot-controller"}, "snapshot-controller:v8.0.0")
		csHold := fake.NewSimpleClientset(
			&appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:   "kube-system",
					Name:        "kured",
					Annotations: map[string]string{"weave.works/kured-node-lock": "upgrade"},
				},
			},
			ctrlPod,
		)
		evHold := captureEvictions(csHold, nil)
		pHold := testProberDyn(csHold, probetest.OpDyn(makeVSObj("apps", "snap-hold", &old, nil, nil, false, nil)))
		probetest.FreezeNow(pHold.Deps, now)
		chkHold := probetest.MustCheck[*volumeSnapshotLifecycleGuardCheck](t, pHold)
		sctxHold := probetest.SweepCtx(ctx, chkHold.Deps)
		_ = chkHold.Run(sctxHold)
		probetest.VerifySweep(sctxHold)
		if len(*evHold) != 0 {
			t.Fatalf("maintenance hold must skip bounce, got %v", *evHold)
		}

		// PDB 429 refunds grant.
		heal.ConfigureBudget(1, time.Hour)
		t.Cleanup(func() { heal.ConfigureBudget(0, 0) })
		cs429 := fake.NewSimpleClientset(ctrlPod)
		_ = captureEvictions(cs429, func(*policyv1.Eviction) (bool, error) {
			return true, apierrors.NewTooManyRequests("pdb blocked", 0)
		})
		p429 := testProberDyn(cs429, probetest.OpDyn(makeVSObj("apps", "snap-429", &old, nil, nil, false, nil)))
		probetest.FreezeNow(p429.Deps, now)
		chk429 := probetest.MustCheck[*volumeSnapshotLifecycleGuardCheck](t, p429)
		beforeHeals := ptestutil.ToFloat64(metrics.ControlPlanePodHealsTotal.WithLabelValues(CheckNameVolumeSnapshotLifecycleGuard))
		sctx429 := probetest.SweepCtx(ctx, chk429.Deps)
		_ = chk429.Run(sctx429)
		probetest.VerifySweep(sctx429)
		afterHeals := ptestutil.ToFloat64(metrics.ControlPlanePodHealsTotal.WithLabelValues(CheckNameVolumeSnapshotLifecycleGuard))
		if afterHeals-beforeHeals != 0 {
			t.Fatalf("ControlPlanePodHealsTotal delta = %v, want 0", afterHeals-beforeHeals)
		}

		if proceed, _ := chk429.HealAllowed(sctx429, logr.Discard(), nil, "after-429-refund", time.Minute, now); !proceed {
			t.Fatal("PDB 429 did not refund heal budget grant")
		}
	})

	t.Run("env knobs resolve minAge and healEnabled", func(t *testing.T) {
		t.Setenv("NODE_AUTOMATION_VOLUMESNAPSHOT_MIN_AGE", "5m")
		t.Setenv("NODE_AUTOMATION_VOLUMESNAPSHOT_HEAL_ENABLED", "false")
		chk := NewVolumeSnapshotLifecycleGuardCheck(probetest.NewDeps(fake.NewSimpleClientset(), probetest.OpDyn())).(*volumeSnapshotLifecycleGuardCheck)
		if chk.minAge != 5*time.Minute || chk.healEnabled {
			t.Fatalf("env knobs = (%v, %v), want (5m, false)", chk.minAge, chk.healEnabled)
		}

		// Invalid/non-positive minAge falls back to 15m.
		t.Setenv("NODE_AUTOMATION_VOLUMESNAPSHOT_MIN_AGE", "-10s")
		chk2 := NewVolumeSnapshotLifecycleGuardCheck(probetest.NewDeps(fake.NewSimpleClientset(), probetest.OpDyn())).(*volumeSnapshotLifecycleGuardCheck)
		if chk2.minAge != 15*time.Minute {
			t.Fatalf("fallback minAge = %v, want 15m", chk2.minAge)
		}
	})
}
