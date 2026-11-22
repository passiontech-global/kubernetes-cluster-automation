// dra_claim_wedge_guard_test.go — table-driven unit and probetest
// coverage for dra-claim-wedge-guard (R6-K6).
package nodehealth

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/go-logr/logr"
	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	resourcev1 "k8s.io/api/resource/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

func makeResourceClaim(
	ns, name, uid, rv string,
	createdAt *time.Time,
	deletedAt *time.Time,
	allocated bool,
	pinnedNode string,
	reserved ...resourcev1.ResourceClaimConsumerReference,
) *resourcev1.ResourceClaim {
	rc := &resourcev1.ResourceClaim{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "resource.k8s.io/v1",
			Kind:       "ResourceClaim",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       ns,
			Name:            name,
			UID:             types.UID(uid),
			ResourceVersion: rv,
		},
	}
	if createdAt != nil {
		rc.CreationTimestamp = metav1.NewTime(*createdAt)
	}
	if deletedAt != nil {
		t := metav1.NewTime(*deletedAt)
		rc.DeletionTimestamp = &t
		rc.Finalizers = []string{"resource.kubernetes.io/delete-protection"}
	}
	if allocated {
		alloc := &resourcev1.AllocationResult{}
		if createdAt != nil {
			at := metav1.NewTime(*createdAt)
			alloc.AllocationTimestamp = &at
		}
		if pinnedNode != "" {
			alloc.NodeSelector = &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{{
					MatchExpressions: []corev1.NodeSelectorRequirement{{
						Key:      corev1.LabelHostname,
						Operator: corev1.NodeSelectorOpIn,
						Values:   []string{pinnedNode},
					}},
				}},
			}
		} else {
			alloc.NodeSelector = &corev1.NodeSelector{}
		}
		rc.Status.Allocation = alloc
	}
	rc.Status.ReservedFor = reserved
	return rc
}

func makeDRANode(name string, ready corev1.ConditionStatus, since time.Time) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			CreationTimestamp: metav1.NewTime(since),
		},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{
				Type:               corev1.NodeReady,
				Status:             ready,
				LastTransitionTime: metav1.NewTime(since),
			}},
		},
	}
}

func TestDRAClaimWedgeGuardAutoSkipAnd403AndEmpty(t *testing.T) {
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)

	t.Run("CRD absent 404 and NoMatch auto-skip without listing pods or nodes", func(t *testing.T) {
		cases := []struct {
			name string
			err  error
		}{
			{
				name: "404 NotFound",
				err:  apierrors.NewNotFound(schema.GroupResource{Group: "resource.k8s.io", Resource: "resourceclaims"}, ""),
			},
			{
				name: "NoResourceMatchError",
				err:  &meta.NoResourceMatchError{PartialResource: schema.GroupVersionResource{Group: "resource.k8s.io", Version: "v1", Resource: "resourceclaims"}},
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				draClaimWedgedGauge.Reset()
				cs := fake.NewSimpleClientset()
				cs.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("AllPods must not be called when CRD absent")
				})
				cs.PrependReactor("list", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("AllNodes must not be called when CRD absent")
				})
				dyn := probetest.OpDyn()
				dyn.PrependReactor("list", "resourceclaims", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, tc.err
				})

				p := testProberDyn(cs, dyn)
				chk := probetest.MustCheck[*draClaimWedgeGuardCheck](t, p)
				sctx := probetest.SweepCtx(ctx, chk.Deps)
				res := chk.Run(sctx)
				probetest.VerifySweep(sctx)
				if !res.Pass || res.Infra != nil {
					t.Fatalf("CRD absent Run = %+v, want Pass=true Infra=nil", res)
				}
			})
		}
	})

	t.Run("empty ResourceClaims skips AllPods and AllNodes", func(t *testing.T) {
		draClaimWedgedGauge.Reset()
		cs := fake.NewSimpleClientset()
		cs.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("AllPods must not be called when claims empty")
		})
		cs.PrependReactor("list", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("AllNodes must not be called when claims empty")
		})
		p := testProberDyn(cs, probetest.OpDyn())
		chk := probetest.MustCheck[*draClaimWedgeGuardCheck](t, p)
		sctx := probetest.SweepCtx(ctx, chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)
		if !res.Pass || res.Infra != nil {
			t.Fatalf("empty claims Run = %+v, want Pass=true Infra=nil", res)
		}
	})

	t.Run("403 Forbidden carries held series gracefully without IncError or AllPods", func(t *testing.T) {
		draClaimWedgedGauge.Reset()
		old := now.Add(-30 * time.Minute)
		cs := fake.NewSimpleClientset()
		dyn := probetest.OpDyn(makeResourceClaim("gpu-ns", "gpu-unalloc", "rc-1", "1", &old, nil, false, ""))
		p := testProberDyn(cs, dyn)
		probetest.FreezeNow(p.Deps, now)
		chk := probetest.MustCheck[*draClaimWedgeGuardCheck](t, p)

		sctx1 := probetest.SweepCtx(ctx, chk.Deps)
		if res1 := chk.Run(sctx1); res1.Pass {
			t.Fatal("initial unallocated aged claim must FAIL")
		}
		probetest.VerifySweep(sctx1)

		cs403 := fake.NewSimpleClientset()
		cs403.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("AllPods must not be called on 403")
		})
		dyn403 := probetest.OpDyn()
		dyn403.PrependReactor("list", "resourceclaims", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "resource.k8s.io", Resource: "resourceclaims"}, "", errors.New("forbidden"))
		})
		chk.CS = cs403
		chk.Dyn = dyn403
		before := probetest.CounterSnapshot(t, p.Deps.Name)
		sctx2 := probetest.SweepCtx(ctx, chk.Deps)
		res2 := chk.Run(sctx2)
		probetest.VerifySweep(sctx2)
		probetest.AssertCounterDelta(t, p.Deps.Name, before, 0)
		if !res2.Pass || res2.Infra != nil {
			t.Fatalf("403 Run = %+v, want Pass=true Infra=nil", res2)
		}
		if v, ok := testutil.GaugeSeriesValue(t, "node_automation_dra_claim_wedged",
			map[string]string{"namespace": "gpu-ns", "claim": "gpu-unalloc", "reason": draReasonUnallocatedStuck}); !ok || v != 1 {
			t.Fatalf("expected carried gauge on 403, got v=%v ok=%v", v, ok)
		}
	})
}

func TestDRAClaimWedgeGuardDetectionAndSharedSafety(t *testing.T) {
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	old := now.Add(-30 * time.Minute)
	fresh := now.Add(-5 * time.Minute)

	livePod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "gpu-ns", Name: "live-pod", UID: "live-uid"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	donePod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "gpu-ns", Name: "done-pod", UID: "done-uid"},
		Status:     corev1.PodStatus{Phase: corev1.PodSucceeded},
	}
	mismatchPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "gpu-ns", Name: "recreated-pod", UID: "new-uid"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}

	cases := []struct {
		name       string
		pods       []runtime.Object
		nodes      []runtime.Object
		claims     []runtime.Object
		wantPass   bool
		wantClaim  string
		wantReason string
	}{
		{
			name:     "fresh unallocated claim passes",
			claims:   []runtime.Object{makeResourceClaim("gpu-ns", "fresh-rc", "rc-f", "1", &fresh, nil, false, "")},
			wantPass: true,
		},
		{
			name:       "aged unallocated claim flagged",
			claims:     []runtime.Object{makeResourceClaim("gpu-ns", "old-unalloc", "rc-u", "1", &old, nil, false, "")},
			wantPass:   false,
			wantClaim:  "old-unalloc",
			wantReason: draReasonUnallocatedStuck,
		},
		{
			name: "healthy allocated claim for live pod passes",
			pods: []runtime.Object{livePod},
			claims: []runtime.Object{makeResourceClaim("gpu-ns", "ok-rc", "rc-ok", "1", &old, nil, true, "",
				resourcev1.ResourceClaimConsumerReference{Resource: "pods", Name: "live-pod", UID: "live-uid"})},
			wantPass: true,
		},
		{
			name: "shared reservation with live and dead pod passes unmutated",
			pods: []runtime.Object{livePod},
			claims: []runtime.Object{makeResourceClaim("gpu-ns", "shared-rc", "rc-sh", "1", &old, nil, true, "",
				resourcev1.ResourceClaimConsumerReference{Resource: "pods", Name: "live-pod", UID: "live-uid"},
				resourcev1.ResourceClaimConsumerReference{Resource: "pods", Name: "dead-pod", UID: "dead-uid"})},
			wantPass: true,
		},
		{
			name: "non-Pod consumer in reservedFor fails closed (healthy)",
			claims: []runtime.Object{makeResourceClaim("gpu-ns", "nonpod-rc", "rc-np", "1", &old, nil, true, "",
				resourcev1.ResourceClaimConsumerReference{APIGroup: "batch", Resource: "jobs", Name: "job-1", UID: "job-uid"})},
			wantPass: true,
		},
		{
			name: "zombie reserved with missing pod flagged",
			claims: []runtime.Object{makeResourceClaim("gpu-ns", "z-miss", "rc-zm", "1", &old, nil, true, "",
				resourcev1.ResourceClaimConsumerReference{Resource: "pods", Name: "dead-pod", UID: "dead-uid"})},
			wantPass:   false,
			wantClaim:  "z-miss",
			wantReason: draReasonZombieReserved,
		},
		{
			name: "zombie reserved with terminal Succeeded pod flagged",
			pods: []runtime.Object{donePod},
			claims: []runtime.Object{makeResourceClaim("gpu-ns", "z-done", "rc-zd", "1", &old, nil, true, "",
				resourcev1.ResourceClaimConsumerReference{Resource: "pods", Name: "done-pod", UID: "done-uid"})},
			wantPass:   false,
			wantClaim:  "z-done",
			wantReason: draReasonZombieReserved,
		},
		{
			name: "zombie reserved with UID mismatch flagged",
			pods: []runtime.Object{mismatchPod},
			claims: []runtime.Object{makeResourceClaim("gpu-ns", "z-uid", "rc-zu", "1", &old, nil, true, "",
				resourcev1.ResourceClaimConsumerReference{Resource: "pods", Name: "recreated-pod", UID: "old-uid"})},
			wantPass:   false,
			wantClaim:  "z-uid",
			wantReason: draReasonZombieReserved,
		},
		{
			name:       "terminating stuck claim flagged",
			claims:     []runtime.Object{makeResourceClaim("gpu-ns", "term-rc", "rc-t", "1", &old, &old, true, "")},
			wantPass:   false,
			wantClaim:  "term-rc",
			wantReason: draReasonTerminatingStuck,
		},
		{
			name: "terminating claim without finalizers ignored",
			claims: func() []runtime.Object {
				rc := makeResourceClaim("gpu-ns", "term-nofin", "rc-tnf", "1", &old, &old, true, "")
				rc.Finalizers = nil
				return []runtime.Object{rc}
			}(),
			wantPass: true,
		},
		{
			name:       "dead node allocation missing node flagged",
			nodes:      []runtime.Object{makeDRANode("live-node", corev1.ConditionTrue, old)},
			claims:     []runtime.Object{makeResourceClaim("gpu-ns", "deadnode-miss", "rc-dm", "1", &old, nil, true, "gone-node")},
			wantPass:   false,
			wantClaim:  "deadnode-miss",
			wantReason: draReasonDeadNodeAllocation,
		},
		{
			name:       "dead node allocation NotReady past minAge flagged",
			nodes:      []runtime.Object{makeDRANode("dead-node", corev1.ConditionFalse, old)},
			claims:     []runtime.Object{makeResourceClaim("gpu-ns", "deadnode-nr", "rc-dn", "1", &old, nil, true, "dead-node")},
			wantPass:   false,
			wantClaim:  "deadnode-nr",
			wantReason: draReasonDeadNodeAllocation,
		},
		{
			name:     "allocated claim on live Ready node without reservedFor passes",
			nodes:    []runtime.Object{makeDRANode("live-node", corev1.ConditionTrue, old)},
			claims:   []runtime.Object{makeResourceClaim("gpu-ns", "live-alloc", "rc-la", "1", &old, nil, true, "live-node")},
			wantPass: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			draClaimWedgedGauge.Reset()
			t.Setenv("NODE_AUTOMATION_DRA_CLAIM_REMEDIATE_ENABLED", "false")
			objs := append([]runtime.Object{}, tc.pods...)
			objs = append(objs, tc.nodes...)
			cs := fake.NewSimpleClientset(objs...)
			dyn := probetest.OpDyn(tc.claims...)
			patched := 0
			dyn.PrependReactor("patch", "resourceclaims", func(k8stesting.Action) (bool, runtime.Object, error) {
				patched++
				return false, nil, nil
			})
			p := testProberDyn(cs, dyn)
			probetest.FreezeNow(p.Deps, now)
			chk := probetest.MustCheck[*draClaimWedgeGuardCheck](t, p)

			sctx := probetest.SweepCtx(ctx, chk.Deps)
			res := chk.Run(sctx)
			probetest.VerifySweep(sctx)
			if res.Pass != tc.wantPass || res.Infra != nil {
				t.Fatalf("Run = %+v, want Pass=%v Infra=nil", res, tc.wantPass)
			}
			if patched != 0 {
				t.Fatalf("expected 0 ResourceClaim patches when remediation disabled or shared-live, got %d", patched)
			}
			if !tc.wantPass {
				v, ok := testutil.GaugeSeriesValue(t, "node_automation_dra_claim_wedged",
					map[string]string{"namespace": "gpu-ns", "claim": tc.wantClaim, "reason": tc.wantReason})
				if !ok || v != 1 {
					t.Fatalf("wedged gauge = (%v,%v), want (1,true)", v, ok)
				}
				evs, err := cs.EventsV1().Events("gpu-ns").List(ctx, metav1.ListOptions{})
				if err != nil || len(evs.Items) != 1 || evs.Items[0].Reason != draClaimEventReason {
					t.Fatalf("events = %+v (err=%v), want 1 DRAClaimWedged event", evs.Items, err)
				}
			}
		})
	}

	t.Run("gauge cleanup on recovery", func(t *testing.T) {
		draClaimWedgedGauge.Reset()
		cs := fake.NewSimpleClientset()
		dyn := probetest.OpDyn(makeResourceClaim("gpu-ns", "rec-rc", "rc-rec", "1", &old, nil, false, ""))
		p := testProberDyn(cs, dyn)
		probetest.FreezeNow(p.Deps, now)
		chk := probetest.MustCheck[*draClaimWedgeGuardCheck](t, p)

		sctx1 := probetest.SweepCtx(ctx, chk.Deps)
		if res := chk.Run(sctx1); res.Pass {
			t.Fatal("expected initial FAIL")
		}
		probetest.VerifySweep(sctx1)

		chk.Dyn = probetest.OpDyn(makeResourceClaim("gpu-ns", "rec-rc", "rc-rec", "2", &old, nil, true, "",
			resourcev1.ResourceClaimConsumerReference{Resource: "pods", Name: "live", UID: "live-u"}))
		chk.CS = fake.NewSimpleClientset(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "gpu-ns", Name: "live", UID: "live-u"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		})
		sctx2 := probetest.SweepCtx(ctx, chk.Deps)
		if res := chk.Run(sctx2); !res.Pass {
			t.Fatalf("recovered Run = %+v, want Pass=true", res)
		}
		probetest.VerifySweep(sctx2)
		if _, ok := testutil.GaugeSeriesValue(t, "node_automation_dra_claim_wedged",
			map[string]string{"namespace": "gpu-ns", "claim": "rec-rc", "reason": draReasonUnallocatedStuck}); ok {
			t.Fatal("stale wedged gauge series was not pruned on recovery")
		}
	})
}

func TestDRAClaimWedgeGuardRemediation(t *testing.T) {
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	old := now.Add(-30 * time.Minute)

	t.Run("zombie reserved clears status.reservedFor via /status merge patch and increments heals counter", func(t *testing.T) {
		draClaimWedgedGauge.Reset()
		cs := fake.NewSimpleClientset()
		dyn := probetest.OpDyn(makeResourceClaim("gpu-ns", "z-heal", "rc-zh", "42", &old, nil, true, "",
			resourcev1.ResourceClaimConsumerReference{Resource: "pods", Name: "dead-pod", UID: "dead-uid"}))
		var patchSubresource string
		dyn.PrependReactor("patch", "resourceclaims", func(a k8stesting.Action) (bool, runtime.Object, error) {
			pa := a.(k8stesting.PatchAction)
			patchSubresource = pa.GetSubresource()
			return false, nil, nil
		})
		p := testProberDyn(cs, dyn)
		probetest.FreezeNow(p.Deps, now)
		chk := probetest.MustCheck[*draClaimWedgeGuardCheck](t, p)

		before := ptestutil.ToFloat64(draClaimHealsTotal.WithLabelValues("clear_reserved_for"))
		sctx := probetest.SweepCtx(ctx, chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)
		if res.Pass || res.Infra != nil {
			t.Fatalf("Run = %+v, want Pass=false Infra=nil", res)
		}
		if patchSubresource != "status" {
			t.Fatalf("patch subresource = %q, want \"status\"", patchSubresource)
		}
		after := ptestutil.ToFloat64(draClaimHealsTotal.WithLabelValues("clear_reserved_for"))
		if after-before != 1 {
			t.Fatalf("draClaimHealsTotal delta = %v, want 1", after-before)
		}

		updated, err := dyn.Resource(schema.GroupVersionResource{Group: "resource.k8s.io", Version: "v1", Resource: "resourceclaims"}).
			Namespace("gpu-ns").Get(ctx, "z-heal", metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get updated claim: %v", err)
		}
		statusMap, _ := updated.Object["status"].(map[string]any)
		if rf, ok := statusMap["reservedFor"].([]any); !ok || len(rf) != 0 {
			t.Fatalf("expected empty status.reservedFor after /status patch, got %#v", statusMap["reservedFor"])
		}
	})

	t.Run("live Pods.Get race aborts /status patch fail-closed and refunds grant", func(t *testing.T) {
		draClaimWedgedGauge.Reset()
		heal.ConfigureBudget(1, time.Hour)
		t.Cleanup(func() { heal.ConfigureBudget(0, 0) })

		cs := fake.NewSimpleClientset()
		// List returns empty (stale snapshot), but live Get finds the pod running!
		cs.PrependReactor("get", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "gpu-ns", Name: "race-pod", UID: "race-uid"},
				Status:     corev1.PodStatus{Phase: corev1.PodRunning},
			}, nil
		})
		dyn := probetest.OpDyn(makeResourceClaim("gpu-ns", "z-race", "rc-zr", "7", &old, nil, true, "",
			resourcev1.ResourceClaimConsumerReference{Resource: "pods", Name: "race-pod", UID: "race-uid"}))
		patched := 0
		dyn.PrependReactor("patch", "resourceclaims", func(k8stesting.Action) (bool, runtime.Object, error) {
			patched++
			return false, nil, nil
		})
		p := testProberDyn(cs, dyn)
		probetest.FreezeNow(p.Deps, now)
		chk := probetest.MustCheck[*draClaimWedgeGuardCheck](t, p)

		sctx := probetest.SweepCtx(ctx, chk.Deps)
		_ = chk.Run(sctx)
		probetest.VerifySweep(sctx)
		if patched != 0 {
			t.Fatalf("live Pods.Get race must abort patch, got %d patches", patched)
		}
		if proceed, _ := chk.HealAllowed(sctx, logr.Discard(), nil, "after-race-refund", time.Minute, now); !proceed {
			t.Fatal("aborted Pods.Get race did not refund heal budget grant")
		}
	})

	t.Run("maintenance hold defers /status patch and 404 /status patch causes zero IncError", func(t *testing.T) {
		draClaimWedgedGauge.Reset()
		csHold := fake.NewSimpleClientset(&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:   "kube-system",
				Name:        "kured",
				Annotations: map[string]string{"weave.works/kured-node-lock": "upgrade"},
			},
		})
		dynHold := probetest.OpDyn(makeResourceClaim("gpu-ns", "z-hold", "rc-zhld", "1", &old, nil, true, "",
			resourcev1.ResourceClaimConsumerReference{Resource: "pods", Name: "dead-pod", UID: "dead-uid"}))
		patchedHold := 0
		dynHold.PrependReactor("patch", "resourceclaims", func(k8stesting.Action) (bool, runtime.Object, error) {
			patchedHold++
			return false, nil, nil
		})
		pHold := testProberDyn(csHold, dynHold)
		probetest.FreezeNow(pHold.Deps, now)
		chkHold := probetest.MustCheck[*draClaimWedgeGuardCheck](t, pHold)
		sctxHold := probetest.SweepCtx(ctx, chkHold.Deps)
		_ = chkHold.Run(sctxHold)
		probetest.VerifySweep(sctxHold)
		if patchedHold != 0 {
			t.Fatalf("maintenance hold must defer patch, got %d", patchedHold)
		}

		// 404 on /status subresource refunds grant and keeps IncError at 0.
		heal.ConfigureBudget(1, time.Hour)
		t.Cleanup(func() { heal.ConfigureBudget(0, 0) })
		cs404 := fake.NewSimpleClientset()
		dyn404 := probetest.OpDyn(makeResourceClaim("gpu-ns", "z-404", "rc-z404", "1", &old, nil, true, "",
			resourcev1.ResourceClaimConsumerReference{Resource: "pods", Name: "dead-pod", UID: "dead-uid"}))
		dyn404.PrependReactor("patch", "resourceclaims", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(schema.GroupResource{Group: "resource.k8s.io", Resource: "resourceclaims"}, "z-404")
		})
		p404 := testProberDyn(cs404, dyn404)
		probetest.FreezeNow(p404.Deps, now)
		chk404 := probetest.MustCheck[*draClaimWedgeGuardCheck](t, p404)
		beforeErr := probetest.CounterSnapshot(t, p404.Deps.Name)
		sctx404 := probetest.SweepCtx(ctx, chk404.Deps)
		_ = chk404.Run(sctx404)
		probetest.VerifySweep(sctx404)
		probetest.AssertCounterDelta(t, p404.Deps.Name, beforeErr, 0)
		if proceed, _ := chk404.HealAllowed(sctx404, logr.Discard(), nil, "after-404-refund", time.Minute, now); !proceed {
			t.Fatal("404 on /status patch did not refund heal budget grant")
		}

		// 409 Conflict on /status subresource refunds grant and keeps IncError at 0.
		heal.ConfigureBudget(1, time.Hour)
		cs409 := fake.NewSimpleClientset()
		dyn409 := probetest.OpDyn(makeResourceClaim("gpu-ns", "z-409", "rc-z409", "1", &old, nil, true, "",
			resourcev1.ResourceClaimConsumerReference{Resource: "pods", Name: "dead-pod", UID: "dead-uid"}))
		dyn409.PrependReactor("patch", "resourceclaims", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewConflict(schema.GroupResource{Group: "resource.k8s.io", Resource: "resourceclaims"}, "z-409", errors.New("rv mismatch"))
		})
		p409 := testProberDyn(cs409, dyn409)
		probetest.FreezeNow(p409.Deps, now)
		chk409 := probetest.MustCheck[*draClaimWedgeGuardCheck](t, p409)
		before409 := probetest.CounterSnapshot(t, p409.Deps.Name)
		sctx409 := probetest.SweepCtx(ctx, chk409.Deps)
		_ = chk409.Run(sctx409)
		probetest.VerifySweep(sctx409)
		probetest.AssertCounterDelta(t, p409.Deps.Name, before409, 0)
		if proceed, _ := chk409.HealAllowed(sctx409, logr.Discard(), nil, "after-409-refund", time.Minute, now); !proceed {
			t.Fatal("409 on /status patch did not refund heal budget grant")
		}
	})

	t.Run("terminating stuck claim bounces DRA driver DaemonSet pod on pinned live node", func(t *testing.T) {
		draClaimWedgedGauge.Reset()
		ctrlTrue := true
		driverPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "kube-system",
				Name:      "nvidia-dra-driver-abc",
				UID:       "uid-dra-drv",
				OwnerReferences: []metav1.OwnerReference{{
					Kind:       "DaemonSet",
					Name:       "nvidia-dra-driver",
					UID:        "ds-dra-uid",
					Controller: &ctrlTrue,
				}},
			},
			Spec: corev1.PodSpec{
				NodeName:   "gpu-node-1",
				Containers: []corev1.Container{{Name: "dra-plugin", Image: "nvcr.io/nvidia/k8s-dra-driver:v1"}},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		}
		liveNode := makeDRANode("gpu-node-1", corev1.ConditionTrue, old)
		cs := fake.NewSimpleClientset(liveNode, driverPod)
		var deleted []string
		cs.PrependReactor("delete", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
			da := a.(k8stesting.DeleteAction)
			deleted = append(deleted, da.GetNamespace()+"/"+da.GetName())
			return false, nil, nil
		})
		dyn := probetest.OpDyn(makeResourceClaim("gpu-ns", "term-drv", "rc-tdrv", "1", &old, &old, true, "gpu-node-1"))
		p := testProberDyn(cs, dyn)
		probetest.FreezeNow(p.Deps, now)
		chk := probetest.MustCheck[*draClaimWedgeGuardCheck](t, p)

		before := ptestutil.ToFloat64(metrics.ControlPlanePodHealsTotal.WithLabelValues(CheckNameDRAClaimWedgeGuard))
		sctx := probetest.SweepCtx(ctx, chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)
		if res.Pass {
			t.Fatal("expected terminating claim to FAIL")
		}
		if len(deleted) != 1 || deleted[0] != "kube-system/nvidia-dra-driver-abc" {
			t.Fatalf("deleted = %v, want [kube-system/nvidia-dra-driver-abc]", deleted)
		}
		after := ptestutil.ToFloat64(metrics.ControlPlanePodHealsTotal.WithLabelValues(CheckNameDRAClaimWedgeGuard))
		if after-before != 1 {
			t.Fatalf("ControlPlanePodHealsTotal delta = %v, want 1", after-before)
		}
	})

	t.Run("zero creationTimestamp uses firstSeen fallback", func(t *testing.T) {
		draClaimWedgedGauge.Reset()
		cs := fake.NewSimpleClientset()
		dyn := probetest.OpDyn(makeResourceClaim("gpu-ns", "no-ct", "rc-noct", "1", nil, nil, false, ""))
		p := testProberDyn(cs, dyn)
		chk := probetest.MustCheck[*draClaimWedgeGuardCheck](t, p)

		probetest.FreezeNow(p.Deps, now)
		sctx1 := probetest.SweepCtx(ctx, chk.Deps)
		if res := chk.Run(sctx1); !res.Pass {
			t.Fatalf("T=0 Run = %+v, want Pass", res)
		}
		probetest.VerifySweep(sctx1)

		probetest.FreezeNow(p.Deps, now.Add(16*time.Minute))
		sctx2 := probetest.SweepCtx(ctx, chk.Deps)
		if res := chk.Run(sctx2); res.Pass {
			t.Fatal("T+16m Run must FAIL")
		}
		probetest.VerifySweep(sctx2)
	})

	t.Run("env knobs resolve minAge and remediateEnabled", func(t *testing.T) {
		t.Setenv("NODE_AUTOMATION_DRA_CLAIM_MIN_AGE", "5m")
		t.Setenv("NODE_AUTOMATION_DRA_CLAIM_REMEDIATE_ENABLED", "false")
		chk := NewDRAClaimWedgeGuardCheck(probetest.NewDeps(fake.NewSimpleClientset(), probetest.OpDyn())).(*draClaimWedgeGuardCheck)
		if chk.minAge != 5*time.Minute || chk.remediateEnabled {
			t.Fatalf("env knobs = (%v, %v), want (5m, false)", chk.minAge, chk.remediateEnabled)
		}

		t.Setenv("NODE_AUTOMATION_DRA_CLAIM_MIN_AGE", "0s")
		chk2 := NewDRAClaimWedgeGuardCheck(probetest.NewDeps(fake.NewSimpleClientset(), probetest.OpDyn())).(*draClaimWedgeGuardCheck)
		if chk2.minAge != 15*time.Minute {
			t.Fatalf("fallback minAge = %v, want 15m", chk2.minAge)
		}
	})
}

func makeDaemonSetPod(
	ns, name, dsName, nodeName string,
	labels map[string]string,
	containerName, image string,
) *corev1.Pod {
	ctrlTrue := true
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
			UID:       types.UID("uid-" + ns + "-" + name),
			Labels:    labels,
			OwnerReferences: []metav1.OwnerReference{{
				Kind:       "DaemonSet",
				Name:       dsName,
				UID:        types.UID("ds-uid-" + ns + "-" + dsName),
				Controller: &ctrlTrue,
			}},
		},
		Spec: corev1.PodSpec{
			NodeName:   nodeName,
			Containers: []corev1.Container{{Name: containerName, Image: image}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func TestHasDRATokenAndIsDRADriverDaemonSetPod(t *testing.T) {
	t.Run("hasDRAToken", func(t *testing.T) {
		cases := []struct {
			input string
			want  bool
		}{
			{input: "", want: false},
			{input: "dra", want: true},
			{input: "DRA", want: true},
			{input: "nvidia-dra-driver-abc", want: true},
			{input: "dra-example-driver-xyz", want: true},
			{input: "k8s-dra-driver-kubelet-plugin", want: true},
			{input: "registry.k8s.io/dra-driver:v1", want: true},
			{input: "nvcr.io/nvidia/k8s-dra-driver:v1", want: true},
			{input: "dra_plugin", want: true},
			{input: "gpu.dra.plugin", want: true},
			{input: "cassandra-exporter-xyz", want: false},
			{input: "hydra-agent", want: false},
			{input: "quadra_ds", want: false},
			{input: "ghcr.io/dragonflydb/dragonfly:v1.0", want: false},
			{input: "dragonfly-operator", want: false},
			{input: "drainer-daemon", want: false},
			{input: "dra2-agent", want: false},
		}
		for _, tc := range cases {
			t.Run(tc.input, func(t *testing.T) {
				if got := hasDRAToken(tc.input); got != tc.want {
					t.Fatalf("hasDRAToken(%q) = %v, want %v", tc.input, got, tc.want)
				}
			})
		}
	})

	t.Run("isDRADriverDaemonSetPod", func(t *testing.T) {
		now := metav1.Now()
		ctrlTrue := true

		cases := []struct {
			name string
			pod  *corev1.Pod
			want bool
		}{
			{
				name: "genuine DRA driver by pod and DS name",
				pod:  makeDaemonSetPod("kube-system", "nvidia-dra-driver-abc", "nvidia-dra-driver", "gpu-node-1", nil, "plugin", "nvcr.io/nvidia/gpu-driver:v1"),
				want: true,
			},
			{
				name: "genuine DRA driver by label",
				pod:  makeDaemonSetPod("dra-system", "gpu-plugin-abc", "gpu-plugin", "gpu-node-1", map[string]string{"app.kubernetes.io/part-of": "k8s-dra-driver"}, "plugin", "example.com/gpu:v1"),
				want: true,
			},
			{
				name: "genuine DRA driver by container image",
				pod:  makeDaemonSetPod("kube-system", "gpu-helper-abc", "gpu-helper", "gpu-node-1", nil, "helper", "registry.k8s.io/dra-driver:v1"),
				want: true,
			},
			{
				name: "unrelated cassandra-exporter DaemonSet pod",
				pod:  makeDaemonSetPod("monitoring", "cassandra-exporter-xyz", "cassandra-exporter", "gpu-node-1", map[string]string{"app": "cassandra-exporter"}, "exporter", "prom/cassandra-exporter:v1.0"),
				want: false,
			},
			{
				name: "unrelated dragonfly DaemonSet pod with /dra prefix in image",
				pod:  makeDaemonSetPod("dragonfly-operator-system", "df-agent-xyz", "df-agent", "gpu-node-1", map[string]string{"app.kubernetes.io/name": "dragonfly"}, "dragonfly-agent", "ghcr.io/dragonflydb/dragonfly:v1.0"),
				want: false,
			},
			{
				name: "unrelated hydra-agent DaemonSet pod",
				pod:  makeDaemonSetPod("kube-system", "hydra-agent-xyz", "hydra-agent", "gpu-node-1", map[string]string{"app": "hydra-agent"}, "hydra", "quay.io/hydra/hydra-agent:v1"),
				want: false,
			},
			{
				name: "unrelated quadra_ds DaemonSet pod",
				pod:  makeDaemonSetPod("kube-system", "quadra-pod-xyz", "quadra_ds", "gpu-node-1", nil, "quadra_worker", "example.com/quadra:v1"),
				want: false,
			},
			{
				name: "non-DaemonSet pod with dra name is ignored",
				pod: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "kube-system",
						Name:      "nvidia-dra-driver-abc",
						OwnerReferences: []metav1.OwnerReference{{
							Kind:       "ReplicaSet",
							Name:       "nvidia-dra-driver-rs",
							Controller: &ctrlTrue,
						}},
					},
					Spec:   corev1.PodSpec{NodeName: "gpu-node-1", Containers: []corev1.Container{{Name: "dra", Image: "registry.k8s.io/dra-driver:v1"}}},
					Status: corev1.PodStatus{Phase: corev1.PodRunning},
				},
				want: false,
			},
			{
				name: "terminating DRA DaemonSet pod is ignored",
				pod: func() *corev1.Pod {
					p := makeDaemonSetPod("kube-system", "nvidia-dra-driver-term", "nvidia-dra-driver", "gpu-node-1", nil, "dra", "registry.k8s.io/dra-driver:v1")
					p.DeletionTimestamp = &now
					return p
				}(),
				want: false,
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if got := isDRADriverDaemonSetPod(tc.pod); got != tc.want {
					t.Fatalf("isDRADriverDaemonSetPod(%s/%s) = %v, want %v", tc.pod.Namespace, tc.pod.Name, got, tc.want)
				}
			})
		}
	})
}

func TestDRAClaimWedgeGuardDoesNotDeleteUnrelatedDaemonSetPods(t *testing.T) {
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	old := now.Add(-30 * time.Minute)

	cassandraPod := makeDaemonSetPod(
		"monitoring", "cassandra-exporter-xyz", "cassandra-exporter", "gpu-node-1",
		map[string]string{"app": "cassandra-exporter"}, "exporter", "prom/cassandra-exporter:v1",
	)
	dragonflyPod := makeDaemonSetPod(
		"dragonfly-operator-system", "df-agent-xyz", "df-agent", "gpu-node-1",
		map[string]string{"app.kubernetes.io/name": "dragonfly"}, "agent", "ghcr.io/dragonflydb/dragonfly:v1.0",
	)
	hydraPod := makeDaemonSetPod(
		"kube-system", "hydra-agent-xyz", "hydra-agent", "gpu-node-1",
		map[string]string{"app": "hydra-agent"}, "hydra", "quay.io/hydra/agent:v1",
	)
	draDriverPod := makeDaemonSetPod(
		"kube-system", "nvidia-dra-driver-abc", "nvidia-dra-driver", "gpu-node-1",
		map[string]string{"app.kubernetes.io/name": "nvidia-dra-driver"}, "dra-plugin", "nvcr.io/nvidia/k8s-dra-driver:v1",
	)

	t.Run("deletes only genuine DRA driver DaemonSet pod alongside unrelated DaemonSet pods", func(t *testing.T) {
		draClaimWedgedGauge.Reset()
		liveNode := makeDRANode("gpu-node-1", corev1.ConditionTrue, old)
		cs := fake.NewSimpleClientset(liveNode, cassandraPod, dragonflyPod, hydraPod, draDriverPod)
		var deleted []string
		cs.PrependReactor("delete", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
			da := a.(k8stesting.DeleteAction)
			deleted = append(deleted, da.GetNamespace()+"/"+da.GetName())
			return false, nil, nil
		})
		dyn := probetest.OpDyn(makeResourceClaim("gpu-ns", "term-drv", "rc-tdrv", "1", &old, &old, true, "gpu-node-1"))
		p := testProberDyn(cs, dyn)
		probetest.FreezeNow(p.Deps, now)
		chk := probetest.MustCheck[*draClaimWedgeGuardCheck](t, p)

		sctx := probetest.SweepCtx(ctx, chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)
		if res.Pass || res.Infra != nil {
			t.Fatalf("Run = %+v, want Pass=false Infra=nil", res)
		}
		want := []string{"kube-system/nvidia-dra-driver-abc"}
		if !slices.Equal(deleted, want) {
			t.Fatalf("deleted pods = %v, want %v", deleted, want)
		}
	})

	t.Run("deletes zero pods when only unrelated DaemonSet pods exist on pinned node", func(t *testing.T) {
		draClaimWedgedGauge.Reset()
		liveNode := makeDRANode("gpu-node-1", corev1.ConditionTrue, old)
		cs := fake.NewSimpleClientset(liveNode, cassandraPod, dragonflyPod, hydraPod)
		var deleted []string
		cs.PrependReactor("delete", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
			da := a.(k8stesting.DeleteAction)
			deleted = append(deleted, da.GetNamespace()+"/"+da.GetName())
			return false, nil, nil
		})
		dyn := probetest.OpDyn(makeResourceClaim("gpu-ns", "term-no-drv", "rc-tndrv", "1", &old, &old, true, "gpu-node-1"))
		p := testProberDyn(cs, dyn)
		probetest.FreezeNow(p.Deps, now)
		chk := probetest.MustCheck[*draClaimWedgeGuardCheck](t, p)

		sctx := probetest.SweepCtx(ctx, chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)
		if res.Pass || res.Infra != nil {
			t.Fatalf("Run = %+v, want Pass=false Infra=nil", res)
		}
		if len(deleted) != 0 {
			t.Fatalf("unrelated DaemonSet pods deleted: %v, want none", deleted)
		}
	})
}
