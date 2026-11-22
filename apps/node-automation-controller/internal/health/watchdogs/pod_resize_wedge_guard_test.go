package watchdogs

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/go-logr/logr"
	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
)

func makeResizePod(ns, name, uid string, phase corev1.PodPhase, ready bool, owner *metav1.OwnerReference, conds ...corev1.PodCondition) *corev1.Pod {
	readyStatus := corev1.ConditionFalse
	if ready {
		readyStatus = corev1.ConditionTrue
	}
	condList := append([]corev1.PodCondition{{Type: corev1.PodReady, Status: readyStatus}}, conds...)
	var owners []metav1.OwnerReference
	if owner != nil {
		owners = []metav1.OwnerReference{*owner}
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       ns,
			Name:            name,
			UID:             types.UID(uid),
			OwnerReferences: owners,
		},
		Status: corev1.PodStatus{
			Phase:      phase,
			Conditions: condList,
		},
	}
}

func TestPodResizeWedgeGuardDetectionAndMetrics(t *testing.T) {
	base := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)

	t.Run("auto-skip and ignore cases", func(t *testing.T) {
		podResizeWedgedGauge.Reset()
		delAt := metav1.NewTime(base.Add(-5 * time.Minute))
		cases := []struct {
			name string
			pods []runtime.Object
		}{
			{name: "no pods"},
			{
				name: "healthy pod without resize condition",
				pods: []runtime.Object{makeResizePod("apps", "ok", "u1", corev1.PodRunning, true, nil)},
			},
			{
				name: "resize condition Status=False ignored",
				pods: []runtime.Object{makeResizePod("apps", "false-cond", "u2", corev1.PodRunning, true, nil, corev1.PodCondition{
					Type:               corev1.PodResizePending,
					Status:             corev1.ConditionFalse,
					Reason:             corev1.PodReasonDeferred,
					LastTransitionTime: metav1.NewTime(base.Add(-20 * time.Minute)),
				})},
			},
			{
				name: "terminating pod ignored",
				pods: []runtime.Object{func() *corev1.Pod {
					p := makeResizePod("apps", "term", "u3", corev1.PodRunning, true, nil, corev1.PodCondition{
						Type:               corev1.PodResizePending,
						Status:             corev1.ConditionTrue,
						Reason:             corev1.PodReasonDeferred,
						LastTransitionTime: metav1.NewTime(base.Add(-20 * time.Minute)),
					})
					p.DeletionTimestamp = &delAt
					return p
				}()},
			},
			{
				name: "terminal Succeeded and Failed pods ignored",
				pods: []runtime.Object{
					makeResizePod("apps", "done", "u4", corev1.PodSucceeded, false, nil, corev1.PodCondition{
						Type:               corev1.PodResizeInProgress,
						Status:             corev1.ConditionTrue,
						Reason:             corev1.PodReasonError,
						LastTransitionTime: metav1.NewTime(base.Add(-20 * time.Minute)),
					}),
					makeResizePod("apps", "fail", "u5", corev1.PodFailed, false, nil, corev1.PodCondition{
						Type:               corev1.PodResizePending,
						Status:             corev1.ConditionTrue,
						Reason:             corev1.PodReasonInfeasible,
						LastTransitionTime: metav1.NewTime(base.Add(-20 * time.Minute)),
					}),
				},
			},
			{
				name: "younger than minAge ignored",
				pods: []runtime.Object{makeResizePod("apps", "young", "u6", corev1.PodRunning, true, nil, corev1.PodCondition{
					Type:               corev1.PodResizePending,
					Status:             corev1.ConditionTrue,
					Reason:             corev1.PodReasonDeferred,
					LastTransitionTime: metav1.NewTime(base.Add(-10 * time.Minute)),
				})},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				podResizeWedgedGauge.Reset()
				cs := fake.NewSimpleClientset(tc.pods...)
				p := testProber(cs)
				probetest.FreezeNow(p.Deps, base)
				chk := probetest.MustCheck[*podResizeWedgeGuardCheck](t, p)

				sctx := probetest.SweepCtx(ctx, chk.Deps)
				res := chk.Run(sctx)
				probetest.VerifySweep(sctx)
				if !res.Pass || res.Infra != nil {
					t.Fatalf("Run = %+v, want Pass=true", res)
				}
			})
		}
	})

	t.Run("all reason classifications, dual condition pod, and gauge pruning", func(t *testing.T) {
		podResizeWedgedGauge.Reset()
		oldTime := metav1.NewTime(base.Add(-20 * time.Minute))
		pods := []runtime.Object{
			makeResizePod("apps", "p-def", "u1", corev1.PodRunning, true, nil, corev1.PodCondition{
				Type: corev1.PodResizePending, Status: corev1.ConditionTrue, Reason: corev1.PodReasonDeferred, LastTransitionTime: oldTime,
			}),
			makeResizePod("apps", "p-inf", "u2", corev1.PodRunning, true, nil, corev1.PodCondition{
				Type: corev1.PodResizePending, Status: corev1.ConditionTrue, Reason: corev1.PodReasonInfeasible, LastTransitionTime: oldTime,
			}),
			makeResizePod("apps", "p-oth", "u3", corev1.PodRunning, true, nil, corev1.PodCondition{
				Type: corev1.PodResizePending, Status: corev1.ConditionTrue, Reason: "", LastTransitionTime: oldTime,
			}),
			makeResizePod("apps", "p-err", "u4", corev1.PodRunning, true, nil, corev1.PodCondition{
				Type: corev1.PodResizeInProgress, Status: corev1.ConditionTrue, Reason: corev1.PodReasonError, LastTransitionTime: oldTime,
			}),
			makeResizePod("apps", "p-dual", "u5", corev1.PodRunning, true, nil,
				corev1.PodCondition{
					Type: corev1.PodResizePending, Status: corev1.ConditionTrue, Reason: corev1.PodReasonDeferred, LastTransitionTime: oldTime,
				},
				corev1.PodCondition{
					Type: corev1.PodResizeInProgress, Status: corev1.ConditionTrue, Reason: "", LastTransitionTime: oldTime,
				},
			),
		}
		cs := fake.NewSimpleClientset(pods...)
		p := testProber(cs)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*podResizeWedgeGuardCheck](t, p)

		sctx := probetest.SweepCtx(ctx, chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)
		if res.Pass || res.Infra != nil {
			t.Fatalf("Run = %+v, want Pass=false Infra=nil", res)
		}

		wantMetrics := [][3]string{
			{"apps", "p-def", podResizeReasonPendingDeferred},
			{"apps", "p-inf", podResizeReasonPendingInfeasible},
			{"apps", "p-oth", podResizeReasonPending},
			{"apps", "p-err", podResizeReasonInProgressError},
			{"apps", "p-dual", podResizeReasonPendingDeferred},
			{"apps", "p-dual", podResizeReasonInProgress},
		}
		for _, lv := range wantMetrics {
			if v := ptestutil.ToFloat64(podResizeWedgedGauge.WithLabelValues(lv[0], lv[1], lv[2])); v != 1 {
				t.Fatalf("gauge %v = %v, want 1", lv, v)
			}
		}

		evs, err := cs.EventsV1().Events("apps").List(ctx, metav1.ListOptions{})
		if err != nil || len(evs.Items) != 6 {
			t.Fatalf("events = %d (err=%v), want 6", len(evs.Items), err)
		}
		for _, ev := range evs.Items {
			if ev.Reason != podResizeEventReason || ev.Type != corev1.EventTypeWarning {
				t.Fatalf("unexpected event: %+v", ev)
			}
		}

		// Repeat within 30m cooldown -> 0 new events.
		probetest.FreezeNow(p.Deps, base.Add(10*time.Minute))
		sctx2 := probetest.SweepCtx(ctx, chk.Deps)
		_ = chk.Run(sctx2)
		probetest.VerifySweep(sctx2)
		evs2, _ := cs.EventsV1().Events("apps").List(ctx, metav1.ListOptions{})
		if len(evs2.Items) != 6 {
			t.Fatalf("expected cooldown dedup, got %d events", len(evs2.Items))
		}

		// Clear condition on p-def -> gauge pruned back to 0.
		pDef, _ := cs.CoreV1().Pods("apps").Get(ctx, "p-def", metav1.GetOptions{})
		pDef.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		_, _ = cs.CoreV1().Pods("apps").UpdateStatus(ctx, pDef, metav1.UpdateOptions{})
		p.InvalidatePods(ctx)

		sctx3 := probetest.SweepCtx(ctx, chk.Deps)
		_ = chk.Run(sctx3)
		probetest.VerifySweep(sctx3)
		if v := ptestutil.ToFloat64(podResizeWedgedGauge.WithLabelValues("apps", "p-def", podResizeReasonPendingDeferred)); v != 0 {
			t.Fatalf("cleared pod gauge = %v, want 0", v)
		}
	})

	t.Run("zero LastTransitionTime uses firstSeen ledger and prunes on clear", func(t *testing.T) {
		podResizeWedgedGauge.Reset()
		pod := makeResizePod("apps", "no-ts", "u-nots", corev1.PodRunning, true, nil, corev1.PodCondition{
			Type: corev1.PodResizePending, Status: corev1.ConditionTrue, Reason: corev1.PodReasonDeferred,
		})
		cs := fake.NewSimpleClientset(pod)
		p := testProber(cs)
		chk := probetest.MustCheck[*podResizeWedgeGuardCheck](t, p)

		// Sweep 1 (T=0): stamps firstSeen, passes.
		probetest.FreezeNow(p.Deps, base)
		sctx1 := probetest.SweepCtx(ctx, chk.Deps)
		if res := chk.Run(sctx1); !res.Pass {
			t.Fatalf("T=0 Run = %+v, want Pass", res)
		}
		probetest.VerifySweep(sctx1)

		// Sweep 2 (T+10m < 15m): still passes.
		probetest.FreezeNow(p.Deps, base.Add(10*time.Minute))
		sctx2 := probetest.SweepCtx(ctx, chk.Deps)
		if res := chk.Run(sctx2); !res.Pass {
			t.Fatalf("T+10m Run = %+v, want Pass", res)
		}
		probetest.VerifySweep(sctx2)

		// Sweep 3 (T+15m): fires!
		probetest.FreezeNow(p.Deps, base.Add(15*time.Minute))
		sctx3 := probetest.SweepCtx(ctx, chk.Deps)
		if res := chk.Run(sctx3); res.Pass {
			t.Fatalf("T+15m Run unexpectedly passed")
		}
		probetest.VerifySweep(sctx3)

		// Clear condition -> firstSeen pruned; re-appearing later restarts the 15m clock.
		got, _ := cs.CoreV1().Pods("apps").Get(ctx, "no-ts", metav1.GetOptions{})
		got.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		_, _ = cs.CoreV1().Pods("apps").UpdateStatus(ctx, got, metav1.UpdateOptions{})
		p.InvalidatePods(ctx)

		probetest.FreezeNow(p.Deps, base.Add(20*time.Minute))
		sctx4 := probetest.SweepCtx(ctx, chk.Deps)
		if res := chk.Run(sctx4); !res.Pass {
			t.Fatalf("after clear Run = %+v, want Pass", res)
		}
		probetest.VerifySweep(sctx4)

		got2, _ := cs.CoreV1().Pods("apps").Get(ctx, "no-ts", metav1.GetOptions{})
		got2.Status.Conditions = append(got2.Status.Conditions, corev1.PodCondition{
			Type: corev1.PodResizePending, Status: corev1.ConditionTrue, Reason: corev1.PodReasonDeferred,
		})
		_, _ = cs.CoreV1().Pods("apps").UpdateStatus(ctx, got2, metav1.UpdateOptions{})
		p.InvalidatePods(ctx)

		probetest.FreezeNow(p.Deps, base.Add(25*time.Minute))
		sctx5 := probetest.SweepCtx(ctx, chk.Deps)
		if res := chk.Run(sctx5); !res.Pass {
			t.Fatalf("re-armed pod must pass on first sighting: %+v", res)
		}
		probetest.VerifySweep(sctx5)
	})

	t.Run("pods list error returns Infra and event create error does not fail check", func(t *testing.T) {
		podResizeWedgedGauge.Reset()
		cs := fake.NewSimpleClientset()
		cs.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("apiserver unavailable")
		})
		p := testProber(cs)
		chk := probetest.MustCheck[*podResizeWedgeGuardCheck](t, p)
		sctx := probetest.SweepCtx(ctx, chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)
		if res.Pass || res.Infra == nil {
			t.Fatalf("expected Infra error on list pods failure, got %+v", res)
		}

		// Event create error does not mark Infra or stamp cooldown.
		pod := makeResizePod("apps", "ev-err", "u-ev", corev1.PodRunning, true, nil, corev1.PodCondition{
			Type: corev1.PodResizePending, Status: corev1.ConditionTrue, Reason: corev1.PodReasonDeferred,
			LastTransitionTime: metav1.NewTime(base.Add(-20 * time.Minute)),
		})
		cs2 := fake.NewSimpleClientset(pod)
		cs2.PrependReactor("create", "events", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("events 403")
		})
		p2 := testProber(cs2)
		probetest.FreezeNow(p2.Deps, base)
		chk2 := probetest.MustCheck[*podResizeWedgeGuardCheck](t, p2)
		before := probetest.CounterSnapshot(t, p2.Deps.Name)
		sctx2 := probetest.SweepCtx(ctx, chk2.Deps)
		res2 := chk2.Run(sctx2)
		probetest.VerifySweep(sctx2)
		probetest.AssertCounterDelta(t, p2.Deps.Name, before, 0)
		if res2.Pass || res2.Infra != nil {
			t.Fatalf("Run with event create failure = %+v, want Pass=false Infra=nil", res2)
		}
		if chk2.eventCooldown.CooledDown("podresize.apps.ev-err.pending_deferred", podResizeEventCooldown, base) {
			t.Fatal("eventCooldown must not stamp on create failure")
		}
	})
}

func TestPodResizeWedgeGuardEnvKnobs(t *testing.T) {
	t.Setenv("NODE_AUTOMATION_POD_RESIZE_MIN_AGE", "5m")
	t.Setenv("NODE_AUTOMATION_POD_RESIZE_EVICT_ENABLED", "true")

	chk := NewPodResizeWedgeGuardCheck(probetest.NewDeps(fake.NewSimpleClientset(), probetest.OpDyn())).(*podResizeWedgeGuardCheck)
	if chk.minAge != 5*time.Minute {
		t.Fatalf("minAge = %v, want 5m", chk.minAge)
	}
	if !chk.evictEnabled {
		t.Fatal("evictEnabled = false, want true")
	}

	t.Setenv("NODE_AUTOMATION_POD_RESIZE_MIN_AGE", "not-a-duration")
	t.Setenv("NODE_AUTOMATION_POD_RESIZE_EVICT_ENABLED", "false")
	chk2 := NewPodResizeWedgeGuardCheck(probetest.NewDeps(fake.NewSimpleClientset(), probetest.OpDyn())).(*podResizeWedgeGuardCheck)
	if chk2.minAge != 15*time.Minute || chk2.evictEnabled {
		t.Fatalf("fallback config = (%v, %v), want (15m, false)", chk2.minAge, chk2.evictEnabled)
	}
}

func TestPodResizeWedgeGuardEviction(t *testing.T) {
	base := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	oldTime := metav1.NewTime(base.Add(-20 * time.Minute))
	ctrlTrue := true
	rsOwner := &metav1.OwnerReference{Kind: "ReplicaSet", Name: "web-rs", UID: "rs-uid-1", Controller: &ctrlTrue}
	dsOwner := &metav1.OwnerReference{Kind: "DaemonSet", Name: "ds-agent", UID: "ds-uid-1", Controller: &ctrlTrue}

	captureEvictions := func(cs *fake.Clientset, react func(ev *policyv1.Eviction) (bool, error)) *[]string {
		var evicted []string
		cs.PrependReactor("create", "pods", func(action ktesting.Action) (bool, runtime.Object, error) {
			if action.GetSubresource() != "eviction" {
				return false, nil, nil
			}
			ca := action.(ktesting.CreateAction)
			ev := ca.GetObject().(*policyv1.Eviction)
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

	t.Run("eviction disabled by default performs zero evictions", func(t *testing.T) {
		podResizeWedgedGauge.Reset()
		sib := makeResizePod("apps", "web-sib", "u-sib", corev1.PodRunning, true, rsOwner)
		wedged := makeResizePod("apps", "web-0", "u-0", corev1.PodRunning, true, rsOwner, corev1.PodCondition{
			Type: corev1.PodResizePending, Status: corev1.ConditionTrue, Reason: corev1.PodReasonDeferred, LastTransitionTime: oldTime,
		})
		cs := fake.NewSimpleClientset(sib, wedged)
		evicted := captureEvictions(cs, nil)
		p := testProber(cs)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*podResizeWedgeGuardCheck](t, p)

		sctx := probetest.SweepCtx(ctx, chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)
		if res.Pass || len(*evicted) != 0 {
			t.Fatalf("res=%+v evicted=%v, want Pass=false and 0 evictions", res, *evicted)
		}
	})

	t.Run("safety filters exclude system ns, mirror, unowned, DaemonSet, Infeasible, InProgress, sole Ready", func(t *testing.T) {
		podResizeWedgedGauge.Reset()
		t.Setenv("NODE_AUTOMATION_POD_RESIZE_EVICT_ENABLED", "true")
		defCond := corev1.PodCondition{
			Type: corev1.PodResizePending, Status: corev1.ConditionTrue, Reason: corev1.PodReasonDeferred, LastTransitionTime: oldTime,
		}
		infCond := corev1.PodCondition{
			Type: corev1.PodResizePending, Status: corev1.ConditionTrue, Reason: corev1.PodReasonInfeasible, LastTransitionTime: oldTime,
		}
		errCond := corev1.PodCondition{
			Type: corev1.PodResizeInProgress, Status: corev1.ConditionTrue, Reason: corev1.PodReasonError, LastTransitionTime: oldTime,
		}

		sysOwner := &metav1.OwnerReference{Kind: "ReplicaSet", Name: "sys-rs", UID: "sys-rs-uid", Controller: &ctrlTrue}
		soleOwner := &metav1.OwnerReference{Kind: "ReplicaSet", Name: "sole-rs", UID: "sole-rs-uid", Controller: &ctrlTrue}

		mirror := makeResizePod("apps", "mirror", "u-mir", corev1.PodRunning, true, rsOwner, defCond)
		mirror.Annotations = map[string]string{"kubernetes.io/config.mirror": "node-1"}

		pods := []runtime.Object{
			// Eligible sibling + wedged pod for web-rs
			makeResizePod("apps", "web-sib", "u-wsib", corev1.PodRunning, true, rsOwner),
			makeResizePod("apps", "web-eligible", "u-welig", corev1.PodRunning, true, rsOwner, defCond),
			// Excluded: Infeasible & InProgress(Error) even with siblings
			makeResizePod("apps", "web-infeasible", "u-winf", corev1.PodRunning, true, rsOwner, infCond),
			makeResizePod("apps", "web-inprog-err", "u-werr", corev1.PodRunning, true, rsOwner, errCond),
			// Excluded: system namespace (even with Ready sibling)
			makeResizePod("kube-system", "coredns-sib", "u-ksib", corev1.PodRunning, true, sysOwner),
			makeResizePod("kube-system", "coredns-0", "u-ks0", corev1.PodRunning, true, sysOwner, defCond),
			// Excluded: mirror pod
			mirror,
			// Excluded: unowned pod
			makeResizePod("apps", "unowned", "u-unown", corev1.PodRunning, true, nil, defCond),
			// Excluded: DaemonSet pod (even with Ready sibling on same DS)
			makeResizePod("apps", "ds-sib", "u-dsib", corev1.PodRunning, true, dsOwner),
			makeResizePod("apps", "ds-0", "u-ds0", corev1.PodRunning, true, dsOwner, defCond),
			// Excluded: sole Ready replica (Ready=True itself, so ReadySiblings==0)
			makeResizePod("apps", "sole-0", "u-sole", corev1.PodRunning, true, soleOwner, defCond),
		}

		cs := fake.NewSimpleClientset(pods...)
		var gotUID types.UID
		evicted := captureEvictions(cs, func(ev *policyv1.Eviction) (bool, error) {
			if ev.DeleteOptions != nil && ev.DeleteOptions.Preconditions != nil && ev.DeleteOptions.Preconditions.UID != nil {
				gotUID = *ev.DeleteOptions.Preconditions.UID
			}
			return false, nil
		})
		p := testProber(cs)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*podResizeWedgeGuardCheck](t, p)

		beforeHeals := ptestutil.ToFloat64(metrics.ControlPlanePodHealsTotal.WithLabelValues(CheckNamePodResizeWedgeGuard))
		sctx := probetest.SweepCtx(ctx, chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)
		if res.Pass {
			t.Fatal("expected Pass=false")
		}
		if len(*evicted) != 1 || (*evicted)[0] != "apps/web-eligible" {
			t.Fatalf("evicted = %v, want [apps/web-eligible]", *evicted)
		}
		if gotUID != "u-welig" {
			t.Fatalf("UID precondition = %q, want u-welig", gotUID)
		}
		afterHeals := ptestutil.ToFloat64(metrics.ControlPlanePodHealsTotal.WithLabelValues(CheckNamePodResizeWedgeGuard))
		if afterHeals-beforeHeals != 1 {
			t.Fatalf("ControlPlanePodHealsTotal delta = %v, want 1", afterHeals-beforeHeals)
		}
	})

	t.Run("cap at 4 per sweep sorted deterministically", func(t *testing.T) {
		podResizeWedgedGauge.Reset()
		t.Setenv("NODE_AUTOMATION_POD_RESIZE_EVICT_ENABLED", "true")
		defCond := corev1.PodCondition{
			Type: corev1.PodResizePending, Status: corev1.ConditionTrue, Reason: corev1.PodReasonDeferred, LastTransitionTime: oldTime,
		}
		var objs []runtime.Object
		for _, name := range []string{"foxtrot", "bravo", "delta", "alpha", "echo", "charlie"} {
			owner := &metav1.OwnerReference{
				Kind:       "ReplicaSet",
				Name:       name + "-rs",
				UID:        types.UID("uid-rs-" + name),
				Controller: &ctrlTrue,
			}
			objs = append(objs,
				makeResizePod("apps", name+"-sib", "sib-"+name, corev1.PodRunning, true, owner),
				makeResizePod("apps", name, "pod-"+name, corev1.PodRunning, true, owner, defCond),
			)
		}
		cs := fake.NewSimpleClientset(objs...)
		evicted := captureEvictions(cs, nil)
		p := testProber(cs)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*podResizeWedgeGuardCheck](t, p)

		sctx := probetest.SweepCtx(ctx, chk.Deps)
		_ = chk.Run(sctx)
		probetest.VerifySweep(sctx)

		want := []string{"apps/alpha", "apps/bravo", "apps/charlie", "apps/delta"}
		if len(*evicted) != len(want) {
			t.Fatalf("evicted = %v, want %v", *evicted, want)
		}
		for i := range want {
			if (*evicted)[i] != want[i] {
				t.Fatalf("evicted[%d] = %q, want %q (all=%v)", i, (*evicted)[i], want[i], *evicted)
			}
		}
	})

	t.Run("PDB 429 and 404 refund budget and target breaker; breaker opens on repeated evictions", func(t *testing.T) {
		podResizeWedgedGauge.Reset()
		t.Setenv("NODE_AUTOMATION_POD_RESIZE_EVICT_ENABLED", "true")
		heal.ConfigureBudget(1, time.Hour)
		t.Cleanup(func() { heal.ConfigureBudget(0, 0) })

		defCond := corev1.PodCondition{
			Type: corev1.PodResizePending, Status: corev1.ConditionTrue, Reason: corev1.PodReasonDeferred, LastTransitionTime: oldTime,
		}
		rsA := &metav1.OwnerReference{Kind: "ReplicaSet", Name: "rs-a", UID: "uid-rsa", Controller: &ctrlTrue}
		rsB := &metav1.OwnerReference{Kind: "ReplicaSet", Name: "rs-b", UID: "uid-rsb", Controller: &ctrlTrue}

		pods := []runtime.Object{
			makeResizePod("apps", "a-sib", "u-asib", corev1.PodRunning, true, rsA),
			makeResizePod("apps", "a-0", "u-a0", corev1.PodRunning, true, rsA, defCond),
			makeResizePod("apps", "b-sib", "u-bsib", corev1.PodRunning, true, rsB),
			makeResizePod("apps", "b-0", "u-b0", corev1.PodRunning, true, rsB, defCond),
		}
		cs := fake.NewSimpleClientset(pods...)
		evicted := captureEvictions(cs, func(ev *policyv1.Eviction) (bool, error) {
			if ev.Name == "a-0" {
				return true, apierrors.NewTooManyRequests("pdb disallow", 0)
			}
			return false, nil
		})
		p := testProber(cs)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*podResizeWedgeGuardCheck](t, p)

		// a-0 gets 429 and refunds grant -> b-0 receives the single grant and is evicted!
		sctx := probetest.SweepCtx(ctx, chk.Deps)
		_ = chk.Run(sctx)
		probetest.VerifySweep(sctx)
		if len(*evicted) != 1 || (*evicted)[0] != "apps/b-0" {
			t.Fatalf("evicted = %v, want [apps/b-0] (429 did not refund grant)", *evicted)
		}

		// 404 NotFound on c-0 also refunds grant and does not IncError.
		heal.ConfigureBudget(1, time.Hour)
		rsC := &metav1.OwnerReference{Kind: "ReplicaSet", Name: "rs-c", UID: "uid-rsc", Controller: &ctrlTrue}
		cs2 := fake.NewSimpleClientset(
			makeResizePod("apps", "c-sib", "u-csib", corev1.PodRunning, true, rsC),
			makeResizePod("apps", "c-0", "u-c0", corev1.PodRunning, true, rsC, defCond),
		)
		_ = captureEvictions(cs2, func(*policyv1.Eviction) (bool, error) {
			return true, apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "c-0")
		})
		p2 := testProber(cs2)
		probetest.FreezeNow(p2.Deps, base)
		chk2 := probetest.MustCheck[*podResizeWedgeGuardCheck](t, p2)
		before := probetest.CounterSnapshot(t, p2.Deps.Name)
		sctx2 := probetest.SweepCtx(ctx, chk2.Deps)
		_ = chk2.Run(sctx2)
		probetest.VerifySweep(sctx2)
		probetest.AssertCounterDelta(t, p2.Deps.Name, before, 0)
		if proceed, _ := chk2.HealAllowed(sctx2, logr.Discard(), nil, "other", time.Minute, base); !proceed {
			t.Fatal("404 NotFound did not refund fleet budget grant")
		}

		// Non-convergent target breaker: 3 grants for apps.rs-brk-unique opens circuit on 4th attempt and refunds fleet grant.
		heal.ConfigureTargetBreaker(3, 3*time.Hour)
		t.Cleanup(func() { heal.ConfigureTargetBreaker(0, 0) })
		rsBrk := &metav1.OwnerReference{Kind: "ReplicaSet", Name: "rs-brk-unique", UID: "uid-rsbrk", Controller: &ctrlTrue}
		for i := 0; i < 3; i++ {
			if ok, _ := heal.TryAcquireTarget(CheckNamePodResizeWedgeGuard, "apps.rs-brk-unique", base); !ok {
				t.Fatalf("pre-acquire %d failed", i)
			}
		}
		heal.ConfigureBudget(1, time.Hour)
		cs3 := fake.NewSimpleClientset(
			makeResizePod("apps", "brk-sib", "u-brksib", corev1.PodRunning, true, rsBrk),
			makeResizePod("apps", "brk-0", "u-brk0", corev1.PodRunning, true, rsBrk, defCond),
		)
		ev3 := captureEvictions(cs3, nil)
		p3 := testProber(cs3)
		probetest.FreezeNow(p3.Deps, base)
		chk3 := probetest.MustCheck[*podResizeWedgeGuardCheck](t, p3)
		sctx3 := probetest.SweepCtx(ctx, chk3.Deps)
		_ = chk3.Run(sctx3)
		probetest.VerifySweep(sctx3)
		if len(*ev3) != 0 {
			t.Fatalf("open target breaker did not block eviction: %v", *ev3)
		}
		if proceed, _ := chk3.HealAllowed(sctx3, logr.Discard(), nil, "other-after-brk", time.Minute, base); !proceed {
			t.Fatal("open target breaker did not refund fleet budget grant")
		}
	})

	t.Run("maintenance hold, unverifiable mutex, and eviction error", func(t *testing.T) {
		podResizeWedgedGauge.Reset()
		t.Setenv("NODE_AUTOMATION_POD_RESIZE_EVICT_ENABLED", "true")
		defCond := corev1.PodCondition{
			Type: corev1.PodResizePending, Status: corev1.ConditionTrue, Reason: corev1.PodReasonDeferred, LastTransitionTime: oldTime,
		}

		// Maintenance hold skips eviction.
		csHold := fake.NewSimpleClientset(
			&appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:   "kube-system",
					Name:        "kured",
					Annotations: map[string]string{"weave.works/kured-node-lock": "cluster-upgrade"},
				},
			},
			makeResizePod("apps", "h-sib", "u-hsib", corev1.PodRunning, true, rsOwner),
			makeResizePod("apps", "h-0", "u-h0", corev1.PodRunning, true, rsOwner, defCond),
		)
		evHold := captureEvictions(csHold, nil)
		pHold := testProber(csHold)
		probetest.FreezeNow(pHold.Deps, base)
		chkHold := probetest.MustCheck[*podResizeWedgeGuardCheck](t, pHold)
		sctxHold := probetest.SweepCtx(ctx, chkHold.Deps)
		_ = chkHold.Run(sctxHold)
		probetest.VerifySweep(sctxHold)
		if len(*evHold) != 0 {
			t.Fatalf("maintenance hold allowed eviction: %v", *evHold)
		}

		// Unverifiable mutex (Dyn == nil) increments error counter and skips eviction.
		csUnv := fake.NewSimpleClientset(
			makeResizePod("apps", "u-sib", "u-usib", corev1.PodRunning, true, rsOwner),
			makeResizePod("apps", "u-0", "u-u0", corev1.PodRunning, true, rsOwner, defCond),
		)
		evUnv := captureEvictions(csUnv, nil)
		pUnv := testProber(csUnv)
		probetest.FreezeNow(pUnv.Deps, base)
		chkUnv := probetest.MustCheck[*podResizeWedgeGuardCheck](t, pUnv)
		chkUnv.Dyn = nil
		beforeUnv := probetest.CounterSnapshot(t, pUnv.Deps.Name)
		sctxUnv := probetest.SweepCtx(ctx, chkUnv.Deps)
		_ = chkUnv.Run(sctxUnv)
		probetest.VerifySweep(sctxUnv)
		probetest.AssertCounterDelta(t, pUnv.Deps.Name, beforeUnv, 1)
		if len(*evUnv) != 0 {
			t.Fatalf("unverifiable mutex allowed eviction: %v", *evUnv)
		}

		// Eviction API 500 error increments error counter.
		csErr := fake.NewSimpleClientset(
			makeResizePod("apps", "e-sib", "u-esib", corev1.PodRunning, true, rsOwner),
			makeResizePod("apps", "e-0", "u-e0", corev1.PodRunning, true, rsOwner, defCond),
		)
		_ = captureEvictions(csErr, func(*policyv1.Eviction) (bool, error) {
			return true, apierrors.NewGenericServerResponse(http.StatusInternalServerError, "post", schema.GroupResource{Resource: "pods"}, "e-0", "boom", 0, false)
		})
		pErr := testProber(csErr)
		probetest.FreezeNow(pErr.Deps, base)
		chkErr := probetest.MustCheck[*podResizeWedgeGuardCheck](t, pErr)
		beforeErr := probetest.CounterSnapshot(t, pErr.Deps.Name)
		sctxErr := probetest.SweepCtx(ctx, chkErr.Deps)
		_ = chkErr.Run(sctxErr)
		probetest.VerifySweep(sctxErr)
		probetest.AssertCounterDelta(t, pErr.Deps.Name, beforeErr, 1)
	})
}
