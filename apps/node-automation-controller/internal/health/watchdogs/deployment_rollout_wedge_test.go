// deployment_rollout_wedge_test.go — coverage for the
// deployment-rollout-wedge check: the 20-minute persistence window
// applied to BOTH ProgressDeadlineExceeded and ReplicaFailure,
// the intentionally-downscaled skip, and the Flux patch gate on
// the stage-3 template nudge.
package watchdogs

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// wedgeDep builds a Deployment whose Progressing condition carries
// the given reason/status/age.
func wedgeDep(ns, name string, replicas int32, reason string,
	status corev1.ConditionStatus, age time.Duration) *appsv1.Deployment {

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(replicas),
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
			},
		},
		Status: appsv1.DeploymentStatus{
			Conditions: []appsv1.DeploymentCondition{{
				Type:               appsv1.DeploymentProgressing,
				Status:             status,
				Reason:             reason,
				LastTransitionTime: metav1.NewTime(time.Now().Add(-age)),
			}},
		},
	}
}

// wedgeRS builds a ReplicaSet owned by depUID carrying an aged
// ReplicaFailure condition.
func wedgeRS(ns, name string, depUID types.UID, depName string,
	failedFor time.Duration) *appsv1.ReplicaSet {
	return &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "Deployment",
				Name: depName, UID: depUID, Controller: ptr.To(true),
			}},
		},
		Spec: appsv1.ReplicaSetSpec{Replicas: ptr.To(int32(1))},
		Status: appsv1.ReplicaSetStatus{
			Conditions: []appsv1.ReplicaSetCondition{{
				Type:               appsv1.ReplicaSetReplicaFailure,
				Status:             corev1.ConditionTrue,
				LastTransitionTime: metav1.NewTime(time.Now().Add(-failedFor)),
			}},
		},
	}
}

func templateNudged(t *testing.T, cs *fake.Clientset, ns, name string) bool {
	t.Helper()
	got, err := cs.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get deployment %s/%s: %v", ns, name, err)
	}
	_, ok := got.Spec.Template.Annotations[kube.RestartedAtAnno]
	return ok
}

func TestRolloutWedgeProgressDeadlineWindow(t *testing.T) {
	dep := wedgeDep("apps", "wedged", 3, "ProgressDeadlineExceeded",
		corev1.ConditionFalse, rolloutWedgeMinAge+time.Minute)
	cs := fake.NewSimpleClientset(dep)
	d := probetest.NewDeps(cs, probetest.OpDyn())
	ch := &deploymentRolloutWedgeCheck{Deps: d}

	res := ch.Run(probetest.SweepCtx(ctx, ch.Deps))
	if res.Pass {
		t.Fatal("aged ProgressDeadlineExceeded must flag")
	}
	// A FRESH PDE (just flipped) must not flag — the window exists
	// to spare slow rollouts.
	fresh := wedgeDep("apps", "slow", 3, "ProgressDeadlineExceeded",
		corev1.ConditionFalse, time.Minute)
	cs2 := fake.NewSimpleClientset(fresh)
	d2 := probetest.NewDeps(cs2, probetest.OpDyn())
	ch2 := &deploymentRolloutWedgeCheck{Deps: d2}
	if res := ch2.Run(probetest.SweepCtx(ctx, ch2.Deps)); res.Pass != true {
		t.Fatalf("fresh PDE inside window must pass: %+v", res)
	}
}

func TestRolloutWedgeReplicaFailureNeedsSameWindow(t *testing.T) {
	// ReplicaFailure just flipped is a rollout in progress — the
	// same 20m persistence window as PDE must apply (the review
	// found it fired on first sight).
	dep := wedgeDep("apps", "dep", 3, "Available", corev1.ConditionTrue, 0)
	dep.UID = "dep-uid"
	freshRS := wedgeRS("apps", "dep-rs", "dep-uid", "dep", time.Minute)
	csFresh := fake.NewSimpleClientset(dep, freshRS)
	d1 := probetest.NewDeps(csFresh, probetest.OpDyn())
	ch1 := &deploymentRolloutWedgeCheck{Deps: d1}
	if res := ch1.Run(probetest.SweepCtx(ctx, ch1.Deps)); res.Pass != true {
		t.Fatalf("fresh ReplicaFailure must not flag: %+v", res)
	}

	// A second Deployment whose RS failure is aged past the window.
	dep2 := wedgeDep("apps", "dep2", 3, "Available", corev1.ConditionTrue, 0)
	dep2.UID = "dep2-uid"
	agedRS2 := wedgeRS("apps", "dep2-rs", "dep2-uid", "dep2",
		rolloutWedgeMinAge+time.Minute)
	csAged := fake.NewSimpleClientset(dep2, agedRS2)
	d2 := probetest.NewDeps(csAged, probetest.OpDyn())
	ch2 := &deploymentRolloutWedgeCheck{Deps: d2}
	if res := ch2.Run(probetest.SweepCtx(ctx, ch2.Deps)); res.Pass {
		t.Fatal("aged ReplicaFailure must flag")
	}
}

func TestRolloutWedgeSkipsIntentionallyDownscaled(t *testing.T) {
	// A Deployment the downscaler parked at 0 replicas — the wedge
	// signature is EXPECTED there; stage 3 must not nudge.
	dep := wedgeDep("apps", "asleep", 0, "ProgressDeadlineExceeded",
		corev1.ConditionFalse, rolloutWedgeMinAge+time.Minute)
	dep.Annotations = map[string]string{
		"downscaler/uptime": "Mon-Fri 08:00-20:00",
	}
	cs := fake.NewSimpleClientset(dep)
	d := probetest.NewDeps(cs, probetest.OpDyn())
	ch := &deploymentRolloutWedgeCheck{Deps: d}
	ch.Run(probetest.SweepCtx(ctx, ch.Deps))
	if templateNudged(t, cs, "apps", "asleep") {
		t.Fatal("template nudge landed on an intentionally-downscaled Deployment")
	}
}

// An explicit replicas=0 is skipped even WITHOUT downscaler
// annotations — there is no roll to wedge and no stage may act.
func TestRolloutWedgeSkipsZeroReplicaDeployment(t *testing.T) {
	dep := wedgeDep("apps", "zeroed", 0, "ProgressDeadlineExceeded",
		corev1.ConditionFalse, rolloutWedgeMinAge+time.Minute)
	cs := fake.NewSimpleClientset(dep)
	d := probetest.NewDeps(cs, probetest.OpDyn())
	ch := &deploymentRolloutWedgeCheck{Deps: d}
	if res := ch.Run(probetest.SweepCtx(ctx, ch.Deps)); !res.Pass {
		t.Fatalf("zero-replica Deployment must not flag: %+v", res)
	}
	if templateNudged(t, cs, "apps", "zeroed") {
		t.Fatal("zero-replica Deployment was nudged")
	}
}

func rsReplicas(t *testing.T, cs *fake.Clientset, ns, name string) int32 {
	t.Helper()
	got, err := cs.AppsV1().ReplicaSets(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get replicaset %s/%s: %v", ns, name, err)
	}
	if got.Spec.Replicas == nil {
		return 1 // apiserver default
	}
	return *got.Spec.Replicas
}

// A sweep that deleted a terminal pod must NOT also zero a stale
// ReplicaSet or nudge the template: each stage invalidates the census
// it derived from, so the next sweep re-derives from fresh state.
func TestRolloutWedgeRunsOneStagePerSweep(t *testing.T) {
	dep := wedgeDep("apps", "staged", 3, "ProgressDeadlineExceeded",
		corev1.ConditionFalse, rolloutWedgeMinAge+time.Minute)
	dep.UID = "staged-uid"
	rsOld := wedgeRS("apps", "staged-old", "staged-uid", "staged", 0)
	rsOld.UID = "rs-old-uid"
	rsOld.Annotations = map[string]string{"deployment.kubernetes.io/revision": "1"}
	rsNew := wedgeRS("apps", "staged-new", "staged-uid", "staged", 0)
	rsNew.UID = "rs-new-uid"
	rsNew.Annotations = map[string]string{"deployment.kubernetes.io/revision": "2"}
	terminal := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "staged-old-abc", UID: "terminal-uid",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "ReplicaSet",
				Name: rsOld.Name, UID: rsOld.UID, Controller: ptr.To(true),
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodFailed},
	}
	cs := fake.NewSimpleClientset(dep, rsOld, rsNew, terminal)
	d := probetest.NewDeps(cs, probetest.OpDyn())
	ch := &deploymentRolloutWedgeCheck{Deps: d}

	// Sweep 1 — Stage 1 GC only.
	ch.Run(probetest.SweepCtx(ctx, ch.Deps))
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "staged-old-abc", metav1.GetOptions{}); err == nil {
		t.Fatal("terminal pod survived stage 1")
	}
	if got := rsReplicas(t, cs, "apps", "staged-old"); got != 1 {
		t.Fatalf("stage 2 ran in the same sweep: stale RS replicas=%d", got)
	}
	if templateNudged(t, cs, "apps", "staged") {
		t.Fatal("stage 3 ran in the same sweep as stage 1")
	}

	// Sweep 2 — Stage 2 zero only; stage 3 must wait for sweep 3.
	ch.Run(probetest.SweepCtx(ctx, ch.Deps))
	if got := rsReplicas(t, cs, "apps", "staged-old"); got != 0 {
		t.Fatalf("stage 2 did not zero the stale RS: replicas=%d", got)
	}
	if templateNudged(t, cs, "apps", "staged") {
		t.Fatal("stage 3 ran in the same sweep as stage 2")
	}
}

func TestRolloutWedgeFluxGateBlocksNudge(t *testing.T) {
	// Arm the conflict loop at threshold 1 — the FIRST sighting of
	// a Flux-owned key is already the ping-pong repeat, so the gate
	// denies and the template nudge must not land.
	heal.ConfigureFluxConflictLoop(1, 30*time.Minute)
	defer heal.ConfigureFluxConflictLoop(0, 0)

	dep := wedgeDep("apps", "gitops", 3, "ProgressDeadlineExceeded",
		corev1.ConditionFalse, rolloutWedgeMinAge+time.Minute)
	dep.ManagedFields = []metav1.ManagedFieldsEntry{{
		Manager:    "kustomize-controller",
		Operation:  metav1.ManagedFieldsOperationApply,
		APIVersion: "apps/v1",
	}}
	cs := fake.NewSimpleClientset(dep)
	d := probetest.NewDeps(cs, probetest.OpDyn())
	ch := &deploymentRolloutWedgeCheck{Deps: d}
	ch.Run(probetest.SweepCtx(ctx, ch.Deps))
	if templateNudged(t, cs, "apps", "gitops") {
		t.Fatal("template nudge landed past the Flux patch gate")
	}
}

func TestRolloutWedgeNudgeLandsOnPlainDeployment(t *testing.T) {
	// Control case: same aged wedge on a non-Flux, non-downscaled
	// Deployment — the stage-3 nudge must land (detection passed
	// the window, no gate objects it).
	dep := wedgeDep("apps", "plain", 3, "ProgressDeadlineExceeded",
		corev1.ConditionFalse, rolloutWedgeMinAge+time.Minute)
	cs := fake.NewSimpleClientset(dep)
	d := probetest.NewDeps(cs, probetest.OpDyn())
	ch := &deploymentRolloutWedgeCheck{Deps: d}
	res := ch.Run(probetest.SweepCtx(ctx, ch.Deps))
	if res.Pass {
		t.Fatal("aged wedge must flag")
	}
	if !templateNudged(t, cs, "apps", "plain") {
		t.Fatal("template nudge did not land on an eligible Deployment")
	}
}

func TestRolloutWedgeTerminalDeleteUsesTombstoneWithoutReList(t *testing.T) {
	dep := wedgeDep("apps", "staged", 3, "ProgressDeadlineExceeded",
		corev1.ConditionFalse, rolloutWedgeMinAge+time.Minute)
	dep.UID = "staged-uid"
	rsOld := wedgeRS("apps", "staged-old", "staged-uid", "staged", 1)
	rsOld.UID = "rs-old-uid"
	terminal := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "staged-old-abc", UID: "terminal-uid",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "ReplicaSet",
				Name: rsOld.Name, UID: rsOld.UID, Controller: ptr.To(true),
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodFailed},
	}
	cs := fake.NewSimpleClientset(dep, rsOld, terminal)
	var podLists int
	cs.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		podLists++
		return false, nil, nil
	})
	d := probetest.NewDeps(cs, probetest.OpDyn())
	ch := &deploymentRolloutWedgeCheck{Deps: d}

	sctx := probetest.SweepCtx(ctx, ch.Deps)
	ch.Run(sctx)

	podsInSweep, err := ch.Deps.AllPods(sctx)
	if err != nil {
		t.Fatalf("AllPods in same sweep: %v", err)
	}
	if podLists != 1 {
		t.Fatalf("pod list count = %d, want 1 (no InvalidatePods re-list)", podLists)
	}
	for i := range podsInSweep {
		if podsInSweep[i].Name == terminal.Name {
			t.Fatal("tombstoned terminal pod still visible in same sweep")
		}
	}
}

func TestRolloutWedgeAllTypedReplicaSetsAndLazyPodsIn(t *testing.T) {
	t.Run("memoizes typed ReplicaSets and skips PodsIn when no Deployment is wedged", func(t *testing.T) {
		healthy := wedgeDep("apps", "healthy", 2, "Available", corev1.ConditionTrue, time.Hour)
		cs := fake.NewSimpleClientset(healthy)
		var rsLists, podLists int
		cs.PrependReactor("list", "replicasets", func(ktesting.Action) (bool, runtime.Object, error) {
			rsLists++
			return false, nil, nil
		})
		cs.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
			podLists++
			return false, nil, nil
		})
		d := probetest.NewDeps(cs, probetest.OpDyn())
		ch := &deploymentRolloutWedgeCheck{Deps: d}
		sctx := probetest.SweepCtx(ctx, ch.Deps)

		res := ch.Run(sctx)
		if !res.Pass || res.Infra != nil {
			t.Fatalf("healthy deployment should pass cleanly: %+v", res)
		}
		if _, err := ch.Deps.AllTypedReplicaSets(sctx); err != nil {
			t.Fatalf("AllTypedReplicaSets in sweep: %v", err)
		}
		if rsLists != 1 {
			t.Fatalf("replicasets list count = %d, want 1 (memoized via AllTypedReplicaSets)", rsLists)
		}
		if podLists != 0 {
			t.Fatalf("pods list count = %d, want 0 when no Deployment is wedged", podLists)
		}
	})

	t.Run("Stage 2 invalidates ReplicaSets after scaling down stale RS", func(t *testing.T) {
		dep := wedgeDep("apps", "staged", 3, "ProgressDeadlineExceeded",
			corev1.ConditionFalse, rolloutWedgeMinAge+time.Minute)
		dep.UID = "staged-uid"
		rsOld := wedgeRS("apps", "staged-old", "staged-uid", "staged", 0)
		rsOld.UID = "rs-old-uid"
		rsOld.Annotations = map[string]string{"deployment.kubernetes.io/revision": "1"}
		rsNew := wedgeRS("apps", "staged-new", "staged-uid", "staged", 0)
		rsNew.UID = "rs-new-uid"
		rsNew.Annotations = map[string]string{"deployment.kubernetes.io/revision": "2"}
		cs := fake.NewSimpleClientset(dep, rsOld, rsNew)
		var rsLists int
		cs.PrependReactor("list", "replicasets", func(ktesting.Action) (bool, runtime.Object, error) {
			rsLists++
			return false, nil, nil
		})
		d := probetest.NewDeps(cs, probetest.OpDyn())
		ch := &deploymentRolloutWedgeCheck{Deps: d}
		sctx := probetest.SweepCtx(ctx, ch.Deps)

		ch.Run(sctx)
		if _, err := ch.Deps.AllTypedReplicaSets(sctx); err != nil {
			t.Fatalf("AllTypedReplicaSets after Stage 2: %v", err)
		}
		if rsLists != 2 {
			t.Fatalf("replicasets list count = %d, want 2 (InvalidateReplicaSets called after Stage 2)", rsLists)
		}
	})

	t.Run("PodsIn error inside unwedgeDeployment surfaces as Infra error", func(t *testing.T) {
		dep := wedgeDep("apps", "wedged", 3, "ProgressDeadlineExceeded",
			corev1.ConditionFalse, rolloutWedgeMinAge+time.Minute)
		cs := fake.NewSimpleClientset(dep)
		cs.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("pod list failed")
		})
		d := probetest.NewDeps(cs, probetest.OpDyn())
		ch := &deploymentRolloutWedgeCheck{Deps: d}
		res := ch.Run(probetest.SweepCtx(ctx, ch.Deps))
		if res.Infra == nil || !strings.Contains(res.Infra.Error(), "list pods") {
			t.Fatalf("expected Infra error wrapping list pods, got %+v", res)
		}
	})

	t.Run("AllTypedReplicaSets wire request uses ResourceVersion=0", func(t *testing.T) {
		var rsRV string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case strings.HasSuffix(r.URL.Path, "/deployments"):
				_, _ = w.Write([]byte(`{"apiVersion":"apps/v1","kind":"DeploymentList","items":[]}`))
			case strings.HasSuffix(r.URL.Path, "/replicasets"):
				rsRV = r.URL.Query().Get("resourceVersion")
				_, _ = w.Write([]byte(`{"apiVersion":"apps/v1","kind":"ReplicaSetList","items":[]}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()
		cs, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL})
		if err != nil {
			t.Fatal(err)
		}
		d := probetest.NewDeps(cs, probetest.OpDyn())
		ch := &deploymentRolloutWedgeCheck{Deps: d}
		res := ch.Run(probetest.SweepCtx(ctx, ch.Deps))
		if !res.Pass || res.Infra != nil {
			t.Fatalf("unexpected result: %+v", res)
		}
		if rsRV != "0" {
			t.Fatalf("replicasets resourceVersion = %q, want \"0\"", rsRV)
		}
	})
}

func TestRolloutWedgeStage3GateOrderingRefundAndReservation(t *testing.T) {
	fluxManaged := []metav1.ManagedFieldsEntry{{
		Manager:    "kustomize-controller",
		Operation:  metav1.ManagedFieldsOperationApply,
		APIVersion: "apps/v1",
	}}

	t.Run("cooldown suppresses FluxPatchGate sightings", func(t *testing.T) {
		heal.ConfigureFluxConflictLoop(2, 2*time.Hour)
		var hookCalls int
		heal.SetFluxConflictHook(func(heal.FluxConflictSignal) { hookCalls++ })
		t.Cleanup(func() {
			heal.ConfigureFluxConflictLoop(0, 0)
			heal.SetFluxConflictHook(nil)
		})

		dep := wedgeDep("apps", "gitops-cool", 3, "ProgressDeadlineExceeded",
			corev1.ConditionFalse, rolloutWedgeMinAge+time.Minute)
		dep.ManagedFields = fluxManaged
		cs := fake.NewSimpleClientset(dep)
		d := probetest.NewDeps(cs, probetest.OpDyn())
		ch := &deploymentRolloutWedgeCheck{Deps: d}
		base := time.Now()

		// Stamp cooldown before sweeps.
		ck := probefw.SelfHealKey(CheckNameDeploymentRolloutWedge, "apps/gitops-cool")
		ch.nudgeHeals.Stamp(ck, base)

		probetest.FreezeNow(d, base.Add(time.Minute))
		ch.Run(probetest.SweepCtx(ctx, ch.Deps))
		probetest.FreezeNow(d, base.Add(2*time.Minute))
		ch.Run(probetest.SweepCtx(ctx, ch.Deps))

		if hookCalls != 0 {
			t.Fatalf("FluxConflictHook fired %d times during cooldown, want 0", hookCalls)
		}
		if templateNudged(t, cs, "apps", "gitops-cool") {
			t.Fatal("deployment nudged while on cooldown")
		}

		// Past cooldown: 1st unblocked nudge must succeed at LOOP_MAX=2.
		probetest.FreezeNow(d, base.Add(rolloutWedgeNudgeCooldown+time.Minute))
		ch.Run(probetest.SweepCtx(ctx, ch.Deps))
		if !templateNudged(t, cs, "apps", "gitops-cool") {
			t.Fatal("post-cooldown nudge blocked — cooldown leaked phantom FluxPatchGate sightings")
		}
	})

	t.Run("TryReserveWorkloadKey denial refunds budget and skips FluxPatchGate", func(t *testing.T) {
		heal.ConfigureBudget(1, time.Hour)
		heal.ConfigureFluxConflictLoop(2, 30*time.Minute)
		t.Cleanup(func() {
			heal.ConfigureBudget(0, 0)
			heal.ConfigureFluxConflictLoop(0, 0)
		})

		depReserved := wedgeDep("apps", "a-reserved", 3, "ProgressDeadlineExceeded",
			corev1.ConditionFalse, rolloutWedgeMinAge+time.Minute)
		depReserved.ManagedFields = fluxManaged
		depFree := wedgeDep("apps", "b-free", 3, "ProgressDeadlineExceeded",
			corev1.ConditionFalse, rolloutWedgeMinAge+time.Minute)
		cs := fake.NewSimpleClientset(depReserved, depFree)
		d := probetest.NewDeps(cs, probetest.OpDyn())
		ch := &deploymentRolloutWedgeCheck{Deps: d}
		base := time.Now()
		probetest.FreezeNow(d, base)

		sctx := probetest.SweepCtx(ctx, ch.Deps)
		if !kube.TryReserveWorkloadKey(sctx, "apps/Deployment/a-reserved") {
			t.Fatal("failed to pre-reserve workload key")
		}
		ch.Run(sctx)

		if templateNudged(t, cs, "apps", "a-reserved") {
			t.Fatal("pre-reserved deployment was nudged")
		}
		if !templateNudged(t, cs, "apps", "b-free") {
			t.Fatal("sibling deployment b-free did not get refunded budget grant")
		}

		// Verify FluxPatchGate was NOT stamped for a-reserved while reserved.
		heal.ConfigureBudget(1, time.Hour)
		sctx2 := probetest.SweepCtx(ctx, ch.Deps)
		probetest.FreezeNow(d, base.Add(time.Minute))
		ch.Run(sctx2)
		if !templateNudged(t, cs, "apps", "a-reserved") {
			t.Fatal("a-reserved failed on next sweep — reservation denial leaked FluxPatchGate hit")
		}
	})

	t.Run("FluxPatchGate denial releases workload key, refunds budget, and uses duty-prefixed key", func(t *testing.T) {
		heal.ConfigureBudget(1, time.Hour)
		heal.ConfigureFluxConflictLoop(2, 30*time.Minute)
		t.Cleanup(func() {
			heal.ConfigureBudget(0, 0)
			heal.ConfigureFluxConflictLoop(0, 0)
		})

		depFlux := wedgeDep("apps", "a-flux", 3, "ProgressDeadlineExceeded",
			corev1.ConditionFalse, rolloutWedgeMinAge+time.Minute)
		depFlux.ManagedFields = fluxManaged
		depFree := wedgeDep("apps", "b-free", 3, "ProgressDeadlineExceeded",
			corev1.ConditionFalse, rolloutWedgeMinAge+time.Minute)
		depIsolated := wedgeDep("apps", "c-iso", 3, "ProgressDeadlineExceeded",
			corev1.ConditionFalse, rolloutWedgeMinAge+time.Minute)
		depIsolated.ManagedFields = fluxManaged
		base := time.Now()

		// Pre-exhaust a-flux under the duty-prefixed key (1 hit at max=2 -> next call denies),
		// and exhaust c-iso ONLY under sibling/legacy keys (must NOT block c-iso).
		heal.FluxPatchGate("deployment", depFlux, CheckNameDeploymentRolloutWedge+":apps/a-flux", base)
		heal.FluxPatchGate("deployment", depIsolated, "other-duty:apps/c-iso", base)
		heal.FluxPatchGate("deployment", depIsolated, "apps/c-iso", base)

		// First sweep: a-flux denied by FluxPatchGate -> releases key + refunds grant -> b-free nudged.
		cs1 := fake.NewSimpleClientset(depFlux, depFree)
		d1 := probetest.NewDeps(cs1, probetest.OpDyn())
		ch1 := &deploymentRolloutWedgeCheck{Deps: d1}
		probetest.FreezeNow(d1, base)
		sctx1 := probetest.SweepCtx(ctx, ch1.Deps)
		ch1.Run(sctx1)

		if templateNudged(t, cs1, "apps", "a-flux") {
			t.Fatal("a-flux must be blocked by FluxPatchGate")
		}
		if !kube.TryReserveWorkloadKey(sctx1, "apps/Deployment/a-flux") {
			t.Fatal("FluxPatchGate denial leaked workload key reservation")
		}
		if !templateNudged(t, cs1, "apps", "b-free") {
			t.Fatal("sibling b-free did not receive refunded grant after FluxPatchGate denial")
		}

		// Second check: c-iso is unaffected by sibling/bare keys (budget=2 or fresh budget).
		heal.ConfigureBudget(1, time.Hour)
		cs2 := fake.NewSimpleClientset(depIsolated)
		d2 := probetest.NewDeps(cs2, probetest.OpDyn())
		ch2 := &deploymentRolloutWedgeCheck{Deps: d2}
		probetest.FreezeNow(d2, base)
		ch2.Run(probetest.SweepCtx(ctx, ch2.Deps))
		if !templateNudged(t, cs2, "apps", "c-iso") {
			t.Fatal("c-iso was wrongly blocked by sibling/unprefixed FluxPatchGate key")
		}
	})

	t.Run("Stage 3 Patch failure releases workload key without refunding budget", func(t *testing.T) {
		heal.ConfigureBudget(1, time.Hour)
		t.Cleanup(func() { heal.ConfigureBudget(0, 0) })

		depFail := wedgeDep("apps", "a-fail", 3, "ProgressDeadlineExceeded",
			corev1.ConditionFalse, rolloutWedgeMinAge+time.Minute)
		depOther := wedgeDep("apps", "b-other", 3, "ProgressDeadlineExceeded",
			corev1.ConditionFalse, rolloutWedgeMinAge+time.Minute)
		cs := fake.NewSimpleClientset(depFail, depOther)
		cs.PrependReactor("patch", "deployments", func(action ktesting.Action) (bool, runtime.Object, error) {
			pa := action.(ktesting.PatchAction)
			if pa.GetName() == "a-fail" {
				return true, nil, errors.New("apiserver patch error")
			}
			return false, nil, nil
		})
		d := probetest.NewDeps(cs, probetest.OpDyn())
		ch := &deploymentRolloutWedgeCheck{Deps: d}
		probetest.FreezeNow(d, time.Now())
		sctx := probetest.SweepCtx(ctx, ch.Deps)
		ch.Run(sctx)

		if !kube.TryReserveWorkloadKey(sctx, "apps/Deployment/a-fail") {
			t.Fatal("Patch failure leaked workload key reservation")
		}
		if templateNudged(t, cs, "apps", "b-other") {
			t.Fatal("failed Patch must NOT refund budget grant to sibling b-other")
		}
	})
}
