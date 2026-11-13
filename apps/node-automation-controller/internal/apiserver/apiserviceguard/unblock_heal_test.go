// unblock_heal_test.go — coverage for the unblock healer's
// deleteBackingPods eviction loop (apiservice-guard): the maintenance
// gate outcomes, the PDB-refusal deferral, eviction failures and the
// per-APIService pod cap.
package apiserviceguard

import (
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// backingTarget builds one evictable backend pod — the UID is what
// the eviction's DeleteOptions precondition carries.
func backingTarget(ns, name string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name, UID: types.UID("u-" + name),
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func backingTargets(ns string, names ...string) []corev1.Pod {
	out := make([]corev1.Pod, 0, len(names))
	for _, n := range names {
		out = append(out, backingTarget(ns, n))
	}
	return out
}

// The maintenance gate is the FIRST leg of every eviction attempt: a
// verdict that cannot be produced (the cordon-signal node list
// fails) fails the whole pass closed — one IncError, an early
// return, and not a single eviction attempted.
func TestDeleteBackingPodsUnverifiableStopsPass(t *testing.T) {
	targets := backingTargets("kube-system", "ms-0", "ms-1")
	cs := fake.NewSimpleClientset(&targets[0], &targets[1])
	testutil.EmulateEviction(cs)
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	g := asgGuard(cs, asgDynFake())
	g.queue = "apiservice-guard"
	u := &unblockHealer{}

	before := testutil.QueueErrorCount(t, "apiservice-guard")
	if deleted := u.deleteBackingPods(ctx, g, "v1beta1.metrics.k8s.io",
		targets, time.Now()); deleted != 0 {
		t.Fatalf("deleted = %d, want 0 — unverifiable must stop the pass", deleted)
	}
	for _, name := range []string{"ms-0", "ms-1"} {
		if !testutil.PodExists(t, cs, "kube-system", name) {
			t.Fatalf("pod %s evicted while the maintenance check was unverifiable", name)
		}
	}
	if got := testutil.QueueErrorCount(t, "apiservice-guard") - before; got != 1 {
		t.Fatalf("queue errors delta = %v, want 1 — fail closed is counted once", got)
	}
}

// A held maintenance mutex (an actively cordoned node) defers each
// target WITHOUT counting an error — a normal defer, not a failure.
func TestDeleteBackingPodsMaintenanceDefers(t *testing.T) {
	targets := backingTargets("kube-system", "ms-0")
	ts := metav1.NewTime(time.Now())
	cordoned := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "w1"},
		Spec: corev1.NodeSpec{
			Unschedulable: true,
			Taints: []corev1.Taint{{
				Key: kube.UnschedulableTaintKey, TimeAdded: &ts}},
		},
	}
	cs := fake.NewSimpleClientset(&targets[0], cordoned)
	testutil.EmulateEviction(cs)
	g := asgGuard(cs, asgDynFake())
	g.queue = "apiservice-guard"
	u := &unblockHealer{}

	before := testutil.QueueErrorCount(t, "apiservice-guard")
	if deleted := u.deleteBackingPods(ctx, g, "v1beta1.metrics.k8s.io",
		targets, time.Now()); deleted != 0 {
		t.Fatalf("deleted = %d, want 0 — a held mutex defers every target", deleted)
	}
	if !testutil.PodExists(t, cs, "kube-system", "ms-0") {
		t.Fatal("pod evicted while maintenance was in flight")
	}
	if got := testutil.QueueErrorCount(t, "apiservice-guard") - before; got != 0 {
		t.Fatalf("queue errors delta = %v, want 0 — a held mutex is a defer, not an error", got)
	}
}

// A PDB refusal (HTTP 429) keeps the pod and counts nothing — the
// workload is at its replica floor, so the DEFER is logged and the
// sweep moves to the next target instead of treating it as failure.
func TestDeleteBackingPodsPDBRefusedSkips(t *testing.T) {
	targets := backingTargets("kube-system", "ms-0", "ms-1")
	cs := fake.NewSimpleClientset(&targets[0], &targets[1])
	cs.PrependReactor("create", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			ca, ok := a.(ktesting.CreateAction)
			if !ok || ca.GetSubresource() != "eviction" {
				return false, nil, nil
			}
			return true, nil, apierrors.NewTooManyRequests(
				"pdb allows no disruptions", 0)
		})
	g := asgGuard(cs, asgDynFake())
	g.queue = "apiservice-guard"
	u := &unblockHealer{}

	before := testutil.QueueErrorCount(t, "apiservice-guard")
	if deleted := u.deleteBackingPods(ctx, g, "v1beta1.metrics.k8s.io",
		targets, time.Now()); deleted != 0 {
		t.Fatalf("deleted = %d, want 0 — refused evictions deliver no heal", deleted)
	}
	for _, name := range []string{"ms-0", "ms-1"} {
		if !testutil.PodExists(t, cs, "kube-system", name) {
			t.Fatalf("PDB-refused pod %s was evicted anyway", name)
		}
	}
	if got := testutil.QueueErrorCount(t, "apiservice-guard") - before; got != 0 {
		t.Fatalf("queue errors delta = %v, want 0 — refusal is a deferral, never an error", got)
	}
}

// A non-NotFound eviction failure is metered and tolerated per pod —
// the sweep IncErrors and moves on; a NotFound race is a quiet no-op.
func TestDeleteBackingPodsEvictionErrorsCounted(t *testing.T) {
	targets := backingTargets("kube-system", "ms-0", "ms-1", "ms-2")
	cs := fake.NewSimpleClientset(&targets[0], &targets[1], &targets[2])
	cs.PrependReactor("create", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			ca, ok := a.(ktesting.CreateAction)
			if !ok || ca.GetSubresource() != "eviction" {
				return false, nil, nil
			}
			ev := ca.GetObject().(*policyv1.Eviction)
			if ev.Name == "ms-1" {
				return true, nil, apierrors.NewNotFound(
					corev1.Resource("pods"), "ms-1")
			}
			return true, nil, errors.New("eviction api down")
		})
	g := asgGuard(cs, asgDynFake())
	g.queue = "apiservice-guard"
	u := &unblockHealer{}

	before := testutil.QueueErrorCount(t, "apiservice-guard")
	if deleted := u.deleteBackingPods(ctx, g, "v1beta1.metrics.k8s.io",
		targets, time.Now()); deleted != 0 {
		t.Fatalf("deleted = %d, want 0 — no eviction landed", deleted)
	}
	// Two generic errors counted; the NotFound race is quiet.
	if got := testutil.QueueErrorCount(t, "apiservice-guard") - before; got != 2 {
		t.Fatalf("queue errors delta = %v, want 2 — ms-0/ms-2 failures, ms-1 NotFound quiet", got)
	}
	for _, name := range []string{"ms-0", "ms-1", "ms-2"} {
		if !testutil.PodExists(t, cs, "kube-system", name) {
			t.Fatalf("pod %s evicted although every eviction failed", name)
		}
	}
}

// apiServiceUnblockSweepCap bounds delivered evictions per sweep:
// even a single wedged APIService with more live targets than the
// cap restarts exactly one pod — the rest wait for the next sweep.
func TestDeleteBackingPodsCap(t *testing.T) {
	var names []string
	for i := 0; i < apiServiceUnblockSweepCap+2; i++ {
		names = append(names, "ms-"+string(rune('a'+i)))
	}
	targets := backingTargets("kube-system", names...)
	objs := make([]runtime.Object, 0, len(targets))
	for i := range targets {
		objs = append(objs, &targets[i])
	}
	cs := fake.NewSimpleClientset(objs...)
	testutil.EmulateEviction(cs)
	g := asgGuard(cs, asgDynFake())
	g.queue = "apiservice-guard"
	u := &unblockHealer{}

	if deleted := u.deleteBackingPods(ctx, g, "v1beta1.metrics.k8s.io",
		targets, time.Now()); deleted != apiServiceUnblockSweepCap {
		t.Fatalf("deleted = %d, want the %d-pod sweep cap",
			deleted, apiServiceUnblockSweepCap)
	}
	// Every target past the first delivered eviction must survive —
	// the sweep cap, not a failure.
	alive := 0
	for _, name := range names {
		if testutil.PodExists(t, cs, "kube-system", name) {
			alive++
		}
	}
	if alive != len(names)-apiServiceUnblockSweepCap {
		t.Fatalf("alive pods = %d, want %d — evictions past the sweep cap landed",
			alive, len(names)-apiServiceUnblockSweepCap)
	}
}

// A cooled-down APIService skips up front in healCandidate without
// resolving targets or consuming a fleet budget token.
func TestHealCandidateCooledDownSkipsBeforeBudget(t *testing.T) {
	heal.ConfigureBudget(1, time.Hour)
	t.Cleanup(func() { heal.ConfigureBudget(0, 0) })

	now := time.Now()
	cs := fake.NewSimpleClientset()
	g := asgGuard(cs, asgDynFake())
	u := &unblockHealer{}
	u.unblocked.Stamp("v1beta1.metrics.k8s.io", now.Add(-time.Minute))

	item := &unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "v1beta1.metrics.k8s.io"},
	}}
	if u.healCandidate(ctx, &apiServiceSnapshot{g: g}, item, "metrics.k8s.io",
		&u.unblocked, apiServiceUnblockCooldown, now, nil) {
		t.Fatal("cooled-down healCandidate returned true")
	}

	proceed, unverifiable := heal.Gate(ctx, logr.Discard(), nil, cs, asgDynFake(), "probe", now)
	if !proceed || unverifiable {
		t.Fatalf("cooled-down healCandidate spent a budget token: Gate = (%v,%v)",
			proceed, unverifiable)
	}
}
