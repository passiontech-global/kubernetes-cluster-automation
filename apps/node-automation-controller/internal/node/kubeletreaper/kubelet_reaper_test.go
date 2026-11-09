// kubelet_reaper_test.go — the taint action's per-target
// non-convergent circuit breaker: an open breaker defers the taint
// (sweep stays a nil-error defer), a fresh circuit taints as before,
// and a healthy probe clears the node's history.
package kubeletreaper

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// krStaleNode builds a worker whose Ready heartbeat is far older than
// kubeletReaperHBStaleS — the taint decision's precondition.
func krStaleNode(name string) *corev1.Node {
	n := testutil.Node(name, corev1.ConditionTrue, nil)
	n.Status.Conditions[0].LastHeartbeatTime =
		metav1.NewTime(time.Now().Add(-10 * time.Minute))
	return n
}

// krReaper builds the sweep fixture: direct clientset, pinned clock,
// the registry ops name as the breaker's module label.
func krReaper(cs *fake.Clientset, now time.Time) *kubeletReaper {
	return &kubeletReaper{
		cs:    cs,
		queue: "kubelet-liveness-reaper",
		now:   shared.NewClock(func() time.Time { return now }),
	}
}

// krConfigureBreaker arms the package-global breaker with a tight
// window and pre-charges (module,node) to its limit — the circuit is
// open before the sweep runs. Cleaning up drops the global state so
// no sibling test inherits it.
func krConfigureBreaker(t *testing.T, module, node string, now time.Time) {
	t.Helper()
	heal.ConfigureTargetBreaker(3, time.Hour)
	t.Cleanup(func() { heal.ConfigureTargetBreaker(0, 0) })
	for range 3 {
		heal.TryAcquireTarget(module, node, now)
	}
}

// A node the breaker already opened for defers its taint: nothing
// lands on the node, and the sweep absorbs the defer without an
// error (no IncError loop over the queue).
func TestKubeletReaperDefersTaintUnderOpenCircuit(t *testing.T) {
	n := krStaleNode("w1")
	cs := fake.NewSimpleClientset(n)
	now := time.Now()
	krConfigureBreaker(t, "kubelet-liveness-reaper", "w1", now)
	r := krReaper(cs, now)
	if err := r.sweep(context.Background(), n, false); err != nil {
		t.Fatalf("open circuit must defer, not error: %v", err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("taint applied while the target circuit is open")
	}
}

// The same decision on a fresh circuit taints as before — the
// breaker never blocks first-line remediation of a node it has not
// already acted on.
func TestKubeletReaperFreshCircuitTaints(t *testing.T) {
	n := krStaleNode("w1")
	cs := fake.NewSimpleClientset(n)
	now := time.Now()
	heal.ConfigureTargetBreaker(3, time.Hour)
	t.Cleanup(func() { heal.ConfigureTargetBreaker(0, 0) })
	r := krReaper(cs, now)
	if err := r.sweep(context.Background(), n, false); err != nil {
		t.Fatal(err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("fresh circuit did not taint the stale-kubelet node")
	}
}

// A healthy probe clears the node's breaker history: after three
// taints and a recovery, the breaker grants again — a kubelet
// restart ends the episode instead of banking against the next one.
func TestKubeletReaperHealthyProbeClearsHistory(t *testing.T) {
	n := krStaleNode("w1")
	cs := fake.NewSimpleClientset(n)
	now := time.Now()
	krConfigureBreaker(t, "kubelet-liveness-reaper", "w1", now)
	r := krReaper(cs, now)
	if err := r.sweep(context.Background(), n, true); err != nil {
		t.Fatal(err)
	}
	if ok, _ := heal.TryAcquireTarget("kubelet-liveness-reaper", "w1",
		now.Add(time.Minute)); !ok {
		t.Fatal("healthy probe did not clear the node's breaker history")
	}
}

// ---------------------------------------------------------------------------
// run() — the sweep driver: parallel probes, the zero-success abort,
// control-plane skip, and per-node error absorption.
// ---------------------------------------------------------------------------

// krRunReaper builds the reaper with a stubbed probeFn — the apiserver
// REST path the fake clientset cannot serve.
func krRunReaper(cs *fake.Clientset, now time.Time,
	probe func(ctx context.Context, node string) bool) *kubeletReaper {

	r := krReaper(cs, now)
	r.probeFn = probe
	return r
}

// A node census failure is the run's only hard error — the periodic
// meters it through the returned error.
func TestKubeletReaperRunListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("apiserver down")
		})
	r := krRunReaper(cs, time.Now(), func(context.Context, string) bool { return true })
	if err := r.run(context.Background()); err == nil {
		t.Fatal("node list failure must return an error")
	}
}

// Zero successful probes means the probe PATH is broken (apiserver or
// konnectivity), not that every kubelet died — the run aborts before
// any taint decision rather than mass-tainting the fleet.
func TestKubeletReaperRunAbortsWhenNoProbeSucceeds(t *testing.T) {
	cp := testutil.Node("cp1", corev1.ConditionTrue,
		map[string]string{"node-role.kubernetes.io/control-plane": ""})
	w1 := krStaleNode("w1")
	cs := fake.NewSimpleClientset(cp, w1)
	var probed []string
	var mu sync.Mutex
	r := krRunReaper(cs, time.Now(),
		func(_ context.Context, node string) bool {
			mu.Lock()
			probed = append(probed, node)
			mu.Unlock()
			return false
		})
	if err := r.run(context.Background()); err != nil {
		t.Fatalf("all-fail run must absorb, not error: %v", err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("tainted on a dead probe path — the mass-taint guard failed")
	}
	for _, n := range probed {
		if n == "cp1" {
			t.Fatal("control-plane node was probed — k0s CPs run no kubelet")
		}
	}
	if len(probed) != 1 || probed[0] != "w1" {
		t.Fatalf("probed = %v, want [w1]", probed)
	}
}

// The healthy/dead split: a serving kubelet clears its marks, a dead
// one with a stale heartbeat gets the NoSchedule taint — and the
// control-plane node is never probed nor swept.
func TestKubeletReaperRunTaintsOnlyTheDeadWorker(t *testing.T) {
	cp := testutil.Node("cp1", corev1.ConditionTrue,
		map[string]string{"node-role.kubernetes.io/control-plane": ""})
	wOK := testutil.Node("w-ok", corev1.ConditionTrue, nil)
	wDead := krStaleNode("w-dead")
	wDead.Spec.Taints = []corev1.Taint{{
		Key: kubeletReaperTaint, Effect: corev1.TaintEffectNoSchedule}}
	wFresh := krStaleNode("w-fresh") // probe fails but heartbeat is fresh -> skip
	wFresh.Status.Conditions[0].LastHeartbeatTime =
		metav1.NewTime(time.Now())
	cs := fake.NewSimpleClientset(cp, wOK, wDead, wFresh)
	now := time.Now()
	r := krRunReaper(cs, now,
		func(_ context.Context, node string) bool { return node == "w-ok" })
	if err := r.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	// w-dead already carried the taint -> kept (heartbeat stale).
	if !kube.HasTaint(testutil.GetNode(t, cs, "w-dead").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("stale-heartbeat dead worker lost its taint")
	}
	// w-fresh: probe failed but the heartbeat proves life -> no taint.
	if kube.HasTaint(testutil.GetNode(t, cs, "w-fresh").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("fresh-heartbeat worker tainted — broken proxy path punished")
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "w-ok").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("healthy worker tainted")
	}
}

// A per-node sweep failure is absorbed — logged, IncError'd, and the
// remaining nodes still get their decision (the bash loop's
// best-effort contract).
func TestKubeletReaperRunAbsorbsSweepErrors(t *testing.T) {
	wBad := krStaleNode("w-bad")
	wDead := krStaleNode("w-dead")
	cs := fake.NewSimpleClientset(wBad, wDead)
	// The re-Get inside sweep fails for w-bad — but only the FIRST
	// one, so the test's own verification Get below still reads the
	// node back.
	badGets := 0
	cs.PrependReactor("get", "nodes",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			if action.(ktesting.GetAction).GetName() == "w-bad" {
				badGets++
				if badGets == 1 {
					return true, nil, errors.New("get boom")
				}
			}
			return false, nil, nil
		})
	// One healthy node keeps anyOK true so the sweep runs at all —
	// zero successes would abort before any per-node decision.
	wOK := testutil.Node("w-ok", corev1.ConditionTrue, nil)
	if _, err := cs.CoreV1().Nodes().Create(context.Background(), wOK, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	r := krRunReaper(cs, time.Now(),
		func(_ context.Context, node string) bool { return node == "w-ok" })
	if err := r.run(context.Background()); err != nil {
		t.Fatalf("sweep error must be absorbed into a nil return: %v", err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "w-dead").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("w-dead not tainted — the w-bad failure blocked the sweep")
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "w-bad").Spec.Taints, kubeletReaperTaint) {
		t.Fatal("w-bad tainted despite its get failing")
	}
}
