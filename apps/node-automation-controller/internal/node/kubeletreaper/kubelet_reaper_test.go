// kubelet_reaper_test.go — the taint action's per-target
// non-convergent circuit breaker: an open breaker defers the taint
// (sweep stays a nil-error defer), a fresh circuit taints as before,
// and a healthy probe clears the node's history.
package kubeletreaper

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

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
