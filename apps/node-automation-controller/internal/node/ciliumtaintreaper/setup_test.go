// setup_test.go — registration coverage for the cilium-taint-reaper module's
// Setup function (see testutil.StubManager for the
// registration-capture contract).
package ciliumtaintreaper

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
)

// The reaper skips mgr.Add entirely when Deps.Disabled is stamped
// (setupModules resolves CILIUM_TAINT_REAPER_ENABLED) — no informer,
// no RequeueAfter loop, no periodic LIST against the apiserver.
func TestSetupDisabled(t *testing.T) {
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Mgr: m, CS: fake.NewSimpleClientset(), Disabled: true}); err != nil {
		t.Fatalf("disabled setup must return nil, got %v", err)
	}
	if len(m.Added) != 0 {
		t.Fatalf("disabled module registered %d runnables, want 0", len(m.Added))
	}
}

// Builder-based: .Complete() resolves the For() GVK via the real
// scheme, builds a controller through controller.New and lands it in
// mgr.Add — enabled registers two sources (.Watches on Nodes + cilium
// Pods), still one controller runnable. Zero-value Deps.Disabled =
// gate-on (the opt-in CILIUM_TAINT_REAPER_ENABLED wiring is covered by
// setupModules' registry tests in cmd/manager).
func TestSetupRegistersController(t *testing.T) {
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Mgr: m, CS: fake.NewSimpleClientset()}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if len(m.Added) != 1 {
		t.Fatalf("builder registered %d runnables, want 1", len(m.Added))
	}
}

// The module's Node watch maps every node event onto its fixed sweep
// key — a multi-node burst must set-collapse to a single queued
// request (the reconcile ignores the request name; only the dedup
// contract matters). Drives the exact MapFunc the watch installs
// (nodeSweepRequests) through a real workqueue.
func TestSetupSweepFixedKey(t *testing.T) {
	h := handler.EnqueueRequestsFromMapFunc(nodeSweepRequests)
	q := workqueue.NewTypedRateLimitingQueue(
		workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	defer q.ShutDown()
	for _, name := range []string{"n1", "n2", "n3"} {
		h.Create(context.Background(), event.CreateEvent{
			Object: testutil.Node(name, corev1.ConditionTrue, nil)}, q)
	}
	if q.Len() != 1 {
		t.Fatalf("3-node burst enqueued %d requests, want 1 (set-collapse)", q.Len())
	}
	item, _ := q.Get()
	if item.Name != "cilium-taint-reaper-sweep" || item.Namespace != "" {
		t.Fatalf("enqueued request = %+v, want fixed key %q", item,
			"cilium-taint-reaper-sweep")
	}
	q.Done(item)
}

// The cilium-taint-reaper Node predicate only fires on changes to the
// agent-not-ready taint projection; the pod mapfunc collapses
// scheduled kube-system cilium Pods onto the same fixed sweep key.
// These are the exact vars the Setup watch wiring installs — the
// number/shape of registered watch sources is no longer asserted here
// (it required reaching into controller-runtime internals).
func TestSetupCiliumTaintReaperWatches(t *testing.T) {
	p := ciliumTaintChanges
	if !p.Create(event.CreateEvent{Object: testutil.Node("n1", corev1.ConditionTrue, nil)}) {
		t.Fatal("node add did not fire")
	}
	if !p.Delete(event.DeleteEvent{Object: testutil.Node("n1", corev1.ConditionTrue, nil)}) {
		t.Fatal("node delete did not fire")
	}
	if !p.Generic(event.GenericEvent{Object: testutil.Node("n1", corev1.ConditionTrue, nil)}) {
		t.Fatal("generic event did not fire")
	}
	if !p.Update(testutil.UpdateEvent(&corev1.Pod{}, &corev1.Pod{})) {
		t.Fatal("non-Node update did not fire")
	}
	old := testutil.Node("n1", corev1.ConditionTrue, nil)
	if p.Update(testutil.UpdateEvent(old, testutil.Node("n1", corev1.ConditionFalse, nil))) {
		t.Fatal("unrelated status change fired — heartbeat storms would sweep every 20s")
	}
	if !p.Update(testutil.UpdateEvent(old,
		testutil.Node("n1", corev1.ConditionTrue, nil, ciliumStaleTaint))) {
		t.Fatal("agent-not-ready taint change did not fire")
	}

	// The Node watch itself enqueues the fixed sweep key — identical
	// NamespacedNames are what the workqueue set collapses, so it must
	// be the SAME key the pod watch below produces.
	nodeH := handler.EnqueueRequestsFromMapFunc(nodeSweepRequests)
	nq := workqueue.NewTypedRateLimitingQueue(
		workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	defer nq.ShutDown()
	nodeH.Create(context.Background(), event.CreateEvent{
		Object: testutil.Node("n1", corev1.ConditionTrue, nil)}, nq)
	nodeH.Create(context.Background(), event.CreateEvent{
		Object: testutil.Node("n2", corev1.ConditionFalse, nil)}, nq)
	if nq.Len() != 1 {
		t.Fatalf("2-node burst enqueued %d requests, want 1 (set-collapse)", nq.Len())
	}
	nitem, _ := nq.Get()
	if nitem.Name != "cilium-taint-reaper-sweep" || nitem.Namespace != "" {
		t.Fatalf("node event enqueued %+v, want fixed sweep key", nitem)
	}
	nq.Done(nitem)

	// The pod watch maps a scheduled cilium pod onto the same fixed
	// sweep key (it used to enqueue the pod's spec.nodeName).
	h := handler.EnqueueRequestsFromMapFunc(ciliumPodSweepRequests)
	q := workqueue.NewTypedRateLimitingQueue(
		workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	defer q.ShutDown()
	// The pod watch enqueues the same fixed sweep key as the Node
	// watch — the reconcile ignores the request name, so collapsing
	// pod events onto it keeps one queued item per trigger burst.
	h.Create(context.Background(), event.CreateEvent{
		Object: ciliumPod("n7", corev1.PodRunning, true)}, q)
	if q.Len() != 1 {
		t.Fatalf("pod event enqueued %d requests, want 1", q.Len())
	}
	item, _ := q.Get()
	if item.Name != "cilium-taint-reaper-sweep" || item.Namespace != "" {
		t.Fatalf("enqueued request = %+v, want fixed sweep key", item)
	}
	q.Done(item)

	// An unscheduled pod (no spec.nodeName) enqueues nothing.
	h.Create(context.Background(), event.CreateEvent{Object: &corev1.Pod{}}, q)
	if q.Len() != 0 {
		t.Fatalf("nodeless pod enqueued %d requests, want 0", q.Len())
	}
}

// Each sweep module's Node watch maps every node event onto its own
// fixed key — a multi-node burst must set-collapse to a single queued
// request, and the keys must stay stable (the reconcile ignores the
// request name; only the dedup contract matters).
