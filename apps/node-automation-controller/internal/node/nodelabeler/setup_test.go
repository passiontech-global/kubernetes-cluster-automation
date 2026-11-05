// setup_test.go — registration coverage for the node-labeler module's
// Setup function (see testutil.StubManager for the
// registration-capture contract).
package nodelabeler

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

// Builder-based: .Complete() resolves the For() GVK via the real
// scheme, builds a controller through controller.New and lands it in
// mgr.Add.
func TestSetupRegistersController(t *testing.T) {
	t.Setenv("NODE_LABELER_CONFIG_PATH", "labels.txt")
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
// request. Drives the exact MapFunc the watch installs
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
	if item.Name != "node-labeler-sweep" || item.Namespace != "" {
		t.Fatalf("enqueued request = %+v, want fixed key %q", item,
			"node-labeler-sweep")
	}
	q.Done(item)
}

// The node-labeler predicate (nodeLabelChanges — the exact
// predicate.Funcs Setup installs) is the bash
// jqFilter='.metadata.labels': only label drift fires, everything
// else is dropped.
func TestSetupNodeLabelerPredicate(t *testing.T) {
	p := nodeLabelChanges

	if !p.Create(event.CreateEvent{Object: testutil.Node("n1", corev1.ConditionTrue, nil)}) {
		t.Fatal("node add did not fire")
	}
	if !p.Delete(event.DeleteEvent{Object: testutil.Node("n1", corev1.ConditionTrue, nil)}) {
		t.Fatal("node delete did not fire")
	}
	if !p.Generic(event.GenericEvent{Object: testutil.Node("n1", corev1.ConditionTrue, nil)}) {
		t.Fatal("generic event did not fire")
	}

	// Missing objects never fire.
	if p.Update(testutil.UpdateEvent(nil, testutil.Node("n1", corev1.ConditionTrue, nil))) {
		t.Fatal("nil ObjectOld fired")
	}
	if p.Update(testutil.UpdateEvent(testutil.Node("n1", corev1.ConditionTrue, nil), nil)) {
		t.Fatal("nil ObjectNew fired")
	}

	labeled := testutil.Node("n1", corev1.ConditionTrue,
		map[string]string{"passiontech.dev/workload": "app"})
	if !p.Update(testutil.UpdateEvent(testutil.Node("n1", corev1.ConditionTrue, nil), labeled)) {
		t.Fatal("label drift did not fire")
	}
	if p.Update(testutil.UpdateEvent(labeled, labeled)) {
		t.Fatal("identical labels fired")
	}
}

// The cilium-taint-reaper Node predicate only fires on changes to the
// agent-not-ready taint projection; the enabled variant additionally
// watches kube-system cilium Pods and collapses them onto the same
// fixed sweep key.
