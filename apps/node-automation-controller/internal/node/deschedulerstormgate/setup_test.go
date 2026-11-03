// setup_test.go — registration coverage for the descheduler-storm-gate module's
// Setup function (see testutil.StubManager for the
// registration-capture contract).
package deschedulerstormgate

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
)

// Builder-based: .Complete() resolves the For() GVK via the real
// scheme, builds a controller through controller.New and lands it in
// mgr.Add.
func TestSetupRegistersController(t *testing.T) {
	m := testutil.NewStubManager()
	if err := Setup(m, fake.NewSimpleClientset(), testutil.StubDyn()); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if len(m.Added) != 1 {
		t.Fatalf("builder registered %d runnables, want 1", len(m.Added))
	}
}

// The module's Node watch maps every node event onto its fixed sweep
// key — a multi-node burst must set-collapse to a single queued
// request.
func TestSetupSweepFixedKey(t *testing.T) {
	m := testutil.NewStubManager()
	if err := Setup(m, fake.NewSimpleClientset(), testutil.StubDyn()); err != nil {
		t.Fatalf("setup: %v", err)
	}
	_, h := testutil.KindSource(t, testutil.ControllerWatches(t, m.Added[0])[0])
	if h == nil {
		t.Fatal("node watch has no event handler")
	}
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
	if item.Name != "descheduler-storm-gate-sweep" || item.Namespace != "" {
		t.Fatalf("enqueued request = %+v, want fixed key %q", item,
			"descheduler-storm-gate-sweep")
	}
	q.Done(item)
}

// The storm-gate For(Node) predicate must fire on node add/remove and
// on changes to the verdict inputs (condition statuses, taint keys) —
// but not on kubelet heartbeat churn.
func TestSetupStormGatePredicate(t *testing.T) {
	p := testutil.ForPredicate(t, func(m manager.Manager) error {
		return Setup(m, fake.NewSimpleClientset(), testutil.StubDyn())
	})

	if !p.Create(event.CreateEvent{Object: testutil.Node("n1", corev1.ConditionTrue, nil)}) {
		t.Fatal("node add did not fire")
	}
	if !p.Delete(event.DeleteEvent{Object: testutil.Node("n1", corev1.ConditionTrue, nil)}) {
		t.Fatal("node delete did not fire")
	}
	if !p.Generic(event.GenericEvent{Object: testutil.Node("n1", corev1.ConditionTrue, nil)}) {
		t.Fatal("generic event did not fire")
	}

	// Unexpected types fall back to firing (conservative).
	if !p.Update(testutil.UpdateEvent(&corev1.Pod{}, &corev1.Pod{})) {
		t.Fatal("non-Node update did not fire")
	}

	old := testutil.Node("n1", corev1.ConditionTrue, nil)
	same := testutil.Node("n1", corev1.ConditionTrue, nil)
	same.ResourceVersion = "2" // RV churn alone must not fire
	same.Status.Conditions[0].LastHeartbeatTime = metav1.Now()
	if p.Update(testutil.UpdateEvent(old, same)) {
		t.Fatal("heartbeat/RV churn fired the predicate")
	}

	condChanged := testutil.Node("n1", corev1.ConditionFalse, nil)
	if !p.Update(testutil.UpdateEvent(old, condChanged)) {
		t.Fatal("condition status flip did not fire")
	}

	taintChanged := testutil.Node("n1", corev1.ConditionTrue, nil,
		corev1.Taint{Key: "node.ops/kubelet-unresponsive", Effect: corev1.TaintEffectNoSchedule})
	if !p.Update(testutil.UpdateEvent(old, taintChanged)) {
		t.Fatal("taint change did not fire")
	}
}

// The node-labeler predicate is the bash jqFilter='.metadata.labels':
// only label drift fires, everything else is dropped.
