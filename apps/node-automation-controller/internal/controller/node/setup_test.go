// setup_test.go — registration coverage for the node-lifecycle
// modules' Setup* functions (see testutil.StubManager for the
// registration-capture contract).
package node

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/controller/testutil"
)

// Every AddPeriodic-based module must register its shell-operator
// queue name with the crontab-equivalent interval — the pairing is
// what keeps metrics/alerts compatible with the old hook names.
func TestSetupPeriodicModules(t *testing.T) {
	cs := fake.NewSimpleClientset()
	for _, tc := range []struct {
		name     string
		interval time.Duration
		setup    func(manager.Manager) error
	}{
		{"kubelet-liveness-reaper", 2 * time.Minute,
			func(m manager.Manager) error { return SetupKubeletReaper(m, cs) }},
		{"partition-pod-evictor", 5 * time.Minute,
			func(m manager.Manager) error { return SetupPartitionEvictor(m, cs) }},
		{"dead-node-sweeper", 5 * time.Minute,
			func(m manager.Manager) error { return SetupDeadNodeSweeper(m, cs, testutil.StubDyn()) }},
		{"csr-watcher", 10 * time.Minute,
			func(m manager.Manager) error { return SetupCSRWatcher(m, cs, true) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := testutil.NewStubManager()
			if err := tc.setup(m); err != nil {
				t.Fatalf("setup: %v", err)
			}
			testutil.ExpectPeriodic(t, m, tc.name, tc.interval)
		})
	}
}

// csr-watcher registers unconditionally (the flag only gates the tick
// body, like the bash exit-early at the top of the hook), while
// cilium-taint-reaper skips mgr.Add entirely when disabled (no
// informer, no RequeueAfter loop).
func TestSetupFeatureFlagVariants(t *testing.T) {
	cs := fake.NewSimpleClientset()

	m := testutil.NewStubManager()
	if err := SetupCSRWatcher(m, cs, false); err != nil {
		t.Fatalf("detect-only csr setup: %v", err)
	}
	testutil.ExpectPeriodic(t, m, "csr-watcher", 10*time.Minute)

	m = testutil.NewStubManager()
	if err := SetupCiliumTaintReaper(m, cs, false); err != nil {
		t.Fatalf("disabled setup must return nil, got %v", err)
	}
	if len(m.Added) != 0 {
		t.Fatalf("disabled module registered %d runnables, want 0", len(m.Added))
	}
}

// Builder-based modules: .Complete() resolves the For() GVK via the
// real scheme, builds a controller through controller.New and lands it
// in mgr.Add — assert exactly one runnable per Setup.
func TestSetupBuilderModules(t *testing.T) {
	cs := fake.NewSimpleClientset()
	for _, tc := range []struct {
		name  string
		setup func(manager.Manager) error
	}{
		{"descheduler-storm-gate", func(m manager.Manager) error {
			return SetupDeschedulerStormGate(m, cs)
		}},
		{"node-labeler", func(m manager.Manager) error {
			return SetupNodeLabeler(m, cs, "labels.txt")
		}},
		// enabled registers two sources (.Watches on Nodes + cilium
		// Pods) — still one controller runnable.
		{"cilium-taint-reaper", func(m manager.Manager) error {
			return SetupCiliumTaintReaper(m, cs, true)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := testutil.NewStubManager()
			if err := tc.setup(m); err != nil {
				t.Fatalf("setup: %v", err)
			}
			if len(m.Added) != 1 {
				t.Fatalf("builder registered %d runnables, want 1", len(m.Added))
			}
		})
	}
}

// A manager.Add failure must propagate through AddPeriodic so cmd/
// can abort boot instead of silently losing a module.
func TestSetupAddErrorPropagates(t *testing.T) {
	want := errors.New("manager rejected runnable")
	m := testutil.NewStubManager()
	m.AddErr = want
	if err := SetupKubeletReaper(m, fake.NewSimpleClientset()); !errors.Is(err, want) {
		t.Fatalf("Add error = %v, want %v", err, want)
	}
}

// The storm-gate For(Node) predicate must fire on node add/remove and
// on changes to the verdict inputs (condition statuses, taint keys) —
// but not on kubelet heartbeat churn.
func TestSetupStormGatePredicate(t *testing.T) {
	p := testutil.ForPredicate(t, func(m manager.Manager) error {
		return SetupDeschedulerStormGate(m, fake.NewSimpleClientset())
	})

	if !p.Create(event.CreateEvent{Object: node("n1", corev1.ConditionTrue, nil)}) {
		t.Fatal("node add did not fire")
	}
	if !p.Delete(event.DeleteEvent{Object: node("n1", corev1.ConditionTrue, nil)}) {
		t.Fatal("node delete did not fire")
	}
	if !p.Generic(event.GenericEvent{Object: node("n1", corev1.ConditionTrue, nil)}) {
		t.Fatal("generic event did not fire")
	}

	// Unexpected types fall back to firing (conservative).
	if !p.Update(testutil.UpdateEvent(&corev1.Pod{}, &corev1.Pod{})) {
		t.Fatal("non-Node update did not fire")
	}

	old := node("n1", corev1.ConditionTrue, nil)
	same := node("n1", corev1.ConditionTrue, nil)
	same.ResourceVersion = "2" // RV churn alone must not fire
	same.Status.Conditions[0].LastHeartbeatTime = metav1.Now()
	if p.Update(testutil.UpdateEvent(old, same)) {
		t.Fatal("heartbeat/RV churn fired the predicate")
	}

	condChanged := node("n1", corev1.ConditionFalse, nil)
	if !p.Update(testutil.UpdateEvent(old, condChanged)) {
		t.Fatal("condition status flip did not fire")
	}

	taintChanged := node("n1", corev1.ConditionTrue, nil,
		corev1.Taint{Key: "node.ops/kubelet-unresponsive", Effect: corev1.TaintEffectNoSchedule})
	if !p.Update(testutil.UpdateEvent(old, taintChanged)) {
		t.Fatal("taint change did not fire")
	}
}

// The node-labeler predicate is the bash jqFilter='.metadata.labels':
// only label drift fires, everything else is dropped.
func TestSetupNodeLabelerPredicate(t *testing.T) {
	p := testutil.ForPredicate(t, func(m manager.Manager) error {
		return SetupNodeLabeler(m, fake.NewSimpleClientset(), "labels.txt")
	})

	if !p.Create(event.CreateEvent{Object: node("n1", corev1.ConditionTrue, nil)}) {
		t.Fatal("node add did not fire")
	}
	if !p.Delete(event.DeleteEvent{Object: node("n1", corev1.ConditionTrue, nil)}) {
		t.Fatal("node delete did not fire")
	}
	if !p.Generic(event.GenericEvent{Object: node("n1", corev1.ConditionTrue, nil)}) {
		t.Fatal("generic event did not fire")
	}

	// Missing objects never fire.
	if p.Update(testutil.UpdateEvent(nil, node("n1", corev1.ConditionTrue, nil))) {
		t.Fatal("nil ObjectOld fired")
	}
	if p.Update(testutil.UpdateEvent(node("n1", corev1.ConditionTrue, nil), nil)) {
		t.Fatal("nil ObjectNew fired")
	}

	labeled := node("n1", corev1.ConditionTrue,
		map[string]string{"passiontech.dev/workload": "app"})
	if !p.Update(testutil.UpdateEvent(node("n1", corev1.ConditionTrue, nil), labeled)) {
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
func TestSetupCiliumTaintReaperWatches(t *testing.T) {
	m := testutil.NewStubManager()
	if err := SetupCiliumTaintReaper(m, fake.NewSimpleClientset(), true); err != nil {
		t.Fatalf("setup: %v", err)
	}
	srcs := testutil.ControllerWatches(t, m.Added[0])
	if len(srcs) != 2 {
		t.Fatalf("enabled reaper registered %d watches, want 2", len(srcs))
	}

	preds, _ := testutil.KindSource(t, srcs[0])
	if len(preds) != 1 {
		t.Fatalf("Node watch carries %d predicates, want 1", len(preds))
	}
	p := preds[0]
	if !p.Create(event.CreateEvent{Object: node("n1", corev1.ConditionTrue, nil)}) {
		t.Fatal("node add did not fire")
	}
	if !p.Delete(event.DeleteEvent{Object: node("n1", corev1.ConditionTrue, nil)}) {
		t.Fatal("node delete did not fire")
	}
	if !p.Generic(event.GenericEvent{Object: node("n1", corev1.ConditionTrue, nil)}) {
		t.Fatal("generic event did not fire")
	}
	if !p.Update(testutil.UpdateEvent(&corev1.Pod{}, &corev1.Pod{})) {
		t.Fatal("non-Node update did not fire")
	}
	old := node("n1", corev1.ConditionTrue, nil)
	if p.Update(testutil.UpdateEvent(old, node("n1", corev1.ConditionFalse, nil))) {
		t.Fatal("unrelated status change fired — heartbeat storms would sweep every 20s")
	}
	if !p.Update(testutil.UpdateEvent(old,
		node("n1", corev1.ConditionTrue, nil, ciliumStaleTaint))) {
		t.Fatal("agent-not-ready taint change did not fire")
	}

	// The Node watch itself enqueues the fixed sweep key — identical
	// NamespacedNames are what the workqueue set collapses, so it must
	// be the SAME key the pod watch below produces.
	_, nodeH := testutil.KindSource(t, srcs[0])
	if nodeH == nil {
		t.Fatal("node watch has no event handler")
	}
	nq := workqueue.NewTypedRateLimitingQueue(
		workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	defer nq.ShutDown()
	nodeH.Create(context.Background(), event.CreateEvent{
		Object: node("n1", corev1.ConditionTrue, nil)}, nq)
	nodeH.Create(context.Background(), event.CreateEvent{
		Object: node("n2", corev1.ConditionFalse, nil)}, nq)
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
	_, h := testutil.KindSource(t, srcs[1])
	if h == nil {
		t.Fatal("pod watch has no event handler")
	}
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
func TestSetupSweepModulesFixedKey(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(manager.Manager) error
		key   string
	}{
		{"node-labeler", func(m manager.Manager) error {
			return SetupNodeLabeler(m, fake.NewSimpleClientset(), "labels.txt")
		}, "node-labeler-sweep"},
		{"descheduler-storm-gate", func(m manager.Manager) error {
			return SetupDeschedulerStormGate(m, fake.NewSimpleClientset())
		}, "descheduler-storm-gate-sweep"},
		{"cilium-taint-reaper", func(m manager.Manager) error {
			return SetupCiliumTaintReaper(m, fake.NewSimpleClientset(), true)
		}, "cilium-taint-reaper-sweep"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := testutil.NewStubManager()
			if err := tc.setup(m); err != nil {
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
					Object: node(name, corev1.ConditionTrue, nil)}, q)
			}
			if q.Len() != 1 {
				t.Fatalf("3-node burst enqueued %d requests, want 1 (set-collapse)", q.Len())
			}
			item, _ := q.Get()
			if item.Name != tc.key || item.Namespace != "" {
				t.Fatalf("enqueued request = %+v, want fixed key %q", item, tc.key)
			}
			q.Done(item)
		})
	}
}
