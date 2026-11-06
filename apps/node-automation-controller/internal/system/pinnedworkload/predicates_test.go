// predicates_test.go — the two shared watch predicates:
// OnlyNamespacedName (the ns/name pin every For() watch carries) and
// NodeCountChanges (the create/delete-only Node predicate behind the
// proportional replica pin's second watch).
package pinnedworkload

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// OnlyNamespacedName pins a For() watch to one namespace/name — the
// informer sees every object of the kind, so anything outside the pin
// must never enqueue a reconcile. NewPredicateFuncs applies the same
// check to every verb.
func TestOnlyNamespacedName(t *testing.T) {
	p := OnlyNamespacedName("kube-system", "coredns")
	deploy := func(ns, name string) *appsv1.Deployment {
		return &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name}}
	}
	match := deploy("kube-system", "coredns")
	if !p.Create(event.CreateEvent{Object: match}) {
		t.Fatal("pinned object did not pass on create")
	}
	if !p.Update(testutil.UpdateEvent(
		deploy("kube-system", "coredns"), match)) {
		t.Fatal("pinned object did not pass on update")
	}
	if !p.Delete(event.DeleteEvent{Object: match}) {
		t.Fatal("pinned object did not pass on delete")
	}
	if !p.Generic(event.GenericEvent{Object: match}) {
		t.Fatal("pinned object did not pass on generic")
	}
	for _, tc := range []struct {
		name string
		obj  *appsv1.Deployment
	}{
		{"wrong name", deploy("kube-system", "metrics-server")},
		{"wrong namespace", deploy("default", "coredns")},
		{"both wrong", deploy("default", "other")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if p.Create(event.CreateEvent{Object: tc.obj}) {
				t.Fatal("unpinned object passed the predicate")
			}
		})
	}
}

// NodeCountChanges drives the proportional replica count — only node
// add/remove changes the total (includeUnschedulableNodes counts EVERY
// Node object, cordoned or not), so updates and generic events must
// never enqueue: kubelet heartbeats land ~every 20s.
func TestNodeCountChanges(t *testing.T) {
	n1 := testutil.Node("n1", corev1.ConditionTrue, nil)
	if !NodeCountChanges.Create(event.CreateEvent{Object: n1}) {
		t.Fatal("node add did not fire")
	}
	if !NodeCountChanges.Delete(event.DeleteEvent{Object: n1}) {
		t.Fatal("node delete did not fire")
	}
	if NodeCountChanges.Update(testutil.UpdateEvent(n1,
		testutil.Node("n1", corev1.ConditionFalse, nil))) {
		t.Fatal("node update fired — heartbeat/cordon churn would " +
			"re-reconcile constantly")
	}
	if NodeCountChanges.Generic(event.GenericEvent{Object: n1}) {
		t.Fatal("generic event fired")
	}
}
