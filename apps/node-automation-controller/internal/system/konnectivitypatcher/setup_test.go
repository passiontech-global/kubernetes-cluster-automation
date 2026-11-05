// setup_test.go — registration coverage for the module's Setup
// function.
package konnectivitypatcher

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
)

// Builder-based: .Complete() resolves the For() GVK via the real
// scheme, builds a controller through controller.New and lands it in
// mgr.Add — assert exactly one runnable per Setup.
func TestSetupRegistersController(t *testing.T) {
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Mgr: m, CS: fake.NewSimpleClientset(),
		Dyn: testutil.StubDyn()}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if len(m.Added) != 1 {
		t.Fatalf("builder registered %d runnables, want 1", len(m.Added))
	}
}

// The konnectivity-patcher predicate pins ns/name on top of the
// field-selected informer — belt-and-suspenders against cache misses.
func TestSetupPredicate(t *testing.T) {
	p := testutil.ForPredicate(t, func(m manager.Manager) error {
		return Setup(shared.Deps{Mgr: m, CS: fake.NewSimpleClientset(),
			Dyn: testutil.StubDyn()})
	})
	ds := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: "kube-system", Name: "konnectivity-agent"}}
	if !p.Create(event.CreateEvent{Object: ds}) {
		t.Fatal("konnectivity-agent DS did not pass the predicate")
	}
	other := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: "kube-system", Name: "kube-proxy"}}
	if p.Create(event.CreateEvent{Object: other}) {
		t.Fatal("unrelated DS passed the predicate")
	}
	wrongNS := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: "default", Name: "konnectivity-agent"}}
	if p.Create(event.CreateEvent{Object: wrongNS}) {
		t.Fatal("wrong-namespace DS passed the predicate")
	}
}
