// setup_test.go — registration coverage for the module's Setup
// function.
package fluentbitroller

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
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
	t.Setenv("FLUENTBIT_ROLLER_ENABLED", "true")
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Mgr: m, CS: fake.NewSimpleClientset(),
		Dyn: testutil.StubDyn()}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if len(m.Added) != 1 {
		t.Fatalf("builder registered %d runnables, want 1", len(m.Added))
	}
}

// The ported roller skips mgr.Add entirely when disabled.
func TestSetupDisabled(t *testing.T) {
	t.Setenv("FLUENTBIT_ROLLER_ENABLED", "false")
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Mgr: m, CS: fake.NewSimpleClientset(),
		Dyn: testutil.StubDyn()}); err != nil {
		t.Fatalf("disabled setup must return nil, got %v", err)
	}
	if len(m.Added) != 0 {
		t.Fatalf("disabled module registered %d runnables, want 0", len(m.Added))
	}
}

// The fluent-bit roller predicate pins the pipeline secret.
func TestSetupPredicate(t *testing.T) {
	t.Setenv("FLUENTBIT_ROLLER_ENABLED", "true")
	p := testutil.ForPredicate(t, func(m manager.Manager) error {
		return Setup(shared.Deps{Mgr: m, CS: fake.NewSimpleClientset(),
			Dyn: testutil.StubDyn()})
	})
	pipeline := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Namespace: "fluent-system", Name: "passiontech-pipeline"}}
	if !p.Create(event.CreateEvent{Object: pipeline}) {
		t.Fatal("pipeline secret did not pass the predicate")
	}
	other := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Namespace: "fluent-system", Name: "other"}}
	if p.Create(event.CreateEvent{Object: other}) {
		t.Fatal("unrelated secret passed the predicate")
	}
}
