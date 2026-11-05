// setup_test.go — registration coverage for the module's Setup
// function.
package fluentbitroller

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// Builder-based: .Complete() resolves the For() GVK via the real
// scheme, builds a controller through controller.New and lands it in
// mgr.Add — assert exactly one runnable per Setup.
func TestSetupRegistersController(t *testing.T) {
	// Zero-value Deps.Disabled = gate-on — FLUENTBIT_ROLLER_ENABLED
	// is resolved by setupModules, not re-read here.
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Name: "fluent-bit-config-roller", Mgr: m, CS: fake.NewSimpleClientset(),
		Dyn: testutil.StubDyn()}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if len(m.Added) != 1 {
		t.Fatalf("builder registered %d runnables, want 1", len(m.Added))
	}
}

// The ported roller skips mgr.Add entirely when Deps.Disabled is
// stamped.
func TestSetupDisabled(t *testing.T) {
	testutil.DisabledNoop(t, Setup, shared.Deps{
		Name: "fluent-bit-config-roller",
		CS:   fake.NewSimpleClientset(),
		Dyn:  testutil.StubDyn(),
	})
}

// The fluent-bit roller predicate pins the pipeline secret.
// onlyPipelineSecret is the exact predicate the For() watch installs.
func TestSetupPredicate(t *testing.T) {
	p := onlyPipelineSecret
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
