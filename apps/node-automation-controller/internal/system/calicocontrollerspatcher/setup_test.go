// setup_test.go — registration coverage for calico-controllers-patcher Setup.
package calicocontrollerspatcher

import (
	"testing"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func TestSetupRegistersController(t *testing.T) {
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{
		Name: "calico-controllers-patcher",
		Mgr:  m,
		CS:   fake.NewSimpleClientset(),
		Dyn:  testutil.StubDyn(),
	}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if len(m.Added) != 1 {
		t.Fatalf("builder registered %d runnables, want 1", len(m.Added))
	}
}

func TestSetupDisabled(t *testing.T) {
	testutil.DisabledNoop(t, Setup, shared.Deps{
		Name: "calico-controllers-patcher",
		CS:   fake.NewSimpleClientset(),
		Dyn:  testutil.StubDyn(),
	})
}
