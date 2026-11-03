// setup_test.go — registration coverage for the kubelet-liveness-reaper
// module's Setup function (see testutil.StubManager for the
// registration-capture contract).
package kubeletreaper

import (
	"errors"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
)

// The module must register its shell-operator queue name with the
// crontab-equivalent interval — the pairing is what keeps
// metrics/alerts compatible with the old hook names.
func TestSetupRegistersPeriodic(t *testing.T) {
	m := testutil.NewStubManager()
	if err := Setup(m, fake.NewSimpleClientset()); err != nil {
		t.Fatalf("setup: %v", err)
	}
	testutil.ExpectPeriodic(t, m, "kubelet-liveness-reaper", 2*time.Minute)
}

// A manager.Add failure must propagate through AddPeriodic so cmd/
// can abort boot instead of silently losing a module.
func TestSetupAddErrorPropagates(t *testing.T) {
	want := errors.New("manager rejected runnable")
	m := testutil.NewStubManager()
	m.AddErr = want
	if err := Setup(m, fake.NewSimpleClientset()); !errors.Is(err, want) {
		t.Fatalf("Add error = %v, want %v", err, want)
	}
}
