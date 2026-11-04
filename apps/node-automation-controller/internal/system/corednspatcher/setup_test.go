// setup_test.go — registration coverage for the module's Setup
// function.
package corednspatcher

import (
	"testing"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
)

// Builder-based: .Complete() resolves the For() GVK via the real
// scheme, builds a controller through controller.New and lands it in
// mgr.Add — assert exactly one runnable per Setup.
func TestSetupRegistersController(t *testing.T) {
	m := testutil.NewStubManager()
	if err := Setup(m, fake.NewSimpleClientset(), true, "DoNotSchedule", 2, 4, 1); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if len(m.Added) != 1 {
		t.Fatalf("builder registered %d runnables, want 1", len(m.Added))
	}
}

// The ported patcher skips mgr.Add entirely when disabled — no
// informer, no RequeueAfter loop.
func TestSetupDisabled(t *testing.T) {
	m := testutil.NewStubManager()
	if err := Setup(m, fake.NewSimpleClientset(), false,
		"DoNotSchedule", 2, 4, 1); err != nil {
		t.Fatalf("disabled setup must return nil, got %v", err)
	}
	if len(m.Added) != 0 {
		t.Fatalf("disabled module registered %d runnables, want 0", len(m.Added))
	}
}

// zoneWhen lands verbatim in the patch's whenUnsatisfiable enum — a
// typo would make needsPatch permanently true while the apiserver
// rejects every rendered patch (eternal error loop). An invalid
// zoneWhen disables ONLY this module (nil error, 0 runnables, error
// logged + counted) — a returned error would abort all 32 modules
// through setupModules for one ConfigMap typo.
func TestSetupRejectsInvalidZoneWhen(t *testing.T) {
	errsBefore := testutil.QueueErrorCount(t, "coredns-patcher")
	m := testutil.NewStubManager()
	if err := Setup(m, fake.NewSimpleClientset(), true,
		"ScheduleAnywway", 0, 0, 0); err != nil { //nolint:misspell — a typo is the point
		t.Fatalf("invalid zoneWhen must disable the module, not error: %v", err)
	}
	if len(m.Added) != 0 {
		t.Fatalf("invalid zoneWhen registered %d runnables, want 0", len(m.Added))
	}
	if got := testutil.QueueErrorCount(t, "coredns-patcher"); got != errsBefore+1 {
		t.Fatalf("invalid zoneWhen bumped error metric by %.0f, want 1",
			got-errsBefore)
	}
	// The empty string (unset env) disables the same way.
	m = testutil.NewStubManager()
	if err := Setup(m, fake.NewSimpleClientset(), true, "", 0, 0, 0); err != nil {
		t.Fatalf("empty zoneWhen must disable the module, not error: %v", err)
	}
	if len(m.Added) != 0 {
		t.Fatalf("empty zoneWhen registered %d runnables, want 0", len(m.Added))
	}
	// A disabled module never validates — an unused env must not
	// disable or error.
	m = testutil.NewStubManager()
	if err := Setup(m, fake.NewSimpleClientset(), false,
		"ScheduleAnywway", 0, 0, 0); err != nil { //nolint:misspell
		t.Fatalf("disabled setup must ignore zoneWhen, got %v", err)
	}
}
