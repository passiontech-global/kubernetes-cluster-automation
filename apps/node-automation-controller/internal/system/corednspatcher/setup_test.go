// setup_test.go — registration coverage for the module's Setup
// function.
package corednspatcher

import (
	"testing"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
)

// Builder-based: .Complete() resolves the For() GVK via the real
// scheme, builds a controller through controller.New and lands it in
// mgr.Add — assert exactly one runnable per Setup.
func TestSetupRegistersController(t *testing.T) {
	t.Setenv("COREDNS_PATCHER_ENABLED", "true")
	t.Setenv("COREDNS_PATCHER_ZONE_WHEN", "DoNotSchedule")
	t.Setenv("COREDNS_PATCHER_ZONE_MIN_DOMAINS", "2")
	t.Setenv("COREDNS_MIN_REPLICAS", "4")
	t.Setenv("COREDNS_NODES_PER_REPLICA", "1")
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Mgr: m, CS: fake.NewSimpleClientset(),
		Dyn: testutil.StubDyn()}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if len(m.Added) != 1 {
		t.Fatalf("builder registered %d runnables, want 1", len(m.Added))
	}
}

// The ported patcher skips mgr.Add entirely when disabled — no
// informer, no RequeueAfter loop.
func TestSetupDisabled(t *testing.T) {
	t.Setenv("COREDNS_PATCHER_ENABLED", "false")
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Mgr: m, CS: fake.NewSimpleClientset(),
		Dyn: testutil.StubDyn()}); err != nil {
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
	t.Setenv("COREDNS_PATCHER_ENABLED", "true")
	t.Setenv("COREDNS_PATCHER_ZONE_WHEN", "ScheduleAnywway") //nolint:misspell — a typo is the point
	t.Setenv("COREDNS_PATCHER_ZONE_MIN_DOMAINS", "0")
	t.Setenv("COREDNS_MIN_REPLICAS", "0")
	t.Setenv("COREDNS_NODES_PER_REPLICA", "0")
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Mgr: m, CS: fake.NewSimpleClientset(),
		Dyn: testutil.StubDyn()}); err != nil {
		t.Fatalf("invalid zoneWhen must disable the module, not error: %v", err)
	}
	if len(m.Added) != 0 {
		t.Fatalf("invalid zoneWhen registered %d runnables, want 0", len(m.Added))
	}
	if got := testutil.QueueErrorCount(t, "coredns-patcher"); got != errsBefore+1 {
		t.Fatalf("invalid zoneWhen bumped error metric by %.0f, want 1",
			got-errsBefore)
	}
	// An empty zoneWhen env falls back to the DoNotSchedule default
	// (shared.Getenv treats empty as unset) and registers normally —
	// only a non-empty invalid value can reach the validation above.
	m = testutil.NewStubManager()
	t.Setenv("COREDNS_PATCHER_ZONE_WHEN", "")
	if err := Setup(shared.Deps{Mgr: m, CS: fake.NewSimpleClientset(),
		Dyn: testutil.StubDyn()}); err != nil {
		t.Fatalf("default zoneWhen must not error: %v", err)
	}
	if len(m.Added) != 1 {
		t.Fatalf("default zoneWhen registered %d runnables, want 1", len(m.Added))
	}
	// A disabled module never validates — an unused env must not
	// disable or error.
	m = testutil.NewStubManager()
	t.Setenv("COREDNS_PATCHER_ENABLED", "false")
	t.Setenv("COREDNS_PATCHER_ZONE_WHEN", "ScheduleAnywway") //nolint:misspell
	if err := Setup(shared.Deps{Mgr: m, CS: fake.NewSimpleClientset(),
		Dyn: testutil.StubDyn()}); err != nil {
		t.Fatalf("disabled setup must ignore zoneWhen, got %v", err)
	}
}
