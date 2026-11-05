// contract.go — the module-contract assertions behind the per-package
// setup_test.go one-liners. Nearly every module's Setup test pair is
// the same two checks: enabled Setup registers exactly one
// *shared.Periodic carrying the ops queue name + crontab-equivalent
// interval (the pairing that keeps metrics/alerts compatible with the
// old hook names), and Disabled Setup registers nothing but still
// returns nil — setupModules resolves the gate and still calls Setup
// so knob-parsing warnings fire, but registration must no-op. Both
// halves get a fresh StubManager; the caller supplies base Deps with
// only the fields its module touches (Name plus the CS/Dyn fakes).
package testutil

import (
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

// PeriodicContract asserts the whole module Setup contract in one
// call — the replacement for the near-identical
// TestSetupRegistersPeriodic/TestSetupDisabled pair ~30 module
// packages repeat:
//
//	testutil.PeriodicContract(t, Setup, shared.Deps{
//		Name: "my-module",
//		CS:   fake.NewSimpleClientset(),
//		Dyn:  testutil.StubDyn(),
//	}, "my-module", 15*time.Minute)
//
// The enabled half runs setup with Disabled's zero value (gate-on —
// the *_ENABLED gate is resolved by setupModules, not re-read here)
// and expects exactly one *shared.Periodic named queue ticking every
// interval; the disabled half is DisabledNoop. Modules whose enabled
// registration isn't a lone Periodic (builder-installed controllers,
// env-gated ticks) keep a custom enabled-side test and call
// DisabledNoop for the other half.
func PeriodicContract(t *testing.T, setup func(shared.Deps) error, base shared.Deps, queue string, interval time.Duration) {
	t.Helper()

	m := NewStubManager()
	d := base
	d.Mgr = m
	if err := setup(d); err != nil {
		t.Fatalf("setup %q: %v", queue, err)
	}
	ExpectPeriodic(t, m, queue, interval)

	DisabledNoop(t, setup, base)
}

// DisabledNoop asserts only the disabled half of the contract: setup
// with Deps.Disabled=true must return nil without registering any
// runnable. For modules that register unconditionally or whose
// enabled assertion needs custom checks — the disabled gate contract
// still applies even when the enabled side can't be expressed as
// one Periodic registration.
func DisabledNoop(t *testing.T, setup func(shared.Deps) error, base shared.Deps) {
	t.Helper()

	m := NewStubManager()
	d := base
	d.Mgr = m
	d.Disabled = true
	if err := setup(d); err != nil {
		t.Fatalf("disabled setup %q must return nil, got %v", d.Name, err)
	}
	if len(m.Added) != 0 {
		t.Fatalf("disabled module %q registered %d runnables, want 0",
			d.Name, len(m.Added))
	}
}
