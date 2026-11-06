// gate_contract_test.go — the structural Disabled-gate contract,
// proven against the live Modules table rather than a
// hand-maintained list: every gated module's Setup must return nil
// and register NOTHING when Deps.Disabled is stamped — the exact
// input setupModules produces when a GateEnv evaluates off — no
// matter which helper (SetupWithConfig / SetupNoConfig) or
// hand-rolled check implements the gate. A new gated module is
// covered the day its registry row lands.
package registry

import (
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// TestDisabledGateContract drives every registry row through Setup
// with Deps.Disabled stamped and asserts the module contract: nil
// error, zero registered runnables.
//
// The zero-registration assertion applies to GATED modules
// (GateEnv != "") only. Disabled is unreachable for always-on rows —
// setupModules stamps it solely from a GateEnv evaluation, so an
// ungated module's Setup legitimately registers even under a
// synthetic Disabled:true (the always-on hand-rolled Setups never
// read the field). Those rows still get the nil-error smoke check:
// a Disabled:true that crashes or errors is a bug regardless of
// reachability. Scoping on GateEnv — not on which helper a Setup
// happens to call — keeps the assertion self-maintaining: gating a
// previously always-on module automatically subjects it to the
// zero-registration check.
func TestDisabledGateContract(t *testing.T) {
	for _, m := range Modules {
		t.Run(m.Name, func(t *testing.T) {
			mgr := testutil.NewStubManager()
			d := testDeps(mgr)
			d.Name = m.Name
			d.Disabled = true
			if err := m.Setup(d); err != nil {
				t.Fatalf("disabled setup must return nil, got %v", err)
			}
			if m.GateEnv == "" {
				return // always-on: Disabled is unreachable — see above
			}
			if len(mgr.Added) != 0 {
				t.Fatalf("disabled module registered %d runnables, want 0",
					len(mgr.Added))
			}
		})
	}
}
