// checkreg_contract_test.go — the CheckReg row contract, proven
// against the live Modules table rather than a hand-maintained list:
// every row carries exactly one of Setup/CheckReg, every CheckReg has
// a non-empty Name (it becomes the kuberhealthy_check label value —
// ops contract) and a New that type-asserts to the sweep's
// constructor shape. shared stores New as `any` because it cannot
// name internal/health/probefw (import cycle + depguard) — this test
// is the compile-time-shape stand-in, so a mistyped registration
// fails HERE, at test time, instead of at some later boot.
package registry

import (
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// TestCheckRegContract walks every registry row: exactly one of
// Setup/CheckReg is set, and CheckReg rows are well-formed for the
// sweep that consumes them.
func TestCheckRegContract(t *testing.T) {
	for _, m := range Modules {
		t.Run(m.Name, func(t *testing.T) {
			switch {
			case m.Setup == nil && m.CheckReg == nil:
				t.Fatal("row has neither Setup nor CheckReg")
			case m.Setup != nil && m.CheckReg != nil:
				t.Fatal("row has both Setup and CheckReg — exactly one allowed")
			}
			if m.CheckReg == nil {
				return
			}
			if m.CheckReg.Name == "" {
				t.Fatal("CheckReg.Name is empty — it becomes the kuberhealthy_check label value")
			}
			if _, ok := m.CheckReg.New.(func(*probefw.Deps) probefw.Check); !ok {
				t.Fatalf("CheckReg.New is %T, want func(*probefw.Deps) probefw.Check",
					m.CheckReg.New)
			}
		})
	}
}

// TestSetupModulesCheckRegGate drives SetupModules over a synthetic
// CheckReg row plus a spy module that captures the Deps it was
// handed: a gated-off check row contributes nothing to
// Deps.CheckRegs (the roster never sees the check), an enabled one
// contributes exactly its registration.
func TestSetupModulesCheckRegGate(t *testing.T) {
	checkRow := shared.Module{
		Name:      "spy-check",
		GateEnv:   "TEST_CHECKREG_GATE",
		DefaultOn: true,
		CheckReg: &shared.CheckReg{
			Name: "spy-check",
			New:  func(*probefw.Deps) probefw.Check { return nil },
		},
	}
	var got []shared.CheckReg
	spy := shared.Module{
		Name: "checkreg-spy",
		Setup: func(d shared.Deps) error {
			got = d.CheckRegs
			return nil
		},
	}

	t.Run("gated off contributes nothing", func(t *testing.T) {
		t.Setenv("TEST_CHECKREG_GATE", "false")
		got = nil
		m := testutil.NewStubManager()
		if err := SetupModules(testDeps(m), []shared.Module{checkRow, spy}); err != nil {
			t.Fatalf("SetupModules: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("gated-off check row contributed %d regs, want 0", len(got))
		}
	})

	t.Run("enabled contributes its reg", func(t *testing.T) {
		t.Setenv("TEST_CHECKREG_GATE", "true")
		got = nil
		m := testutil.NewStubManager()
		if err := SetupModules(testDeps(m), []shared.Module{checkRow, spy}); err != nil {
			t.Fatalf("SetupModules: %v", err)
		}
		if len(got) != 1 || got[0].Name != "spy-check" {
			t.Fatalf("CheckRegs = %+v, want exactly the spy-check reg", got)
		}
	})
}
