// check_modules.go — the CheckReg merge: the per-check registry rows
// (the W13 gitops checks) carry shared.CheckReg instead of a Setup —
// they contribute one check into this sweep's roster rather than
// registering runnables of their own. registry.SetupModules collects
// the ENABLED rows' registrations into Deps.CheckRegs (stamped on
// every module's Deps) and appendCheckRegs folds them into the
// prober's check list after the static checkDefs.
//
// Semantics that fall out of the shape:
//
//   - GateEnv off (or -modules excludes the check row) → the row's
//     CheckReg is never collected → the check never joins the
//     roster. That is the per-check gate the rows exist for.
//   - The check still requires the cluster-health-probes module
//     itself: a check row selected WITHOUT cluster-health-probes
//     contributes to a Deps.CheckRegs nothing consumes. Documented
//     next to the registry rows and in docs/env.md.
//   - No ordering constraint: collection runs before ANY Setup, so a
//     check row may sit anywhere in registry.Modules — the
//     checkDefs-mutation era's "check rows must precede
//     cluster-health-probes" constraint is gone.
package clusterhealthprobes

import (
	"fmt"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

// appendCheckRegs folds the SetupModules-collected check
// registrations into the prober roster, deduped by name — a repeat
// registration (SetupModules driven twice in one test binary, or a
// CheckReg naming an already-static checkDefs check) cannot
// double-register, preserving the old registerCheck idempotence.
// r.New is `any` because shared cannot name probefw (import cycle +
// depguard); a registration that isn't the standard
// `func(*probefw.Deps) probefw.Check` shape is a boot-time error
// naming the check, never a silent skip.
func (p *clusterHealthProber) appendCheckRegs(regs []shared.CheckReg) error {
	seen := make(map[string]bool, len(p.checks)+len(regs))
	for _, c := range p.checks {
		seen[c.name] = true
	}
	for _, r := range regs {
		if seen[r.Name] {
			continue
		}
		newCheck, ok := r.New.(func(*probefw.Deps) probefw.Check)
		if !ok {
			return fmt.Errorf("check %q: CheckReg.New is %T, want func(*probefw.Deps) probefw.Check",
				r.Name, r.New)
		}
		p.checks = append(p.checks, checkEntry{name: r.Name, check: newCheck(p.Deps)})
		seen[r.Name] = true
	}
	return nil
}
