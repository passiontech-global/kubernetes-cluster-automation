// modules_flag.go — the -modules allowlist machinery
// (ParseModulesFlag / FilterModules / ValidGroups) and the boot-time
// wiring loop (SetupModules). The registration table itself lives in
// registry.go (module rows) and registry_health.go (health CheckReg
// rows).
package registry

import (
	"fmt"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// ParseModulesFlag splits the -modules flag value into entries —
// comma-separated, whitespace-tolerant, empty entries dropped so a
// trailing comma or an all-whitespace value behaves as "unset". An
// entry is either a module ops name or a "@<group>" group selector;
// which one is resolved by FilterModules, not here.
func ParseModulesFlag(s string) []string {
	var names []string
	for n := range strings.SplitSeq(s, ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	return names
}

// FilterModules resolves the -modules allowlist against the
// registry. An empty names slice means "flag unset" and returns the
// full registry untouched. Otherwise entries are module ops names
// or "@<group>" selectors — an @-entry expands to every module
// whose Group matches (a module with an empty Group can never match
// one: "@x" is looked up against "@"+Group, so Group="" would need
// a bare "@" entry, and even that is guarded out). The result is
// exactly the selected modules in REGISTRY order (not argv order)
// with repeats collapsed, so boot order stays deterministic however
// the operator wrote the list. An unrecognized name OR @group is a
// boot error, not a skip — a typo'd allowlist silently running the
// wrong subset is worse than refusing to start — so the error names
// the offenders plus every valid name and every valid group.
func FilterModules(names []string) ([]shared.Module, error) {
	if len(names) == 0 {
		return Modules, nil
	}
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}
	var out []shared.Module
	valid := make([]string, 0, len(Modules))
	// matched tracks which allowlist entries selected ≥1 module. `want`
	// cannot double for this — an @group must stay live for its WHOLE
	// section, so consuming it on first match would truncate the
	// expansion at the first member.
	matched := make(map[string]bool, len(names))
	for _, m := range Modules {
		valid = append(valid, m.Name)
		switch {
		case want[m.Name]:
			matched[m.Name] = true
		case m.Group != "" && want["@"+m.Group]:
			matched["@"+m.Group] = true
		default:
			continue
		}
		out = append(out, m)
	}
	if len(matched) < len(want) {
		// Report the offenders in the operator's argv order — the
		// entries that matched nothing.
		var bad []string
		seen := make(map[string]bool)
		for _, n := range names {
			if !matched[n] && !seen[n] {
				bad = append(bad, n)
				seen[n] = true
			}
		}
		return nil, fmt.Errorf("unknown module name(s) or @group(s) %s — valid names: %s — valid groups: %s",
			strings.Join(bad, ", "), strings.Join(valid, ", "),
			strings.Join(ValidGroups(), ", "))
	}
	return out, nil
}

// ValidGroups lists the registry's "@<group>" selectors in
// first-seen registry order — what an operator may write after "@"
// in -modules — for the unknown-entry error message. Deriving it
// from the registry (instead of hardcoding the constants) means a
// new group can never ship unstamped rows and a stale help list at
// the same time.
func ValidGroups() []string {
	seen := make(map[string]bool)
	var groups []string
	for _, m := range Modules {
		if m.Group != "" && !seen[m.Group] {
			seen[m.Group] = true
			groups = append(groups, "@"+m.Group)
		}
	}
	return groups
}

// SetupModules wires the allowlisted modules on the manager,
// registry order. The queue's error-metric series are predeclared
// for the FULL registry first — /metrics must expose the complete
// 0-valued fleet even on a Deployment where -modules (or a gate)
// runs only a subset, so a mid-flight flag change can never gap a
// series. Predeclaration is deliberately uniform — CheckReg rows
// get a queue series too (~48 extra
// shell_operator_hook_run_errors_total{queue="<check-name>"}
// series pinned at 0: the sweep reports its run errors under the
// cluster-health-probes queue only). That matches the three gated
// check rows that already carried series and keeps predeclaration
// a plain row walk rather than a Setup/CheckReg type switch.
// Then `mods` goes through two passes:
//
//  1. Gate evaluation + CheckReg collection. Each row's GateEnv
//     (when set) is resolved ONCE here. Health-sweep check rows
//     (CheckReg instead of Setup) contribute their registration
//     into regs only while their own gate is ON — a gated-off or
//     unselected check row simply never reaches the roster, which
//     IS the per-check gate the rows exist for. Collection order
//     is `mods` order — registry order — so the check rows'
//     relative order in Modules IS the sweep order.
//  2. Runnable wiring, registry order. Every row's Deps gets the
//     collected regs stamped — only the cluster-health-probes sweep
//     reads them, and because collection finished before ANY Setup
//     ran, a check row may sit anywhere relative to it (the old
//     "check rows must precede cluster-health-probes" constraint is
//     gone). A module whose gate is off still has its Setup
//     invoked, but with Deps.Disabled stamped so it can parse its
//     knobs (warning on bad values) while registering nothing;
//     CheckReg rows carry Setup == nil and are skipped. A returned
//     error aborts boot: a module that fails to register is a
//     broken operator, not a degraded one.
func SetupModules(deps shared.Deps, mods []shared.Module) error {
	for _, m := range Modules {
		metrics.PredeclareQueue(m.Name)
	}
	var regs []shared.CheckReg
	gatedOff := make(map[string]bool, len(mods))
	for _, m := range mods {
		if m.GateEnv != "" && !envx.Gate(m.GateEnv, m.DefaultOn) {
			gatedOff[m.Name] = true
			continue
		}
		if m.CheckReg != nil {
			regs = append(regs, *m.CheckReg)
		}
	}
	for _, m := range mods {
		d := deps
		d.Name = m.Name
		// The collected roster is stamped ONLY on the row that
		// consumes it (Module.ConsumesCheckRegs — today just
		// cluster-health-probes): handing the whole check list to
		// every module's Deps would invite a second consumer to
		// grow around the sweep's private contract.
		d.CheckRegs = nil
		if m.ConsumesCheckRegs {
			d.CheckRegs = regs
		}
		// Latency-sensitive probe rows swap in the probe-rate-limited
		// clients before Setup ever runs — the module code still reads
		// d.CS/d.Dyn, it just draws from the probe token bucket (own
		// QPS/Burst in cmd/manager main.go) so janitor delete bursts
		// on the shared bucket cannot queue-delay it. Nil ProbeCS
		// (literal test Deps, StubManager wiring) leaves the shared
		// clients in place.
		if m.ProbeClients {
			if deps.ProbeCS != nil {
				d.CS = deps.ProbeCS
			}
			if deps.ProbeDyn != nil {
				d.Dyn = deps.ProbeDyn
			}
			if deps.ProbeMeta != nil {
				d.Meta = deps.ProbeMeta
			}
		}
		if gatedOff[m.Name] {
			d.Disabled = true
			d.Log.WithName(m.Name).Info("disabled — module not registered", "gate", m.GateEnv)
		}
		if m.Setup == nil {
			continue // CheckReg row — its check already went into regs
		}
		if err := m.Setup(d); err != nil {
			d.Log.WithName(m.Name).Error(err, "unable to setup module")
			return err
		}
	}
	return nil
}
