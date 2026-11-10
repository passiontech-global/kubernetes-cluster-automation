// module.go — the Module descriptor: the single source of truth for
// what a module is called and which env gate controls its
// registration. internal/registry holds the fleet's table;
// registry.SetupModules walks it, evaluating the gate and stamping
// Deps.Disabled before calling Setup, so the gate env lives in ONE
// place (the descriptor) instead of being re-named inside each
// module's Setup.
package shared

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// Module is one operator module's registration row.
//
//   - Name is the ops/queue name — it labels the run-error counters
//     (shell_operator_hook_run_errors_total{queue}) and the boot log
//     lines, so it must stay byte-stable forever.
//   - Group is the blast-radius set the module belongs to — a
//     `-modules @<group>` allowlist entry (e.g. "-modules @janitors")
//     expands to every row carrying it. Like Name it is an ops
//     contract: group strings land in Deployment args and runbooks,
//     so they must stay byte-stable, and moving a module between
//     groups changes what an operator's pinned @-entry selects.
//     Empty means ungrouped — such a module can only be allowlisted
//     by Name and never matches an @-entry.
//   - GateEnv is the feature-gate env var that controls
//     REGISTRATION only (empty = always enabled). defaultOn=false is
//     the opt-in convention (enabled only when the value is exactly
//     "true"); defaultOn=true is the always-on convention (enabled
//     unless the value is exactly "false") — same semantics as Gate.
//     Sub-feature gates that only alter run behavior (approve mode,
//     a heal toggle) do NOT belong here — the module keeps reading
//     those itself.
//   - Setup builds and registers the module's runnables. It is
//     called even when the gate is off (with Deps.Disabled set) so
//     knob-parsing warnings still fire; the module must register
//     nothing in that case.
//   - ProbeClients opts the row's Setup into the latency-sensitive
//     probe clients: when the boot Deps carry ProbeCS/ProbeDyn (own
//     client-go rate limiter), SetupModules hands those to the
//     module's Setup AS CS/Dyn, so the module's reads — and its low
//     volume of quarantine/taint patches — draw from the probe
//     bucket instead of contending with janitor delete bursts on the
//     shared one. Wiring-only: the module code is unchanged (it
//     still reads d.CS/d.Dyn); tests that build Deps literally (no
//     ProbeCS) are unaffected.
//   - CheckReg is the alternative to Setup for health-sweep check
//     rows: the row contributes a check into the
//     cluster-health-probes roster instead of registering
//     runnables. Every sweep check registers this way — the
//     cluster-health-probes row carries the sweep's Setup.
//     SetupModules collects the enabled rows' CheckRegs into
//     Deps.CheckRegs for the sweep to consume; rows with CheckReg
//     have Setup == nil and are never Setup-called.
//   - ConsumesCheckRegs marks the ONE row whose Setup reads
//     Deps.CheckRegs (today: cluster-health-probes). SetupModules
//     stamps the collected roster only on rows carrying it — every
//     other module's Deps.CheckRegs stays nil so the roster cannot
//     be mistaken for a general-purpose dep.
type Module struct {
	Name              string
	Group             string
	GateEnv           string
	DefaultOn         bool
	ProbeClients      bool
	ConsumesCheckRegs bool
	Setup             func(Deps) error
	CheckReg          *CheckReg
}

// CheckReg is one health-sweep check contribution — what a
// CheckReg-carrying Module row hands the cluster-health-probes
// sweep instead of runnables.
//
//   - Name is the check's kuberhealthy_check label value — an ops
//     contract like Module.Name: alerts key on it, so it must stay
//     byte-stable forever.
//   - New is the check constructor — statically
//     `func(*probefw.Deps) probefw.Check`, typed at compile time:
//     probefw is a top-level leaf (internal/probefw, not under the
//     health domain tree) precisely so the contract layer can name
//     this type — a mistyped registration is a build error, not a
//     boot-time assert.
type CheckReg struct {
	Name string
	New  func(*probefw.Deps) probefw.Check
}
