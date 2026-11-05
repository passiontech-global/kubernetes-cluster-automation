// module.go — the Module descriptor: the single source of truth for
// what a module is called and which env gate controls its
// registration. internal/registry holds the fleet's table;
// registry.SetupModules walks it, evaluating the gate and stamping
// Deps.Disabled before calling Setup, so the gate env lives in ONE
// place (the descriptor) instead of being re-named inside each
// module's Setup.
package shared

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
type Module struct {
	Name      string
	Group     string
	GateEnv   string
	DefaultOn bool
	Setup     func(Deps) error
}
