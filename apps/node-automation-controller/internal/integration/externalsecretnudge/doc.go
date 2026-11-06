// Package externalsecretnudge is the externalsecret-nudge module: nudges
// ExternalSecrets out of sync backoff when their SecretStore recovers.
// EXTERNALSECRET_NUDGE_ENABLED is the module's REGISTRATION gate (opt-in:
// only "true" registers) — resolved by setupModules into Deps.Disabled,
// so a gated-off cluster wires no runnable at all rather than running a
// no-op sweep.
package externalsecretnudge
