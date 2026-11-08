// Package webhookguard is the admission-webhook-guard module: prunes
// orphan admission-webhook entries whose Service namespace was deleted
// (fail-closed), patches failurePolicy Fail->Ignore while a Fail
// webhook’s Service has zero Ready endpoints (the self-deadlock circuit
// breaker, restored on recovery), guards CRD conversion webhook
// backends, and audits unmeshed pods that should carry the
// linkerd-proxy sidecar.
//
// The duties live in leaf subpackages — guardstate (shared deps,
// run snapshot, endpoint census), orphansweep, circuitbreaker,
// criticalns and unmeshed — while this package keeps the
// registry-facing Setup and the errors.Join sweep orchestration
// behind the single "admission-webhook-guard" periodic.
package webhookguard
