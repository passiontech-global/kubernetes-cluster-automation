// Package webhookguard is the admission-webhook-guard module: prunes
// orphan admission-webhook entries whose Service namespace was deleted
// (fail-closed), patches failurePolicy Fail->Ignore while a Fail
// webhook’s Service has zero Ready endpoints (the self-deadlock circuit
// breaker, restored on recovery), and audits unmeshed pods that should
// carry the linkerd-proxy sidecar.
package webhookguard
