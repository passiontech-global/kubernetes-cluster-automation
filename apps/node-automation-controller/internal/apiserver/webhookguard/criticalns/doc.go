// Package criticalns — the critical-namespace audit duties behind the
// admission-webhook-guard run (W12-CP-B): it flags live
// Mutating/Validating admission sub-webhooks whose failurePolicy fails
// closed while their namespaceSelector still matches one of the
// critical self-healing namespaces (kube-system, kube-node-lease,
// node-ops, medik8s) — the runtime twin of check-webhook-guard.sh —
// and, behind the WEBHOOK_CRITICAL_NS_ENFORCE_ENABLED ops lever,
// injects the four-namespace NotIn exclusion by strategic-merge patch.
// It also flags webhooks whose rules intercept a heartbeat-path
// resource (nodes/status, leases, pods/status, pods/eviction,
// wildcards) while matching a critical namespace. The duties are
// stateless per sweep apart from the emitted-series ledgers on
// Sweeper, which the facade holds across runs — the same leaf
// subpackage pattern as orphansweep, circuitbreaker and unmeshed.
package criticalns
