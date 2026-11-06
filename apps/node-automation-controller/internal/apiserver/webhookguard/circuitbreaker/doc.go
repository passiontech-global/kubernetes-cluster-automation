// Package circuitbreaker is the C1 admission-webhook self-deadlock
// circuit breaker plus the W9-CP1 brownout probe/pod-bounce and the
// CRD conversion-webhook backend health check — two of the four
// independent duties behind the admission-webhook-guard sweep. The
// sweep trips fail-closed sub-webhooks whose backend Service has
// reported 0 effective Ready endpoints past the dead threshold to
// failurePolicy=Ignore, restores them on recovery, bounces the
// oldest Ready backing pod of a TCP+TLS-unresponsive backend, and
// exports node_automation_crd_conversion_webhook_unhealthy for CRDs
// whose conversion webhook backend is measurably broken. Its state
// (dead-backend streaks, the broken-series ledger, bounce cooldowns,
// test-seam thresholds) lives on Breaker; shared deps and the run
// snapshot come from guardstate.
package circuitbreaker
