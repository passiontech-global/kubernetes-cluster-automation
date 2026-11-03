// Package apiserver groups the modules guarding apiserver integrity:
// the per-backend watch-cache wedge quarantine
// (apiserver_endpoint_guard) and the webhook_guard — orphan
// admission-webhook pruner plus the self-deadlock circuit breaker
// that patches failurePolicy to Ignore while a Fail webhook's
// Service has zero Ready endpoints (and restores it on recovery).
package apiserver
