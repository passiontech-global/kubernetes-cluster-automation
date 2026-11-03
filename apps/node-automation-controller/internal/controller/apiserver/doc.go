// Package apiserver groups the modules guarding apiserver integrity:
// the per-backend watch-cache wedge quarantine
// (apiserver_endpoint_guard) and the orphan admission-webhook pruner
// (webhook_guard).
package apiserver
