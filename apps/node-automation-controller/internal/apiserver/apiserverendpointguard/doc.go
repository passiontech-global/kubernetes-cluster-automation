// Package apiserverendpointguard is the apiserver-endpoint-guard module:
// the per-backend watch-cache wedge quarantine — it probes each
// apiserver backend’s live-vs-cached resourceVersion and pulls a wedged
// IP out of the default/kubernetes Endpoints+EndpointSlices until the
// watch cache catches up.
package apiserverendpointguard
