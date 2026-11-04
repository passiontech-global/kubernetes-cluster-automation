// Package helmreleaseunlocker is the helmrelease-unlocker module:
// unsticks Flux HelmReleases wedged in pending operations, reaps failed
// helm-hook Jobs, heals stale artifact sources, and (opt-in via
// HELM_STALL_UNWEDGE_ENABLED) unwedges Deployments surge-deadlocked by
// required podAntiAffinity behind Stalled/RetriesExceeded HelmReleases.
package helmreleaseunlocker
