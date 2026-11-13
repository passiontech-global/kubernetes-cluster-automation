// Package sprawl holds the api-object-sprawl-report-gc check of the
// cluster-health sweep — the API object census, the kine large-object
// audit and the superseded-helm-secret prune/cap it reports and heals
// (the shared prune lives in platform/kube). It split out of the flat
// nodehealth package by domain: core node/pod/namespace wedge checks
// stay in nodehealth, the lease guards in watchdogs/leases.
package sprawl
