// Package leases holds the controller-lease-guard check of the
// cluster-health sweep — leader-election Lease health (stale-holder
// delete, flapping/thrashing detection) and the kube-state-metrics
// wedge guard riding the same check (ksm_wedge.go carries methods on
// the lease guard's check type). It split out of the flat nodehealth
// package by domain: core node/pod/namespace wedge checks stay in
// nodehealth, the API-object census in nodehealth/sprawl.
package leases
