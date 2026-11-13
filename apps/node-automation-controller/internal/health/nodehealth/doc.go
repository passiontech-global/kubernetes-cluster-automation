// Package nodehealth holds the node/pod/namespace wedge checks riding
// the cluster-health sweep: node-hang-precordon, image-pull-storm,
// namespace-terminating-wedged, cpu-steal-taint-sync and
// node-condition-sweeper. Each reports on the shared kuberhealthy_check
// series under its own check name.
//
// The rest of the former flat package split off by domain, keeping
// every registry row and sweep order identical: the api-object
// census in watchdogs/sprawl, the controller-lease-guard (with its
// ksm wedge) in watchdogs/leases, the localpv-stranded-pods check in
// storage/localpv, keda-scaledobject-guard in gitops and
// apiserver-relist-storm in watchdogs.
package nodehealth
