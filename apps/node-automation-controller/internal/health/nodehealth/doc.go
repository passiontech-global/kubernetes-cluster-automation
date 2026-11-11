// Package nodehealth holds the node/pod/namespace wedge checks riding
// the cluster-health sweep: node-hang-precordon, image-pull-storm,
// localpv-stranded-pods, namespace-terminating-wedged,
// cpu-steal-taint-sync and keda-scaledobject-guard. Each reports
// on the shared kuberhealthy_check series under its own check name.
//
// Two sibling packages split the rest of the former flat package by
// domain, keeping every registry row and sweep order identical:
// nodehealth/sprawl the api-object-sprawl-report-gc census + prune,
// nodehealth/leases the controller-lease-guard (with its ksm wedge),
// nodehealth/localpv the localpv-stranded-pods check and heals.
package nodehealth
