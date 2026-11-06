// Package nodehealth holds the node/pod/namespace wedge checks riding
// the cluster-health sweep: node-hang-precordon, image-pull-storm,
// localpv-stranded-pods, namespace-terminating-wedged,
// api-object-sprawl-report-gc, cpu-steal-taint-sync,
// keda-scaledobject-guard and controller-lease-guard. Each reports
// on the shared kuberhealthy_check series under its own check name.
package nodehealth
