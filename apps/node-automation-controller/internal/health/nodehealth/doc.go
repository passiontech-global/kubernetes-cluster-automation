// Package nodehealth holds the node/pod/namespace wedge checks riding
// the cluster-health sweep: node-hang-precordon, image-pull-storm,
// localpv-stranded-pods and namespace-terminating-wedged. Each reports
// on the shared kuberhealthy_check series under its own check name.
package nodehealth
