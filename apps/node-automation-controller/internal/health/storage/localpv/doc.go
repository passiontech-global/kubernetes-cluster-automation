// Package localpv holds the localpv-stranded-pods check of the
// cluster-health sweep — the local-PV dead-node stranding census
// (Pending pods whose bound local PV is nodeAffinity-pinned to a
// dead node), the maintenance-gated ephemeral PVC+pod rescue and the
// wedged openebs-localpv-provisioner bounce. It split out of the
// flat nodehealth package by domain: core node/pod/namespace wedge
// checks stay in nodehealth, the lease guards in watchdogs/leases,
// the sprawl census in watchdogs/sprawl.
package localpv
