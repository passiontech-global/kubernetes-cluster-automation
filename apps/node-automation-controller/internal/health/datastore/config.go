// config.go — env resolution for the datastore checks' knobs:
// ConfigFromEnv fills c.Datastore — the W13-ST3 persistence windows
// postgres-wal-archive-guard's CloudNativePG signatures and the
// pvc-resize-stall-guard run under. Resolved once at sweep Setup via
// clusterhealthprobes.healthProbeConfigFromEnv (the same delegation
// ported.ConfigFromEnv / watchdogs.KCMConfigFromEnv /
// probefw.CiliumConfigFromEnv use), so an unparseable value warns
// even when the module is gated off.
package datastore

import (
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	// CNPGUnhealthyMinAgeDefault is how long a CloudNativePG
	// Cluster must hold a stuck phase (Failing over / Waiting for
	// the instances to become active) or a ready<instances count
	// before node_automation_cnpg_cluster_unhealthy fires — short
	// enough to catch a hung failover, long enough to ride out a
	// legitimate rolling restart.
	CNPGUnhealthyMinAgeDefault = 15 * time.Minute
	// PVCResizeStallMinAgeDefault is how long a PVC may sit with a
	// FileSystemResizePending or Resizing condition True before
	// node_automation_pvc_resize_stalled fires — an online
	// filesystem expansion is seconds-to-minutes; half an hour
	// wedged means kubelet's volume expansion loop lost it.
	PVCResizeStallMinAgeDefault = 30 * time.Minute
)

// ConfigFromEnv fills c.Datastore from the HEALTH_* env vars.
// envx.GetenvDuration floors each knob at 1s — a sub-second
// persistence window was never a sane setting.
func ConfigFromEnv(c *probefw.Config) {
	c.Datastore = probefw.DatastoreConfig{
		CNPGUnhealthyMinAge: envx.GetenvDuration(
			"HEALTH_CNPG_UNHEALTHY_MIN_AGE", CNPGUnhealthyMinAgeDefault),
		PVCResizeStallMinAge: envx.GetenvDuration(
			"HEALTH_PVC_RESIZE_STALL_MIN_AGE", PVCResizeStallMinAgeDefault),
	}
}
