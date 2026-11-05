// Wave 10 self-healing metrics (W10-NM2/W10-ST6).
//
// Kept in a sibling file because internal/metrics/metrics.go is
// owned by a parallel workstream — same package, same
// ctrlmetrics.Registry registration pattern, exported vecs the
// module packages drive directly.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// CFTunnelWedgePodsDeletedTotal counts cloudflared connector pods
// deleted by the cf-tunnel proxy watchdog wedge healer (W10-NM2).
// reason is fatal_logs (wedged log signature) or all_unready_oldest
// (readyCount==0 deadlock — oldest stale-unready pod deleted once per
// cooldown). Labels: pod namespace + reason.
var CFTunnelWedgePodsDeletedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_cftunnel_wedge_pods_deleted_total",
	Help: "Wedged cloudflared connector pods deleted, by namespace and reason.",
}, []string{"namespace", "reason"})

// VeleroBackupStuck marks (1) each velero.io Backup wedged
// InProgress or Deleting for over 6h (W10-ST6). Labels: namespace +
// backup name.
var VeleroBackupStuck = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_velero_backup_stuck",
	Help: "1 while a velero.io Backup is InProgress or Deleting for over 6h.",
}, []string{"namespace", "backup"})

// VeleroPodVolumeBackupWedged marks (1) each velero.io
// PodVolumeBackup stuck InProgress for over 6h whose node-agent
// restarted or has no active Kopia process (W10-ST6). Labels:
// namespace + pvb name.
var VeleroPodVolumeBackupWedged = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_velero_podvolumebackup_wedged",
	Help: "1 while a PodVolumeBackup is wedged InProgress past the Kopia criteria.",
}, []string{"namespace", "pvb"})

// VeleroWedgedObjectsCleanedTotal counts wedged velero objects
// cleaned by the backup auditor (W10-ST6). action is pvb_deleted or
// pod_restarted. Labels: namespace + action.
var VeleroWedgedObjectsCleanedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_velero_wedged_objects_cleaned_total",
	Help: "Wedged velero PodVolumeBackups deleted and pods bounced, by namespace and action.",
}, []string{"namespace", "action"})

// APIServiceUnblockHealsTotal counts dead APIService heals forced
// through the namespace-skip gate by the apiservice guard (W10-CP1):
// an APIService in a normally-skipped namespace that stayed
// Available=False >=15m while a namespace sat Terminating >=15m with
// references to its API group.
var APIServiceUnblockHealsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_apiservice_unblock_heals_total",
	Help: "APIService heals forced past the skip-namespace gate, by namespace and reason.",
}, []string{"namespace", "reason"})

func init() {
	ctrlmetrics.Registry.MustRegister(
		CFTunnelWedgePodsDeletedTotal,
		VeleroBackupStuck,
		VeleroPodVolumeBackupWedged,
		VeleroWedgedObjectsCleanedTotal,
		APIServiceUnblockHealsTotal)
}
