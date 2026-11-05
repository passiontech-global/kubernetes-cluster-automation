// Wave 9 self-healing metrics (W9-CP1/W9-CP2/W9-ST3/W9-GO1).
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

// HelmSecretsPrunedTotal counts superseded helm release secrets
// deleted by the helmrelease-unlocker Kine bloat guard (W9-CP2) —
// helm keeps every revision forever and each secret embeds the full
// compressed chart, so unbounded superseded history bloats Kine.
// Label: the namespace the release secrets live in.
var HelmSecretsPrunedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "node_automation_helm_secrets_pruned_total",
	Help: "Superseded helm release secrets pruned per release, by namespace.",
}, []string{"namespace"})

// DBBackupUnhealthy marks (1) each Everest DatabaseCluster whose
// backup posture is unhealthy (W9-ST3). reason is failed (latest
// backup Failed), stuck (a Running/Starting backup older than 6h)
// or stale (newest Succeeded backup older than 36h). Labels:
// DatabaseCluster namespace + name + reason.
var DBBackupUnhealthy = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_db_backup_unhealthy",
	Help: "1 while the DatabaseCluster's backups are failed, stuck or stale.",
}, []string{"namespace", "cluster", "reason"})

// ExternalSecretStormSuppressed marks (1) while the
// externalsecret-nudge storm guard is active (W9-GO1): >=5
// ExternalSecrets Ready=False AND >=50% of all ExternalSecrets
// failing simultaneously — the signature of a 1Password
// Connect/429/store outage where force-sync stamps would only
// amplify the failure.
var ExternalSecretStormSuppressed = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "node_automation_externalsecret_storm_suppressed",
	Help: "1 while the ExternalSecret storm guard suppresses force-sync stamps.",
})

func init() {
	ctrlmetrics.Registry.MustRegister(
		HelmSecretsPrunedTotal, DBBackupUnhealthy, ExternalSecretStormSuppressed)
}
