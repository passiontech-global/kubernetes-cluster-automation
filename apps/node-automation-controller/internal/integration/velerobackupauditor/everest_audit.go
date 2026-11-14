// everest_audit.go — backup-posture-audit of velero-backup-auditor: the Percona
// Everest DatabaseCluster backup audit. Backup-enabled, unpaused
// DatabaseClusters are judged against their DatabaseClusterBackups
// (matched on spec.dbClusterName in the same namespace) for the
// failed / stuck / stale / missing postures exported on
// DBBackupUnhealthy{namespace,cluster,reason}. Clusters without the
// Everest CRDs no-op quietly, same contract as the Velero half.
// The sweep skeleton (list/404/index/skip/zero-backup/emit/prune)
// lives in db_backup_audit.go — this file is the Everest row of that
// table plus the product-specific reason functions.
package velerobackupauditor

import (
	"context"
	"slices"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// ---------------------------------------------------------------------------
// backup-posture-audit — Everest (Percona) DatabaseCluster backup auditor
// ---------------------------------------------------------------------------

// everestDBBackupAudit is the backup-posture-audit Everest row of the
// db_backup_audit.go table: the DatabaseCluster/DatabaseClusterBackup
// GVR pair, the always-list backup gating, the spec.dbClusterName
// owner field, the backup-enabled-and-not-paused skip predicate and
// the status.state reasons functions.
var everestDBBackupAudit = dbBackupAudit{
	primaryGVR:     everestDBClusterGVR,
	backupGVR:      everestDBBackupGVR,
	primaryListErr: "list everest databaseclusters",
	backupListErr:  "list everest databaseclusterbackups",
	listBackups: func(*unstructured.UnstructuredList) bool {
		// everest reads DatabaseClusterBackups regardless of the
		// cluster list — the primary result is non-nil past the
		// 404/NoMatch switch either way.
		return true
	},
	ownerPath: []string{"spec", "dbClusterName"},
	identity: func(dc *unstructured.Unstructured) (string, string, bool) {
		ns, name := dc.GetNamespace(), dc.GetName()
		// Only clusters that opted into backups AND are not paused —
		// a paused cluster's stale backups are deliberate, not rot.
		enabled, _ := kube.NestedBool(dc.Object, "spec", "backup", "enabled")
		paused, _ := kube.NestedBool(dc.Object, "spec", "paused")
		return ns, name, !enabled || paused
	},
	reasons:      everestBackupReasons,
	hasGood:      everestHasSucceeded,
	unhealthyMsg: "everest databasecluster backup unhealthy",
}

// auditEverestBackups evaluates every unpaused DatabaseCluster with
// spec.backup.enabled against its DatabaseClusterBackups (matched on
// spec.dbClusterName in the same namespace) and marks unhealthy
// postures on metrics.DBBackupUnhealthy{namespace,cluster,reason}:
//
//	failed — the LATEST backup's status.state is "Failed";
//	stuck  — ANY backup sits in "Running"/"Starting" for >6h;
//	stale  — the newest "Succeeded" backup is older than 36h.
//
// Multiple reasons can co-flag (a stuck run beside a stale success
// is both signals at once); a cluster with none emits nothing and
// the seen-set prune clears whatever it used to flag. Clusters
// without the Everest CRDs 404/NoMatch on the list — a quiet no-op,
// same contract as the Velero half of this module.
func (a *veleroBackupAuditor) auditEverestBackups(ctx context.Context) error {
	return a.auditDBBackups(ctx, &a.seenEverest, everestDBBackupAudit)
}

// everestBackupReasons evaluates one DatabaseCluster's backup list
// and returns the unhealthy reasons that apply (possibly several,
// possibly none). Backup ordering is by creationTimestamp — the same
// "latest" convention latestBackupsBySchedule uses for Velero.
func everestBackupReasons(backups []*unstructured.Unstructured,
	now time.Time) []string {
	if len(backups) == 0 {
		return nil // never produced a backup — can't judge, not rot
	}
	// Newest first by creationTimestamp.
	sorted := slices.Clone(backups)
	slices.SortFunc(sorted, func(x, y *unstructured.Unstructured) int {
		return y.GetCreationTimestamp().Compare(x.GetCreationTimestamp().Time)
	})
	var reasons []string

	// failed — the LATEST backup ended Failed.
	if state, _ := kube.NestedString(
		sorted[0].Object, "status", "state"); state == "Failed" {
		reasons = append(reasons, "failed")
	}

	// stuck — ANY backup wedged in Running/Starting past 6h.
	for _, b := range sorted {
		state, _ := kube.NestedString(b.Object, "status", "state")
		if state != "Running" && state != "Starting" {
			continue
		}
		if now.Sub(b.GetCreationTimestamp().Time) > everestBackupStuckMaxAge {
			reasons = append(reasons, "stuck")
			break
		}
	}

	// stale — the newest Succeeded backup is older than 36h. Age is
	// measured from status.completionTime when present (the moment
	// the restorable point actually landed), else creationTimestamp.
	for _, b := range sorted {
		state, _ := kube.NestedString(b.Object, "status", "state")
		if state != "Succeeded" {
			continue
		}
		done := kube.NestedStatusTimeOrCreated(b, "completionTime")
		if now.Sub(done) > everestBackupStaleMaxAge {
			reasons = append(reasons, "stale")
		}
		break // newest Succeeded decides — older ones are history
	}
	return reasons
}

// everestHasSucceeded reports whether any backup in the cluster's
// history reached state=Succeeded — the zero-success-history half
// of the selfheal-alert-coverage stale check (caller-side: it needs the cluster's age).
func everestHasSucceeded(backups []*unstructured.Unstructured) bool {
	for _, b := range backups {
		if state, _ := kube.NestedString(
			b.Object, "status", "state"); state == "Succeeded" {
			return true
		}
	}
	return false
}
