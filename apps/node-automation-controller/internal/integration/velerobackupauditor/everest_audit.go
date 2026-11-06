// everest_audit.go — W9-ST3 of velero-backup-auditor: the Percona
// Everest DatabaseCluster backup audit. Backup-enabled, unpaused
// DatabaseClusters are judged against their DatabaseClusterBackups
// (matched on spec.dbClusterName in the same namespace) for the
// failed / stuck / stale / missing postures exported on
// DBBackupUnhealthy{namespace,cluster,reason}. Clusters without the
// Everest CRDs no-op quietly, same contract as the Velero half.
package velerobackupauditor

import (
	"context"
	"fmt"
	"slices"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// ---------------------------------------------------------------------------
// W9-ST3 — Everest (Percona) DatabaseCluster backup auditor
// ---------------------------------------------------------------------------

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
	a.seenEverest.Begin() // drop any aborted sweep's leftover emissions
	log := logf.FromContext(ctx)

	clusters, err := a.veleroList(ctx, everestDBClusterGVR)
	switch {
	case err == nil:
		// proceed below
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		// Everest operator not installed — current stays empty so the
		// prune below still clears any stale series.
		clusters = &unstructured.UnstructuredList{}
	default:
		return fmt.Errorf("list everest databaseclusters: %w", err)
	}

	var backups *unstructured.UnstructuredList
	if clusters != nil {
		backups, err = a.veleroList(ctx, everestDBBackupGVR)
		switch {
		case err == nil:
			// proceed
		case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
			backups = nil // backup CRD absent — clusters audit as "no backups"
		default:
			return fmt.Errorf("list everest databaseclusterbackups: %w", err)
		}
	}

	// Index backups by owning DatabaseCluster ("ns/name") once —
	// each cluster then judges only its own history.
	byCluster := map[string][]*unstructured.Unstructured{}
	if backups != nil {
		for i := range backups.Items {
			b := &backups.Items[i]
			owner, _ := kube.NestedString(b.Object, "spec", "dbClusterName")
			if owner == "" {
				continue
			}
			key := b.GetNamespace() + "/" + owner
			byCluster[key] = append(byCluster[key], b)
		}
	}

	now := a.now.Now()
	for i := range clusters.Items {
		dc := &clusters.Items[i]
		ns, name := dc.GetNamespace(), dc.GetName()
		// Only clusters that opted into backups AND are not paused —
		// a paused cluster's stale backups are deliberate, not rot.
		enabled, _ := kube.NestedBool(dc.Object, "spec", "backup", "enabled")
		paused, _ := kube.NestedBool(dc.Object, "spec", "paused")
		if !enabled || paused {
			continue
		}
		clusterBackups := byCluster[ns+"/"+name]
		reasons := everestBackupReasons(clusterBackups, now)
		// W10-FIX6 — same zero-backup blind spot as the Velero
		// Schedule check: a backup-enabled DatabaseCluster older
		// than 36h with ZERO DatabaseClusterBackups is silently
		// unprotected. Caller-side because the age clock belongs to
		// the cluster, not the (empty) backup list.
		if len(clusterBackups) == 0 {
			dcCreated := dc.GetCreationTimestamp()
			if !dcCreated.IsZero() &&
				now.Sub(dcCreated.Time) > veleroMissingBackupMaxAge {
				reasons = append(reasons, "missing")
			}
		}
		for _, reason := range reasons {
			k := everestKey{ns, name, reason}
			a.seenEverest.Set(metrics.DBBackupUnhealthy, 1, k, ns, name, reason)
			log.Info("everest databasecluster backup unhealthy",
				"cluster", ns+"/"+name, "reason", reason,
				"backups", len(clusterBackups))
		}
	}

	a.seenEverest.Prune(metrics.DBBackupUnhealthy.DeleteLabelValues)
	return nil
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
		done := b.GetCreationTimestamp().Time
		if ct, ok := kube.NestedString(
			b.Object, "status", "completionTime"); ok {
			if t, err := time.Parse(time.RFC3339, ct); err == nil {
				done = t
			}
		}
		if now.Sub(done) > everestBackupStaleMaxAge {
			reasons = append(reasons, "stale")
		}
		break // newest Succeeded decides — older ones are history
	}
	return reasons
}
