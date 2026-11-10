// cnpg_audit.go — cnpg-backup-audit of velero-backup-auditor: the CloudNativePG
// backup audit. CNPG ScheduledBackups drive a spec.clusterName's
// Backup objects (matched on spec.clusterName in the same namespace);
// the schedule's posture is judged for the failed / stuck / stale /
// missing postures exported on DBBackupUnhealthy{
// namespace,cluster,reason}. Clusters without the CNPG CRDs no-op
// quietly, same contract as the Velero and Everest halves.
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
// cnpg-backup-audit — CloudNativePG backup auditor
// ---------------------------------------------------------------------------

// cnpg-backup-audit — CNPG backup health thresholds: a backup still "running"
// after 6h lost the thread (same window as the Velero in-flight and
// Everest stuck checks), and the newest "completed" backup older than
// 36h means the schedule stopped producing restorable points (same
// horizon as the Everest stale check and the zero-backup threshold).
const (
	cnpgBackupStuckMaxAge = 6 * time.Hour
	cnpgBackupStaleMaxAge = 36 * time.Hour
)

// auditCNPGBackups evaluates every non-suspended ScheduledBackup
// against its cluster's Backup objects (matched on spec.clusterName
// in the same namespace) and marks unhealthy postures on
// metrics.DBBackupUnhealthy{namespace,cluster,reason}:
//
//	failed  — the LATEST backup's status.phase is "failed";
//	stuck   — ANY backup sits in "running" for >6h;
//	stale   — the newest "completed" backup is older than 36h;
//	missing — the schedule is older than 36h and its cluster has
//	          produced ZERO Backup objects.
//
// Multiple reasons can co-flag (a stuck run beside a stale success is
// both signals at once); a schedule with none emits nothing and the
// seen-set prune clears whatever it used to flag. Clusters without
// the CNPG CRDs 404/NoMatch on the list — a quiet no-op, same
// contract as the Velero and Everest halves of this module.
func (a *veleroBackupAuditor) auditCNPGBackups(ctx context.Context) error {
	a.seenCNPG.Begin() // drop any aborted sweep's leftover emissions
	log := logf.FromContext(ctx)

	sbs, err := a.veleroList(ctx, cnpgScheduledBackupGVR)
	switch {
	case err == nil:
		// proceed below
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		// CNPG operator not installed — current stays empty so the
		// prune below still clears any stale series.
		sbs = &unstructured.UnstructuredList{}
	default:
		return fmt.Errorf("list cnpg scheduledbackups: %w", err)
	}

	var backups *unstructured.UnstructuredList
	if len(sbs.Items) > 0 {
		backups, err = a.veleroList(ctx, cnpgBackupGVR)
		switch {
		case err == nil:
			// proceed
		case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
			backups = nil // backup CRD absent — schedules audit as "no backups"
		default:
			return fmt.Errorf("list cnpg backups: %w", err)
		}
	}

	// Index backups by owning cluster ("ns/spec.clusterName") once —
	// each schedule then judges only its own cluster's history.
	byCluster := map[string][]*unstructured.Unstructured{}
	if backups != nil {
		for i := range backups.Items {
			b := &backups.Items[i]
			owner, _ := kube.NestedString(b.Object, "spec", "clusterName")
			if owner == "" {
				continue
			}
			key := b.GetNamespace() + "/" + owner
			byCluster[key] = append(byCluster[key], b)
		}
	}

	now := a.now.Now()
	for i := range sbs.Items {
		sb := &sbs.Items[i]
		ns := sb.GetNamespace()
		cluster, _ := kube.NestedString(sb.Object, "spec", "clusterName")
		if cluster == "" {
			continue // schedule not bound to a cluster — nothing to judge
		}
		// A suspended schedule's stale backups are deliberate, not
		// rot — same posture as a paused Velero Schedule / paused
		// Everest DatabaseCluster.
		if suspend, _ := kube.NestedBool(sb.Object, "spec", "suspend"); suspend {
			continue
		}
		clusterBackups := byCluster[ns+"/"+cluster]
		reasons := cnpgBackupReasons(clusterBackups, now)
		// Same zero-backup blind spot as the Velero Schedule and
		// Everest cluster checks: a schedule older than 36h whose
		// cluster produced ZERO backups is silently unprotected.
		// Caller-side because the age clock belongs to the schedule,
		// not the (empty) backup list.
		if len(clusterBackups) == 0 {
			sbCreated := sb.GetCreationTimestamp()
			if !sbCreated.IsZero() &&
				now.Sub(sbCreated.Time) > veleroMissingBackupMaxAge {
				reasons = append(reasons, "missing")
			}
		} else if !cnpgHasCompleted(clusterBackups) {
			// W24 Schrödinger's-backup: backup objects EXIST but
			// none ever reached phase=completed — every attempt
			// failed (or is wedged) and the newest may sit in
			// "running" forever, so the in-list stale check (which
			// keys on the newest COMPLETED) sees nothing. Past the
			// 36h horizon the schedule is effectively unprotected.
			// Caller-side because the age clock is the schedule's.
			sbCreated := sb.GetCreationTimestamp()
			if !sbCreated.IsZero() &&
				now.Sub(sbCreated.Time) > veleroMissingBackupMaxAge {
				reasons = append(reasons, "stale")
			}
		}
		for _, reason := range reasons {
			k := everestKey{ns, cluster, reason}
			a.seenCNPG.Set(metrics.DBBackupUnhealthy, 1, k, ns, cluster, reason)
			log.Info("cnpg cluster backup unhealthy",
				"cluster", ns+"/"+cluster, "reason", reason,
				"backups", len(clusterBackups))
		}
	}

	a.seenCNPG.Prune(metrics.DBBackupUnhealthy.DeleteLabelValues)
	return nil
}

// cnpgBackupReasons evaluates one cluster's CNPG backup list and
// returns the unhealthy reasons that apply (possibly several,
// possibly none). Backup ordering is by creationTimestamp — the same
// "latest" convention everestBackupReasons uses. CNPG Backup
// status.phase values are lowercase ("running", "completed",
// "failed"); ages read status.startedAt / status.stoppedAt
// (RFC3339) when present, else creationTimestamp.
func cnpgBackupReasons(backups []*unstructured.Unstructured,
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

	// failed — the LATEST backup ended failed.
	if phase, _ := kube.NestedString(
		sorted[0].Object, "status", "phase"); phase == "failed" {
		reasons = append(reasons, "failed")
	}

	// stuck — ANY backup wedged in running past 6h.
	for _, b := range sorted {
		phase, _ := kube.NestedString(b.Object, "status", "phase")
		if phase != "running" {
			continue
		}
		if now.Sub(cnpgBackupStart(b)) > cnpgBackupStuckMaxAge {
			reasons = append(reasons, "stuck")
			break
		}
	}

	// stale — the newest completed backup is older than 36h. Age is
	// measured from status.stoppedAt when present (the moment the
	// restorable point actually landed), else startedAt, else
	// creationTimestamp — same convention as the Everest stale check.
	// The same pass judges the newest completed backup's restore
	// metadata (W24 empty_metadata — a "green shell, red heart"
	// backup that cannot PITR/restore).
	for _, b := range sorted {
		phase, _ := kube.NestedString(b.Object, "status", "phase")
		if phase != "completed" {
			continue
		}
		if now.Sub(cnpgBackupDone(b)) > cnpgBackupStaleMaxAge {
			reasons = append(reasons, "stale")
		}
		if cnpgBackupEmptyMetadata(b) {
			reasons = append(reasons, "empty_metadata")
		}
		break // newest completed decides — older ones are history
	}
	return reasons
}

// cnpgHasCompleted reports whether any backup in the cluster's
// history reached phase=completed — the zero-completed-history half
// of the W24 stale check (caller-side: it needs the schedule's age).
func cnpgHasCompleted(backups []*unstructured.Unstructured) bool {
	for _, b := range backups {
		if phase, _ := kube.NestedString(
			b.Object, "status", "phase"); phase == "completed" {
			return true
		}
	}
	return false
}

// cnpgBackupEmptyMetadata reports whether a completed CNPG backup
// carries no usable restore metadata — the "xanh vỏ đỏ lòng" (green
// shell, red heart) signature: phase=completed but the object
// cannot actually restore. Two shapes flag:
//
//   - status.error non-empty — CNPG recorded a completion-time
//     error on the backup;
//   - Barman-method backups (status.method != "volumeSnapshot")
//     with BOTH status.backupId and status.beginWal empty — no WAL
//     range was ever registered, so PITR has nothing to replay.
//     volumeSnapshot backups restore from the snapshot itself and
//     legitimately carry neither field.
func cnpgBackupEmptyMetadata(b *unstructured.Unstructured) bool {
	if e, _ := kube.NestedString(b.Object, "status", "error"); e != "" {
		return true
	}
	method, _ := kube.NestedString(b.Object, "status", "method")
	if method == "volumeSnapshot" {
		return false
	}
	backupID, _ := kube.NestedString(b.Object, "status", "backupId")
	beginWal, _ := kube.NestedString(b.Object, "status", "beginWal")
	return backupID == "" && beginWal == ""
}

// cnpgBackupStart is the running-age clock: status.startedAt when
// parseable, else creationTimestamp.
func cnpgBackupStart(b *unstructured.Unstructured) time.Time {
	return cnpgBackupTime(b, "startedAt")
}

// cnpgBackupDone is the completed-age clock: status.stoppedAt, then
// status.startedAt, then creationTimestamp.
func cnpgBackupDone(b *unstructured.Unstructured) time.Time {
	if t, ok := kube.NestedString(b.Object, "status", "stoppedAt"); ok {
		if tt, err := time.Parse(time.RFC3339, t); err == nil {
			return tt
		}
	}
	return cnpgBackupTime(b, "startedAt")
}

func cnpgBackupTime(b *unstructured.Unstructured, field string) time.Time {
	if t, ok := kube.NestedString(b.Object, "status", field); ok {
		if tt, err := time.Parse(time.RFC3339, t); err == nil {
			return tt
		}
	}
	return b.GetCreationTimestamp().Time
}
