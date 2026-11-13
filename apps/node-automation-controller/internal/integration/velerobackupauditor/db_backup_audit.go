// db_backup_audit.go — the shared backup-posture-audit core behind
// everest_audit.go and cnpg_audit.go: ONE table-driven sweep skeleton
// parameterized by dbBackupAudit. The skeleton is identical for both
// products — Begin the series ledger, list the primary CRDs with a
// quiet 404/NoMatch (operator not installed → empty current so the
// prune still clears stale series), gate the backup-CRD list off the
// primary result, index backups by owning cluster, run each subject
// through its skip predicate + reasons function + the zero-backup /
// no-good fallback decision, emit DBBackupUnhealthy + the ACTION log,
// and prune the ledger. What differs lives in the config table: the
// two GVRs, the list-gating rule, the backup owner field, the subject
// identity + skip predicate, the product reasons function (status.state
// vs status.phase and their age clocks) and the good-terminal-state
// predicate behind the Schrödinger's-backup stale fallback.
package velerobackupauditor

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// dbBackupAudit is the config table one product audit hands the
// shared core — every axis the everest and cnpg sweeps differ in.
type dbBackupAudit struct {
	// primaryGVR / backupGVR are the two CRD lists: the audit's
	// subjects (DatabaseCluster / ScheduledBackup) and the per-subject
	// backup history judged against them (DatabaseClusterBackup /
	// Backup).
	primaryGVR schema.GroupVersionResource
	backupGVR  schema.GroupVersionResource
	// primaryListErr / backupListErr are the error-wrap prefixes for
	// the non-benign list failures (anything but 404/NoMatch, which
	// is the operator-not-installed quiet no-op).
	primaryListErr string
	backupListErr  string
	// listBackups gates the second list on the primary result: cnpg
	// skips the Backup read entirely when no schedule exists, everest
	// always reads DatabaseClusterBackups.
	listBackups func(primary *unstructured.UnstructuredList) bool
	// ownerPath locates the owning cluster on a backup object
	// (spec.dbClusterName / spec.clusterName) for the "ns/name" index.
	ownerPath []string
	// identity resolves one primary object to the audited cluster
	// identity (namespace, cluster) plus the skip predicate — an
	// opt-in/pause gate for everest, the bound-cluster/suspend gate
	// for cnpg.
	identity func(obj *unstructured.Unstructured) (ns, cluster string, skip bool)
	// reasons judges one subject's backup history and returns the
	// unhealthy reasons that apply (product postures, possibly
	// several).
	reasons func(backups []*unstructured.Unstructured, now time.Time) []string
	// hasGood reports whether any backup in the history ever reached
	// the product's good terminal state (state=Succeeded /
	// phase=completed) — the zero-good-history half of the stale
	// fallback below.
	hasGood func(backups []*unstructured.Unstructured) bool
	// unhealthyMsg is the log line emitted per flagged reason.
	unhealthyMsg string
}

// auditDBBackups runs the shared skeleton for one product audit; seen
// is that product's DBBackupUnhealthy series ledger (own ledger per
// audit so one sweep's prune never deletes the other's series).
func (a *veleroBackupAuditor) auditDBBackups(ctx context.Context,
	seen *state.GaugeLedger[dbBackupKey], cfg dbBackupAudit) error {
	seen.Begin() // drop any aborted sweep's leftover emissions
	log := logf.FromContext(ctx)

	primary, err := a.veleroList(ctx, cfg.primaryGVR)
	switch {
	case err == nil:
		// proceed below
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		// Operator not installed — current stays empty so the
		// prune below still clears any stale series.
		primary = &unstructured.UnstructuredList{}
	default:
		return fmt.Errorf("%s: %w", cfg.primaryListErr, err)
	}

	var backups *unstructured.UnstructuredList
	if cfg.listBackups(primary) {
		backups, err = a.veleroList(ctx, cfg.backupGVR)
		switch {
		case err == nil:
			// proceed
		case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
			backups = nil // backup CRD absent — subjects audit as "no backups"
		default:
			return fmt.Errorf("%s: %w", cfg.backupListErr, err)
		}
	}

	// Index backups by owning cluster ("ns/name") once —
	// each subject then judges only its own history.
	byCluster := map[string][]*unstructured.Unstructured{}
	if backups != nil {
		for i := range backups.Items {
			b := &backups.Items[i]
			owner, _ := kube.NestedString(b.Object, cfg.ownerPath...)
			if owner == "" {
				continue
			}
			key := b.GetNamespace() + "/" + owner
			byCluster[key] = append(byCluster[key], b)
		}
	}

	now := a.now.Now()
	for i := range primary.Items {
		obj := &primary.Items[i]
		ns, cluster, skip := cfg.identity(obj)
		if skip {
			continue
		}
		clusterBackups := byCluster[ns+"/"+cluster]
		reasons := cfg.reasons(clusterBackups, now)
		// zero-backup-guard — same zero-backup blind spot as the
		// Velero Schedule check: a subject older than 36h whose
		// cluster produced ZERO backups is silently unprotected.
		// Caller-side because the age clock belongs to the subject,
		// not the (empty) backup list.
		if len(clusterBackups) == 0 {
			created := obj.GetCreationTimestamp()
			if !created.IsZero() &&
				now.Sub(created.Time) > veleroMissingBackupMaxAge {
				reasons = append(reasons, "missing")
			}
		} else if !cfg.hasGood(clusterBackups) {
			// selfheal-alert-coverage Schrödinger's-backup: backup
			// objects EXIST but none ever reached the good terminal
			// state — every attempt failed (or is wedged in
			// running) and the in-list stale check, which keys on
			// the newest GOOD backup, sees nothing. Past the 36h
			// horizon the subject is effectively unprotected.
			created := obj.GetCreationTimestamp()
			if !created.IsZero() &&
				now.Sub(created.Time) > veleroMissingBackupMaxAge {
				reasons = append(reasons, "stale")
			}
		}
		for _, reason := range reasons {
			k := dbBackupKey{ns, cluster, reason}
			seen.Set(metrics.DBBackupUnhealthy, 1, k, ns, cluster, reason)
			log.Info(cfg.unhealthyMsg,
				"cluster", ns+"/"+cluster, "reason", reason,
				"backups", len(clusterBackups))
		}
	}

	seen.Prune(metrics.DBBackupUnhealthy.DeleteLabelValues)
	return nil
}
