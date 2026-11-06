// schedule_audit.go — the per-Schedule rot checks of
// velero-backup-auditor: flagMissingBackups (W10-FIX6 — a Schedule
// older than veleroMissingBackupMaxAge that produced ZERO Backup
// objects is silently unprotected) and flagBadBackup (the latest
// schedule-owned Backup's empty/errored/wedged signatures on
// VeleroBackupEmptyOrErrored{namespace,schedule,reason}).
package velerobackupauditor

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// flagMissingBackups is the W10-FIX6 zero-backup check: a Schedule
// older than veleroMissingBackupMaxAge (36h) that has produced ZERO
// Backup objects is silently unprotected — the schedule fires, the
// backups vanish (or never ran), and every other check sees
// "nothing to judge". Flags reason=missing on the same
// VeleroBackupEmptyOrErrored series the other rot signatures use.
// A zero creationTimestamp cannot prove age — skipped (fail closed).
func (a *veleroBackupAuditor) flagMissingBackups(ctx context.Context,
	s *unstructured.Unstructured, ns, schedule string) {
	log := logf.FromContext(ctx)
	created := s.GetCreationTimestamp()
	if created.IsZero() {
		return
	}
	age := a.now.Now().Sub(created.Time)
	if age <= veleroMissingBackupMaxAge {
		return
	}
	a.seenBad.Set(metrics.VeleroBackupEmptyOrErrored, 1,
		backupKey{ns, schedule, "missing"}, ns, schedule, "missing")
	log.Info("velero schedule older than 36h has zero backups — silently unprotected",
		"schedule", ns+"/"+schedule, "age", age.Truncate(time.Hour))
}

// flagBadBackup evaluates the latest Backup's status against the
// three rot signatures and marks the matching reason series. All
// three gate on phase=Completed: the signatures mean "a successful
// backup that protected nothing" — errors/warnings on an in-flight
// or failed backup are partial counters, not rot.
func (a *veleroBackupAuditor) flagBadBackup(ctx context.Context,
	b *unstructured.Unstructured, ns, schedule string) {
	log := logf.FromContext(ctx)
	phase, _ := kube.NestedString(b.Object, "status", "phase")
	// W8-ST1 — terminal failures and wedged in-flight phases are
	// flagged on their own reason series before the Completed path
	// runs: Failed/PartiallyFailed/FailedValidation flag immediately,
	// InProgress/Deleting only past 6h (measured from
	// status.startTimestamp, else creationTimestamp).
	if reason, watched := veleroStuckPhases[phase]; watched {
		flag := reason == "failed"
		if reason == "stuck" {
			since := b.GetCreationTimestamp().Time
			if st, ok := kube.NestedString(
				b.Object, "status", "startTimestamp"); ok {
				if t, err := time.Parse(time.RFC3339, st); err == nil {
					since = t
				}
			}
			flag = a.now.Now().Sub(since) > veleroStuckMaxAge
		}
		if flag {
			a.seenBad.Set(metrics.VeleroBackupEmptyOrErrored, 1,
				backupKey{ns, schedule, reason}, ns, schedule, reason)
			log.Info("velero backup in a bad phase",
				"backup", b.GetNamespace()+"/"+b.GetName(),
				"schedule", ns+"/"+schedule, "phase", phase)
		}
		return
	}
	if phase != "Completed" {
		return
	}
	// Velero's BackupProgress carries itemsBackedUp/totalItems — there
	// is no totalBytes field (reading one always yields 0). Both reads
	// gate on `found`: a Completed backup with no progress block at
	// all (older Velero, stripped status) is "can't tell", not empty —
	// without the gate every absent-progress backup false-flags.
	items, itemsFound := kube.NestedInt64(
		b.Object, "status", "progress", "itemsBackedUp")
	total, totalFound := kube.NestedInt64(
		b.Object, "status", "progress", "totalItems")
	if (itemsFound && items == 0) || (totalFound && total == 0) {
		a.seenBad.Set(metrics.VeleroBackupEmptyOrErrored, 1,
			backupKey{ns, schedule, "zero_items"}, ns, schedule, "zero_items")
		log.Info("velero backup completed with zero items",
			"backup", b.GetNamespace()+"/"+b.GetName(), "schedule", ns+"/"+schedule)
	}
	if errs, _ := kube.NestedInt64(b.Object, "status", "errors"); errs > 0 {
		a.seenBad.Set(metrics.VeleroBackupEmptyOrErrored, 1,
			backupKey{ns, schedule, "errors"}, ns, schedule, "errors")
		log.Info("velero backup completed with item errors",
			"backup", b.GetNamespace()+"/"+b.GetName(), "schedule", ns+"/"+schedule,
			"errors", errs)
	}
	if warns, _ := kube.NestedInt64(b.Object, "status", "warnings"); warns > 0 {
		a.seenBad.Set(metrics.VeleroBackupEmptyOrErrored, 1,
			backupKey{ns, schedule, "warnings"}, ns, schedule, "warnings")
		log.Info("velero backup completed with item warnings",
			"backup", b.GetNamespace()+"/"+b.GetName(), "schedule", ns+"/"+schedule,
			"warnings", warns)
	}
}
