// velero-backup-auditor — C3 "silent backup rot" sweep: backup
// schedules that stopped protecting anything without ever firing a
// conventional alert. Two signatures, both detect-only:
//
//  1. Paused schedules: a velero.io/v1 Schedule with spec.paused=true
//     continuously for >24h — nobody remembers a pause, and the next
//     restore test finds nothing to restore.
//  2. Empty/errored backups: the LATEST Backup a Schedule produced
//     reporting phase=Completed with progress.itemsBackedUp==0 or
//     progress.totalBytes==0 (reason=zero_items), or status.errors>0
//     (reason=errors), or status.warnings>0 (reason=warnings) — a
//     "successful" backup of nothing is worse than a failed one: it
//     LOOKS protected. All three reasons gate on Completed: partial
//     counters on an in-flight or failed backup are not rot.
//
// Clusters without Velero have no CRDs — the Schedule List 404s and
// the sweep no-ops quietly (same contract as externalsecret-nudge).
//
// Series lifecycle mirrors cert-drift-auditor: seen-sets prune the
// gauges the moment the condition resolves (unpaused, healthy new
// backup, object deleted).
package integration

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/controller/shared"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

const (
	veleroAuditQueue    = "velero-backup-auditor"
	veleroAuditInterval = 15 * time.Minute
	veleroPausedMinAge  = 24 * time.Hour // paused schedule must be this old to alert
	// veleroScheduleLabel links a Backup to the Schedule that made it
	// (ad-hoc backups carry no label and stay out of the audit).
	veleroScheduleLabel = "velero.io/schedule-name"
)

var (
	veleroScheduleGVR = schema.GroupVersionResource{
		Group: "velero.io", Version: "v1", Resource: "schedules"}
	veleroBackupGVR = schema.GroupVersionResource{
		Group: "velero.io", Version: "v1", Resource: "backups"}
)

// pausedKey / backupKey are the exact label tuples of the two
// exported gauge vecs — the seen-set prune pattern from
// cert-drift-auditor, kept as map keys so re-emit needs no splitting.
type pausedKey struct{ namespace, schedule string }
type backupKey struct{ namespace, schedule, reason string }

// pausedLedgerKey identifies one Schedule generation for the
// firstSeenPaused clock — the UID distinguishes a delete+recreate
// with the same name (a fresh object re-arms the 24h measurement
// instead of inheriting the dead one's pause time).
type pausedLedgerKey struct{ uid, namespace, schedule string }

type veleroBackupAuditor struct {
	cs         kubernetes.Interface // reserved for future typed reads
	dyn        dynamic.Interface
	nowFn      func() time.Time // clock seam — same pattern as certDriftAuditor
	seenPaused map[pausedKey]bool
	seenBad    map[backupKey]bool
	// firstSeenPaused: when the sweep first saw this Schedule
	// generation paused — measures the actual pause duration. A
	// Schedule carries no "paused since" timestamp, so the ledger is
	// the only honest clock; it resets on unpause and prunes on
	// delete, and a controller restart re-arms it (biased to
	// under-page, never to alert on an unmeasurable pause).
	firstSeenPaused map[pausedLedgerKey]time.Time
}

// SetupVeleroBackupAuditor registers the 15m sweep — or nothing when
// the cluster opts out (VELERO_BACKUP_AUDITOR_ENABLED in main.go feeds
// `enabled`): same disabled-flag pattern as cert-drift-auditor.
func SetupVeleroBackupAuditor(mgr ctrl.Manager, cs kubernetes.Interface,
	dyn dynamic.Interface, enabled bool) error {
	if !enabled {
		logf.Log.WithName(veleroAuditQueue).Info("disabled — module not registered")
		return nil
	}
	a := &veleroBackupAuditor{
		cs:              cs,
		dyn:             dyn,
		nowFn:           time.Now,
		seenPaused:      map[pausedKey]bool{},
		seenBad:         map[backupKey]bool{},
		firstSeenPaused: map[pausedLedgerKey]time.Time{},
	}
	return shared.AddPeriodic(mgr, veleroAuditQueue, veleroAuditInterval, a.run)
}

func (a *veleroBackupAuditor) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	// Lazily arm the zero-value struct — unit tests construct the
	// auditor literally without the Setup path.
	if a.nowFn == nil {
		a.nowFn = time.Now
	}
	if a.seenPaused == nil {
		a.seenPaused = map[pausedKey]bool{}
	}
	if a.seenBad == nil {
		a.seenBad = map[backupKey]bool{}
	}
	if a.firstSeenPaused == nil {
		a.firstSeenPaused = map[pausedLedgerKey]time.Time{}
	}

	schedules, err := a.dyn.Resource(veleroScheduleGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		// Clusters without Velero have no CRDs — quiet skip, same
		// contract as externalsecret-nudge.
		if apierrors.IsNotFound(err) {
			log.Info("skip: velero CRDs not installed")
			return nil
		}
		return fmt.Errorf("list velero schedules: %w", err)
	}
	backups, err := a.dyn.Resource(veleroBackupGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			backups = nil // schedules exist but backups CRD absent — check 1 still runs
		} else {
			return fmt.Errorf("list velero backups: %w", err)
		}
	}
	latest := latestBackupsBySchedule(backups)

	currentPaused := map[pausedKey]bool{}
	currentBad := map[backupKey]bool{}
	pausedNow := map[pausedLedgerKey]bool{}
	for i := range schedules.Items {
		s := &schedules.Items[i]
		ns, name := s.GetNamespace(), s.GetName()

		// Check 1 — spec.paused held past 24h. A Schedule carries no
		// "paused since" timestamp, so firstSeenPaused measures the
		// real pause duration from first sight; an entry pruned on
		// unpause means a re-pause restarts the clock, and the UID in
		// the key keeps a delete+recreate from inheriting pause time.
		if paused, _, _ := unstructured.NestedBool(s.Object, "spec", "paused"); paused {
			lk := pausedLedgerKey{string(s.GetUID()), ns, name}
			pausedNow[lk] = true
			if _, ok := a.firstSeenPaused[lk]; !ok {
				a.firstSeenPaused[lk] = a.nowFn()
			}
			k := pausedKey{ns, name}
			currentPaused[k] = true
			v := 0.0
			if pausedFor := a.nowFn().Sub(a.firstSeenPaused[lk]); pausedFor > veleroPausedMinAge {
				v = 1
				log.Info("velero schedule paused >24h — backups silently stopped",
					"schedule", ns+"/"+name, "pausedFor", pausedFor.Truncate(time.Hour))
			}
			metrics.VeleroSchedulePaused.WithLabelValues(ns, name).Set(v)
		}

		// Check 2 — the latest schedule-owned Backup empty/errored.
		b := latest[ns+"/"+name]
		if b == nil {
			continue // never produced a backup — nothing to judge
		}
		a.flagBadBackup(ctx, b, ns, name, currentBad)
	}

	// Prune series whose condition resolved since the last sweep —
	// a schedule unpaused or a fresh healthy backup must clear the
	// gauge, not pin it at 1.
	for k := range a.seenPaused {
		if !currentPaused[k] {
			metrics.VeleroSchedulePaused.DeleteLabelValues(k.namespace, k.schedule)
		}
	}
	a.seenPaused = currentPaused
	// Drop first-seen entries for schedules that unpaused or vanished
	// — a later re-pause measures a fresh duration, not the
	// cumulative time it once spent paused.
	for lk := range a.firstSeenPaused {
		if !pausedNow[lk] {
			delete(a.firstSeenPaused, lk)
		}
	}
	for k := range a.seenBad {
		if !currentBad[k] {
			metrics.VeleroBackupEmptyOrErrored.
				DeleteLabelValues(k.namespace, k.schedule, k.reason)
		}
	}
	a.seenBad = currentBad
	log.Info("sweep done", "schedules", len(schedules.Items),
		"paused", len(currentPaused), "badBackups", len(currentBad))
	return nil
}

// latestBackupsBySchedule indexes the newest Backup per owning
// Schedule (velero.io/schedule-name label, keyed "ns/name") —
// manual backups without the label stay out.
func latestBackupsBySchedule(backups *unstructured.UnstructuredList) map[string]*unstructured.Unstructured {
	out := map[string]*unstructured.Unstructured{}
	if backups == nil {
		return out
	}
	for i := range backups.Items {
		b := &backups.Items[i]
		sched := b.GetLabels()[veleroScheduleLabel]
		if sched == "" {
			continue
		}
		key := b.GetNamespace() + "/" + sched
		cur, ok := out[key]
		if !ok || b.GetCreationTimestamp().After(cur.GetCreationTimestamp().Time) {
			out[key] = b
		}
	}
	return out
}

// flagBadBackup evaluates the latest Backup's status against the
// three rot signatures and marks the matching reason series. All
// three gate on phase=Completed: the signatures mean "a successful
// backup that protected nothing" — errors/warnings on an in-flight
// or failed backup are partial counters, not rot.
func (a *veleroBackupAuditor) flagBadBackup(ctx context.Context,
	b *unstructured.Unstructured, ns, schedule string, current map[backupKey]bool) {
	log := logf.FromContext(ctx)
	phase, _, _ := unstructured.NestedString(b.Object, "status", "phase")
	if phase != "Completed" {
		return
	}
	items, _, _ := unstructured.NestedInt64(
		b.Object, "status", "progress", "itemsBackedUp")
	bytes, _, _ := unstructured.NestedInt64(
		b.Object, "status", "progress", "totalBytes")
	if items == 0 || bytes == 0 {
		current[backupKey{ns, schedule, "zero_items"}] = true
		metrics.VeleroBackupEmptyOrErrored.
			WithLabelValues(ns, schedule, "zero_items").Set(1)
		log.Info("velero backup completed with zero items/bytes",
			"backup", b.GetNamespace()+"/"+b.GetName(), "schedule", ns+"/"+schedule)
	}
	if errs, _, _ := unstructured.NestedInt64(b.Object, "status", "errors"); errs > 0 {
		current[backupKey{ns, schedule, "errors"}] = true
		metrics.VeleroBackupEmptyOrErrored.
			WithLabelValues(ns, schedule, "errors").Set(1)
		log.Info("velero backup completed with item errors",
			"backup", b.GetNamespace()+"/"+b.GetName(), "schedule", ns+"/"+schedule,
			"errors", errs)
	}
	if warns, _, _ := unstructured.NestedInt64(b.Object, "status", "warnings"); warns > 0 {
		current[backupKey{ns, schedule, "warnings"}] = true
		metrics.VeleroBackupEmptyOrErrored.
			WithLabelValues(ns, schedule, "warnings").Set(1)
		log.Info("velero backup completed with item warnings",
			"backup", b.GetNamespace()+"/"+b.GetName(), "schedule", ns+"/"+schedule,
			"warnings", warns)
	}
}
