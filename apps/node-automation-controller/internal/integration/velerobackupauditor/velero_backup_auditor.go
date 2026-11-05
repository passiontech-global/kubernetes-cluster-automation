// velero-backup-auditor — C3 "silent backup rot" sweep: backup
// schedules that stopped protecting anything without ever firing a
// conventional alert. Two signatures, both detect-only:
//
//  1. Paused schedules: a velero.io/v1 Schedule with spec.paused=true
//     continuously for >24h — nobody remembers a pause, and the next
//     restore test finds nothing to restore.
//  2. Empty/errored backups: the LATEST Backup a Schedule produced
//     reporting phase=Completed with progress.itemsBackedUp==0 or
//     progress.totalItems==0 — progress fields actually PRESENT, else
//     the read is "can't tell" (reason=zero_items) — or
//     status.errors>0 (reason=errors), or status.warnings>0
//     (reason=warnings) — a "successful" backup of nothing is worse
//     than a failed one: it LOOKS protected. All three reasons gate
//     on Completed: partial counters on an in-flight or failed
//     backup are not rot.
//
// Clusters without Velero have no CRDs — the Schedule List 404s and
// the sweep no-ops quietly (same contract as externalsecret-nudge).
//
// Series lifecycle mirrors cert-drift-auditor: seen-sets prune the
// gauges the moment the condition resolves (unpaused, healthy new
// backup, object deleted).
package velerobackupauditor

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
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
	veleroBSLGVR = schema.GroupVersionResource{
		Group: "velero.io", Version: "v1", Resource: "backupstoragelocations"}
	// W9-ST3 — Percona Everest operator CRDs: the DatabaseCluster
	// declares spec.backup.enabled and the DatabaseClusterBackup
	// carries spec.dbClusterName + status.state.
	everestDBClusterGVR = schema.GroupVersionResource{
		Group: "everest.percona.com", Version: "v1alpha1", Resource: "databaseclusters"}
	everestDBBackupGVR = schema.GroupVersionResource{
		Group: "everest.percona.com", Version: "v1alpha1", Resource: "databaseclusterbackups"}
)

// veleroStuckPhases are terminal-failure and wedged-in-flight
// signatures — a backup Failed, PartiallyFailed or FailedValidation
// is a data-protection failure worth surfacing, and InProgress or
// Deleting held past veleroStuckMaxAge means the velero server lost
// the thread (W8-ST1).
var veleroStuckPhases = map[string]string{
	"Failed":           "failed",
	"PartiallyFailed":  "failed",
	"FailedValidation": "failed",
	"InProgress":       "stuck",
	"Deleting":         "stuck",
}

const veleroStuckMaxAge = 6 * time.Hour

// W9-ST3 — Everest backup health thresholds: a backup still
// Running/Starting after 6h lost the thread (same window as the
// Velero in-flight check), and the newest Succeeded backup older
// than 36h means the schedule stopped producing restorable points.
const (
	everestBackupStuckMaxAge = 6 * time.Hour
	everestBackupStaleMaxAge = 36 * time.Hour
)

// pausedKey / backupKey are the exact label tuples of the two
// exported gauge vecs — the seen-set prune pattern from
// cert-drift-auditor, kept as map keys so re-emit needs no splitting.
type pausedKey struct{ namespace, schedule string }
type backupKey struct{ namespace, schedule, reason string }

// everestKey identifies one DBBackupUnhealthy series — the label
// triple (namespace, DatabaseCluster name, reason) needed to delete
// it again once the cluster's backup posture recovers.
type everestKey struct{ namespace, cluster, reason string }

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
	// seenBSL: series ledger for VeleroBSLUnavailable — an
	// Available-again or deleted BSL gets DeleteLabelValues.
	seenBSL map[pausedKey]bool
	// firstSeenPaused: when the sweep first saw this Schedule
	// generation paused — measures the actual pause duration. A
	// Schedule carries no "paused since" timestamp, so the ledger is
	// the only honest clock; it resets on unpause and prunes on
	// delete, and a controller restart re-arms it (biased to
	// under-page, never to alert on an unmeasurable pause).
	firstSeenPaused map[pausedLedgerKey]time.Time
	// seenEverest: series ledger for DBBackupUnhealthy — an
	// everestKey the sweep stops re-asserting gets
	// DeleteLabelValues'd so a recovered or deleted
	// DatabaseCluster never pins the gauge.
	seenEverest map[everestKey]bool
}

// Setup registers the 15m sweep — or nothing when
// the cluster opts out (VELERO_BACKUP_AUDITOR_ENABLED in main.go feeds
// `enabled`): same disabled-flag pattern as cert-drift-auditor.
func Setup(mgr ctrl.Manager, cs kubernetes.Interface,
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
		seenBSL:         map[pausedKey]bool{},
		firstSeenPaused: map[pausedLedgerKey]time.Time{},
		seenEverest:     map[everestKey]bool{},
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
	if a.seenBSL == nil {
		a.seenBSL = map[pausedKey]bool{}
	}
	if a.firstSeenPaused == nil {
		a.firstSeenPaused = map[pausedLedgerKey]time.Time{}
	}
	if a.seenEverest == nil {
		a.seenEverest = map[everestKey]bool{}
	}

	// W9-ST3 — the Everest DB-backup audit is independent of Velero:
	// a cluster can run the Percona operator with no Velero at all,
	// so it runs before (and regardless of) the schedule 404 early
	// return below. Its error joins the run's, never masks it.
	everestErr := a.auditEverestBackups(ctx)

	schedules, err := a.dyn.Resource(veleroScheduleGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		// Clusters without Velero have no CRDs — quiet skip, same
		// contract as externalsecret-nudge.
		if apierrors.IsNotFound(err) {
			log.Info("skip: velero CRDs not installed")
			return everestErr
		}
		return errors.Join(everestErr,
			fmt.Errorf("list velero schedules: %w", err))
	}
	backups, err := a.dyn.Resource(veleroBackupGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			backups = nil // schedules exist but backups CRD absent — check 1 still runs
		} else {
			return errors.Join(everestErr,
				fmt.Errorf("list velero backups: %w", err))
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

	// W8-ST1 — BackupStorageLocation availability: a BSL not
	// phase=Available means backups run to an unreachable bucket and
	// the next restore has nothing to read.
	currentBSL := map[pausedKey]bool{}
	bsls, err := a.dyn.Resource(veleroBSLGVR).List(ctx, metav1.ListOptions{})
	switch {
	case apierrors.IsNotFound(err):
		// CRD absent — nothing to audit.
	case err != nil:
		return errors.Join(everestErr,
			fmt.Errorf("list velero backupstoragelocations: %w", err))
	default:
		for i := range bsls.Items {
			bsl := &bsls.Items[i]
			ns, name := bsl.GetNamespace(), bsl.GetName()
			phase, _, _ := unstructured.NestedString(bsl.Object, "status", "phase")
			if phase == "Available" {
				continue
			}
			k := pausedKey{ns, name}
			currentBSL[k] = true
			metrics.VeleroBSLUnavailable.WithLabelValues(ns, name).Set(1)
			log.Info("velero BSL unavailable — backups/restore at risk",
				"bsl", ns+"/"+name, "phase", phase)
		}
	}
	for k := range a.seenBSL {
		if !currentBSL[k] {
			metrics.VeleroBSLUnavailable.DeleteLabelValues(k.namespace, k.schedule)
		}
	}
	a.seenBSL = currentBSL

	log.Info("sweep done", "schedules", len(schedules.Items),
		"paused", len(currentPaused), "badBackups", len(currentBad),
		"bslUnavailable", len(currentBSL))
	return everestErr
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
	// W8-ST1 — terminal failures and wedged in-flight phases are
	// flagged on their own reason series before the Completed path
	// runs: Failed/PartiallyFailed/FailedValidation flag immediately,
	// InProgress/Deleting only past 6h (measured from
	// status.startTimestamp, else creationTimestamp).
	if reason, watched := veleroStuckPhases[phase]; watched {
		flag := reason == "failed"
		if reason == "stuck" {
			since := b.GetCreationTimestamp().Time
			if st, found, _ := unstructured.NestedString(
				b.Object, "status", "startTimestamp"); found {
				if t, err := time.Parse(time.RFC3339, st); err == nil {
					since = t
				}
			}
			flag = a.nowFn().Sub(since) > veleroStuckMaxAge
		}
		if flag {
			current[backupKey{ns, schedule, reason}] = true
			metrics.VeleroBackupEmptyOrErrored.
				WithLabelValues(ns, schedule, reason).Set(1)
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
	items, itemsFound, _ := unstructured.NestedInt64(
		b.Object, "status", "progress", "itemsBackedUp")
	total, totalFound, _ := unstructured.NestedInt64(
		b.Object, "status", "progress", "totalItems")
	if (itemsFound && items == 0) || (totalFound && total == 0) {
		current[backupKey{ns, schedule, "zero_items"}] = true
		metrics.VeleroBackupEmptyOrErrored.
			WithLabelValues(ns, schedule, "zero_items").Set(1)
		log.Info("velero backup completed with zero items",
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
	log := logf.FromContext(ctx)
	current := map[everestKey]bool{}

	clusters, err := a.dyn.Resource(everestDBClusterGVR).List(ctx, metav1.ListOptions{})
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
		backups, err = a.dyn.Resource(everestDBBackupGVR).List(ctx, metav1.ListOptions{})
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
			owner, _, _ := unstructured.NestedString(b.Object, "spec", "dbClusterName")
			if owner == "" {
				continue
			}
			key := b.GetNamespace() + "/" + owner
			byCluster[key] = append(byCluster[key], b)
		}
	}

	now := a.nowFn()
	for i := range clusters.Items {
		dc := &clusters.Items[i]
		ns, name := dc.GetNamespace(), dc.GetName()
		// Only clusters that opted into backups AND are not paused —
		// a paused cluster's stale backups are deliberate, not rot.
		enabled, _, _ := unstructured.NestedBool(dc.Object, "spec", "backup", "enabled")
		paused, _, _ := unstructured.NestedBool(dc.Object, "spec", "paused")
		if !enabled || paused {
			continue
		}
		clusterBackups := byCluster[ns+"/"+name]
		reasons := everestBackupReasons(clusterBackups, now)
		for _, reason := range reasons {
			k := everestKey{ns, name, reason}
			current[k] = true
			metrics.DBBackupUnhealthy.WithLabelValues(ns, name, reason).Set(1)
			log.Info("everest databasecluster backup unhealthy",
				"cluster", ns+"/"+name, "reason", reason,
				"backups", len(clusterBackups))
		}
	}

	for k := range a.seenEverest {
		if !current[k] {
			metrics.DBBackupUnhealthy.DeleteLabelValues(
				k.namespace, k.cluster, k.reason)
		}
	}
	a.seenEverest = current
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
		return y.GetCreationTimestamp().Time.Compare(x.GetCreationTimestamp().Time)
	})
	var reasons []string

	// failed — the LATEST backup ended Failed.
	if state, _, _ := unstructured.NestedString(
		sorted[0].Object, "status", "state"); state == "Failed" {
		reasons = append(reasons, "failed")
	}

	// stuck — ANY backup wedged in Running/Starting past 6h.
	for _, b := range sorted {
		state, _, _ := unstructured.NestedString(b.Object, "status", "state")
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
		state, _, _ := unstructured.NestedString(b.Object, "status", "state")
		if state != "Succeeded" {
			continue
		}
		done := b.GetCreationTimestamp().Time
		if ct, found, _ := unstructured.NestedString(
			b.Object, "status", "completionTime"); found {
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
