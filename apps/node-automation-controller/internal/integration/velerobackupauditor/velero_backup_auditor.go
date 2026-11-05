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
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
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
	// W10-ST6 — podvolumebackups.velero.io: per-volume snapshots
	// taken by the node-agent DaemonSet; a wedged InProgress PVB
	// blocks the next backup's volume phase.
	veleroPVBGVR = schema.GroupVersionResource{
		Group: "velero.io", Version: "v1", Resource: "podvolumebackups"}
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

// veleroMissingBackupMaxAge is the W10-FIX6 zero-backup threshold:
// a Schedule (or backup-enabled DatabaseCluster) older than 36h
// that has produced ZERO backup objects is silently unprotected —
// same horizon as the Everest stale check.
const veleroMissingBackupMaxAge = 36 * time.Hour

// veleroPVBCleanup* bound the W10-ST6 wedged-PVB cleaner: only
// InProgress PVBs past the 6h stuck window are candidates, at most
// this many are cleaned per sweep, and a cleaned PVB name cools down
// so a still-broken agent cannot be delete-looped.
const (
	veleroPVBCleanupMaxPerRun = 3
	veleroPVBCleanupCooldown  = 30 * time.Minute
)

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
	// seenStuckBackup / seenWedgedPVB: series ledgers for the
	// W10-ST6 in-flight gauges — same prune-on-resolve contract.
	seenStuckBackup map[pausedKey]bool
	seenWedgedPVB   map[pausedKey]bool
	// pvbHealed: "<ns>/<name>" -> last wedged-PVB cleanup time —
	// the per-object cooldown that stops a still-broken node-agent
	// from being delete-looped every sweep.
	pvbHealed map[string]time.Time
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
		seenStuckBackup: map[pausedKey]bool{},
		seenWedgedPVB:   map[pausedKey]bool{},
		pvbHealed:       map[string]time.Time{},
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
	if a.seenStuckBackup == nil {
		a.seenStuckBackup = map[pausedKey]bool{}
	}
	if a.seenWedgedPVB == nil {
		a.seenWedgedPVB = map[pausedKey]bool{}
	}
	if a.pvbHealed == nil {
		a.pvbHealed = map[string]time.Time{}
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
		isPaused, _, _ := unstructured.NestedBool(s.Object, "spec", "paused")
		if isPaused {
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
			// W10-FIX6 — zero Backup objects is not "nothing to
			// judge" once the Schedule itself is old enough to have
			// produced some. A paused Schedule is exempt: it
			// legitimately stops producing (check 1 already covers
			// it).
			if !isPaused {
				a.flagMissingBackups(ctx, s, ns, name, currentBad)
			}
			continue
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

	// W10-ST6 — in-flight transfer audit: mark Backups/PVBs wedged
	// InProgress|Deleting >6h, and clean up PVBs whose node-agent
	// provably lost the Kopia thread. Runs on the already-listed
	// backups plus its own PVB/pod reads; independent of the
	// schedule checks above.
	stuckErr := a.auditInFlightTransfers(ctx, backups)

	log.Info("sweep done", "schedules", len(schedules.Items),
		"paused", len(currentPaused), "badBackups", len(currentBad),
		"bslUnavailable", len(currentBSL))
	return errors.Join(everestErr, stuckErr)
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

// flagMissingBackups is the W10-FIX6 zero-backup check: a Schedule
// older than veleroMissingBackupMaxAge (36h) that has produced ZERO
// Backup objects is silently unprotected — the schedule fires, the
// backups vanish (or never ran), and every other check sees
// "nothing to judge". Flags reason=missing on the same
// VeleroBackupEmptyOrErrored series the other rot signatures use.
// A zero creationTimestamp cannot prove age — skipped (fail closed).
func (a *veleroBackupAuditor) flagMissingBackups(ctx context.Context,
	s *unstructured.Unstructured, ns, schedule string, current map[backupKey]bool) {
	log := logf.FromContext(ctx)
	created := s.GetCreationTimestamp()
	if created.IsZero() {
		return
	}
	age := a.nowFn().Sub(created.Time)
	if age <= veleroMissingBackupMaxAge {
		return
	}
	current[backupKey{ns, schedule, "missing"}] = true
	metrics.VeleroBackupEmptyOrErrored.
		WithLabelValues(ns, schedule, "missing").Set(1)
	log.Info("velero schedule older than 36h has zero backups — silently unprotected",
		"schedule", ns+"/"+schedule, "age", age.Truncate(time.Hour))
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

// ---------------------------------------------------------------------------
// W10-ST6 — in-flight Backup / PodVolumeBackup wedge audit
// ---------------------------------------------------------------------------

// auditInFlightTransfers is the W10-ST6 sweep: every Backup and
// PodVolumeBackup held InProgress or Deleting past veleroStuckMaxAge
// (6h) has lost the thread — the velero server or node-agent that
// owned it is gone. Backups are mark-only (deleting a Backup CR can
// abort a genuinely-running backup); PodVolumeBackups get the
// stronger treatment the plan calls for: when the owning node-agent
// provably lost its Kopia thread (pod gone, recreated after the PVB
// started, not Running, or a container restarted mid-backup), the
// wedged PVB is deleted AND its node-agent pod bounced so the next
// scheduled backup is not blocked behind it.
func (a *veleroBackupAuditor) auditInFlightTransfers(ctx context.Context,
	backups *unstructured.UnstructuredList) error {
	log := logf.FromContext(ctx)
	now := a.nowFn()

	// --- Backups: mark-only gauge over the already-listed set ---
	currentStuck := map[pausedKey]bool{}
	if backups != nil {
		for i := range backups.Items {
			b := &backups.Items[i]
			phase, _, _ := unstructured.NestedString(b.Object, "status", "phase")
			if phase != "InProgress" && phase != "Deleting" {
				continue
			}
			since := inFlightSince(b)
			if now.Sub(since) <= veleroStuckMaxAge {
				continue
			}
			k := pausedKey{b.GetNamespace(), b.GetName()}
			currentStuck[k] = true
			metrics.VeleroBackupStuck.WithLabelValues(k.namespace, k.schedule).Set(1)
			log.Info("velero backup wedged in-flight >6h",
				"backup", k.namespace+"/"+k.schedule, "phase", phase)
		}
	}
	for k := range a.seenStuckBackup {
		if !currentStuck[k] {
			metrics.VeleroBackupStuck.DeleteLabelValues(k.namespace, k.schedule)
		}
	}
	a.seenStuckBackup = currentStuck

	// --- PodVolumeBackups: mark + conditional cleanup ---
	pvbs, err := a.dyn.Resource(veleroPVBGVR).List(ctx, metav1.ListOptions{})
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		// CRD absent — clear any stale wedge series and stop.
		for k := range a.seenWedgedPVB {
			metrics.VeleroPodVolumeBackupWedged.DeleteLabelValues(k.namespace, k.schedule)
		}
		a.seenWedgedPVB = map[pausedKey]bool{}
		return nil
	case err != nil:
		return fmt.Errorf("list velero podvolumebackups: %w", err)
	}

	currentWedged := map[pausedKey]bool{}
	cleaned := 0
	for i := range pvbs.Items {
		pvb := &pvbs.Items[i]
		phase, _, _ := unstructured.NestedString(pvb.Object, "status", "phase")
		if phase != "InProgress" && phase != "Deleting" {
			continue
		}
		since := inFlightSince(pvb)
		if now.Sub(since) <= veleroStuckMaxAge {
			continue
		}
		ns, name := pvb.GetNamespace(), pvb.GetName()
		k := pausedKey{ns, name}
		currentWedged[k] = true
		metrics.VeleroPodVolumeBackupWedged.WithLabelValues(ns, name).Set(1)
		log.Info("velero podvolumebackup wedged in-flight >6h",
			"pvb", ns+"/"+name, "phase", phase)

		// Only an InProgress PVB is a cleanup candidate — a
		// Deleting one is already on its way out.
		if phase != "InProgress" || cleaned >= veleroPVBCleanupMaxPerRun {
			continue
		}
		if last, ok := a.pvbHealed[ns+"/"+name]; ok &&
			now.Sub(last) < veleroPVBCleanupCooldown {
			continue
		}
		if a.cleanWedgedPVB(ctx, pvb, since) {
			a.pvbHealed[ns+"/"+name] = now
			cleaned++
		}
	}
	for k := range a.seenWedgedPVB {
		if !currentWedged[k] {
			metrics.VeleroPodVolumeBackupWedged.DeleteLabelValues(k.namespace, k.schedule)
		}
	}
	a.seenWedgedPVB = currentWedged
	return nil
}

// inFlightSince is the wedge-age clock for an in-flight velero
// object: status.startTimestamp when parseable, else
// creationTimestamp — the same convention flagBadBackup uses.
func inFlightSince(u *unstructured.Unstructured) time.Time {
	since := u.GetCreationTimestamp().Time
	if st, found, _ := unstructured.NestedString(u.Object, "status", "startTimestamp"); found {
		if t, err := time.Parse(time.RFC3339, st); err == nil {
			since = t
		}
	}
	return since
}

// cleanWedgedPVB decides whether the PVB's node-agent provably lost
// its Kopia thread and, if so, deletes the PVB and bounces the agent
// pod. Returns true when the cleanup ran (cooldown-worthy).
func (a *veleroBackupAuditor) cleanWedgedPVB(ctx context.Context,
	pvb *unstructured.Unstructured, pvbStart time.Time) bool {
	log := logf.FromContext(ctx)
	agent, err := a.pvbAgentPod(ctx, pvb)
	if err != nil {
		log.Error(err, "pvb agent pod lookup failed — cleanup skipped",
			"pvb", pvb.GetNamespace()+"/"+pvb.GetName())
		metrics.IncError(veleroAuditQueue)
		return false
	}
	if !pvbAgentWedged(pvbStart, agent) {
		return false // agent still owns the thread — not provably wedged
	}
	ns, name := pvb.GetNamespace(), pvb.GetName()
	uid := pvb.GetUID()
	if err := a.dyn.Resource(veleroPVBGVR).Namespace(ns).Delete(ctx, name,
		metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid},
		}); err != nil && !apierrors.IsNotFound(err) {
		log.Error(err, "wedged pvb delete failed", "pvb", ns+"/"+name)
		metrics.IncError(veleroAuditQueue)
		return false
	}
	metrics.VeleroWedgedObjectsCleanedTotal.
		WithLabelValues(ns, "pvb_deleted").Inc()
	log.Info("ACTION: deleted wedged podvolumebackup",
		"pvb", ns+"/"+name, "agentPod", agentPodName(agent))

	// Bounce the node-agent pod so its next scheduled backup starts
	// clean — the DaemonSet recreates it. A missing agent pod needs
	// no bounce (it is already gone).
	if agent != nil {
		agentUID := agent.UID
		if err := a.cs.CoreV1().Pods(agent.Namespace).Delete(ctx, agent.Name,
			metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &agentUID},
			}); err != nil && !apierrors.IsNotFound(err) {
			log.Error(err, "node-agent bounce failed",
				"pod", agent.Namespace+"/"+agent.Name)
			metrics.IncError(veleroAuditQueue)
		} else {
			metrics.VeleroWedgedObjectsCleanedTotal.
				WithLabelValues(ns, "pod_restarted").Inc()
			log.Info("ACTION: bounced node-agent pod",
				"pod", agent.Namespace+"/"+agent.Name)
		}
	}
	return true
}

// pvbAgentPod resolves the node-agent pod that owns the PVB's Kopia
// thread. PodVolumeBackupSpec carries spec.node (the node the
// snapshot runs on) and spec.pod (the WORKLOAD pod — not the
// agent); status has no pod/node fields. The velero node-agent
// DaemonSet runs one pod per node, so spec.node identifies it.
// nil,nil means "no agent pod found" which IS wedge evidence.
func (a *veleroBackupAuditor) pvbAgentPod(ctx context.Context,
	pvb *unstructured.Unstructured) (*corev1.Pod, error) {
	ns := pvb.GetNamespace()
	node, found, _ := unstructured.NestedString(pvb.Object, "spec", "node")
	if !found || node == "" {
		// Older velero wrote the node under status — accept it as a
		// fallback so pre-upgrade PVBs still resolve.
		node, _, _ = unstructured.NestedString(pvb.Object, "status", "node")
	}
	if node == "" {
		return nil, nil
	}
	pods, err := a.cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + node,
	})
	if err != nil {
		return nil, err
	}
	// Prefer an actual node-agent pod; the DaemonSet names them
	// "node-agent-*". Fall back to the first pod on the node —
	// velero's namespace is otherwise quiet.
	for i := range pods.Items {
		if strings.Contains(pods.Items[i].Name, "node-agent") {
			return &pods.Items[i], nil
		}
	}
	if len(pods.Items) > 0 {
		return &pods.Items[0], nil
	}
	return nil, nil
}

// pvbAgentWedged reports whether the agent pod provably lost its
// Kopia thread: the pod is gone, not Running, was (re)created after
// the PVB started, or any container restarted/terminated after the
// PVB started — in every case the in-process kopia backup is dead
// while the PVB object still claims InProgress.
func pvbAgentWedged(pvbStart time.Time, pod *corev1.Pod) bool {
	if pod == nil {
		return true // agent gone — nothing owns the thread
	}
	if pod.Status.Phase != corev1.PodRunning {
		return true
	}
	if pod.Status.StartTime != nil && pod.Status.StartTime.Time.After(pvbStart) {
		return true
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Running != nil && cs.State.Running.StartedAt.After(pvbStart) {
			return true
		}
		if cs.LastTerminationState.Terminated != nil &&
			cs.LastTerminationState.Terminated.FinishedAt.After(pvbStart) {
			return true
		}
	}
	return false
}

func agentPodName(p *corev1.Pod) string {
	if p == nil {
		return "<none>"
	}
	return p.Namespace + "/" + p.Name
}
