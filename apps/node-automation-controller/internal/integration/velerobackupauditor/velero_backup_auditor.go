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
//
// Layout: this file holds the shared keys/state, the Setup + run
// entry point and the paged-list helpers; schedule_audit.go the
// per-Schedule rot checks, everest_audit.go the W9-ST3 Percona
// Everest audit, inflight_pvb_audit.go the W10-ST6 wedged-transfer
// audit + PVB cleanup.
package velerobackupauditor

import (
	"context"
	"errors"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

const (
	veleroAuditInterval = 15 * time.Minute
	veleroPausedMinAge  = 24 * time.Hour // paused schedule must be this old to alert
	// veleroScheduleLabel links a Backup to the Schedule that made it
	// (ad-hoc backups carry no label and stay out of the audit).
	veleroScheduleLabel = "velero.io/schedule-name"
)

var (
	veleroScheduleGVR = kube.GVVeleroSchedule
	veleroBackupGVR   = kube.GVVeleroBackup
	veleroBSLGVR      = kube.GVVeleroBackupStorageLocation
	// W10-ST6 — podvolumebackups.velero.io: per-volume snapshots
	// taken by the node-agent DaemonSet; a wedged InProgress PVB
	// blocks the next backup's volume phase.
	veleroPVBGVR = kube.GVVeleroPodVolumeBackup
	// W9-ST3 — Percona Everest operator CRDs: the DatabaseCluster
	// declares spec.backup.enabled and the DatabaseClusterBackup
	// carries spec.dbClusterName + status.state.
	everestDBClusterGVR = kube.GVREverestDatabaseCluster
	everestDBBackupGVR  = kube.GVREverestDatabaseClusterBackup
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

// veleroListPageSize bounds each List page — Backup/PVB objects are
// cluster-wide and accumulate unboundedly on busy schedules.
const veleroListPageSize = 500

// veleroList pages a full dynamic List through veleroListPageSize —
// same contract as a raw .List but bounded per response (Velero and
// Everest CRDs are cluster-scoped here, so every audit read is
// cluster-wide).
func (a *veleroBackupAuditor) veleroList(ctx context.Context,
	gvr schema.GroupVersionResource) (*unstructured.UnstructuredList, error) {
	items, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: veleroListPageSize},
		kube.DynamicPage(a.dyn.Resource(gvr)))
	if err != nil {
		return nil, err
	}
	return &unstructured.UnstructuredList{Items: items}, nil
}

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
// instead of inheriting the dead one's pause time). Joined as
// "uid/ns/name" — UIDs and DNS-1123 names never contain a bare "/"
// collision that matters here (the key is never split back).
func pausedLedgerKey(uid, namespace, schedule string) string {
	return uid + "/" + namespace + "/" + schedule
}

type veleroBackupAuditor struct {
	cs  kubernetes.Interface // reserved for future typed reads
	dyn dynamic.Interface
	now shared.Clock // clock seam — same pattern as certDriftAuditor
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name and every IncError label
	// come from one place.
	queue      string
	seenPaused state.GaugeLedger[pausedKey]
	seenBad    state.GaugeLedger[backupKey]
	// seenBSL: series ledger for VeleroBSLUnavailable — an
	// Available-again or deleted BSL gets DeleteLabelValues.
	seenBSL state.GaugeLedger[pausedKey]
	// firstSeenPaused: when the sweep first saw this Schedule
	// generation paused — measures the actual pause duration. A
	// Schedule carries no "paused since" timestamp, so the ledger is
	// the only honest clock; it resets on unpause and prunes on
	// delete, and a controller restart re-arms it (biased to
	// under-page, never to alert on an unmeasurable pause).
	firstSeenPaused state.FirstSeenLedger
	// seenEverest: series ledger for DBBackupUnhealthy — an
	// everestKey the sweep stops re-asserting gets
	// DeleteLabelValues'd so a recovered or deleted
	// DatabaseCluster never pins the gauge.
	seenEverest state.GaugeLedger[everestKey]
	// seenStuckBackup / seenWedgedPVB: series ledgers for the
	// W10-ST6 in-flight gauges — same prune-on-resolve contract.
	seenStuckBackup state.GaugeLedger[pausedKey]
	seenWedgedPVB   state.GaugeLedger[pausedKey]
	// pvbHealed: "<ns>/<name>" -> last wedged-PVB cleanup time —
	// the per-object cooldown that stops a still-broken node-agent
	// from being delete-looped every sweep.
	pvbHealed state.CooldownSet
}

// Setup registers the 15m sweep — or nothing when
// the cluster opts out (VELERO_BACKUP_AUDITOR_ENABLED=false, resolved
// by setupModules into Deps.Disabled): same disabled-flag pattern as
// cert-drift-auditor.
func Setup(d shared.Deps) error {
	mgr, cs, dyn := d.Mgr, d.CS, d.Dyn
	if d.Disabled {
		return nil
	}
	a := &veleroBackupAuditor{
		cs:    cs,
		dyn:   dyn,
		now:   shared.SystemClock,
		queue: d.Name,
	}
	return shared.AddPeriodic(mgr, a.queue, veleroAuditInterval, a.run)
}

func (a *veleroBackupAuditor) run(ctx context.Context) error {
	log := logf.FromContext(ctx)

	// W9-ST3 — the Everest DB-backup audit is independent of Velero:
	// a cluster can run the Percona operator with no Velero at all,
	// so it runs before (and regardless of) the schedule 404 early
	// return below. Its error joins the run's, never masks it.
	everestErr := a.auditEverestBackups(ctx)

	schedules, err := a.veleroList(ctx, veleroScheduleGVR)
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
	backups, err := a.veleroList(ctx, veleroBackupGVR)
	if err != nil {
		if apierrors.IsNotFound(err) {
			backups = nil // schedules exist but backups CRD absent — check 1 still runs
		} else {
			return errors.Join(everestErr,
				fmt.Errorf("list velero backups: %w", err))
		}
	}
	latest := latestBackupsBySchedule(backups)

	pausedNow := map[string]bool{}
	for i := range schedules.Items {
		s := &schedules.Items[i]
		ns, name := s.GetNamespace(), s.GetName()

		// Check 1 — spec.paused held past 24h. A Schedule carries no
		// "paused since" timestamp, so firstSeenPaused measures the
		// real pause duration from first sight; an entry pruned on
		// unpause means a re-pause restarts the clock, and the UID in
		// the key keeps a delete+recreate from inheriting pause time.
		isPaused, _ := kube.NestedBool(s.Object, "spec", "paused")
		if isPaused {
			lk := pausedLedgerKey(string(s.GetUID()), ns, name)
			pausedNow[lk] = true
			first, _ := a.firstSeenPaused.Observe(lk, a.now.Now())
			k := pausedKey{ns, name}
			a.seenPaused.Emit(k, ns, name)
			v := 0.0
			if pausedFor := a.now.Now().Sub(first); pausedFor > veleroPausedMinAge {
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
				a.flagMissingBackups(ctx, s, ns, name)
			}
			continue
		}
		a.flagBadBackup(ctx, b, ns, name)
	}

	// Prune series whose condition resolved since the last sweep —
	// a schedule unpaused or a fresh healthy backup must clear the
	// gauge, not pin it at 1.
	a.seenPaused.Prune(metrics.VeleroSchedulePaused.DeleteLabelValues)
	// Drop first-seen entries for schedules that unpaused or vanished
	// — a later re-pause measures a fresh duration, not the
	// cumulative time it once spent paused.
	a.firstSeenPaused.Prune(func(lk string) bool { return pausedNow[lk] })
	a.seenBad.Prune(metrics.VeleroBackupEmptyOrErrored.DeleteLabelValues)

	// W8-ST1 — BackupStorageLocation availability: a BSL not
	// phase=Available means backups run to an unreachable bucket and
	// the next restore has nothing to read.
	bsls, err := a.veleroList(ctx, veleroBSLGVR)
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
			phase, _ := kube.NestedString(bsl.Object, "status", "phase")
			if phase == "Available" {
				continue
			}
			k := pausedKey{ns, name}
			a.seenBSL.Emit(k, ns, name)
			metrics.VeleroBSLUnavailable.WithLabelValues(ns, name).Set(1)
			log.Info("velero BSL unavailable — backups/restore at risk",
				"bsl", ns+"/"+name, "phase", phase)
		}
	}
	a.seenBSL.Prune(metrics.VeleroBSLUnavailable.DeleteLabelValues)

	// W10-ST6 — in-flight transfer audit: mark Backups/PVBs wedged
	// InProgress|Deleting >6h, and clean up PVBs whose node-agent
	// provably lost the Kopia thread. Runs on the already-listed
	// backups plus its own PVB/pod reads; independent of the
	// schedule checks above.
	stuckErr := a.auditInFlightTransfers(ctx, backups)

	log.Info("sweep done", "schedules", len(schedules.Items),
		"paused", len(a.seenPaused.Last()), "badBackups", len(a.seenBad.Last()),
		"bslUnavailable", len(a.seenBSL.Last()))
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
