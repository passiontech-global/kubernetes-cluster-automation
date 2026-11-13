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
// backup-health adds the BackupRepository audit: a repo whose status.phase
// is not Ready cannot be opened by restic/kopia, and a
// status.lastMaintenanceTime older than 7 days means the scheduled
// prune/repack maintenance loop stopped — either way the next
// restore reads an unmaintained or unreachable repo. Both flag on
// VeleroRepoUnhealthy{namespace,name,reason}. velero-repo-reinit-heal adds the heal
// half: a repo held at phase=NotReady for >=30m is deleted (UID-
// preconditioned, heal.AllowedV-gated, 2h cooldown) so Velero's repo
// controller re-creates it and re-initializes the Kopia/Restic
// connection — the only recovery a wedged repo handshake has.
//
// Series lifecycle mirrors cert-drift-auditor: seen-sets prune the
// gauges the moment the condition resolves (unpaused, healthy new
// backup, object deleted).
//
// Layout: this file holds the shared keys/state, the Setup + run
// entry point and the paged-list helpers; schedule_audit.go the
// per-Schedule rot checks, db_backup_audit.go the shared backup-posture-audit
// sweep skeleton both product audits drive through their config rows,
// everest_audit.go the backup-posture-audit Percona
// Everest audit, cnpg_audit.go the cnpg-backup-audit CloudNativePG backup
// audit, inflight_pvb_audit.go the velero-inflight-audit wedged-transfer
// audit + PVB cleanup (+ cnpg-backup-audit DataUpload/DataDownload scan),
// velero_storage_audit.go the BSL + BackupRepository audits and the
// velero-repo-reinit-heal repo re-init heal.
package velerobackupauditor

import (
	"context"
	"errors"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/maintenance"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
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
	// velero-inflight-audit — podvolumebackups.velero.io: per-volume snapshots
	// taken by the node-agent DaemonSet; a wedged InProgress PVB
	// blocks the next backup's volume phase.
	veleroPVBGVR = kube.GVVeleroPodVolumeBackup
	// velero-restore-wedge-audit — podvolumerestores.velero.io: the restore-side twin
	// of the PVB wedge audit; a restore held InProgress past 6h with
	// a dead node-agent thread is the same lost-thread signature.
	veleroPVRGVR = kube.GVVeleroPodVolumeRestore
	// backup-health — backuprepositories.velero.io: the restic/kopia repo
	// each BSL's snapshots land in; its phase and maintenance clock
	// say whether a restore can actually read them.
	veleroRepoGVR = kube.GVVeleroBackupRepository
	// backup-posture-audit — Percona Everest operator CRDs: the DatabaseCluster
	// declares spec.backup.enabled and the DatabaseClusterBackup
	// carries spec.dbClusterName + status.state.
	everestDBClusterGVR = kube.GVREverestDatabaseCluster
	everestDBBackupGVR  = kube.GVREverestDatabaseClusterBackup
	// cnpg-backup-audit — CloudNativePG CRDs: the ScheduledBackup declares
	// spec.clusterName + spec.schedule and the Backup carries
	// spec.clusterName + status.phase.
	cnpgScheduledBackupGVR = kube.GVRCNPGScheduledBackup
	cnpgBackupGVR          = kube.GVRCNPGBackup
)

// veleroStuckPhases are terminal-failure and wedged-in-flight
// signatures — a backup Failed, PartiallyFailed or FailedValidation
// is a data-protection failure worth surfacing, and InProgress or
// Deleting held past veleroStuckMaxAge means the velero server lost
// the thread (velero-bsl-audit).
var veleroStuckPhases = map[string]string{
	"Failed":           "failed",
	"PartiallyFailed":  "failed",
	"FailedValidation": "failed",
	"InProgress":       "stuck",
	"Deleting":         "stuck",
}

const veleroStuckMaxAge = 6 * time.Hour

// veleroInstallNSDefault is where the velero server and its
// node-agent DaemonSet are installed — the namespace the in-flight
// audit resolves the agent pod in (PVBs/PVRs themselves live in the
// WORKLOAD namespaces). Override with VELERO_NAMESPACE for installs
// in a non-default namespace.
const veleroInstallNSDefault = "velero"

// veleroRepoMaintenanceMaxAge is the backup-health repo-maintenance bound:
// velero runs restic/kopia repository maintenance (prune + repack)
// on a regular cycle — default hourly, never sparser than daily — so
// a lastMaintenanceTime older than 7 days means the maintenance loop
// stopped (dead velero server, unreachable repo, wedged maintenance
// job) and the next restore reads an unmaintained repo.
const veleroRepoMaintenanceMaxAge = 7 * 24 * time.Hour

// veleroRepoNotReadyMinAge (velero-repo-reinit-heal) bounds how long a
// BackupRepository may report phase=NotReady before the auditor
// deletes the CR — Velero's repo controller recreates it and
// re-initializes the Kopia/Restic connection, which is the only
// recovery a wedged repo handshake has ever had.
const veleroRepoNotReadyMinAge = 30 * time.Minute

// veleroRepoHealedCooldown bounds re-init churn per repository — a
// repo that re-wedges inside the window keeps its unhealthy series
// but is not delete-looped.
const veleroRepoHealedCooldown = 2 * time.Hour

// veleroList pages a full dynamic List through the shared page bound —
// same contract as a raw .List but bounded per response (Velero and
// Everest CRDs are cluster-scoped here, so every audit read is
// cluster-wide). ResourceVersion "0" routes the read to the
// apiserver's watch cache: these censuses are point-in-time audit
// snapshots, and under kube-apiserver-on-Kine every paged page was a
// separate SQL round-trip — one cache-served response replaces them
// (pageOpts strips the Limit companion on the wire).
func (a *veleroBackupAuditor) veleroList(ctx context.Context,
	gvr schema.GroupVersionResource) (*unstructured.UnstructuredList, error) {
	return kube.ListAllUnstructured(ctx, a.dyn.Resource(gvr),
		metav1.ListOptions{
			Limit:           kube.DefaultListPageSize,
			ResourceVersion: "0",
		})
}

// veleroMissingBackupMaxAge is the zero-backup-guard zero-backup threshold:
// a Schedule (or backup-enabled DatabaseCluster) older than 36h
// that has produced ZERO backup objects is silently unprotected —
// same horizon as the Everest stale check.
const veleroMissingBackupMaxAge = 36 * time.Hour

// veleroPVBCleanup* bound the velero-inflight-audit wedged-PVB cleaner: only
// InProgress PVBs past the 6h stuck window are candidates, at most
// this many are cleaned per sweep, and a cleaned PVB name cools down
// so a still-broken agent cannot be delete-looped.
const (
	veleroPVBCleanupMaxPerRun = 3
	veleroPVBCleanupCooldown  = 30 * time.Minute
)

// backup-posture-audit — Everest backup health thresholds: a backup still
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

// dbBackupKey identifies one DBBackupUnhealthy series — the label
// triple (namespace, cluster, reason) needed to delete it again once
// the subject's backup posture recovers. Shared by the everest and
// cnpg rows of the db_backup_audit.go table.
type dbBackupKey struct{ namespace, cluster, reason string }

// repoKey identifies one VeleroRepoUnhealthy series — the label
// triple (namespace, BackupRepository name, reason) of the backup-health
// repo audit.
type repoKey struct{ namespace, name, reason string }

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
	// veleroNS is the namespace velero itself is installed in —
	// where the node-agent DaemonSet runs, resolved from
	// VELERO_NAMESPACE at Setup (zero value = the default, so the
	// literally-built tests read "velero" too).
	veleroNS string
	now      shared.Clock // clock seam — same pattern as certDriftAuditor
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name and every IncError label
	// come from one place.
	queue      string
	seenPaused state.GaugeLedger[pausedKey]
	seenBad    state.GaugeLedger[backupKey]
	// seenBSL: series ledger for VeleroBSLUnavailable — an
	// Available-again or deleted BSL gets DeleteLabelValues.
	seenBSL state.GaugeLedger[pausedKey]
	// seenRepo: series ledger for VeleroRepoUnhealthy (backup-health) — a
	// repo that goes Ready again or gets a fresh maintenance stamp
	// loses its series.
	seenRepo state.GaugeLedger[repoKey]
	// firstSeenPaused: when the sweep first saw this Schedule
	// generation paused — measures the actual pause duration. A
	// Schedule carries no "paused since" timestamp, so the ledger is
	// the only honest clock; it resets on unpause and prunes on
	// delete, and a controller restart re-arms it (biased to
	// under-page, never to alert on an unmeasurable pause).
	firstSeenPaused state.FirstSeenLedger
	// seenEverest: series ledger for DBBackupUnhealthy — a
	// dbBackupKey the sweep stops re-asserting gets
	// DeleteLabelValues'd so a recovered or deleted
	// DatabaseCluster never pins the gauge.
	seenEverest state.GaugeLedger[dbBackupKey]
	// seenCNPG: series ledger for the cnpg-backup-audit CNPG half of
	// DBBackupUnhealthy — its own ledger so the Everest sweep's
	// prune never deletes CNPG series (the two audits assert
	// disjoint key sets on the same gauge vec).
	seenCNPG state.GaugeLedger[dbBackupKey]
	// seenDataMovement: series ledger for the cnpg-backup-audit
	// DataUpload/DataDownload wedge gauge — keys "kind/ns/name".
	seenDataMovement state.GaugeLedger[string]
	// seenStuckBackup / seenWedgedPVB: series ledgers for the
	// velero-inflight-audit in-flight gauges — same prune-on-resolve contract.
	seenStuckBackup state.GaugeLedger[pausedKey]
	seenWedgedPVB   state.GaugeLedger[pausedKey]
	// seenWedgedPVR is the velero-restore-wedge-audit restore-side twin of seenWedgedPVB.
	seenWedgedPVR state.GaugeLedger[pausedKey]
	// pvbHealed: "<ns>/<name>" -> last wedged-PVB cleanup time —
	// the per-object cooldown that stops a still-broken node-agent
	// from being delete-looped every sweep.
	pvbHealed state.CooldownSet
	// firstSeenRepoNotReady: "ns/name" -> first sweep the repo
	// reported phase=NotReady — the 30m persistence window the
	// velero-repo-reinit-heal re-init heal requires; pruned when the repo leaves
	// NotReady so a re-wedge measures fresh.
	firstSeenRepoNotReady state.FirstSeenLedger
	// repoHealed: "backuprepository/ns/name" -> last repo re-init —
	// the 2h cooldown that stops a still-broken repo being
	// delete-looped.
	repoHealed state.CooldownSet
	// verdict memoizes the maintenance-mutex evaluation for the
	// sweep's PVB-cleanup preambles — the deletes below are
	// destructive (a PVB object AND a live node-agent pod), so they
	// gate on heal.AllowedV and share one verdict per sweep.
	verdict *maintenance.Verdict
}

// veleroInstallNS is the namespace the velero node-agent DaemonSet
// runs in — the pod list behind pvbAgentPod must land there, never in
// the PVB's (workload) namespace.
func (a *veleroBackupAuditor) veleroInstallNS() string {
	if a.veleroNS == "" {
		return veleroInstallNSDefault
	}
	return a.veleroNS
}

// Setup registers the 15m sweep — or nothing when
// the cluster opts out (VELERO_BACKUP_AUDITOR_ENABLED=false, resolved
// by setupModules into Deps.Disabled): same disabled-flag pattern as
// cert-drift-auditor.
func Setup(d shared.Deps) error {
	mgr, cs, dyn := d.Mgr, d.CS, d.Dyn
	return shared.SetupNoConfig(d, func() error {
		a := &veleroBackupAuditor{
			verdict:  d.Maintenance,
			cs:       cs,
			dyn:      dyn,
			veleroNS: envx.Getenv("VELERO_NAMESPACE", veleroInstallNSDefault),
			now:      shared.SystemClock,
			queue:    d.Name,
		}
		return shared.AddPeriodic(mgr, a.queue, veleroAuditInterval, a.run)
	})
}

func (a *veleroBackupAuditor) run(ctx context.Context) error {
	// Begin EVERY emitted-gauge ledger up front — not just the four
	// this function prunes itself. The audit helpers Begin their own
	// ledgers at their start, but an early return BELOW (a failed
	// veleroObjects list, a BSL/repo audit error) can strand
	// "current" emissions an aborted sweep left behind; resetting
	// here means every ledger's next Prune rolls forward only what
	// THIS sweep measured. Begin is idempotent — the per-audit
	// Begins stay so a direct audit call (tests) is still safe.
	a.seenBSL.Begin()          // drop any aborted sweep's leftover emissions
	a.seenBad.Begin()          // drop any aborted sweep's leftover emissions
	a.seenPaused.Begin()       // drop any aborted sweep's leftover emissions
	a.seenRepo.Begin()         // drop any aborted sweep's leftover emissions
	a.seenEverest.Begin()      // drop any aborted sweep's leftover emissions
	a.seenCNPG.Begin()         // drop any aborted sweep's leftover emissions
	a.seenStuckBackup.Begin()  // drop any aborted sweep's leftover emissions
	a.seenWedgedPVB.Begin()    // drop any aborted sweep's leftover emissions
	a.seenWedgedPVR.Begin()    // drop any aborted sweep's leftover emissions
	a.seenDataMovement.Begin() // drop any aborted sweep's leftover emissions
	log := logf.FromContext(ctx)

	// backup-posture-audit — the Everest DB-backup audit is independent of Velero:
	// a cluster can run the Percona operator with no Velero at all,
	// so it runs before (and regardless of) the schedule 404 early
	// return below. Its error joins the run's, never masks it.
	everestErr := a.auditEverestBackups(ctx)
	// cnpg-backup-audit — the CNPG backup audit is likewise independent of
	// Velero (CNPG runs fine with no Velero installed); its error
	// joins the same way.
	cnpgErr := a.auditCNPGBackups(ctx)
	dbErr := errors.Join(everestErr, cnpgErr)

	schedules, backups, err := a.veleroObjects(ctx)
	if err != nil {
		return errors.Join(dbErr, err)
	}
	if schedules == nil {
		// Clusters without Velero have no CRDs — quiet skip, same
		// contract as externalsecret-nudge. Every seen ledger still
		// gets its prune BEFORE the early return: series emitted
		// while Velero was installed must not linger as stale
		// gauges after the CRDs go away (the normal prunes live
		// inside the audit passes this path skips). That includes
		// the four ledgers owned by audits BELOW this return —
		// in-flight transfers, wedged PVB/PVR and data movement
		// never ran, so without these prunes their series pin at 1
		// forever. seenEverest/seenCNPG are NOT pruned here: their
		// audits already ran and self-pruned above (a second Prune
		// would delete series they just re-asserted).
		a.seenPaused.Prune(metrics.VeleroSchedulePaused.DeleteLabelValues)
		a.seenBad.Prune(metrics.VeleroBackupEmptyOrErrored.DeleteLabelValues)
		a.seenBSL.Prune(metrics.VeleroBSLUnavailable.DeleteLabelValues)
		a.seenRepo.Prune(metrics.VeleroRepoUnhealthy.DeleteLabelValues)
		a.seenStuckBackup.Prune(metrics.VeleroBackupStuck.DeleteLabelValues)
		a.seenWedgedPVB.Prune(metrics.VeleroPodVolumeBackupWedged.DeleteLabelValues)
		a.seenWedgedPVR.Prune(metrics.VeleroPodVolumeRestoreWedged.DeleteLabelValues)
		a.seenDataMovement.Prune(metrics.VeleroDataMovementWedged.DeleteLabelValues)
		a.firstSeenPaused.Prune(func(string) bool { return false })
		a.firstSeenRepoNotReady.Prune(func(string) bool { return false })
		log.Info("skip: velero CRDs not installed")
		return dbErr
	}
	latest := latestBackupsBySchedule(backups)

	a.auditSchedules(ctx, schedules, latest, log)

	// velero-bsl-audit + backup-health — the storage-side audits run
	// after the schedule checks; a list failure short-circuits the
	// remaining audits exactly as the inline code did.
	if err := a.auditBSLs(ctx, log); err != nil {
		return errors.Join(dbErr, err)
	}
	if err := a.auditBackupRepositories(ctx, log); err != nil {
		return errors.Join(dbErr, err)
	}

	// velero-inflight-audit — in-flight transfer audit: mark Backups/PVBs wedged
	// InProgress|Deleting >6h, and clean up PVBs whose node-agent
	// provably lost the Kopia thread. Runs on the already-listed
	// backups plus its own PVB/pod reads; independent of the
	// schedule checks above. pvbHealed keys on node names that can
	// leave the fleet — bound the map once per sweep at the cleanup
	// cooldown so decommissioned nodes' stamps cannot accumulate.
	a.pvbHealed.PruneExpired(a.now.Now(), veleroPVBCleanupCooldown)
	a.repoHealed.PruneExpired(a.now.Now(), veleroRepoHealedCooldown)
	stuckErr := a.auditInFlightTransfers(ctx, backups)
	// cnpg-backup-audit — the data-mover half of the in-flight audit: mark-only
	// scan of DataUpload/DataDownload wedges.
	dmErr := a.auditDataMovement(ctx)

	log.Info("sweep done", "schedules", len(schedules.Items),
		"paused", len(a.seenPaused.Last()), "badBackups", len(a.seenBad.Last()),
		"bslUnavailable", len(a.seenBSL.Last()))
	return errors.Join(dbErr, stuckErr, dmErr)
}

// veleroObjects lists the Velero Schedule and Backup objects the
// schedule audits and the in-flight audit consume. A missing Velero
// CRD set (no Velero installed) returns (nil, nil, nil) — the caller
// logs the quiet skip and returns the already-collected db errors.
// A missing Backups CRD while Schedules exist is tolerated (the
// paused-schedule check still runs on an empty backup view); any
// other list error aborts the sweep.
func (a *veleroBackupAuditor) veleroObjects(ctx context.Context) (
	*unstructured.UnstructuredList, *unstructured.UnstructuredList, error) {
	schedules, err := a.veleroList(ctx, veleroScheduleGVR)
	if err != nil {
		if apierrors.IsNotFound(err) || meta.IsNoMatchError(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("list velero schedules: %w", err)
	}
	backups, err := a.veleroList(ctx, veleroBackupGVR)
	if err != nil {
		if apierrors.IsNotFound(err) || meta.IsNoMatchError(err) {
			backups = nil // schedules exist but backups CRD absent — check 1 still runs
		} else {
			return nil, nil, fmt.Errorf("list velero backups: %w", err)
		}
	}
	return schedules, backups, nil
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
