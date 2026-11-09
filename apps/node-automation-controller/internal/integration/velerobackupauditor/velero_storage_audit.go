// velero_storage_audit.go — the storage-side audits of
// velero-backup-auditor: auditBSLs (velero-bsl-audit — a
// BackupStorageLocation not phase=Available means backups run to an
// unreachable bucket) and auditBackupRepositories (backup-health —
// the restic/kopia repo every snapshot lands in, plus the W19-ST2
// re-init heal for repos wedged NotReady >=30m).
package velerobackupauditor

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// auditBSLs flags every BackupStorageLocation whose status.phase is
// not Available on VeleroBSLUnavailable{namespace,name} — a BSL not
// Available means backups run to an unreachable bucket and the next
// restore has nothing to read. A missing CRD is a quiet no-op.
func (a *veleroBackupAuditor) auditBSLs(ctx context.Context,
	log logr.Logger) error {
	bsls, err := a.veleroList(ctx, veleroBSLGVR)
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		// CRD absent — nothing to audit.
	case err != nil:
		return fmt.Errorf("list velero backupstoragelocations: %w", err)
	default:
		for i := range bsls.Items {
			bsl := &bsls.Items[i]
			ns, name := bsl.GetNamespace(), bsl.GetName()
			phase, _ := kube.NestedString(bsl.Object, "status", "phase")
			if phase == "Available" {
				continue
			}
			k := pausedKey{ns, name}
			a.seenBSL.Set(metrics.VeleroBSLUnavailable, 1, k, ns, name)
			log.Info("velero BSL unavailable — backups/restore at risk",
				"bsl", ns+"/"+name, "phase", phase)
		}
	}
	a.seenBSL.Prune(metrics.VeleroBSLUnavailable.DeleteLabelValues)
	return nil
}

// auditBackupRepositories is the backup-health repo audit: the
// restic/kopia repo every snapshot lands in. A repo whose phase is
// not Ready cannot be opened at all, and a lastMaintenanceTime
// older than 7d means the scheduled maintenance (prune/repack)
// stopped — both leave "successful" backups unrestorable.
// reason=phase_not_ready | maintenance_stale. A repo held at
// phase=NotReady for the full veleroRepoNotReadyMinAge window gets
// re-initialized via reinitStaleRepo (W19-ST2).
func (a *veleroBackupAuditor) auditBackupRepositories(ctx context.Context,
	log logr.Logger) error {
	repos, err := a.veleroList(ctx, veleroRepoGVR)
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		// CRD absent (older Velero without the repo API) — nothing
		// to audit.
	case err != nil:
		return fmt.Errorf("list velero backuprepositories: %w", err)
	default:
		repoNotReadyNow := map[string]bool{}
		for i := range repos.Items {
			repo := &repos.Items[i]
			ns, name := repo.GetNamespace(), repo.GetName()
			if phase, ok := kube.NestedString(
				repo.Object, "status", "phase"); ok && phase != "Ready" {
				a.seenRepo.Set(metrics.VeleroRepoUnhealthy, 1,
					repoKey{ns, name, "phase_not_ready"},
					ns, name, "phase_not_ready")
				log.Info("velero backup repository not Ready — repo cannot be opened",
					"repo", ns+"/"+name, "phase", phase)
				// W19-ST2 — a repo wedged NotReady >=30m gets
				// deleted so Velero re-initializes the Kopia/
				// Restic connection (heal-gated + cooled down).
				if phase == "NotReady" {
					lk := ns + "/" + name
					repoNotReadyNow[lk] = true
					first, _ := a.firstSeenRepoNotReady.Observe(
						lk, a.now.Now())
					if a.now.Now().Sub(first) >= veleroRepoNotReadyMinAge {
						a.reinitStaleRepo(ctx, repo, ns, name)
					}
				}
			}
			lmt, ok := kube.NestedString(
				repo.Object, "status", "lastMaintenanceTime")
			if !ok {
				continue // never stamped — can't tell, not stale
			}
			t, perr := time.Parse(time.RFC3339, lmt)
			if perr != nil || a.now.Now().Sub(t) <= veleroRepoMaintenanceMaxAge {
				continue
			}
			a.seenRepo.Set(metrics.VeleroRepoUnhealthy, 1,
				repoKey{ns, name, "maintenance_stale"},
				ns, name, "maintenance_stale")
			log.Info("velero backup repository maintenance stale — prune/repack loop stopped",
				"repo", ns+"/"+name, "lastMaintenanceTime", lmt,
				"age", a.now.Now().Sub(t).Truncate(time.Hour))
		}
		a.firstSeenRepoNotReady.Prune(
			func(k string) bool { return repoNotReadyNow[k] })
	}
	a.seenRepo.Prune(metrics.VeleroRepoUnhealthy.DeleteLabelValues)
	return nil
}

// reinitStaleRepo deletes a BackupRepository that has reported
// phase=NotReady for the full persistence window — Velero's repo
// controller recreates the CR and re-initializes the Kopia/Restic
// connection, the only recovery a wedged repo handshake has. The
// delete is destructive on a live object, so it gates on
// heal.AllowedV (per-repo cooldown + maintenance mutex, fail closed
// on unverifiable) and is UID-preconditioned; the cooldown stamps
// only after the delete is delivered.
func (a *veleroBackupAuditor) reinitStaleRepo(ctx context.Context,
	repo *unstructured.Unstructured, ns, name string) {

	log := logf.FromContext(ctx)
	now := a.now.Now()
	key := "backuprepository/" + ns + "/" + name
	proceed, unverifiable := heal.AllowedV(ctx, log, &a.verdict, a.cs,
		a.dyn, &a.repoHealed, key, veleroRepoHealedCooldown, now)
	switch {
	case unverifiable:
		metrics.IncError(a.queue)
		return
	case !proceed:
		return // cooldown or maintenance — detection already flagged
	}
	if err := a.dyn.Resource(veleroRepoGVR).Namespace(ns).Delete(ctx,
		name, kube.UIDDeleteOptions(repo.GetUID(), "")); err != nil {
		if !apierrors.IsNotFound(err) {
			log.Error(err, "stale backup repository delete failed",
				"repo", ns+"/"+name)
			metrics.IncError(a.queue)
		}
		return
	}
	a.repoHealed.Stamp(key, now)
	metrics.VeleroWedgedObjectsCleanedTotal.
		WithLabelValues(ns, "repo_reinitialized").Inc()
	log.Info("ACTION: deleted stale BackupRepository — velero will re-init the repo",
		"repo", ns+"/"+name)
}
