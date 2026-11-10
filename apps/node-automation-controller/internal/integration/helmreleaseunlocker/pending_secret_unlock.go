// pending_secret_unlock.go — the "another operation in progress"
// signature of helmrelease-unlocker: an HR Ready=False on "in
// progress" for >30m whose newest helm release secret sits pending-*
// gets that secret deleted (only when an older deployed/superseded
// revision exists to roll back to) plus the
// reconcile.fluxcd.io/requestedAt nudge, then the release namespace
// is swept for failed helm-hook Jobs (C3a).
package helmreleaseunlocker

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

const (
	// helmLastUnlockAnno persists the last unlock moment on the HR —
	// the 24h cooldown survives operator restarts where the unlocked
	// ledger cannot.
	helmLastUnlockAnno = kube.AnnoLastHelmUnlock
	// helmHookFreshWindow is how recently a helm.sh/hook Job must have
	// been created to count as live progress evidence even before its
	// pods show up (Status.Active lags Job creation). Deliberately
	// below the 30m stuck threshold: residue from the wedged attempt
	// the unlock targets is always older, while an upgrade genuinely
	// mid-flight just started its hook.
	helmHookFreshWindow = 10 * time.Minute
)

// hrStuckInProgress reports whether the HR's Ready condition is False
// with a "…in progress" message — the deadlock signature. A missing or
// non-False Ready never counts.
func hrStuckInProgress(hr *unstructured.Unstructured) bool {
	c, _ := kube.ConditionOf(hr.Object, "Ready")
	return c.Status == "False" && strings.Contains(c.Message, "in progress")
}

// unlockDue runs the unlock pass over the due HRs — cooldown check,
// pending-secret delete, reconcile stamp — and returns how many HRs
// were actually unlocked.
func (u *helmReleaseUnlocker) unlockDue(ctx context.Context, gvr schema.GroupVersionResource,
	stuck map[string]*unstructured.Unstructured, due []string, now time.Time) int {
	log := logf.FromContext(ctx)
	unlocked := 0
	for _, key := range due {
		hr := stuck[key]
		// The cooldown reads the wider of the in-RAM ledger and the
		// persisted passiontech.dev/last-helm-unlock stamp — an operator
		// restart empties the ledger but must not refund the 24h.
		// The persisted stamp is folded INTO the ledger before the
		// verdict because the fold is load-bearing: unlocked.Prune
		// releases the alerted dedup only when the ledger entry ages
		// out, so an anno-only stamp must live in the ledger too.
		if t, hasAnno := helmLastUnlock(hr); hasAnno {
			if last, _ := u.pending.unlocked.Last(key); t.After(last) {
				u.pending.unlocked.Stamp(key, t)
			}
		}
		if heal.PersistedCooledDown(&u.pending.unlocked, hr, helmLastUnlockAnno,
			key, helmUnlockCooldown, now) {
			// Still/again stuck inside the cooldown: the previous
			// unlock did NOT resolve it — page instead of churning
			// secrets every tick. The alert itself fires once per
			// cooldown window (alerted ledger), not per sweep.
			if u.pending.alerted.Add(key) {
				last, _ := u.pending.unlocked.Last(key)
				metrics.IncError(u.queue)
				log.Info("ALERT: HR still stuck after unlock — not retrying inside cooldown",
					"hr", key, "unlockedAgo", now.Sub(last).Truncate(time.Minute))
			}
			continue
		}
		acted, err := u.unlock(ctx, gvr, hr)
		if err != nil {
			// Tolerated per-HR failure: the run absorbs it (logs +
			// continues, returns nil) so it never reaches the
			// wrapper — IncError here keeps it on the alert path.
			metrics.IncError(u.queue)
			log.Error(err, "helmrelease unlock failed", "hr", key)
			continue // per-HR failures must not starve the rest
		}
		if !acted {
			// Refused/skipped (no pending secret, or no safe
			// predecessor) — NOT an unlock: stamping the ledger
			// here would suppress re-evaluation for 24h AND spam
			// "still stuck after unlock" errors for a refusal.
			continue
		}
		u.pending.unlocked.Stamp(key, now)
		unlocked++
	}
	return unlocked
}

// unlock deletes the newest pending-* release secret and stamps
// reconcile.fluxcd.io/requestedAt on the HR. Only acts when an older
// deployed/superseded revision exists to roll back to AND the release
// namespace shows no live reconcile evidence (helmUpgradeInProgress).
// acted=false means the HR was evaluated but refused/skipped (no
// pending secret, no safe predecessor, an upgrade still visibly
// progressing, or the secret already gone) — the caller must not
// stamp the cooldown ledger for those.
func (u *helmReleaseUnlocker) unlock(ctx context.Context, gvr schema.GroupVersionResource, hr *unstructured.Unstructured) (bool, error) {
	log := logf.FromContext(ctx)
	key := hr.GetNamespace() + "/" + hr.GetName()
	release := hrReleaseName(hr)

	// Restrict server-side to this release's own secrets: helm
	// release secrets embed the full compressed chart, so an
	// unfiltered list hauls every release in the namespace across
	// the wire. owner=helm + name=<release> is the same label pair
	// the revision scan below matches on. Storage ns is flux's
	// GetStorageNamespace() — spec.storageNamespace || HR namespace;
	// targetNamespace is NOT part of that chain.
	secrets, err := u.cs.CoreV1().Secrets(hrStorageNS(hr)).List(ctx,
		metav1.ListOptions{LabelSelector: "owner=helm,name=" + release})
	if err != nil {
		return false, fmt.Errorf("list release secrets in %s for %s: %w",
			hrStorageNS(hr), release, err)
	}

	var pending *corev1.Secret
	pendingRev := -1
	var safeRevs []int // deployed/superseded revisions = rollback targets
	for i := range secrets.Items {
		s := &secrets.Items[i]
		if s.Type != corev1.SecretType(helmSecretType) || s.Labels["name"] != release {
			continue
		}
		rev, err := strconv.Atoi(s.Labels["version"])
		if err != nil {
			continue
		}
		switch st := s.Labels["status"]; {
		case strings.HasPrefix(st, "pending-"):
			if rev > pendingRev {
				pending, pendingRev = s, rev
			}
		case st == "deployed" || st == "superseded":
			safeRevs = append(safeRevs, rev)
		}
	}
	if pending == nil {
		log.Info("skip: no pending-* release secret — not the pending deadlock", "hr", key, "release", release)
		return false, nil
	}
	olderSafe := false
	for _, r := range safeRevs {
		if r < pendingRev {
			olderSafe = true
			break
		}
	}
	if !olderSafe {
		// pending-install with no prior revision: deleting it orphans
		// the release — refuse (helm-controller#644 class).
		log.Info("skip: pending revision has no deployed/superseded predecessor — refusing",
			"hr", key, "release", release, "pendingRev", pendingRev)
		return false, nil
	}

	// Progress gate — the 30m "in progress" condition cannot tell a
	// genuinely long-running upgrade from a wedged one, so before
	// deleting the pending secret require the release namespace to
	// show NO live reconcile evidence: a helm.sh/hook Job still
	// running (or freshly created, pods not scheduled yet) means
	// helm-controller is mid-flight and the delete would truncate a
	// healthy upgrade. Terminal hook Jobs (Failed/Complete) are the
	// residue of the wedged attempt, not progress; hook Jobs in other
	// namespaces are other releases' business. (status.
	// lastAttemptedGenerationTime was the alternative freshness
	// signal, but flux's v2 HelmRelease status carries no such field —
	// only lastAttemptedGeneration, which has no timestamp and cannot
	// prove recency — so the hook-Job evidence is the gate.) A failed
	// Job list fails closed: unverifiable means no delete.
	inProgress, err := u.helmUpgradeInProgress(ctx, hrReleaseNS(hr))
	if err != nil {
		return false, fmt.Errorf("list hook jobs in %s for %s: %w",
			hrReleaseNS(hr), key, err)
	}
	if inProgress {
		log.Info("skip: hook Jobs still active in the release namespace — upgrade looks alive",
			"hr", key, "releaseNS", hrReleaseNS(hr))
		return false, nil
	}

	log.Info("ACTION: delete stuck pending release secret",
		"hr", key, "secret", pending.Name, "status", pending.Labels["status"], "rev", pendingRev)
	if err := u.cs.CoreV1().Secrets(pending.Namespace).Delete(ctx, pending.Name,
		kube.UIDDeleteOptions(pending.UID, "")); err != nil {
		if apierrors.IsNotFound(err) {
			// Raced with helm-controller's own cleanup (or a prior
			// unlock) — the object this sweep vetted is already gone.
			// A benign race is a skip, not an error, and not an
			// unlock: no cooldown stamp, the next sweep re-evaluates.
			log.Info("skip: pending release secret already gone — raced with helm-controller",
				"hr", key, "secret", pending.Namespace+"/"+pending.Name)
			return false, nil
		}
		return false, fmt.Errorf("delete pending secret %s/%s: %w", pending.Namespace, pending.Name, err)
	}

	// reconcile.fluxcd.io/requestedAt is flux's "reconcile now" hint —
	// only the value changing matters; RFC3339 is the convention. The
	// same patch persists passiontech.dev/last-helm-unlock so the 24h
	// cooldown survives an operator restart.
	now := u.now.Now().UTC().Format(time.RFC3339)
	patch, err := kube.MergePatchAnnos(map[string]any{
		fluxReconcileAnno:  now,
		helmLastUnlockAnno: now,
	})
	if err != nil {
		return false, err
	}
	if _, err := u.dyn.Resource(gvr).Namespace(hr.GetNamespace()).Patch(ctx, hr.GetName(),
		types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
		return false, fmt.Errorf("annotate helmrelease %s: %w", key, err)
	}
	log.Info("ACTION: requested HR reconcile", "hr", key)

	// C3a: failed helm-hook Jobs in the RELEASE namespace are the second
	// half of this deadlock class — hook Jobs are created where the
	// release is installed (targetNamespace || HR namespace), NOT in
	// the storage namespace where the release secrets live. The
	// pending operation that wedged the release usually left a failed
	// hook Job behind, and helm refuses to re-run a hook while its
	// Job object still exists ("cannot re-use a name that is still
	// in use"). Hooks are one-shot by contract, so a Failed hook Job
	// is pure residue; reaping it lets the retried helm run recreate
	// the hook fresh. Best-effort: a list/delete failure here must
	// NOT undo the unlock that already landed — the pending-secret
	// delete + reconcile stamp are the fix.
	u.cleanFailedHookJobs(ctx, hrReleaseNS(hr), hrReleaseName(hr))
	return true, nil
}

// helmLastUnlock reads the persisted passiontech.dev/last-helm-unlock stamp
// — the durable half of the 24h cooldown, surviving operator restarts
// where the in-memory ledger cannot.
func helmLastUnlock(hr *unstructured.Unstructured) (time.Time, bool) {
	return kube.AnnoTime(hr, helmLastUnlockAnno)
}

// helmUpgradeInProgress reports whether the release namespace holds
// evidence that a reconcile is genuinely progressing right now: any
// helm.sh/hook Job still active (or freshly created, pods not yet
// scheduled). The same paged Job list cleanFailedHookJobs uses feeds
// this check — one read, two consumers of the namespace's Jobs.
func (u *helmReleaseUnlocker) helmUpgradeInProgress(ctx context.Context,
	ns string) (bool, error) {
	jobs, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.Jobs(u.cs, ns))
	if err != nil {
		return false, err
	}
	now := u.now.Now()
	for i := range jobs {
		j := &jobs[i]
		// Only helm's own hook Jobs are reconcile evidence — a plain
		// batch Job running in the namespace is just a workload.
		if _, ok := j.Annotations["helm.sh/hook"]; !ok {
			continue
		}
		if hookJobInProgress(j, now) {
			return true, nil
		}
	}
	return false, nil
}

// hookJobInProgress reports whether a hook Job shows live activity:
// no terminal condition (JobFailed/JobComplete=True) AND either pods
// currently active or a creation timestamp inside helmHookFreshWindow.
// A hook Job that is terminal, or stale with no pods, is residue of
// the wedged attempt — never progress.
func hookJobInProgress(j *batchv1.Job, now time.Time) bool {
	for _, c := range j.Status.Conditions {
		if (c.Type == batchv1.JobComplete || c.Type == batchv1.JobFailed) &&
			c.Status == corev1.ConditionTrue {
			return false
		}
	}
	return j.Status.Active > 0 ||
		now.Sub(j.CreationTimestamp.Time) < helmHookFreshWindow
}
