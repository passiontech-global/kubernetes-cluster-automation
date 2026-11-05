// helmrelease-unlocker — breaks the HelmRelease "another operation in
// progress" deadlock (fluxcd/helm-controller#149, #644): the newest
// helm release secret sits in a pending-* state because the helm run
// that created it was killed mid-operation, so helm-controller refuses
// every subsequent reconcile ("another operation ... in progress") and
// the HR stays Ready=False forever.
//
// Detection: HR Ready=False whose message contains "in progress"
// continuously for >30m (first-seen tracked in memory — a healthy
// upgrade legitimately shows that message for minutes).
//
// Confirmation before touching anything: the release's own secrets
// (type helm.sh/release.v1, label name=<release>) in the STORAGE
// namespace (flux GetStorageNamespace: spec.storageNamespace || HR
// namespace — targetNamespace is not in that chain)
// must show the NEWEST revision as pending-* AND an older deployed/
// superseded revision must exist — that is a safe rollback target;
// deleting the pending secret restores the previous state instead of
// orphaning a first-install release with nothing to roll back to.
//
// Action: delete that newest pending-* secret + merge-patch the HR
// annotation reconcile.fluxcd.io/requestedAt=<now> (flux's "reconcile
// now" signal) so helm-controller retries immediately. On a successful
// unlock the RELEASE namespace (targetNamespace || HR namespace —
// where helm installs hook Jobs) is also swept for FAILED helm-hook
// Jobs (C3a): hooks are one-shot, but a failed hook Job object blocks
// the retried release — helm cannot re-run a hook while its old Job
// still exists ("cannot re-use a name that is still in use").
//
// Flux source artifact healer (C1): a HelmRelease OR Kustomization
// stuck Ready=False >=15m on a stale-artifact signature ("artifact
// not found", "failed to fetch", "chart pull error", "failed to
// untar") is almost always a source-controller cache problem, not a
// consumer problem — the fix is stamping
// reconcile.fluxcd.io/requestedAt on the SOURCE object (HelmChart,
// GitRepository, HelmRepository, OCIRepository), which refetches the
// artifact. node.ops/last-source-nudge on the source caps this at
// once per source per 30m across all consumers.
//
// Stalled-rollout surge unwedge (opt-in via
// HELM_STALL_UNWEDGE_ENABLED): a HelmRelease wedged in
// Stalled=True/RetriesExceeded (or Ready=False with a "stalled
// resources" message) after a failed upgrade can sit behind a
// Deployment surge deadlock — the old ReplicaSet's pods still carry
// REQUIRED podAntiAffinity occupying every schedulable node, so the
// new surge pod can never land (incident 2026-11-04,
// 1password/connect on passiontech-k0s-cicd). When the stalled
// workload verifiably matches that shape, the unwedge scales the OLD
// ReplicaSet down by the minimum needed to free one node, then stamps
// reconcile.fluxcd.io/{requestedAt,resetAt,forceAt} on the HR — the
// resetAt token is what clears the RetriesExceeded/Stalled
// bookkeeping (helm-controller >= v0.37.0) without a suspend/resume
// cycle. Full signature + guard details live in
// helm_stall_unwedge.go.
//
// Guards:
//   - max one unlock per HR per 24h (in-memory ledger AND the
//     persisted node.ops/last-helm-unlock annotation — a restart
//     wipes the ledger but must not refund the cooldown); the stall
//     unwedge carries the same 24h cap under its own
//     node.ops/last-helm-stall-unwedge annotation so the two
//     cooldowns never refund each other;
//   - skip+warn while a helm-controller pod (flux-system,
//     app.kubernetes.io/name=helm-controller) is CrashLoopBackOff —
//     deleting secrets cannot converge without a working controller;
//   - an HR stuck again inside the 24h cooldown means the previous
//     unlock did NOT fix it → IncError (alert) instead of churn.
package helmreleaseunlocker

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

const (
	helmUnlockQueue    = "helmrelease-unlocker"
	helmUnlockInterval = 10 * time.Minute
	helmStuckThreshold = 30 * time.Minute // first-seen window before acting
	helmUnlockCooldown = 24 * time.Hour   // max 1 unlock/HR inside this window
	helmSecretType     = "helm.sh/release.v1"
	helmControllerNS   = "flux-system"
	helmControllerSel  = "app.kubernetes.io/name=helm-controller"
	fluxReconcileAnno  = "reconcile.fluxcd.io/requestedAt"
	// helmLastUnlockAnno persists the last unlock moment on the HR —
	// the 24h cooldown survives operator restarts where the unlocked
	// ledger cannot.
	helmLastUnlockAnno = "node.ops/last-helm-unlock"
	// fluxLastNudgeAnno is the per-source 30m cooldown stamp written
	// onto the Flux source object by the artifact healer.
	fluxLastNudgeAnno = "node.ops/last-source-nudge"
	// artifactStuckMinAge: a consumer Ready=False on an artifact-
	// fetch signature this long is a stale source cache, not a
	// transient fetch retry.
	artifactStuckMinAge = 15 * time.Minute
	sourceNudgeCooldown = 30 * time.Minute // max 1 nudge per Flux source
	// W8-GO1 — a Flux Kustomization Ready=False >=15m on an
	// immutable-Job apply error gets the completed/failed Job
	// deleted so kustomize-controller recreates it; the cooldown is
	// per-Kustomization (in-RAM + persisted annotation).
	immutableJobMinAge   = 15 * time.Minute
	immutableJobCooldown = 30 * time.Minute
	immutableJobHealAnno = "node.ops/last-immutable-job-heal"
	// W8-GO2 — the stall-unwedge retry cycle: max 2 attempts per
	// lastAttemptedRevision, each at least 6h apart.
	stallMaxAttemptsPerRevision = 2
	stallAttemptCooldown        = 6 * time.Hour
	// helmListPageSize caps each List response — cluster-wide HR /
	// Kustomization reads page through continue tokens instead of one
	// unbounded fetch.
	helmListPageSize = 500
	// maxSupersededSecrets caps the superseded helm release secrets
	// kept per release (W9-CP2 — Kine bloat guard): every revision
	// secret embeds the full compressed chart and helm never GCs
	// them, so a hot release grows Kine without bound.
	maxSupersededSecrets = 10
)

// helmReleaseGVRs tried in order — v2 on current flux, v2beta2 on
// installs that have not bumped the CRDs yet. The first listable GVR
// wins and is reused for the requestedAt patches.
var helmReleaseGVRs = shared.HelmReleaseGVRs

// fluxKustomizationGVR is the second consumer kind the artifact
// healer scans (kustomize-controller owns the same stale-artifact
// failure class as helm-controller).
var fluxKustomizationGVR = shared.GVRFluxKustomization

// fluxSourceGVRs maps the sourceRef kinds flux consumers carry to
// their source.toolkit.fluxcd.io/v1 GVRs — the objects a stale-
// artifact nudge actually lands on.
var fluxSourceGVRs = map[string]schema.GroupVersionResource{
	"HelmChart":      shared.GVRFluxHelmChart,
	"GitRepository":  shared.GVRFluxGitRepository,
	"HelmRepository": shared.GVRFluxHelmRepository,
	"OCIRepository":  shared.GVRFluxOCIRepository,
	// Bucket is a first-class v1 source kind — a Kustomization or HR
	// sourcing artifacts from an S3/GCS bucket needs the same nudge.
	"Bucket": shared.GVRFluxBucket,
}

type helmReleaseUnlocker struct {
	cs  kubernetes.Interface
	dyn dynamic.Interface
	mu  sync.Mutex
	// firstSeen: ns/name → first tick that saw the HR stuck on
	// "in progress". Pruned when the HR recovers; an operator restart
	// re-arms it, biasing conservative.
	firstSeen map[string]time.Time
	// unlocked: ns/name → last successful unlock — enforces the
	// 1-unlock/24h cap and detects "stuck again after unlock".
	// Pruned each sweep once past the cooldown or when the HR
	// vanished.
	unlocked map[string]time.Time
	// alerted: ns/name → the "still stuck after unlock" page already
	// fired for the CURRENT cooldown window — without it a stuck HR
	// re-bumps the error metric every 10-minute sweep for up to
	// 24h (~144 increments/day). Pruned alongside unlocked so a new
	// cooldown window alerts afresh.
	alerted map[string]bool
	// stallEnabled gates the stalled-rollout surge unwedge —
	// HELM_STALL_UNWEDGE_ENABLED. Opt-in because the remediation
	// scales workload ReplicaSets (brief availability dip) and needs
	// apps/replicasets RBAC the base ClusterRole does not carry.
	stallEnabled bool
	// stallFirstSeen / unwedged / stallAlerted mirror the ledgers
	// above for the stalled-rollout signature: first-seen tracking
	// for the 30m window, the 24h remediation cooldown (also
	// persisted via node.ops/last-helm-stall-unwedge), and the
	// once-per-cooldown alert dedup shared by "re-stalled after
	// unwedge" and "signature matched but a guard refused".
	stallFirstSeen map[string]time.Time
	unwedged       map[string]time.Time
	stallAlerted   map[string]time.Time
	// stallAttempts caps the stall-unwedge retry cycle per
	// lastAttemptedRevision (W8-GO2): at most 2 attempts for one
	// revision, each at least 6h apart — a revision that could not
	// be freed twice is a human problem, not a retry loop.
	stallAttempts map[string]*stallAttempt
	// immutableJobHealed: Kustomization ns/name → last failed-immutable-
	// Job delete (W8-GO1) — the 30m in-RAM half of the cooldown; the
	// durable half is node.ops/last-immutable-job-heal on the
	// Kustomization itself.
	immutableJobHealed map[string]time.Time
}

// stallAttempt counts unwedge tries against one lastAttemptedRevision.
type stallAttempt struct {
	revision string
	count    int
	last     time.Time
}

// Setup registers the 10-minute sweep. HELM_STALL_UNWEDGE_ENABLED
// gates ONLY the stalled-rollout unwedge pass (the pod-affecting
// signature); the pending-secret unlock and the artifact-source
// healer run unconditionally like before.
func Setup(d shared.Deps) error {
	u := &helmReleaseUnlocker{
		cs:                 d.CS,
		dyn:                d.Dyn,
		firstSeen:          map[string]time.Time{},
		unlocked:           map[string]time.Time{},
		alerted:            map[string]bool{},
		stallEnabled:       shared.Gate("HELM_STALL_UNWEDGE_ENABLED", false),
		stallFirstSeen:     map[string]time.Time{},
		unwedged:           map[string]time.Time{},
		stallAlerted:       map[string]time.Time{},
		stallAttempts:      map[string]*stallAttempt{},
		immutableJobHealed: map[string]time.Time{},
	}
	return shared.AddPeriodic(d.Mgr, helmUnlockQueue, helmUnlockInterval, u.run)
}

func (u *helmReleaseUnlocker) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	u.mu.Lock()
	defer u.mu.Unlock()
	// Lazy-init for literal-constructed structs (tests) — Setup
	// always initializes, but a fixture must not panic on a nil map.
	if u.stallFirstSeen == nil {
		u.stallFirstSeen = map[string]time.Time{}
	}
	if u.unwedged == nil {
		u.unwedged = map[string]time.Time{}
	}
	if u.stallAlerted == nil {
		u.stallAlerted = map[string]time.Time{}
	}
	if u.stallAttempts == nil {
		u.stallAttempts = map[string]*stallAttempt{}
	}
	if u.immutableJobHealed == nil {
		u.immutableJobHealed = map[string]time.Time{}
	}

	list, gvr, err := u.listHelmReleases(ctx)
	if err != nil {
		return err
	}

	now := time.Now()
	stuck := map[string]*unstructured.Unstructured{}
	stalled := map[string]*unstructured.Unstructured{}
	present := map[string]bool{} // every listed HR, stuck or not
	for i := range list.Items {
		hr := &list.Items[i]
		key := hr.GetNamespace() + "/" + hr.GetName()
		present[key] = true
		if hrStuckInProgress(hr) {
			stuck[key] = hr
			if _, ok := u.firstSeen[key]; !ok {
				u.firstSeen[key] = now
				log.Info("HR shows 'in progress' — tracking first-seen", "hr", key)
			}
			continue // the pending-op signature claims it — no double-tracking
		}
		if u.stallEnabled && hrStalledRollout(hr) {
			stalled[key] = hr
			if _, ok := u.stallFirstSeen[key]; !ok {
				u.stallFirstSeen[key] = now
				log.Info("HR shows stalled-rollout signature — tracking first-seen", "hr", key)
			}
		}
	}
	// Prune HRs that recovered (or vanished) so a later stall re-arms
	// the 30m window from scratch.
	for key := range u.firstSeen {
		if _, ok := stuck[key]; !ok {
			delete(u.firstSeen, key)
		}
	}
	for key := range u.stallFirstSeen {
		if _, ok := stalled[key]; !ok {
			delete(u.stallFirstSeen, key)
		}
	}
	// Same prune for the unlock ledger: entries past the 24h cooldown
	// are dead weight and entries for HRs that vanished would pile up
	// forever — the map is otherwise append-only per unlocked HR.
	for key, last := range u.unlocked {
		if !present[key] || now.Sub(last) >= helmUnlockCooldown {
			delete(u.unlocked, key)
			delete(u.alerted, key)
		}
	}
	// Identical prune for the unwedge ledger + its alert dedup.
	for key, last := range u.unwedged {
		if !present[key] || now.Sub(last) >= helmUnlockCooldown {
			delete(u.unwedged, key)
		}
	}
	for key, last := range u.stallAlerted {
		if !present[key] || now.Sub(last) >= helmUnlockCooldown {
			delete(u.stallAlerted, key)
		}
	}

	var due []string
	for key := range stuck {
		if now.Sub(u.firstSeen[key]) >= helmStuckThreshold {
			due = append(due, key)
		}
	}
	sort.Strings(due)
	var stallDue []string
	for key := range stalled {
		if now.Sub(u.stallFirstSeen[key]) >= helmStuckThreshold {
			stallDue = append(stallDue, key)
		}
	}
	sort.Strings(stallDue)

	var firstErr error
	// W9-CP2 — Kine bloat guard: cap superseded helm release secrets
	// per release. Independent of every signature below — it runs on
	// every sweep, healthy cluster or not, and BEFORE the per-HR
	// unlock pass so its cluster-wide list never masks the
	// release-scoped secret lists the unlock path performs.
	if err := u.pruneSupersededSecrets(ctx); err != nil && firstErr == nil {
		firstErr = err
	}
	unlocked, unwedged := 0, 0
	if len(due) > 0 || len(stallDue) > 0 {
		// helm-controller crashlooping → neither signature can
		// converge (someone must finish the rollback after the
		// pending secret is deleted, and someone must retry the
		// release after the surge window opens). Warn and abort;
		// the next tick re-evaluates.
		down, err := u.helmControllerDown(ctx)
		switch {
		case err != nil:
			// Report, but don't blind the C1 source healer below —
			// it reads different resources than the pod list.
			firstErr = err
		case down:
			log.Info("SKIP: helm-controller pod CrashLoopBackOff — unlock/unwedge would not converge",
				"due", due, "stallDue", stallDue)
		default:
			unlocked = u.unlockDue(ctx, gvr, stuck, due, now)
			unwedged = u.unwedgeDue(ctx, gvr, stalled, stallDue, now)
		}
	}

	// C1 — stale-artifact source healing is independent of the
	// in-progress unlock path: it scans the same HR list plus
	// Kustomizations and must run on every sweep.
	if err := u.healArtifactSources(ctx, list); err != nil && firstErr == nil {
		firstErr = err
	}
	// W8-GO1 — immutable-Job apply errors on Kustomizations: the
	// completed/failed Job blocking the apply is reaped so
	// kustomize-controller can recreate it.
	if err := u.healImmutableJobs(ctx); err != nil && firstErr == nil {
		firstErr = err
	}
	log.Info("sweep done", "stuck", len(stuck), "due", len(due), "unlocked", unlocked,
		"stalled", len(stalled), "stallDue", len(stallDue), "unwedged", unwedged)
	return firstErr
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
		// persisted node.ops/last-helm-unlock stamp — an operator
		// restart empties the ledger but must not refund the 24h.
		last, ok := u.unlocked[key]
		if t, hasAnno := helmLastUnlock(hr); hasAnno && t.After(last) {
			last, ok = t, true
		}
		if ok && now.Sub(last) < helmUnlockCooldown {
			u.unlocked[key] = last // fold the persisted stamp into the ledger
			// Still/again stuck inside the cooldown: the previous
			// unlock did NOT resolve it — page instead of churning
			// secrets every tick. The alert itself fires once per
			// cooldown window (alerted ledger), not per sweep.
			if u.alerted == nil {
				u.alerted = map[string]bool{} // literal-constructed structs (tests)
			}
			if !u.alerted[key] {
				metrics.IncError(helmUnlockQueue)
				u.alerted[key] = true
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
			metrics.IncError(helmUnlockQueue)
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
		u.unlocked[key] = now
		unlocked++
	}
	return unlocked
}

// listHelmReleases returns the HR list and the GVR that answered — v2
// first, v2beta2 when the v2 CRDs are absent. Pages at
// helmListPageSize: HRs are unbounded cluster-wide and each item
// embeds values/crds hooks — a single shot List of a large fleet is
// a heap spike.
func (u *helmReleaseUnlocker) listHelmReleases(ctx context.Context) (*unstructured.UnstructuredList, schema.GroupVersionResource, error) {
	var lastErr error
	for _, gvr := range helmReleaseGVRs {
		list, err := u.listAllPages(ctx, u.dyn.Resource(gvr))
		if err == nil {
			return list, gvr, nil
		}
		lastErr = err
	}
	return nil, schema.GroupVersionResource{},
		fmt.Errorf("list helmreleases (all known GVRs failed): %w", lastErr)
}

// listAllPages walks ListOptions.Continue until the apiserver stops
// paging — every cluster-wide dynamic List in this module goes through
// it so no single response hauls the whole resource across the wire.
func (u *helmReleaseUnlocker) listAllPages(ctx context.Context,
	ri dynamic.ResourceInterface) (*unstructured.UnstructuredList, error) {
	items, err := shared.ListAll(ctx, metav1.ListOptions{Limit: helmListPageSize},
		shared.DynamicPage(ri))
	if err != nil {
		return nil, err
	}
	return &unstructured.UnstructuredList{Items: items}, nil
}

// hrStuckInProgress reports whether the HR's Ready condition is False
// with a "…in progress" message — the deadlock signature. A missing or
// non-False Ready never counts.
func hrStuckInProgress(hr *unstructured.Unstructured) bool {
	status, msg := shared.ReadyCond(hr)
	return status == "False" && strings.Contains(msg, "in progress")
}

// helmControllerDown reports whether any helm-controller pod is
// CrashLoopBackOff. A list error is a real error for the caller.
func (u *helmReleaseUnlocker) helmControllerDown(ctx context.Context) (bool, error) {
	pods, err := u.cs.CoreV1().Pods(helmControllerNS).List(ctx,
		metav1.ListOptions{LabelSelector: helmControllerSel})
	if err != nil {
		return false, fmt.Errorf("list helm-controller pods: %w", err)
	}
	for i := range pods.Items {
		statuses := append([]corev1.ContainerStatus{},
			pods.Items[i].Status.InitContainerStatuses...)
		statuses = append(statuses, pods.Items[i].Status.ContainerStatuses...)
		for _, s := range statuses {
			if s.State.Waiting != nil && s.State.Waiting.Reason == "CrashLoopBackOff" {
				logf.FromContext(ctx).Info("helm-controller pod CrashLoopBackOff",
					"pod", helmControllerNS+"/"+pods.Items[i].Name,
					"container", s.Name)
				return true, nil
			}
		}
	}
	return false, nil
}

// unlock deletes the newest pending-* release secret and stamps
// reconcile.fluxcd.io/requestedAt on the HR. Only acts when an older
// deployed/superseded revision exists to roll back to. acted=false
// means the HR was evaluated but refused (no pending secret / no
// safe predecessor) — the caller must not stamp the cooldown ledger
// for those.
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

	log.Info("ACTION: delete stuck pending release secret",
		"hr", key, "secret", pending.Name, "status", pending.Labels["status"], "rev", pendingRev)
	if err := u.cs.CoreV1().Secrets(pending.Namespace).Delete(ctx, pending.Name,
		metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &pending.UID}}); err != nil {
		return false, fmt.Errorf("delete pending secret %s/%s: %w", pending.Namespace, pending.Name, err)
	}

	// reconcile.fluxcd.io/requestedAt is flux's "reconcile now" hint —
	// only the value changing matters; RFC3339 is the convention. The
	// same patch persists node.ops/last-helm-unlock so the 24h
	// cooldown survives an operator restart.
	now := time.Now().UTC().Format(time.RFC3339)
	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"annotations": map[string]string{
			fluxReconcileAnno:  now,
			helmLastUnlockAnno: now,
		}},
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
	u.cleanFailedHookJobs(ctx, hrReleaseNS(hr))
	return true, nil
}

// ---------------------------------------------------------------------------
// W9-CP2 — superseded helm release secret pruner (Kine bloat guard)
// ---------------------------------------------------------------------------

// pruneSupersededSecrets caps superseded helm release secrets per
// release. Helm writes one sh.helm.release.v1 Secret per revision and
// never garbage-collects the superseded ones — each embeds the full
// compressed chart, so a frequently-upgraded release grows Kine
// (and the storage backend behind it) without bound.
//
// For every release — grouped by storage namespace + the `name`
// label, the same identity unlock() scopes its revision scan to —
// secrets with status=="superseded" and a valid integer `version`
// label are sorted ascending; when a release holds more than
// maxSupersededSecrets the OLDEST excess are deleted with a UID
// precondition. deployed, pending-*, and failed secrets are NEVER
// touched — they are live install/rollback state, not history — and
// neither is the highest-version secret of the release, which stays
// the newest rollback point even when it is itself superseded.
func (u *helmReleaseUnlocker) pruneSupersededSecrets(ctx context.Context) error {
	log := logf.FromContext(ctx)
	// Cluster-wide, server-side filtered to helm release secrets —
	// owner=helm is the same label unlock() selects on. Paged like
	// every cluster-wide list in this module.
	secrets, err := shared.ListAll(ctx, metav1.ListOptions{
		LabelSelector: "owner=helm", Limit: helmListPageSize},
		shared.Secrets(u.cs, metav1.NamespaceAll))
	if err != nil {
		// Hygiene sweep — a list failure must not fail the run
		// (same posture as cleanFailedHookJobs): the next sweep
		// retries, and IncError keeps it on the alert path.
		metrics.IncError(helmUnlockQueue)
		log.Error(err, "superseded secret prune: list failed — skipped")
		return nil
	}
	// Group by storage namespace + release name.
	type relKey struct{ ns, name string }
	byRelease := map[relKey][]*corev1.Secret{}
	for i := range secrets {
		s := &secrets[i]
		release := s.Labels["name"]
		if release == "" || s.Type != corev1.SecretType(helmSecretType) {
			continue
		}
		k := relKey{s.Namespace, release}
		byRelease[k] = append(byRelease[k], s)
	}
	secrets = nil // release the cluster-wide slice before issuing deletes

	type supersededSecret struct {
		s *corev1.Secret
		v int
	}
	pruned := 0
	for k, relSecrets := range byRelease {
		// Highest revision across ALL statuses — the one secret that
		// is never pruned even when it is itself superseded.
		highest := -1
		var superseded []supersededSecret
		for _, s := range relSecrets {
			v, err := strconv.Atoi(s.Labels["version"])
			if err != nil {
				continue // unversioned — never ours to judge
			}
			if v > highest {
				highest = v
			}
			if s.Labels["status"] == "superseded" {
				superseded = append(superseded, supersededSecret{s, v})
			}
		}
		if len(superseded) <= maxSupersededSecrets {
			continue
		}
		sort.Slice(superseded, func(i, j int) bool {
			return superseded[i].v < superseded[j].v
		})
		toDelete := len(superseded) - maxSupersededSecrets
		for _, cand := range superseded {
			if toDelete <= 0 {
				break
			}
			if cand.v == highest {
				continue // never touch the highest-version secret
			}
			log.Info("ACTION: prune superseded helm release secret",
				"release", k.ns+"/"+k.name, "secret", cand.s.Name,
				"version", cand.v, "supersededTotal", len(superseded))
			if err := u.cs.CoreV1().Secrets(cand.s.Namespace).Delete(ctx,
				cand.s.Name, metav1.DeleteOptions{
					Preconditions: &metav1.Preconditions{UID: &cand.s.UID}}); err != nil {
				metrics.IncError(helmUnlockQueue)
				log.Error(err, "superseded secret delete failed",
					"secret", cand.s.Namespace+"/"+cand.s.Name)
				continue // try the next-oldest instead of giving up
			}
			metrics.HelmSecretsPrunedTotal.WithLabelValues(cand.s.Namespace).Inc()
			pruned++
			toDelete--
		}
	}
	if pruned > 0 {
		log.Info("superseded helm secret prune done", "pruned", pruned)
	}
	return nil
}

// cleanFailedHookJobs deletes batchv1 Jobs in ns that carry the
// helm.sh/hook annotation and report JobFailed=True, with background
// propagation so their pods go with them. Each deletion bumps
// metrics.HelmHookJobsCleanedTotal{namespace}. Errors are logged and
// skipped — hook cleanup never fails the caller.
func (u *helmReleaseUnlocker) cleanFailedHookJobs(ctx context.Context, ns string) {
	log := logf.FromContext(ctx)
	jobs, err := u.cs.BatchV1().Jobs(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Error(err, "helm-hook job list failed — hook cleanup skipped", "ns", ns)
		return
	}
	bg := metav1.DeletePropagationBackground
	for i := range jobs.Items {
		j := &jobs.Items[i]
		if _, ok := j.Annotations["helm.sh/hook"]; !ok {
			continue // not a helm hook — never ours to reap
		}
		if !jobFailed(j) {
			continue // still running or succeeded — leave it
		}
		log.Info("ACTION: delete failed helm-hook Job",
			"ns", ns, "job", j.Name)
		if err := u.cs.BatchV1().Jobs(ns).Delete(ctx, j.Name,
			metav1.DeleteOptions{PropagationPolicy: &bg,
				Preconditions: &metav1.Preconditions{UID: &j.UID}}); err != nil {
			log.Error(err, "helm-hook job delete failed", "ns", ns, "job", j.Name)
			continue
		}
		metrics.HelmHookJobsCleanedTotal.WithLabelValues(ns).Inc()
	}
}

// jobFailed reports whether the Job carries a JobFailed=True condition.
func jobFailed(j *batchv1.Job) bool {
	for _, c := range j.Status.Conditions {
		if c.Type == batchv1.JobFailed && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// helmLastUnlock reads the persisted node.ops/last-helm-unlock stamp
// — the durable half of the 24h cooldown, surviving operator restarts
// where the in-memory ledger cannot.
func helmLastUnlock(hr *unstructured.Unstructured) (time.Time, bool) {
	v := hr.GetAnnotations()[helmLastUnlockAnno]
	if v == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// ---------------------------------------------------------------------------
// C1 — Flux source artifact cache healer
// ---------------------------------------------------------------------------

// artifactFailMsgs are the Ready=False message fragments marking a
// stale artifact on the SOURCE side — refetching the source is the
// fix, not churning the consumer's own backoff.
var artifactFailMsgs = []string{
	"artifact not found", "failed to fetch", "chart pull error", "failed to untar",
}

// fluxSourceRef is a resolved source object coordinates tuple.
type fluxSourceRef struct{ kind, namespace, name string }

// healArtifactSources scans every HelmRelease (already listed by the
// caller) and every Kustomization for the stale-artifact signature,
// resolves each consumer's Flux source, and stamps
// reconcile.fluxcd.io/requestedAt on it — source-controller refetches
// the artifact, which is what actually unstucks the consumer. The
// node.ops/last-source-nudge stamp on the source caps this at once
// per source per 30m across ALL consumers pointing at it.
func (u *helmReleaseUnlocker) healArtifactSources(ctx context.Context,
	hrs *unstructured.UnstructuredList) error {
	log := logf.FromContext(ctx)
	kustomizations, err := u.listAllPages(ctx, u.dyn.Resource(fluxKustomizationGVR))
	if err != nil {
		if apierrors.IsNotFound(err) {
			kustomizations = nil // pre-v1 flux — the HR half still runs
		} else {
			return fmt.Errorf("list kustomizations: %w", err)
		}
	}
	nudged := 0
	for i := range hrs.Items {
		hr := &hrs.Items[i]
		if !fluxArtifactStale(hr) {
			continue
		}
		if ref, ok := hrSourceRef(hr); ok &&
			u.nudgeSource(ctx, ref, consumerID("HelmRelease", hr)) {
			nudged++
		}
		if hcRef, ok := hrStatusHelmChartRef(hr); ok &&
			u.nudgeSource(ctx, hcRef, consumerID("HelmRelease", hr)) {
			nudged++
		}
	}
	if kustomizations != nil {
		for i := range kustomizations.Items {
			k := &kustomizations.Items[i]
			if !fluxArtifactStale(k) {
				continue
			}
			if ref, ok := ksSourceRef(k); ok &&
				u.nudgeSource(ctx, ref, consumerID("Kustomization", k)) {
				nudged++
			}
		}
	}
	log.Info("flux artifact-source sweep done", "sourcesNudged", nudged)
	return nil
}

// fluxArtifactStale is the stale-artifact signature: a non-suspended
// consumer Ready=False continuously for >=15m with a message pointing
// at the source's artifact (not the consumer's own logic).
func fluxArtifactStale(o *unstructured.Unstructured) bool {
	if suspended, _ := shared.NestedBool(o.Object, "spec", "suspend"); suspended {
		return false // suspended objects are parked, not broken
	}
	status, msg := shared.ReadyCond(o)
	if status != "False" {
		return false
	}
	lower := strings.ToLower(msg)
	hit := false
	for _, s := range artifactFailMsgs {
		if strings.Contains(lower, s) {
			hit = true
			break
		}
	}
	if !hit {
		return false
	}
	since, ok := shared.ReadySince(o)
	if !ok {
		since = o.GetCreationTimestamp().Time
	}
	return time.Since(since) >= artifactStuckMinAge
}

// hrSourceRef resolves the source a HelmRelease pulls its artifact
// from: spec.chartRef (v2 — HelmChart/OCIRepository) or the legacy
// spec.chart.spec.sourceRef (HelmRepository/GitRepository). The
// namespace defaults to the HR's own (flux convention).
func hrSourceRef(hr *unstructured.Unstructured) (fluxSourceRef, bool) {
	kind, _ := shared.NestedString(hr.Object, "spec", "chartRef", "kind")
	name, _ := shared.NestedString(hr.Object, "spec", "chartRef", "name")
	ns, _ := shared.NestedString(hr.Object, "spec", "chartRef", "namespace")
	if kind == "" || name == "" {
		kind, _ = shared.NestedString(
			hr.Object, "spec", "chart", "spec", "sourceRef", "kind")
		name, _ = shared.NestedString(
			hr.Object, "spec", "chart", "spec", "sourceRef", "name")
		ns, _ = shared.NestedString(
			hr.Object, "spec", "chart", "spec", "sourceRef", "namespace")
	}
	if kind == "" || name == "" {
		return fluxSourceRef{}, false
	}
	if ns == "" {
		ns = hr.GetNamespace()
	}
	return fluxSourceRef{kind: kind, namespace: ns, name: name}, true
}

// hrStatusHelmChartRef resolves the synthesized HelmChart recorded in
// status.helmChart ("<namespace>/<name>") when the HelmRelease uses
// spec.chart.spec.sourceRef (not spec.chartRef: HelmChart), so both the
// upstream repository and the HelmChart artifact are nudged.
func hrStatusHelmChartRef(hr *unstructured.Unstructured) (fluxSourceRef, bool) {
	if cKind, _ := shared.NestedString(hr.Object, "spec", "chartRef", "kind"); cKind == "HelmChart" {
		return fluxSourceRef{}, false
	}
	hc, _ := shared.NestedString(hr.Object, "status", "helmChart")
	ns, name, ok := strings.Cut(hc, "/")
	if !ok || ns == "" || name == "" {
		return fluxSourceRef{}, false
	}
	return fluxSourceRef{kind: "HelmChart", namespace: ns, name: name}, true
}

// ksSourceRef is spec.sourceRef on a Kustomization — same flux
// convention (namespace defaults to the object's own).
func ksSourceRef(k *unstructured.Unstructured) (fluxSourceRef, bool) {
	kind, _ := shared.NestedString(k.Object, "spec", "sourceRef", "kind")
	name, _ := shared.NestedString(k.Object, "spec", "sourceRef", "name")
	ns, _ := shared.NestedString(k.Object, "spec", "sourceRef", "namespace")
	if kind == "" || name == "" {
		return fluxSourceRef{}, false
	}
	if ns == "" {
		ns = k.GetNamespace()
	}
	return fluxSourceRef{kind: kind, namespace: ns, name: name}, true
}

// consumerID renders the complaining consumer for log lines.
func consumerID(kind string, o *unstructured.Unstructured) string {
	return kind + " " + o.GetNamespace() + "/" + o.GetName()
}

// nudgeSource stamps reconcile.fluxcd.io/requestedAt + the
// node.ops/last-source-nudge cooldown onto a Flux source object.
// Failures are per-source: IncError + false, never an aborted sweep.
func (u *helmReleaseUnlocker) nudgeSource(ctx context.Context,
	ref fluxSourceRef, consumer string) bool {
	log := logf.FromContext(ctx)
	key := ref.namespace + "/" + ref.name
	gvr, ok := fluxSourceGVRs[ref.kind]
	if !ok {
		log.Info("skip: source kind is not a nudgeable Flux source",
			"kind", ref.kind, "consumer", consumer)
		return false
	}
	src, err := u.dyn.Resource(gvr).Namespace(ref.namespace).
		Get(ctx, ref.name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("skip: flux source gone",
				"kind", ref.kind, "source", key, "consumer", consumer)
			return false
		}
		metrics.IncError(helmUnlockQueue)
		log.Error(err, "flux source get failed", "kind", ref.kind, "source", key)
		return false
	}
	if ts := src.GetAnnotations()[fluxLastNudgeAnno]; ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil &&
			time.Since(t) < sourceNudgeCooldown {
			log.Info("skip: source nudged inside cooldown",
				"kind", ref.kind, "source", key,
				"ago", time.Since(t).Truncate(time.Minute))
			return false
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"annotations": map[string]string{
			fluxReconcileAnno: now,
			fluxLastNudgeAnno: now,
		}},
	})
	if err != nil {
		return false
	}
	if _, err := u.dyn.Resource(gvr).Namespace(ref.namespace).Patch(ctx, ref.name,
		types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
		metrics.IncError(helmUnlockQueue)
		log.Error(err, "flux source nudge patch failed", "kind", ref.kind, "source", key)
		return false
	}
	metrics.FluxSourceReconcilesTriggeredTotal.
		WithLabelValues(ref.kind, ref.namespace, ref.name).Inc()
	log.Info("ACTION: requested flux source reconcile — consumer reports a stale artifact",
		"kind", ref.kind, "source", key, "consumer", consumer)
	return true
}

// hrReleaseName mirrors upstream flux's GetReleaseName():
// spec.releaseName wins, then "<targetNamespace>-<name>" when a
// targetNamespace is set (flux prefixes the release name to keep
// same-named HRs in different target namespaces distinct), then the
// bare object name. It is the `name=` label helm puts on its release
// secrets.
func hrReleaseName(hr *unstructured.Unstructured) string {
	if n, _ := shared.NestedString(hr.Object, "spec", "releaseName"); n != "" {
		return n
	}
	if ns, _ := shared.NestedString(hr.Object, "spec", "targetNamespace"); ns != "" {
		return ns + "-" + hr.GetName()
	}
	return hr.GetName()
}

// hrReleaseNS resolves where the release is INSTALLED —
// spec.targetNamespace || HR namespace (upstream flux's
// GetReleaseNamespace used to locate hook Jobs, pods, and every
// workload the chart renders). Hook Jobs live here, not in the
// storage namespace.
func hrReleaseNS(hr *unstructured.Unstructured) string {
	if ns, _ := shared.NestedString(hr.Object, "spec", "targetNamespace"); ns != "" {
		return ns
	}
	return hr.GetNamespace()
}

// hrStorageNS mirrors upstream flux's GetStorageNamespace():
// spec.storageNamespace || HR namespace. This is where helm-controller
// writes the sh.helm.release.v1 secrets — spec.targetNamespace is NOT
// part of the chain (it only locates the installed release, not its
// bookkeeping).
func hrStorageNS(hr *unstructured.Unstructured) string {
	if ns, _ := shared.NestedString(hr.Object, "spec", "storageNamespace"); ns != "" {
		return ns
	}
	return hr.GetNamespace()
}

// ---------------------------------------------------------------------------
// W8-GO1 — immutable-Job apply error healer
// ---------------------------------------------------------------------------

// immutableJobRe extracts the Job name out of the kustomize apply
// error `Job.batch "<name>" is invalid: ... field is immutable`.
var immutableJobRe = regexp.MustCompile(`Job\.batch "([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)" is invalid`)

// healImmutableJobs scans Kustomizations for Ready=False >=15m whose
// message is the immutable-Job apply error: a Job manifest changed an
// immutable field (spec.template), so apply fails forever until the
// OLD Job object disappears — and a Job that already ran to Complete
// or Failed is pure residue. Deleting it unblocks the apply. The
// 30m cooldown rides the in-RAM ledger + the persisted
// node.ops/last-immutable-job-heal stamp on the Kustomization.
func (u *helmReleaseUnlocker) healImmutableJobs(ctx context.Context) error {
	log := logf.FromContext(ctx)
	kustomizations, err := u.listAllPages(ctx, u.dyn.Resource(fluxKustomizationGVR))
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil // pre-v1 flux — nothing to scan
		}
		return fmt.Errorf("list kustomizations: %w", err)
	}
	now := time.Now()
	for i := range kustomizations.Items {
		k := &kustomizations.Items[i]
		if suspended, _ := shared.NestedBool(k.Object, "spec", "suspend"); suspended {
			continue
		}
		status, msg := shared.ReadyCond(k)
		if status != "False" || !strings.Contains(strings.ToLower(msg), "field is immutable") {
			continue
		}
		m := immutableJobRe.FindStringSubmatch(msg)
		if m == nil {
			continue
		}
		since, ok := shared.ReadySince(k)
		if !ok {
			since = k.GetCreationTimestamp().Time
		}
		if now.Sub(since) < immutableJobMinAge {
			continue
		}
		key := k.GetNamespace() + "/" + k.GetName()
		// Cooldown: wider of the in-RAM ledger and the persisted stamp.
		last := u.immutableJobHealed[key]
		if t, err := time.Parse(time.RFC3339,
			k.GetAnnotations()[immutableJobHealAnno]); err == nil && t.After(last) {
			last = t
		}
		if now.Sub(last) < immutableJobCooldown {
			u.immutableJobHealed[key] = last
			continue
		}
		// The Job lives where the manifests apply — spec.targetNamespace
		// wins, else the Kustomization's own namespace.
		jobNS := k.GetNamespace()
		if tns, _ := shared.NestedString(k.Object, "spec", "targetNamespace"); tns != "" {
			jobNS = tns
		}
		job, err := u.cs.BatchV1().Jobs(jobNS).Get(ctx, m[1], metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				continue // already gone — nothing to reap
			}
			metrics.IncError(helmUnlockQueue)
			log.Error(err, "immutable-job lookup failed", "kustomization", key, "job", jobNS+"/"+m[1])
			continue
		}
		done := job.Status.Succeeded >= 1 || jobFailed(job)
		for _, c := range job.Status.Conditions {
			if c.Type == batchv1.JobComplete && c.Status == corev1.ConditionTrue {
				done = true
			}
		}
		if !done {
			log.Info("skip: immutable Job still active — deleting it mid-run would orphan its pods",
				"kustomization", key, "job", jobNS+"/"+job.Name)
			continue
		}
		log.Info("ACTION: delete completed/failed immutable Job — apply can recreate it",
			"kustomization", key, "job", jobNS+"/"+job.Name)
		bg := metav1.DeletePropagationBackground
		if err := u.cs.BatchV1().Jobs(jobNS).Delete(ctx, job.Name,
			metav1.DeleteOptions{PropagationPolicy: &bg,
				Preconditions: &metav1.Preconditions{UID: &job.UID}}); err != nil {
			metrics.IncError(helmUnlockQueue)
			log.Error(err, "immutable job delete failed", "job", jobNS+"/"+job.Name)
			continue
		}
		// Persist the stamp — the durable half of the 30m cooldown.
		u.immutableJobHealed[key] = now
		payload, err := json.Marshal(map[string]any{
			"metadata": map[string]any{"annotations": map[string]string{
				immutableJobHealAnno: now.UTC().Format(time.RFC3339),
			}},
		})
		if err != nil {
			continue
		}
		if _, err := u.dyn.Resource(fluxKustomizationGVR).Namespace(k.GetNamespace()).
			Patch(ctx, k.GetName(), types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
			metrics.IncError(helmUnlockQueue)
			log.Error(err, "immutable-job heal stamp failed", "kustomization", key)
		}
	}
	return nil
}
