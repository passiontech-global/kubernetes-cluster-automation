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
// artifact. passiontech.dev/last-source-nudge on the source caps this at
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
//     persisted passiontech.dev/last-helm-unlock annotation — a restart
//     wipes the ledger but must not refund the cooldown); the stall
//     unwedge carries the same 24h cap under its own
//     passiontech.dev/last-helm-stall-unwedge annotation so the two
//     cooldowns never refund each other;
//   - skip+warn while a helm-controller pod (flux-system,
//     app.kubernetes.io/name=helm-controller) is CrashLoopBackOff —
//     deleting secrets cannot converge without a working controller;
//   - an HR stuck again inside the 24h cooldown means the previous
//     unlock did NOT fix it → IncError (alert) instead of churn.
package helmreleaseunlocker

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/go-logr/logr"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/reap"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	helmUnlockInterval = 10 * time.Minute
	helmStuckThreshold = 30 * time.Minute // first-seen window before acting
	helmUnlockCooldown = 24 * time.Hour   // max 1 unlock/HR inside this window
	helmSecretType     = "helm.sh/release.v1"
	helmControllerNS   = "flux-system"
	helmControllerSel  = "app.kubernetes.io/name=helm-controller"
	fluxReconcileAnno  = kube.AnnoFluxRequestedAt
)

// helmReleaseGVRs tried in order — v2 on current flux, v2beta2 on
// installs that have not bumped the CRDs yet. The first listable GVR
// wins and is reused for the requestedAt patches.
var helmReleaseGVRs = kube.HelmReleaseGVRs

type helmReleaseUnlocker struct {
	cs  kubernetes.Interface
	dyn dynamic.Interface
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name and every IncError label
	// come from one place.
	queue string
	// now is the clock seam — tests pin it so the first-seen
	// windows and the 24h cooldowns are deterministic. nil →
	// time.Now.
	now shared.Clock

	// One sub-struct per healer duty so run() prunes/resets each
	// duty's ledgers as one block. Every ledger type is zero-value
	// ready, so literal-constructed fixtures keep working unchanged.
	pending      pendingState
	stall        stallState
	immutableJob immutableJobState
}

// pendingState carries the pending-secret unlock duty's ledgers.
type pendingState struct {
	// firstSeen: ns/name → first tick that saw the HR stuck on
	// "in progress". Pruned when the HR recovers; an operator restart
	// re-arms it, biasing conservative.
	firstSeen state.FirstSeenLedger
	// unlocked: ns/name → last successful unlock — enforces the
	// 1-unlock/24h cap and detects "stuck again after unlock".
	// Pruned each sweep once past the cooldown or when the HR
	// vanished (Last() feeds the per-HR raw-stamp read and Prune's
	// `last` arg the expiry check).
	unlocked state.CooldownSet
	// alerted: ns/name → the "still stuck after unlock" page already
	// fired for the CURRENT cooldown window — without it a stuck HR
	// re-bumps the error metric every 10-minute sweep for up to
	// 24h (~144 increments/day). Pruned alongside unlocked so a new
	// cooldown window alerts afresh.
	alerted state.SeenSet
}

// stallState mirrors pendingState for the stalled-rollout signature:
// enabled is the HELM_STALL_UNWEDGE_ENABLED opt-in (the remediation
// scales workload ReplicaSets — brief availability dip — and needs
// apps/replicasets RBAC the base ClusterRole does not carry);
// firstSeen tracks the 30m window, unwedged the 24h remediation
// cooldown (also persisted via passiontech.dev/last-helm-stall-unwedge),
// alerted the once-per-cooldown alert dedup shared by "re-stalled
// after unwedge" and "signature matched but a guard refused", and
// attempts the W8-GO2 retry-cycle cap. CooldownSets are zero-value
// ready and deliberately unbounded: stamps past the window read
// uncooled and entries for vanished HRs are dead weight.
type stallState struct {
	enabled   bool
	firstSeen state.FirstSeenLedger
	unwedged  state.CooldownSet
	alerted   state.CooldownSet
	attempts  map[string]*stallAttempt
}

// immutableJobState carries the W8-GO1 immutable-Job heal ledger:
// Kustomization ns/name → last failed-immutable-Job delete — the 30m
// in-RAM half of the cooldown; the durable half is
// passiontech.dev/last-immutable-job-heal on the Kustomization itself.
type immutableJobState struct {
	healed state.CooldownSet
}

// stallAttempt counts unwedge tries against one lastAttemptedRevision.
type stallAttempt struct {
	revision string
	count    int
	last     time.Time
}

// Setup registers the 10-minute sweep. HELM_STALL_UNWEDGE_ENABLED
// gates ONLY the stalled-rollout unwedge pass (the pod-affecting
// signature) — a run-behavior sub-gate parsed through SetupWithConfig,
// NOT a registration gate; the pending-secret unlock and the
// artifact-source healer run unconditionally like before.
func Setup(d shared.Deps) error {
	return shared.SetupWithConfig(d, stallEnabledFromEnv,
		func(stallEnabled bool) error {
			u := &helmReleaseUnlocker{
				cs:    d.CS,
				dyn:   d.Dyn,
				queue: d.Name,
				now:   shared.SystemClock,
			}
			u.stall.enabled = stallEnabled
			u.stall.attempts = map[string]*stallAttempt{}
			return shared.AddPeriodic(d.Mgr, u.queue, helmUnlockInterval, u.run)
		})
}

// stallEnabledFromEnv resolves the stalled-rollout unwedge sub-gate.
// SetupWithConfig runs it before the Deps.Disabled check so an
// unparseable HELM_STALL_UNWEDGE_ENABLED warns even on a gated-off
// cluster (the module carries no GateEnv row — always registered —
// but the parse-before-gate ordering contract stays uniform).
func stallEnabledFromEnv() bool {
	return envx.Gate("HELM_STALL_UNWEDGE_ENABLED", false)
}

func (u *helmReleaseUnlocker) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	// Lazy-init for literal-constructed structs (tests) — Setup
	// always initializes, but a fixture must not panic on a nil map.
	// The FirstSeenLedger, SeenSet and CooldownSet fields are
	// zero-value ready — no arm needed.
	if u.stall.attempts == nil {
		u.stall.attempts = map[string]*stallAttempt{}
	}

	list, gvr, err := u.listHelmReleases(ctx)
	if err != nil {
		return err
	}

	now := u.now.Now()
	stuck := map[string]*unstructured.Unstructured{}
	stalled := map[string]*unstructured.Unstructured{}
	present := map[string]bool{} // every listed HR, stuck or not
	for i := range list.Items {
		hr := &list.Items[i]
		key := hr.GetNamespace() + "/" + hr.GetName()
		present[key] = true
		if hrStuckInProgress(hr) {
			stuck[key] = hr
			if _, tracked := u.pending.firstSeen.Observe(key, now); !tracked {
				log.Info("HR shows 'in progress' — tracking first-seen", "hr", key)
			}
			continue // the pending-op signature claims it — no double-tracking
		}
		if u.stall.enabled && hrStalledRollout(hr) {
			stalled[key] = hr
			if _, tracked := u.stall.firstSeen.Observe(key, now); !tracked {
				log.Info("HR shows stalled-rollout signature — tracking first-seen", "hr", key)
			}
		}
	}
	// Prune HRs that recovered (or vanished) so a later stall re-arms
	// the 30m window from scratch.
	u.pending.firstSeen.Prune(func(key string) bool {
		_, ok := stuck[key]
		return ok
	})
	u.stall.firstSeen.Prune(func(key string) bool {
		_, ok := stalled[key]
		return ok
	})
	// Same prune for the unlock ledger — not because CooldownSet
	// needs it (a stale stamp reads uncooled on its own) but to keep
	// the alerted dedup paired: a vanished or aged-out entry must
	// release its alert key so a NEW cooldown window alerts afresh.
	u.pending.unlocked.Prune(func(key string, last time.Time) bool {
		keep := present[key] && now.Sub(last) < helmUnlockCooldown
		if !keep {
			u.pending.alerted.Forget(key)
		}
		return keep
	})
	// The unwedge ledger, its alert dedup and the immutable-Job heal
	// ledger all key on HR/Kustomization names that can be
	// decommissioned — bound each map once per sweep at the cooldown
	// it serves so dead names cannot accumulate forever (a stamp
	// inside the window always reads cooled, so maxAge IS the
	// window).
	u.stall.unwedged.PruneExpired(now, helmUnlockCooldown)
	u.stall.alerted.PruneExpired(now, helmUnlockCooldown)
	u.immutableJob.healed.PruneExpired(now, immutableJobCooldown)

	var due []string
	for key := range stuck {
		if stuckFor, _ := u.pending.firstSeen.Seen(key, now); stuckFor >= helmStuckThreshold {
			due = append(due, key)
		}
	}
	sort.Strings(due)
	var stallDue []string
	for key := range stalled {
		if stalledFor, _ := u.stall.firstSeen.Seen(key, now); stalledFor >= helmStuckThreshold {
			stallDue = append(stallDue, key)
		}
	}
	sort.Strings(stallDue)

	// The superseded-secret prune, the helm-controller health gate
	// and the Kustomization list are independent duties — a failure
	// in one must never blind the others, so all run and their
	// errors join (nil+nil+nil → nil).
	// W9-CP2 — Kine bloat guard: cap superseded helm release secrets
	// per release. Independent of every signature below — it runs on
	// every sweep, healthy cluster or not, and BEFORE the per-HR
	// unlock pass so its cluster-wide list never masks the
	// release-scoped secret lists the unlock path performs.
	pruneErr := u.pruneSupersededSecrets(ctx)
	unlocked, unwedged := 0, 0
	var ctlErr error
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
			ctlErr = err
		case down:
			log.Info("SKIP: helm-controller pod CrashLoopBackOff — unlock/unwedge would not converge",
				"due", due, "stallDue", stallDue)
		default:
			unlocked = u.unlockDue(ctx, gvr, stuck, due, now)
			unwedged = u.unwedgeDue(ctx, gvr, stalled, stallDue, now)
		}
	}

	// The Kustomization list feeds both K-scanning healers below —
	// page it once per sweep instead of once per healer. NotFound
	// (pre-v1 flux CRDs) yields a nil list — the artifact healer's
	// HR half still runs, the immutable-Job healer has nothing to
	// scan; a real error is reported once for both consumers.
	kustomizations, err := u.listAllPages(ctx, u.dyn.Resource(fluxKustomizationGVR))
	var ksErr error
	if err != nil && !apierrors.IsNotFound(err) {
		ksErr = fmt.Errorf("list kustomizations: %w", err)
	}
	// C1 — stale-artifact source healing is independent of the
	// in-progress unlock path: it scans the same HR list plus
	// Kustomizations and must run on every sweep.
	u.healArtifactSources(ctx, list, kustomizations)
	// W8-GO1 — immutable-Job apply errors on Kustomizations: the
	// completed/failed Job blocking the apply is reaped so
	// kustomize-controller can recreate it.
	u.healImmutableJobs(ctx, kustomizations)
	log.Info("sweep done", "stuck", len(stuck), "due", len(due), "unlocked", unlocked,
		"stalled", len(stalled), "stallDue", len(stallDue), "unwedged", unwedged)
	return errors.Join(pruneErr, ctlErr, ksErr)
}

// listHelmReleases returns the HR list and the GVR that answered — v2
// first, v2beta2 when the v2 CRDs are absent. Pages at
// kube.DefaultListPageSize: HRs are unbounded cluster-wide and each item
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
	return kube.ListAllUnstructured(ctx, ri,
		metav1.ListOptions{Limit: kube.DefaultListPageSize})
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

// cleanFailedHookJobs deletes batchv1 Jobs in ns that carry the
// helm.sh/hook annotation and report JobFailed=True, with background
// propagation so their pods go with them. Only FAILED hook Jobs are
// targets — a Running one is a live workload, never reaped. Each
// deletion bumps metrics.HelmHookJobsCleanedTotal{namespace}. Errors
// are logged and skipped — hook cleanup never fails the caller.
func (u *helmReleaseUnlocker) cleanFailedHookJobs(ctx context.Context, ns string) {
	log := logf.FromContext(ctx)
	jobs, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.Jobs(u.cs, ns))
	if err != nil {
		log.Error(err, "helm-hook job list failed — hook cleanup skipped", "ns", ns)
		return
	}
	var targets []*batchv1.Job
	for i := range jobs {
		j := &jobs[i]
		if _, ok := j.Annotations["helm.sh/hook"]; !ok {
			continue // not a helm hook — never ours to reap
		}
		if !jobFailed(j) {
			continue // still running or succeeded — leave it
		}
		targets = append(targets, j)
	}
	reap.Sweep(ctx, log, targets, reap.Options[*batchv1.Job]{
		LogTarget: func(log logr.Logger, j *batchv1.Job) {
			log.Info("ACTION: delete failed helm-hook Job",
				"ns", ns, "job", j.Name)
		},
		Delete: func(ctx context.Context, j *batchv1.Job) error {
			if err := u.cs.BatchV1().Jobs(ns).Delete(ctx, j.Name,
				kube.UIDDeleteOptions(j.UID, metav1.DeletePropagationBackground)); err != nil {
				return err
			}
			metrics.HelmHookJobsCleanedTotal.WithLabelValues(ns).Inc()
			return nil
		},
		// Delete failures are logged and skipped, never IncError'd —
		// the sweep is best-effort residue cleanup riding a heal,
		// and the periodic wrapper already counts the run error.
		OnError: func(log logr.Logger, j *batchv1.Job, err error) {
			log.Error(err, "helm-hook job delete failed", "ns", ns, "job", j.Name)
		},
	})
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

// hrReleaseName mirrors upstream flux's GetReleaseName():
// spec.releaseName wins, then "<targetNamespace>-<name>" when a
// targetNamespace is set (flux prefixes the release name to keep
// same-named HRs in different target namespaces distinct), then the
// bare object name. It is the `name=` label helm puts on its release
// secrets.
func hrReleaseName(hr *unstructured.Unstructured) string {
	if n, _ := kube.NestedString(hr.Object, "spec", "releaseName"); n != "" {
		return n
	}
	if ns, _ := kube.NestedString(hr.Object, "spec", "targetNamespace"); ns != "" {
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
	if ns, _ := kube.NestedString(hr.Object, "spec", "targetNamespace"); ns != "" {
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
	if ns, _ := kube.NestedString(hr.Object, "spec", "storageNamespace"); ns != "" {
		return ns
	}
	return hr.GetNamespace()
}
