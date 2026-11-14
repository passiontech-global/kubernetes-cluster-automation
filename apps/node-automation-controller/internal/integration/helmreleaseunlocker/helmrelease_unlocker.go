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
//
// File layout: this file holds the module contract, the
// unlocker/stall/ledger types and the sweep pipeline (run + Setup);
// helmrelease_list.go the HR list/paging helpers and the
// helm-controller health gate, helm_hook_jobs.go the failed helm-hook
// Job cleanup, helmrelease_identity.go the release-name/namespace
// resolvers; pending_secret_unlock.go the pending-secret unlock
// operation, superseded_secret_prune.go the superseded-secret prune,
// stall_plan.go + helm_stall_unwedge.go + stalled_deployment.go the
// stalled-rollout unwedge, flux_source_nudge.go the C1 source
// healer, immutable_job_healer.go the immutable-Job healer.
package helmreleaseunlocker

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/maintenance"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	helmUnlockInterval = 10 * time.Minute
	helmStuckThreshold = 30 * time.Minute // first-seen window before acting
	helmUnlockCooldown = 24 * time.Hour   // max 1 unlock/HR inside this window
	helmSecretType     = "helm.sh/release.v1"
	// helmReleaseNameLabel is the label helm 3 stamps on EVERY
	// rendered resource — hook Jobs included — naming the release
	// that owns it. Hook Jobs without it carry no release
	// attribution and are never reaped (they may be another
	// release's residue an operator is keeping for debugging).
	helmReleaseNameLabel = "meta.helm.sh/release-name"
	helmControllerNS     = "flux-system"
	helmControllerSel    = "app.kubernetes.io/name=helm-controller"
	fluxReconcileAnno    = kube.AnnoFluxRequestedAt
)

// helmReleaseGVRs tried in order — v2 on current flux, v2beta2 on
// installs that have not bumped the CRDs yet. The first listable GVR
// wins and is reused for the requestedAt patches.
var helmReleaseGVRs = kube.HelmReleaseGVRs

type helmReleaseUnlocker struct {
	cs   kubernetes.Interface
	dyn  dynamic.Interface
	meta metadata.Interface
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name and every IncError label
	// come from one place.
	queue string
	// now is the clock seam — tests pin it so the first-seen
	// windows and the 24h cooldowns are deterministic. nil →
	// time.Now.
	now shared.Clock
	// verdict is the shared maintenance-mutex memo the unwedge
	// pass folds into heal.Gate — one evaluation serves every
	// due HR in the sweep instead of one API-read bundle each.
	verdict *maintenance.Verdict

	// One sub-struct per healer duty so run() prunes/resets each
	// duty's ledgers as one block. Every ledger type is zero-value
	// ready, so literal-constructed fixtures keep working unchanged.
	pending      pendingState
	stall        stallState
	immutableJob immutableJobState
	// fluxSources tracks every FluxSourceReconcilesTriggeredTotal
	// series this process has emitted (kind/ns/name keys): counter
	// children are never collected by prometheus/client_golang, so
	// this set is the delete half of the series lifecycle — the
	// sweep prunes entries whose source no consumer resolves to
	// anymore (pruneFluxSourceSeries). Zero-value ready like the
	// ledgers above.
	fluxSources state.SeenSet
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
// attempts the helm-stall-unwedge retry-cycle cap. CooldownSets are
// zero-value ready and bounded per sweep — Run PruneExpired's each
// at the cooldown it serves, so vanished or aged-out HR entries
// cannot accumulate.
type stallState struct {
	enabled   bool
	firstSeen state.FirstSeenLedger
	unwedged  state.CooldownSet
	alerted   state.CooldownSet
	attempts  map[string]*stallAttempt
}

// immutableJobState carries the immutable-job-heal immutable-Job heal ledger:
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
				verdict: d.Maintenance,
				cs:      d.CS,
				dyn:     d.Dyn,
				meta:    d.Meta,
				queue:   d.Name,
				now:     shared.SystemClock,
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
	// stallAttempts keys on the same decommissionable HR names but
	// carries no stamps to age out — a revision change already resets
	// the entry in unwedgeDue, so a vanished HR is the only dead
	// weight: drop it by presence (deleting during range is safe).
	for key := range u.stall.attempts {
		if !present[key] {
			delete(u.stall.attempts, key)
		}
	}

	var due []string
	for key := range stuck {
		if stuckFor, _ := u.pending.firstSeen.Seen(key, now); stuckFor >= helmStuckThreshold {
			due = append(due, key)
		}
	}
	slices.Sort(due)
	var stallDue []string
	for key := range stalled {
		if stalledFor, _ := u.stall.firstSeen.Seen(key, now); stalledFor >= helmStuckThreshold {
			stallDue = append(stallDue, key)
		}
	}
	slices.Sort(stallDue)

	// The superseded-secret prune, the helm-controller health gate
	// and the Kustomization list are independent duties — a failure
	// in one must never blind the others, so all run and their
	// errors join (nil+nil+nil → nil).
	// kine-bloat-guard — Kine bloat guard: cap superseded helm release secrets
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
	if err != nil && !kube.IsCRDAbsent(err) {
		ksErr = fmt.Errorf("list kustomizations: %w", err)
	}
	// C1 — stale-artifact source healing is independent of the
	// in-progress unlock path: it scans the same HR list plus
	// Kustomizations and must run on every sweep.
	u.healArtifactSources(ctx, list, kustomizations)
	// The FluxSourceReconcilesTriggeredTotal prune rides the same
	// consumer lists the heal just used. It runs only on a complete
	// sweep: a Kustomization LIST error leaves the inventory half-
	// blind, and pruning then would delete series of sources that
	// still have Kustomization consumers — carry-forward keeps the
	// previous set and the next whole sweep decides. NotFound → nil
	// (pre-v1 flux) is a complete-empty answer, not an error.
	if ksErr == nil {
		u.pruneFluxSourceSeries(list, kustomizations)
	}
	// immutable-job-heal — immutable-Job apply errors on Kustomizations: the
	// completed/failed Job blocking the apply is reaped so
	// kustomize-controller can recreate it.
	u.healImmutableJobs(ctx, kustomizations)
	log.Info("sweep done", "stuck", len(stuck), "due", len(due), "unlocked", unlocked,
		"stalled", len(stalled), "stallDue", len(stallDue), "unwedged", unwedged)
	return errors.Join(pruneErr, ctlErr, ksErr)
}
