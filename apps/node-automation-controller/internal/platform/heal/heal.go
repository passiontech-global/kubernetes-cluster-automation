// heal.go — the shared preamble + actuation helpers implementing the
// sequence doc.go describes, split at the points call sites differ:
// AllowedV runs the preamble (cooldown + mutex), OldestRunningPod is
// the shared "bounce the operator" target pick, DeletePod is the raw
// delete + stamp actuation and EvictPod is its PDB-respecting
// policy/v1-Eviction sibling. Modules that pick a different target (a
// leader pod, a wedged consumer) simply skip OldestRunningPod.
package heal

import (
	"context"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// AllowedV runs the shared preamble every pod-kill heal repeats
// before picking its target: per-key cooldown on the heals ledger,
// then the maintenance mutex (kube.MaintenanceActive — fail closed:
// unverifiable counts as held). Returns proceed=true when the caller
// may proceed to target selection + delete.
//
// The second return distinguishes WHY a defer happened:
// unverifiable=true means the maintenance check itself errored —
// the caller IncErrors its own queue (this package never touches
// metrics, so the signal would otherwise be lost). Cooldown and
// held-mutex defers are normal operation and return (false, false).
// The defer reason is logged here with the heal's key; callers log
// only their own ACTION/defer wording.
//
// v is the shared maintenance verdict: loops that run the preamble
// once per target pass the module's Verdict field so the whole sweep
// pays a single mutex evaluation instead of three API reads per pod.
// A nil v means "no memoization" — the mutex evaluates fresh every
// call (the one-shot-heal shape).
//
// A nil heals pointer skips the cooldown check entirely — heals
// that persist their stamp on the object itself (the passiontech.dev/last-*
// annotations read via kube.AnnoTime, see persisted.go) pass nil and
// keep only the mutex gate.
func AllowedV(ctx context.Context, log logr.Logger, v *kube.Verdict,
	cs kubernetes.Interface, dyn dynamic.Interface,
	heals *state.CooldownSet, key string, cooldown time.Duration,
	now time.Time) (proceed bool, unverifiable bool) {

	if heals != nil && heals.CooledDown(key, cooldown, now) {
		log.Info("skip heal: inside cooldown", "target", key)
		return false, false
	}
	if v == nil {
		// No memoization — a throwaway zero Verdict evaluates fresh
		// (an unstamped verdict is always expired).
		v = &kube.Verdict{}
	}
	held, why, err := v.Active(ctx, cs, dyn, now)
	if err != nil {
		log.Info("WARN: maintenance check unverifiable — "+
			"heal deferred (fail closed)", "target", key, "error", err)
		return false, true
	}
	if held {
		log.Info("maintenance in progress — heal deferred",
			"target", key, "why", why)
		return false, false
	}
	// The global heal budget is the last gate: a grant is consumed
	// only once cooldown AND mutex already passed, so a spent window
	// defers heals that would otherwise have fired — fail closed,
	// exactly like a held mutex (see budget.go for why the aggregate
	// ceiling exists and why the deny is (false,false), not
	// unverifiable: an exhausted budget is normal operation, not a
	// check the caller should IncError). The grant this gate hands
	// out is refunded by the GATE OWNER — exactly once, and only
	// when no delete/patch mutation executed (see RefundGrant in
	// budget.go). Low-level helpers like DeletePod/EvictPod cannot
	// refund: they cannot tell whether the caller paid a grant at
	// all, so refunding inside them double-credits batch-gated
	// callers.
	if !budgetGate(now) {
		log.Info("heal budget exhausted — heal deferred",
			"target", key)
		return false, false
	}
	return true, false
}

// DeletePod issues the UID-preconditioned delete the heals share —
// kube.UIDDeleteOptions with no propagation policy (the apiserver
// default, matching every reference implementation: Preconditions{UID}
// only) — and stamps the heals ledger ONLY when the delete is
// delivered: a failed delete leaves the target alive, and stamping
// anyway would let one transient error suppress the heal for the
// whole cooldown window.
//
// Returns (deleted, err): any API failure is (false, err) — the
// caller IncErrors its own queue and logs err in its own wording
// (each module phrases the failure with its own target context).
// A nil heals pointer skips the stamp, mirroring AllowedV's
// nil-ledger contract. Callers whose target pod may sit under a
// PodDisruptionBudget use EvictPod instead — a raw Delete bypasses
// every PDB.
//
// This helper NEVER refunds a budget grant: it cannot know whether
// the caller's AllowedV/Gate consumed one. A gate owner that gets
// (false, nil) — L1 hold or quorum-reservation deferral, no
// mutation executed — must RefundGrant(now) itself, exactly once;
// a (false, err) means the delete was attempted and the grant is
// spent.
func DeletePod(ctx context.Context, cs kubernetes.Interface,
	heals *state.CooldownSet, key string, pod *corev1.Pod,
	now time.Time) (bool, error) {

	// L1↔L3 yield runs BEFORE the disruption reservation: a pod
	// inside a node-host-agent self-heal window is deferred without
	// burning the sweep's one-disruption slot. The caller's fleet
	// grant (if AllowedV consumed one) goes back at the GATE — this
	// helper cannot see it.
	hold, err := localRemediationHold(ctx, cs, pod, now)
	if err != nil {
		return false, err
	}
	if hold {
		return false, nil
	}
	// Quorum guard: inside a sweep the overlay grants each workload
	// controller ONE disruption slot per sweep — a sibling check
	// that already reserved this owner must not spend a second
	// delete and take a 2-replica workload to zero (cooldowns are
	// per-CHECK keys, so without the shared slot two checks each
	// pass their own gate and each delete). Denial is a deferral:
	// (false, nil) — no API call, no ledger stamp, and the next
	// sweep retries once the sibling's cooldown has lapsed. Outside
	// a sweep the reservation always succeeds (no overlay, no
	// sharing). The deferral also hands back any grant the
	// caller's AllowedV preamble consumed — at the gate, same
	// contract EvictPodV applies to a refused eviction.
	if !kube.TryReserveWorkloadDisruption(ctx, pod) {
		return false, nil
	}
	if err := cs.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name,
		kube.UIDDeleteOptions(pod.UID, "")); err != nil {
		return false, err
	}
	// Tombstone the UID so later census reads this sweep hide the
	// pod without a pod-list invalidation (the O(1) half of the
	// sweep overlay — MarkPodDeleted is a no-op outside a sweep).
	kube.MarkPodDeleted(ctx, pod.UID)
	if heals != nil {
		heals.Stamp(key, now)
	}
	return true, nil
}

// EvictPod is DeletePod's PDB-respecting sibling: the same
// UID-preconditioned kill (kube.UIDDeleteOptions, apiserver-default
// propagation) issued through the policy/v1 Eviction API instead of a
// raw Delete — a raw Delete bypasses every PodDisruptionBudget and
// could take a workload's last Ready replica, which is exactly the
// contract the unmeshed-pod-auditor path already runs on. The
// apiserver enforces the PDB and consumes a disruption slot
// atomically; the stamp contract is identical to DeletePod (ledger
// stamped on a DELIVERED eviction only; nil heals skips it).
//
// Returns (evicted, refused, err). refused=true means NO heal was
// delivered and NO mutation executed — it covers every clean
// deferral: the L1 local-remediation hold, the sweep overlay's
// quorum-reservation denial, and HTTP 429 (a PDB with
// disruptionsAllowed==0). That is a DEFERRAL, not a failure (err is
// nil): the workload is already at its replica floor or another
// actor owns the window, so the caller keeps the pod, counts no
// error and stamps no ledger — the next sweep retries once the
// window frees up. Any other API failure is (false, false, err) —
// the caller IncErrors its own queue and logs err in its own
// wording. Budget-gated callers (AllowedV preamble consumed the
// grant) should call EvictPodV instead — the pairing refunds the
// grant on ANY refused=true outcome.
//
// This helper NEVER refunds a budget grant — same contract as
// DeletePod: it cannot know whether the caller's gate consumed one,
// and a refund here would double-credit callers that refund at
// their own gate (the pre-fix double-refund: EvictPod refunded the
// hold/quorum deferral AND EvictPodV refunded the same grant again
// on refused=true, eating a sibling gate's stamp at the same `now`).
// A gate owner that gets refused=true must RefundGrant(now) itself,
// exactly once; an evicted=true or err!=nil outcome keeps the grant.
func EvictPod(ctx context.Context, cs kubernetes.Interface,
	heals *state.CooldownSet, key string, pod *corev1.Pod,
	now time.Time) (evicted bool, refused bool, err error) {

	// Same L1↔L3 yield as DeletePod — deferred BEFORE the
	// disruption reservation so the slot stays free, reported as
	// refused=true so every caller's existing "deferral, retry
	// later" path applies (and EvictPodV refunds the grant, exactly
	// like a real 429: no heal was delivered).
	hold, err := localRemediationHold(ctx, cs, pod, now)
	if err != nil {
		return false, false, err
	}
	if hold {
		return false, true, nil
	}
	// Same quorum guard as DeletePod: a sibling check that already
	// reserved this workload's one-disruption slot this sweep makes
	// this eviction a deferral — reported as refused=true so every
	// caller's existing "PDB said no, retry later" path applies
	// unchanged (EvictPodV refunds the grant it consumed, exactly
	// like a real 429: no heal was delivered).
	if !kube.TryReserveWorkloadDisruption(ctx, pod) {
		return false, true, nil
	}
	deleteOpts := kube.UIDDeleteOptions(pod.UID, "")
	err = cs.CoreV1().Pods(pod.Namespace).EvictV1(ctx, &policyv1.Eviction{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pod.Name,
			Namespace: pod.Namespace,
		},
		DeleteOptions: &deleteOpts,
	})
	if apierrors.IsTooManyRequests(err) {
		// PDB refusal — a deferral, never an error.
		return false, true, nil
	}
	if err != nil {
		return false, false, err
	}
	// Tombstone the UID — an accepted eviction is a delivered kill
	// for census purposes even while the pod finishes terminating.
	kube.MarkPodDeleted(ctx, pod.UID)
	if heals != nil {
		heals.Stamp(key, now)
	}
	return true, false, nil
}

// EvictPodV is the budget-safe EvictPod: the full preamble→actuation
// pair every budget-gated eviction repeats — AllowedV (per-key
// cooldown + maintenance mutex + the fleet-wide heal budget grant)
// and then the PDB-respecting eviction — folded into ONE call so a
// caller cannot consume the grant in one function and spend it in
// another. The pairing closes a burn path the split shape leaves
// open: the budget is deliberately a grant-time counter (see
// budget.go), but a refused eviction delivers no heal for the
// grant it consumed — refused=true covers the PDB 429, the L1
// local-remediation hold and the sweep quorum denial alike — so a
// backend wedged behind a PodDisruptionBudget at its replica floor
// would burn one fleet grant per sweep forever (budget: 10/5min)
// and starve every other heal-gated module. On refused=true this
// wrapper hands the grant back EXACTLY ONCE (budgetRefund —
// Budget.Refund un-consumes the window's stamp symmetrically),
// while every other contract is unchanged: refused stays a
// DEFERRAL, never an error (err nil, no IncError owed, no ledger
// stamp, the pod stays); a DELIVERED eviction keeps its grant AND
// stamps the cooldown exactly as EvictPod always did — one grant
// per delivered heal remains the accounting (the linkerd
// endpoint-sync pin holds). An API failure (err != nil) does NOT
// refund: the eviction was attempted and failed, which is the
// documented "a grant whose delete then fails simply spent a cheap
// token" case.
//
// Returns AllowedV's pair followed by EvictPod's triple: proceed=false
// is a defer the preamble already logged (cooldown, held mutex, spent
// budget — nothing consumed, triple all-zero); unverifiable=true is
// fail-closed and the CALLER IncErrors its queue (platform must not
// import internal/metrics). v/heals/key/cooldown pass through to
// AllowedV unchanged (nil v = fresh mutex evaluation, nil heals = no
// cooldown gate — a manual-stamp caller pairs this with its own
// Stamp-on-delivered).
func EvictPodV(ctx context.Context, log logr.Logger, v *kube.Verdict,
	cs kubernetes.Interface, dyn dynamic.Interface,
	heals *state.CooldownSet, key string, cooldown time.Duration,
	pod *corev1.Pod, now time.Time) (proceed, unverifiable bool,
	evicted, refused bool, err error) {

	proceed, unverifiable = AllowedV(ctx, log, v, cs, dyn,
		heals, key, cooldown, now)
	if !proceed {
		return proceed, unverifiable, false, false, nil
	}
	evicted, refused, err = EvictPod(ctx, cs, heals, key, pod, now)
	if refused {
		// No heal delivered and no mutation executed — the grant
		// goes back so a PDB-hung (or L1-held, or quorum-denied)
		// target cannot starve the rest of the fleet. Exactly once:
		// EvictPod itself never refunds, so this is the single
		// hand-back for the grant AllowedV consumed above.
		budgetRefund(now)
	}
	return proceed, unverifiable, evicted, refused, err
}

// OldestRunningPod returns the oldest Running, non-terminating pod
// whose name matches any of prefixes as prefix+"-" — the
// cluster-wide operator-pod pick several heals repeat (datastore's
// db-operator bounce, the connect heal). The trailing dash is
// deliberate: operator pods are <deployment>-<rs-hash>-<suffix>, so
// requiring it keeps prefix "pxc-operator" from also swallowing a
// "pxc-operator2-..." pod. Returns nil when nothing qualifies —
// the caller logs "no target" in its own wording. The returned
// pointer aliases the input slice; do not mutate it.
func OldestRunningPod(pods []corev1.Pod, prefixes ...string) *corev1.Pod {
	var oldest *corev1.Pod
	for i := range pods {
		p := &pods[i]
		if p.Status.Phase != corev1.PodRunning || p.DeletionTimestamp != nil {
			continue
		}
		matched := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(p.Name, prefix+"-") {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if oldest == nil || p.CreationTimestamp.Before(&oldest.CreationTimestamp) {
			oldest = p
		}
	}
	return oldest
}

// Gate runs AllowedV's mutex+budget shape — the nil-heals-ledger,
// zero-cooldown call every maintenance-gated module repeats — so the
// WHY-comment for that preamble lives once, here, instead of being
// re-pasted per module. It returns AllowedV's pair unchanged:
// proceed=false means defer (held mutex or spent budget) and the
// caller just returns; unverifiable=true is fail-closed and the
// CALLER IncErrors its queue — platform must not import
// internal/metrics (depguard leaf rule), and every gate user is a
// domain module that already owns that counter. Callers that can run
// with a nil dyn client keep their `dyn != nil` guard at the call
// site (nil dyn there means "gate skipped, proceed", not
// "deferred").
func Gate(ctx context.Context, log logr.Logger, v *kube.Verdict,
	cs kubernetes.Interface, dyn dynamic.Interface,
	key string, now time.Time) (proceed, unverifiable bool) {
	return AllowedV(ctx, log, v, cs, dyn, nil, key, 0, now)
}
