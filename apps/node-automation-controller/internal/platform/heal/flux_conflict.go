// flux_conflict.go — the SSA ping-pong defense (roadmap B8): a
// heal that writes desired-state fields on an object Flux also
// manages (helm-controller / kustomize-controller managers present
// in the object's managedFields — every HelmRelease/Kustomization-
// applied resource carries one) enters a Heal-Revert Loop when Git
// keeps reverting the write: the heal re-patches every sweep, Flux
// re-asserts Git, and the write storm lands in Kine forever.
//
// The defense mirrors the budget.go shape: the gate is consulted at
// the heal path's desired-state patch sites (webhook-config policy
// flips, OLM CSV spec restores); it records one sighting per patch
// under a stable object key, and once the SAME object has been
// re-patched fluxConflictLoopMax times inside fluxConflictWindow
// while a Flux manager is present, further patches SKIP — the loop
// is reported (hook → counter + log, alert GitOpsAutoHealConflict
// keys on the counter) so the drift is fixed at the Git source, and
// never fought field-for-field.
//
// Two deliberate non-gates:
//   - the gitops nudges (argocd-app refresh, HelmRelease retry reset,
//     Kustomization reconc poke) patch the Flux/ArgoCD control
//     objects THEMSELVES by design — poking reconcile is the heal,
//     not a field fight;
//   - bookkeeping annotation stamps (first-seen/persisted-cooldown
//     keys the sweep owns) — Flux never asserts annotations it does
//     not ship in Git, so those writes converge by construction.
//
// Wiring: opt-in and process-global like the budget — cmd/manager
// calls ConfigureFluxConflictLoop once at boot with the resolved
// NODE_AUTOMATION_HEAL_FLUX_CONFLICT_* knobs (a leaf package cannot
// read env, and "env inside a run" is a bug). max <= 0 installs a
// nil config: the gate compiles away to always-proceed.
package heal

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The Flux GitOps controllers' SSA field-manager names. Flux
// versions spell them bare or suffixed ("helm-controller",
// "kustomize-controller", release/revision suffixes), so the match
// is a contains on the lower-cased manager string.
const (
	fluxHelmManager      = "helm-controller"
	fluxKustomizeManager = "kustomize-controller"
)

// fluxConflictLoopMax is the Heal-Revert-Loop threshold (roadmap:
// the same object re-patched >= 3 times while Flux just reverted it)
// and fluxConflictWindow the sliding window those repeats count in —
// six 5m sweeps, long enough to span a Flux revert cycle, short
// enough that a converged object drops out inside half an hour.
const (
	fluxConflictLoopMax   = 3
	fluxConflictWindow    = 30 * time.Minute
	fluxConflictLedgerCap = 4096
)

// FluxConflictSignal is one Heal-Revert-Loop denial — the shape the
// boot-wired hook turns into the counter/log pair.
type FluxConflictSignal struct {
	// Kind/Namespace/Name identify the object the heal stopped
	// writing (Namespace empty for cluster-scoped kinds).
	Kind, Namespace, Name string
	// Manager is the Flux managedFields manager that owns fields on
	// the object ("helm-controller" / "kustomize-controller", as
	// spelled on the object).
	Manager string
	// Key is the ledger key the patch site uses ("kind/ns/name").
	Key string
}

// fluxConflictLoop holds the gate knobs plus the per-object patch
// ledger. ConfigureFluxConflictLoop is boot-only; the gate reads the
// fields without a lock (no hot reconfigure), the ledger locks —
// patch sites may run in concurrent module goroutines.
type fluxConflictLoop struct {
	max    int
	window time.Duration

	mu   sync.Mutex
	hits map[string][]time.Time // key → ascending stamp window
}

// defaultFluxConflicts is the process-global loop the gate consults;
// nil (ConfigureFluxConflictLoop(0, 0) / never configured) leaves
// the gate inert.
var defaultFluxConflicts atomic.Pointer[fluxConflictLoop]

// fluxConflictHook fires once per loop-denied patch — the bridge that
// lets internal/metrics count conflicts without platform importing
// the metrics package (depguard: platform is a leaf). cmd/manager
// wires it at boot; unset is a no-op.
var fluxConflictHook atomic.Pointer[func(FluxConflictSignal)]

// ConfigureFluxConflictLoop installs the process-global loop: max
// repeats per window per object before a patch site skips. max <= 0
// or window <= 0 clears it (the knob's documented "off" value).
func ConfigureFluxConflictLoop(max int, window time.Duration) {
	if max <= 0 || window <= 0 {
		defaultFluxConflicts.Store(nil)
		return
	}
	defaultFluxConflicts.Store(&fluxConflictLoop{
		max: max, window: window,
		hits: map[string][]time.Time{},
	})
}

// SetFluxConflictHook registers fn to run once per loop-denied patch.
// Passing nil clears it. Boot-time wiring only.
func SetFluxConflictHook(fn func(FluxConflictSignal)) {
	if fn == nil {
		fluxConflictHook.Store(nil)
		return
	}
	fluxConflictHook.Store(&fn)
}

// FluxManagerOf returns the Flux GitOps manager present in obj's
// managedFields ("helm-controller"/"kustomize-controller", as
// spelled on the object), or "" when none — the caller's signal the
// object is not Git-owned and the patch needs no loop defense.
func FluxManagerOf(obj metav1.Object) string {
	for _, mf := range obj.GetManagedFields() {
		m := strings.ToLower(mf.Manager)
		if strings.Contains(m, fluxHelmManager) ||
			strings.Contains(m, fluxKustomizeManager) {
			return mf.Manager
		}
	}
	return ""
}

// FluxPatchGate decides whether a desired-state heal patch may write
// obj: proceed=true when no Flux manager owns fields on the object,
// or when this key's in-window repeat count is still below the loop
// threshold. At the threshold the patch is the ping-pong half of a
// Heal-Revert Loop — proceed=false SKIPS the write (the conflict is
// reported, never fought) and the hook fires.
//
// The sighting is recorded ONLY on an allowed patch: a denied call
// must not re-arm the window. Recording on denial was the lockout
// bug — every skipped sweep appended a fresh stamp, so the 30m
// window never drained and the object stayed gated forever instead
// of releasing one window after Flux stopped reverting. With
// record-on-allow the count decays: max stamps inside window →
// deny without stamping → window expires → allow again.
//
// kind is the patch site's kind spelling for the signal ("webhook
// config", "csv", ...); key the site's stable object key. now comes
// from the caller's clock seam, like every heal gate.
//
// Emergency writes — the webhookguard Fail->Ignore bootstrap flip —
// do NOT call this gate at all: a Git-owned webhook config on a
// cluster that cannot boot is not a drift fight, and gating it would
// deadlock bring-up (Git cannot fix drift on a cluster it locks out
// of existence).
func FluxPatchGate(kind string, obj metav1.Object, key string,
	now time.Time) bool {

	loop := defaultFluxConflicts.Load()
	if loop == nil {
		return true // knob off — gate inert, behavior unchanged
	}
	manager := FluxManagerOf(obj)
	if manager == "" {
		loop.forget(key) // not Git-owned — drop any stale loop history
		return true
	}
	// Check-and-record under a single lock: this call would be sighting
	// #(count+1) — deny when it reaches the threshold, leaving the window
	// untouched (max=3 denies the third repeat).
	if !loop.allow(key, now) {
		if fn := fluxConflictHook.Load(); fn != nil && *fn != nil {
			(*fn)(FluxConflictSignal{
				Kind: kind, Namespace: obj.GetNamespace(),
				Name: obj.GetName(), Manager: manager, Key: key,
			})
		}
		return false
	}
	return true
}

// allow atomically checks whether key has room in its sliding window and,
// when allowed, appends now. A denied call leaves the window untouched.
// Stamps expire oldest-first (append order); once the key set passes the cap,
// expired keys are swept so pathological fleet-wide conflict storms stay bounded.
func (l *fluxConflictLoop) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := now.Add(-l.window)
	keep := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	if len(keep)+1 >= l.max {
		if len(keep) == 0 {
			delete(l.hits, key)
		} else {
			l.hits[key] = keep
		}
		return false
	}
	l.hits[key] = append(keep, now)
	// Key-set hygiene: past the cap, drop every key whose newest
	// stamp already left the window — an expired key can never
	// contribute to a loop count again, so holding it is pure leak.
	if len(l.hits) > fluxConflictLedgerCap {
		for k, ts := range l.hits {
			if len(ts) == 0 || !ts[len(ts)-1].After(cut) {
				delete(l.hits, k)
			}
		}
	}
	return true
}

// forget drops key's loop history — a site whose object lost its
// Flux manager (GitOps moved elsewhere) must not carry a stale count.
func (l *fluxConflictLoop) forget(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.hits, key)
}
