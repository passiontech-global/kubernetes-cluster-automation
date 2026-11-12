// budget.go — the fleet-wide heal budget: a sliding-window grant
// limiter consulted inside AllowedV so EVERY heal-gated module
// shares one aggregate ceiling on destructive action.
//
// The per-target cooldown caps how often ONE workload is bounced;
// nothing capped how many DIFFERENT targets the whole controller
// could heal per unit time — a fleet-wide signature (a bad rollout,
// an apiserver flap misread as a wedge, a check bug) could delete a
// pod in every namespace within a single sweep. The budget is the
// aggregate fail-safe: past max grants in window, AllowedV defers
// exactly like a held maintenance mutex — fail closed, no delete.
// The per-target gates are unchanged; the budget only throttles the
// aggregate.
//
// It is deliberately a grant-time counter (one token per AllowedV
// "proceed"), not a delivered-delete counter: the budget bounds how
// many heals the controller may UNLOCK per window — a grant whose
// delete then fails simply spent a cheap token.
//
// The per-target non-convergent circuit breaker below is the other
// half of the same contract: the aggregate budget bounds the FLEET's
// heal rate, the breaker bounds how many times ONE
// (module,targetKey) may be remediated without the target ever
// converging — the repeated-taint-on-a-dead-node churn shape, where
// every sweep re-fires the same fix on the same node.
//
// Wiring: the budget is opt-in and process-global — cmd/manager
// calls ConfigureBudget once at boot with the resolved
// NODE_AUTOMATION_HEAL_BUDGET_* knobs (a leaf package cannot read
// env, and "env inside a run" is a bug — Setup-time resolution is
// the contract). max <= 0 installs a nil budget: the gate compiles
// away to the old behavior.
package heal

import (
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Budget is a sliding-window grant limiter: Allow(now) consumes one
// grant while fewer than max grants were consumed inside the
// trailing window. Mutex-guarded — reconcilers may call AllowedV
// from more than one goroutine even though sweeps are serial.
type Budget struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	grants []time.Time // grant stamps inside the window, ascending
}

// NewBudget returns a limiter granting at most max heals per window.
func NewBudget(max int, window time.Duration) *Budget {
	return &Budget{max: max, window: window}
}

// Allow consumes a grant at now and reports whether the budget had
// room. Stamps older than window expire out of the count first.
func (b *Budget) Allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	cut := now.Add(-b.window)
	// Grants append in time order, so the expired prefix drops with
	// one slice trim — a full scan only on clock skew.
	if i := slices.IndexFunc(b.grants, func(t time.Time) bool {
		return t.After(cut)
	}); i > 0 {
		b.grants = append([]time.Time{}, b.grants[i:]...)
	} else if i < 0 {
		b.grants = b.grants[:0]
	}
	if len(b.grants) >= b.max {
		return false
	}
	b.grants = append(b.grants, now)
	return true
}

// Refund returns the grant Allow consumed at now — the refused-eviction
// counterpart of the gate. The budget is deliberately a grant-time
// counter (a grant is spent when AllowedV unlocks a heal, before the
// actuation), but a PDB refusal delivers no heal for the grant it
// consumed, so the refused path hands the stamp back. Un-consuming is
// symmetric: exactly ONE stamp Equal(now) is removed — the one Allow
// appended — restoring the window's remaining grant count to its
// pre-Allow value and never below the grants actually consumed (a
// refund for an instant that consumed nothing — never granted,
// already refunded, or already expired out of the window — finds no
// stamp and is a no-op, so it can never eat a sibling grant). The
// removal is by value, not a tail trim, so an interleaved later grant
// (another module's Allow landing between this Allow and this
// Refund) keeps the slice's ascending order.
func (b *Budget) Refund(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := len(b.grants) - 1; i >= 0; i-- {
		if b.grants[i].Equal(now) {
			b.grants = append(b.grants[:i], b.grants[i+1:]...)
			return
		}
	}
}

// defaultBudget is the process-wide limiter AllowedV consults; nil
// disables the gate. Written once at boot by ConfigureBudget, read
// per AllowedV call — a plain pointer is fine (no hot reconfigure),
// but atomic keeps the race detector honest if a test ever swaps it.
var defaultBudget atomic.Pointer[Budget]

// budgetExhaustedHook fires once per budget-denied grant — the
// bridge that lets internal/metrics count denials without platform
// importing the metrics package (depguard: platform is a leaf).
// cmd/manager wires it to the counter at boot; unset is a no-op.
var budgetExhaustedHook atomic.Pointer[func()]

// ConfigureBudget installs the process-global limiter: max grants
// per window shared by every AllowedV caller. max <= 0 or window <= 0
// clears the budget (the knob's documented "off" value).
func ConfigureBudget(max int, window time.Duration) {
	if max <= 0 || window <= 0 {
		defaultBudget.Store(nil)
		return
	}
	defaultBudget.Store(NewBudget(max, window))
}

// SetBudgetExhaustedHook registers fn to run once per budget-denied
// AllowedV grant. Passing nil clears it. Boot-time wiring only —
// callers do not swap hooks mid-sweep.
func SetBudgetExhaustedHook(fn func()) {
	budgetExhaustedHook.Store(&fn)
}

// budgetGate runs the global budget check for AllowedV: false means
// the aggregate window is spent and the caller must defer.
func budgetGate(now time.Time) bool {
	b := defaultBudget.Load()
	if b == nil {
		return true // no budget configured — gate is inert
	}
	if b.Allow(now) {
		return true
	}
	if h := budgetExhaustedHook.Load(); h != nil && *h != nil {
		(*h)()
	}
	return false
}

// budgetRefund hands one grant back to the process-global budget —
// the no-heal-delivered counterpart of budgetGate. Callers: EvictPodV
// on ANY refused=true outcome (PDB 429, L1 hold, quorum denial — all
// clean deferrals that executed no mutation). No budget configured
// consumed nothing, so it is a no-op; a refund fires no hook — only
// denials are metered.
func budgetRefund(now time.Time) {
	if b := defaultBudget.Load(); b != nil {
		b.Refund(now)
	}
}

// RefundGrant is budgetRefund's exported face for GATE-OWNING
// callers — the functions that consumed a grant via heal.Gate /
// AllowedV / HealAllowed and then ran their own actuation loop.
//
// THE CONTRACT — exactly once per gate call, and only when NO
// delete/patch mutation was executed:
//
//   - The gate consumed ONE grant for the whole call. Refund at
//     most once per gate call — never once per skipped target in a
//     batch (BounceOperatorPod's per-target deletes share the one
//     grant; refunding per deferral would over-credit the window).
//   - Refund only when the pass delivered nothing AND attempted
//     nothing: every target cleanly deferred (L1 hold, quorum
//     denial, sibling guard) means the grant bought no heal.
//   - Do NOT refund when a mutation was attempted and failed —
//     "a grant whose delete then fails simply spent a cheap token"
//     (budget.go header). An attempted write is not a free retry.
//   - Do NOT refund inside low-level helpers (heal.DeletePod /
//     heal.EvictPod): they cannot know whether the caller's gate
//     charged the budget at all — a bare DeletePod call may follow
//     no gate, and a gated caller that also refunds would
//     double-credit. The pre-fix shape did exactly that (the helper
//     refunded the hold/quorum deferral AND the V-wrapper refunded
//     again on refused=true), which could eat a SIBLING gate's
//     grant stamped at the same `now`.
//
// A refund for an instant that consumed nothing finds no stamp and
// is itself a no-op, so an extra call cannot push the window
// negative — but the exactly-once rule still stands: relying on the
// no-op makes correctness depend on stamp timing, not contract.
func RefundGrant(now time.Time) {
	budgetRefund(now)
}

// ---------------------------------------------------------------------------
// Per-target non-convergent circuit breaker.
//
// The aggregate budget says "the fleet may heal N times per window";
// nothing said "the same target may not be remediated forever". A
// module whose fix never converges (kubelet still dead next sweep,
// pods keep landing back on the partitioned node, steal latch
// flapping) would re-fire the same node patch every cycle until the
// aggregate budget starved everyone else. The breaker bounds ONE
// (module,targetKey) instead: past limit grants inside the sliding
// window the circuit opens and further TryAcquireTarget calls are
// rejected with reason target_non_convergent_circuit_open — the
// caller defers the action exactly like a held mutex, never errors.
//
// History for a target expires window after its last grant
// (rejections do NOT extend it — the breaker rate-limits, it does
// not punish retrying), and RecordTargetHealthy clears it outright:
// the recovery-side call — probe ok, partition healed, steal cleared
// — is the target's own evidence the episode converged.
//
// Boot wiring mirrors the aggregate budget: cmd/manager calls
// ConfigureTargetBreaker once with the package defaults, and the
// open transition is bridged out through SetTargetCircuitOpenHook
// (platform is a depguard leaf — no metrics or clientset access
// here), where the counter increments and the RemediationCircuit-
// BreakerOpen Warning event lands on the target Node.
// ---------------------------------------------------------------------------

// TargetBreakerLimit / TargetBreakerWindow are the boot defaults: a
// target healed 3 times inside the trailing 3h opens its circuit.
// Pinned by budget_test.go — do not retune silently.
const (
	TargetBreakerLimit  = 3
	TargetBreakerWindow = 3 * time.Hour
)

// ReasonTargetNonConvergentCircuitOpen is the defer reason
// TryAcquireTarget reports once a target's circuit is open — the
// string the modules log and the event note carries, so dashboards
// can grep one spelling.
const ReasonTargetNonConvergentCircuitOpen = "target_non_convergent_circuit_open"

// breakerTarget splits (module,targetKey) — the map key the breaker
// history is filed under. Modules are isolated by construction: the
// kubelet reaper's taints never consume the evictor's grants.
type breakerTarget struct{ module, target string }

// targetHistory is one target's ledger: the grant stamps inside the
// window (ascending — same append order Budget.Allow relies on) and
// whether the circuit is currently announced open. open latches only
// for the announcement — a granted request or a full expiry resets
// it, so one episode emits exactly one open notification.
type targetHistory struct {
	stamps []time.Time
	open   bool
}

// TargetBreaker is the per-(module,targetKey) sliding-window circuit
// breaker. Mutex-guarded: module sweeps run on shared.AddPeriodic
// serially per module, but the process-global instance is consulted
// from several module goroutines.
type TargetBreaker struct {
	mu         sync.Mutex
	limit      int
	window     time.Duration
	targets    map[breakerTarget]*targetHistory
	openHook   func(module, target, reason string)
	forgetHook func(module, target string)
}

// NewTargetBreaker returns a breaker granting at most limit grants
// per (module,targetKey) inside the trailing window.
func NewTargetBreaker(limit int, window time.Duration) *TargetBreaker {
	return &TargetBreaker{
		limit:   limit,
		window:  window,
		targets: make(map[breakerTarget]*targetHistory),
	}
}

// SetOpenHook registers fn to run once per open transition — the
// bridge that lets cmd/manager count the episode and stamp the
// Warning event on the target Node without platform importing the
// metrics package or holding a clientset. Passing nil clears it.
// Boot-time wiring only — callers do not swap hooks mid-sweep.
func (b *TargetBreaker) SetOpenHook(fn func(module, target, reason string)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.openHook = fn
}

// SetForgetHook registers fn to run once per FORGET — the breaker
// dropping a (module,targetKey)'s history outright. Both fire sites
// mean the breaker no longer holds state for the target, so nothing
// it announced is live anymore: the expiry GC inside TryAcquireTarget
// (a fully expired window closes and deletes the entry) and
// RecordTargetHealthy's convergence clear. The bridge lets
// cmd/manager prune the HealTargetCircuitBrokenTotal series the open
// hook emitted, bounding the vec's cardinality to targets the
// breaker still tracks instead of the process lifetime (platform is
// a depguard leaf — no metrics access here). Passing nil clears it.
// Boot-time wiring only — callers do not swap hooks mid-sweep.
//
// Ordering: open and forget hooks fire OUTSIDE the mutex with no
// cross-key sequencing, so a forget observed by its sink before a
// concurrent open's emit lands can leave that one series alive until
// the target's next episode. Reaching that needs the same
// (module,target) touched from two goroutines AND the open-firing
// goroutine stalled a full breaker window between its critical
// section and its hook — accepted as metric-hygiene-only residual
// (never heal correctness); serializing via the lock would pin hook
// sinks (including network-emitting ones) to breaker latency.
func (b *TargetBreaker) SetForgetHook(fn func(module, target string)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.forgetHook = fn
}

// TryAcquireTarget records one node-action grant for
// (module,targetKey) at now and reports whether it was allowed. When
// limit grants already sit inside the trailing window the request is
// rejected with ReasonTargetNonConvergentCircuitOpen — the caller
// defers its action. The open transition fires the hook once per
// episode (rejections while already open stay silent, so the event
// lands once per stuck target, not once per sweep); a granted
// request closes the circuit again. The hook runs OUTSIDE the mutex.
func (b *TargetBreaker) TryAcquireTarget(module, targetKey string, now time.Time) (bool, string) {
	b.mu.Lock()
	cut := now.Add(-b.window)
	k := breakerTarget{module: module, target: targetKey}
	h := b.targets[k]
	// forgotten collects every (module,target) whose history this call
	// dropped — the inline expiry GC below and the bulk prune — so the
	// forget hook can fire ONCE per dropped entry outside the mutex.
	var forgotten []breakerTarget
	if h != nil {
		// Same ascending-prefix trim as Budget.Allow: grants append
		// in time order, so the expired prefix drops with one slice
		// trim — a full scan only on clock skew. A fully expired
		// history closes and GCs the entry: the circuit resets.
		if i := slices.IndexFunc(h.stamps, func(t time.Time) bool {
			return t.After(cut)
		}); i > 0 {
			h.stamps = append([]time.Time{}, h.stamps[i:]...)
		} else if i < 0 {
			h.stamps = h.stamps[:0]
		}
		if len(h.stamps) == 0 {
			delete(b.targets, k)
			h = nil
			forgotten = append(forgotten, k)
		}
	}
	if len(b.targets) > 64 {
		forgotten = append(forgotten, b.pruneLocked(cut)...)
	}
	forgetHook := b.forgetHook
	var fire func(module, target, reason string)
	allowed := true
	reason := ""
	if h != nil && len(h.stamps) >= b.limit {
		allowed = false
		reason = ReasonTargetNonConvergentCircuitOpen
		if !h.open {
			h.open = true // one announcement per open episode
			fire = b.openHook
		}
	} else {
		if h == nil {
			h = &targetHistory{}
			b.targets[k] = h
		}
		h.open = false
		h.stamps = append(h.stamps, now)
	}
	b.mu.Unlock()
	if forgetHook != nil {
		for _, f := range forgotten {
			forgetHook(f.module, f.target)
		}
	}
	if fire != nil {
		fire(module, targetKey, reason)
	}
	return allowed, reason
}

// pruneLocked drops target entries whose grant history has fully
// expired — random pod names would otherwise accumulate one map
// entry per healed pod forever. Runs only past the 64-entry soft
// cap so the common case pays nothing; the caller HOLDS b.mu.
// Returns every dropped (module,target) key so the caller can fire
// the forget hook for them outside the mutex — a bulk-dropped entry
// is a forget exactly like the inline expiry GC's.
func (b *TargetBreaker) pruneLocked(cut time.Time) []breakerTarget {
	var dropped []breakerTarget
	for k, h := range b.targets {
		if len(h.stamps) == 0 {
			delete(b.targets, k)
			dropped = append(dropped, k)
			continue
		}
		// stamps are ascending — the first in-window stamp ends
		// the expired prefix.
		if i := slices.IndexFunc(h.stamps, func(t time.Time) bool {
			return t.After(cut)
		}); i < 0 {
			delete(b.targets, k)
			dropped = append(dropped, k)
		}
	}
	return dropped
}

// RecordTargetHealthy clears (module,targetKey)'s history
// immediately — the recovery-side call: the target's own evidence of
// convergence (healthy probe, partition healed, steal cleared) ends
// the episode now instead of waiting out the window. Clearing a
// history that existed is a forget — the forget hook fires (outside
// the mutex) so the series the open hook emitted can be pruned; a
// clear with no history is a no-op and stays silent.
func (b *TargetBreaker) RecordTargetHealthy(module, targetKey string) {
	b.mu.Lock()
	_, had := b.targets[breakerTarget{module: module, target: targetKey}]
	delete(b.targets, breakerTarget{module: module, target: targetKey})
	forget := b.forgetHook
	b.mu.Unlock()
	if had && forget != nil {
		forget(module, targetKey)
	}
}

// defaultTargetBreaker is the process-wide breaker the module sweeps
// consult; nil (unconfigured or limit<=0) disables the gate — the
// same opt-in contract as defaultBudget. Boot-time write, read per
// call; atomic keeps the race detector honest.
var defaultTargetBreaker atomic.Pointer[TargetBreaker]

// ConfigureTargetBreaker installs the process-global per-target
// breaker: limit grants per (module,targetKey) per window. limit <= 0
// or window <= 0 clears the breaker (the gate compiles away).
func ConfigureTargetBreaker(limit int, window time.Duration) {
	if limit <= 0 || window <= 0 {
		defaultTargetBreaker.Store(nil)
		return
	}
	defaultTargetBreaker.Store(NewTargetBreaker(limit, window))
}

// SetTargetCircuitOpenHook registers fn to run once per breaker open
// transition (see TargetBreaker.SetOpenHook). No-op while no breaker
// is configured — boot order is ConfigureTargetBreaker first, and
// reconfiguring drops any previously wired hook with the old
// instance.
func SetTargetCircuitOpenHook(fn func(module, target, reason string)) {
	if b := defaultTargetBreaker.Load(); b != nil {
		b.SetOpenHook(fn)
	}
}

// SetTargetCircuitForgetHook registers fn to run once per breaker
// forget (see TargetBreaker.SetForgetHook) — the prune bridge
// cmd/manager wires so HealTargetCircuitBrokenTotal series die with
// the target's breaker state. No-op while no breaker is configured —
// boot order is ConfigureTargetBreaker first, and reconfiguring drops
// any previously wired hook with the old instance.
func SetTargetCircuitForgetHook(fn func(module, target string)) {
	if b := defaultTargetBreaker.Load(); b != nil {
		b.SetForgetHook(fn)
	}
}

// TryAcquireTarget is the sweep-facing entry: consult the
// process-global breaker for one (module,targetKey) grant. No breaker
// configured is the inert gate — every request proceeds.
func TryAcquireTarget(module, targetKey string, now time.Time) (bool, string) {
	if b := defaultTargetBreaker.Load(); b != nil {
		return b.TryAcquireTarget(module, targetKey, now)
	}
	return true, ""
}

// RecordTargetHealthy clears the (module,targetKey) history on the
// process-global breaker. No-op while no breaker is configured.
func RecordTargetHealthy(module, targetKey string) {
	if b := defaultTargetBreaker.Load(); b != nil {
		b.RecordTargetHealthy(module, targetKey)
	}
}
