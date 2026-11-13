// breaker.go — the per-target non-convergent circuit breaker,
// split out of budget.go: the aggregate Budget bounds the FLEET's
// heal rate, this bounds how many times ONE (module,targetKey) may
// be remediated inside the sliding window without the target ever
// converging — the repeated-taint-on-a-dead-node churn shape.
package heal

import (
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

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
