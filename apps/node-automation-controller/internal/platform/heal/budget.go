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
	mu       sync.Mutex
	limit    int
	window   time.Duration
	targets  map[breakerTarget]*targetHistory
	openHook func(module, target, reason string)
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
		}
	}
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
	if fire != nil {
		fire(module, targetKey, reason)
	}
	return allowed, reason
}

// RecordTargetHealthy clears (module,targetKey)'s history
// immediately — the recovery-side call: the target's own evidence of
// convergence (healthy probe, partition healed, steal cleared) ends
// the episode now instead of waiting out the window.
func (b *TargetBreaker) RecordTargetHealthy(module, targetKey string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.targets, breakerTarget{module: module, target: targetKey})
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
