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
