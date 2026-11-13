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
// The per-target non-convergent circuit breaker in breaker.go is
// the other half of the same contract: the aggregate budget bounds
// the FLEET's heal rate, the breaker bounds how many times ONE
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
