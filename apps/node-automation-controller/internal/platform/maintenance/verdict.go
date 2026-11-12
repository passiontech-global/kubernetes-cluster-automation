// verdict.go — Verdict, the TTL memo every gated module shares via
// shared.Deps.Maintenance: heal loops that run the mutex once per
// target would otherwise pay three API reads (node list, kured DS
// get, autopilot plan list) per pod.
package maintenance

import (
	"context"
	"sync"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// verdictTTL is how long a Verdict reuses one MaintenanceActive
// evaluation — sized to cover a sweep's per-target heal preambles
// without letting a drain that starts mid-incident go unseen past
// the next cycle.
const verdictTTL = time.Minute

// Verdict memoizes one MaintenanceActive evaluation for the verdict
// TTL — heal loops that run the mutex once per target would otherwise pay
// three API reads (node list, kured DS get, autopilot plan list) per
// pod. Zero value is ready (expired — evaluates on first call); an
// error verdict is sticky for the window too, matching the
// fail-closed contract of a fresh check.
type Verdict struct {
	// mu guards the memo fields — several module goroutines share
	// one Verdict (Deps.verdict) and may evaluate Active
	// concurrently; an unguarded read-modify-write could tear the
	// (at, held, why, err) tuple mid-sweep.
	mu   sync.Mutex
	at   time.Time
	held bool
	why  string
	err  error
}

// Active returns the maintenance verdict, evaluating
// MaintenanceActiveWithClock (with THIS call's `now` — the memo and
// the cordon window age on one clock) only when the memo is older
// than the verdict TTL. The evaluation runs under a DETACHED ctx —
// context.WithoutCancel keeps the sweep snapshot/overlay values but
// drops the caller's deadline: a check whose PerCheck ctx expires
// mid-eval must not cache its DeadlineExceeded into the 60s memo
// (every later gate would fail closed on a poisoned verdict), and
// the 15s bound keeps a wedged apiserver read from stalling the
// caller past its own budget.
func (v *Verdict) Active(ctx context.Context, cs kubernetes.Interface,
	dyn dynamic.Interface, now time.Time) (bool, string, error) {
	if v == nil {
		// Nil-safe per the shared-Dps contract: a literally-built
		// fixture with no verdict wired evaluates fresh every call
		// (unmemoized but correct) instead of panicking.
		v = &Verdict{}
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if now.Sub(v.at) < verdictTTL {
		return v.held, v.why, v.err
	}
	mctx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx), maintenanceEvalTimeout)
	defer cancel()
	v.held, v.why, v.err = MaintenanceActiveWithClock(mctx, cs, dyn, now)
	v.at = now
	// READ-ONLY by contract: a "does maintenance hold?" query must
	// never patch Nodes as a side effect — heal gates call Active
	// dozens of times per sweep and an unexpected write inside a
	// verdict read is exactly the kind of hidden mutation the
	// snapshot/fingerprint work exists to catch. Stamping is the
	// dedicated cluster-maintenance-stamper runnable's job
	// (cmd/manager/maintenancestamper.go) on its own 30s cadence.
	return v.held, v.why, v.err
}

// maintenanceEvalTimeout bounds one mutex evaluation — the four
// signal reads are small LISTs/GETs; 15s is generous headroom that
// still lands well inside a check's PerCheck budget.
const maintenanceEvalTimeout = 15 * time.Second
