// verdict.go — Verdict, the TTL memo every gated module shares via
// shared.Deps.Maintenance: heal loops that run the mutex once per
// target would otherwise pay three API reads (node list, kured DS
// get, autopilot plan list) per pod. The memoized payload is the
// tiered Scope — cluster-wide vs per-node holds — so node-scoped
// gates (DaemonSet bounces on one node) can proceed while a
// DIFFERENT node drains.
package maintenance

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

const (
	// verdictTTL is how long a Scope reuses one maintenance
	// evaluation — sized to cover a sweep's per-target heal
	// preambles without letting a drain that starts mid-incident
	// go unseen past the next cycle.
	verdictTTL = time.Minute
	// verdictErrorTTL is the shorter stickiness for an ERROR
	// verdict: a transient apiseret failure must not poison the
	// memo for the full minute — the next gate retries after 5s
	// instead of deferring every heal behind a stale failure.
	verdictErrorTTL = 5 * time.Second
)

// Scope is the tiered maintenance verdict: Held is the boolean the
// classic mutex contract needs; ClusterWide marks signals that hold
// EVERY node (autopilot Plan, unscoped kured lock, unresolvable
// medik8s CR); Nodes names the specific nodes under hold (fresh
// cordons, node-scoped kured locks, medik8s remediation targets).
// Why is the first held signal's evidence string in canonical
// a→b→c→d order, matching the short-circuit verdict's wording.
type Scope struct {
	Held        bool
	ClusterWide bool
	Nodes       map[string]bool
	Why         string
}

// evalFlight is one in-flight Scope evaluation: the leader computes
// outside v.mu while waiters block on done (or their own ctx) — a
// sweep's N concurrent heal gates share ONE apiserver read round
// instead of stampeding it, and a waiter whose PerCheck ctx expires
// mid-eval exits immediately rather than inheriting the leader's
// 15s detached bound.
type evalFlight struct {
	done  chan struct{}
	scope Scope
	err   error
}

// Verdict memoizes one maintenance evaluation for the verdict TTL —
// heal loops that run the mutex once per target would otherwise pay
// three API reads (node list, kured DS get, autopilot plan list) per
// pod. Zero value is ready (expired — evaluates on first call); an
// error verdict is sticky for verdictErrorTTL only.
type Verdict struct {
	// mu guards the memo fields AND the flight pointer — several
	// module goroutines share one Verdict (Deps.verdict) and may
	// evaluate Scope concurrently; an unguarded read-modify-write
	// could tear the (at, scope, err, flight) tuple mid-sweep.
	mu     sync.Mutex
	at     time.Time
	scope  Scope
	err    error
	flight *evalFlight
	// NodeReader backs the node census the active-cordon signal (a)
	// reads — the manager's informer-backed client (mgr.GetClient),
	// wired at the ONE production construction site (main.go's
	// shared.Deps, the same CachedNodeReader posture
	// clusterhealthprobes uses). The verdict is a read-only query by
	// contract, so the watch-fresh cache read is exactly the
	// sanctioned census class; nil (tests, literally-built fixtures,
	// the per-module fallback verdicts) keeps the direct ListNodes
	// read — ListNodesCached's documented nil-reader fallback.
	NodeReader kube.CachedNodeReader
}

// Active returns the maintenance verdict, evaluating Scope only
// when the memo is stale. The (held, why, err) triple is Scope's
// Held/Why projected — the signature is unchanged so every existing
// caller and test keeps its contract.
func (v *Verdict) Active(ctx context.Context, cs kubernetes.Interface,
	dyn dynamic.Interface, now time.Time) (bool, string, error) {
	s, err := v.Scope(ctx, cs, dyn, now)
	return s.Held, s.Why, err
}

// Scope returns the tiered maintenance verdict, evaluating
// maintenanceScope (with THIS call's `now` — the memo and the
// cordon/remediation windows age on one clock) only when the memo
// is older than its TTL. The evaluation runs OUTSIDE v.mu under a
// singleflight: concurrent callers join the in-flight evalFlight
// and share its result, and waiters exit on their own ctx.Done()
// instead of queueing behind the leader's detached 15s bound.
//
// Freshness requires !now.Before(v.at) — a clock rollback makes
// now.Sub(at) negative, which would otherwise read as "fresh"
// forever; requiring now >= at forces re-evaluation instead of
// trusting a memo stamped by a clock that has since moved back.
//
// READ-ONLY by contract: a "does maintenance hold?" query must
// never patch Nodes as a side effect — heal gates call Scope
// dozens of times per sweep and an unexpected write inside a
// verdict read is exactly the kind of hidden mutation the
// snapshot/fingerprint work exists to catch. Stamping is the
// dedicated cluster-maintenance-stamper runnable's job
// (cmd/manager/maintenancestamper.go) on its own 30s cadence.
func (v *Verdict) Scope(ctx context.Context, cs kubernetes.Interface,
	dyn dynamic.Interface, now time.Time) (Scope, error) {
	if v == nil {
		// Nil-safe per the shared-Deps contract: a literally-built
		// fixture with no verdict wired evaluates fresh every call
		// (unmemoized but correct) instead of panicking.
		v = &Verdict{}
	}
	v.mu.Lock()
	ttl := verdictTTL
	if v.err != nil {
		ttl = verdictErrorTTL
	}
	if !now.Before(v.at) && now.Sub(v.at) < ttl {
		s, err := v.scope, v.err
		v.mu.Unlock()
		return s, err
	}
	if v.flight != nil {
		// Join the in-flight evaluation — its result is
		// fresher than any memo this caller could restart.
		f := v.flight
		v.mu.Unlock()
		select {
		case <-f.done:
			return f.scope, f.err
		case <-ctx.Done():
			return Scope{}, ctx.Err()
		}
	}
	f := &evalFlight{done: make(chan struct{})}
	v.flight = f
	v.mu.Unlock()

	// DETACHED ctx — context.WithoutCancel keeps the sweep
	// snapshot/overlay values but drops the caller's deadline:
	// a check whose PerCheck ctx expires mid-eval must not
	// cache its DeadlineExceeded into the memo (every later
	// gate would fail closed on a poisoned verdict), and the
	// 15s bound keeps a wedged apiserver read from stalling
	// the caller past its own budget. Waiters still exit on
	// THEIR ctx via the flight select above.
	mctx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx), maintenanceEvalTimeout)
	scope, err := maintenanceScope(mctx, cs, dyn, v.NodeReader, now)
	cancel()

	v.mu.Lock()
	v.scope, v.err, v.at = scope, err, now
	v.flight = nil
	f.scope, f.err = scope, err
	close(f.done)
	v.mu.Unlock()
	return scope, err
}

// maintenanceScope evaluates all four maintenance signals through
// the shared stamp.go target resolver at the VERDICT's 45m cordon
// horizon (the stamp path's wider 2h window is for agent hints,
// not the mutex) and projects the (all, names) target sets onto
// Scope. Any degraded signal read fails the whole evaluation —
// "cannot verify" must never read as "clear", and a partial scope
// would let a node-scoped gate proceed through a hold it could not
// observe.
func maintenanceScope(ctx context.Context, cs kubernetes.Interface,
	dyn dynamic.Interface, nodeReader kube.CachedNodeReader,
	now time.Time) (Scope, error) {
	if dyn == nil {
		return Scope{}, errors.New("no dynamic client — autopilot/medik8s checks unverifiable (maintenance mutex)")
	}
	nodes, err := maintenanceNodeList(ctx, cs, nodeReader)
	if err != nil {
		return Scope{}, fmt.Errorf("list nodes (maintenance mutex): %w", err)
	}
	all, names, complete, why := maintenanceTargets(ctx, cs, dyn,
		nodes, now, kube.NodeCordonActiveMaxAge)
	sc := Scope{
		ClusterWide: all,
		Nodes:       names,
		Why:         why,
	}
	sc.Held = all || len(names) > 0
	if !complete && !all {
		// A degraded signal read fails the evaluation ONLY when no
		// cluster-wide hold is already proven — "cannot verify"
		// must never read as "clear". Once all==true (autopilot
		// plan / unscoped medik8s / unscoped kured lock), every
		// gate denies on ClusterWide alone, so a second signal's
		// read failure cannot change the verdict — failing here
		// would just churn the error TTL and IncError noise.
		return Scope{}, errors.New("maintenance signal read failed — scope unverifiable (maintenance mutex)")
	}
	return sc, nil
}

// maintenanceEvalTimeout bounds one mutex evaluation — the four
// signal reads are small LISTs/GETs; 15s is generous headroom that
// still lands well inside a check's PerCheck budget.
const maintenanceEvalTimeout = 15 * time.Second
