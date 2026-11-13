// liveness.go — the per-loop heartbeat registry the agent
// supervisor's /healthz staleness check reads. The supervisor
// installs one *Liveness per subsystem via WithLiveness; every
// cycle.Runner registers its own Beat with a staleness budget
// derived from its interval, and bare Heartbeat(ctx) callers
// (custom ticker loops like hubsync's) share the fallback beat.
//
// Per-loop budgets are the whole point: a single 15m constant
// false-positives on legitimately slow loops (sweeper's 1h sweep,
// kinedb's 6h maint pass) and crash-loops the entire DaemonSet.
// Each loop is judged against max(3*interval + cycle budget,
// LivenessFloor) instead — a wedged loop still trips, a slow one
// does not.
//
// Child registries: cycle.RunAll gives every non-*Runner Looper
// its own *Liveness (attached via Attach for the RunAll lifetime)
// so a fast custom loop's bare Heartbeat stamps ITS fallback —
// never the subsystem's shared one — and a wedged slow sibling
// can't be masked by the fast loop's stamps. LoopBeats/LoopCount/
// Fallbacks all aggregate the non-exempt subtree so /healthz sees
// the flattened view.
package cycle

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// LivenessFloor is the minimum staleness bound any loop gets —
// below it, ordinary scheduling jitter and a couple of missed
// ticks would look like a wedge.
const LivenessFloor = 15 * time.Minute

// DefaultCycleBudget is the per-cycle deadline most subsystems
// apply around fn (the CycleTimeout class of bounds) — folded
// into a loop's staleness budget so a cycle allowed to run long
// is not reported wedged while legitimately working.
const DefaultCycleBudget = 15 * time.Minute

// Beat is one loop's last-cycle stamp — unixnano, 0 until the
// first stamp lands. MaxStaleNanos carries the loop's own
// staleness bound (0 → the reader's default).
type Beat struct {
	LastProgress  atomic.Int64
	MaxStaleNanos atomic.Int64
}

// StaleAfter returns the beat's configured staleness bound, or 0
// when unset (the /healthz reader substitutes its default).
func (b *Beat) StaleAfter() time.Duration {
	if ns := b.MaxStaleNanos.Load(); ns > 0 {
		return time.Duration(ns)
	}
	return 0
}

// Liveness is one heartbeat scope: the loop beats cycle.Runner
// registers plus the shared fallback beat bare Heartbeat(ctx)
// calls stamp, plus any child registries RunAll attached for its
// non-*Runner loopers. Exempt marks the whole registry invisible
// to /healthz (cycle.Idle — a parked, disabled loop is alive by
// definition); an exempt registry's children are skipped too.
type Liveness struct {
	mu       sync.Mutex
	loops    []*Beat
	children []*Liveness
	fallback *Beat
	exempt   atomic.Bool
}

// NewLiveness returns an empty registry.
func NewLiveness() *Liveness {
	return &Liveness{fallback: &Beat{}}
}

type livenessKey struct{}

// WithLiveness returns a ctx carrying l — the supervisor installs
// one per subsystem so Runner loops and bare Heartbeat callers
// stamp beats the /healthz check can find, and RunAll installs one
// per non-*Runner Looper so sibling loops never share a beat.
func WithLiveness(ctx context.Context, l *Liveness) context.Context {
	return context.WithValue(ctx, livenessKey{}, l)
}

// LivenessFrom returns the ctx's registry, nil outside an
// agent-supervised ctx (tests, ops, embedders).
func LivenessFrom(ctx context.Context) *Liveness {
	if l, ok := ctx.Value(livenessKey{}).(*Liveness); ok {
		return l
	}
	return nil
}

// Attach registers child as a sub-scope of l and returns the
// detach func — RunAll calls it once per non-*Runner Looper and
// defers every detach so a restarted Run never leaks dead
// registries (whose stale beats would false-positive /healthz).
// Attaching the same child twice is a no-op the second time.
func (l *Liveness) Attach(child *Liveness) (detach func()) {
	l.mu.Lock()
	for _, c := range l.children {
		if c == child {
			l.mu.Unlock()
			return func() {}
		}
	}
	l.children = append(l.children, child)
	l.mu.Unlock()
	return func() {
		l.mu.Lock()
		for i, c := range l.children {
			if c == child {
				l.children = append(l.children[:i], l.children[i+1:]...)
				break
			}
		}
		l.mu.Unlock()
	}
}

// RegisterLoop records a periodic loop and returns its beat. The
// staleness bound is max(3*interval + budget, LivenessFloor):
// three missed ticks plus one full cycle budget of slack. Beats
// accumulate in a SLICE — two child runners sharing a name each
// keep their own beat instead of the second RegisterLoop
// overwriting the first's map entry.
func (l *Liveness) RegisterLoop(name string, interval, budget time.Duration) *Beat {
	stale := 3*interval + budget
	if stale < LivenessFloor {
		stale = LivenessFloor
	}
	b := &Beat{}
	b.MaxStaleNanos.Store(int64(stale))
	l.mu.Lock()
	l.loops = append(l.loops, b)
	l.mu.Unlock()
	return b
}

// Unregister removes a beat RegisterLoop returned — cycle.Runner
// defers it in Run so a loop's beat cannot outlive the loop. A beat
// left registered keeps its last stamp forever: after a panic
// restart the orphaned beat trips the /healthz staleness check ~one
// budget later and the supervisor gets killed while healthy. A beat
// not (or no longer) registered is a no-op, so a double-unregister
// race is harmless. The fallback beat is NOT unregisterable — bare
// Heartbeat callers stamp it for the registry's whole lifetime; the
// supervisor renews whole registries per Run attempt instead.
func (l *Liveness) Unregister(b *Beat) {
	if b == nil {
		return
	}
	l.mu.Lock()
	for i, lb := range l.loops {
		if lb == b {
			l.loops = append(l.loops[:i], l.loops[i+1:]...)
			break
		}
	}
	l.mu.Unlock()
}

// LoopBeats snapshots every registered loop beat in the
// non-exempt subtree — own loops first, then each live child's
// (recursively). An exempt registry contributes nothing: cycle.Idle
// parks are alive by definition.
func (l *Liveness) LoopBeats() []*Beat {
	l.mu.Lock()
	out := make([]*Beat, 0, len(l.loops))
	out = append(out, l.loops...)
	children := append([]*Liveness(nil), l.children...)
	exempt := l.exempt.Load()
	l.mu.Unlock()
	if exempt {
		return nil
	}
	for _, c := range children {
		out = append(out, c.LoopBeats()...)
	}
	return out
}

// LoopCount reports how many Runner loops are registered in the
// whole non-exempt subtree — /healthz uses it to decide whether a
// registry's fallback beat is meaningful.
func (l *Liveness) LoopCount() int {
	l.mu.Lock()
	n := len(l.loops)
	children := append([]*Liveness(nil), l.children...)
	exempt := l.exempt.Load()
	l.mu.Unlock()
	if exempt {
		return 0
	}
	for _, c := range children {
		n += c.LoopCount()
	}
	return n
}

// Fallbacks returns the fallback beats /healthz must judge: one
// per registry in the non-exempt subtree whose OWN subtree holds
// no Runner loops. A registry with loops stamps its fallback once
// at run entry and judging it would false-positive — the same rule
// the flat LoopCount()==0 check applied, now per scope so a
// RunAll child's bare-Heartbeat loop is judged on its own beat
// while the parent's entry stamp stays exempt.
func (l *Liveness) Fallbacks() []*Beat {
	var out []*Beat
	l.collectFallbacks(&out)
	return out
}

func (l *Liveness) collectFallbacks(out *[]*Beat) {
	l.mu.Lock()
	loops := len(l.loops)
	children := append([]*Liveness(nil), l.children...)
	exempt := l.exempt.Load()
	fb := l.fallback
	l.mu.Unlock()
	if exempt {
		return
	}
	childLoops := 0
	for _, c := range children {
		childLoops += c.LoopCount()
	}
	if loops+childLoops == 0 {
		*out = append(*out, fb)
		return
	}
	for _, c := range children {
		c.collectFallbacks(out)
	}
}

// Fallback returns the shared beat bare Heartbeat(ctx) callers
// stamp — always non-nil.
func (l *Liveness) Fallback() *Beat { return l.fallback }

// Exempt marks the registry invisible to /healthz — cycle.Idle
// calls it so a parked subsystem is never reported wedged.
func (l *Liveness) Exempt() { l.exempt.Store(true) }

// IsExempt reports the exempt flag.
func (l *Liveness) IsExempt() bool { return l.exempt.Load() }

// Heartbeat records one completed cycle on the ctx's liveness
// beat — a no-op outside an agent-supervised ctx (tests, ops,
// embedders), so loops may call it unconditionally. An explicit
// WithBeat ctx wins (legacy single-beat callers); otherwise the
// call lands on the shared fallback beat of the ctx's OWN
// registry — under RunAll that is the per-looper child, never the
// subsystem-wide one.
func Heartbeat(ctx context.Context) {
	if l := LivenessFrom(ctx); l != nil {
		l.fallback.LastProgress.Store(time.Now().UnixNano())
	}
}

// Exempt marks the ctx's liveness registry invisible to /healthz —
// cycle.Idle uses it; a no-op outside a supervised ctx.
func Exempt(ctx context.Context) {
	if l := LivenessFrom(ctx); l != nil {
		l.Exempt()
	}
}

// stampLoop is Runner's per-iteration heartbeat: it writes the
// loop's own beat directly (no ctx indirection — the beat was
// registered by this same Run).
func stampLoop(b *Beat) {
	if b != nil {
		b.LastProgress.Store(time.Now().UnixNano())
	}
}
