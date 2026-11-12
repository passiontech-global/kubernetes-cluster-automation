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

// Liveness is one subsystem's heartbeat registry: the loop beats
// cycle.Runner registers plus the shared fallback beat bare
// Heartbeat(ctx) calls stamp. Exempt marks the whole registry
// invisible to /healthz (cycle.Idle — a parked, disabled loop is
// alive by definition).
type Liveness struct {
	mu       sync.Mutex
	loops    map[string]*Beat
	fallback *Beat
	exempt   atomic.Bool
}

// NewLiveness returns an empty registry.
func NewLiveness() *Liveness {
	return &Liveness{
		loops:    make(map[string]*Beat),
		fallback: &Beat{},
	}
}

type livenessKey struct{}

// WithLiveness returns a ctx carrying l — the supervisor installs
// one per subsystem so Runner loops and bare Heartbeat callers
// stamp beats the /healthz check can find.
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

// RegisterLoop records a periodic loop and returns its beat. The
// staleness bound is max(3*interval + budget, LivenessFloor):
// three missed ticks plus one full cycle budget of slack.
func (l *Liveness) RegisterLoop(name string, interval, budget time.Duration) *Beat {
	stale := 3*interval + budget
	if stale < LivenessFloor {
		stale = LivenessFloor
	}
	b := &Beat{}
	b.MaxStaleNanos.Store(int64(stale))
	l.mu.Lock()
	l.loops[name] = b
	l.mu.Unlock()
	return b
}

// LoopBeats snapshots the registered loop beats.
func (l *Liveness) LoopBeats() []*Beat {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]*Beat, 0, len(l.loops))
	for _, b := range l.loops {
		out = append(out, b)
	}
	return out
}

// LoopCount reports how many Runner loops registered — the
// /healthz reader uses it to decide whether the fallback beat is
// meaningful (a Runner-only subsystem never stamps it after the
// run-entry grace, so judging it would false-positive).
func (l *Liveness) LoopCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.loops)
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
// call lands on the shared fallback beat.
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
