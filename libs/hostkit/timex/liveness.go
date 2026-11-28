// liveness.go — stdlib-only monotonic loop heartbeat registry shared
// across apps so /healthz checks can detect wedged run loops without
// false-failing on standby replicas (0 registered loops) or NTP
// wall-clock jumps.
package timex

import (
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultLivenessFloor is the standard minimum staleness budget for
// long-lived periodic loops (15m) — callers can assign it to
// Liveness.Floor so short-interval loops do not trip /healthz on
// transient scheduling or API jitter.
const DefaultLivenessFloor = 15 * time.Minute

var processMonoEpoch = time.Now()

// Beat is a single registered loop's heartbeat handle. All methods are
// nil-safe and safe for concurrent use with Liveness.Check.
type Beat struct {
	owner      *Liveness
	name       string
	regAt      time.Duration
	grace      atomic.Int64
	staleAfter atomic.Int64
	lastBeat   atomic.Int64 // 0 before first Beat(); >= 1 once stamped
}

// Name returns the loop name recorded at registration, or "" on nil.
func (b *Beat) Name() string {
	if b == nil {
		return ""
	}
	return b.name
}

// Beat records monotonic progress for this loop. Nil-safe.
func (b *Beat) Beat() {
	if b == nil || b.owner == nil {
		return
	}
	b.lastBeat.Store(int64(b.owner.monoNow()))
}

// SetStaleAfter updates the loop's steady-state staleness threshold
// dynamically (e.g., adaptive intervals). Respects owner.Floor when > 0.
func (b *Beat) SetStaleAfter(d time.Duration) {
	if b == nil {
		return
	}
	if d > 0 && b.owner != nil && b.owner.Floor > 0 && d < b.owner.Floor {
		d = b.owner.Floor
	}
	b.staleAfter.Store(int64(d))
}

// StaleAfter returns the loop's configured steady-state staleness
// threshold (0 when disabled or nil).
func (b *Beat) StaleAfter() time.Duration {
	if b == nil {
		return 0
	}
	return time.Duration(b.staleAfter.Load())
}

// Age returns the monotonic duration elapsed since the last Beat (or
// since registration if never beaten), or 0 on a nil/unowned Beat.
func (b *Beat) Age() time.Duration {
	if b == nil || b.owner == nil {
		return 0
	}
	now := b.owner.monoNow()
	last := time.Duration(b.lastBeat.Load())
	if last == 0 {
		last = b.regAt
	}
	if now <= last {
		return 0
	}
	return now - last
}

// Liveness tracks monotonic progress across active loops. A zero
// Liveness is ready to use (reads monotonic elapsed time since process
// start); NewLiveness anchors the monotonic epoch at creation time, and
// NewLivenessWithClock installs a deterministic monotonic clock seam
// for tests.
type Liveness struct {
	// Floor, when > 0, sets the minimum grace/stale threshold applied
	// by Register, RegisterWithGrace, and Beat.SetStaleAfter.
	Floor time.Duration
	// Now, when non-nil, overrides the monotonic elapsed clock used by
	// Beat and Check (must be monotonically non-decreasing).
	Now func() time.Duration

	mu     sync.Mutex
	loops  []*Beat
	epoch  time.Time
	exempt atomic.Bool
}

// NewLiveness constructs a Liveness tracker anchored to the monotonic
// clock at creation time.
func NewLiveness() *Liveness {
	return &Liveness{epoch: time.Now()}
}

// NewLivenessWithClock constructs a Liveness tracker backed by a
// caller-supplied monotonic elapsed clock seam (for deterministic tests).
func NewLivenessWithClock(now func() time.Duration) *Liveness {
	return &Liveness{
		epoch: time.Now(),
		Now:   now,
	}
}

func (l *Liveness) monoNow() time.Duration {
	if l != nil && l.Now != nil {
		d := l.Now()
		if d < 0 {
			d = 0
		}
		// Shift by +1ns so 0 in lastBeat unambiguously means "not yet beaten"
		// even when a test clock starts at 0.
		return d + 1
	}
	epoch := processMonoEpoch
	if l != nil && !l.epoch.IsZero() {
		epoch = l.epoch
	}
	d := time.Since(epoch) + 1
	if d < 1 {
		return 1
	}
	return d
}

func (l *Liveness) clampFloor(d time.Duration) time.Duration {
	if d > 0 && l != nil && l.Floor > 0 && d < l.Floor {
		return l.Floor
	}
	return d
}

// Register adds a loop named name with staleness threshold staleAfter
// (used for both initial grace and steady-state checks).
func (l *Liveness) Register(name string, staleAfter time.Duration) *Beat {
	return l.RegisterWithGrace(name, staleAfter, staleAfter)
}

// RegisterWithGrace adds a loop named name with an initial startup
// grace window (before its first Beat) and a steady-state staleAfter
// threshold (after its first Beat). If grace <= 0, staleAfter is used.
func (l *Liveness) RegisterWithGrace(name string, grace, staleAfter time.Duration) *Beat {
	if l == nil {
		return nil
	}
	if grace <= 0 {
		grace = staleAfter
	}
	grace = l.clampFloor(grace)
	staleAfter = l.clampFloor(staleAfter)
	b := &Beat{
		owner: l,
		name:  name,
		regAt: l.monoNow(),
	}
	b.grace.Store(int64(grace))
	b.staleAfter.Store(int64(staleAfter))
	l.mu.Lock()
	l.loops = append(l.loops, b)
	l.mu.Unlock()
	return b
}

// Unregister removes b from the registry so a cleanly exited or
// restarted loop does not linger and trip Check. Nil-safe and idempotent.
func (l *Liveness) Unregister(b *Beat) {
	if l == nil || b == nil {
		return
	}
	l.mu.Lock()
	for i, existing := range l.loops {
		if existing == b {
			l.loops = append(l.loops[:i], l.loops[i+1:]...)
			break
		}
	}
	l.mu.Unlock()
}

// Beat records monotonic progress for b. Nil-safe.
func (l *Liveness) Beat(b *Beat) {
	if b == nil {
		return
	}
	if b.owner == nil && l != nil {
		b.lastBeat.Store(int64(l.monoNow()))
		return
	}
	b.Beat()
}

// Exempt marks the registry invisible to Check (e.g., an intentionally
// parked/idle subsystem).
func (l *Liveness) Exempt() {
	if l == nil {
		return
	}
	l.exempt.Store(true)
}

// IsExempt reports whether the registry is marked exempt.
func (l *Liveness) IsExempt() bool {
	if l == nil {
		return false
	}
	return l.exempt.Load()
}

// Beats returns a snapshot of currently registered loop beats.
func (l *Liveness) Beats() []*Beat {
	if l == nil || l.exempt.Load() {
		return nil
	}
	l.mu.Lock()
	out := slices.Clone(l.loops)
	l.mu.Unlock()
	return out
}

// Check verifies that every registered loop has progressed within its
// grace (before first Beat) or stale threshold (after first Beat).
// Returns nil on nil/exempt registries or when no loops are registered.
func (l *Liveness) Check() error {
	if l == nil || l.exempt.Load() {
		return nil
	}
	l.mu.Lock()
	loops := slices.Clone(l.loops)
	l.mu.Unlock()
	now := l.monoNow()
	for _, b := range loops {
		last := time.Duration(b.lastBeat.Load())
		var threshold time.Duration
		if last == 0 {
			last = b.regAt
			threshold = time.Duration(b.grace.Load())
		} else {
			threshold = time.Duration(b.staleAfter.Load())
		}
		if threshold <= 0 || last <= 0 {
			continue
		}
		if elapsed := now - last; elapsed > threshold {
			return fmt.Errorf("loop %q stale for %s (budget %s)",
				b.name, elapsed.Round(time.Millisecond), threshold)
		}
	}
	return nil
}
