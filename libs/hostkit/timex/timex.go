// Package timex provides the Clock seam shared by the apps in this
// monorepo (it lives in libs/hostkit, shared via replace).
//
// Clock names the `nowFn func() time.Time` shape every sweep/subsystem
// carries for tests: a func type with a nil-safe Now() so an unarmed
// seam reads as system time. It was lifted out of
// node-automation-controller's internal/shared (shared.Clock) — which
// itself replaced the per-module `nowFn func() time.Time` +
// `if nowFn == nil { nowFn = time.Now }` lazy arm — because
// node-host-agent re-implements the identical seam in a dozen
// subsystem/platform config structs.
package timex

import "time"

// Clock is a clock seam — the standard `nowFn func() time.Time`
// shape sweep modules carry for tests. Convert a plain func with
// Clock(fn); a nil Clock still answers with system time, so
// `var now Clock` needs no constructor. A Clock value calls like the
// underlying func (`c()`) AND answers nil-safely via Now() — pick
// whichever the call site already uses.
type Clock func() time.Time

// Now returns the current time. A nil Clock falls back to system
// time — the same "unarmed seam reads as real clock" convention the
// hand-rolled `if nowFn == nil { nowFn = time.Now }` arms encode.
func (c Clock) Now() time.Time {
	if c == nil {
		return time.Now()
	}
	return c()
}

// SystemClock is the production clock — what every seam defaults to.
var SystemClock Clock = time.Now

// NewClock wraps fn as a Clock, mapping nil to SystemClock so a
// struct field can be assigned unconditionally (`now: NewClock(fn)`)
// without a separate nil check.
func NewClock(fn func() time.Time) Clock {
	if fn == nil {
		return SystemClock
	}
	return Clock(fn)
}
