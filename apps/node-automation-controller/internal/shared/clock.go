// clock.go — the Clock seam. Every module carries the same
// `nowFn func() time.Time` field so tests pin "now" instead of
// sleeping; each also repeats the lazy `if nowFn == nil { nowFn =
// time.Now }` arm for literally-constructed fixtures. Clock names the
// seam once: a func type with a nil-safe Now() (a zero-value Clock
// reads as system time, so the lazy arm collapses into the call
// site) and SystemClock as the production default.
package shared

import "time"

// Clock is a clock seam — the standard `nowFn func() time.Time`
// shape every sweep module carries for tests. Convert a plain func
// with Clock(fn); a nil Clock still answers with system time, so
// `var now Clock` needs no constructor.
type Clock func() time.Time

// Now returns the current time. A nil Clock falls back to system
// time — the same "unarmed seam reads as real clock" convention the
// modules' `if nowFn == nil { nowFn = time.Now }` blocks encode.
func (c Clock) Now() time.Time {
	if c == nil {
		return time.Now()
	}
	return c()
}

// SystemClock is the production clock — what every module's nowFn
// defaults to.
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
