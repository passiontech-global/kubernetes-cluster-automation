// cell.go — Cell: the settable clock cell. Clock (timex.go) is a
// func value — re-stubbing it post-construction only reaches
// collaborators that close over the live config field, which forced
// every hoststate.New call site into a repeated
// `func() time.Time { return cfg.nowFn() }` contract. A *Cell
// shared between a Config and every collaborator built from it
// (hoststate.Store, trackers) instead observes Set() calls made
// after construction: pass the method value `cfg.Clock.Now` and the
// bound POINTER keeps reading whatever the last Set installed.
package timex

import (
	"sync/atomic"
	"time"
)

// Cell is a settable clock — a *Cell shared between a Config and
// every collaborator built from it observes Set() calls made after
// construction, removing the "capture a closure over the live
// field" contract the nowFn seam needed.
//
// Goroutine-safe (the stored Clock swaps atomically). A nil *Cell
// and a Cell that was never Set both read as system time — the same
// "unarmed seam reads as real clock" convention Clock.Now encodes.
type Cell struct {
	// v holds the installed Clock (never nil after Set — Set maps nil
	// to SystemClock). atomic.Pointer rather than a mutex or
	// atomic.Value: Now() is a single typed Load on the hot path.
	v atomic.Pointer[Clock]
}

// NewCell returns a Cell armed with cl; nil → SystemClock.
func NewCell(cl Clock) *Cell {
	c := &Cell{}
	c.Set(cl)
	return c
}

// Now returns the current time from the installed Clock. A nil
// *Cell or a never-Set Cell falls back to system time.
func (c *Cell) Now() time.Time {
	if c == nil {
		return time.Now()
	}
	if p := c.v.Load(); p != nil {
		return (*p).Now()
	}
	return time.Now()
}

// Set installs cl as the Cell's clock; nil → SystemClock (reset to
// production time). Every collaborator holding the *Cell observes
// the swap on its next Now().
func (c *Cell) Set(cl Clock) {
	if cl == nil {
		cl = SystemClock
	}
	c.v.Store(&cl)
}
