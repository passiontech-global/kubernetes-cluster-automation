package timex

import (
	"testing"
	"time"
)

func TestClockNow(t *testing.T) {
	fixed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if got := Clock(func() time.Time { return fixed }).Now(); !got.Equal(fixed) {
		t.Fatalf("Clock.Now() = %v, want %v", got, fixed)
	}
}

func TestClockNilReadsSystemTime(t *testing.T) {
	var c Clock // zero value — the lazy-arm case
	before := time.Now()
	got := c.Now()
	after := time.Now()
	if got.Before(before) || got.After(after) {
		t.Fatalf("nil Clock.Now() = %v outside [%v, %v]", got, before, after)
	}
}

func TestSystemClock(t *testing.T) {
	before := time.Now()
	got := SystemClock.Now()
	if got.Before(before) || got.After(time.Now()) {
		t.Fatalf("SystemClock.Now() = %v", got)
	}
}

func TestNewClock(t *testing.T) {
	fixed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if got := NewClock(func() time.Time { return fixed }).Now(); !got.Equal(fixed) {
		t.Fatalf("NewClock(fn).Now() = %v, want %v", got, fixed)
	}
	// nil fn maps to SystemClock — no panic on Now().
	if got := NewClock(nil).Now(); got.IsZero() || got.After(time.Now()) {
		t.Fatalf("NewClock(nil).Now() = %v", got)
	}
}

func TestCellSetObservedAfterSharing(t *testing.T) {
	// The contract the hoststate.New call sites rely on: a method
	// value captured BEFORE Set still observes the new clock —
	// the whole point of sharing a *Cell over closing over a
	// config field.
	c := NewCell(nil)
	nowFn := c.Now // binds the pointer, not the installed Clock

	fixed := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	c.Set(func() time.Time { return fixed })
	if got := nowFn(); !got.Equal(fixed) {
		t.Fatalf("post-Set Now() = %v, want %v", got, fixed)
	}
	// Set(nil) resets to system time.
	c.Set(nil)
	before := time.Now()
	if got := nowFn(); got.Before(before) || got.After(time.Now()) {
		t.Fatalf("post-Set(nil) Now() = %v", got)
	}
}

func TestCellNilReceiverReadsSystemTime(t *testing.T) {
	var c *Cell
	before := time.Now()
	got := c.Now()
	if got.Before(before) || got.After(time.Now()) {
		t.Fatalf("nil *Cell.Now() = %v", got)
	}
	// A never-Set Cell (not via NewCell) reads the same way.
	if got := (&Cell{}).Now(); got.Before(before) {
		t.Fatalf("unset Cell.Now() = %v", got)
	}
}
