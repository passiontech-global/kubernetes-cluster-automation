package shared

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
