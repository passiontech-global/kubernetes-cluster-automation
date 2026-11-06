package reap

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/go-logr/logr"
)

var ctx = context.Background()

// rec records the per-item call sequence Sweep makes — the order of
// LogTarget/Delete/OnError invocations is the observable contract
// the hand-rolled loops had (ACTION line, then the attempt).
type rec struct {
	calls   []string // e.g. "log:b", "del:a", "err:c"
	delErrs map[string]error
}

func (r *rec) target() func(logr.Logger, string) {
	return func(_ logr.Logger, it string) { r.calls = append(r.calls, "log:"+it) }
}

func (r *rec) delete() func(context.Context, string) error {
	return func(_ context.Context, it string) error {
		r.calls = append(r.calls, "del:"+it)
		if err := r.delErrs[it]; err != nil {
			return err
		}
		return nil
	}
}

func (r *rec) onErr() func(logr.Logger, string, error) {
	return func(_ logr.Logger, it string, _ error) {
		r.calls = append(r.calls, "err:"+it)
	}
}

// The basic loop: every item logs then deletes; tally returns so the
// caller can emit its own "sweep done" line.
func TestSweepDeletesEach(t *testing.T) {
	r := &rec{}
	deleted, failed, capped := Sweep(ctx, logr.Discard(),
		[]string{"a", "b", "c"}, Options[string]{
			LogTarget: r.target(), Delete: r.delete(), OnError: r.onErr(),
		})
	if deleted != 3 || failed != 0 || capped {
		t.Fatalf("Sweep = (%d,%d,%v), want (3,0,false)", deleted, failed, capped)
	}
	want := []string{"log:a", "del:a", "log:b", "del:b", "log:c", "del:c"}
	if !slices.Equal(r.calls, want) {
		t.Fatalf("calls = %v, want %v", r.calls, want)
	}
}

// Less runs before the cap: the deterministic-victims rule — a
// capped sweep reaps the same candidates every cycle, not the
// apiserver's order.
func TestSweepSortsBeforeCap(t *testing.T) {
	r := &rec{}
	items := []string{"c", "a", "b"}
	deleted, _, capped := Sweep(ctx, logr.Discard(), items, Options[string]{
		Cap:       2,
		Less:      func(a, b string) bool { return a < b },
		LogTarget: r.target(), Delete: r.delete(),
	})
	if deleted != 2 || !capped {
		t.Fatalf("Sweep = (%d,_,%v), want (2,_,true)", deleted, capped)
	}
	want := []string{"log:a", "del:a", "log:b", "del:b"}
	if !slices.Equal(r.calls, want) {
		t.Fatalf("calls = %v, want %v", r.calls, want)
	}
	// The caller's slice is sorted in place — the deterministic
	// order is observable to post-sweep bookkeeping too.
	if !slices.Equal(items, []string{"a", "b", "c"}) {
		t.Fatalf("items not sorted in place: %v", items)
	}
}

// The cap counts ATTEMPTS, not just delivered deletes — a rejected
// delete churns the apiserver the same way a delivered one does.
// Exactly Cap calls happen even when every delete errors.
func TestSweepCapCountsFailedAttempts(t *testing.T) {
	r := &rec{delErrs: map[string]error{
		"a": errors.New("rejected"), "b": errors.New("rejected")}}
	deleted, failed, capped := Sweep(ctx, logr.Discard(),
		[]string{"a", "b", "c"}, Options[string]{
			Cap:       2,
			LogTarget: r.target(), Delete: r.delete(), OnError: r.onErr(),
		})
	if deleted != 0 || failed != 2 || !capped {
		t.Fatalf("Sweep = (%d,%d,%v), want (0,2,true)", deleted, failed, capped)
	}
	want := []string{"log:a", "del:a", "err:a", "log:b", "del:b", "err:b"}
	if !slices.Equal(r.calls, want) {
		t.Fatalf("calls = %v, want %v", r.calls, want)
	}
}

// Cap=0 is unlimited — the small-fleet shape.
func TestSweepNoCap(t *testing.T) {
	r := &rec{}
	items := make([]string, 20)
	for i := range items {
		items[i] = string(rune('a' + i))
	}
	deleted, _, capped := Sweep(ctx, logr.Discard(), items,
		Options[string]{Delete: r.delete()})
	if deleted != 20 || capped {
		t.Fatalf("Sweep = (%d,_,%v), want (20,_,false)", deleted, capped)
	}
}

// Exactly-at-cap is NOT capped: the loop only reports capped when
// items remain unprocessed.
func TestSweepExactlyAtCapNotCapped(t *testing.T) {
	r := &rec{}
	_, _, capped := Sweep(ctx, logr.Discard(),
		[]string{"a", "b"}, Options[string]{Cap: 2, Delete: r.delete()})
	if capped {
		t.Fatal("capped=true with no remaining items")
	}
}

// Confirm vetoes an item quietly — no log line, no delete, no cap
// spend (the orphan-slice "owner actually exists" re-check shape).
func TestSweepConfirmSkips(t *testing.T) {
	r := &rec{}
	skip := map[string]bool{"b": true}
	deleted, failed, capped := Sweep(ctx, logr.Discard(),
		[]string{"a", "b", "c"}, Options[string]{
			Confirm: func(_ context.Context, it string) (bool, error) {
				return !skip[it], nil
			},
			LogTarget: r.target(), Delete: r.delete(), OnError: r.onErr(),
		})
	if deleted != 2 || failed != 0 || capped {
		t.Fatalf("Sweep = (%d,%d,%v), want (2,0,false)", deleted, failed, capped)
	}
	want := []string{"log:a", "del:a", "log:c", "del:c"}
	if !slices.Equal(r.calls, want) {
		t.Fatalf("calls = %v, want %v", r.calls, want)
	}
}

// A Confirm error keeps the item (fail closed), reports through
// OnError, and does NOT spend the cap — no delete was attempted.
func TestSweepConfirmErrorKeepsItem(t *testing.T) {
	r := &rec{}
	confErr := errors.New("get failed")
	deleted, failed, capped := Sweep(ctx, logr.Discard(),
		[]string{"a", "b", "c"}, Options[string]{
			Cap: 2,
			Confirm: func(_ context.Context, it string) (bool, error) {
				if it == "a" {
					return false, confErr
				}
				return true, nil
			},
			LogTarget: r.target(), Delete: r.delete(), OnError: r.onErr(),
		})
	// "a" errored on confirm (kept), b+c deleted — the cap of 2 was
	// spent on real deletes, so a 4th item would have been capped.
	if deleted != 2 || failed != 0 || capped {
		t.Fatalf("Sweep = (%d,%d,%v), want (2,0,false)", deleted, failed, capped)
	}
	want := []string{"err:a", "log:b", "del:b", "log:c", "del:c"}
	if !slices.Equal(r.calls, want) {
		t.Fatalf("calls = %v, want %v", r.calls, want)
	}
}

// A Delete error reports through OnError and moves on — per-item
// failure must not starve the rest of the sweep.
func TestSweepDeleteErrorContinues(t *testing.T) {
	r := &rec{delErrs: map[string]error{"b": errors.New("conflict")}}
	deleted, failed, capped := Sweep(ctx, logr.Discard(),
		[]string{"a", "b", "c"}, Options[string]{
			LogTarget: r.target(), Delete: r.delete(), OnError: r.onErr(),
		})
	if deleted != 2 || failed != 1 || capped {
		t.Fatalf("Sweep = (%d,%d,%v), want (2,1,false)", deleted, failed, capped)
	}
	want := []string{"log:a", "del:a", "log:b", "del:b", "err:b",
		"log:c", "del:c"}
	if !slices.Equal(r.calls, want) {
		t.Fatalf("calls = %v, want %v", r.calls, want)
	}
}

// Nil Confirm/LogTarget/OnError are all legal — a bare cap+delete
// sweep still tallies correctly.
func TestSweepNilHooks(t *testing.T) {
	var dels int
	deleted, failed, _ := Sweep(ctx, logr.Discard(),
		[]string{"a", "b"}, Options[string]{
			Delete: func(context.Context, string) error {
				dels++
				return errors.New("down")
			},
		})
	if deleted != 0 || failed != 2 || dels != 2 {
		t.Fatalf("Sweep = (%d,%d) dels=%d, want (0,2) dels=2",
			deleted, failed, dels)
	}
}
