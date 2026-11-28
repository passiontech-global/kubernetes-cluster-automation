package timex

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLivenessGraceAndStale(t *testing.T) {
	var now atomic.Int64
	l := NewLivenessWithClock(func() time.Duration {
		return time.Duration(now.Load())
	})

	// Empty registry is healthy.
	if err := l.Check(); err != nil {
		t.Fatalf("empty Check = %v, want nil", err)
	}

	b := l.RegisterWithGrace("sweep", 30*time.Second, 10*time.Second)
	if b.Name() != "sweep" || b.StaleAfter() != 10*time.Second {
		t.Fatalf("beat metadata = (%q, %v), want (sweep, 10s)", b.Name(), b.StaleAfter())
	}

	// Within initial 30s grace before first Beat: healthy.
	now.Store(int64(25 * time.Second))
	if err := l.Check(); err != nil {
		t.Fatalf("within grace Check = %v, want nil", err)
	}

	// Exceeding initial grace before first Beat: fails.
	now.Store(int64(31 * time.Second))
	err := l.Check()
	if err == nil || !strings.Contains(err.Error(), `"sweep"`) {
		t.Fatalf("past grace Check = %v, want stale error naming sweep", err)
	}

	// Recording a Beat switches to steady-state 10s staleAfter.
	b.Beat()
	if err := l.Check(); err != nil {
		t.Fatalf("fresh beat Check = %v, want nil", err)
	}

	now.Store(int64(40 * time.Second)) // 9s elapsed <= 10s
	if err := l.Check(); err != nil {
		t.Fatalf("within stale Check = %v, want nil", err)
	}

	now.Store(int64(42 * time.Second)) // 11s elapsed > 10s
	err = l.Check()
	if err == nil || !strings.Contains(err.Error(), `"sweep"`) {
		t.Fatalf("past stale Check = %v, want stale error naming sweep", err)
	}

	// Adaptive threshold increase clears staleness when within new budget.
	b.SetStaleAfter(15 * time.Second)
	if err := l.Check(); err != nil {
		t.Fatalf("after SetStaleAfter(15s) Check = %v, want nil", err)
	}

	// Unregister removes the beat cleanly (and is idempotent).
	l.Unregister(b)
	l.Unregister(b)
	if err := l.Check(); err != nil {
		t.Fatalf("after Unregister Check = %v, want nil", err)
	}
}

func TestLivenessFloorExemptAndNilSafe(t *testing.T) {
	var now atomic.Int64
	l := &Liveness{
		Floor: DefaultLivenessFloor,
		Now:   func() time.Duration { return time.Duration(now.Load()) },
	}
	b := l.Register("fast", 5*time.Second)
	if b.StaleAfter() != DefaultLivenessFloor {
		t.Fatalf("StaleAfter with Floor = %v, want %v", b.StaleAfter(), DefaultLivenessFloor)
	}
	now.Store(int64(10 * time.Minute))
	if err := l.Check(); err != nil {
		t.Fatalf("under Floor Check = %v, want nil", err)
	}
	now.Store(int64(16 * time.Minute))
	if err := l.Check(); err == nil {
		t.Fatal("past Floor Check = nil, want stale error")
	}

	// Exempt hides stale beats.
	l.Exempt()
	if !l.IsExempt() || l.Beats() != nil {
		t.Fatalf("Exempt state mismatch: IsExempt=%v Beats=%v", l.IsExempt(), l.Beats())
	}
	if err := l.Check(); err != nil {
		t.Fatalf("exempt Check = %v, want nil", err)
	}

	// Nil receivers are safe.
	var nilLive *Liveness
	var nilBeat *Beat
	nilBeat.Beat()
	nilBeat.SetStaleAfter(time.Second)
	if nilBeat.Name() != "" || nilBeat.StaleAfter() != 0 || nilBeat.Age() != 0 {
		t.Fatal("nil Beat accessors returned non-zero")
	}
	nilLive.Beat(nilBeat)
	nilLive.Unregister(nilBeat)
	nilLive.Exempt()
	if nilLive.Register("x", time.Second) != nil || nilLive.Check() != nil || nilLive.IsExempt() || nilLive.Beats() != nil {
		t.Fatal("nil Liveness methods misbehaved")
	}
}

func TestLivenessConcurrentRace(t *testing.T) {
	l := NewLiveness()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			b := l.Register("worker", 10*time.Second)
			for range 50 {
				l.Beat(b)
				_ = l.Check()
				_ = l.Beats()
				_ = b.Age()
			}
			if id%2 == 0 {
				l.Unregister(b)
			}
		}(i)
	}
	wg.Wait()
}
