// liveness_test.go — unit tests for Beat.StaleAfter, Liveness
// child Attach/detach, Exempt propagation, and Fallbacks aggregation.
package cycle

import (
	"context"
	"testing"
	"time"
)

func TestBeatStaleAfter(t *testing.T) {
	var b Beat
	if got := b.StaleAfter(); got != 0 {
		t.Fatalf("unset StaleAfter() = %v, want 0", got)
	}
	b.MaxStaleNanos.Store(int64(25 * time.Minute))
	if got := b.StaleAfter(); got != 25*time.Minute {
		t.Fatalf("StaleAfter() = %v, want 25m", got)
	}
}

func TestLivenessAttachAndDetach(t *testing.T) {
	parent := NewLiveness()
	child := NewLiveness()

	b1 := parent.RegisterLoop("parent", time.Minute, time.Minute)
	b2 := child.RegisterLoop("child", time.Hour, time.Minute)

	detach := parent.Attach(child)
	// Attaching the same child twice is a no-op.
	dupDetach := parent.Attach(child)

	if got := parent.LoopCount(); got != 2 {
		t.Fatalf("LoopCount() = %d, want 2", got)
	}
	beats := parent.LoopBeats()
	if len(beats) != 2 || beats[0] != b1 || beats[1] != b2 {
		t.Fatalf("LoopBeats() = %v, want [%p, %p]", beats, b1, b2)
	}

	// Duplicate detach must not remove the child.
	dupDetach()
	if got := parent.LoopCount(); got != 2 {
		t.Fatalf("LoopCount() after dupDetach = %d, want 2", got)
	}

	// Real detach removes the child.
	detach()
	if got := parent.LoopCount(); got != 1 {
		t.Fatalf("LoopCount() after detach = %d, want 1", got)
	}
}

func TestLivenessExempt(t *testing.T) {
	parent := NewLiveness()
	child := NewLiveness()
	parent.RegisterLoop("p", time.Minute, time.Minute)
	child.RegisterLoop("c", time.Minute, time.Minute)
	parent.Attach(child)

	if parent.IsExempt() || child.IsExempt() {
		t.Fatal("new registries must not be exempt")
	}

	// Exempting child hides only child's loops.
	child.Exempt()
	if !child.IsExempt() {
		t.Fatal("child.IsExempt() = false after Exempt()")
	}
	if got := parent.LoopCount(); got != 1 {
		t.Fatalf("LoopCount() with exempt child = %d, want 1", got)
	}

	// Exempting parent hides the entire subtree.
	Exempt(WithLiveness(context.Background(), parent))
	if !parent.IsExempt() {
		t.Fatal("parent.IsExempt() = false after Exempt(ctx)")
	}
	if got := parent.LoopCount(); got != 0 {
		t.Fatalf("LoopCount() with exempt parent = %d, want 0", got)
	}
	if beats := parent.LoopBeats(); beats != nil {
		t.Fatalf("LoopBeats() with exempt parent = %v, want nil", beats)
	}
	// Exempt(plainCtx) is a safe no-op.
	Exempt(context.Background())
}

func TestLivenessFallbacks(t *testing.T) {
	// Empty registry returns its own fallback beat.
	root := NewLiveness()
	if fbs := root.Fallbacks(); len(fbs) != 1 || fbs[0] != root.Fallback() {
		t.Fatalf("empty root Fallbacks() = %v, want [%p]", fbs, root.Fallback())
	}

	// Child with no loops + empty root: root+children have 0 loops total,
	// so root's own fallback represents the scope.
	childNoLoop := NewLiveness()
	root.Attach(childNoLoop)
	if fbs := root.Fallbacks(); len(fbs) != 1 || fbs[0] != root.Fallback() {
		t.Fatalf("root+empty child Fallbacks() = %v, want [%p]", fbs, root.Fallback())
	}

	// Add a second child WITH a loop: now root has childLoops > 0, so
	// root recurses — childWithLoop has a loop (no fallback),
	// childNoLoop has no loops (its fallback is returned).
	childWithLoop := NewLiveness()
	childWithLoop.RegisterLoop("worker", time.Minute, time.Minute)
	root.Attach(childWithLoop)
	fbs := root.Fallbacks()
	if len(fbs) != 1 || fbs[0] != childNoLoop.Fallback() {
		t.Fatalf("mixed children Fallbacks() = %v, want [%p]", fbs, childNoLoop.Fallback())
	}

	// Exempt childNoLoop -> skipped, no fallbacks left.
	childNoLoop.Exempt()
	if fbs := root.Fallbacks(); len(fbs) != 0 {
		t.Fatalf("after childNoLoop.Exempt(), Fallbacks() = %v, want empty", fbs)
	}
}

func TestLivenessUnregister(t *testing.T) {
	l := NewLiveness()
	l.Unregister(nil) // safe no-op
	b := l.RegisterLoop("a", time.Minute, time.Minute)
	if l.LoopCount() != 1 {
		t.Fatalf("LoopCount() = %d, want 1", l.LoopCount())
	}
	l.Unregister(b)
	if l.LoopCount() != 0 {
		t.Fatalf("LoopCount() after Unregister = %d, want 0", l.LoopCount())
	}
	// Double-unregister is a safe no-op.
	l.Unregister(b)
}
