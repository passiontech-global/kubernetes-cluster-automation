package testutil

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

// RunPeriodic fires the registered Periodic's Fn exactly once and
// hands its error back untouched — the error-metric contract depends
// on the raw return (Start would IncError it, Fn does not).
func TestRunPeriodic(t *testing.T) {
	m := NewStubManager()
	ran := 0
	wantErr := errors.New("sweep blew up")
	if err := m.Add(&shared.Periodic{
		Name:     "test-sweep",
		Interval: time.Minute,
		Fn: func(ctx context.Context) error {
			ran++
			if ctx == nil {
				t.Error("fn received nil ctx")
			}
			return wantErr
		},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}

	err := RunPeriodic(t, m, context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("RunPeriodic err = %v, want %v", err, wantErr)
	}
	if ran != 1 {
		t.Fatalf("fn ran %d times, want 1", ran)
	}
}

// A clean sweep returns nil — the common-case assertion shape.
func TestRunPeriodicNilError(t *testing.T) {
	m := NewStubManager()
	if err := m.Add(&shared.Periodic{
		Name:     "test-sweep",
		Interval: time.Minute,
		Fn:       func(context.Context) error { return nil },
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := RunPeriodic(t, m, Ctx); err != nil {
		t.Fatalf("RunPeriodic: %v", err)
	}
}

// InvokeSweep passes a nil-error fn straight through — the
// `if err := x.run(ctx); err != nil { t.Fatal(err) }` one-liner.
func TestInvokeSweep(t *testing.T) {
	InvokeSweep(t, func(context.Context) error { return nil }, Ctx)
}

// Ctx is a usable background context, not a nil or cancelled one.
func TestCtx(t *testing.T) {
	if Ctx == nil {
		t.Fatal("Ctx is nil")
	}
	if err := Ctx.Err(); err != nil {
		t.Fatalf("Ctx.Err() = %v, want nil", err)
	}
}
