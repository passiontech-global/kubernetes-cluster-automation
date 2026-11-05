// sweep.go — the sweep-invocation helpers every module test repeats:
// a shared background context and the fail-on-error one-liner for the
// unexported run(ctx)/sweep(ctx) methods module tests call directly.
package testutil

import (
	"context"
	"testing"
)

// Ctx is the context.Background() every module helpers_test.go
// re-declares as `var ctx` — sweep/run call sites all take a ctx, and
// a shared one lets the per-package boilerplate file shrink to
// nothing once call sites adopt it.
var Ctx = context.Background()

// InvokeSweep runs a module sweep fn once and fails the test on a
// non-nil return — the one-line form of the
// `if err := x.run(ctx); err != nil { t.Fatal(err) }` boilerplate
// repeated across ~30 module test packages. The fn argument is
// normally the module's unexported run/sweep method value
// (testutil.InvokeSweep(t, a.run, ctx)); tests asserting ON an
// expected error keep the explicit check — or use RunPeriodic, which
// returns fn's error for exactly that.
func InvokeSweep(t *testing.T, fn func(context.Context) error, ctx context.Context) {
	t.Helper()
	if err := fn(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}
}
