// streak_test.go — the per-cycle Run bookkeeping the checks share:
// the k0sworker head gate, the Cycles{check,result} bumps and the
// consecutive-fail streak observer.
package wdeps_test

import (
	"strings"
	"testing"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// TestGated — the WD_REQUIRES: k0sworker head gate: active → run,
// inactive → gated counter bump and a true return (skip, not
// healthy).
func TestGated(t *testing.T) {
	e := fixture(t)
	active := &wdeps.CycleEnv{WorkerActive: true}
	if e.D.Gated(active, wdeps.CheckTeardown) {
		t.Fatal("active worker must not gate")
	}
	if got := promtestutil.ToFloat64(e.D.Cycles.WithLabelValues(wdeps.CheckTeardown, "gated")); got != 0 {
		t.Fatalf("gated counter=%d on active worker", int(got))
	}

	down := &wdeps.CycleEnv{WorkerActive: false}
	if !e.D.Gated(down, wdeps.CheckTeardown) {
		t.Fatal("down worker must gate")
	}
	if !e.D.Gated(down, wdeps.CheckTeardown) {
		t.Fatal("second down cycle must gate again")
	}
	if got := promtestutil.ToFloat64(e.D.Cycles.WithLabelValues(wdeps.CheckTeardown, "gated")); got != 2 {
		t.Fatalf("gated counter=%d want 2", int(got))
	}
	// The counter is per check — another check's verdicts stay put.
	if got := promtestutil.ToFloat64(e.D.Cycles.WithLabelValues(wdeps.CheckDNS, "gated")); got != 0 {
		t.Fatalf("cross-check leak: %d", int(got))
	}
}

// TestCycleResult — the verdict label bump lands on the right
// {check,result} pair.
func TestCycleResult(t *testing.T) {
	e := fixture(t)
	e.D.CycleResult(wdeps.CheckStall, "ok")
	e.D.CycleResult(wdeps.CheckStall, "ok")
	e.D.CycleResult(wdeps.CheckStall, "abort")
	if got := promtestutil.ToFloat64(e.D.Cycles.WithLabelValues(wdeps.CheckStall, "ok")); got != 2 {
		t.Fatalf("ok counter=%d want 2", int(got))
	}
	if got := promtestutil.ToFloat64(e.D.Cycles.WithLabelValues(wdeps.CheckStall, "abort")); got != 1 {
		t.Fatalf("abort counter=%d want 1", int(got))
	}
}

// TestStreakPending — below the budget it advances the streak with
// the shared " (check %d/%d)" suspect marker and holds the caller;
// at the budget it releases with no extra line (the latch tail is
// the caller's).
func TestStreakPending(t *testing.T) {
	e := fixture(t)
	fails := 0
	if !e.D.StreakPending(&fails, "cilium healthz down") {
		t.Fatal("first failure must stay pending")
	}
	if fails != 1 {
		t.Fatalf("fails=%d want 1", fails)
	}
	if got := strings.Count(e.LogLines(t), "cilium healthz down (check 1/2)"); got != 1 {
		t.Fatalf("progress lines=%d want 1:\n%s", got, e.LogLines(t))
	}
	// ConsecNeeded=2 in the fixture: the second failure releases.
	if e.D.StreakPending(&fails, "cilium healthz down") {
		t.Fatal("streak at budget must release")
	}
	if fails != 2 {
		t.Fatalf("fails=%d want 2", fails)
	}
	// Past the budget: no new line, still released.
	if e.D.StreakPending(&fails, "cilium healthz down") {
		t.Fatal("past budget must release")
	}
	if fails != 3 || strings.Count(e.LogLines(t), "cilium healthz down") != 1 {
		t.Fatalf("fails=%d lines:\n%s", fails, e.LogLines(t))
	}

	// A streak already at the budget releases without a marker line.
	fresh := 2
	if e.D.StreakPending(&fresh, "other check") {
		t.Fatal("at-budget fresh streak must release")
	}
}
