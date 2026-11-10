// report_test.go — SweepReport coverage: the emit/carry/find
// accumulation, the first-Infra-wins rule, the Pass/Infra/Why folding
// and the Close-time ledger reconcile (stale-tuple pruning).
package probefw

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

func testGauge() *prometheus.GaugeVec {
	return prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "probe_report_test", Help: "t",
	}, []string{"k"})
}

// recDelete returns a DeleteLabelValues-shaped func that records the
// tuples it was asked to drop.
func recDelete(deleted *[][]string) func(...string) bool {
	return func(lv ...string) bool {
		*deleted = append(*deleted, append([]string(nil), lv...))
		return true
	}
}

func TestSweepReportEmitFlagSetCarry(t *testing.T) {
	g := testGauge()
	var rep SweepReport

	rep.Emit(g, "a", []string{"a"}, "a(detail)")
	rep.Flag(g, "b", []string{"b"})
	rep.Set(g, 0.42, "c", []string{"c"})
	rep.Carry("d", []string{"d"})

	if got := testutil.ToFloat64(g.WithLabelValues("a")); got != 1 {
		t.Fatalf("Emit series = %v, want 1", got)
	}
	if got := testutil.ToFloat64(g.WithLabelValues("b")); got != 1 {
		t.Fatalf("Flag series = %v, want 1", got)
	}
	if got := testutil.ToFloat64(g.WithLabelValues("c")); got != 0.42 {
		t.Fatalf("Set series = %v, want 0.42", got)
	}
	// Carry registers the tuple without touching the gauge — the
	// series reads as never-set (0), not 1.
	if got := testutil.ToFloat64(g.WithLabelValues("d")); got != 0 {
		t.Fatalf("Carry series = %v, want 0 (no re-Set)", got)
	}
	if rep.Flagged() != 4 {
		t.Fatalf("Flagged = %d, want 4", rep.Flagged())
	}
	if len(rep.Findings()) != 1 || rep.Findings()[0] != "a(detail)" {
		t.Fatalf("Findings = %v, want [a(detail)]", rep.Findings())
	}
}

func TestSweepReportInfraErrFirstWins(t *testing.T) {
	var rep SweepReport
	rep.InfraErr(nil) // nil-safe no-op
	first := errors.New("first")
	rep.InfraErr(first)
	rep.InfraErr(errors.New("second"))
	rep.Find("f")
	res := rep.Verdict("why: ", ", ")
	if !errors.Is(res.Infra, first) {
		t.Fatalf("Infra = %v, want first error", res.Infra)
	}
}

func TestSweepReportVerdict(t *testing.T) {
	t.Run("empty is Pass", func(t *testing.T) {
		var rep SweepReport
		if res := rep.Verdict("why: ", ", "); !res.Pass || res.Why != "" || res.Infra != nil {
			t.Fatalf("got %+v, want bare Pass", res)
		}
	})
	t.Run("infra-only has no Why", func(t *testing.T) {
		var rep SweepReport
		rep.InfraErr(errors.New("boom"))
		res := rep.Verdict("why: ", ", ")
		if res.Pass || res.Why != "" || res.Infra == nil {
			t.Fatalf("got %+v, want Infra-only", res)
		}
	})
	t.Run("findings sort and join under the prefix", func(t *testing.T) {
		var rep SweepReport
		rep.Find("b(x)")
		rep.Find("a(y)")
		rep.InfraErr(errors.New("tolerated"))
		res := rep.Verdict("why: ", ", ")
		if res.Why != "why: a(y), b(x)" {
			t.Fatalf("Why = %q, want sorted join", res.Why)
		}
		if res.Infra == nil || res.Pass {
			t.Fatalf("Infra+Why must coexist: %+v", res)
		}
	})
	t.Run("custom separator", func(t *testing.T) {
		var rep SweepReport
		rep.Find("b")
		rep.Find("a")
		if res := rep.Verdict("w: ", " | "); res.Why != "w: a | b" {
			t.Fatalf("Why = %q, want \" | \" join", res.Why)
		}
	})
}

func TestSweepReportClosePrunesStale(t *testing.T) {
	var ledger state.GaugeLedger[string]
	// Seed last sweep: "old" emitted, rolled into emitted by a first
	// Reconcile.
	ledger.Reconcile(map[string][]string{"old": {"o"}}, func(...string) bool { return true })

	var rep SweepReport
	rep.register("new", []string{"n"})
	var deleted [][]string
	rep.Close(&ledger, recDelete(&deleted))

	if len(deleted) != 1 || deleted[0][0] != "o" {
		t.Fatalf("deleted = %v, want the stale \"old\" tuple", deleted)
	}
	if _, ok := ledger.Last()["new"]; !ok {
		t.Fatal("new tuple not rolled into the ledger")
	}
}

func TestSweepReportResultIsCloseThenVerdict(t *testing.T) {
	g := testGauge()
	var ledger state.GaugeLedger[string]
	var rep SweepReport
	rep.Emit(g, "k", []string{"k"}, "k(reason)")
	var deleted [][]string
	res := rep.Result(&ledger, recDelete(&deleted), "why: ", ", ")
	if res.Why != "why: k(reason)" || !res.Pass && res.Infra != nil {
		t.Fatalf("got %+v", res)
	}
	if len(deleted) != 0 {
		t.Fatalf("nothing stale — deleted = %v, want empty", deleted)
	}
	if got := testutil.ToFloat64(g.WithLabelValues("k")); got != 1 {
		t.Fatalf("series = %v, want 1", got)
	}
}

func TestSweepReportSortedClones(t *testing.T) {
	var rep SweepReport
	rep.Find("b")
	rep.Find("a")
	got := rep.Sorted()
	if got[0] != "a" {
		t.Fatalf("Sorted = %v", got)
	}
	// Sorted must not reorder the append-order Findings view.
	if rep.Findings()[0] != "b" {
		t.Fatalf("Sorted mutated findings: %v", rep.Findings())
	}
}
