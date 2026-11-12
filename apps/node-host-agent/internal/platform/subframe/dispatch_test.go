package subframe_test

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
)

func newCycles() *prometheus.CounterVec {
	return prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "test_cycles_total",
		Help: "test",
	}, []string{"check", "result"})
}

// ran records execution order across all entries.
type recorder struct{ order []string }

func (r *recorder) entry(name string) subframe.Entry {
	return subframe.Entry{Name: name, Run: func(context.Context) {
		r.order = append(r.order, name)
	}}
}

func TestDispatchRunsInOrderAndCountsDisabled(t *testing.T) {
	var r recorder
	cycles := newCycles()
	sigOff := map[string]bool{"b": true}
	sigOn := func(n string) bool { return !sigOff[n] }
	subframe.Dispatch(context.Background(), sigOn, cycles, []subframe.Group{
		{Entries: []subframe.Entry{r.entry("a"), r.entry("b"), r.entry("c")}},
		{Entries: []subframe.Entry{r.entry("d")}},
	})
	if got := r.order; len(got) != 3 || got[0] != "a" || got[1] != "c" || got[2] != "d" {
		t.Fatalf("ran %v — want [a c d]", got)
	}
	if v := testutil.ToFloat64(cycles.WithLabelValues("b", subframe.ResultDisabled)); v != 1 {
		t.Fatalf("cycles{b,disabled}=%v want 1", v)
	}
}

func TestDispatchGroupGateCountsEachEntry(t *testing.T) {
	var r recorder
	cycles := newCycles()
	subframe.Dispatch(context.Background(), nil, cycles, []subframe.Group{
		{
			GateOK:  func() bool { return false },
			Entries: []subframe.Entry{r.entry("a"), r.entry("b")},
		},
		{Entries: []subframe.Entry{r.entry("c")}},
	})
	if len(r.order) != 1 || r.order[0] != "c" {
		t.Fatalf("ran %v — want [c]", r.order)
	}
	for _, name := range []string{"a", "b"} {
		if v := testutil.ToFloat64(cycles.WithLabelValues(name, subframe.ResultUptimeGate)); v != 1 {
			t.Fatalf("cycles{%s,uptime_gate}=%v want 1", name, v)
		}
	}
}

func TestDispatchGroupGateLabelCountsOnce(t *testing.T) {
	var r recorder
	cycles := newCycles()
	subframe.Dispatch(context.Background(), nil, cycles, []subframe.Group{
		{
			GateOK:    func() bool { return false },
			GateLabel: "hub",
			Entries:   []subframe.Entry{r.entry("a"), r.entry("b")},
		},
	})
	if len(r.order) != 0 {
		t.Fatalf("ran %v — want nothing", r.order)
	}
	if v := testutil.ToFloat64(cycles.WithLabelValues("hub", subframe.ResultUptimeGate)); v != 1 {
		t.Fatalf("cycles{hub,uptime_gate}=%v want 1", v)
	}
	if v := testutil.ToFloat64(cycles.WithLabelValues("b", subframe.ResultUptimeGate)); v != 0 {
		t.Fatalf("cycles{b,uptime_gate}=%v want 0 — GateLabel counts once", v)
	}
}

func TestDispatchNilSigOnRunsEverything(t *testing.T) {
	var r recorder
	subframe.Dispatch(context.Background(), nil, newCycles(), []subframe.Group{
		{Entries: []subframe.Entry{r.entry("a"), r.entry("b")}},
	})
	if len(r.order) != 2 || r.order[0] != "a" || r.order[1] != "b" {
		t.Fatalf("ran %v — want [a b]", r.order)
	}
}
