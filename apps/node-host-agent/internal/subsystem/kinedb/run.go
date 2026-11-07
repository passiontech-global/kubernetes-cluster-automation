// run.go — the loop lifecycle: Run drives the three domain loops
// (probe/compact-guard/maint) through cycle.RunAll. The runtime
// helpers the cycle bodies share (exec budgets, container
// discovery, psql plumbing, textfile emission, the small
// parse/state-file utilities) moved to kdeps with the split.
package kinedb

import (
	"context"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
)

// Run starts the three loops (probe, compact guard, maintenance) and
// blocks until ctx is cancelled.
func (k *KineDB) Run(ctx context.Context) {
	// countPanic is the metric half of the old safeCycle — the
	// recover half moved into cycle.EverySafe, so a panicking round
	// counts cycles{loop,"panic"} and skips to the next interval
	// instead of unwinding the loop's goroutine.
	countPanic := func(loop string, _ any) {
		k.M.Cycles.WithLabelValues(loop, "panic").Inc()
	}
	cycle.RunAll(ctx,
		cycle.EverySafe("probe", k.Cfg.ProbeInterval,
			func(ctx context.Context) { k.probe.Cycle(ctx) }, countPanic),
		cycle.EverySafe("compact-guard", k.Cfg.GuardInterval,
			func(ctx context.Context) { k.guard.Cycle(ctx) }, countPanic),
		cycle.EverySafe("maint", k.Cfg.MaintInterval,
			func(ctx context.Context) { k.maint.Cycle(ctx) }, countPanic),
	)
}
