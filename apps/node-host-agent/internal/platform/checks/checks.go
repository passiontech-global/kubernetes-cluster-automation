// Package checks is the shared ordered-check dispatcher the
// subsystem Cycles used to hand-roll: workerhygiene's
// initChecks-driven loop (per-check WD_SIG_<NAME> kill switch,
// skipped checks counted cycles{check,"disabled"}) and
// nethealth's/controllerhygiene's inline if-chains (the same kill
// switch plus a whole-group WD_REQUIRES:uptime gate counted
// "uptime_gate").
//
// Declared check ORDER inside a Group and group order inside the
// table are load-bearing — they preserve the shell runner's module
// order; Dispatch iterates strictly in declaration order. The
// result label strings are the observable contract (prometheus
// `result` label values + the WD_SIG_<NAME> keys the conf applies),
// so they are exported constants here instead of being re-typed at
// every call site.
//
// Platform packages stay leaf: only context + prometheus.
package checks

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
)

// Result label values the dispatcher counts on the subsystem's
// {check,result} cycles CounterVec — the exact strings the
// per-subsystem dispatch blocks counted before the helper existed.
const (
	// ResultDisabled counts a check skipped by its WD_SIG_<NAME>
	// kill switch.
	ResultDisabled = "disabled"
	// ResultUptimeGate counts a check skipped by its group's
	// uptime gate (WD_REQUIRES:uptime — the post-boot grace).
	ResultUptimeGate = "uptime_gate"
)

// Entry is one ordered check in a Group. Name is BOTH the
// prometheus `check` label and the WD_SIG_<NAME> kill-switch key —
// it must equal the check* constant the subsystem already uses so
// latch names, metric label values and kill switches stay
// identical. Run executes one round and must never panic (the
// check contract).
type Entry struct {
	Name string
	Run  func(context.Context)
}

// Group is an ordered run of entries sharing one group gate — the
// WD_REQUIRES:uptime grace covering a whole module family. A group
// with a nil GateOK is ungated: its entries still pass through the
// per-check kill switch.
type Group struct {
	// GateOK, when non-nil, decides whether the group runs this
	// cycle: false skips EVERY entry and counts the uptime gate
	// instead of running them.
	GateOK func() bool
	// GateLabel is the `check` label a failed gate counts ONCE
	// under ResultUptimeGate (controllerhygiene's hub gate — the
	// skip is attributed to the gated module). "" counts every
	// entry under its own Name instead (nethealth's paired DNS
	// gate counts dns-fallback AND coredns-stub).
	GateLabel string
	// Entries run in declaration order while the gate is open.
	Entries []Entry
}

// Dispatch runs every group in declaration order. A gated-out
// group counts the uptime gate and runs nothing. Inside an open
// group each entry consults sigOn — the WD_SIG_<NAME> kill-switch
// predicate; nil means no kill switch at all (the controllerhygiene
// contract — its shell timers carried none) and every entry runs.
// An entry whose switch is off counts ResultDisabled and is
// skipped. cycles is the subsystem's own CounterVec so metric
// names stay per-subsystem.
func Dispatch(ctx context.Context, sigOn func(string) bool,
	cycles *prometheus.CounterVec, groups []Group) {
	for _, g := range groups {
		if g.GateOK != nil && !g.GateOK() {
			if g.GateLabel != "" {
				cycles.WithLabelValues(g.GateLabel, ResultUptimeGate).Inc()
			} else {
				for _, e := range g.Entries {
					cycles.WithLabelValues(e.Name, ResultUptimeGate).Inc()
				}
			}
			continue
		}
		for _, e := range g.Entries {
			if sigOn == nil || sigOn(e.Name) {
				e.Run(ctx)
			} else {
				cycles.WithLabelValues(e.Name, ResultDisabled).Inc()
			}
		}
	}
}
