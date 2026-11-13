// report.go — SweepReport: the "sweep report tail" every
// emitted-gauge check hand-rolls. The shared shape is:
//
//	current := map[string][]string{}
//	var findings []string          // or unhealthy/wedged/...
//	for each flagged entity:
//		current[key] = lv
//		vec.WithLabelValues(lv...).Set(1)
//		findings = append(findings, detail)
//	p.emitted.Reconcile(current, vec.DeleteLabelValues)
//	if len(findings) == 0 { return Result{Pass: true} }
//	sort.Strings(findings)
//	return Result{Why: prefix + strings.Join(findings, ", ")}
//
// The methods are deliberately granular because the surveyed sites
// decouple the three halves: Emit is the common "tuple + series +
// finding" triplet, while Flag/Set/Carry/Find cover the split cases
// (a series with no finding, a measured value instead of a 1-flag, a
// carry-forward with no re-Set, a finding with no series at all).
// Close/Result fold the accumulated tuples into the check's
// state.GaugeLedger, Verdict folds the findings into the check's
// Result.
package probefw

import (
	"slices"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// SweepReport accumulates one sweep's flagged gauge tuples and
// finding strings, then closes out the emitted-gauge ledger and the
// check's Result. The zero value is ready — the sweep runs serially
// inside one goroutine, so nothing locks.
type SweepReport struct {
	current  map[string][]string // label tuples emitted this sweep
	findings []string            // finding strings for the Why line
	firstErr error               // first tolerated infra failure
}

// register records the label tuple the gauge series for key
// carries this sweep — Close prunes every held tuple the sweep did
// not re-assert.
func (r *SweepReport) register(key string, lv []string) {
	if r.current == nil {
		r.current = map[string][]string{}
	}
	r.current[key] = lv
}

// Emit is the common per-flagged-entity triplet: register the label
// tuple, set its series to 1, and record the finding detail.
func (r *SweepReport) Emit(gauge *prometheus.GaugeVec, key string,
	lv []string, detail string) {

	r.Flag(gauge, key, lv)
	r.Find(detail)
}

// Flag registers the label tuple and sets its series to 1 — an
// emit without a finding (the finding is computed elsewhere, or
// the flag is metric-only).
func (r *SweepReport) Flag(gauge *prometheus.GaugeVec, key string, lv []string) {
	r.Set(gauge, 1, key, lv)
}

// Set registers the label tuple and sets its series to value — the
// shape ratio/count gauges report (a measured value rather than a
// 1-flag), mirroring state.GaugeLedger.Set.
func (r *SweepReport) Set(gauge *prometheus.GaugeVec, value float64,
	key string, lv []string) {

	r.register(key, lv)
	gauge.WithLabelValues(lv...).Set(value)
}

// Carry registers a held tuple without touching the gauge — the
// carry-forward a check re-asserts when a signature was never
// evaluated this sweep: "can't tell" must not read as "resolved",
// or one API flap would prune live series.
func (r *SweepReport) Carry(key string, lv []string) {
	r.register(key, lv)
}

// Find appends one finding string — for findings decoupled from an
// emit (the entity carries no series, or its detail is computed
// away from the emit site).
func (r *SweepReport) Find(detail string) {
	r.findings = append(r.findings, detail)
}

// InfraErr records the first tolerated infra failure of the sweep —
// a partial-scan error the check absorbs (log + continue) but still
// reports on the Result. First non-nil wins.
func (r *SweepReport) InfraErr(err error) {
	if err != nil && r.firstErr == nil {
		r.firstErr = err
	}
}

// Flagged reports how many tuples are registered so far this
// sweep — the "did anything emit" count a post-reconcile heal
// block gates on.
func (r *SweepReport) Flagged() int {
	return len(r.current)
}

// Findings returns this sweep's finding strings in append order —
// for heal loops that iterate the flagged entities. Read-only.
func (r *SweepReport) Findings() []string {
	return r.findings
}

// Sorted returns this sweep's findings sorted — the deterministic
// join order the standard Why tail produces, exposed for custom Why
// builds and for heal loops that iterate findings.
func (r *SweepReport) Sorted() []string {
	out := slices.Clone(r.findings)
	slices.Sort(out)
	return out
}

// Close reconciles the emitted-gauge ledger: every tuple registered
// this sweep is emitted, and tuples held from last sweep that were
// not re-asserted go through delete — typically a
// *prometheus.GaugeVec's DeleteLabelValues, or a flip-to-zero
// method value when the check's contract keeps the resolved edge
// visible as a 0-series. Call once per sweep, after the last
// Emit/Flag/Set/Carry and only on a complete sweep — the ledger
// cannot tell "resolved" from "never evaluated".
func (r *SweepReport) Close(ledger *state.GaugeLedger[string],
	delete func(labelValues ...string) bool) {

	ledger.Reconcile(r.current, delete)
}

// Verdict folds the accumulated findings into the check's Result:
// no findings is a Pass — an Infra-only result when the sweep
// tolerated an infra error — otherwise the findings sort and join
// under whyPrefix (the byte-stable check contract), threading the
// tolerated error through as Result.Infra.
func (r *SweepReport) Verdict(whyPrefix, joinSep string) Result {
	if len(r.findings) == 0 {
		if r.firstErr != nil {
			return Result{Infra: r.firstErr}
		}
		return Result{Pass: true}
	}
	slices.Sort(r.findings)
	return Result{
		Infra: r.firstErr,
		Why:   whyPrefix + strings.Join(r.findings, joinSep),
	}
}

// Result is the standard sweep tail — Close the emitted-gauge
// ledger, then Verdict. A check whose tail is exactly
// "reconcile → pass-or-why" collapses to this one call.
func (r *SweepReport) Result(ledger *state.GaugeLedger[string],
	delete func(labelValues ...string) bool,
	whyPrefix, joinSep string) Result {

	r.Close(ledger, delete)
	return r.Verdict(whyPrefix, joinSep)
}
