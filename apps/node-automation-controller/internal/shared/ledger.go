// ledger.go — GaugeLedger: the emit-once-prune-on-resolve bookkeeping
// every "seen*" gauge series hand-rolls. The pattern repeated across
// velerobackupauditor (seenPaused/seenBad/seenBSL/seenEverest/
// seenStuckBackup/seenWedgedPVB), cert-drift-auditor (seenWebhooks/
// seenSecrets/seenWebhookExpiry/seenTrustBundles/seenReplication),
// failed-jobs-janitor (stuckEmitted), cronjob-catchup (missedEmitted),
// the webhook guard (brokenEmitted/unmeshedEmitted) and
// cluster-health-probes' reconcileEmittedGauges:
//
//	sweep:    for each live condition -> vec.WithLabelValues(lv...).Set(v)
//	end:      for each tuple emitted LAST sweep but not re-asserted
//	          this sweep -> vec.DeleteLabelValues(lv...)   // resolved
//	          series must disappear, not pin at their last value
//
// A GaugeLedger[K] owns exactly that state for ONE gauge vec: K is
// the module's dedup key (a struct of the label fields, or a joined
// string), []string the exact label values DeleteLabelValues needs —
// storing them means no caller ever SplitN's a key back apart.
//
// Adoption contract — Prune ONLY after a complete, verified sweep:
// the ledger cannot tell "condition resolved" from "object never
// evaluated", so pruning on a partial/failed read would delete live
// series (every existing implementation returns before its prune on
// list errors for exactly this reason).
package shared

import "slices"

// GaugeLedger[K comparable] tracks which label-value tuples of one
// gauge were emitted during the previous sweep versus the current
// one. The zero value is ready to use — Emit allocates lazily, so
// modules constructed literally in tests need no Setup path (the
// same lazy-arm convention as the nowFn clock seams).
type GaugeLedger[K comparable] struct {
	emitted map[K][]string // tuples emitted during the PREVIOUS sweep
	current map[K][]string // tuples emitted so far THIS sweep
}

// Emit records that the gauge series for key exists after this sweep
// — call it wherever the module does vec.WithLabelValues(lv...).Set
// (a series Set to 0 still exists and still counts as emitted; only
// tuples never touched get pruned). labelValues are the exact values
// passed to WithLabelValues, cloned so a caller mutating its slice
// afterwards cannot corrupt the ledger.
func (l *GaugeLedger[K]) Emit(key K, labelValues ...string) {
	if l.current == nil {
		l.current = map[K][]string{}
	}
	l.current[key] = slices.Clone(labelValues)
}

// Prune deletes — through delete, typically a *prometheus.GaugeVec's
// DeleteLabelValues method value (its bool "series existed" return
// is ignored) — every tuple emitted last sweep that Emit did not see
// this sweep, then rolls current into emitted. Call once per sweep,
// after all Emits. Returns the number of tuples pruned (handy for
// the "sweep done" log line). Pruning an empty ledger is a no-op.
func (l *GaugeLedger[K]) Prune(delete func(labelValues ...string) bool) int {
	pruned := 0
	for k, lv := range l.emitted {
		if _, ok := l.current[k]; ok {
			continue
		}
		delete(lv...)
		pruned++
	}
	l.emitted = l.current
	l.current = nil
	return pruned
}

// Last returns the tuples emitted during the previous sweep — a
// READ-ONLY view for carry-forward: when a condition is unverifiable
// this sweep (transient lookup miss, "can't tell" not "clean"),
// callers re-Emit the matching keys so Prune keeps their series
// instead of flapping the alert off. Do not mutate the returned map
// or its slices; Emit clones on the way in.
func (l *GaugeLedger[K]) Last() map[K][]string {
	return l.emitted
}
