// suspect.go — the suspect-log dedupe concern: the
// last-suspect-<key> budget family, its Exit/Clear helpers and the
// throttled SuspectLog emitter. The budgets ride the same epoch
// file convention as the action budgets (budgets.go).

package hoststate

import (
	"os"
	"path/filepath"
	"time"
)

// --- suspect-log dedupe ---

// SuspectBudgetPrefix prefixes the suspect-log dedupe budgets:
// last-suspect-<key> epoch files spent at most once per cadence —
// the same rateOK/last-* convention as the action budgets.
const SuspectBudgetPrefix = "last-suspect-"

// ExitClearSuspect is Exit plus removal of this latch's suspect-log
// dedupe budget (last-suspect-<name>): the budget is spent under the
// Store's own dir by SuspectLog, and a cleared condition must not
// suppress the first line of a re-incident under a stale epoch from
// the previous one.
func (s *Store) ExitClearSuspect(name string) {
	s.Exit(name, func() { s.ClearSuspect(name) })
}

// ExitClearAllSuspects is Exit plus removal of the WHOLE
// last-suspect-* family — a latch exit IS an incident boundary. The
// NON-latch keys (egress-probe-<ip>, conntrack-parse, ...) have no
// state-* twin to exit with, so a cleared condition would otherwise
// suppress the first line of a re-incident for up to the suspect
// cadence. No clean per-key pairing exists; a still-held condition
// pays at most one early re-log line.
func (s *Store) ExitClearAllSuspects(name string) {
	s.Exit(name, func() { s.ClearAllSuspects() })
}

// ClearSuspect drops the last-suspect-<name> dedupe budget so the
// next SuspectLog for the key logs immediately. Best-effort: an
// absent budget is already clear, but a failed remove would
// silently keep suppressing a re-incident's first line — surfaced
// at Debug so operators tracing a latch have the evidence without
// spamming steady-state logs.
func (s *Store) ClearSuspect(name string) {
	if err := os.Remove(filepath.Join(s.Dir,
		SuspectBudgetPrefix+name)); err != nil && !os.IsNotExist(err) {
		s.log().Debug("hoststate: failed to clear suspect budget",
			"key", name, "error", err)
	}
}

// ClearAllSuspects drops every last-suspect-* dedupe budget in the
// Store's dir — best-effort like ClearSuspect, with the same Debug
// surfacing of failed removes.
func (s *Store) ClearAllSuspects() {
	files, err := filepath.Glob(filepath.Join(s.Dir, SuspectBudgetPrefix+"*"))
	if err != nil {
		s.log().Debug("hoststate: failed to list suspect budgets",
			"error", err)
		return
	}
	for _, f := range files {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			s.log().Debug("hoststate: failed to clear suspect budget",
				"key", filepath.Base(f), "error", err)
		}
	}
}

// SuspectLog emits msg at most once per cadence per key — a
// last-suspect-<key> epoch file under the same rateOK/rateSpend
// convention as the action budgets. It replaces the per-cycle
// AppendLog for lines whose condition persists: STATE-ENTER still
// announces the transition and a cadence re-reminder keeps a
// long-held condition visible in the tail. Counters, latches and
// metrics keep updating every cycle — only the LOG line is throttled.
// The check+spend is atomic (RateTrySpend): two goroutines hitting
// the same key in one window must not both pass the check and both
// log — the budget is spent exactly once, by whoever wins.
func (s *Store) SuspectLog(key, msg string, cadence time.Duration) {
	if !s.RateTrySpend(SuspectBudgetPrefix+key, cadence) {
		return
	}
	s.AppendLog(msg)
}
