// Package checkkit is the shared per-check bookkeeping primitives
// the subsystem checks used to hand-roll: the consecutive-failure
// streak advance with the standard " (check n/needed)" progress
// suffix every suspect line carries, plus the plain Progress
// formatter for the sites whose streak counters or log shapes are
// too bespoke for the full Pending path (per-key maps, file-backed
// consecutive-* counters, mid-line suffix positions, mutex-guarded
// per-peer state).
//
// Platform packages stay leaf: fmt only.
package checkkit

import "fmt"

// Progress is the standard streak-progress suffix — " (check
// n/needed)" — every consecutive-failure suspect line carries. It
// is the observable log contract runbooks and dashboards parse, so
// the spelling is owned here once instead of being re-typed at
// each call site.
func Progress(n, needed int) string {
	return fmt.Sprintf(" (check %d/%d)", n, needed)
}

// Pending advances a consecutive-failure streak by one and reports
// whether the streak is still below needed. While pending it emits
// line+Progress through logf (nil logf counts silently) and returns
// true — the caller counts its cycle result and returns without
// touching latches or remedies. Once the streak reaches needed it
// returns false and the caller proceeds to its latch/remedy tail.
// Pending never resets the counter — the confirmed path owns that
// (and the healthy path resets it its own way: Exit vs ExitFrom,
// which latch, counter order).
//
// The line must be everything BEFORE the progress suffix — callers
// whose suspect line embeds the marker mid-format (followed by
// ": err (...)" tails) keep their fmt verbatim and use Progress
// directly instead.
func Pending(needed int, n *int, line string, logf func(string)) bool {
	*n++
	if *n < needed {
		if logf != nil {
			logf(line + Progress(*n, needed))
		}
		return true
	}
	return false
}
