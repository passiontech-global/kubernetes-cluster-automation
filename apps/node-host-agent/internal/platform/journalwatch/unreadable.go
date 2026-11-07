// unreadable.go — the canonical Tracker wiring for the
// state-journal-unreadable blindness latch. workerhygiene and
// controllerhygiene each used to hand-build the same Tracker literal;
// the shared on-disk names are the contract (a literal drift between
// the two would silently split one episode into two), so the wiring
// lives here once.
package journalwatch

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
)

// UnreadableCounter is the shared on-disk streak name — BOTH
// hygienes bump the same consecutive-* file in the watchdog state
// dir ON PURPOSE: they own the same state-journal-unreadable latch,
// so the streak that arms it is shared too (a failed journal read on
// either subsystem counts toward the one episode).
const UnreadableCounter = "consecutive-journal-unreadable"

// NewUnreadableTracker returns the persistence-wired Tracker for the
// state-journal-unreadable latch:
//
//   - the consecutive-failure streak persists to
//     <state.Dir>/consecutive-journal-unreadable, so an agent restart
//     mid-episode resumes the count instead of re-arming at zero —
//     a restart during a broken-journald episode used to silently
//     reset the budget and delay the latch by another full Needed
//     streak;
//   - LatchedSeed seeds latched iff the state-journal-unreadable
//     latch file exists, so a restart while latched resumes latched
//     and the first healthy read exits + clears the stale state-*
//     file instead of it lingering to the janitor's 24h reap.
//
// needed is the consecutive-failure budget (<=0 → DefaultNeeded);
// dirs are the HOST-visible journal storage roots Present probes.
func NewUnreadableTracker(state *hoststate.Store, dirs []string, needed int) Tracker {
	return Tracker{
		Needed:      needed,
		Dirs:        dirs,
		Counter:     state,
		CounterName: UnreadableCounter,
		LatchedSeed: func() bool {
			return state.Exists(hoststate.LatchJournalUnreadable)
		},
	}
}
