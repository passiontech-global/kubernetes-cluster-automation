// unreadable.go — the canonical Tracker wiring for the
// state-journal-unreadable blindness latch. workerhygiene and
// controllerhygiene each used to hand-build the same Tracker literal;
// the shared on-disk names are the contract (a literal drift between
// the two would silently split one episode into two), so the wiring
// lives here once.
package journalwatch

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
)

// UnreadableCounter is the shared streak-file base name — each
// producer persists its own streak to
// <state.Dir>/consecutive-journal-unreadable-<owner> (see
// Tracker.EnterFrom), so workerhygiene's healthy read can never
// reset controllerhygiene's failure count while they share the
// state-journal-unreadable latch episode.
const UnreadableCounter = "consecutive-journal-unreadable"

// The two producer ids that share the state-journal-unreadable latch
// through Store.EnterFrom/ExitFrom. They must byte-match the
// latchdefs.Owners declaration for the latch (pinned by
// TestUnreadableOwnersMatchLatchRegistry): the store's legacy-file
// seed path derives the synthetic hold set from that declaration, so
// a drift would make a post-restart ExitFrom clear a latch the other
// hygiene is still failing under.
const (
	OwnerWorkerHygiene     = "workerhygiene"
	OwnerControllerHygiene = "controllerhygiene"
)

// NewUnreadableTracker returns the persistence-wired Tracker for the
// state-journal-unreadable latch:
//
//   - each owner's consecutive-failure streak persists to
//     <state.Dir>/consecutive-journal-unreadable-<owner>, so an agent
//     restart mid-episode resumes the count instead of re-arming at
//     zero — a restart during a broken-journald episode used to
//     silently reset the budget and delay the latch by another full
//     Needed streak;
//   - LatchedSeed seeds latched iff the state-journal-unreadable
//     latch file exists, so a restart while latched resumes latched
//     and the first healthy read releases through Store.ExitFrom +
//     clears the stale state-* file instead of it lingering to the
//     janitor's 24h reap.
//
// needed is the consecutive-failure budget (<=0 → DefaultNeeded);
// dirs are the HOST-visible journal storage roots Present probes.
// The tracker does NOT touch the latch file: callers drive it
// through state.EnterFrom(name, owner, …) / state.ExitFrom(name,
// owner, …) on the tracker's Enter/Exit edges so BOTH hygienes'
// holds register on the one shared Store instance (hoststate.Shared).
func NewUnreadableTracker(state *hoststate.Store, dirs []string, needed int) Tracker {
	return Tracker{
		Needed:      needed,
		Dirs:        dirs,
		Counter:     state,
		CounterName: UnreadableCounter,
		LatchedSeed: func() bool {
			return state.Exists(latchdefs.LatchJournalUnreadable)
		},
	}
}
