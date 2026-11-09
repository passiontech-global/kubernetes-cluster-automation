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

// NewUnreadableTrackerForOwner returns the persistence-wired Tracker
// for the state-journal-unreadable latch, BOUND to one producer id:
//
//   - each owner's consecutive-failure streak persists to
//     <state.Dir>/consecutive-journal-unreadable-<owner>, so an agent
//     restart mid-episode resumes the count instead of re-arming at
//     zero — a restart during a broken-journald episode used to
//     silently reset the budget and delay the latch by another full
//     Needed streak;
//   - the binding scopes every streak read/increment/reset to THAT
//     owner's file, so workerhygiene's healthy journal read can
//     never reset controllerhygiene's failure count while they share
//     the state-journal-unreadable latch episode (and vice versa) —
//     an owner-less tracker would collapse both producers onto one
//     counter and defeat the owner-scoped EnterFrom/ExitFrom calls
//     in wdeps/cdeps;
//   - LatchedSeed seeds latched iff the state-journal-unreadable
//     latch file exists, so a restart while latched resumes latched
//     and the first healthy read releases through Store.ExitFrom +
//     clears the stale state-* file instead of it lingering to the
//     janitor's 24h reap.
//
// owner is OwnerWorkerHygiene or OwnerControllerHygiene — it MUST be
// non-empty and the constructor refuses "" (a wiring error, not a
// runtime condition: the owner-less form is no longer producible).
// needed is the consecutive-failure budget (<=0 → DefaultNeeded);
// dirs are the HOST-visible journal storage roots Present probes.
// The tracker does NOT touch the latch file: callers drive it
// through state.EnterFrom(name, owner, …) / state.ExitFrom(name,
// owner, …) on the tracker's Enter/Exit edges so BOTH hygienes'
// holds register on the one shared Store sync state
// (hoststate.Shared).
func NewUnreadableTrackerForOwner(state *hoststate.Store, dirs []string,
	needed int, owner string) Tracker {
	if owner == "" {
		panic("journalwatch: NewUnreadableTrackerForOwner requires a " +
			"non-empty owner — an owner-less tracker collapses both " +
			"hygienes' streaks onto one counter")
	}
	return Tracker{
		Needed:      needed,
		Dirs:        dirs,
		Counter:     state,
		CounterName: UnreadableCounter,
		Owner:       owner,
		LatchedSeed: func() bool {
			return state.Exists(latchdefs.LatchJournalUnreadable)
		},
	}
}
