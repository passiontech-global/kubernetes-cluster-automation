// Package journalwatch is the shared consecutive-failure accounting
// behind the journal-unreadable blindness latch. Every subsystem
// that greps the systemd journal (controllerhygiene's k0scontroller
// windows, workerhygiene's k0sworker snapshot + A5 probe) classifies
// each read — usable journal data vs a read that produced nothing
// while journald should be answering — and reports the verdict here.
//
// Field incident 2026-11 (cicd controller 103.186.101.30): journald
// was broken — journalctl returned "No journal files"/empty (or was
// killed) although the journal files existed. Every journal-based
// check silently saw "0 hits": a dead journald masks the exact
// events the watchdog greps for, and NOTHING surfaced that the
// checks were blind. The tracker turns "reads keep producing
// nothing" into a single state-journal-unreadable latch + one
// suspect log line, and clears it when reads recover.
//
// The one deliberate NO-fire case: a host with no journal storage
// at all (no /var/log/journal, no /run/log/journal). There journald
// is legitimately absent — every read failing is configuration, not
// a fault.
//
// The streak is RAM by default; callers that wire Counter +
// CounterName persist it as consecutive-* files in the watchdog
// state dir (and bind LatchedSeed to their latch file's existence)
// so an agent restart mid-episode resumes the count instead of
// re-arming at zero — a restart during a broken-journald episode
// used to silently reset the budget and delay the latch by another
// full Needed streak. The files are OWNER-SCOPED (CounterName +
// "-" + owner): two subsystems driving one shared latch episode each
// keep their own streak, so one producer's healthy journal read can
// never reset the other's failure count — the latch file itself
// arbitrates the shared episode through the Store's multi-owner
// EnterFrom/ExitFrom.
//
// json.go holds the package's second piece: the `journalctl -o
// json` line decode + since-cursor fetch shared by the NPD
// journald-plugin ports (nodereporter's kubelet-stale monitor and
// `journalctl -k` kernel fallback). integrity.go is the third: the
// shared corrupt/empty probe + rotate/vacuum remedy behind the A5
// journald-integrity checks (workerhygiene's JournaldCheck,
// hostconfig's journaldIntegrity), parameterized per site.
package journalwatch

import (
	"os"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
)

// DefaultNeeded is the consecutive-failed-read budget before the
// latch may enter — one bad read is a blip (timeout under load, a
// rotating journald), Needed in a row while journal storage exists
// is blindness.
const DefaultNeeded = 5

// Tracker accumulates consecutive journal-read failures per OWNER and
// decides when the blindness is persistent enough to surface. It
// owns ONLY the counting + the journal-storage gate; the caller turns
// the transitions into its own state-* latch and log lines (per-
// subsystem conventions) and drives the shared latch FILE through the
// Store's multi-owner EnterFrom/ExitFrom — the tracker never touches
// the latch file itself. Not goroutine-safe — one tracker per cycle
// loop.
type Tracker struct {
	// Needed is the consecutive-failure budget; <=0 → DefaultNeeded.
	Needed int
	// Dirs are the journal storage roots probed by Present — the
	// latch can only fire while at least one exists. Pass the
	// HOST-visible paths (/host/var/log/journal in a container,
	// /var/log/journal standalone), covering both persistent and
	// volatile (/run/log/journal) storage.
	Dirs []string
	// Stat probes dir existence; nil → os.Stat (test seam).
	Stat func(string) (os.FileInfo, error)

	// Counter, when non-nil (and its Dir non-empty), persists each
	// owner's consecutive-failure streak to
	// <dir>/<CounterName>-<owner> — consecutive-* files in the
	// watchdog state dir — so an agent restart mid-episode resumes
	// the counts instead of re-arming at zero. Per-owner files: a
	// sibling producer's healthy read resets ITS file only, never
	// this owner's. RAM stays the fallback when a write fails (Incr's
	// 0 return): the file is the restart witness, RAM the fast path.
	Counter     *hoststate.Store
	CounterName string
	// Owner binds the tracker to ONE producer id when wired through
	// NewUnreadableTrackerForOwner (the production wiring): streaks,
	// persisted files, the seed resume and the reset all resolve to
	// THAT id, so a call-site owner can never straddle two files or
	// leak across the hygienes. Hand-built literals (tests) leave it
	// empty and keep the per-call owner.
	Owner string
	// LatchedSeed, when non-nil, is consulted ONCE before the first
	// EnterFrom/ExitFrom — callers bind it to their latch file's
	// existence so a restart while latched resumes latched: the first
	// healthy read then releases through Store.ExitFrom and clears
	// the stale state-* file instead of it lingering to the janitor's
	// 24h reap. When nil, a non-empty latch name argument to
	// EnterFrom/ExitFrom seeds from the wired Counter's Exists(name) —
	// same contract for hand-built trackers that carry the store.
	LatchedSeed func() bool

	streaks map[string]int // owner → consecutive failures (RAM fast path)
	latched bool
	seeded  bool
}

func (t *Tracker) needed() int {
	if t.Needed <= 0 {
		return DefaultNeeded
	}
	return t.Needed
}

// resolveOwner returns the effective streak owner: a tracker wired
// through NewUnreadableTrackerForOwner is bound to one producer id —
// its streaks, persisted files and seed resume all use THAT id, so a
// call-site owner can never straddle two streak files. Hand-built
// literals carry no binding and keep the per-call owner.
func (t *Tracker) resolveOwner(owner string) string {
	if t.Owner != "" {
		return t.Owner
	}
	return owner
}

// counterWired reports whether the persistence pair is usable: a
// "" Counter.Dir would write bare filenames into the process CWD
// (never do that) and a "" name has no file to write, so either
// disables the file half entirely — RAM-only tracking, the
// pre-persistence behavior.
func (t *Tracker) counterWired() bool {
	return t.Counter != nil && t.Counter.Dir != "" && t.CounterName != ""
}

// counterName is the per-owner streak file: <CounterName>-<owner>.
// The suffix is what keeps workerhygiene's healthy read from
// resetting controllerhygiene's persisted streak (and vice versa).
func (t *Tracker) counterName(owner string) string {
	return t.CounterName + "-" + owner
}

// seed loads the persisted state once, lazily on the first
// EnterFrom/ExitFrom: the calling owner's streak resumes from
// <dir>/<CounterName>-<owner> and the latch from LatchedSeed (or the
// named latch file's existence when the seed func is absent) so an
// agent restart mid-episode continues where the previous process
// left off. The one PRE-owner-scoping shared streak file is dead
// state after the split — swept once here so no orphan
// consecutive-journal-unreadable lingers in the dir. Fails()/
// Latched() deliberately do NOT seed — they are pure accessors, and
// seeding-on-read would let a debug peek consume the one-shot
// restore before the first real verdict.
func (t *Tracker) seed(owner, name string) {
	if t.seeded {
		return
	}
	t.seeded = true
	t.streaks = map[string]int{}
	if t.counterWired() {
		t.streaks[owner] = t.Counter.Counter(t.counterName(owner))
		t.Counter.ResetCounter(t.CounterName)
	}
	switch {
	case t.LatchedSeed != nil:
		t.latched = t.LatchedSeed()
	case name != "" && t.counterWired():
		t.latched = t.Counter.Exists(name)
	}
}

// Present reports whether any configured journal storage dir
// exists — the "journald is installed" witness. With no dir the
// host legitimately has no journald: reads failing is config, not
// a fault, and the tracker must never fire.
func (t *Tracker) Present() bool {
	stat := t.Stat
	if stat == nil {
		stat = os.Stat
	}
	for _, d := range t.Dirs {
		if _, err := stat(d); err == nil {
			return true
		}
	}
	return false
}

// EnterFrom records one FAILED journal read for owner and reports
// the latch-ENTER edge: true exactly once per episode, when owner's
// streak reaches Needed AND journal storage exists — the caller then
// (re)asserts the latch through Store.EnterFrom(name, owner, …).
// Every further failing read returns false while the tracker stays
// latched; the caller must KEEP asserting the store hold (the store
// registration + the latch mtime refresh ride those calls, and the
// hold is what stops a sibling producer from deleting the episode).
// name is the latch name the caller drives — used only to seed the
// latched state when no LatchedSeed func is wired.
func (t *Tracker) EnterFrom(owner, name string) bool {
	owner = t.resolveOwner(owner)
	t.seed(owner, name)
	n := t.streaks[owner] + 1
	t.streaks[owner] = n
	if t.counterWired() {
		// The file is authoritative — Incr returns the new on-disk
		// value, so a restart-resumed streak wins over the RAM guess.
		// A 0 return means the write failed (dir gone, disk full):
		// keep the RAM count, never invent a streak.
		if v := t.Counter.Incr(t.counterName(owner)); v > 0 {
			n = v
			t.streaks[owner] = n
		}
	}
	if t.latched {
		return false
	}
	if n >= t.needed() && t.Present() {
		t.latched = true
		return true
	}
	return false
}

// ExitFrom records one SUCCESSFUL journal read for owner and reports
// the latch-EXIT edge for this tracker: true when owner's episode
// ends while latched (the caller then releases through
// Store.ExitFrom(name, owner, …)), false when this tracker never
// held the episode. Either way the owner's streak zeroes and its
// persisted counter file goes — and the caller should release the
// store hold REGARDLESS of the return: the store decides whether the
// FILE may exit (a sibling owner still holding the episode keeps it
// alive), so a producer that joined an episode without ever reaching
// its own Needed streak must still be able to drop its hold.
func (t *Tracker) ExitFrom(owner, name string) bool {
	owner = t.resolveOwner(owner)
	t.seed(owner, name)
	delete(t.streaks, owner)
	if t.counterWired() {
		t.Counter.ResetCounter(t.counterName(owner))
	}
	if !t.latched {
		return false
	}
	t.latched = false
	return true
}

// Fails reports the highest per-owner consecutive-failure streak
// (tests/debug — a tracker in production carries exactly one feeding
// owner, so this is that owner's streak).
func (t *Tracker) Fails() int {
	best := 0
	for _, n := range t.streaks {
		if n > best {
			best = n
		}
	}
	return best
}

// Latched reports whether the tracker currently holds the latched
// state (tests/debug — the on-disk latch is the caller's business).
func (t *Tracker) Latched() bool { return t.latched }

// SinceLayout is the journalctl --since wall-clock timestamp format —
// the "2006-01-02 15:04:05" contract the unit-window readers share
// (systemd.Client.Journal callers and the hygiene deps'
// journalRead both stamp through it).
const SinceLayout = "2006-01-02 15:04:05"

// UnitWindowArgv builds the unit-journal window read —
// `journalctl -u <unit> --since <since> --no-pager` — the ONE argv
// shape behind every unit-scoped signature grep (platform/systemd's
// Client.Journal, controllerhygiene's journalRead). The transport
// must fold stderr into the output (combined capture): the
// "No journal files" notice this package classifies is a journald
// diagnostic on stderr, not journal content.
func UnitWindowArgv(unit, since string) []string {
	return []string{"journalctl", "-u", unit, "--since", since, "--no-pager"}
}

// AnyLineArgv is the unfiltered second probe — `journalctl -n 1
// --no-pager` — that disambiguates a quiet unit window from
// journald-level blindness (ClassifyRead's empty branch): journald
// answering ANY line means the unit was merely quiet. Same
// combined-capture requirement as UnitWindowArgv.
func AnyLineArgv() []string {
	return []string{"journalctl", "-n", "1", "--no-pager"}
}

// FilesGone reports whether journalctl output carries its
// "No journal files were found." notice — journald cannot open the
// journal storage although journalctl itself ran. On a read that
// otherwise succeeded (rc=0) this text is the only blindness
// evidence; stderr must be folded into the output for it to be
// seen (the notice is a journald diagnostic, not journal content).
func FilesGone(out string) bool {
	return strings.Contains(strings.ToLower(out), "no journal files")
}

// ReadClass is the shared journal-read verdict every
// journald-unreadable check folds into — the blindness classes are
// identical across subsystems, only the follow-up detail differs.
type ReadClass int

const (
	// ClassOK — the read produced usable journal data.
	ClassOK ReadClass = iota
	// ClassFailed — the journalctl exec itself errored.
	ClassFailed
	// ClassFilesGone — output carries the "No journal files"
	// notice: journald answered but has no storage.
	ClassFilesGone
	// ClassEmpty — literally empty output: ambiguous between a
	// quiet unit and journald-level blindness (callers disambiguate
	// with an unfiltered probe or the integrity classifier).
	ClassEmpty
)

// ClassifyRead reduces one journalctl read (combined output + exec
// error) to its ReadClass and the human detail string the callers'
// suspect/log lines already spell — the single classifier behind
// every "is journald blind" check so the classes cannot drift.
func ClassifyRead(out string, err error) (ReadClass, string) {
	switch {
	case err != nil:
		return ClassFailed, "read failed: " + err.Error()
	case FilesGone(out):
		return ClassFilesGone, "journalctl reports no journal files"
	case strings.TrimSpace(out) == "":
		return ClassEmpty, ""
	}
	return ClassOK, ""
}
