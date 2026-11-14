// store.go — the Store type itself plus the core state-<name> latch
// lifecycle: Path/Exists lookups, Enter/Exit and their multi-owner
// EnterFrom/ExitFrom variants (the RAM-side owners registry lives on
// Store). Rate budgets, counters, suspect-log dedupe, the watchdog
// log and the heartbeat pair are split into their own files.

package hoststate

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// Store is a handle to one state dir. Dir may be "" — path helpers
// then produce bare filenames (callers that gate on an empty dir
// keep that gate; StampLastRun no-ops on "").
type Store struct {
	// Dir is the state dir — e.g. /var/lib/node-watchdog, or
	// kinedb's GuardStateDir.
	Dir string
	// LogFile is the watchdog log appended by AppendLog* — ""
	// disables the file half (slog mirror still fires). The CALLER'S
	// log: a Shared-built Store never inherits a sibling's LogFile,
	// so nodereporter's readers-only "" handle cannot mute another
	// subsystem's watchdog log (and vice versa).
	LogFile string
	// Now supplies the current time — the test seam every subsystem
	// carries as cfg.Clock (*timex.Cell). Pass the method value
	// `cfg.Clock.Now`: it binds the cell POINTER, so a post-New
	// cfg.Clock.Set is observed here without the old "closure over
	// the live config field" contract. nil → system time. Per-caller
	// like LogFile: production passes the one shared hostctx clock
	// cell everywhere, so the stamps agree without a shared field.
	Now timex.Clock
	// Log resolves the slog logger per call — pass the package
	// `logger` func itself so the "logger"=<pkg> attr and any
	// post-construction slog.SetDefault are honored exactly like the
	// per-call logger() invocations this replaces. nil →
	// slog.Default(). Per-caller: the "subsystem" label follows the
	// Store owner, not whoever constructed first.
	Log func() *slog.Logger

	// shared is the per-dir sync core: the mutex serializes the
	// read-modify-write ops across goroutines — RateTrySpend (the
	// feeder remediate path and Cycle compete on the shared
	// last-restart budget: without it a feeder "ok" and a Cycle
	// check "ok" could both pass in the same window and double-spend
	// a restart), Incr's check-then-write counter bump (the shared
	// consecutive-journal streaks), and Enter/Exit's
	// stat→(touch|create|remove) latch half (the shared per-Dir
	// instance funnels several subsystem goroutines through one
	// store). The AppendLog halves stay OUTSIDE the lock — appendFile
	// re-enters the mutex for the rotation decision and sync.Mutex
	// is not reentrant. owners is the RAM-side registry behind
	// EnterFrom/ExitFrom: latch name → the set of owner ids
	// currently holding it. A shared latch (state-pod-teardown-wedged
	// is held by BOTH pod-teardown's stuck-pod count and ctr-tasks'
	// unkillable orphan shims) must outlive the FIRST owner's exit —
	// the file is removed only when the last hold releases. Shared()
	// hands every Store over one dir THE SAME core (so workerhygiene
	// and controllerhygiene share the registry and the rotation
	// mutex); New() mints a private one for hand-built stores.
	shared *sharedState
}

// sharedState is the process-wide per-dir sync core Shared hands
// out — ONLY the serialization state, never a caller's LogFile/Now/
// Log (those stay per-Store).
type sharedState struct {
	mu sync.Mutex
	// owners is the RAM-side multi-owner latch registry — see the
	// Store.shared comment.
	owners map[string]map[string]bool
	// active is the set of producer ids RegisterActiveOwner has
	// declared live on this node — ExitFrom intersects it with a
	// latch's declared owners when seeding the post-restart owner
	// set, so a worker-only node does not seed phantom holds for
	// producers that never run here.
	active map[string]bool
	// lastSpent is the RAM mirror of the last-* rate budgets —
	// key → spend epoch. RateSpendIn stamps it BEFORE the disk
	// write so an ENOSPC/EROFS failure still enforces the
	// cooldown: without the mirror a failed budget write leaves
	// RateOK passing every cycle and the gated action (a
	// systemctl restart above all) storms until the disk recovers.
	// Bounded by the fixed set of budget names callers use.
	lastSpent map[string]int64
}

// New returns a Store for dir/logFile. now and log may be nil. The
// Store carries its OWN private sync core — cross-subsystem sharing
// (one owners registry, one rotation mutex per dir) is Shared's job.
func New(dir, logFile string, now timex.Clock,
	log func() *slog.Logger) *Store {

	if now == nil {
		now = timex.SystemClock
	}
	return &Store{
		Dir: dir, LogFile: logFile, Now: now, Log: log,
		shared: &sharedState{},
	}
}

// sharedMu guards the process-wide per-Dir registry below.
var (
	sharedMu     sync.Mutex
	sharedStates = map[string]*sharedState{}
)

// Shared returns a Store for the canonical dir whose SYNC STATE is
// the process-wide singleton for that dir — every subsystem that
// stamps the same state dir must share the multi-owner latch
// registry (EnterFrom/ExitFrom) and the mutex that serializes
// Enter/Exit/Incr/rotation:
//
//   - the multi-owner latch registry lives on the shared state.
//     workerhygiene and controllerhygiene share the
//     state-journal-unreadable latch — sibling registries would each
//     keep a private owner set and each believe itself the last
//     holder, deleting the latch out from under the other;
//   - the mu that serializes Enter/Exit/Incr/rotation lives on the
//     shared state — with sibling copies, two subsystems appending
//     to one watchdog log or writing one latch file race
//     unserialized.
//
// Each returned Store keeps the CALLER'S OWN LogFile/Now/Log: the
// first construction no longer imposes its logger/clock/log file on
// later subsystems (the old single-*Store-per-dir sharing made
// hostmetrics win the subsystem label for every other package's
// watchdog lines and let nodereporter's readers-only empty LogFile
// mute the watchdog log). Identity — one registry + one mutex per
// canonical dir — is what the sharing guarantees, not one shared
// *Store pointer.
//
// New stays for hand-built stores (tests, one-off dirs); production
// wiring resolves stores through Shared (subframe.StoreAt).
//
// The canonical key is filepath.Clean(dir), so callers may pass
// already-joined or suffixed spellings of one dir freely.
func Shared(dir, logFile string, now timex.Clock,
	log func() *slog.Logger) *Store {

	key := filepath.Clean(dir)
	sharedMu.Lock()
	st, ok := sharedStates[key]
	if !ok {
		st = &sharedState{}
		sharedStates[key] = st
	}
	sharedMu.Unlock()
	if now == nil {
		now = timex.SystemClock
	}
	return &Store{
		Dir: dir, LogFile: logFile, Now: now, Log: log, shared: st,
	}
}

func (s *Store) log() *slog.Logger {
	if s.Log != nil {
		return s.Log()
	}
	return slog.Default()
}

// --- state-* latches ---

// Path returns Dir/state-<name> — the latch file path.
func (s *Store) Path(name string) string {
	return filepath.Join(s.Dir, latchdefs.LatchFilePrefix+name)
}

// Exists reports whether state-<name> is present (e.g. the
// node-overloaded latch written by another writer).
func (s *Store) Exists(name string) bool {
	_, err := os.Stat(s.Path(name))
	return err == nil
}

// Enter creates state-<name> with the current epoch — only when
// absent (the file's mtime/content is when the condition STARTED) —
// and logs the transition once, lib.sh STATE-ENTER parity. An
// existing latch gets its mtime refreshed (BUG-H6): the janitor reaps
// state-* files older than 24h, so a latch maintained for days by an
// owner still evaluating the condition would otherwise be reaped
// mid-episode. The stat→(touch|write) half runs under the shared mu — the
// shared per-Dir instance (Shared) funnels several subsystem
// goroutines through one store, and two of them racing one latch
// file must serialize — while the AppendLog stays outside it
// (appendFile re-enters the shared mu for the rotation decision; sync.Mutex
// is not reentrant).
func (s *Store) Enter(name, extra string) {
	_ = s.EnterFresh(name, extra)
}

// EnterFresh behaves like Enter and returns true only when the latch
// file was newly created this call (so callers can emit a one-shot
// per-episode ACTION entry without a separate Exists race).
func (s *Store) EnterFresh(name, extra string) bool {
	s.shared.mu.Lock()
	written := s.enterLocked(name)
	s.shared.mu.Unlock()
	if !written {
		return false
	}
	if extra != "" {
		s.AppendLog(fmt.Sprintf(latchdefs.StateEnterPrefix+"%s %s", name, extra))
	} else {
		s.AppendLog(latchdefs.StateEnterPrefix + name)
	}
	return true
}

// enterLocked performs the stat→(touch|create) half of Enter — the
// caller HOLDS s.shared.mu. true only when the latch file was
// (re)written this call; an existing file is touched and reports
// false (no STATE-ENTER transition to log).
func (s *Store) enterLocked(name string) bool {
	p := s.Path(name)
	if fi, err := os.Stat(p); err == nil {
		now := s.Now()
		// Touch only once the mtime ages past LatchTouchMinInterval —
		// the janitor reaps at 24h, so a per-cycle utimensat was
		// ~2,800 needless syscalls/day per held latch.
		if cerr := fsx.TouchIfDue(p, fi, now,
			latchdefs.LatchTouchMinInterval); cerr != nil {
			s.log().Debug("state latch touch failed",
				"state", name, "path", p, "error", cerr)
		}
		return false
	}
	return s.WriteEpochFile(p, s.Now().Unix())
}

// RegisterActiveOwner declares that producer id runs on this node —
// subsystems call it from New for every EnterFrom/ExitFrom owner id
// they can emit. ExitFrom consults the set when seeding the
// post-restart owner registry for a latch file found on disk: the
// seed is the INTERSECTION of the latch's declared owners and the
// registered active producers, so state-journal-unreadable held by
// {workerhygiene, controllerhygiene} on a worker-only node seeds
// just {workerhygiene} and releases as soon as that producer's
// journal recovers instead of waiting 24h for janitor reap. Stores
// with no registrations (hand-built unit-test stores) keep the
// legacy seed of the full declared set.
func (s *Store) RegisterActiveOwner(owner string) {
	s.shared.mu.Lock()
	if s.shared.active == nil {
		s.shared.active = map[string]bool{}
	}
	s.shared.active[owner] = true
	s.shared.mu.Unlock()
}

// Exit removes state-<name> if present and logs the transition —
// clears the NPD permanent condition. The return reports whether the
// latch file actually went: true only when it existed and was
// removed — the ExitClearSuspect/ExitClearAllSuspects gating keys on
// it so a suspect budget survives a no-op exit (a sibling owner may
// still hold the episode). cleanup, when non-nil, runs after the
// removal and before the log line: subsystems drop their per-latch
// dedupe budgets there; workerhygiene and everyone else pass nil.
// The stat+remove runs under the shared mu for the same cross-subsystem
// serialization as Enter (cleanup + AppendLog stay outside).
func (s *Store) Exit(name string, cleanup func()) bool {
	s.shared.mu.Lock()
	exited := s.exitLocked(name)
	s.shared.mu.Unlock()
	if !exited {
		return false
	}
	if cleanup != nil {
		cleanup()
	}
	s.AppendLog(latchdefs.StateExitPrefix + name)
	return true
}

// exitLocked removes the state-<name> latch file — the caller HOLDS
// s.shared.mu. true only when the file existed and was removed.
func (s *Store) exitLocked(name string) bool {
	p := s.Path(name)
	if _, err := os.Stat(p); err != nil {
		return false
	}
	if err := os.Remove(p); err != nil {
		s.log().Warn("state latch remove failed",
			"state", name, "path", p, "error", err)
		return false
	}
	return true
}

// seedOwnersLocked returns the post-restart owner set for a shared
// latch whose file exists on disk but whose RAM registry has no
// recorded holds: every DECLARED owner (LatchDef.Owners),
// intersected with the producers RegisterActiveOwner declared live
// on this node — a worker-only node must not inherit phantom
// controllerhygiene holds nothing here will ever release. nil when
// the latch declares no owners or no file exists — nothing to
// inherit. EnterFrom and ExitFrom share this seed: whichever side
// observes the latch first after a restart reconstructs the same
// holder set instead of each inventing its own.
func (s *Store) seedOwnersLocked(name string) map[string]bool {
	declared := latchdefs.SharedOwners(name)
	if declared == nil || !s.Exists(name) {
		return nil
	}
	set := make(map[string]bool, len(declared))
	for _, o := range declared {
		set[o] = true
	}
	if len(s.shared.active) > 0 {
		for o := range set {
			if !s.shared.active[o] {
				delete(set, o)
			}
		}
	}
	return set
}

// EnterFrom is Enter for a latch shared by several producers: the
// caller registers ITS owner id and the latch file is entered
// (create + STATE-ENTER only while absent, mtime refresh while
// held — the on-disk contract is identical to Enter). The file then
// stays latched until every recorded owner has ExitFrom'ed —
// pod-teardown clearing "no wedged pods" must not delete a latch
// ctr-tasks entered for an unkillable orphan shim inside the same
// Cycle. The owner set is process-local: a producer re-registers
// its hold every cycle, so the dispatch order inside a Cycle
// (load-bearing, subframe.Group) repopulates it before any ExitFrom
// can observe a stale empty set.
//
// Post-restart: when the file already exists but this process has
// no recorded holds (first EnterFrom after a restart), the declared
// owners are seeded in FIRST — the same reconstruction ExitFrom
// applies — so this owner's hold JOINS the surviving producers'
// holds instead of replacing them. Without the seed a lone
// EnterFrom would register {owner} only, and its ExitFrom one cycle
// later would delete a latch another subsystem still holds.
func (s *Store) EnterFrom(name, owner, extra string) {
	s.shared.mu.Lock()
	if s.shared.owners == nil {
		s.shared.owners = map[string]map[string]bool{}
	}
	set := s.shared.owners[name]
	if set == nil {
		set = s.seedOwnersLocked(name)
		if set == nil {
			set = map[string]bool{}
		}
		s.shared.owners[name] = set
	}
	set[owner] = true
	// The owner registration and the latch file create must be ONE
	// critical section: releasing the lock before Enter let a racing
	// ExitFrom observe the new owner set, delete the file, and leave
	// the registry claiming a hold on a latch that no longer exists.
	written := s.enterLocked(name)
	s.shared.mu.Unlock()
	if !written {
		return
	}
	if extra != "" {
		s.AppendLog(fmt.Sprintf(latchdefs.StateEnterPrefix+"%s %s", name, extra))
	} else {
		s.AppendLog(latchdefs.StateEnterPrefix + name)
	}
}

// ReapStaleLatch removes state-<name> AND its RAM owner holds —
// the janitor's stale-file reap must not leave shared.owners
// claiming holds on a latch that no longer exists: a surviving
// hold-set makes the next EnterFrom skip the post-restart seed and
// join phantom holders, and a later ExitFrom can then "release" a
// latch another producer never re-entered. Returns whether the
// file was actually removed (same contract as exitLocked).
func (s *Store) ReapStaleLatch(name string) bool {
	s.shared.mu.Lock()
	defer s.shared.mu.Unlock()
	if s.shared.owners != nil {
		delete(s.shared.owners, name)
	}
	return s.exitLocked(name)
}

// ExitFrom releases one owner's hold on a shared latch: the
// state-<name> file is removed (plain Exit semantics — STATE-EXIT
// line + cleanup hook) only when no owner still holds it. When no
// owner set is recorded and a file exists — e.g. the first cycle
// after a restart, before the holding check has re-entered, or a
// latch minted through plain Enter — a latch with DECLARED owners
// (LatchDef.Owners) is treated as held by all of them: the seed
// release below drops only this owner, so a foreign latch never
// dies to a check that never held it (the latch pod-teardown
// entered must survive ctr-tasks' clean scan, and vice versa).
// Once every declared owner has released, the set empties and the
// file exits normally — a genuinely stale shared latch still
// clears within a couple of cycles instead of the janitor's 24h
// reap. Latches with no declared owners keep legacy semantics:
// an unowned file exits like a plain Exit.
func (s *Store) ExitFrom(name, owner string, cleanup func()) {
	s.shared.mu.Lock()
	held := false
	if set, ok := s.shared.owners[name]; ok {
		delete(set, owner)
		held = len(set) > 0
		if !held {
			delete(s.shared.owners, name)
		}
	} else if set := s.seedOwnersLocked(name); set != nil {
		// Post-restart seed: the latch file exists with no recorded
		// holds — reconstruct the declared owners (already
		// intersected with this node's active producers) and drop
		// only this owner, so a foreign latch never dies to a check
		// that never held it.
		delete(set, owner)
		held = len(set) > 0
		if held {
			if s.shared.owners == nil {
				s.shared.owners = map[string]map[string]bool{}
			}
			s.shared.owners[name] = set
		}
	}
	if held {
		s.shared.mu.Unlock()
		return
	}
	// The exit runs INSIDE the same critical section that dropped
	// this owner's hold. Unlocking before Exit left a window where
	// another goroutine's EnterFrom could re-register a fresh owner
	// and re-enter the latch, and this release would then delete the
	// file out from under the new holder — the hold-drop verdict and
	// the removal must be one atomic decision.
	exited := s.exitLocked(name)
	s.shared.mu.Unlock()
	if !exited {
		return
	}
	if cleanup != nil {
		cleanup()
	}
	s.AppendLog(latchdefs.StateExitPrefix + name)
}
