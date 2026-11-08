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
	// disables the file half (slog mirror still fires).
	LogFile string
	// Now supplies the current time — the test seam every subsystem
	// carries as cfg.Clock (*timex.Cell). Pass the method value
	// `cfg.Clock.Now`: it binds the cell POINTER, so a post-New
	// cfg.Clock.Set is observed here without the old "closure over
	// the live config field" contract. nil → system time.
	Now timex.Clock
	// Log resolves the slog logger per call — pass the package
	// `logger` func itself so the "logger"=<pkg> attr and any
	// post-construction slog.SetDefault are honored exactly like the
	// per-call logger() invocations this replaces. nil →
	// slog.Default().
	Log func() *slog.Logger

	// mu serializes the read-modify-write ops across goroutines —
	// RateTrySpend (the feeder remediate path and Cycle compete on
	// the shared last-restart budget: without it a feeder "ok" and
	// a Cycle check "ok" could both pass in the same window and
	// double-spend a restart) and Incr's check-then-write counter
	// bump (the shared consecutive-journal-unreadable streak).
	mu sync.Mutex
	// owners is the RAM-side registry behind EnterFrom/ExitFrom:
	// latch name → the set of owner ids currently holding it. A
	// shared latch (state-pod-teardown-wedged is held by BOTH
	// pod-teardown's stuck-pod count and ctr-tasks' unkillable
	// orphan shims) must outlive the FIRST owner's exit — the file
	// is removed only when the last hold releases.
	owners map[string]map[string]bool
}

// New returns a Store for dir/logFile. now and log may be nil.
func New(dir, logFile string, now timex.Clock,
	log func() *slog.Logger) *Store {

	if now == nil {
		now = timex.SystemClock
	}
	return &Store{Dir: dir, LogFile: logFile, Now: now, Log: log}
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
// mid-episode.
func (s *Store) Enter(name, extra string) {
	p := s.Path(name)
	if _, err := os.Stat(p); err == nil {
		now := s.Now()
		if cerr := os.Chtimes(p, now, now); cerr != nil {
			s.log().Debug("state latch touch failed",
				"state", name, "path", p, "error", cerr)
		}
		return
	}
	if !s.WriteEpochFile(p, s.Now().Unix()) {
		return
	}
	if extra != "" {
		s.AppendLog(fmt.Sprintf(latchdefs.StateEnterPrefix+"%s %s", name, extra))
	} else {
		s.AppendLog(latchdefs.StateEnterPrefix + name)
	}
}

// Exit removes state-<name> if present and logs the transition —
// clears the NPD permanent condition. cleanup, when non-nil, runs
// after the removal and before the log line: subsystems drop their
// per-latch dedupe budgets there. The two shared suspect-budget
// divergences have named wrappers — ExitClearSuspect (drop only
// last-suspect-<name>; controllerhygiene) and ExitClearAllSuspects
// (drop the whole last-suspect-* family; nethealth) — workerhygiene
// and everyone else pass nil.
func (s *Store) Exit(name string, cleanup func()) {
	p := s.Path(name)
	if _, err := os.Stat(p); err != nil {
		return
	}
	if err := os.Remove(p); err != nil {
		s.log().Warn("state latch remove failed",
			"state", name, "path", p, "error", err)
		return
	}
	if cleanup != nil {
		cleanup()
	}
	s.AppendLog(latchdefs.StateExitPrefix + name)
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
// (load-bearing, checks.Group) repopulates it before any ExitFrom
// can observe a stale empty set.
func (s *Store) EnterFrom(name, owner, extra string) {
	s.mu.Lock()
	if s.owners == nil {
		s.owners = map[string]map[string]bool{}
	}
	set := s.owners[name]
	if set == nil {
		set = map[string]bool{}
		s.owners[name] = set
	}
	set[owner] = true
	s.mu.Unlock()
	s.Enter(name, extra)
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
	s.mu.Lock()
	held := false
	if set, ok := s.owners[name]; ok {
		delete(set, owner)
		held = len(set) > 0
		if !held {
			delete(s.owners, name)
		}
	} else if declared := latchdefs.SharedOwners(name); declared != nil &&
		s.Exists(name) {
		set := make(map[string]bool, len(declared))
		for _, o := range declared {
			set[o] = true
		}
		delete(set, owner)
		held = len(set) > 0
		if held {
			if s.owners == nil {
				s.owners = map[string]map[string]bool{}
			}
			s.owners[name] = set
		}
	}
	s.mu.Unlock()
	if held {
		return
	}
	s.Exit(name, cleanup)
}
