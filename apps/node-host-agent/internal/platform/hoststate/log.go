// log.go — the watchdog log concern: AppendLog/AppendLogWarn and
// the size-capped appendFile they write through. The latch lifecycle
// (store.go) and suspect dedupe (suspect.go) are the callers.

package hoststate

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// --- watchdog log ---

// AppendLog mirrors lib.sh log(): "<rfc3339> <msg>" appended to
// LogFile (the NPD filelog tails it — message text is a contract),
// plus a slog mirror for `kubectl logs` debugging. Best-effort: an
// unwritable log file never fails a check.
func (s *Store) AppendLog(msg string) {
	s.log().Info(msg)
	s.appendFile(msg)
}

// AppendLogWarn is AppendLog for failure/degraded paths — the file
// line is identical (NPD contract), the slog mirror is Warn-level.
func (s *Store) AppendLogWarn(msg string) {
	s.log().Warn(msg)
	s.appendFile(msg)
}

// watchdogLogMaxBytes bounds LogFile — appendFile rotates the log
// to <file>.1 once it passes this size before appending. The
// nodereporter filelog tails by byte offset: when it sees the file
// SHRINK (the rename-to-.1 case) it first drains the unread tail
// from the rotated .1 generation, then restarts the fresh file at
// offset 0 (events.go readNewLogLines). The rotate decision + rename
// run under the per-path logFileLock so two concurrent appends
// cannot both rename.
const watchdogLogMaxBytes = 10 << 20

// logFileLocks serializes appendFile per LogFile PATH, not per
// sharedState: two Stores over different state dirs can still share
// one watchdog log, and s.shared.mu only covers stores on the same
// dir — a cross-dir pair could both stat an oversized log and
// double-rename. Keyed by filepath.Clean(LogFile).
var logFileLocks sync.Map // clean path -> *sync.Mutex

func logFileLock(path string) *sync.Mutex {
	key := filepath.Clean(path)
	if v, ok := logFileLocks.Load(key); ok {
		return v.(*sync.Mutex)
	}
	v, _ := logFileLocks.LoadOrStore(key, &sync.Mutex{})
	return v.(*sync.Mutex)
}

func (s *Store) appendFile(msg string) {
	if s.LogFile == "" {
		return
	}
	// Stat + rename + open + write run as ONE critical section under
	// the per-path mutex: splitting the rotate decision from the
	// append let a second writer's open land between the rename and
	// the first writer's append — its fd then followed into the
	// rotated .1 generation while a THIRD writer created a fresh
	// log, interleaving generations. O_APPEND keeps each individual
	// Write atomic; the mutex keeps the generation boundary clean.
	mu := logFileLock(s.LogFile)
	mu.Lock()
	defer mu.Unlock()
	if fi, err := os.Stat(s.LogFile); err == nil &&
		fi.Size() >= watchdogLogMaxBytes {
		// Single-file rotation: <log> → <log>.1, then append to a
		// fresh file. Best-effort — a failed rename still appends
		// to the oversized file rather than dropping the line.
		if rerr := os.Rename(s.LogFile, s.LogFile+".1"); rerr != nil {
			s.log().Warn("watchdog log rotate failed",
				"file", s.LogFile, "error", rerr)
		}
	}
	f, err := os.OpenFile(s.LogFile,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		s.log().Warn("watchdog log file unwritable",
			"file", s.LogFile, "error", err)
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = fmt.Fprintf(f, "%s %s\n", s.Now().Format(time.RFC3339), msg)
}
