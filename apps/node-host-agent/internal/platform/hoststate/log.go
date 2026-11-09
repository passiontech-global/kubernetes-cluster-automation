// log.go — the watchdog log concern: AppendLog/AppendLogWarn and
// the size-capped appendFile they write through. The latch lifecycle
// (store.go) and suspect dedupe (suspect.go) are the callers.

package hoststate

import (
	"fmt"
	"os"
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
// run under s.shared.mu so two concurrent appends cannot both rename.
const watchdogLogMaxBytes = 10 << 20

func (s *Store) appendFile(msg string) {
	if s.LogFile == "" {
		return
	}
	// The rotate decision + rename run under s.shared.mu: two concurrent
	// appends that both stat an oversized log can otherwise BOTH
	// rename — the second rename throwing away the fresh file the
	// first rotation just started (and its early lines) by replacing
	// the .1 generation wholesale. The append itself stays outside
	// the lock — O_APPEND makes each write atomic, and an append
	// whose open raced the rename simply follows its fd into the
	// rotated .1 file (no loss, one stray line in the old
	// generation).
	s.shared.mu.Lock()
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
	s.shared.mu.Unlock()
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
