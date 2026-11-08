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
// nodereporter filelog tails by byte offset and already resets to 0
// (with a lookback-filtered rescan) whenever the file SHRINKS, so a
// rename-to-.1 + fresh file presents exactly the rotation case the
// reader handles; no offset bookkeeping is needed on this side.
const watchdogLogMaxBytes = 10 << 20

func (s *Store) appendFile(msg string) {
	if s.LogFile == "" {
		return
	}
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
