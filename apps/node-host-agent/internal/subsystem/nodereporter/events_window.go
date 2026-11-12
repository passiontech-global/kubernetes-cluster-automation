// events_window.go — the nodereporter log-window reader:
// readNewLogLines/readLogWindow/readTailBytes/splitLogLine pull
// and frame the journal tail that syncLogEvents replays.
// Split out of events.go — events.go keeps sync/process/emit.

package nodereporter

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"time"
)

// readNewLogLines returns the complete lines appended since the last
// call and how many of the LEADING lines must go through the replay
// filter (the LogLookback window in processLogLine) — replay is
// per-line because the two byte generations one read can carry have
// different claims to liveness. A trailing partial line is carried
// over to the next cycle so a line split across writes is never
// half-matched.
//
// Every line replays on the first scan after (re)start. On a
// rotation (the rename-to-.1 the watchdog store performs at
// watchdogLogMaxBytes) only the OLD-generation bytes replay — the
// unread .1 tail drained before the offset reset, plus the partial
// line it continues — while the FRESH file's lines are live events,
// not replay (a blanket replay flag would let the lookback filter
// drop a just-written line whose timestamp is unparseable or outside
// the window). A shrink with NO .1 tail is a wholesale rewrite: no
// generation boundary exists to attribute the new file's content to,
// so every line replays exactly like the pre-split behavior — old
// retained lines stay behind the lookback filter instead of
// re-incrementing problem_counter. (NPD kept the stale offset and
// silently missed post-rotation lines; rescanning is strictly
// better.)
//
// The lines appended to the old generation AFTER the last read live
// on in <log>.1 and would be lost by a bare offset reset — so on a
// shrink the unread tail is drained from .1 FIRST and prepended to
// the fresh file's bytes, preserving both order and the carried
// partial line (the .1 tail continues it).
func (r *Reporter) readNewLogLines() ([][]byte, int, error) {
	replayAll := !r.logScanned
	win, err := r.readLogWindow()
	if err != nil || win == nil {
		return nil, 0, err
	}

	pending := r.logPending
	r.logPending = nil
	buf := append(pending, win.data...)
	if len(buf) == 0 {
		return nil, 0, nil
	}
	last := bytes.LastIndexByte(buf, '\n')
	if last < 0 {
		// The whole tail is one unfinished line — keep only the last
		// maxLogPendingBytes so a never-terminated line cannot grow
		// the carry buffer without bound.
		if len(buf) > maxLogPendingBytes {
			buf = buf[len(buf)-maxLogPendingBytes:]
		}
		r.logPending = buf
		return nil, 0, nil
	}
	if rem := buf[last+1:]; len(rem) > 0 {
		if len(rem) > maxLogPendingBytes {
			rem = rem[len(rem)-maxLogPendingBytes:]
		}
		r.logPending = append([]byte(nil), rem...)
	}
	// Split in place — bytes.Split on a big chunk materialises a
	// [][]byte header per line; IndexByte iteration avoids that.
	var lines [][]byte
	for rest := buf[:last]; len(rest) > 0; {
		i := bytes.IndexByte(rest, '\n')
		if i < 0 {
			lines = append(lines, rest)
			break
		}
		lines = append(lines, rest[:i])
		rest = rest[i+1:]
	}
	// The replay prefix: everything on the first scan, everything
	// after an unattributed rewrite, and otherwise exactly the lines
	// STARTING inside the old-generation prefix (a line straddling
	// the boundary began in the old generation — its completion
	// rides the fresh bytes, but it is still old-gen content).
	switch {
	case replayAll, win.noTail:
		return lines, len(lines), nil
	default:
		// oldGenBuf is the length of the OLD-generation prefix of
		// buf: the carried partial line (it began in the old
		// generation) plus the drained .1 tail — only meaningful
		// for a rename rotation, the replay boundary the fresh
		// file's lines start behind. No rotation → no old
		// generation → nothing replays.
		oldGenBuf := 0
		if win.rotated {
			oldGenBuf = len(pending) + win.oldGenTail
		}
		replayCount := 0
		pos := 0
		for _, ln := range lines {
			if pos >= oldGenBuf {
				break
			}
			replayCount++
			pos += len(ln) + 1
		}
		return lines, replayCount, nil
	}
}

// logWindow is one read cycle's byte window plus the rotation
// metadata the replay attribution needs: data is the .1 tail
// prepended to the fresh file's bytes, oldGenTail the drained
// tail's length, rotated/noTail the shrink classification.
type logWindow struct {
	data       []byte
	oldGenTail int
	rotated    bool
	noTail     bool
}

// readLogWindow performs the stat/rotate/mid-seek/open/read half of
// a scan and returns the consumed byte window. It owns the offset
// bookkeeping — r.logOffset advances by bytes actually consumed
// from the LIVE file (not fi.Size(), so lines appended between
// Stat and Read aren't double-read next cycle, and the drained .1
// tail's length is excluded), and r.logScanned arms only after a
// successful read so a failed first pass can't disarm the lookback
// filter. nil window = the log file is absent (not an error).
func (r *Reporter) readLogWindow() (*logWindow, error) {
	fi, err := os.Stat(r.cfg.WatchdogLogFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat %s: %w", r.cfg.WatchdogLogFile, err)
	}
	var tail []byte // unread bytes of the rotated .1 generation
	win := &logWindow{}
	// A rename rotation swaps the file under the same path. Size
	// alone misses it when the fresh file grows past the old offset
	// before the next scan — the seek would then land mid-file in
	// the NEW generation and the unread .1 tail would never drain
	// (Events + problem_counter silently lost for that window).
	// Identity (dev/ino via os.SameFile) detects the generation
	// change regardless of size; the size check stays for the
	// same-inode shrink (in-place truncate/rewrite).
	generationChanged := r.logFi != nil && !os.SameFile(r.logFi, fi)
	if generationChanged || fi.Size() < r.logOffset {
		win.rotated = true
		logger().Debug("nodereporter: watchdog log rotated — draining "+
			"the .1 tail, offset reset", "file", r.cfg.WatchdogLogFile,
			"oldOffset", r.logOffset, "size", fi.Size(),
			"generationChanged", generationChanged)
		// The .1 tail continues r.logPending (the partial line the
		// old generation never terminated) — read it BEFORE clearing
		// anything. The carry survives only when the tail actually
		// carries its continuation; an absent/empty tail (in-place
		// rewrite, .1 already gone or fully consumed) means the
		// partial line can never complete — keeping it would
		// concatenate the fresh file's first line onto a dead
		// fragment.
		tail = readTailBytes(r.cfg.WatchdogLogFile+".1",
			r.logOffset, maxLogReadBytes)
		if len(tail) == 0 {
			r.logPending = nil
			win.noTail = true // wholesale rewrite — nothing is attributable
		}
		r.logOffset = 0
	}
	// First scan of an oversized file: jump to the last
	// maxLogReadBytes and drop the partial line at the cut — the cap
	// exists so a log that outgrew the ~1MB watchdog cap (broken
	// rotation, flood) is never slurped whole into RAM.
	midSeek := false
	if r.logOffset == 0 && fi.Size() > maxLogReadBytes {
		r.logOffset = fi.Size() - maxLogReadBytes
		r.logPending = nil
		midSeek = true
	}
	f, err := os.Open(r.cfg.WatchdogLogFile)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", r.cfg.WatchdogLogFile, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Seek(r.logOffset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek %s: %w", r.cfg.WatchdogLogFile, err)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxLogReadBytes))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", r.cfg.WatchdogLogFile, err)
	}
	// Bytes consumed from the LIVE file — captured before any cut or
	// tail-prepend mangles data (the mid-file seek's discarded head
	// WAS consumed; the .1 tail was not).
	rawLen := int64(len(data))
	// A mid-file seek lands inside a line — discard everything up to
	// the first newline; the head of that line was never read.
	if midSeek {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		} else {
			data = nil
		}
	}
	if len(tail) > 0 {
		// Rotated-generation bytes precede the fresh file's — the
		// events they map onto must not be reordered behind it.
		data = append(tail, data...)
	}
	win.data = data
	win.oldGenTail = len(tail)
	// The tail was fully read — this successful pass counts as the
	// replay scan even if it yielded no complete lines yet.
	r.logScanned = true
	r.logOffset += rawLen
	// Remember the generation read — the next scan's os.SameFile
	// check compares against THIS stat.
	r.logFi = fi
	return win, nil
}

// readTailBytes drains up to max bytes of path starting at offset —
// the rotated .1 generation's unread tail. nil on any absence/error/
// empty read: the drain is strictly best-effort, a lost tail just
// degrades to the pre-tail behavior (offset reset + fresh-file read).
func readTailBytes(path string, offset, max int64) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || offset >= fi.Size() {
		return nil
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(f, max))
	if err != nil || len(data) == 0 {
		return nil
	}
	return data
}

// splitLogLine peels the leading timestamp token (filelog
// pluginConfig parity): returns the message and the parsed RFC3339
// timestamp (zero when absent/unparseable).
func splitLogLine(line []byte) (msg string, ts time.Time) {
	s := string(bytes.TrimRight(line, "\r"))
	i := bytes.IndexByte(line, ' ')
	if i < 0 {
		return s, time.Time{}
	}
	msg = string(bytes.TrimLeft(line[i+1:], " "))
	if t, err := time.Parse(time.RFC3339, s[:i]); err == nil {
		ts = t
	}
	return msg, ts
}
