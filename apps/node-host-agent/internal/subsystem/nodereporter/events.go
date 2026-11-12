// Watchdog log tailing → Kubernetes Events + problem_counter.
//
// Ported 1:1 from the removed watchdog-filelog-monitor.json: the same
// pattern→reason rules applied to the same log file. The NPD filelog
// plugin stripped the leading timestamp token (pluginConfig
// message="^\S+\s+(.*)$") and effectively anchored each pattern at
// end-of-buffer, which is why every JSON pattern ended in ".*" — a
// plain unanchored regex per complete line is the exact equivalent.
//
// Every matched line bumps problem_counter{reason} (NPD parity — one
// increment per match, aggregation doesn't undercount). The Event
// object is deduplicated: an identical reason+message inside
// EventDedupTTL aggregates into the existing Event's series
// (count++ / lastObservedTime) via merge-patch instead of creating a
// new object.
package nodereporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// logRule is one temporary filelog rule — reason → K8s Event reason +
// problem_counter label, pattern → unanchored match on the message
// part of a log line.
// garbage log line must not fail the create.
const maxEventNote = 1024

const (
	// maxLogReadBytes bounds one tail read. The watchdog caps its own
	// log at ~1MB, so a file far beyond that means broken rotation or
	// a flood — the first scan jumps to the last maxLogReadBytes
	// instead of slurping the whole file into heap.
	maxLogReadBytes = 4 << 20
	// maxLogPendingBytes bounds the carried partial-line buffer — a
	// line that never terminates cannot grow the carry forever.
	maxLogPendingBytes = 64 << 10
	// maxEmittedEvents bounds the dedup map after TTL pruning — a
	// flood of distinct reason+message pairs evicts oldest-first
	// instead of growing without limit.
	maxEmittedEvents = 1024
)

// emittedEvent tracks one created Event for series aggregation.
type emittedEvent struct {
	name  string
	count int64
	at    time.Time // last emit — TTL eviction key
}

// syncLogEvents consumes new watchdog log lines, matches the ported
// rules, bumps problem_counter and emits/aggregates Events. A missing
// log file is not an error (nodes without the watchdog simply have
// nothing to report).
//
// The log offset commits ONLY when every Event write in the batch
// succeeded: readNewLogLines advances r.logOffset while reading, so
// a failed emit would otherwise lose those lines permanently (the
// next scan resumes past them). On any emit failure the pre-read
// offset/pending/scanned state is restored and the whole window
// replays next cycle — emitEvent's reason+message dedup absorbs the
// re-emission, and problem_counter recounts the replayed matches
// (a counter of observed problems, not delivered events).
func (r *Reporter) syncLogEvents(ctx context.Context) error {
	savedOffset, savedPending := r.logOffset, r.logPending
	savedScanned, savedFi := r.logScanned, r.logFi
	lines, replayCount, err := r.readNewLogLines()
	if err != nil {
		return err
	}
	r.pruneEmitted()
	allEmitted := true
	for i, line := range lines {
		if !r.processLogLine(ctx, line, i < replayCount) {
			allEmitted = false
		}
	}
	if !allEmitted {
		r.logOffset, r.logPending = savedOffset, savedPending
		r.logScanned, r.logFi = savedScanned, savedFi
	}
	return nil
}

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

// processLogLine applies all rules to one line and reports whether
// every matched Event write succeeded — false tells syncLogEvents to
// roll the log offset back so the line replays next cycle. On the
// first scan (replay) only lines inside LogLookback with a parseable
// timestamp are emitted — unparseable/older lines are skipped so a
// restart doesn't re-report ancient history.
func (r *Reporter) processLogLine(ctx context.Context, line []byte, replay bool) bool {
	if len(line) == 0 {
		return true
	}
	msg, ts := splitLogLine(line)
	if replay && (ts.IsZero() || r.cfg.Clock.Now().Sub(ts) > r.cfg.LogLookback) {
		return true
	}
	ok := true
	for _, rule := range logRules {
		if !rule.re.MatchString(msg) {
			continue
		}
		r.problemCounter.WithLabelValues(rule.reason).Inc()
		if err := r.emitEvent(ctx, rule.reason, msg, corev1.EventTypeWarning); err != nil {
			// Logged, not fatal — the counter already reflects the
			// match and the next identical line retries the Event.
			logger().Error("nodereporter: event emit failed",
				"reason", rule.reason, "error", err)
			ok = false
		}
	}
	for _, rule := range exitLogRules {
		if !rule.re.MatchString(msg) {
			continue
		}
		r.problemCounter.WithLabelValues(rule.reason).Inc()
		if err := r.emitEvent(ctx, rule.reason, msg, corev1.EventTypeNormal); err != nil {
			logger().Error("nodereporter: exit event emit failed",
				"reason", rule.reason, "error", err)
			ok = false
		}
	}
	return ok
}

// emitEvent creates or aggregates one Event of the given type on this
// Node.
// Dedup key is reason+message: a fresh key creates a new object; a
// repeat inside EventDedupTTL series-patches the existing one
// (count++, lastObservedTime). A NotFound patch failure (event TTL'd
// away) drops the entry and recreates; any OTHER patch error keeps
// the entry and returns the error — recreating a fresh object per
// occurrence under a persistent failure (RBAC create-but-not-patch,
// apiserver degradation) would spam unbounded Events.
func (r *Reporter) emitEvent(ctx context.Context, reason, note string, eventType string) error {
	events := r.cfg.Client.EventsV1().Events(r.cfg.EventNamespace)
	now := r.cfg.Clock.Now()
	// Truncate BEFORE keying: two >1KiB notes sharing the first
	// maxEventNote bytes store an identical Note, so they must share
	// one dedup entry — keying on the untruncated note would create
	// distinct Events with identical content. The cut snaps back to
	// a rune boundary and ToValidUTF8 strips any remaining invalid
	// bytes: the apiserver stores Note as a UTF-8 string and rejects
	// invalid input, so a garbage log line must not wedge its Event
	// create permanently.
	if len(note) > maxEventNote {
		i := maxEventNote
		for i > 0 && !utf8.RuneStart(note[i]) {
			i--
		}
		note = strings.ToValidUTF8(note[:i], "")
	}
	key := reason + "\x1f" + note

	if e, ok := r.emittedEvts[key]; ok && now.Sub(e.at) <= r.cfg.EventDedupTTL {
		patch, err := json.Marshal(map[string]any{
			"series": map[string]any{
				"count":            e.count + 1,
				"lastObservedTime": metav1.NewMicroTime(now),
			},
		})
		if err == nil {
			_, err = events.Patch(ctx, e.name, types.MergePatchType,
				patch, metav1.PatchOptions{})
		}
		if err == nil {
			e.count++
			e.at = now
			return nil
		}
		if !apierrors.IsNotFound(err) {
			// Not a "the Event is gone" — RBAC, throttling, a wedged
			// apiserver. Keep the dedup entry: deleting it here would
			// fall through to a fresh Create on EVERY occurrence of
			// this reason+message for as long as the failure lasts.
			// The caller logs the error; the next identical line
			// retries the patch against the same entry.
			return fmt.Errorf("patch event %s/%s: %w",
				r.cfg.EventNamespace, e.name, err)
		}
		delete(r.emittedEvts, key) // stale entry — recreate below
	}

	// Kubelet-style <node>.<hex> name with a monotonic sequence — the
	// nanos alone could collide for two reasons fired in the same
	// cycle.
	name := fmt.Sprintf("%s.%x%x", r.cfg.NodeName, now.UnixNano(), r.evSeq.Add(1))
	ev := &eventsv1.Event{
		ObjectMeta:          metav1.ObjectMeta{Name: name, Namespace: r.cfg.EventNamespace},
		EventTime:           metav1.NewMicroTime(now),
		Reason:              reason,
		Note:                note,
		Type:                eventType,
		ReportingController: "node-host-agent",
		ReportingInstance:   r.cfg.NodeName,
		// events.k8s.io/v1 validation: action is REQUIRED and the
		// deprecated* compat fields must be UNSET (apiserver rejects
		// with "needs to be unset" on this k8s version).
		Action: reason,
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Node",
			Name:       r.cfg.NodeName,
		},
	}
	created, err := events.Create(ctx, ev, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create event %s/%s: %w", r.cfg.EventNamespace, name, err)
	}
	r.emittedEvts[key] = &emittedEvent{name: created.Name, count: 1, at: now}
	logger().Info("nodereporter: event emitted",
		"node", r.cfg.NodeName, "event", created.Name,
		"namespace", r.cfg.EventNamespace, "reason", reason)
	return nil
}

// pruneEmitted drops dedup entries past the TTL — the apiserver GCs
// Events at ~1h, so aggregation targets older than that are gone and
// the map would grow unboundedly otherwise. The map is additionally
// hard-capped: a flood of distinct reason+message pairs evicts the
// least-recently-observed entries first.
func (r *Reporter) pruneEmitted() {
	now := r.cfg.Clock.Now()
	for k, e := range r.emittedEvts {
		if now.Sub(e.at) > r.cfg.EventDedupTTL {
			delete(r.emittedEvts, k)
		}
	}
	if len(r.emittedEvts) > maxEmittedEvents {
		// Single pass: collect (key, at), sort freshest-first, drop
		// everything past the cap — no per-eviction map rescan.
		type observed struct {
			key string
			at  time.Time
		}
		es := make([]observed, 0, len(r.emittedEvts))
		for k, e := range r.emittedEvts {
			es = append(es, observed{k, e.at})
		}
		slices.SortFunc(es, func(a, b observed) int { return b.at.Compare(a.at) })
		for _, o := range es[maxEmittedEvents:] {
			delete(r.emittedEvts, o.key)
		}
	}
}
