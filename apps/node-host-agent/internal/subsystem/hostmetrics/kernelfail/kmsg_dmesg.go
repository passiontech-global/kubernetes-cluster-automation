// kmsg_dmesg.go — kernel-dmesg: the no-/dev/kmsg fallback drain
// (`dmesg -T`, then plain `dmesg`) with its line-level parsing —
// the -T timestamp parse, the message extraction and the fnv line
// anchors the raw-mode cursor needs. Pure move out of kmsg.go
// (per-concern file split).
package kernelfail

import (
	"context"
	"hash/fnv"
	"strings"
	"time"
)

// --- dmesg fallback (kernel-dmesg) ---

// drainDmesg is the no-/dev/kmsg path: `dmesg -T` carries parseable
// timestamps (cursor = last unix ts + same-second consumed count);
// plain `dmesg` has no wall clock (cursor = fnv hash of the last
// processed line — a saturated ring holds a constant line count, so
// a count cursor would go permanently blind; a lost anchor skips
// the tick and re-anchors at the tail rather than reprocessing the
// whole retained ring).
func (r *Runner) drainDmesg(ctx context.Context, st *kernelScanState) {
	out, err := r.deps.RunHostCmd(ctx, "dmesg", "-T")
	mode := "dmesgT"
	if err != nil {
		out, err = r.deps.RunHostCmd(ctx, "dmesg")
		mode = "dmesgRaw"
	}
	if err != nil {
		// No kernel-log access at all — inconclusive, not an error.
		return
	}
	lines := strings.Split(out, "\n")
	cur := r.readKmsgCursor()
	// First sighting in this mode (no cursor, or a cursor from the
	// OTHER fallback mode): dmesg output is the whole retained ring
	// — history, not news. Prime the cursor at the tail and
	// classify nothing, exactly like the kmsg first-open path.
	if cur == nil || cur.mode != mode {
		switch mode {
		case "dmesgT":
			newest := int64(0)
			atNewest := 0
			for _, ln := range lines {
				ts, ok := parseDmesgTimestamp(ln)
				if !ok {
					continue
				}
				if ts > newest {
					newest = ts
					atNewest = 0
				}
				if ts == newest {
					atNewest++
				}
			}
			if newest > 0 {
				r.writeKmsgCursor(&kmsgCursor{
					mode: "dmesgT", unixTS: newest, lines: atNewest})
			}
		default:
			r.writeKmsgCursor(&kmsgCursor{
				mode: "dmesgRaw", lines: len(lines),
				hash: dmesgTailHash(lines)})
		}
		return
	}
	var fresh []string
	var maxTS int64
	switch mode {
	case "dmesgT":
		lastTS := cur.unixTS
		pending := cur.lines // same-second records already consumed
		if pending < 0 {
			pending = len(lines) + 1 // legacy cursor — boundary unknown
		}
		atLast, atMax := 0, 0
		for _, ln := range lines {
			ts, ok := parseDmesgTimestamp(ln)
			if !ok {
				continue // can't order it — never reprocess blindly
			}
			if ts > lastTS {
				fresh = append(fresh, dmesgMessage(ln))
				if ts > maxTS {
					maxTS = ts
					atMax = 0
				}
				if ts == maxTS {
					atMax++
				}
			} else if ts == lastTS {
				atLast++
				if atLast > pending {
					fresh = append(fresh, dmesgMessage(ln))
				}
			}
		}
		switch {
		case maxTS > 0:
			r.writeKmsgCursor(&kmsgCursor{
				mode: "dmesgT", unixTS: maxTS, lines: atMax})
		case atLast > pending:
			// Only same-second arrivals — advance the consumed
			// count so they aren't reprocessed next tick.
			r.writeKmsgCursor(&kmsgCursor{
				mode: "dmesgT", unixTS: lastTS, lines: atLast})
		}
	default: // dmesgRaw — content-anchored, see drainDmesg doc.
		trimmed := lines
		for len(trimmed) > 0 && trimmed[len(trimmed)-1] == "" {
			trimmed = trimmed[:len(trimmed)-1]
		}
		if len(trimmed) == 0 {
			break
		}
		tail := dmesgLineHash(trimmed[len(trimmed)-1])
		anchor := -1
		if cur.hash != 0 {
			for i := len(trimmed) - 1; i >= 0; i-- {
				if dmesgLineHash(trimmed[i]) == cur.hash {
					anchor = i
					break
				}
			}
		}
		if anchor < 0 {
			// Anchor evicted (ring wrapped past it) or a legacy
			// line-count cursor — can't order the retained window.
			// Skip this tick and re-anchor at the tail: missed
			// detections beat double-counted ones.
			r.writeKmsgCursor(&kmsgCursor{
				mode: "dmesgRaw", lines: len(lines), hash: tail})
			break
		}
		fresh = trimmed[anchor+1:]
		if tail != cur.hash {
			// Position advanced — persist it. An unchanged tail
			// hash means nothing new arrived; rewriting the same
			// cursor would pay WriteFileAtomic's two fsyncs every
			// tick on a quiet node for zero information.
			r.writeKmsgCursor(&kmsgCursor{
				mode: "dmesgRaw", lines: len(lines), hash: tail})
		}
	}
	for _, msg := range fresh {
		if msg == "" {
			continue
		}
		r.classifyKernelLine(msg, st)
	}
}

// dmesgLineHash fingerprints one dmesg output line for the cursor
// anchor — fnv-1a, collision odds are irrelevant at ring sizes.
func dmesgLineHash(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

// dmesgTailHash hashes the last non-empty dmesg line — the anchor
// the next drain resumes after. 0 when output is empty.
func dmesgTailHash(lines []string) uint64 {
	for i := len(lines) - 1; i >= 0; i-- {
		if lines[i] != "" {
			return dmesgLineHash(lines[i])
		}
	}
	return 0
}

// dmesgTSLayout is `dmesg -T`'s "[Thu Oct 30 12:34:56 2025]" prefix.
const dmesgTSLayout = "Mon Jan _2 15:04:05 2006"

// parseDmesgTimestamp extracts the bracketed timestamp dmesg -T
// prepends; ok=false for unparseable/missing prefixes.
func parseDmesgTimestamp(line string) (int64, bool) {
	if !strings.HasPrefix(line, "[") {
		return 0, false
	}
	end := strings.IndexByte(line, ']')
	if end < 0 {
		return 0, false
	}
	t, err := time.Parse(dmesgTSLayout, strings.TrimSpace(line[1:end]))
	if err != nil {
		return 0, false
	}
	return t.Unix(), true
}

// dmesgMessage strips the "[timestamp] " prefix, returning the raw
// kernel message.
func dmesgMessage(line string) string {
	if i := strings.IndexByte(line, ']'); i >= 0 {
		return strings.TrimSpace(line[i+1:])
	}
	return strings.TrimSpace(line)
}
