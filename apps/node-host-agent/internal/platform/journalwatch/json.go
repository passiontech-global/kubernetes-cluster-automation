// json.go — the `journalctl -o json` tail: line-delimited record
// decode (MESSAGE as a JSON string or a byte array,
// __REALTIME_TIMESTAMP as the µs-since-epoch cursor field) plus
// Fetch, the since-cursor journal read the NPD journald-plugin
// ports use — `journalctl <args> --since @<µs cursor> -o json
// --no-pager` with a lookback-bounded first fetch.
//
// The hygiene subsystems do NOT share this reader: their signature
// greps consume journalctl's short text output via
// systemd.Client.Journal/ExecCombined (stderr folded in so the
// "No journal files" notice is visible — see FilesGone), keyed on
// wall-clock --since windows, not entry cursors. Moving them onto
// -o json would change what the greps see, so this file is the
// JSON-line shape only.
package journalwatch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Entry is one `journalctl -o json` record reduced to the two
// fields the consumers' rules need.
type Entry struct {
	Msg  string
	TSUS int64 // __REALTIME_TIMESTAMP, µs since epoch
}

// ExecFunc runs `journalctl <args>` against the host journal and
// returns its output — the subsystem Config seams (the nsenter
// wrapper for containerized agents) plug in here.
type ExecFunc func(ctx context.Context, args ...string) (string, error)

// ParseJSON decodes line-delimited `journalctl -o json` output.
// Malformed lines (a truncated tail of a flooded journal) are
// skipped rather than failing the whole batch.
func ParseJSON(data string) []Entry {
	var out []Entry
	for _, line := range bytes.Split([]byte(data), []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var e struct {
			Message json.RawMessage `json:"MESSAGE"`
			TS      string          `json:"__REALTIME_TIMESTAMP"`
		}
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		ts, _ := strconv.ParseInt(e.TS, 10, 64)
		out = append(out, Entry{Msg: messageField(e.Message), TSUS: ts})
	}
	return out
}

// messageField unwraps the MESSAGE field — journald emits a JSON
// string for text but an array of byte values for non-UTF8 payloads.
func messageField(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var b []byte
	if err := json.Unmarshal(raw, &b); err == nil {
		return string(b)
	}
	return ""
}

// Fetch runs `journalctl <args...> --since @<cursor> -o json
// --no-pager` through execFn and returns the entries strictly newer
// than *cursor. The cursor is a µs wall timestamp: <=0 means "first
// fetch", which bounds the window to lookback ending at now. On
// success the cursor advances to the newest KEPT entry — never to
// the fetch time; entries <= cursor were already processed. A fetch
// error leaves the cursor untouched — the same window is retried
// next call.
//
// Cursor monotonicity: `next` starts at *cursor so a rewound host
// clock can never rewind the resume point and replay the window.
// And the cursor never advances past the newest seen entry:
// journald may hold records written before `now` that this read
// could not yet see (journalctl's own flush latency) — jumping the
// cursor into that (max TSUS, now) gap would drop those records
// forever on the next strictly-newer fetch. The same window is
// re-scanned next call and the <= cursor filter absorbs the replay.
func Fetch(ctx context.Context, execFn ExecFunc, now time.Time,
	lookback time.Duration, cursor *int64, args ...string) ([]Entry, error) {
	sinceUS := *cursor
	if sinceUS <= 0 {
		sinceUS = now.Add(-lookback).UnixMicro()
	}
	full := append([]string(nil), args...)
	full = append(full, "--since", "@"+strconv.FormatInt(sinceUS/1e6, 10),
		"-o", "json", "--no-pager")
	out, err := execFn(ctx, full...)
	if err != nil {
		return nil, fmt.Errorf("journalctl %s: %w", strings.Join(args, " "), err)
	}
	var kept []Entry
	// Resume-point invariant: next = max(*cursor, max TSUS of kept).
	// Starting at *cursor (not now) both parks the cursor when
	// nothing newer was seen AND keeps it immune to a rewound clock
	// — a rewound cursor would re-emit the whole window and strand
	// entries between the two marks once the clock corrects.
	next := *cursor
	for _, e := range ParseJSON(out) {
		if e.TSUS <= *cursor {
			continue // already processed on a previous cycle
		}
		kept = append(kept, e)
		if e.TSUS > next {
			next = e.TSUS
		}
	}
	*cursor = next
	return kept, nil
}
