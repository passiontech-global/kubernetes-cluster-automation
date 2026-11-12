// json.go — the `journalctl -o json` tail: line-delimited record
// decode (MESSAGE as a JSON string or a byte array,
// __REALTIME_TIMESTAMP as the µs-since-epoch stamp, __CURSOR as
// the opaque resume position, _SYSTEMD_UNIT for subscriber
// filtering) plus Fetch, the since/cursor journal read the NPD
// journald-plugin ports use.
//
// The hygiene subsystems do NOT share this reader directly: their
// signature greps consume journalctl's short text output via
// systemd.Client.Journal/ExecCombined (stderr folded in so the
// "No journal files" notice is visible — see FilesGone), keyed on
// wall-clock --since windows, not entry cursors. The Multiplexer
// (mux.go) is the shared JSON tail they converge on.
package journalwatch

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Entry is one `journalctl -o json` record reduced to the fields
// the consumers' rules need.
type Entry struct {
	Msg       string
	TSUS      int64  // __REALTIME_TIMESTAMP, µs since epoch
	Cursor    string // __CURSOR — the opaque journal position
	Unit      string // _SYSTEMD_UNIT — unit attribution for mux filters
	Transport string // _TRANSPORT — "kernel" is journalctl -k's own match
}

// fetchMaxLines caps one journalctl read — see Fetch's doc for why
// the bound lives on the command line (first-N-after-cursor) rather
// than on decoded output.
const fetchMaxLines = 10000

// ExecFunc runs `journalctl <args>` against the host journal and
// returns its output — the subsystem Config seams (the nsenter
// wrapper for containerized agents) plug in here.
type ExecFunc func(ctx context.Context, args ...string) (string, error)

// ParseJSON decodes line-delimited `journalctl -o json` output.
// Malformed lines (a truncated tail of a flooded journal, or the
// partial last line an exec capture cap can leave) are skipped
// rather than failing the whole batch — callers advancing a cursor
// MUST only move it to a successfully decoded entry's Cursor, so a
// truncated tail is simply re-fetched next read.
func ParseJSON(data string) []Entry {
	var out []Entry
	// Zero-copy line walk: strings.Cut slices the input instead of
	// bytes.Split materializing a [][]byte of every line — journal
	// tails can run to the 16 MiB capture cap.
	rest := data
	for rest != "" {
		var line string
		var found bool
		line, rest, found = strings.Cut(rest, "\n")
		line = strings.TrimSpace(line)
		if line != "" {
			var e struct {
				Message   json.RawMessage `json:"MESSAGE"`
				TS        string          `json:"__REALTIME_TIMESTAMP"`
				Cursor    string          `json:"__CURSOR"`
				Unit      string          `json:"_SYSTEMD_UNIT"`
				Transport string          `json:"_TRANSPORT"`
			}
			if err := json.Unmarshal([]byte(line), &e); err == nil {
				ts, _ := strconv.ParseInt(e.TS, 10, 64)
				out = append(out, Entry{Msg: messageField(e.Message), TSUS: ts,
					Cursor: e.Cursor, Unit: e.Unit, Transport: e.Transport})
			}
		}
		if !found {
			break // last line had no trailing newline
		}
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

// Fetch runs `journalctl <args...> -o json --no-pager` through
// execFn and returns the decoded entries. cursor is the journal's
// opaque __CURSOR resume position: "" means "first fetch", which
// bounds the window to lookback ending at now via --since; a
// non-empty cursor reads strictly-forward via --after-cursor=<c> —
// --cursor= would re-include the boundary entry and double-process
// the last line of every window, while --after-cursor starts
// strictly past it. Journal positions are monotonic where µs
// timestamps collide, so same-instant entries can neither duplicate
// nor drop.
//
// --lines=fetchMaxLines bounds every read: journalctl's
// after-cursor+lines combination returns the FIRST N entries after
// the cursor (the "wrong" behavior per the man page's "most recent"
// wording — exactly what a forward tail wants), so a flooded journal
// drains in capped batches with the cursor advancing through each
// last COMPLETE line instead of one unbounded dump. The first
// --since fetch is likewise capped at the window's most recent
// fetchMaxLines entries.
//
// On success *cursor advances to the __CURSOR of the LAST
// successfully decoded entry — the final COMPLETE JSON line. When
// hostexec's 16 MiB capture cap truncates the stream mid-line, the
// partial tail fails to decode, the cursor parks on the last whole
// record, and the next call resumes exactly there: no entry is
// ever skipped.
//
// A fetch error leaves the cursor untouched — the same window is
// retried next call.
func Fetch(ctx context.Context, execFn ExecFunc, now time.Time,
	lookback time.Duration, cursor *string, args ...string) ([]Entry, error) {
	full := append([]string(nil), args...)
	if *cursor == "" {
		// First fetch: bound the replay window to lookback.
		full = append(full, "--since",
			"@"+strconv.FormatInt(now.Add(-lookback).UnixMicro()/1e6, 10))
	} else {
		full = append(full, "--after-cursor="+*cursor)
	}
	full = append(full, "--lines="+strconv.Itoa(fetchMaxLines),
		"-o", "json", "--no-pager")
	out, err := execFn(ctx, full...)
	if err != nil {
		return nil, fmt.Errorf("journalctl %s: %w", strings.Join(args, " "), err)
	}
	entries := ParseJSON(out)
	if len(entries) > 0 && entries[len(entries)-1].Cursor != "" {
		*cursor = entries[len(entries)-1].Cursor
	}
	return entries, nil
}
