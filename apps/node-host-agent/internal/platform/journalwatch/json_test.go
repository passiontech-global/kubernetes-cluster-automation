// json_test.go — coverage for the `journalctl -o json` tail: the
// line decode (string vs byte-array MESSAGE, malformed lines) and
// Fetch's since-cursor contract (lookback-bounded first fetch,
// strictly-newer filtering, cursor advance on success and retention
// on error).
package journalwatch

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

func entryJSON(tsUS int64, msg string) string {
	return fmt.Sprintf(
		`{"__REALTIME_TIMESTAMP":"%d","MESSAGE":%s}`, tsUS,
		strconv.Quote(msg))
}

// TestParseJSON: MESSAGE arrives as a JSON string or a byte array
// (non-UTF8 payloads); malformed lines are skipped.
func TestParseJSON(t *testing.T) {
	data := entryJSON(1700000000000000, `node "n1" not found`) + "\n" +
		"not-json-garbage\n" +
		`{"__REALTIME_TIMESTAMP":"1700000001000000","MESSAGE":[104,101,108,108,111]}` + "\n"
	got := ParseJSON(data)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(got), got)
	}
	if got[0].TSUS != 1700000000000000 || !strings.Contains(got[0].Msg, "not found") {
		t.Fatalf("entry 0 = %+v", got[0])
	}
	if got[1].Msg != "hello" {
		t.Fatalf("byte-array MESSAGE decoded to %q", got[1].Msg)
	}
}

// TestFetchCursor: the µs cursor makes each fetch return only
// strictly-new entries — a boundary replay is filtered, a later
// line is kept — and the --since argv is the epoch-second cursor.
func TestFetchCursor(t *testing.T) {
	now := time.Unix(1700000000, 0)
	lookback := 5 * time.Minute
	var calls [][]string
	payloads := []string{
		entryJSON(now.UnixMicro()-1000, "first"),
		// Same entry re-shown at the boundary plus a new one.
		entryJSON(now.UnixMicro()-1000, "first") + "\n" +
			entryJSON(now.UnixMicro()+1000, "second"),
	}
	i := 0
	exec := func(_ context.Context, args ...string) (string, error) {
		calls = append(calls, args)
		out := payloads[i]
		if i < len(payloads)-1 {
			i++
		}
		return out, nil
	}
	var cursor int64
	got, err := Fetch(context.Background(), exec, now, lookback, &cursor, "-u", "u.service")
	if err != nil || len(got) != 1 || got[0].Msg != "first" {
		t.Fatalf("fetch 1: got=%+v err=%v", got, err)
	}
	got, err = Fetch(context.Background(), exec, now, lookback, &cursor, "-u", "u.service")
	if err != nil || len(got) != 1 || got[0].Msg != "second" {
		t.Fatalf("fetch 2: got=%+v err=%v", got, err)
	}
	if len(calls) != 2 {
		t.Fatalf("exec calls = %d, want 2", len(calls))
	}
	// argv tail: --since @<epoch-s> -o json --no-pager. The second
	// window opens at the newest KEPT entry's timestamp (truncated
	// to seconds), not at `now` — the cursor never advances past a
	// seen entry into journald's unflushed tail.
	since1 := calls[0][len(calls[0])-4]
	since2 := calls[1][len(calls[1])-4]
	want1 := "@" + strconv.FormatInt(now.Add(-lookback).Unix(), 10)
	want2 := "@" + strconv.FormatInt((now.UnixMicro()-1000)/1e6, 10)
	if since1 != want1 || since2 != want2 {
		t.Fatalf("--since args = %q then %q, want %q then %q",
			since1, since2, want1, want2)
	}
}

// TestFetchEmptyKeepsCursor: a fetch that returns nothing new must
// NOT advance the cursor into the unflushed window — journald may
// deliver records timestamped before `now` on the NEXT read, and a
// cursor already past them would drop them forever (the
// strictly-newer filter).
func TestFetchEmptyKeepsCursor(t *testing.T) {
	now := time.Unix(1700000000, 0)
	later := now.Add(30 * time.Second)
	payloads := []string{
		entryJSON(now.UnixMicro()-1000, "first"),
		"", // quiet window — nothing flushed yet
		// Late flush: 'second' was written before `later` but only
		// became visible now — a cursor at `later` would drop it.
		entryJSON(now.UnixMicro()+500, "second"),
	}
	i := 0
	exec := func(context.Context, ...string) (string, error) {
		out := payloads[i]
		if i < len(payloads)-1 {
			i++
		}
		return out, nil
	}
	var cursor int64
	if _, err := Fetch(context.Background(), exec, now, time.Minute,
		&cursor, "-k"); err != nil {
		t.Fatal(err)
	}
	// Empty read at `later`: the cursor must stay at the last
	// advanced mark — the fetch-1 entry's own timestamp — not jump
	// to `now` or later.UnixMicro().
	got, err := Fetch(context.Background(), exec, later, time.Minute,
		&cursor, "-k")
	if err != nil || len(got) != 0 {
		t.Fatalf("empty fetch: got=%+v err=%v", got, err)
	}
	want := now.UnixMicro() - 1000 // parked at the fetch-1 entry's TSUS
	if cursor != want {
		t.Fatalf("cursor advanced to %d on empty fetch, want %d", cursor, want)
	}
	// The late-flushed record (ts < `later`) is still returned —
	// it survived the parked cursor.
	got, err = Fetch(context.Background(), exec, later, time.Minute,
		&cursor, "-k")
	if err != nil || len(got) != 1 || got[0].Msg != "second" {
		t.Fatalf("late flush lost: got=%+v err=%v", got, err)
	}
}

// TestFetchClockRewindKeepsCursor: a fetch made while the host clock
// sits BEFORE the cursor (stepped back) must not rewind the resume
// point — otherwise the whole window replays.
func TestFetchClockRewindKeepsCursor(t *testing.T) {
	now := time.Unix(1700000000, 0)
	exec := func(context.Context, ...string) (string, error) {
		return entryJSON(now.UnixMicro(), "x"), nil
	}
	cursor := now.UnixMicro() + 60_000_000 // already 60s ahead of `now`
	got, err := Fetch(context.Background(), exec, now, time.Minute,
		&cursor, "-k")
	if err != nil || len(got) != 0 {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	if cursor != now.UnixMicro()+60_000_000 {
		t.Fatalf("cursor rewound to %d", cursor)
	}
}

// TestFetchErrorKeepsCursor: a failed fetch does not advance the
// cursor — the same window is retried next call.
func TestFetchErrorKeepsCursor(t *testing.T) {
	now := time.Unix(1700000000, 0)
	fail := true
	exec := func(context.Context, ...string) (string, error) {
		if fail {
			return "", errors.New("journald busy")
		}
		return entryJSON(now.UnixMicro(), "ok"), nil
	}
	var cursor int64
	if _, err := Fetch(context.Background(), exec, now, time.Minute,
		&cursor, "-k"); err == nil {
		t.Fatal("expected fetch error")
	}
	if cursor != 0 {
		t.Fatalf("cursor advanced on error: %d", cursor)
	}
	fail = false
	got, err := Fetch(context.Background(), exec, now, time.Minute, &cursor, "-k")
	if err != nil || len(got) != 1 {
		t.Fatalf("retry: got=%+v err=%v", got, err)
	}
}

// TestMessageFieldEdges: MESSAGE arrives in shapes the string
// decode cannot take — absent (len 0), a non-string scalar, or a
// non-byte array. All reduce to "" and never fail the batch.
func TestMessageFieldEdges(t *testing.T) {
	data := `{"__REALTIME_TIMESTAMP":"10","MESSAGE":42}` + "\n" +
		`{"__REALTIME_TIMESTAMP":"11"}` + "\n" +
		`{"__REALTIME_TIMESTAMP":"12","MESSAGE":{"nested":1}}`
	got := ParseJSON(data)
	if len(got) != 3 {
		t.Fatalf("got %d entries want 3: %+v", len(got), got)
	}
	for i, e := range got {
		if e.Msg != "" {
			t.Fatalf("entry %d Msg=%q want \"\"", i, e.Msg)
		}
	}
}
