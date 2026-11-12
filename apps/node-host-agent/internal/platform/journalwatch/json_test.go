// json_test.go — coverage for the `journalctl -o json` tail: the
// line decode (string vs byte-array MESSAGE, malformed lines,
// __CURSOR/_SYSTEMD_UNIT fields) and Fetch's cursor contract
// (lookback-bounded first fetch, --cursor forward reads, advance
// to the last COMPLETE decoded line only, retention on error).
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

// entryJSON emits one journal line whose __CURSOR derives from the
// timestamp — distinct ts ⇒ distinct cursor, matching the journal's
// monotonic-position contract closely enough for fixtures.
func entryJSON(tsUS int64, msg string) string {
	return fmt.Sprintf(
		`{"__REALTIME_TIMESTAMP":"%d","__CURSOR":"cur-%d","MESSAGE":%s}`,
		tsUS, tsUS, strconv.Quote(msg))
}

// TestParseJSON: MESSAGE arrives as a JSON string or a byte array
// (non-UTF8 payloads); malformed lines are skipped; __CURSOR and
// _SYSTEMD_UNIT decode through.
func TestParseJSON(t *testing.T) {
	data := `{"__REALTIME_TIMESTAMP":"1700000000000000","__CURSOR":"c1","_SYSTEMD_UNIT":"k0sworker.service","MESSAGE":` +
		strconv.Quote(`node "n1" not found`) + `}` + "\n" +
		"not-json-garbage\n" +
		`{"__REALTIME_TIMESTAMP":"1700000001000000","__CURSOR":"c2","MESSAGE":[104,101,108,108,111]}` + "\n"
	got := ParseJSON(data)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(got), got)
	}
	if got[0].TSUS != 1700000000000000 || !strings.Contains(got[0].Msg, "not found") {
		t.Fatalf("entry 0 = %+v", got[0])
	}
	if got[0].Cursor != "c1" || got[0].Unit != "k0sworker.service" || got[1].Cursor != "c2" {
		t.Fatalf("cursor/unit decode: %+v %+v", got[0], got[1])
	}
	if got[1].Msg != "hello" {
		t.Fatalf("byte-array MESSAGE decoded to %q", got[1].Msg)
	}
}

// TestFetchCursor: the first fetch is --since-bounded to lookback;
// every later fetch is an --after-cursor=<opaque> forward read and
// the cursor lands on the last entry's __CURSOR — strictly-newer
// filtering is journalctl's job now, so same-timestamp entries
// can neither duplicate nor drop.
func TestFetchCursor(t *testing.T) {
	now := time.Unix(1700000000, 0)
	lookback := 5 * time.Minute
	ts1 := now.UnixMicro() - 1000
	ts2 := now.UnixMicro() + 1000
	var calls [][]string
	payloads := []string{
		entryJSON(ts1, "first"),
		// Real journalctl honors --cursor and would never replay
		// "first"; the stub returns only genuinely new entries.
		entryJSON(ts2, "second"),
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
	var cursor string
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
	// argv tail: --since @<epoch-s> --lines=10000 -o json
	// --no-pager, then --after-cursor=<opaque> --lines=10000 -o json
	// --no-pager. --after-cursor (not --cursor) keeps the boundary
	// entry from being served twice; --lines bounds each read.
	if calls[0][len(calls[0])-6] != "--since" ||
		calls[0][len(calls[0])-5] != "@"+strconv.FormatInt(now.Add(-lookback).Unix(), 10) ||
		calls[0][len(calls[0])-4] != "--lines=10000" {
		t.Fatalf("fetch-1 argv tail = %q", calls[0][len(calls[0])-7:])
	}
	if !strings.HasPrefix(calls[1][len(calls[1])-5], "--after-cursor=cur-") ||
		calls[1][len(calls[1])-4] != "--lines=10000" {
		t.Fatalf("fetch-2 argv tail = %q, want --after-cursor= --lines=",
			calls[1][len(calls[1])-6:])
	}
	if cursor != "cur-"+strconv.FormatInt(ts2, 10) {
		t.Fatalf("cursor = %q, want last entry's __CURSOR", cursor)
	}
}

// TestFetchTruncatedTailKeepsCursor: when the exec capture cap cuts
// the stream mid-line, the partial tail fails to decode and the
// cursor parks on the last COMPLETE record — the next fetch
// resumes exactly there instead of skipping the truncated region.
func TestFetchTruncatedTailKeepsCursor(t *testing.T) {
	now := time.Unix(1700000000, 0)
	ts1 := now.UnixMicro() - 1000
	ts2 := now.UnixMicro()
	payload := entryJSON(ts1, "complete") + "\n" +
		`{"__REALTIME_TIMESTAMP":"` + strconv.FormatInt(ts2, 10) // cut mid-line
	var cursor string
	exec := func(context.Context, ...string) (string, error) { return payload, nil }
	got, err := Fetch(context.Background(), exec, now, time.Minute, &cursor, "-k")
	if err != nil || len(got) != 1 || got[0].Msg != "complete" {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	if cursor != "cur-"+strconv.FormatInt(ts1, 10) {
		t.Fatalf("cursor = %q, want parked at last complete line", cursor)
	}
}

// TestFetchEmptyKeepsCursor: an empty read must not move the
// cursor — the window retries identically next call.
func TestFetchEmptyKeepsCursor(t *testing.T) {
	now := time.Unix(1700000000, 0)
	payloads := []string{
		entryJSON(now.UnixMicro()-1000, "first"),
		"", // quiet window
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
	var cursor string
	if _, err := Fetch(context.Background(), exec, now, time.Minute,
		&cursor, "-k"); err != nil {
		t.Fatal(err)
	}
	want := "cur-" + strconv.FormatInt(now.UnixMicro()-1000, 10)
	got, err := Fetch(context.Background(), exec, now.Add(30*time.Second),
		time.Minute, &cursor, "-k")
	if err != nil || len(got) != 0 {
		t.Fatalf("empty fetch: got=%+v err=%v", got, err)
	}
	if cursor != want {
		t.Fatalf("cursor moved on empty fetch: %q want %q", cursor, want)
	}
	got, err = Fetch(context.Background(), exec, now.Add(30*time.Second),
		time.Minute, &cursor, "-k")
	if err != nil || len(got) != 1 || got[0].Msg != "second" {
		t.Fatalf("late flush lost: got=%+v err=%v", got, err)
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
	var cursor string
	if _, err := Fetch(context.Background(), exec, now, time.Minute,
		&cursor, "-k"); err == nil {
		t.Fatal("expected fetch error")
	}
	if cursor != "" {
		t.Fatalf("cursor advanced on error: %q", cursor)
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
