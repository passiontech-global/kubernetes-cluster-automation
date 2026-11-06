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
	// argv tail: --since @<epoch-s> -o json --no-pager.
	since1 := calls[0][len(calls[0])-4]
	since2 := calls[1][len(calls[1])-4]
	want1 := "@" + strconv.FormatInt(now.Add(-lookback).Unix(), 10)
	want2 := "@" + strconv.FormatInt(now.Unix(), 10)
	if since1 != want1 || since2 != want2 {
		t.Fatalf("--since args = %q then %q, want %q then %q",
			since1, since2, want1, want2)
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
