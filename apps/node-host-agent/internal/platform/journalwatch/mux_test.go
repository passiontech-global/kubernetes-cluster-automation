// mux_test.go — the shared-tail contract: one exec per poll
// window, per-subscriber match fan-out, pending queues absorbing
// different poll cadences, cursor/error retention.
package journalwatch

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

func muxEntryJSON(tsUS int64, unit, msg string) string {
	return `{"__REALTIME_TIMESTAMP":"` + strconv.FormatInt(tsUS, 10) +
		`","__CURSOR":"cur-` + strconv.FormatInt(tsUS, 10) +
		`","_SYSTEMD_UNIT":"` + unit +
		`","MESSAGE":` + strconv.Quote(msg) + `}` + "\n"
}

func TestMuxSharesOneFetch(t *testing.T) {
	mux := New(func(context.Context, ...string) (string, error) {
		return muxEntryJSON(100, "k0sworker.service", "worker line") +
			muxEntryJSON(200, "k0scontroller.service", "ctrl line") +
			muxEntryJSON(300, "k0sworker.service", "worker two"), nil
	})
	mux.Now = func() time.Time { return time.Unix(1700000000, 0) }
	mux.PollEvery = time.Minute
	if err := mux.Subscribe("wh", func(e Entry) bool {
		return e.Unit == "k0sworker.service"
	}); err != nil {
		t.Fatal(err)
	}
	if err := mux.Subscribe("ch", func(e Entry) bool {
		return e.Unit == "k0scontroller.service"
	}); err != nil {
		t.Fatal(err)
	}

	// First Poll fetches once and fans out by unit.
	wh, err := mux.Poll(context.Background(), "wh")
	if err != nil || len(wh) != 2 {
		t.Fatalf("wh poll: %+v err=%v", wh, err)
	}
	ch, err := mux.Poll(context.Background(), "ch")
	if err != nil || len(ch) != 1 || ch[0].Msg != "ctrl line" {
		t.Fatalf("ch poll: %+v err=%v", ch, err)
	}
	if mux.Fetches() != 1 {
		t.Fatalf("fetches = %d, want 1 shared exec", mux.Fetches())
	}
	// Second Poll inside PollEvery drains pending without exec.
	wh2, err := mux.Poll(context.Background(), "wh")
	if err != nil || len(wh2) != 0 {
		t.Fatalf("wh re-poll inside window: %+v err=%v", wh2, err)
	}
	if mux.Fetches() != 1 {
		t.Fatalf("fetches = %d after in-window poll", mux.Fetches())
	}
}

func TestMuxSlowSubscriberKeepsEntries(t *testing.T) {
	var calls int
	mux := New(func(context.Context, ...string) (string, error) {
		calls++
		return muxEntryJSON(int64(100+calls), "u", "line"), nil
	})
	base := time.Unix(1700000000, 0)
	var tick int64
	mux.Now = func() time.Time { return base.Add(time.Duration(tick) * time.Minute) }
	mux.PollEvery = time.Minute
	_ = mux.Subscribe("slow", nil)
	_ = mux.Subscribe("fast", nil)

	// fast polls every minute; slow skips three windows — its queue
	// must still hold every entry (up to cap).
	for i := 0; i < 4; i++ {
		tick = int64(i)
		if _, err := mux.Poll(context.Background(), "fast"); err != nil {
			t.Fatal(err)
		}
	}
	got, err := mux.Poll(context.Background(), "slow")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("slow sub drained %d entries, want all 4", len(got))
	}
}

func TestMuxFetchErrorRetains(t *testing.T) {
	fail := true
	mux := New(func(context.Context, ...string) (string, error) {
		if fail {
			return "", errors.New("journald busy")
		}
		return muxEntryJSON(100, "u", "ok"), nil
	})
	_ = mux.Subscribe("s", nil)
	if _, err := mux.Poll(context.Background(), "s"); err == nil {
		t.Fatal("expected fetch error")
	}
	if mux.Cursor() != "" {
		t.Fatalf("cursor advanced on error: %q", mux.Cursor())
	}
	fail = false
	got, err := mux.Poll(context.Background(), "s")
	if err != nil || len(got) != 1 {
		t.Fatalf("retry: %+v err=%v", got, err)
	}
}

func TestMuxUnknownSubscriber(t *testing.T) {
	mux := New(func(context.Context, ...string) (string, error) { return "", nil })
	if _, err := mux.Poll(context.Background(), "ghost"); err == nil ||
		!strings.Contains(err.Error(), "ghost") {
		t.Fatalf("err = %v, want unknown-subscriber", err)
	}
}

// TestMuxRequeue: failed deliveries go back on the pending FRONT in
// journal order — ahead of anything fetched since — so the next
// Poll retries them before newer entries. Unknown ids error; an
// empty slice is a no-op; overflow drops the OLDEST requeued
// entries like fetch fan-out does.
func TestMuxRequeue(t *testing.T) {
	mux := New(func(context.Context, ...string) (string, error) {
		return muxEntryJSON(100, "u", "one") +
			muxEntryJSON(200, "u", "two") +
			muxEntryJSON(300, "u", "three"), nil
	})
	mux.Now = func() time.Time { return time.Unix(1700000000, 0) }
	mux.PollEvery = time.Minute
	if err := mux.Subscribe("s", nil); err != nil {
		t.Fatal(err)
	}
	got, err := mux.Poll(context.Background(), "s")
	if err != nil || len(got) != 3 {
		t.Fatalf("poll: %+v err=%v", got, err)
	}
	// "one" failed to deliver — it must retry BEFORE the entries a
	// later fetch appends.
	if err := mux.Requeue("s", got[:1]); err != nil {
		t.Fatal(err)
	}
	// Unknown subscriber + empty requeue contracts.
	if err := mux.Requeue("ghost", got[:1]); err == nil ||
		!strings.Contains(err.Error(), "ghost") {
		t.Fatalf("requeue ghost err = %v", err)
	}
	if err := mux.Requeue("s", nil); err != nil {
		t.Fatalf("empty requeue err = %v", err)
	}
	// Force the next poll to fetch (window elapsed): "four" lands
	// behind the requeued "one".
	mux.Now = func() time.Time { return time.Unix(1700000120, 0) }
	mux.Exec = func(context.Context, ...string) (string, error) {
		return muxEntryJSON(400, "u", "four"), nil
	}
	got, err = mux.Poll(context.Background(), "s")
	if err != nil || len(got) != 2 {
		t.Fatalf("poll2: %+v err=%v", got, err)
	}
	if got[0].Msg != "one" || got[1].Msg != "four" {
		t.Fatalf("order = %q,%q — want requeued 'one' before new 'four'",
			got[0].Msg, got[1].Msg)
	}
}

// TestMuxRequeueOverflowDropsOldest: a pending queue already at cap
// keeps the NEWEST entries when requeued failures overflow it —
// same oldest-first policy as fetch fan-out.
func TestMuxRequeueOverflowDropsOldest(t *testing.T) {
	mux := New(func(context.Context, ...string) (string, error) {
		return "", nil
	})
	mux.PollEvery = time.Minute
	if err := mux.Subscribe("s", nil); err != nil {
		t.Fatal(err)
	}
	sub := mux.subs["s"]
	sub.cap = 3
	// Queue already holds 3 entries at cap.
	sub.pending = []Entry{{Msg: "p1"}, {Msg: "p2"}, {Msg: "p3"}}
	// Requeue 2 failed entries → total 5, cap 3 → drop the 2
	// oldest, which are the requeued ones (they hold the oldest
	// journal positions).
	if err := mux.Requeue("s", []Entry{{Msg: "f1"}, {Msg: "f2"}}); err != nil {
		t.Fatal(err)
	}
	if len(sub.pending) != 3 {
		t.Fatalf("pending len = %d, want cap 3", len(sub.pending))
	}
	if sub.pending[0].Msg != "p1" {
		t.Fatalf("pending[0] = %q, want p1 (both requeued entries dropped)", sub.pending[0].Msg)
	}
	if mux.Dropped("s") != 2 {
		t.Fatalf("dropped = %d, want 2", mux.Dropped("s"))
	}
}
