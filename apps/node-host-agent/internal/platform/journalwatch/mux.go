// mux.go — the Multiplexer: ONE journal tail shared by every
// subsystem that consumes `journalctl -o json` entries. The audit
// target was N subsystems each forking their own journalctl per
// cycle; the mux collapses that to a single read per poll window
// with per-subscriber match predicates applied in RAM — the
// "phân phối sự kiện trong RAM" half of the L1 design.
//
// Pull model (no background goroutine, no streaming exec): each
// subscriber's cycle calls Poll(ctx, id); the FIRST Poll past the
// PollEvery staleness window runs one journalctl fetch for the
// whole journal, advances the shared __CURSOR through the last
// COMPLETE decoded line (the 16 MiB cap contract from json.go),
// and appends each subscriber's matched entries to that sub's
// pending queue. Every later Poll — by any subscriber — drains
// only its own queue, so a slow consumer never blocks the shared
// read and a fast one never waits on the slow one's processing.
//
// Correctness: the shared cursor is a JOURNAL position, not a
// per-sub consumption mark — entries sit in per-sub pending queues
// until drained, so subscribers polling at different cadences all
// see every matched entry exactly once. A fetch error leaves the
// cursor and every queue untouched; the same window retries.
package journalwatch

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// DefaultLookback bounds the first (cursor-less) fetch — the
// replay window before the mux has a journal position.
const DefaultLookback = 10 * time.Minute

// DefaultPollEvery is the minimum interval between shared fetches
// when PollEvery is unset — one journalctl per window regardless
// of how many subscribers poll inside it.
const DefaultPollEvery = 30 * time.Second

// DefaultPendingCap bounds one subscriber's queue; a consumer that
// stops polling must not grow RAM without limit — overflow drops
// the OLDEST entries (the sub is already behind; newest state
// matters more for watchdog semantics).
const DefaultPendingCap = 8192

// MatchFunc reports whether an Entry belongs to a subscriber.
// nil matches everything.
type MatchFunc func(Entry) bool

// Multiplexer is the shared journal tail. Construct with the
// ExecFunc seam (the nsenter-wrapped host journalctl in production,
// a stub in tests); Poll is safe for concurrent use — the fetch
// itself is serialized on the mux mutex so two racing Polls can
// never double-read the same window.
type Multiplexer struct {
	// Exec runs `journalctl <args>` — required.
	Exec ExecFunc
	// Now is the clock seam; nil → time.Now.
	Now func() time.Time
	// Lookback bounds the first fetch's --since window; <=0 →
	// DefaultLookback.
	Lookback time.Duration
	// PollEvery is the minimum interval between shared fetches;
	// 0 → DefaultPollEvery. Subscribers polling inside the window
	// drain their pending queues without a new exec. A NEGATIVE
	// value disables throttling — every Poll fetches (the seam
	// per-consumer cadence tests use so each sync maps to one exec).
	PollEvery time.Duration
	// Args are EXTRA journalctl args prepended to every fetch
	// (e.g. a priority floor "-p warning"); empty reads the whole
	// journal and lets Match predicates do the filtering — the
	// audit's one-stream design.
	Args []string

	mu         sync.Mutex
	cursor     string
	lastFetch  time.Time
	subs       map[string]*muxSub
	fetchErr   error // last fetch error, surfaced to Poll callers
	fetchCount int
	// fetchMu serializes the journalctl exec OUTSIDE m.mu — the
	// subprocess can run for seconds and must not stall Subscribe,
	// Cursor or every other subscriber's queue drain. State
	// (staleness check + commit) stays on m.mu; only the exec
	// window is lock-free.
	fetchMu sync.Mutex
}

type muxSub struct {
	match   MatchFunc
	cap     int
	pending []Entry
	dropped int
}

// New returns a Multiplexer over execFn.
func New(execFn ExecFunc) *Multiplexer {
	return &Multiplexer{Exec: execFn, subs: map[string]*muxSub{}}
}

func (m *Multiplexer) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Multiplexer) lookback() time.Duration {
	if m.Lookback <= 0 {
		return DefaultLookback
	}
	return m.Lookback
}

func (m *Multiplexer) pollEvery() time.Duration {
	if m.PollEvery < 0 {
		return 0
	}
	if m.PollEvery == 0 {
		return DefaultPollEvery
	}
	return m.PollEvery
}

// Subscribe registers a consumer under id with its match predicate.
// Re-subscribing the same id REPLACES the predicate and keeps the
// pending queue — a subsystem rebuilding its monitor mid-run must
// not lose entries already fetched for it. Returns an error on an
// empty id.
func (m *Multiplexer) Subscribe(id string, match MatchFunc) error {
	if id == "" {
		return errors.New("journalwatch: empty subscriber id")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.subs[id]; ok {
		s.match = match
		return nil
	}
	m.subs[id] = &muxSub{match: match, cap: DefaultPendingCap}
	return nil
}

// Poll drains subscriber id's pending queue, fetching the shared
// journal window first when the last fetch is older than
// PollEvery (or never happened). Returns the matched entries in
// journal order; an empty slice with nil error means "nothing new"
// — NOT an error. Unknown ids and exec failures return errors; a
// failed fetch leaves every queue and the cursor untouched so the
// next Poll retries the identical window.
func (m *Multiplexer) Poll(ctx context.Context, id string) ([]Entry, error) {
	m.mu.Lock()
	sub, ok := m.subs[id]
	if !ok {
		m.mu.Unlock()
		return nil, fmt.Errorf("journalwatch: unknown subscriber %q", id)
	}
	if m.Exec == nil {
		m.mu.Unlock()
		return nil, errors.New("journalwatch: nil Exec")
	}
	needFetch := m.lastFetch.IsZero() || m.pollEvery() == 0 ||
		m.now().Sub(m.lastFetch) >= m.pollEvery()
	m.mu.Unlock()

	if needFetch {
		// The journalctl exec runs outside m.mu (fetchMu
		// serializes concurrent fetchers) so a slow read never
		// stalls Subscribe/Cursor/other drains.
		if err := m.maybeFetch(ctx); err != nil {
			return nil, err
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	out := sub.pending
	sub.pending = nil
	return out, nil
}

// maybeFetch runs one shared journalctl read when the window is
// still stale — the staleness re-check inside fetchMu means a
// Poll that queued behind another fetcher's exec does not
// double-read. The mutex is held only for the state check and the
// commit; the subprocess itself runs unlocked.
func (m *Multiplexer) maybeFetch(ctx context.Context) error {
	m.fetchMu.Lock()
	defer m.fetchMu.Unlock()

	m.mu.Lock()
	if !m.lastFetch.IsZero() && m.pollEvery() != 0 &&
		m.now().Sub(m.lastFetch) < m.pollEvery() {
		m.mu.Unlock()
		return nil // another fetcher refreshed the window
	}
	var cursor = m.cursor
	now := m.now()
	m.mu.Unlock()

	entries, err := Fetch(ctx, m.Exec, now, m.lookback(), &cursor, m.Args...)

	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.fetchErr = err
		return err
	}
	// cursor advanced inside Fetch through the last COMPLETE line;
	// committing it here (not before) keeps a mid-parse failure
	// from losing the window. lastFetch updates on EVERY successful
	// read — an empty journal window is still a fresh fetch and
	// must not re-exec journalctl on every Poll.
	m.cursor = cursor
	m.lastFetch = m.now()
	m.fetchCount++
	m.fetchErr = nil
	for _, e := range entries {
		for _, sub := range m.subs {
			if sub.match != nil && !sub.match(e) {
				continue
			}
			sub.pending = append(sub.pending, e)
			if len(sub.pending) > sub.cap {
				// Drop oldest — copy within the same backing array
				// region is fine; the dropped prefix is dead.
				n := len(sub.pending) - sub.cap
				copy(sub.pending, sub.pending[n:])
				sub.pending = sub.pending[:sub.cap]
				sub.dropped += n
			}
		}
	}
	return nil
}

// Requeue returns drained entries to subscriber id's pending FRONT
// — the emit-failure retry path: the shared cursor already advanced
// past these entries at fetch time, so a consumer that could not
// deliver every Event puts the unprocessed ones back and the next
// Poll retries them (the pending queue IS the per-consumer cursor).
// Entries are prepended in journal order; overflow drops the oldest
// exactly like fetch fan-out does. Unknown ids are a no-op error.
func (m *Multiplexer) Requeue(id string, entries []Entry) error {
	if len(entries) == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	sub, ok := m.subs[id]
	if !ok {
		return fmt.Errorf("journalwatch: unknown subscriber %q", id)
	}
	sub.pending = append(append([]Entry(nil), entries...), sub.pending...)
	if len(sub.pending) > sub.cap {
		n := len(sub.pending) - sub.cap
		// The requeued entries are the OLDEST journal positions —
		// dropping the prefix keeps the same oldest-first policy as
		// fetch overflow.
		sub.pending = sub.pending[n:]
		sub.dropped += n
	}
	return nil
}

// Cursor exposes the shared journal position — tests/debug; ""
// means the first fetch has not completed.
func (m *Multiplexer) Cursor() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cursor
}

// Fetches counts completed shared fetches — tests/debug.
func (m *Multiplexer) Fetches() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.fetchCount
}

// Dropped reports how many pending entries subscriber id lost to
// the cap overflow — tests/debug.
func (m *Multiplexer) Dropped(id string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.subs[id]; ok {
		return s.dropped
	}
	return 0
}
