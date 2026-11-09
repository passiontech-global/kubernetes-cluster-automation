// tailer.go — Tailer: the /dev/kmsg tail lifecycle both kernel-log
// consumers used to hand-roll in parallel — lazy open over the
// candidate device paths, the byte-capped O_NONBLOCK drain, the
// partial-line carry across drains, and the first-scan backlog
// gates (the lookback window stays armed until a drain ends
// caught-up; a reopen re-arms it). The Tailer owns ONLY the
// mechanics: cursor bookkeeping, record classification and
// latch/event emission stay in the consumers (hostmetrics' kernel-dmesg
// scanner, nodereporter's NPD kernel monitor), which is why every
// point they legitimately diverged on — whether the carry counts
// against the drain budget, the pending overflow rule, and the
// partial-data-on-error verdict — is an explicit option, not a
// shared default.
package kmsg

import (
	"errors"
	"os"
)

// ErrNoDevice reports that no candidate device path opened — the
// consumers' no-device fallback trigger (hostmetrics → dmesg,
// nodereporter → `journalctl -k`). It is distinct from a mid-stream
// read failure on an already-open handle, which the consumers
// answer with Close so the next Read re-opens and re-arms the
// backlog gates.
var ErrNoDevice = errors.New("kmsg: no device path opened")

// TailerOptions carries the per-consumer tail policy. The byte caps
// and overflow rules are behavior-parity contract, so the shared
// lifecycle takes them as options instead of picking defaults.
type TailerOptions struct {
	// Paths returns the candidate device paths tried in order on
	// every (re)open — DevicePaths output. It is re-evaluated per
	// open so the consumers' config values and test seams stay live.
	Paths func() []string
	// DrainCap bounds the fresh bytes pulled per Read — a printk
	// flood is sliced across Reads instead of slurping the whole
	// ring in one cycle.
	DrainCap int
	// DrainIncludesPending counts the carried partial line against
	// DrainCap (hostmetrics: the tick cap bounds pending+fresh
	// bytes); false drains a flat DrainCap of fresh bytes
	// (nodereporter).
	DrainIncludesPending bool
	// PendingCap bounds the partial-line carry; <=0 leaves it
	// unbounded.
	PendingCap int
	// PendingTrimTail picks the overflow policy: keep the carry's
	// tail bytes (nodereporter — a never-terminated record keeps its
	// end, same as the watchdog filelog tail) vs drop the carry
	// whole (hostmetrics — one record can't sanely exceed the cap).
	PendingTrimTail bool
	// KeepPartialOnError turns a drain that delivered bytes before
	// hitting a hard error into a successful Read of those bytes
	// (hostmetrics) — the same error resurfaces on the next Read,
	// which then delivers nothing. false fails the Read outright
	// and discards the delivered bytes with the doomed handle
	// (nodereporter).
	KeepPartialOnError bool
}

// ReadResult reports where one Read sits in the current handle's
// lifecycle — the two backlog-disposition gates the consumers used
// to track by hand.
type ReadResult struct {
	// First marks the first successful read on the current handle —
	// hostmetrics' "primed" gate: the retained ring on first open is
	// history, not news (a resume cursor overrides the gate).
	First bool
	// Backlog reports that the first-scan lookback window was still
	// armed when these lines were pulled. It arms on every (re)open
	// and stays armed until a drain ends caught-up, so a ring
	// backlog bigger than one DrainCap keeps replaying through the
	// consumer's age filter across Reads instead of turning live
	// mid-flood (nodereporter's replay gate — a stale hung-task
	// record must not latch a permanent condition on agent start).
	Backlog bool
	// CaughtUp reports whether the current handle has drained to
	// EAGAIN/EOF at least once — the post-read form of Backlog.
	CaughtUp bool
}

// Tailer owns one /dev/kmsg tail: the lazily-opened O_NONBLOCK
// handle, the partial-line carry and the backlog gates. Not
// goroutine-safe — one Tailer per tail loop.
type Tailer struct {
	opts    TailerOptions
	f       *os.File // nil until the first successful open
	pending []byte   // carried partial line — survives Close (see there)
	reads   int      // successful reads on the current handle
	caught  bool     // the current handle drained dry at least once
}

// NewTailer returns a Tailer that opens its device lazily on the
// first Read (and on the first Read after every Close). The options
// are normalized here: when the carry counts against the drain
// budget, PendingCap >= DrainCap would zero the budget as soon as
// the carry saturates — Drain(<=0) then returns caught-up with no
// data every tick and the tail wedges forever (the carry can never
// shrink below the cap it equals). The constructor has no error
// return, so the invariant is clamped instead: PendingCap leaves at
// least one fresh byte per drain, and Read clamps the remaining
// budget as belt-and-braces for unbounded carries.
func NewTailer(opts TailerOptions) *Tailer {
	if opts.DrainIncludesPending && opts.DrainCap > 0 &&
		opts.PendingCap >= opts.DrainCap {
		opts.PendingCap = opts.DrainCap - 1
	}
	return &Tailer{opts: opts}
}

// Read opens the device lazily when no handle is held, drains up to
// DrainCap fresh bytes (optionally minus the carried partial line),
// splits the result into complete record lines and re-arms the
// carry. ErrNoDevice means no candidate path opened — the caller's
// no-device fallback; any other error is a mid-stream read failure
// the caller answers with Close. The carry is only consumed on a
// successful read — a failed Read leaves it for the next handle to
// rejoin.
func (t *Tailer) Read() (lines [][]byte, res ReadResult, err error) {
	if t.f == nil {
		f := Open(t.opts.Paths()...)
		if f == nil {
			return nil, ReadResult{}, ErrNoDevice
		}
		t.f = f
	}
	maxBytes := t.opts.DrainCap
	if t.opts.DrainIncludesPending {
		// The pending carry counts against this Read's drain budget
		// — the cap bounds pending+fresh bytes, not just fd reads.
		maxBytes -= len(t.pending)
		// A saturated carry (unbounded PendingCap, or a cap clamped
		// only here) can zero the budget — Drain(<=0) returns
		// caught-up with no data and the tail would never advance.
		// Clamp to one byte: every Read makes progress, and the
		// PendingCap trim below still keeps the carry bounded.
		if maxBytes < 1 {
			maxBytes = 1
		}
	}
	fresh, caughtUp, derr := Drain(t.f, maxBytes)
	if derr != nil {
		if len(fresh) == 0 || !t.opts.KeepPartialOnError {
			return nil, ReadResult{}, derr
		}
		// Delivered bytes plus a sticky error — keep them; the error
		// resurfaces on the next Read.
	}
	res = ReadResult{
		First:   t.reads == 0,
		Backlog: !t.caught,
	}
	t.reads++
	if caughtUp {
		t.caught = true
	}
	res.CaughtUp = t.caught

	lines, rest := SplitLines(t.pending, fresh)
	if t.opts.PendingCap > 0 && len(rest) > t.opts.PendingCap {
		if t.opts.PendingTrimTail {
			// A never-terminated record keeps only its tail so the
			// carry cannot grow without bound.
			rest = rest[len(rest)-t.opts.PendingCap:]
		} else {
			// A single record can't exceed this sanely — drop the
			// carry rather than grow without bound.
			rest = nil
		}
	}
	t.pending = rest
	return lines, res, nil
}

// Close drops the open handle so the next Read re-opens the device
// — the consumers' answer to a mid-stream read error. The backlog
// gates reset with the handle (a reopen replays the retained ring
// through the lookback filter instead of emitting it live), and the
// partial-line carry is dropped WITH it: the reopened handle resumes
// at a different ring position (the kernel rewinds or auto-advances
// on reopen), so splicing the stale carry onto the next first record
// would corrupt a line.
func (t *Tailer) Close() {
	if t.f != nil {
		_ = t.f.Close()
		t.f = nil
	}
	t.reads = 0
	t.caught = false
	t.pending = nil
}
