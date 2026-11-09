// Package kmsg holds the /dev/kmsg drain machinery shared by the two
// kernel-log consumers — hostmetrics' kernel-dmesg kernel classifier and
// nodereporter's NPD kernel-monitor port. Both tail the kernel ring
// buffer the way the ported shell watchdog modules did: candidate
// device paths under a host root, an O_NONBLOCK read handle, a
// byte-bounded drain, a partial-line carry across drains, and the
// "pri,seq,usec,flags;msg" record parse. Tailer (tailer.go) owns the
// full tail lifecycle — lazy open/reopen, capped drain, carry and
// the first-scan backlog gates — over these primitives, with the
// per-consumer caps and overflow rules passed in as options. The
// package is a leaf — consumer policy (cursor bookkeeping, the
// lookback replay filter itself, classification, latch/event
// emission, dmesg/journalctl fallbacks) stays in the callers.
package kmsg

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// DevicePaths returns the /dev/kmsg candidates in open order:
// primary first (the DaemonSet bind-mounts host /dev/kmsg at the
// same path), then <hostRoot>/dev/kmsg for layouts that mount the
// whole host /dev (or host root) instead. Empty and duplicate paths
// are dropped.
func DevicePaths(primary, hostRoot string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range []string{primary, filepath.Join(hostRoot, "dev/kmsg")} {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// Open tries the candidate paths in order and returns the first that
// opens O_RDONLY|O_NONBLOCK. O_CLOEXEC keeps the fd out of exec'd
// helpers (journalctl/nsenter) — an inherited kmsg descriptor would
// let a child steal ring records mid-drain. nil when nothing opens.
func Open(paths ...string) *os.File {
	for _, p := range paths {
		if f, err := os.OpenFile(p,
			os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0); err == nil {
			return f
		}
	}
	return nil
}

// Record is one parsed kmsg record — Seq/Parsed for resume cursors,
// Usec for the µs-since-boot lookback filters, Msg for the
// classifiers. Headerless lines keep their whole text in Msg with
// Parsed=false and Usec=-1.
type Record struct {
	Seq    uint64
	Usec   int64
	Msg    string
	Parsed bool
}

// ParseRecord splits one kmsg line "<pri>,<seq>,<usec>,<flags>;<msg>".
// A trailing '\r' is stripped first. The message is whatever follows
// the first ';' — a line without ';' passes through whole with
// Usec=-1 and Parsed=false. Usec decodes from the third header field
// whenever it parses, independent of Seq (a garbage seq still yields
// the timestamp); Parsed reports the FULL strict decode — at least
// three comma fields with both seq and usec numeric — which is what
// cursor-resume dedup is allowed to trust.
func ParseRecord(line []byte) Record {
	s := strings.TrimRight(string(line), "\r")
	i := strings.IndexByte(s, ';')
	if i < 0 {
		return Record{Msg: s, Usec: -1}
	}
	r := Record{Msg: s[i+1:], Usec: -1}
	hdr := strings.Split(s[:i], ",")
	if len(hdr) < 3 {
		return r
	}
	usec, errU := strconv.ParseInt(hdr[2], 10, 64)
	if errU == nil {
		r.Usec = usec
	}
	seq, errS := strconv.ParseUint(hdr[1], 10, 64)
	if errS == nil && errU == nil {
		r.Seq, r.Parsed = seq, true
	}
	return r
}

// SplitLines merges the carried partial line with freshly-drained
// bytes and returns the complete lines plus the unterminated tail to
// carry into the next drain — same contract as the watchdog log
// tail. The carry comes back unbounded: each caller applies its own
// size cap and its own overflow policy (trim-to-tail vs drop).
func SplitLines(pending, data []byte) (lines [][]byte, rest []byte) {
	buf := append(pending, data...)
	last := bytes.LastIndexByte(buf, '\n')
	if last < 0 {
		return nil, buf
	}
	if rem := buf[last+1:]; len(rem) > 0 {
		rest = append([]byte(nil), rem...)
	}
	// Split in place — bytes.Split on a big chunk materialises a
	// [][]byte header per line; IndexByte iteration avoids that.
	for b := buf[:last]; len(b) > 0; {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			lines = append(lines, b)
			break
		}
		lines = append(lines, b[:i])
		b = b[i+1:]
	}
	return lines, rest
}

// Drain pulls every record the kernel currently offers into one
// buffer, bounded by maxBytes per call so a printk flood is
// amortised across ticks (each O_NONBLOCK read returns one ring
// record). The source is an io.Reader — normally the *os.File from
// Open — so tests can script EAGAIN directly (a real O_NONBLOCK
// pipe goes through the runtime poller and would block instead of
// surfacing it). caughtUp reports whether the drain ended because
// the source ran dry — EAGAIN, EOF, a zero-byte read, or a closed
// handle — rather than being cut at the byte cap; callers use it to
// decide when backlog replay ends.
//
// A ring-buffer overrun surfaces as EPIPE on the NEXT read after
// the kernel already auto-advanced the reader past the lost records
// — it is a resume marker, not a handle failure. Treating it as
// fatal made consumers close+reopen the fd (rewinding to the ring
// start and re-emitting the backlog) or fall back to `dmesg -T`
// forks; the right answer is to skip it and keep reading the records
// the kernel now offers. The skip count is bounded so a pathological
// all-EPIPE reader cannot spin the drain forever.
//
// A hard read error returns what the drain gathered: data is nil
// when the erroring read delivered nothing, otherwise the bytes read
// so far accompany the error — partial-output-vs-fatal is the
// caller's policy.
func Drain(r io.Reader, maxBytes int) (data []byte, caughtUp bool, err error) {
	if maxBytes <= 0 {
		return nil, false, nil
	}
	const maxOverruns = 32
	overruns := 0
	var out []byte
	tmp := make([]byte, 32*1024)
	for len(out) <= maxBytes {
		n, rerr := r.Read(tmp)
		if n > 0 {
			out = append(out, tmp[:n]...)
		}
		if rerr != nil {
			if errors.Is(rerr, syscall.EPIPE) {
				// Ring overrun — kernel auto-advanced to the
				// newest records; keep draining (records were
				// lost, but the handle is still good).
				if overruns++; overruns >= maxOverruns {
					return out, false, nil
				}
				continue
			}
			if errors.Is(rerr, syscall.EAGAIN) ||
				errors.Is(rerr, io.EOF) || errors.Is(rerr, os.ErrClosed) {
				return out, true, nil
			}
			if n == 0 {
				return nil, false, rerr
			}
			// Delivered bytes plus a sticky error — keep them.
			return out, false, rerr
		}
		if n == 0 {
			return out, true, nil
		}
	}
	return out, false, nil
}
