// kmsg_test.go — unit coverage for the shared drain machinery:
// record parse (strict + headerless paths), the partial-line carry,
// and the byte-capped O_NONBLOCK drain (scripted readers — a real
// O_NONBLOCK pipe goes through the runtime poller and can't surface
// EAGAIN to callers).
package kmsg

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestParseRecord: full header decodes seq/usec/msg; a headerless
// line passes through whole; a garbage header still yields the
// post-';' message with usec decoded independently of seq.
func TestParseRecord(t *testing.T) {
	r := ParseRecord([]byte("6,1234,9876543210,-;EXT4-fs error (device vda1): x"))
	if !r.Parsed || r.Seq != 1234 || r.Usec != 9876543210 ||
		r.Msg != "EXT4-fs error (device vda1): x" {
		t.Fatalf("full record = %+v", r)
	}
	r = ParseRecord([]byte("no header message"))
	if r.Parsed || r.Msg != "no header message" || r.Usec != -1 {
		t.Fatalf("headerless = %+v", r)
	}
	// ';' but fewer than three header fields → message after ';'.
	r = ParseRecord([]byte("garbage;tail"))
	if r.Parsed || r.Msg != "tail" || r.Usec != -1 {
		t.Fatalf("short header = %+v", r)
	}
	// Bad usec → unknown timestamp, message still split out.
	r = ParseRecord([]byte("6,1,notanum,-;broken ts"))
	if r.Parsed || r.Msg != "broken ts" || r.Usec != -1 {
		t.Fatalf("bad usec = %+v", r)
	}
	// Bad seq, good usec → usec survives, strict Parsed stays false.
	r = ParseRecord([]byte("6,zzz,42,-;seq broken"))
	if r.Parsed || r.Usec != 42 || r.Msg != "seq broken" {
		t.Fatalf("bad seq = %+v", r)
	}
	// Trailing CR stripped before the header/message split.
	r = ParseRecord([]byte("6,1,7,-;msg\r"))
	if !r.Parsed || r.Msg != "msg" || r.Seq != 1 || r.Usec != 7 {
		t.Fatalf("cr-terminated = %+v", r)
	}
}

// TestSplitLines: a trailing partial line is carried into the next
// drain; empty lines pass through; a buffer with no newline is all
// carry. Size caps are caller policy and exercised there.
func TestSplitLines(t *testing.T) {
	lines, rest := SplitLines(nil, []byte("a\nb\npart"))
	if len(lines) != 2 || string(lines[0]) != "a" || string(lines[1]) != "b" ||
		string(rest) != "part" {
		t.Fatalf("split: lines=%q rest=%q", lines, rest)
	}
	// The carry rejoins the next chunk into a complete line.
	lines, rest = SplitLines(rest, []byte("ial\nc\n"))
	if len(lines) != 2 || string(lines[0]) != "partial" || string(lines[1]) != "c" ||
		rest != nil {
		t.Fatalf("carry: lines=%q rest=%q", lines, rest)
	}
	// No newline at all → everything is carry.
	lines, rest = SplitLines(nil, []byte("unterminated"))
	if lines != nil || string(rest) != "unterminated" {
		t.Fatalf("no-newline: lines=%q rest=%q", lines, rest)
	}
	// Empty lines are emitted — the consumers' matchers simply don't
	// fire on them.
	lines, rest = SplitLines(nil, []byte("\n\nx\n"))
	if len(lines) != 3 || string(lines[0]) != "" || string(lines[1]) != "" ||
		string(lines[2]) != "x" || rest != nil {
		t.Fatalf("empty lines: lines=%q rest=%q", lines, rest)
	}
}

// scriptReader plays back a scripted sequence of read results —
// Drain's EAGAIN semantics need a reader that surfaces it raw: a
// real O_NONBLOCK pipe goes through the runtime poller (which parks
// the read instead of returning EAGAIN) and a regular file never
// returns it at all.
type scriptReader struct {
	reads []readResult
	i     int
}

type readResult struct {
	data string
	err  error
}

func (s *scriptReader) Read(p []byte) (int, error) {
	if s.i >= len(s.reads) {
		return 0, io.EOF
	}
	r := s.reads[s.i]
	s.i++
	if r.data == "" {
		return 0, r.err
	}
	n := copy(p, r.data)
	return n, r.err
}

var errBoom = errors.New("boom")

// TestDrainEAGAIN: a nonblocking source that runs dry reports
// caughtUp=true with everything read so far.
func TestDrainEAGAIN(t *testing.T) {
	payload := "6,1,5,-;one\n6,2,6,-;two\n"
	r := &scriptReader{reads: []readResult{
		{data: payload}, {err: syscall.EAGAIN},
	}}
	data, caughtUp, err := Drain(r, 1<<20)
	if err != nil || !caughtUp || string(data) != payload {
		t.Fatalf("data=%q caughtUp=%v err=%v", data, caughtUp, err)
	}
}

// TestDrainByteCap: a source with more than the cap stops at it and
// reports caughtUp=false — the flood is sliced, not slurped.
func TestDrainByteCap(t *testing.T) {
	r := &scriptReader{reads: []readResult{
		{data: strings.Repeat("x", 32*1024)},
		{data: strings.Repeat("y", 32*1024)},
		{err: syscall.EAGAIN},
	}}
	data, caughtUp, err := Drain(r, 4)
	if err != nil || caughtUp {
		t.Fatalf("cap drain: caughtUp=%v err=%v", caughtUp, err)
	}
	if len(data) != 32*1024 {
		t.Fatalf("cap drain: len=%d, want one read buffer", len(data))
	}
	// The rest of the scripted input is still there for next drain.
	if r.i != 1 {
		t.Fatalf("drained %d scripted reads, want 1", r.i)
	}
}

// TestDrainEOF: EOF counts as a dry source, same as EAGAIN.
func TestDrainEOF(t *testing.T) {
	r := &scriptReader{reads: []readResult{{data: "x\n"}}}
	data, caughtUp, err := Drain(r, 1<<20)
	if err != nil || !caughtUp || string(data) != "x\n" {
		t.Fatalf("eof drain: data=%q caughtUp=%v err=%v", data, caughtUp, err)
	}
	// A zero-byte nil-error read is also "dry".
	r = &scriptReader{reads: []readResult{{}}}
	if _, caughtUp, err = Drain(r, 1<<20); err != nil || !caughtUp {
		t.Fatalf("zero-read drain: caughtUp=%v err=%v", caughtUp, err)
	}
}

// TestDrainNonPositiveCap: a spent budget reads nothing and is not
// "caught up" — the source was never tried.
func TestDrainNonPositiveCap(t *testing.T) {
	r := &scriptReader{reads: []readResult{{data: "x"}}}
	data, caughtUp, err := Drain(r, 0)
	if err != nil || caughtUp || data != nil || r.i != 0 {
		t.Fatalf("zero cap: data=%q caughtUp=%v err=%v reads=%d",
			data, caughtUp, err, r.i)
	}
}

// TestDrainClosedHandle: a closed fd counts as a dry source, not a
// drain error.
func TestDrainClosedHandle(t *testing.T) {
	r := &scriptReader{reads: []readResult{{err: os.ErrClosed}}}
	data, caughtUp, err := Drain(r, 1<<20)
	if err != nil || !caughtUp || data != nil {
		t.Fatalf("closed drain: data=%q caughtUp=%v err=%v", data, caughtUp, err)
	}
}

// TestDrainHardError: a hard error with nothing delivered fails the
// drain (nil data); delivered bytes ride along with the error so the
// caller can keep them.
func TestDrainHardError(t *testing.T) {
	r := &scriptReader{reads: []readResult{{err: errBoom}}}
	data, caughtUp, err := Drain(r, 1<<20)
	if err != errBoom || caughtUp || data != nil {
		t.Fatalf("empty hard error: data=%q caughtUp=%v err=%v",
			data, caughtUp, err)
	}
	r = &scriptReader{reads: []readResult{
		{data: "6,1,5,-;one\n"}, {data: "tail", err: errBoom},
	}}
	data, caughtUp, err = Drain(r, 1<<20)
	if err != errBoom || caughtUp || string(data) != "6,1,5,-;one\ntail" {
		t.Fatalf("sticky error: data=%q caughtUp=%v err=%v",
			data, caughtUp, err)
	}
	// Same, but the error arrives with n==0 after earlier reads —
	// an empty erroring read fails the whole drain (the carry
	// contract of the hostmetrics session this mirrors).
	r = &scriptReader{reads: []readResult{
		{data: "6,1,5,-;one\n"}, {err: errBoom},
	}}
	data, caughtUp, err = Drain(r, 1<<20)
	if err != errBoom || caughtUp || data != nil {
		t.Fatalf("mid-drain hard error: data=%q caughtUp=%v err=%v",
			data, caughtUp, err)
	}
}

// TestDevicePaths: primary then <hostRoot>/dev/kmsg, deduped, empty
// primary dropped.
func TestDevicePaths(t *testing.T) {
	got := DevicePaths("/dev/kmsg", "/host")
	if len(got) != 2 || got[0] != "/dev/kmsg" || got[1] != "/host/dev/kmsg" {
		t.Fatalf("paths = %v", got)
	}
	// hostRoot "/" makes the join identical to the primary → dedup.
	got = DevicePaths("/dev/kmsg", "/")
	if len(got) != 1 || got[0] != "/dev/kmsg" {
		t.Fatalf("dedup paths = %v", got)
	}
	got = DevicePaths("", "/host")
	if len(got) != 1 || got[0] != "/host/dev/kmsg" {
		t.Fatalf("empty primary = %v", got)
	}
}

// TestOpen: first openable candidate wins; none open → nil.
func TestOpen(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "kmsg")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	f := Open(filepath.Join(dir, "missing"), p)
	if f == nil {
		t.Fatal("open failed on second candidate")
	}
	_ = f.Close()
	if f := Open(filepath.Join(dir, "missing")); f != nil {
		_ = f.Close()
		t.Fatal("open succeeded on a missing path")
	}
}
