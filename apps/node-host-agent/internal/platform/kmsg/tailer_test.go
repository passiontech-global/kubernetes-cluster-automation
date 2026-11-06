// tailer_test.go — Tailer lifecycle coverage over real fixture
// files: lazy open over the candidates, the pending carry across
// reads, the backlog gates (First/Backlog/CaughtUp) and their
// re-arm on Close+reopen, and ErrNoDevice vs a mid-stream read
// failure (a directory opens O_RDONLY fine but errors on Read).
// EAGAIN-scripting stays in kmsg_test.go — a regular file surfaces
// EOF, which Drain already counts as "caught up".
package kmsg

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func tailerFixture(t *testing.T, body string) (dir, dev string) {
	t.Helper()
	dir = t.TempDir()
	dev = filepath.Join(dir, "kmsg")
	if err := os.WriteFile(dev, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, dev
}

func tailerFor(dev string, opts TailerOptions) *Tailer {
	opts.Paths = func() []string { return []string{dev} }
	if opts.DrainCap <= 0 {
		opts.DrainCap = 4 << 20
	}
	return NewTailer(opts)
}

func appendDev(t *testing.T, dev, data string) {
	t.Helper()
	f, err := os.OpenFile(dev, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(data); err != nil {
		t.Fatal(err)
	}
}

// TestTailerRead: a first Read opens lazily, returns the complete
// lines, marks First+Backlog and reports CaughtUp at EOF.
func TestTailerRead(t *testing.T) {
	_, dev := tailerFixture(t, "6,1,5,-;one\n6,2,6,-;two\n")
	tail := tailerFor(dev, TailerOptions{})
	defer tail.Close()

	lines, res, err := tail.Read()
	if err != nil || !res.First || !res.Backlog || !res.CaughtUp {
		t.Fatalf("res=%+v err=%v, want First+Backlog+CaughtUp", res, err)
	}
	if len(lines) != 2 || string(lines[0]) != "6,1,5,-;one" {
		t.Fatalf("lines=%q", lines)
	}
	// Second read: nothing new — the gate flags all clear.
	lines, res, err = tail.Read()
	if err != nil || res.First || res.Backlog || !res.CaughtUp || len(lines) != 0 {
		t.Fatalf("second read: res=%+v lines=%q err=%v", res, lines, err)
	}
	// Fresh data after EOF tails live.
	appendDev(t, dev, "6,3,7,-;three\n")
	lines, res, err = tail.Read()
	if err != nil || res.Backlog || len(lines) != 1 ||
		string(lines[0]) != "6,3,7,-;three" {
		t.Fatalf("live read: res=%+v lines=%q err=%v", res, lines, err)
	}
}

// TestTailerPendingCarry: an unterminated record carries into the
// next read and rejoins.
func TestTailerPendingCarry(t *testing.T) {
	_, dev := tailerFixture(t, "6,1,5,-;partial")
	tail := tailerFor(dev, TailerOptions{})
	defer tail.Close()

	lines, _, err := tail.Read()
	if err != nil || len(lines) != 0 {
		t.Fatalf("partial read: lines=%q err=%v", lines, err)
	}
	appendDev(t, dev, " record\n")
	lines, _, err = tail.Read()
	if err != nil || len(lines) != 1 ||
		string(lines[0]) != "6,1,5,-;partial record" {
		t.Fatalf("rejoined: lines=%q err=%v", lines, err)
	}
}

// TestTailerPendingCaps: the two overflow policies — trim-tail keeps
// the end of a never-terminated record; drop discards the carry.
func TestTailerPendingCaps(t *testing.T) {
	for _, tc := range []struct {
		name string
		trim bool
		want string
	}{
		{"trim-tail", true, "tail"},
		{"drop", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// One unterminated record longer than the 4-byte cap.
			_, dev := tailerFixture(t, "headlongtail")
			tail := tailerFor(dev, TailerOptions{
				PendingCap:      4,
				PendingTrimTail: tc.trim,
			})
			defer tail.Close()
			if _, _, err := tail.Read(); err != nil {
				t.Fatal(err)
			}
			if got := string(tail.pending); got != tc.want {
				t.Fatalf("pending=%q want %q", got, tc.want)
			}
		})
	}
}

// TestTailerBacklogUntilCaughtUp: a drain that stops at the byte
// cap keeps the Backlog gate armed — it must not disarm mid-flood;
// only the drain that ends dry reports CaughtUp. (The cap cuts the
// read LOOP, not a single Read — a regular file delivers everything
// in one call; Drain's slicing is covered in kmsg_test.go.)
func TestTailerBacklogUntilCaughtUp(t *testing.T) {
	_, dev := tailerFixture(t, "6,1,5,-;aaaa\n6,2,6,-;bbbb\n6,3,7,-;cccc\n")
	tail := tailerFor(dev, TailerOptions{DrainCap: 10})
	defer tail.Close()

	// One oversized read delivers the whole file and the cap stops
	// the drain short of EOF — still armed, still the first read.
	lines, res, err := tail.Read()
	if err != nil || !res.First || !res.Backlog || res.CaughtUp {
		t.Fatalf("capped drain: res=%+v err=%v", res, err)
	}
	if len(lines) != 3 {
		t.Fatalf("capped drain lines=%q", lines)
	}
	// Drain 2 reaches EOF: pulled while the gate was still armed →
	// Backlog=true, and only now does CaughtUp report.
	_, res, err = tail.Read()
	if err != nil || res.First || !res.Backlog || !res.CaughtUp {
		t.Fatalf("caught-up drain: res=%+v err=%v", res, err)
	}
	// Live tail from here.
	_, res, err = tail.Read()
	if err != nil || res.Backlog {
		t.Fatalf("post-catchup: res=%+v err=%v", res, err)
	}
}

// TestTailerReopenRearms: Close drops the handle; the next Read
// re-opens and the backlog gates are armed again.
func TestTailerReopenRearms(t *testing.T) {
	_, dev := tailerFixture(t, "6,1,5,-;one\n")
	tail := tailerFor(dev, TailerOptions{})
	defer tail.Close()
	if _, _, err := tail.Read(); err != nil {
		t.Fatal(err)
	}
	tail.Close()
	appendDev(t, dev, "6,2,6,-;two\n")
	lines, res, err := tail.Read()
	if err != nil || !res.First || !res.Backlog {
		t.Fatalf("reopen read: res=%+v err=%v — gates must re-arm", res, err)
	}
	// A regular file rewinds on reopen — the whole content reads as
	// backlog again (the consumer's cursor dedup owns replay
	// suppression; the Tailer only re-arms the gate).
	if len(lines) != 2 {
		t.Fatalf("reopened lines=%q", lines)
	}
}

// TestTailerErrNoDevice: no openable candidate → ErrNoDevice (the
// consumers' dmesg/journalctl fallback trigger), retried each Read.
func TestTailerErrNoDevice(t *testing.T) {
	dir := t.TempDir()
	tail := NewTailer(TailerOptions{
		Paths:    func() []string { return []string{filepath.Join(dir, "missing")} },
		DrainCap: 1 << 20,
	})
	defer tail.Close()
	if _, _, err := tail.Read(); !errors.Is(err, ErrNoDevice) {
		t.Fatalf("err=%v, want ErrNoDevice", err)
	}
}

// TestTailerReadError: a path that opens but errors on Read (a
// directory) fails the Read — Close+reopen is the consumer's answer.
func TestTailerReadError(t *testing.T) {
	dir, _ := tailerFixture(t, "")
	tail := tailerFor(dir, TailerOptions{}) // a directory opens, Read fails
	defer tail.Close()
	if _, _, err := tail.Read(); err == nil || errors.Is(err, ErrNoDevice) {
		t.Fatalf("err=%v, want a mid-stream read error", err)
	}
}

// TestTailerCarrySurvivesFailedRead: a failed Read must not consume
// the carry — it rejoins on the next handle (nodereporter kept its
// pending buffer across closeKmsg).
func TestTailerCarrySurvivesFailedRead(t *testing.T) {
	dir, dev := tailerFixture(t, "6,1,5,-;partial")
	paths := []string{dev}
	tail := NewTailer(TailerOptions{
		Paths:    func() []string { return paths },
		DrainCap: 1 << 20,
	})
	defer tail.Close()
	if _, _, err := tail.Read(); err != nil {
		t.Fatal(err)
	}
	// Next handle is the erroring directory: the carry must not be
	// consumed by the failed read.
	paths = []string{dir}
	tail.Close()
	if _, _, err := tail.Read(); err == nil {
		t.Fatal("expected read error")
	}
	if string(tail.pending) != "6,1,5,-;partial" {
		t.Fatalf("pending lost on failed read: %q", tail.pending)
	}
}
