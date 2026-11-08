package kernelfail

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// dmesgLine renders one `dmesg -T` line: "[<layout ts>] <msg>".
func dmesgLine(ts time.Time, msg string) string {
	return "[" + ts.Format(dmesgTSLayout) + "] " + msg
}

// TestDmesgHelpers: the fingerprint + prefix-strip utilities.
func TestDmesgHelpers(t *testing.T) {
	if dmesgLineHash("a") == dmesgLineHash("b") {
		t.Fatal("distinct lines hashed equal")
	}
	if dmesgLineHash("a") != dmesgLineHash("a") {
		t.Fatal("hash not stable")
	}
	if got := dmesgTailHash([]string{"", "x", ""}); got != dmesgLineHash("x") {
		t.Fatalf("tailHash=%d want hash of x", got)
	}
	if got := dmesgTailHash([]string{"", ""}); got != 0 {
		t.Fatalf("all-empty tailHash=%d want 0", got)
	}

	ts := time.Date(2026, 3, 2, 8, 1, 2, 0, time.UTC)
	ln := dmesgLine(ts, "EXT4-fs error")
	got, ok := parseDmesgTimestamp(ln)
	if !ok || got != ts.Unix() {
		t.Fatalf("ts=%d ok=%v want %d", got, ok, ts.Unix())
	}
	if _, ok := parseDmesgTimestamp("no bracket"); ok {
		t.Fatal("unprefixed line parsed")
	}
	if _, ok := parseDmesgTimestamp("[unparseable] msg"); ok {
		t.Fatal("garbage timestamp parsed")
	}
	if _, ok := parseDmesgTimestamp("[unclosed"); ok {
		t.Fatal("unclosed bracket parsed")
	}
	if got := dmesgMessage(ln); got != "EXT4-fs error" {
		t.Fatalf("msg=%q", got)
	}
	if got := dmesgMessage("bare"); got != "bare" {
		t.Fatalf("bare msg=%q", got)
	}
}

// TestDrainDmesgT: the first drain primes the cursor at the tail
// (nothing classified); the next drain classifies only lines newer
// than the cursor and advances it.
func TestDrainDmesgT(t *testing.T) {
	f := kfixture(t)
	t1 := time.Date(2026, 3, 2, 8, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Minute)
	out := strings.Join([]string{
		dmesgLine(t1, "routine one"),
		dmesgLine(t1, "routine two"),
	}, "\n")
	f.r.deps.RunHostCmd = func(_ context.Context, argv ...string) (string, error) {
		if len(argv) < 2 || argv[1] != "-T" {
			return "", errors.New("unexpected argv")
		}
		return out, nil
	}

	f.r.drainDmesg(&f.r.kscan)
	b, err := os.ReadFile(f.r.statePath(kmsgCursorFile))
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("dmesgT %d 2\n", t1.Unix())
	if string(b) != want {
		t.Fatalf("cursor=%q want %q", b, want)
	}
	if _, err := os.Stat(
		f.r.statePath(kmsgFsErrorFile)); !os.IsNotExist(err) {
		t.Fatalf("history classified on first drain (marker err=%v)", err)
	}

	// Tick two: same history plus a fresh fs-error line.
	out = out + "\n" + dmesgLine(t2, "EXT4-fs error (dev sda1) in x")
	f.r.drainDmesg(&f.r.kscan)
	if _, err := os.Stat(
		f.r.statePath(kmsgFsErrorFile)); err != nil {
		t.Fatalf("fresh fs error not recorded: %v", err)
	}
	b, err = os.ReadFile(f.r.statePath(kmsgCursorFile))
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("dmesgT %d 1\n", t2.Unix()); string(b) != want {
		t.Fatalf("cursor=%q want %q", b, want)
	}
}

// TestDrainDmesgRaw: when `dmesg -T` fails, plain `dmesg` drives a
// content-anchored cursor — first drain re-anchors at the tail, the
// next drains only lines after the anchor.
func TestDrainDmesgRaw(t *testing.T) {
	f := kfixture(t)
	base := []string{"ring line one", "ring line two"}
	f.r.deps.RunHostCmd = func(_ context.Context, argv ...string) (string, error) {
		if len(argv) > 1 && argv[1] == "-T" {
			return "", errors.New("no -T support")
		}
		return strings.Join(base, "\n"), nil
	}

	f.r.drainDmesg(&f.r.kscan)
	b, err := os.ReadFile(f.r.statePath(kmsgCursorFile))
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("dmesgRaw %d %d\n", 2, dmesgLineHash(base[1]))
	if string(b) != want {
		t.Fatalf("cursor=%q want %q", b, want)
	}

	// Anchor still present + one appended line → only the new line
	// classifies.
	base = append(base, "EXT4-fs error (dev sdb)")
	f.r.drainDmesg(&f.r.kscan)
	if _, err := os.Stat(
		f.r.statePath(kmsgFsErrorFile)); err != nil {
		t.Fatalf("fresh fs error not recorded: %v", err)
	}

	// Anchor evicted (ring wrapped past it) → re-anchor, classify
	// nothing.
	base = []string{"wrapped a", "wrapped b", "wrapped c"}
	f.r.drainDmesg(&f.r.kscan)
	b, err = os.ReadFile(f.r.statePath(kmsgCursorFile))
	if err != nil {
		t.Fatal(err)
	}
	want = fmt.Sprintf("dmesgRaw %d %d\n", 3, dmesgLineHash("wrapped c"))
	if string(b) != want {
		t.Fatalf("cursor after wrap=%q want %q", b, want)
	}
}

// TestDrainDmesgNoAccess: both fallbacks failing is inconclusive —
// no cursor, no markers, no error.
func TestDrainDmesgNoAccess(t *testing.T) {
	f := kfixture(t)
	f.r.drainDmesg(&f.r.kscan)
	if _, err := os.Stat(
		f.r.statePath(kmsgCursorFile)); !os.IsNotExist(err) {
		t.Fatalf("cursor written despite no access (err=%v)", err)
	}
}

// TestCloseKMSSession: closing nils the session and is idempotent.
func TestCloseKMSSession(t *testing.T) {
	f := kfixture(t)
	st := &kernelScanState{sess: f.r.newKmsgSession()}
	f.r.closeKMSSession(st)
	if st.sess != nil {
		t.Fatal("session not released")
	}
	f.r.closeKMSSession(st) // idempotent
}

// TestRunnerRefreshClose: a full hermetic Refresh pass plus Close
// releasing the kmsg session the pass opened.
func TestRunnerRefreshClose(t *testing.T) {
	f := kfixture(t)
	kmsgFixture(t, f.deps, "6,1,1000,0;routine")
	f.r.Refresh()
	f.r.Refresh() // second pass over an open session
	if f.r.kscan.sess == nil {
		t.Fatal("kmsg session not opened by Refresh")
	}
	f.r.Close()
	if f.r.kscan.sess != nil {
		t.Fatal("Close did not release the kmsg session")
	}
}

// TestDefaultRunHostCmd: the nil-seam default execs with a 30s cap.
func TestDefaultRunHostCmd(t *testing.T) {
	out, err := defaultRunHostCmd(context.Background(), "echo", "hi")
	if err != nil || strings.TrimSpace(out) != "hi" {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

// TestDefaultKmsgDevicePaths: primary first, hostRoot variant second,
// empty hostRoot deduped away.
func TestDefaultKmsgDevicePaths(t *testing.T) {
	if got := defaultKmsgDevicePaths(""); len(got) != 2 ||
		got[0] != "/dev/kmsg" || got[1] != "dev/kmsg" {
		t.Fatalf("bare=%v (empty hostRoot still yields the relative variant)",
			got)
	}
	got := defaultKmsgDevicePaths("/host")
	if len(got) != 2 || got[0] != "/dev/kmsg" ||
		got[1] != filepath.Join("/host", "dev", "kmsg") {
		t.Fatalf("hostRoot=%v", got)
	}
}
