// log_test.go — the failure-path watchdog log (AppendLogWarn) and
// the size-cap rotation it writes through. AppendLog's happy path is
// pinned in hoststate_test.go; the Warn variant must land the
// IDENTICAL file line (the NPD filelog contract) and rotate an
// oversized log before appending.

package hoststate

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func TestAppendLogWarnWritesFileLine(t *testing.T) {
	s, clk, logFile := newTestStore(t)

	s.AppendLogWarn("kubelet response timeout")

	want := clk.now.Format(time.RFC3339) + " kubelet response timeout\n"
	if got := testutil.ReadFile(t, logFile); got != want {
		t.Fatalf("log line = %q want %q", got, want)
	}
}

func TestAppendLogWarnRotatesOversizedLog(t *testing.T) {
	s, _, logFile := newTestStore(t)

	// Sparse-truncate the log to exactly the cap — the next append
	// must rotate <log> → <log>.1 and start a fresh file. The file is
	// created lazily by the first append, so seed it first.
	s.AppendLog("seed line")
	if err := os.Truncate(logFile, watchdogLogMaxBytes); err != nil {
		t.Fatal(err)
	}
	s.AppendLogWarn("degraded after rotate")

	if _, err := os.Stat(logFile + ".1"); err != nil {
		t.Fatalf("oversized log not rotated to .1: %v", err)
	}
	if fi, err := os.Stat(logFile + ".1"); err != nil || fi.Size() != watchdogLogMaxBytes {
		t.Fatalf(".1 size = %d err=%v want %d", fi.Size(), err, watchdogLogMaxBytes)
	}
	got := testutil.ReadFile(t, logFile)
	if !strings.HasSuffix(got, " degraded after rotate\n") {
		t.Fatalf("fresh log missing the rotated-in line: %q", got)
	}
}

// TestAppendLogEmptyLogFileIsSlogOnly: LogFile "" disables the file
// half (nodereporter/hostconfig stores) — best-effort contract.
func TestAppendLogEmptyLogFileIsSlogOnly(t *testing.T) {
	s := New(t.TempDir(), "", nil, nil)
	s.AppendLogWarn("file half disabled") // must not panic
}

// TestAppendLogConcurrentRotationLosesNoGeneration: the rotate
// decision+rename must be mutually exclusive (the shared mu) — racing appends
// that both stat an oversized log used to be able to BOTH rename, the
// second rename replacing the .1 generation (and the fresh file's
// early lines) wholesale. Every appended line must survive in the
// union of the live file and the rotated .1.
//
// The write volume is tuned to fire EXACTLY ONE rotation (~11MiB
// total against the 10MiB cap): the .1 slot is single-generation by
// design — a second rotation legitimately replaces the first — so a
// second rotation would defeat the invariant this test pins.
func TestAppendLogConcurrentRotationLosesNoGeneration(t *testing.T) {
	s, _, logFile := newTestStore(t)

	const (
		goroutines = 8
		linesEach  = 42
		lineSize   = 32 << 10
	)
	line := strings.Repeat("x", lineSize)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for g := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := range linesEach {
				s.AppendLog(line + fmt.Sprintf(" g%02d j%03d", g, j))
			}
		}()
	}
	close(start)
	wg.Wait()

	if _, err := os.Stat(logFile + ".1"); err != nil {
		t.Fatalf("rotation never fired — test wrote %d MiB: %v",
			goroutines*linesEach*lineSize>>20, err)
	}
	// Exactly one rotation: the live file holds only the post-rotate
	// lines (< cap), .1 holds the pre-rotate generation.
	if fi, err := os.Stat(logFile); err != nil ||
		fi.Size() >= watchdogLogMaxBytes {
		t.Fatalf("live log size = %d err=%v — a second rotation fired", fi.Size(), err)
	}
	all := testutil.ReadFile(t, logFile)
	if b, err := os.ReadFile(logFile + ".1"); err == nil {
		all += string(b)
	}
	missing := 0
	for g := range goroutines {
		for j := range linesEach {
			if !strings.Contains(all, fmt.Sprintf(" g%02d j%03d", g, j)) {
				missing++
			}
		}
	}
	if missing > 0 {
		t.Fatalf("%d appended lines lost to the rotation race", missing)
	}
}
