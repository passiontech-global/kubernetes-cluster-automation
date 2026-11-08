// log_test.go — the failure-path watchdog log (AppendLogWarn) and
// the size-cap rotation it writes through. AppendLog's happy path is
// pinned in hoststate_test.go; the Warn variant must land the
// IDENTICAL file line (the NPD filelog contract) and rotate an
// oversized log before appending.

package hoststate

import (
	"os"
	"strings"
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
