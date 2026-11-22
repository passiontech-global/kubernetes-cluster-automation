// fail2ban_test.go — fail2ban unit-down latch, restart, and banned-count capture.

package nethealth

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
)

// --- fail2ban (50) ---

func TestFail2banDownAndBans(t *testing.T) {
	e := fixture(t, nil)
	e.sd.On("LoadState --value fail2ban.service", "loaded\n")
	e.sd.On("is-active fail2ban.service", "inactive\n")
	e.sd.On("restart fail2ban.service", "")
	e.n.Cycle(context.Background())
	if !stateExists(e, "fail2ban-down") {
		t.Fatal("fail2ban-down latch missing")
	}
	// A stopped jail protects nothing — the guard restarts the unit.
	if !e.sd.Ran("restart fail2ban.service") {
		t.Fatalf("fail2ban not restarted, cmds=%v", e.sd.Cmds())
	}
	if got := promtest.ToFloat64(e.n.actions.WithLabelValues(checkF2B, "restart")); got != 1 {
		t.Fatalf("restart metric=%v want 1", got)
	}
	if _, err := os.Stat(filepath.Join(e.state, "last-fail2ban-restart")); err != nil {
		t.Fatal("restart budget file missing")
	}
	// Inactive unit → no fail2ban-client fork at all (it could only
	// fail) and the banned series drops — no jails, nothing banned.
	if e.host.Ran("fail2ban-client") {
		t.Fatal("fail2ban-client forked while the unit is inactive")
	}
	if _, err := os.Stat(filepath.Join(e.state, "fail2ban-banned")); !os.IsNotExist(err) {
		t.Fatal("stale banned file kept while the unit is inactive")
	}
}

// A failed restart is logged and the budget already spent — the
// latch stays armed so the next budget window retries.
func TestFail2banRestartFailureLogged(t *testing.T) {
	e := fixture(t, nil)
	e.sd.On("LoadState --value fail2ban.service", "loaded\n")
	e.sd.On("is-active fail2ban.service", "inactive\n")
	e.sd.FailOn("restart fail2ban.service", errCmdFail)
	e.n.Cycle(context.Background())
	if !strings.Contains(logLines(t, e), "fail2ban.service restart failed") {
		t.Fatalf("missing restart-failure log:\n%s", logLines(t, e))
	}
	if got := promtest.ToFloat64(e.n.actions.WithLabelValues(checkF2B, "restart")); got != 0 {
		t.Fatalf("restart metric=%v want 0 on failure", got)
	}
	if !stateExists(e, "fail2ban-down") {
		t.Fatal("down-latch dropped despite the failed restart")
	}
}

func TestFail2banNoUnitSkips(t *testing.T) {
	e := fixture(t, nil)
	e.n.Cycle(context.Background())
	if e.sd.Ran("restart") || stateExists(e, "fail2ban-down") {
		t.Fatal("fail2ban ran without unit")
	}
}

// No systemd client → the whole check gates off (no banned-metrics
// collection either — nothing in the check can run without systemd).
func TestFail2banNilSystemdGates(t *testing.T) {
	e := fixture(t, nil)
	e.n.cfg.Systemd = nil
	e.host.On("fail2ban-client status", "Status\n`- Jail list:\tsshd\n")
	e.host.On("fail2ban-client status sshd", "Currently banned:\t3\n")
	e.n.Cycle(context.Background())
	if e.host.Ran("fail2ban-client") {
		t.Fatal("fail2ban-client ran without a systemd client")
	}
	if stateExists(e, "fail2ban-down") {
		t.Fatal("latch entered without a systemd client")
	}
}

// A unit the manager does not hold a definition for gates the check
// without latching — fail2ban simply is not installed here.
func TestFail2banUnitNotLoadedGates(t *testing.T) {
	e := fixture(t, nil)
	e.sd.On("LoadState --value fail2ban.service", "not-found\n")
	e.n.Cycle(context.Background())
	if stateExists(e, "fail2ban-down") || e.sd.Ran("restart") {
		t.Fatal("down-latch or restart on a not-found unit")
	}
}

// A healthy unit clears a stale down-latch (recovered after an
// agent outage, say) and keeps collecting banned counts.
func TestFail2banActiveUnitClearsLatch(t *testing.T) {
	e := fixture(t, nil)
	e.sd.On("LoadState --value fail2ban.service", "loaded\n")
	e.sd.On("is-active fail2ban.service", "active\n")
	testutil.WriteFile(t, filepath.Join(e.state, "state-fail2ban-down"), "1\n")
	e.host.On("fail2ban-client status", "Status\n`- Jail list:\tsshd\n")
	e.host.On("fail2ban-client status sshd", "Currently banned:\t4\n")
	e.n.Cycle(context.Background())
	if stateExists(e, "fail2ban-down") {
		t.Fatal("down-latch kept while the unit is active")
	}
	if e.sd.Ran("restart") {
		t.Fatal("restart on a healthy unit")
	}
	if !strings.Contains(fsx.ReadTrimmed(filepath.Join(e.state, "fail2ban-banned")), "sshd=4") {
		t.Fatal("banned counts not collected on the healthy unit")
	}
}

// An unanswerable is-active probe must not enter OR clear the
// down-latch on a guess — the latch keeps its previous state.
func TestFail2banActiveProbeErrorKeepsLatch(t *testing.T) {
	e := fixture(t, nil)
	e.sd.On("LoadState --value fail2ban.service", "loaded\n")
	e.sd.FailOn("is-active fail2ban.service", errCmdFail)
	e.host.On("fail2ban-client status", "Status\n`- Jail list:\tsshd\n")
	e.host.On("fail2ban-client status sshd", "Currently banned:\t1\n")
	// Pre-existing latch survives the blind cycle.
	testutil.WriteFile(t, filepath.Join(e.state, "state-fail2ban-down"), "1\n")
	e.n.Cycle(context.Background())
	if !stateExists(e, "fail2ban-down") {
		t.Fatal("down-latch cleared on an unanswerable is-active")
	}
	if e.sd.Ran("restart") {
		t.Fatal("restart decided by a failed probe")
	}
}

// fail2ban-client missing/failed → the banned metric file is REMOVED
// (absent, not 0 — no stale series).
func TestFail2banClientFailureDropsMetricFile(t *testing.T) {
	e := fixture(t, nil)
	e.sd.On("LoadState --value fail2ban.service", "loaded\n")
	e.sd.On("is-active fail2ban.service", "active\n")
	banned := filepath.Join(e.state, "fail2ban-banned")
	testutil.WriteFile(t, banned, "sshd=7\n")
	e.host.FailOn("fail2ban-client", errCmdFail)
	e.n.Cycle(context.Background())
	if _, err := os.Stat(banned); !os.IsNotExist(err) {
		t.Fatal("stale banned file kept after client failure")
	}
	if !strings.Contains(logLines(t, e), "banned metrics dropped") {
		t.Fatalf("missing client-failure suspect line:\n%s", logLines(t, e))
	}
}

// Per-jail statuses answer the counts; a jail whose status fails
// reports 0 (not stale garbage), and a jail without a parseable
// "Currently banned" also reads 0. An empty jail entry in the list
// is skipped entirely.
func TestFail2banPerJailParsing(t *testing.T) {
	e := fixture(t, nil)
	e.sd.On("LoadState --value fail2ban.service", "loaded\n")
	e.sd.On("is-active fail2ban.service", "active\n")
	e.host.On("fail2ban-client status",
		"Status\n|- Number of jail:\t4\n`- Jail list:\tsshd, dead, , recidive\n")
	e.host.On("fail2ban-client status sshd", "Currently banned:\t7\n")
	e.host.FailOn("fail2ban-client status recidive", errCmdFail)
	e.host.On("fail2ban-client status dead",
		"No output matching the regexp\n")
	e.n.Cycle(context.Background())
	got := fsx.ReadTrimmed(filepath.Join(e.state, "fail2ban-banned"))
	// "dead" is a jail whose status lacks the banned counter —
	// reported as 0; "sshd" carries its real count; recidive failed → 0.
	if got != "sshd=7 dead=0 recidive=0" {
		t.Fatalf("banned file=%q want \"sshd=7 dead=0 recidive=0\"", got)
	}
}

// A banned-count write that cannot land (a directory squatting the
// fail2ban-banned path) degrades to a warn — the latch logic above
// is unaffected.
func TestFail2banBannedWriteFailureDegrades(t *testing.T) {
	e := fixture(t, nil)
	e.sd.On("LoadState --value fail2ban.service", "loaded\n")
	e.sd.On("is-active fail2ban.service", "active\n")
	e.host.On("fail2ban-client status", "Status\n`- Jail list:\tsshd\n")
	e.host.On("fail2ban-client status sshd", "Currently banned:\t5\n")
	if err := os.MkdirAll(filepath.Join(e.state, "fail2ban-banned"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.n.Cycle(context.Background())
	if got := promtest.ToFloat64(e.n.actions.WithLabelValues(checkF2B, "restart")); got != 0 {
		t.Fatalf("restart metric=%v want 0 on a healthy unit", got)
	}
}

// A jail list with no parseable names → no pairs → the banned file
// is removed rather than left stale.
func TestFail2banNoJailsRemovesMetricFile(t *testing.T) {
	e := fixture(t, nil)
	e.sd.On("LoadState --value fail2ban.service", "loaded\n")
	e.sd.On("is-active fail2ban.service", "active\n")
	banned := filepath.Join(e.state, "fail2ban-banned")
	testutil.WriteFile(t, banned, "sshd=7\n")
	e.host.On("fail2ban-client status", "Status\n|- Number of jail:\t0\n`- Jail list:\t\n")
	e.n.Cycle(context.Background())
	if _, err := os.Stat(banned); !os.IsNotExist(err) {
		t.Fatal("banned file kept with no jails")
	}
}

func TestParseFail2banBannedFormats(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		want   []string
		wantOK bool
	}{
		{"python repr multi", "[{'sshd': ['192.0.2.1', '192.0.2.2']}, {'recidive': []}]\n", []string{"sshd=2", "recidive=0"}, true},
		{"json double quoted", `[{"sshd": ["192.0.2.1"]}, {"nginx-http-auth": ["198.51.100.1", "2001:db8::1"]}]`, []string{"sshd=1", "nginx-http-auth=2"}, true},
		{"empty list", "[]\n", nil, true},
		{"multi keys in one dict", `[{"sshd": ["1.1.1.1"], "recidive": []}]`, []string{"sshd=1", "recidive=0"}, true},
		{"escaped quote in jail", `[{'a\'b': ['1.1.1.1']}]`, []string{"a'b=1"}, true},
		{"empty string", "", nil, false},
		{"unparseable text", "Status\n`- Jail list:\tsshd\n", nil, false},
		{"truncated", "[{'sshd': ['1.2.3.4'", nil, false},
		{"trailing junk", "[] junk", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseFail2banBanned(tc.in)
			if ok != tc.wantOK || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parseFail2banBanned(%q) = (%v, %v) want (%v, %v)",
					tc.in, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestFail2banCoalescedBannedCommand(t *testing.T) {
	e := fixture(t, nil)
	e.sd.On("LoadState --value fail2ban.service", "loaded\n")
	e.sd.On("is-active fail2ban.service", "active\n")
	e.host.On("fail2ban-client banned",
		"[{'sshd': ['192.0.2.1', '192.0.2.2']}, {'recidive': []}]\n")

	e.n.Cycle(context.Background())

	if got := fsx.ReadTrimmed(filepath.Join(e.state, "fail2ban-banned")); got != "sshd=2 recidive=0" {
		t.Fatalf("banned=%q want %q", got, "sshd=2 recidive=0")
	}
	var f2bCmds []string
	for _, c := range e.host.Cmds() {
		j := strings.Join(c, " ")
		if strings.Contains(j, "fail2ban-client") {
			f2bCmds = append(f2bCmds, j)
		}
	}
	if len(f2bCmds) != 1 || !strings.Contains(f2bCmds[0], "fail2ban-client banned") {
		t.Fatalf("expected 1 fail2ban-client banned fork, got %v", f2bCmds)
	}

	// Empty list `[]` removes pre-existing fail2ban-banned file.
	e.host.On("fail2ban-client banned", "[]\n")
	e.n.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.state, "fail2ban-banned")); !os.IsNotExist(err) {
		t.Fatal("fail2ban-banned kept after empty banned list")
	}
}

func TestFail2banBannedFallbackAndLatchUnsupported(t *testing.T) {
	// Case 1: `banned` fails while `status` succeeds -> fallback + latch unsupported.
	e := fixture(t, nil)
	e.sd.On("LoadState --value fail2ban.service", "loaded\n")
	e.sd.On("is-active fail2ban.service", "active\n")
	e.host.FailOn("fail2ban-client banned", errCmdFail)
	e.host.On("fail2ban-client status", "Status\n`- Jail list:\tsshd\n")
	e.host.On("fail2ban-client status sshd", "Currently banned:\t4\n")

	e.n.Cycle(context.Background())
	if got := fsx.ReadTrimmed(filepath.Join(e.state, "fail2ban-banned")); got != "sshd=4" {
		t.Fatalf("fallback banned=%q want sshd=4", got)
	}
	if !e.n.f2bBannedUnsupported {
		t.Fatal("f2bBannedUnsupported not latched after banned error + status success")
	}

	// Subsequent cycle skips `fail2ban-client banned`.
	e.host.ClearLog()
	e.n.Cycle(context.Background())
	if e.host.Ran("fail2ban-client banned") {
		t.Fatalf("fail2ban-client banned still forked after unsupported latch: %v", e.host.Cmds())
	}

	// Case 2: transient failure (both banned and status fail) does NOT latch unsupported.
	e2 := fixture(t, nil)
	e2.sd.On("LoadState --value fail2ban.service", "loaded\n")
	e2.sd.On("is-active fail2ban.service", "active\n")
	e2.host.FailOn("fail2ban-client", errCmdFail)
	e2.n.Cycle(context.Background())
	if e2.n.f2bBannedUnsupported {
		t.Fatal("f2bBannedUnsupported latched on transient failure when status also failed")
	}
	// Once daemon recovers, `banned` succeeds cleanly.
	e2.host.Clear("fail2ban-client")
	e2.host.On("fail2ban-client banned", "[{'sshd': ['192.0.2.9']}]\n")
	e2.n.Cycle(context.Background())
	if got := fsx.ReadTrimmed(filepath.Join(e2.state, "fail2ban-banned")); got != "sshd=1" {
		t.Fatalf("recovered banned=%q want sshd=1", got)
	}
}

func TestFail2banSkipsUnchangedWriteAndRemove(t *testing.T) {
	e := fixture(t, nil)
	e.sd.On("LoadState --value fail2ban.service", "loaded\n")
	e.sd.On("is-active fail2ban.service", "active\n")
	e.host.On("fail2ban-client banned", "[{'sshd': ['192.0.2.1', '192.0.2.2']}]\n")

	banned := filepath.Join(e.state, "fail2ban-banned")
	e.n.Cycle(context.Background())
	fi1, err := os.Stat(banned)
	if err != nil {
		t.Fatalf("stat cycle 1: %v", err)
	}
	ino1 := fi1.Sys().(*syscall.Stat_t).Ino

	// Cycle 2 with identical content skips atomic rewrite (inode unchanged).
	e.n.Cycle(context.Background())
	fi2, err := os.Stat(banned)
	if err != nil {
		t.Fatalf("stat cycle 2: %v", err)
	}
	if ino2 := fi2.Sys().(*syscall.Stat_t).Ino; ino2 != ino1 {
		t.Fatalf("unchanged content rewrote file: inode %d -> %d", ino1, ino2)
	}

	// External deletion between cycles is detected by os.Stat and recreates file.
	if err := os.Remove(banned); err != nil {
		t.Fatal(err)
	}
	e.n.Cycle(context.Background())
	if got := fsx.ReadTrimmed(banned); got != "sshd=2" {
		t.Fatalf("deleted file not recreated: got=%q", got)
	}

	// Transition to empty jails removes file and caches absent state.
	e.host.On("fail2ban-client banned", "[]\n")
	e.n.Cycle(context.Background())
	if _, err := os.Stat(banned); !os.IsNotExist(err) {
		t.Fatal("fail2ban-banned not removed on empty jails")
	}
	if !e.n.f2bLastKnown || e.n.f2bLastContent != "" {
		t.Fatalf("absent cache not recorded: known=%v content=%q",
			e.n.f2bLastKnown, e.n.f2bLastContent)
	}
	// Because removeFail2banBanned skips os.Remove when known absent, a
	// file planted only to probe whether os.Remove runs stays untouched.
	testutil.WriteFile(t, banned, "sentinel\n")
	e.n.Cycle(context.Background())
	if got := fsx.ReadTrimmed(banned); got != "sentinel" {
		t.Fatalf("expected redundant os.Remove to be skipped, got=%q", got)
	}
}
