// overlay_egress_test.go — overlay egress direct/relay switching and drift heal.

package nethealth

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func TestEgressUnderlayDiesRelaysImmediately(t *testing.T) {
	e := overlayEnv(t, nil)
	// fwmark rule present, no pref-1500 rules.
	e.host.On("rule list pref 1500", "")
	// Marked ping fails; TCP fallback fails too → underlay dead.
	e.tcpOK["8.8.8.8:53"] = false
	e.pingOK["8.8.8.8|true"] = false
	e.n.Cycle(context.Background())
	if !e.host.Ran("rule add pref 1500 to 8.8.8.8/32 lookup 100") {
		t.Fatalf("relay rule not added, cmds=%v", e.host.Cmds())
	}
	if got := hostutil.ReadTrimmed(filepath.Join(e.state, "egress-state-8.8.8.8")); got != "relay" {
		t.Fatalf("committed=%q want relay", got)
	}
	// Relay target itself unreachable through tunnel → suspect log.
	e.pingOK["8.8.8.8|false"] = false
	if !strings.Contains(logLines(t, e), "overlay relay table 100") {
		t.Fatalf("missing ACTION log:\n%s", logLines(t, e))
	}
}

func TestEgressRecoveryNeedsTwoFreshProbes(t *testing.T) {
	e := overlayEnv(t, nil)
	e.host.On("rule list pref 1500", "1500:\tfrom all to 8.8.8.8 lookup 100\n")
	testutil.WriteFile(t, filepath.Join(e.state, "egress-state-8.8.8.8"), "relay\n")
	e.pingOK["8.8.8.8|true"] = true // underlay back
	// Cycle 1: probe=direct, ctr 1 < 2 → stays relay.
	e.n.Cycle(context.Background())
	if e.host.Ran("rule del pref 1500 to 8.8.8.8") {
		t.Fatal("rule removed before hysteresis")
	}
	e.n.Cycle(context.Background())
	if !e.host.Ran("rule del pref 1500 to 8.8.8.8/32 lookup 100") {
		t.Fatalf("direct rule not restored, cmds=%v", e.host.Cmds())
	}
	if got := hostutil.ReadTrimmed(filepath.Join(e.state, "egress-state-8.8.8.8")); got != "direct" {
		t.Fatalf("committed=%q want direct", got)
	}
}

func TestEgressDriftHeal(t *testing.T) {
	e := overlayEnv(t, nil)
	// Committed relay but live rule missing → re-add immediately.
	e.host.On("rule list pref 1500", "")
	testutil.WriteFile(t, filepath.Join(e.state, "egress-state-8.8.8.8"), "relay\n")
	e.pingOK["8.8.8.8|true"] = false
	e.tcpOK["8.8.8.8:53"] = false
	e.n.Cycle(context.Background())
	if !e.host.Ran("rule add pref 1500 to 8.8.8.8/32 lookup 100") {
		t.Fatal("committed relay state not healed into live rules")
	}
	if !strings.Contains(logLines(t, e), "heal egress") {
		t.Fatalf("missing heal log:\n%s", logLines(t, e))
	}
}

func TestEgressICMPBlockedTCPAliveIsDirect(t *testing.T) {
	e := overlayEnv(t, nil)
	e.host.On("rule list pref 1500", "")
	e.pingOK["8.8.8.8|true"] = false // ICMP filtered
	e.tcpOK["8.8.8.8:53"] = true     // but TCP answers
	e.n.Cycle(context.Background())
	if e.host.Ran("rule add pref 1500 to 8.8.8.8") {
		t.Fatal("relay rule added while TCP alive (ICMP-block false positive)")
	}
	if _, err := os.Stat(filepath.Join(e.state, "egress-icmpblk-8.8.8.8")); err != nil {
		t.Fatal("icmpblk flag not written")
	}
}

func TestEgressNoOverlayCleanup(t *testing.T) {
	e := overlayEnv(t, nil)
	// Nebula down → overlayUp false → full cleanup.
	e.sd.Reset()
	e.host.On("rule list pref 1500", "1500:\tfrom all to 8.8.8.8 lookup 100\n")
	testutil.WriteFile(t, filepath.Join(e.state, "egress-state-8.8.8.8"), "relay\n")
	e.n.Cycle(context.Background())
	if !e.host.Ran("rule del pref 1390 fwmark 0x2000") {
		t.Fatal("fwmark probe rule not removed")
	}
	if _, err := os.Stat(filepath.Join(e.state, "egress-state-8.8.8.8")); !os.IsNotExist(err) {
		t.Fatal("egress state kept with overlay down")
	}
}

func TestEgressRemovedRelayCleaned(t *testing.T) {
	e := overlayEnv(t, nil)
	e.host.On("rule list pref 1500", "1500:\tfrom all to 9.9.9.9 lookup 100\n")
	testutil.WriteFile(t, filepath.Join(e.state, "egress-state-9.9.9.9"), "relay\n")
	e.pingOK["8.8.8.8|true"] = true
	e.n.Cycle(context.Background())
	if !e.host.Ran("rule del pref 1500 to 9.9.9.9/32 lookup 100") {
		t.Fatal("stale relay rule not removed")
	}
	if _, err := os.Stat(filepath.Join(e.state, "egress-state-9.9.9.9")); !os.IsNotExist(err) {
		t.Fatal("stale relay state kept")
	}
}

func TestEgressHealedRelayDropsRuleForTCPProbe(t *testing.T) {
	// Committed relay + missing live rule → heal re-adds it, then the
	// TCP fallback must still drop the rule for the probe window
	// (pre-heal snapshot would have said hadRule=false → connect
	// through the overlay → false "direct" → relay/direct flap).
	e := overlayEnv(t, nil)
	e.host.On("rule list pref 1500", "")
	testutil.WriteFile(t, filepath.Join(e.state, "egress-state-8.8.8.8"), "relay\n")
	e.pingOK["8.8.8.8|true"] = false
	e.tcpOK["8.8.8.8:53"] = true // underlay actually alive via TCP
	e.n.Cycle(context.Background())
	if !e.host.Ran("rule del pref 1500 to 8.8.8.8/32 lookup 100") {
		t.Fatalf("rule not dropped for TCP probe window: %v", e.host.Cmds())
	}
	if !e.host.Ran("rule add pref 1500 to 8.8.8.8/32 lookup 100") {
		t.Fatalf("rule not restored after TCP probe: %v", e.host.Cmds())
	}
}

// When the probe-window rule del fails the TCP fallback is skipped —
// committing relay then only restates live; the log must not claim
// "(direct failed)" underlay evidence the skipped probe never made.
func TestEgressUnprobeableWindowCommitsToLive(t *testing.T) {
	e := overlayEnv(t, nil)
	// Committed direct but a live relay rule (drift); the heal del
	// AND the probe-window del both fail → no probe runs.
	e.host.On("rule list pref 1500", "1500:\tfrom all to 8.8.8.8 lookup 100\n")
	testutil.WriteFile(t, filepath.Join(e.state, "egress-state-8.8.8.8"), "direct\n")
	e.host.FailOn("rule del", errCmdFail)
	e.pingOK["8.8.8.8|true"] = false
	e.tcpOK["8.8.8.8:53"] = true // would prove direct — never consulted

	e.n.Cycle(context.Background())

	if got := hostutil.ReadTrimmed(filepath.Join(e.state, "egress-state-8.8.8.8")); got != "relay" {
		t.Fatalf("committed=%q want relay (committed to live)", got)
	}
	log := logLines(t, e)
	if !strings.Contains(log, "unprobeable window — committed to live") {
		t.Fatalf("missing unprobeable-window commit log:\n%s", log)
	}
	if strings.Contains(log, "direct failed") {
		t.Fatalf("misleading '(direct failed)' logged for an unrun probe:\n%s", log)
	}
}

// An unanswerable `ip rule list` aborts the whole egress cycle —
// rules must never be added/removed on a blind read.
func TestEgressRuleListFailureAborts(t *testing.T) {
	e := overlayEnv(t, nil)
	e.host.FailOn("rule list", errCmdFail)
	e.pingOK["8.8.8.8|true"] = false
	e.n.checkOverlayEgress(context.Background())
	if e.host.Ran("rule add pref 1500") || e.host.Ran("rule del pref 1500") {
		t.Fatalf("rule churn on a failed listing: %v", e.host.Cmds())
	}
	if got := promtest.ToFloat64(e.n.cycles.WithLabelValues(
		checkEgress, "abort")); got != 1 {
		t.Fatalf("abort metric=%v want 1", got)
	}
}

// A failed `ip rule list pref 1500` reads as "unruled": the cycle
// continues (the pref-1390 fwmark rule and the probes still run) and
// a committed relay gets healed back in on the blind snapshot.
func TestEgressPref1500ListFailureReadsUnruled(t *testing.T) {
	e := overlayEnv(t, nil)
	e.host.FailOn("rule list pref 1500", errCmdFail)
	testutil.WriteFile(t, filepath.Join(e.state, "egress-state-8.8.8.8"), "relay\n")
	e.pingOK["8.8.8.8|true"] = true // underlay ok → no relay commit
	e.n.checkOverlayEgress(context.Background())
	// committed relay vs live "unruled" → drift heal re-adds.
	if !e.host.Ran("rule add pref 1500 to 8.8.8.8/32 lookup 100") {
		t.Fatalf("committed relay not healed on the blind snapshot: %v", e.host.Cmds())
	}
	if got := promtest.ToFloat64(e.n.cycles.WithLabelValues(
		checkEgress, "abort")); got != 0 {
		t.Fatalf("pref-1500 list failure must not abort the cycle, abort=%v", got)
	}
}

// Rules pointing at a table other than the active one are pruned —
// an overlay flip (tinc↔nebula) must not leave stale-table rules
// pushing traffic into the dead table.
func TestEgressStaleTableRulePruned(t *testing.T) {
	e := overlayEnv(t, nil)
	e.host.On("rule list pref 1500",
		"1500:\tfrom all to 8.8.8.8 lookup 102\n")
	testutil.WriteFile(t, filepath.Join(e.state, "egress-state-8.8.8.8"), "relay\n")
	e.pingOK["8.8.8.8|true"] = true
	e.n.checkOverlayEgress(context.Background())
	if !e.host.Ran("rule del pref 1500 to 8.8.8.8/32 lookup 102") {
		t.Fatalf("stale-table rule not pruned: %v", e.host.Cmds())
	}
	if !strings.Contains(logLines(t, e),
		"rule lookup 102 stale (current table 100)") {
		t.Fatalf("missing stale-table cleanup log:\n%s", logLines(t, e))
	}
}

// A failed icmp-blocked marker write degrades to a warn — the
// direct verdict itself still stands.
func TestEgressICMPMarkerWriteFailureDegrades(t *testing.T) {
	e := overlayEnv(t, nil)
	e.host.On("rule list pref 1500", "")
	if err := os.Chmod(e.state, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(e.state, 0o755) })
	e.pingOK["8.8.8.8|true"] = false // ICMP filtered
	e.tcpOK["8.8.8.8:53"] = true     // TCP answers → direct
	e.n.checkOverlayEgress(context.Background())
	if _, err := os.Stat(filepath.Join(e.state, "egress-icmpblk-8.8.8.8")); !os.IsNotExist(err) {
		t.Fatal("icmpblk marker written despite the read-only state dir")
	}
}

// A probe-window rule restore failure retries once inline and then
// warns — the relay rule stays removed until next cycle's drift
// heal instead of silently disappearing.
func TestEgressProbeWindowRestoreFailureRetriesOnce(t *testing.T) {
	e := overlayEnv(t, nil)
	// Committed relay + live relay rule → the TCP fallback drops the
	// rule for the probe window and must restore it afterwards.
	e.host.On("rule list pref 1500",
		"1500:\tfrom all to 8.8.8.8 lookup 100\n")
	testutil.WriteFile(t, filepath.Join(e.state, "egress-state-8.8.8.8"), "relay\n")
	e.pingOK["8.8.8.8|true"] = false
	e.tcpOK["8.8.8.8:53"] = true
	e.host.FailOn("rule add pref 1500", errCmdFail)
	e.n.checkOverlayEgress(context.Background())
	// Del + BOTH restore attempts ran (the inline retry).
	if got := strings.Count(e.host.Joined(),
		"rule add pref 1500 to 8.8.8.8/32 lookup 100"); got != 2 {
		t.Fatalf("rule add attempts=%d want 2 (restore + retry)", got)
	}
	// No probe ran with the rule present and none proved direct: the
	// probe verdict stays relay-committed, no "(direct failed)" lie.
	if strings.Contains(logLines(t, e), "direct failed") {
		t.Fatalf("false direct evidence logged:\n%s", logLines(t, e))
	}
}

// A failed committed-state write still flips the live rule — the
// commit/converge heals the file next cycle (the warn is the trail).
func TestEgressCommitWriteFailureHealsRuleAnyway(t *testing.T) {
	e := overlayEnv(t, nil)
	e.host.On("rule list pref 1500", "")
	if err := os.Chmod(e.state, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(e.state, 0o755) })
	e.pingOK["8.8.8.8|true"] = false // underlay dead → relay NOW
	e.tcpOK["8.8.8.8:53"] = false
	e.n.checkOverlayEgress(context.Background())
	// The rule flipped even though the state file could not be
	// written.
	if !e.host.Ran("rule add pref 1500 to 8.8.8.8/32 lookup 100") {
		t.Fatalf("relay rule not added despite commit failure: %v", e.host.Cmds())
	}
	if !strings.Contains(logLines(t, e), "-> overlay relay table 100") {
		t.Fatalf("missing relay commit log:\n%s", logLines(t, e))
	}
}
