// overlay_egress_test.go — overlay egress direct/relay switching and drift heal.

package nethealth

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
