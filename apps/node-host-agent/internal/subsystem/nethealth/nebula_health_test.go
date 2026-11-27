// nebula_health_test.go — nebula-health socket/dataplane probes and isolated/degraded/slowpath/siteedge latches.

package nethealth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/vishvananda/netlink"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/nodecoord"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/nethealth/nebula"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

func TestNebulaHealthy(t *testing.T) {
	e := nebulaEnv(t, nil)
	e.n.Cycle(context.Background())
	if stateExists(e, "nebula-isolated") || stateExists(e, "nebula-degraded") {
		t.Fatal("false latch on healthy nebula")
	}
	if e.sd.Ran("restart nebula") {
		t.Fatal("restart on healthy nebula")
	}
}

func TestNebulaNoSocketRestart(t *testing.T) {
	e := nebulaEnv(t, nil)
	testutil.WriteFile(t, e.procudp, "  sl  local_address rem_address   st\n"+
		"  1: 0100007F:0050 00000000:0000 07\n") // no :B9B6 (45670)
	e.n.Cycle(context.Background())
	if e.sd.Ran("restart nebula") {
		t.Fatal("restart before ConsecNeeded")
	}
	e.n.Cycle(context.Background())
	if !e.sd.Ran("restart nebula@interdc") {
		t.Fatalf("nebula not restarted, cmds=%v", e.sd.Cmds())
	}
	if _, err := os.Stat(filepath.Join(e.state, "last-nebula-restart")); err != nil {
		t.Fatal("budget not spent")
	}
}

func TestNebulaDataplaneDeadIsolates(t *testing.T) {
	e := nebulaEnv(t, nil)
	for _, ip := range []string{"10.8.0.1", "10.8.0.2"} {
		e.pingOK[ip+"|false"] = false // all pub targets dead
	}
	e.n.Cycle(context.Background())
	if !stateExists(e, "nebula-isolated") {
		t.Fatal("isolated latch missing on dataplane dead")
	}
	e.n.Cycle(context.Background())
	if !e.sd.Ran("restart nebula@interdc") {
		t.Fatal("no restart on persistent dataplane dead")
	}
}

func TestNebulaDegradedLatch(t *testing.T) {
	e := nebulaEnv(t, func(wd *watchdogconf.Config) {
		wd.OverlayProbeMarkers = []string{"10.8.1.1", "10.8.1.2", "10.8.1.3"}
	})
	// 2 of 3 markers dead but one alive → degraded, not isolated
	// (isolated needs ALL of a group dead).
	e.pingOK["10.8.1.3|false"] = true
	e.pingOK["10.8.1.1|false"] = false
	e.pingOK["10.8.1.2|false"] = false
	e.n.Cycle(context.Background())
	if stateExists(e, "nebula-degraded") {
		t.Fatal("degraded latch before DEGRADED_CONSEC")
	}
	e.n.Cycle(context.Background())
	if !stateExists(e, "nebula-degraded") {
		t.Fatal("degraded latch missing after 2 runs")
	}
	if stateExists(e, "nebula-isolated") {
		t.Fatal("isolated latch on partial loss")
	}
	if e.sd.Ran("restart nebula") {
		t.Fatal("degraded is not a restart reason")
	}
}

func TestNebulaNotActiveCleansStates(t *testing.T) {
	e := nebulaEnv(t, nil)
	e.sd.On("is-active nebula@interdc", "inactive\n")
	testutil.WriteFile(t, filepath.Join(e.state, "state-nebula-isolated"), "1\n")
	e.n.Cycle(context.Background())
	if stateExists(e, "nebula-isolated") {
		t.Fatal("nebula state kept while inactive")
	}
}

func TestNebulaOverlayTincSkipsDataplane(t *testing.T) {
	e := nebulaEnv(t, func(wd *watchdogconf.Config) {
		wd.OverlayActive = "tinc"
	})
	// All probes dead — but overlay=tinc → no dataplane probing, no
	// dataplane states.
	for k := range e.pingOK {
		e.pingOK[k] = false
	}
	e.n.Cycle(context.Background())
	if stateExists(e, "nebula-isolated") || stateExists(e, "nebula-degraded") {
		t.Fatal("dataplane latch while tinc is active overlay")
	}
	if e.sd.Ran("restart nebula") {
		t.Fatal("restart while only dataplane evidence (asymmetric probe)")
	}
}

func TestNebulaSlowpathAndSiteedge(t *testing.T) {
	e := nebulaEnv(t, func(wd *watchdogconf.Config) {
		wd.OverlaySlowpathMarkers = []string{"10.8.1.1"}
		wd.OverlaySiteMarkers = []string{"10.9.0.1"}
	})
	e.pingOK["10.9.0.1|false"] = true
	e.pingRTT["10.8.1.1|false"] = 150 // > slowpath 100ms
	e.pingRTT["10.9.0.1|false"] = 80  // > siteedge 50ms
	e.n.Cycle(context.Background())
	if !stateExists(e, "nebula-slowpath") {
		t.Fatal("slowpath latch missing")
	}
	if !stateExists(e, "nebula-siteedge") {
		t.Fatal("siteedge latch missing")
	}
}

// --- nebula-conntrack-flush: targeted per-peer conntrack flush on degraded/siteedge ---

// nebulaStaticMapEnv wires a HostRoot carrying a rendered
// /etc/nebula/interdc/config.yaml static_host_map — the dead-marker
// → underlay resolution table the per-peer flush consults.
func nebulaStaticMapEnv(t *testing.T, e *env, entries map[string]string) string {
	t.Helper()
	root := t.TempDir()
	var b strings.Builder
	b.WriteString("static_host_map:\n")
	for overlay, under := range entries {
		fmt.Fprintf(&b, "  %q: [%q]\n", overlay, under)
	}
	dir := filepath.Join(root, "etc", "nebula", "interdc")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(dir, "config.yaml"), b.String())
	e.n.cfg.HostRoot = root
	return root
}

// The degraded path must flush ONLY the dead peers' underlay
// conntrack — never a live peer's flows, and never the overlay
// (marker) IPs conntrack doesn't record.
func TestNebulaDegradedFlushesDeadPeerConntrack(t *testing.T) {
	e := nebulaEnv(t, func(wd *watchdogconf.Config) {
		wd.OverlayProbeMarkers = []string{"10.8.1.1", "10.8.1.2", "10.8.1.3"}
	})
	nebulaStaticMapEnv(t, e, map[string]string{
		"10.8.1.1": "203.0.113.11:45670",
		"10.8.1.2": "203.0.113.12:45670",
		"10.8.1.3": "203.0.113.13:45670", // ALIVE — must never be flushed
	})
	e.pingOK["10.8.1.3|false"] = true // 1 alive marker → degraded, not isolated
	e.pingOK["10.8.1.1|false"] = false
	e.pingOK["10.8.1.2|false"] = false

	e.n.Cycle(context.Background()) // streak 1/2 — not yet confirmed
	if countCmds(e, "conntrack -D -p udp --dport 45670") != 0 {
		t.Fatalf("flush fired before the degraded verdict confirmed, cmds=%v", e.host.Cmds())
	}
	e.n.Cycle(context.Background()) // latch confirmed → flush dead only
	if !stateExists(e, "nebula-degraded") {
		t.Fatal("degraded latch missing")
	}
	for _, under := range []string{"203.0.113.11", "203.0.113.12"} {
		if !e.host.Ran("conntrack -D -p udp --dport 45670 -d "+under) ||
			!e.host.Ran("conntrack -D -p udp --dport 45670 -s "+under) {
			t.Fatalf("dead peer %s not flushed both directions, cmds=%v", under, e.host.Cmds())
		}
	}
	for _, bad := range []string{
		"-d 203.0.113.13", "-s 203.0.113.13", // live peer underlay
		"-d 10.8.1.1", "-d 10.8.1.2", // overlay IPs — never in conntrack
		"-d 10.8.0.1", "-d 10.8.0.2", // alive probe targets
	} {
		if e.host.Ran("conntrack -D -p udp --dport 45670 " + bad) {
			t.Fatalf("flush touched %s — only dead peers allowed, cmds=%v", bad, e.host.Cmds())
		}
	}
	if e.sd.Ran("restart nebula") {
		t.Fatal("degraded flush restarted nebula — the point is to avoid that")
	}
	// The 5m budget: another degraded cycle must not re-flush.
	e.host.ClearLog()
	e.n.Cycle(context.Background())
	if countCmds(e, "conntrack -D -p udp --dport 45670") != 0 {
		t.Fatalf("dead-peer flush re-ran inside the 5m budget, cmds=%v", e.host.Cmds())
	}
}

// Dead OVERLAY_PROBE_TARGETS are already underlay IPs — no
// static_host_map lookup needed; they flush verbatim.
func TestNebulaDegradedFlushesDeadTargetsDirectly(t *testing.T) {
	e := nebulaEnv(t, func(wd *watchdogconf.Config) {
		wd.OverlayProbeTargets = []string{"10.8.0.1", "10.8.0.2", "10.8.0.3"}
	})
	e.n.cfg.HostRoot = t.TempDir() // no static map needed for targets
	e.pingOK["10.8.0.3|false"] = true
	e.pingOK["10.8.0.1|false"] = false
	e.pingOK["10.8.0.2|false"] = false // 2/3 dead → degraded
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background())
	if !e.host.Ran("conntrack -D -p udp --dport 45670 -d 10.8.0.1") ||
		!e.host.Ran("conntrack -D -p udp --dport 45670 -d 10.8.0.2") {
		t.Fatalf("dead underlay targets not flushed, cmds=%v", e.host.Cmds())
	}
	if e.host.Ran("-d 10.8.0.3") || e.host.Ran("-s 10.8.0.3") {
		t.Fatalf("live target flushed, cmds=%v", e.host.Cmds())
	}
}

// A dead SITE marker must flush its resolved underlay only after
// ConsecNeeded confirmed siteedge runs — the latch itself arms on
// the first detection.
func TestNebulaSiteedgeFlushesAfterConfirm(t *testing.T) {
	e := nebulaEnv(t, func(wd *watchdogconf.Config) {
		wd.OverlaySiteMarkers = []string{"10.9.0.1"}
	})
	nebulaStaticMapEnv(t, e, map[string]string{
		"10.9.0.1": "198.51.100.7:45670",
	})
	e.pingOK["10.9.0.1|false"] = false // site edge dead, everything else alive
	e.n.Cycle(context.Background())
	if !stateExists(e, "nebula-siteedge") {
		t.Fatal("siteedge latch missing on first detection")
	}
	if countCmds(e, "conntrack -D -p udp --dport 45670") != 0 {
		t.Fatalf("flush fired before ConsecNeeded siteedge runs, cmds=%v", e.host.Cmds())
	}
	e.n.Cycle(context.Background()) // run 2 >= ConsecNeeded → flush
	if !e.host.Ran("conntrack -D -p udp --dport 45670 -d 198.51.100.7") {
		t.Fatalf("dead site-edge underlay not flushed, cmds=%v", e.host.Cmds())
	}
	if e.sd.Ran("restart nebula") {
		t.Fatal("siteedge flush restarted nebula")
	}
}

// A dead marker with NO static_host_map entry is skipped — the
// flush must never guess an underlay for an overlay IP.
func TestNebulaDegradedSkipsUnresolvableMarkers(t *testing.T) {
	e := nebulaEnv(t, func(wd *watchdogconf.Config) {
		wd.OverlayProbeMarkers = []string{"10.8.1.1", "10.8.1.2", "10.8.1.3"}
	})
	e.n.cfg.HostRoot = t.TempDir() // empty — nothing resolves
	e.pingOK["10.8.1.3|false"] = true
	e.pingOK["10.8.1.1|false"] = false
	e.pingOK["10.8.1.2|false"] = false
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background())
	if !stateExists(e, "nebula-degraded") {
		t.Fatal("degraded latch missing")
	}
	if countCmds(e, "conntrack -D -p udp --dport 45670") != 0 {
		t.Fatalf("flush fired with no resolvable dead peer, cmds=%v", e.host.Cmds())
	}
	if _, err := os.Stat(filepath.Join(e.state, "last-nebula-degraded-ct-flush")); err == nil {
		t.Fatal("flush budget spent with nothing to flush")
	}
}

// nebulaUnderlayPeers parses static_host_map overlay→underlay.
func TestNebulaUnderlayPeersParsesStaticHostMap(t *testing.T) {
	e := nebulaEnv(t, nil)
	nebulaStaticMapEnv(t, e, map[string]string{
		"10.8.1.1": "203.0.113.11:45670",
		"10.8.1.2": "203.0.113.12:45670",
	})
	got := e.n.nebulaUnderlayPeers("interdc")
	if len(got["10.8.1.1"]) != 1 || got["10.8.1.1"][0] != "203.0.113.11" {
		t.Fatalf("peers=%v", got)
	}
	if got["10.8.1.2"][0] != "203.0.113.12" {
		t.Fatalf("peers=%v", got)
	}
	if len(e.n.nebulaUnderlayPeers("")) != 0 ||
		len(e.n.nebulaUnderlayPeers("nonexistent")) != 0 {
		t.Fatal("empty net / missing dir must yield an empty map")
	}
}

// --- nebula-conntrack-flush: clock latch → systemd-timesyncd restart ---

func TestNebulaClockLatchRestartsTimesyncd(t *testing.T) {
	e := nebulaEnv(t, nil)
	// timesyncd must be enabled/active for the latch restart —
	// a dormant unit (chrony host) is never woken.
	e.sd.On("is-enabled systemd-timesyncd.service", "enabled\n")
	e.sd.On("restart systemd-timesyncd.service", "")
	testutil.WriteFile(t, e.procudp,
		"  sl  local_address rem_address   st\n") // socket unbound → nebula fails
	testutil.WriteFile(t, filepath.Join(e.state, "state-clock-skew"), "1\n")
	e.n.Cycle(context.Background())
	if !e.sd.Ran("restart systemd-timesyncd.service") {
		t.Fatalf("timesyncd not restarted under clock latch, cmds=%v", e.sd.Cmds())
	}
	// Budget is 10m — a second failing cycle inside the window
	// must not restart again.
	e.n.Cycle(context.Background())
	got := 0
	for _, c := range e.sd.Cmds() {
		if strings.Contains(strings.Join(c, " "), "restart systemd-timesyncd.service") {
			got++
		}
	}
	if got != 1 {
		t.Fatalf("timesyncd restarted %d times, want 1 (10m budget)", got)
	}
}

func TestNebulaNoClockLatchNoTimesyncdRestart(t *testing.T) {
	e := nebulaEnv(t, nil)
	testutil.WriteFile(t, e.procudp,
		"  sl  local_address rem_address   st\n") // socket unbound → nebula fails
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background())
	if e.sd.Ran("restart systemd-timesyncd") {
		t.Fatal("timesyncd restarted without a clock latch")
	}
}

// A clock latch while nebula is unhealthy must not restart a
// DORMANT timesyncd — on chrony hosts the unit ships installed but
// disabled/inactive and a restart would put a second NTP daemon on
// the box fighting chrony over adjtimex.
func TestTimesyncdLatchRestartGatedOnLiveUnit(t *testing.T) {
	e := fixture(t, nil)
	e.n.state.Enter("clock-unsync", "test")
	ctx := context.Background()

	// Default sd Miss = "no unit" — neither enabled nor active:
	// the latch alone must not restart timesyncd (nor spend budget).
	e.n.restartTimesyncdOnClockLatch(ctx)
	if e.sd.Ran("restart systemd-timesyncd.service") {
		t.Fatal("dormant timesyncd restarted on chrony-style host")
	}

	// Enabled (the node's real daemon, possibly crashed) → restart.
	e.sd.On("is-enabled systemd-timesyncd.service", "enabled\n")
	e.n.restartTimesyncdOnClockLatch(ctx)
	if !e.sd.Ran("restart systemd-timesyncd.service") {
		t.Fatal("enabled timesyncd not restarted under clock latch")
	}
}

// --- minRTT parser ---

func TestMinRTTKeepsSmallestSample(t *testing.T) {
	out := "64 bytes from peer: icmp_seq=1 ttl=64 time=42.5 ms\n" +
		"64 bytes from peer: icmp_seq=2 ttl=64 time=13.2 ms\n" +
		"64 bytes from peer: icmp_seq=3 ttl=64 time=9.75 ms\n"
	if got := minRTT(out); got != 9.75 {
		t.Fatalf("minRTT=%v want 9.75", got)
	}
	if got := minRTT("no samples here"); got != -1.0 {
		t.Fatalf("minRTT on no samples=%v want -1", got)
	}
	if got := minRTT("time=notanumber"); got != -1.0 {
		t.Fatalf("minRTT on garbage sample=%v want -1", got)
	}
}

// --- nebula-direct-tcp: the pref-1499 bypass-rule guard ---

// directTCPEnv wires a host with the nebula script deployed (the
// check's only deployment gate) and an empty netlink rule dump.
func directTCPEnv(t *testing.T) *env {
	t.Helper()
	e := fixture(t, &watchdogconf.Config{NebulaNet: "interdc"})
	root := t.TempDir()
	e.n.cfg.HostRoot = root
	testutil.WriteFile(t, filepath.Join(root, "etc/nebula/interdc/nebula-up.sh"),
		"#!/bin/bash\nexit 0\n")
	// The listing rides the rulesFn netlink seam now (writes stay on
	// the scripted host): empty table by default.
	e.n.cfg.rulesFn = func(int) ([]netlink.Rule, error) { return nil, nil }
	return e
}

// An unanswerable policy-rules dump aborts the cycle — rules must
// never be re-added on a blind read.
func TestDirectTCPRuleListFailureAborts(t *testing.T) {
	e := directTCPEnv(t)
	e.n.cfg.rulesFn = func(int) ([]netlink.Rule, error) {
		return nil, errCmdFail
	}
	e.n.checkNebulaDirectTCP(context.Background())
	if e.host.Ran("rule add pref 1499") {
		t.Fatalf("rule added on a failed listing: %v", e.host.Cmds())
	}
	if got := promtest.ToFloat64(e.n.cycles.WithLabelValues(
		checkNebTCP, "open_error")); got != 1 {
		t.Fatalf("open_error metric=%v want 1", got)
	}
}

// Ports outside 1..65535 are skipped without touching ip; in-range
// missing ports get their rule.
func TestDirectTCPSkipsInvalidPorts(t *testing.T) {
	e := directTCPEnv(t)
	e.n.cfg.NebulaDirectTCPPorts = []int{0, -22, 70000, 22}
	e.n.checkNebulaDirectTCP(context.Background())
	if !e.host.Ran("rule add pref 1499 ipproto tcp dport 22 lookup main") ||
		!e.host.Ran("rule add pref 1499 ipproto tcp sport 22 lookup main") {
		t.Fatalf("in-range port not enforced: %v", e.host.Cmds())
	}
	for _, c := range e.host.Cmds() {
		joined := strings.Join(c, " ")
		if strings.Contains(joined, "port 0") ||
			strings.Contains(joined, "port 70000") ||
			strings.Contains(joined, "port -22") {
			t.Fatalf("invalid port reached ip: %v", c)
		}
	}
}

// A port whose rule already shows in the dump is not re-added;
// a missing sibling port still is (the fold-in keeps one dump).
func TestDirectTCPSkipsPresentRules(t *testing.T) {
	e := directTCPEnv(t)
	e.n.cfg.rulesFn = func(int) ([]netlink.Rule, error) {
		return []netlink.Rule{
			{Priority: 1499, Dport: &netlink.RulePortRange{Start: 22, End: 22}},
			{Priority: 1499, Sport: &netlink.RulePortRange{Start: 22, End: 22}},
		}, nil
	}
	e.n.cfg.NebulaDirectTCPPorts = []int{22, 6443}
	e.n.checkNebulaDirectTCP(context.Background())
	if e.host.Ran("dport 22") || e.host.Ran("sport 22") {
		t.Fatal("already-present dport/sport 22 rule re-added")
	}
	if !e.host.Ran("rule add pref 1499 ipproto tcp dport 6443 lookup main") ||
		!e.host.Ran("rule add pref 1499 ipproto tcp sport 6443 lookup main") {
		t.Fatalf("missing dport/sport 6443 rule not added: %v", e.host.Cmds())
	}
}

// A failed rule add is logged and attributed (restore_error) — and
// the remaining ports still get their attempt.
func TestDirectTCPAddFailureLogged(t *testing.T) {
	e := directTCPEnv(t)
	e.host.FailOn("rule add pref 1499", errCmdFail)
	e.n.cfg.NebulaDirectTCPPorts = []int{22, 6443}
	e.n.checkNebulaDirectTCP(context.Background())
	if got := strings.Count(e.host.Joined(), "rule add pref 1499"); got != 4 {
		t.Fatalf("rule add attempts=%d want 4 (dport+sport per port)", got)
	}
	if got := promtest.ToFloat64(e.n.cycles.WithLabelValues(
		checkNebTCP, "restore_error")); got != 4 {
		t.Fatalf("restore_error metric=%v want 4", got)
	}
	if !strings.Contains(logLines(t, e), "dport 22 failed") ||
		!strings.Contains(logLines(t, e), "sport 22 failed") {
		t.Fatalf("missing add-failure log:\n%s", logLines(t, e))
	}
}

// --- nebula-health reason strings ---

// A bound socket with an unaddressed tun names the tun in the
// restart evidence — the operator sees WHICH leg died.
func TestNebulaNoTunAddrReason(t *testing.T) {
	e := nebulaEnv(t, nil)
	// Interface up, no inet addr — the LinkAddrs seam answers empty.
	e.n.cfg.linkAddrsFn = func(int, string) ([]netlink.Addr, error) {
		return nil, nil
	}
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background())
	if !e.sd.Ran("restart nebula@interdc") {
		t.Fatal("nebula not restarted on missing tun addr")
	}
	if !strings.Contains(logLines(t, e), "nebula-no-tun-addr dev=neb1") {
		t.Fatalf("missing no-tun-addr reason:\n%s", logLines(t, e))
	}
}

// A dead stats endpoint names the URL in the restart evidence.
func TestNebulaStatsDeadReason(t *testing.T) {
	e := nebulaEnv(t, nil)
	e.httpErr[e.n.cfg.Watchdog.NebulaStatsURL] = errors.New("refused")
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background())
	if !e.sd.Ran("restart nebula@interdc") {
		t.Fatal("nebula not restarted on dead stats endpoint")
	}
	if !strings.Contains(logLines(t, e), "nebula-stats-dead") {
		t.Fatalf("missing stats-dead reason:\n%s", logLines(t, e))
	}
}

// nebulaRestart without a systemd client is a throttled skip — the
// latch/suspect machinery above it still records the failure.
func TestNebulaRestartNilSystemd(t *testing.T) {
	e := nebulaEnv(t, nil)
	e.n.cfg.Systemd = nil
	e.n.nebulaRestart(context.Background())
	if !strings.Contains(logLines(t, e), "nebula restart skipped — no systemd client") {
		t.Fatalf("missing nil-systemd suspect line:\n%s", logLines(t, e))
	}
}

// probeNebulaOverlay fills unset OVERLAY_PROBE_COUNT/WAIT with the
// wd_ping_fanout defaults (3 probes, 4s wait) — the fanout calls
// must carry both, not zeroed values. The conf is deliberately
// UN-normalized (assigned post-New) — applyDefaults' Normalize would
// pre-fill the fields and mask the fallback.
func TestProbeNebulaOverlayDefaults(t *testing.T) {
	e := fixture(t, nil)
	e.n.cfg.Watchdog = &watchdogconf.Config{
		OverlayProbeTargets: []string{"10.8.0.1", "10.8.0.2"},
		OverlayProbeMarkers: []string{"10.8.1.1"},
	}
	type call struct {
		count, wait int
	}
	var mu sync.Mutex
	var got []call
	e.n.cfg.ping = func(_ context.Context, _ string, count, wait int, _ bool) (bool, float64) {
		mu.Lock()
		got = append(got, call{count, wait})
		mu.Unlock()
		return true, 1
	}
	targets, results := e.n.probeNebulaOverlay(context.Background(), e.n.cfg.Watchdog)
	mu.Lock()
	defer mu.Unlock()
	if len(targets) != 3 || len(results) != len(targets) {
		t.Fatalf("targets=%v results=%v", targets, results)
	}
	for _, c := range got {
		if c.count != 3 || c.wait != 4 {
			t.Fatalf("probe args count=%d wait=%d want 3/4", c.count, c.wait)
		}
	}
}

// Site-edge recovery: the marker set answering again resets the
// confirmation counter and exits the siteedge latch.
func TestSiteedgeRecoveryResetsAndExits(t *testing.T) {
	e := nebulaEnv(t, func(wd *watchdogconf.Config) {
		wd.OverlaySiteMarkers = []string{"10.9.0.1"}
	})
	e.pingOK["10.9.0.1|false"] = true
	testutil.WriteFile(t, filepath.Join(e.state, "state-nebula-siteedge"), "1\n")
	e.n.neb.SiteedgeRun = 3
	wd := e.n.cfg.Watchdog
	_, results := e.n.probeNebulaOverlay(context.Background(), wd)
	st := aggregateNebulaOverlay(wd, results)
	e.n.latchNebulaOverlayPaths(wd, st)
	if e.n.neb.SiteedgeRun != 0 {
		t.Fatalf("siteedge run counter=%d want 0 on recovery", e.n.neb.SiteedgeRun)
	}
	if stateExists(e, "nebula-siteedge") {
		t.Fatal("siteedge latch kept after markers recovered")
	}
}

// A degraded run under the DEFAULT NebulaDegradedConsec (0 → 2)
// enters the latch on the second consecutive run — the shell's
// CONSEC default. The conf is un-normalized (post-New) so the
// `need <= 0` fallback actually runs.
func TestNebulaDegradedDefaultConsec(t *testing.T) {
	e := fixture(t, nil)
	wd := &watchdogconf.Config{
		OverlayActive:       "nebula",
		OverlayProbeTargets: []string{"10.8.0.1", "10.8.0.2", "10.8.0.3"},
	}
	e.n.cfg.Watchdog = wd
	results := map[string]nebula.PingResult{
		"10.8.0.1": {Ok: true, Rtt: 5},
		"10.8.0.2": {Ok: false},
		"10.8.0.3": {Ok: false},
	}
	st := aggregateNebulaOverlay(wd, results)
	// The degraded verdict arms its own latch — it does NOT produce
	// a check-failure reason (a half-alive mesh is not a nebula
	// restart trigger; only full dataplane death is).
	reason, dpFail, isolated := e.n.nebulaOverlayVerdict(context.Background(), wd, st)
	if reason != "" || dpFail || isolated {
		t.Fatalf("verdict reason=%q dpFail=%v isolated=%v want silent degraded", reason, dpFail, isolated)
	}
	if stateExists(e, "nebula-degraded") {
		t.Fatal("degraded latch armed on run 1 of default 2")
	}
	_, _, _ = e.n.nebulaOverlayVerdict(context.Background(), wd, st)
	if !stateExists(e, "nebula-degraded") {
		t.Fatal("degraded latch missing after 2 runs of default consec")
	}
}

// nebulaUnderlayPeers: empty net name → empty map; unreadable and
// unparseable yaml files degrade to an empty map with a suspect
// line (the flush then skips unresolvable markers, never guesses).
func TestNebulaUnderlayPeersDegradedInputs(t *testing.T) {
	e := fixture(t, &watchdogconf.Config{NebulaNet: "interdc"})
	if m := e.n.nebulaUnderlayPeers(""); len(m) != 0 {
		t.Fatalf("empty net name map=%v want empty", m)
	}
	root := t.TempDir()
	dir := filepath.Join(root, "etc", "nebula", "interdc")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	e.n.cfg.HostRoot = root
	// A directory squatting a *.yaml name — ReadFile fails, skipped.
	if err := os.MkdirAll(filepath.Join(dir, "brokendir.yaml"), 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(dir, "garbage.yaml"), "static_host_map: [unclosed\n")
	if m := e.n.nebulaUnderlayPeers("interdc"); len(m) != 0 {
		t.Fatalf("degraded inputs map=%v want empty", m)
	}
	if !strings.Contains(logLines(t, e), "static_host_map parse failed") {
		t.Fatalf("missing parse-failure suspect line:\n%s", logLines(t, e))
	}
}

// underlayHost extracts the conntrack-selectable host half of a
// static_host_map endpoint, bracketed v6 included; junk yields "".
func TestUnderlayHostParsing(t *testing.T) {
	for addr, want := range map[string]string{
		"203.0.113.11:45670": "203.0.113.11",
		"[fd00::1]:45670":    "fd00::1",
		"  10.8.0.9:10000  ": "10.8.0.9",
		"203.0.113.20":       "203.0.113.20",
		"[fd00::2]":          "fd00::2",
		"":                   "",
		"   ":                "",
	} {
		if got := nebula.UnderlayHost(addr); got != want {
			t.Fatalf("nebula.UnderlayHost(%q)=%q want %q", addr, got, want)
		}
	}
}

// The nebula clock-latch timesyncd bounce folds a nil systemd
// client and a dormant timesyncd to no-ops — never a restart of a
// unit that isn't the node's daemon.
func TestTimesyncdClockLatchGates(t *testing.T) {
	ctx := context.Background()
	// Clock-skew (the hostmetrics latch) also arms the path —
	// with no systemd client it stops right there.
	e := fixture(t, nil)
	testutil.WriteFile(t, filepath.Join(e.state, "state-clock-skew"), "1\n")
	e.n.cfg.Systemd = nil
	e.n.restartTimesyncdOnClockLatch(ctx)
	if e.sd.Ran("restart") {
		t.Fatal("restart without a systemd client")
	}
	// With a client but a dormant timesyncd (disabled AND inactive —
	// chrony node), the restart must not fire either.
	e2 := fixture(t, nil)
	testutil.WriteFile(t, filepath.Join(e2.state, "state-clock-unsync"), "1\n")
	e2.n.restartTimesyncdOnClockLatch(ctx)
	if e2.sd.Ran("restart") {
		t.Fatalf("dormant timesyncd restarted, cmds=%v", e2.sd.Cmds())
	}
}

func TestNebulaInactivePreservesForeignLatchesAndExitsOwn(t *testing.T) {
	e := nebulaEnv(t, nil)
	e.sd.On("is-active nebula@interdc", "inactive\n")
	testutil.WriteFile(t, filepath.Join(e.state, "state-nebula-isolated"), "1\n")
	testutil.WriteFile(t, filepath.Join(e.state, "state-nebula-degraded"), "1\n")
	testutil.WriteFile(t, filepath.Join(e.state, "state-nebula-cert-expiring"), "1\n")
	testutil.WriteFile(t, filepath.Join(e.state, "state-nebula-mtu-blackhole"), "1\n")

	e.n.Cycle(context.Background())

	if stateExists(e, "nebula-isolated") || stateExists(e, "nebula-degraded") {
		t.Fatal("owned nebula latches not exited when nebula inactive")
	}
	if !stateExists(e, "nebula-cert-expiring") {
		t.Fatal("hostmetrics-owned state-nebula-cert-expiring was clobbered")
	}
	if !stateExists(e, "nebula-mtu-blackhole") {
		t.Fatal("mtu_blackhole-owned state-nebula-mtu-blackhole was clobbered")
	}
	if logs := logLines(t, e); !strings.Contains(logs, "STATE-EXIT: nebula-isolated") {
		t.Fatalf("expected STATE-EXIT log via State.Exit, got:\n%s", logs)
	}
}

func TestNebulaCoordHoldsEmergencyHealAndStampsRemediation(t *testing.T) {
	e := nebulaEnv(t, nil)
	held := true
	stamped := 0
	coord := &nodecoord.Coord{
		GetNode: func(context.Context) (map[string]string, []string, error) {
			if held {
				return nil, []string{nodecond.KuredRebootTaintKey}, nil
			}
			return nil, nil, nil
		},
		PatchNodeStatus: func(_ context.Context, cond nodecoord.StatusCondition) error {
			if cond.Type == nodecond.CondLocalRemediation && cond.Status == "True" {
				stamped++
			}
			return nil
		},
		Now: func() time.Time { return e.now },
	}
	e.n.cfg.Coord = coord
	e.sd.On("is-enabled systemd-timesyncd.service", "enabled\n")
	e.sd.On("restart systemd-timesyncd.service", "")
	e.sd.On("restart nebula@interdc", "")
	testutil.WriteFile(t, e.procudp, "  sl  local_address rem_address   st\n")
	testutil.WriteFile(t, filepath.Join(e.state, "state-clock-skew"), "1\n")

	// Under maintenance hold: CheckNebulaHealth, NebulaRestart, RestartTimesyncdOnClockLatch,
	// and flushStaleUDPConntrack must NOT restart/flush or spend cooldown budgets.
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background())
	e.n.nebulaRestart(context.Background())
	e.n.flushStaleUDPConntrack(context.Background(), checkNebula)

	if e.sd.Ran("restart nebula") || e.sd.Ran("restart systemd-timesyncd") {
		t.Fatalf("restarted services under nodecoord hold: %v", e.sd.Cmds())
	}
	if e.host.Ran("conntrack -D") {
		t.Fatalf("flushed conntrack under nodecoord hold: %v", e.host.Cmds())
	}
	for _, budget := range []string{"last-nebula-restart", "last-ntp-restart", "last-conntrack-flush"} {
		if _, err := os.Stat(filepath.Join(e.state, budget)); err == nil {
			t.Fatalf("cooldown budget %s spent while held", budget)
		}
	}

	// Lift hold and advance clock past CacheTTL: restart + flush + stamp fire.
	held = false
	e.now = e.now.Add(nodecoord.CacheTTL + time.Second)
	e.n.Cycle(context.Background())
	if !e.sd.Ran("restart nebula@interdc") {
		t.Fatalf("nebula not restarted after hold lifted: %v", e.sd.Cmds())
	}
	if !e.sd.Ran("restart systemd-timesyncd.service") {
		t.Fatalf("timesyncd not restarted after hold lifted: %v", e.sd.Cmds())
	}
	if !e.host.Ran("conntrack -D -p udp --dport 53") {
		t.Fatalf("udp/53 conntrack not flushed after hold lifted: %v", e.host.Cmds())
	}
	if stamped < 2 {
		t.Fatalf("expected StampLocalRemediation for both timesyncd and nebula restarts, got %d", stamped)
	}
}

func TestProbeNebulaOverlayDeduplicatesTargets(t *testing.T) {
	e := fixture(t, nil)
	e.n.cfg.Watchdog = &watchdogconf.Config{
		OverlayProbeTargets: []string{"10.8.0.1", "10.8.0.2", "10.8.0.1"},
		OverlayProbeMarkers: []string{"10.8.0.2", "10.8.1.1"},
		OverlaySiteMarkers:  []string{"10.8.1.1", "", "10.9.0.1"},
	}
	var mu sync.Mutex
	counts := map[string]int{}
	e.n.cfg.ping = func(_ context.Context, ip string, _, _ int, _ bool) (bool, float64) {
		mu.Lock()
		counts[ip]++
		mu.Unlock()
		return true, 5.0
	}
	targets, results := e.n.probeNebulaOverlay(context.Background(), e.n.cfg.Watchdog)
	wantTargets := []string{"10.8.0.1", "10.8.0.2", "10.8.1.1", "10.9.0.1"}
	if !slices.Equal(targets, wantTargets) {
		t.Fatalf("targets=%v want %v", targets, wantTargets)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, ip := range wantTargets {
		if counts[ip] != 1 {
			t.Fatalf("ip %s pinged %d times want 1 (counts=%v)", ip, counts[ip], counts)
		}
	}
	if len(results) != len(wantTargets) {
		t.Fatalf("results len=%d want %d", len(results), len(wantTargets))
	}
	// AggregateNebulaOverlay still tallies full per-class slice counts.
	st := aggregateNebulaOverlay(e.n.cfg.Watchdog, results)
	if st == nil {
		t.Fatal("nil stats")
	}
}

// TestNebulaHubIsolatedPreservesLiveSiteMesh — incident 2026-11-27 cicd:
// when the remote hub/lighthouse is unreachable (dpAlive==0, mkAlive==0)
// but same-site peers (OverlaySiteMarkers) are STILL alive, local
// nebula@interdc dataplane works. The check must STILL arm
// state-nebula-isolated (and clear degraded), flush conntrack ONLY for
// the dead remote/hub peers on the isolation edge (never live site
// peers), log the hold suspect line, and NOT restart nebula@interdc even
// after ConsecNeeded cycles.
func TestNebulaHubIsolatedPreservesLiveSiteMesh(t *testing.T) {
	e := nebulaEnv(t, func(wd *watchdogconf.Config) {
		wd.OverlayProbeTargets = []string{"103.186.101.30"}
		wd.OverlayProbeMarkers = []string{"172.29.0.3"}
		wd.OverlaySiteMarkers = []string{"172.29.0.10"}
		wd.OverlayEgressRelays = []string{"198.51.100.10"} // live site peer underlay
	})
	nebulaStaticMapEnv(t, e, map[string]string{
		"172.29.0.3":  "103.186.101.31:45670", // dead hub marker underlay
		"172.29.0.10": "198.51.100.10:45670",  // live site peer underlay — must NOT be flushed
	})
	e.pingOK["103.186.101.30|false"] = false
	e.pingOK["172.29.0.3|false"] = false
	e.pingOK["172.29.0.10|false"] = true
	e.pingRTT["172.29.0.10|false"] = 2
	// Keep overlay-egress direct probe green for 198.51.100.10 so any flush of
	// it would strictly come from nebula-health (proving nebulaPeerUnderlayIPs
	// was NOT flushed on the site-alive isolation edge).
	e.pingOK["198.51.100.10|true"] = true

	// Seed a stale degraded latch + streak to verify both clear on isolation.
	testutil.WriteFile(t, filepath.Join(e.state, "state-nebula-degraded"), "1\n")
	e.n.neb.NebulaDeg = 2

	// Run past ConsecNeeded (2) cycles — restart must remain held.
	for i := range 3 {
		e.n.Cycle(context.Background())
		if !stateExists(e, "nebula-isolated") {
			t.Fatalf("cycle %d: nebula-isolated latch missing", i+1)
		}
		if stateExists(e, "nebula-degraded") || e.n.neb.NebulaDeg != 0 {
			t.Fatalf("cycle %d: degraded latch/counter not cleared (deg=%d)", i+1, e.n.neb.NebulaDeg)
		}
	}
	if e.sd.Ran("restart nebula") {
		t.Fatalf("nebula@interdc restarted despite live site-mesh, cmds=%v", e.sd.Cmds())
	}
	// Dead hub underlay (direct target + static_host_map resolved marker)
	// flushed on the isolation edge; live site peer untouched.
	for _, dead := range []string{"103.186.101.30", "103.186.101.31"} {
		if !e.host.Ran("conntrack -D -p udp --dport 45670 -d "+dead) ||
			!e.host.Ran("conntrack -D -p udp --dport 45670 -s "+dead) {
			t.Fatalf("dead hub peer %s not flushed, cmds=%v", dead, e.host.Cmds())
		}
	}
	if e.host.Ran("198.51.100.10") {
		t.Fatalf("live site peer underlay was flushed, cmds=%v", e.host.Cmds())
	}
	if logs := logLines(t, e); !strings.Contains(logs,
		"suspect: nebula-hub-isolated-site-alive pub=0/1 marker=0/1 site=1/1 — holding nebula restart to preserve site-mesh") {
		t.Fatalf("missing site-alive hold suspect log:\n%s", logs)
	}
}

// TestNebulaHubAndSiteMeshBothDeadRestarts verifies that when BOTH the
// remote hub AND the local site-mesh markers are dead (siteAlive==0),
// the existing full dataplane-dead restart fires after ConsecNeeded.
func TestNebulaHubAndSiteMeshBothDeadRestarts(t *testing.T) {
	e := nebulaEnv(t, func(wd *watchdogconf.Config) {
		wd.OverlayProbeTargets = []string{"103.186.101.30"}
		wd.OverlayProbeMarkers = []string{"172.29.0.3"}
		wd.OverlaySiteMarkers = []string{"172.29.0.10"}
	})
	e.pingOK["103.186.101.30|false"] = false
	e.pingOK["172.29.0.3|false"] = false
	e.pingOK["172.29.0.10|false"] = false // site-mesh also dead

	e.n.Cycle(context.Background())
	if !stateExists(e, "nebula-isolated") {
		t.Fatal("nebula-isolated latch missing when hub + site-mesh both dead")
	}
	if e.sd.Ran("restart nebula") {
		t.Fatal("restarted before ConsecNeeded")
	}
	e.n.Cycle(context.Background())
	if !e.sd.Ran("restart nebula@interdc") {
		t.Fatalf("nebula@interdc not restarted when hub + site-mesh both dead, cmds=%v", e.sd.Cmds())
	}
}

// TestNebulaTxQueueLenAutoRaised — incident 2026-11-27 production: when
// neb1 is up with tx_queue_len below 4096 (e.g. default 500), nebula-health
// raises it hitlessly via `ip link set dev neb1 txqueuelen 4096`, logs the
// ACTION, increments the txqueuelen action counter, and respects the
// cooldown / already-compliant ceiling.
func TestNebulaTxQueueLenAutoRaised(t *testing.T) {
	e := nebulaEnv(t, nil)
	root := t.TempDir()
	e.n.cfg.HostRoot = root
	txqPath := filepath.Join(root, "sys", "class", "net", "neb1", "tx_queue_len")
	testutil.WriteFile(t, txqPath, "500\n")

	e.n.Cycle(context.Background())
	if !e.host.Ran("ip link set dev neb1 txqueuelen 4096") {
		t.Fatalf("expected hitless txqueuelen raise, cmds=%v", e.host.Cmds())
	}
	if got := promtest.ToFloat64(e.n.actions.WithLabelValues(nebula.CheckNebula, "txqueuelen")); got != 1 {
		t.Fatalf("txqueuelen action counter=%v want 1", got)
	}
	if logs := logLines(t, e); !strings.Contains(logs, "ACTION: nebula txqueuelen raised dev=neb1 500->4096") {
		t.Fatalf("missing txqueuelen ACTION log:\n%s", logs)
	}

	// Second cycle inside cooldown must not repeat even if sysfs still reads 500.
	e.n.Cycle(context.Background())
	if got := promtest.ToFloat64(e.n.actions.WithLabelValues(nebula.CheckNebula, "txqueuelen")); got != 1 {
		t.Fatalf("txqueuelen action counter=%v want 1 (cooldown)", got)
	}

	// Already >= 4096 on a fresh env must be a complete no-op.
	e2 := nebulaEnv(t, nil)
	root2 := t.TempDir()
	e2.n.cfg.HostRoot = root2
	testutil.WriteFile(t, filepath.Join(root2, "sys", "class", "net", "neb1", "tx_queue_len"), "4096\n")
	e2.n.Cycle(context.Background())
	if e2.host.Ran("txqueuelen") {
		t.Fatalf("txqueuelen touched when already 4096, cmds=%v", e2.host.Cmds())
	}
}
