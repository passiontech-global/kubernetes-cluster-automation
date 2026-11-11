// nebula_health_test.go — nebula-health socket/dataplane probes and isolated/degraded/slowpath/siteedge latches.

package nethealth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/nethealth/nebula"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
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
// check's only deployment gate) and empty rule listings.
func directTCPEnv(t *testing.T) *env {
	t.Helper()
	e := fixture(t, &watchdogconf.Config{NebulaNet: "interdc"})
	root := t.TempDir()
	e.n.cfg.HostRoot = root
	testutil.WriteFile(t, filepath.Join(root, "etc/nebula/interdc/nebula-up.sh"),
		"#!/bin/bash\nexit 0\n")
	e.host.On("rule list pref 1499", "")
	return e
}

// An unanswerable `ip rule list pref 1499` aborts the cycle — rules
// must never be re-added on a blind read.
func TestDirectTCPRuleListFailureAborts(t *testing.T) {
	e := directTCPEnv(t)
	e.host.FailOn("rule list pref 1499", errCmdFail)
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
	if !e.host.Ran("rule add pref 1499 ipproto tcp dport 22 lookup main") {
		t.Fatalf("in-range port not enforced: %v", e.host.Cmds())
	}
	for _, c := range e.host.Cmds() {
		joined := strings.Join(c, " ")
		if strings.Contains(joined, "dport 0") ||
			strings.Contains(joined, "dport 70000") ||
			strings.Contains(joined, "dport -22") {
			t.Fatalf("invalid port reached ip: %v", c)
		}
	}
}

// A port whose rule already shows in the listing is not re-added;
// a missing sibling port still is (the fold-in keeps one listing).
func TestDirectTCPSkipsPresentRules(t *testing.T) {
	e := directTCPEnv(t)
	e.host.On("rule list pref 1499",
		"1499:\tfrom all ipproto tcp dport 22 lookup main\n")
	e.n.cfg.NebulaDirectTCPPorts = []int{22, 6443}
	e.n.checkNebulaDirectTCP(context.Background())
	if e.host.Ran("dport 22") {
		t.Fatal("already-present dport 22 rule re-added")
	}
	if !e.host.Ran("rule add pref 1499 ipproto tcp dport 6443 lookup main") {
		t.Fatalf("missing dport 6443 rule not added: %v", e.host.Cmds())
	}
}

// A failed rule add is logged and attributed (restore_error) — and
// the remaining ports still get their attempt.
func TestDirectTCPAddFailureLogged(t *testing.T) {
	e := directTCPEnv(t)
	e.host.FailOn("rule add pref 1499", errCmdFail)
	e.n.cfg.NebulaDirectTCPPorts = []int{22, 6443}
	e.n.checkNebulaDirectTCP(context.Background())
	if got := strings.Count(e.host.Joined(), "rule add pref 1499"); got != 2 {
		t.Fatalf("rule add attempts=%d want 2 (per port)", got)
	}
	if got := promtest.ToFloat64(e.n.cycles.WithLabelValues(
		checkNebTCP, "restore_error")); got != 2 {
		t.Fatalf("restore_error metric=%v want 2", got)
	}
	if !strings.Contains(logLines(t, e), "dport 22 failed") {
		t.Fatalf("missing add-failure log:\n%s", logLines(t, e))
	}
}

// --- nebula-health reason strings ---

// A bound socket with an unaddressed tun names the tun in the
// restart evidence — the operator sees WHICH leg died.
func TestNebulaNoTunAddrReason(t *testing.T) {
	e := nebulaEnv(t, nil)
	e.host.On("addr show dev neb1", "") // interface up, no inet addr
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
