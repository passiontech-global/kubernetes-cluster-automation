// nebula_health_test.go — nebula-health socket/dataplane probes and isolated/degraded/slowpath/siteedge latches.

package nethealth

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
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
