// conntrack_test.go — conntrack-pressure hysteresis latch plus udp/53 and per-peer nebula flush triggers.

package nethealth

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// --- conntrack-guard (H2) ---

func TestConntrackPressureHysteresis(t *testing.T) {
	e := fixture(t, nil)
	testutil.WriteFile(t, e.ctmax, "1000\n")

	// 0.85 — between the bands: no latch without prior state.
	testutil.WriteFile(t, e.ctcount, "850\n")
	e.n.Cycle(context.Background())
	if stateExists(e, "conntrack-pressure") {
		t.Fatal("latch below enter ratio")
	}
	// 0.95 > 0.90 → latch arms.
	testutil.WriteFile(t, e.ctcount, "950\n")
	e.n.Cycle(context.Background())
	if !stateExists(e, "conntrack-pressure") {
		t.Fatal("latch missing above enter ratio")
	}
	// 0.85 — inside the hysteresis band: latch holds.
	testutil.WriteFile(t, e.ctcount, "850\n")
	e.n.Cycle(context.Background())
	if !stateExists(e, "conntrack-pressure") {
		t.Fatal("latch dropped inside hysteresis band")
	}
	// 0.75 < 0.80 → latch clears.
	testutil.WriteFile(t, e.ctcount, "750\n")
	e.n.Cycle(context.Background())
	if stateExists(e, "conntrack-pressure") {
		t.Fatal("latch kept below exit ratio")
	}
}

func TestConntrackMissingFilesDropsLatch(t *testing.T) {
	e := fixture(t, nil)
	testutil.WriteFile(t, filepath.Join(e.state, "state-conntrack-pressure"), "1\n")
	// Module unloaded → both /proc entries gone.
	if err := os.Remove(e.ctcount); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(e.ctmax); err != nil {
		t.Fatal(err)
	}
	e.n.Cycle(context.Background())
	if stateExists(e, "conntrack-pressure") {
		t.Fatal("stale conntrack-pressure latch kept with no table")
	}
}

// --- conntrack udp/53 flush triggers ---

func TestConntrackFlushOnDNSFallbackPin(t *testing.T) {
	e := fixture(t, &watchdogconf.Config{
		DNSFallback: []watchdogconf.DNSEntry{
			{Name: "api.test.internal", Port: "6443",
				Candidates: []string{"10.0.0.2"}},
		},
	})
	testutil.WriteFile(t, e.resv, "nameserver 10.1.1.1\n")
	e.tcpOK["10.0.0.2:6443"] = true
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background()) // second fail → pin + block update
	if !strings.Contains(testutil.ReadFile(t, e.hosts), "10.0.0.2 api.test.internal") {
		t.Fatal("dns-fallback pin missing")
	}
	if !e.host.Ran("conntrack -D -p udp --dport 53") {
		t.Fatalf("stale udp/53 conntrack not flushed, cmds=%v", e.host.Cmds())
	}
}

func TestConntrackFlushMissingBinaryOnlyLogs(t *testing.T) {
	e := fixture(t, &watchdogconf.Config{
		DNSFallback: []watchdogconf.DNSEntry{
			{Name: "api.test.internal", Port: "6443",
				Candidates: []string{"10.0.0.2"}},
		},
	})
	testutil.WriteFile(t, e.resv, "nameserver 10.1.1.1\n")
	e.tcpOK["10.0.0.2:6443"] = true
	e.host.FailOn("conntrack", errCmdFail) // binary absent
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background())
	// The pin still lands — a missing conntrack binary must never
	// fail the cycle.
	if !strings.Contains(testutil.ReadFile(t, e.hosts), "10.0.0.2 api.test.internal") {
		t.Fatal("dns-fallback pin missing after conntrack flush failure")
	}
	if !strings.Contains(logLines(t, e), "flush skipped") {
		t.Fatalf("missing flush-skip log:\n%s", logLines(t, e))
	}
}

func TestConntrackFlushOnCoreDNSRestart(t *testing.T) {
	e := fixture(t, nil)
	testutil.WriteFile(t, e.resv, "nameserver 127.0.0.1\nnameserver 10.1.1.1\n")
	e.sd.On("LoadState --value coredns.service", "loaded\n")
	e.sd.On("is-active coredns.service", "inactive\n")
	e.sd.On("restart coredns.service", "")
	e.n.Cycle(context.Background())
	if !e.sd.Ran("restart coredns.service") {
		t.Fatal("coredns stub not restarted")
	}
	if !e.host.Ran("conntrack -D -p udp --dport 53") {
		t.Fatalf("stale udp/53 conntrack not flushed, cmds=%v", e.host.Cmds())
	}
}

func TestConntrackFlushOnNebulaRestart(t *testing.T) {
	e := nebulaEnv(t, nil)
	e.sd.On("restart nebula@interdc", "")
	testutil.WriteFile(t, e.procudp, "  sl  local_address rem_address   st\n"+
		"  1: 0100007F:0050 00000000:0000 07\n") // :B266 (45670) gone
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background())
	if !e.sd.Ran("restart nebula@interdc") {
		t.Fatal("nebula not restarted")
	}
	if !e.host.Ran("conntrack -D -p udp --dport 53") {
		t.Fatalf("stale udp/53 conntrack not flushed, cmds=%v", e.host.Cmds())
	}
}

// --- B3: per-peer nebula udp/<port> conntrack flush ---

// countCmds returns how many recorded host commands contain sub.
func countCmds(e *env, sub string) int {
	n := 0
	for _, c := range e.host.Cmds() {
		if strings.Contains(strings.Join(c, " "), sub) {
			n++
		}
	}
	return n
}

func TestNebulaIsolatedFlushesPeerConntrack(t *testing.T) {
	e := nebulaEnv(t, nil)
	// Every underlay probe target dead → dataplane isolated. Only the
	// peer underlay IPs (OVERLAY_PROBE_TARGETS) are flushed — marker
	// IPs are overlay addresses conntrack never records.
	for _, ip := range []string{"10.8.0.1", "10.8.0.2", "10.8.1.1", "10.8.1.2"} {
		e.pingOK[ip+"|false"] = false
	}
	e.n.Cycle(context.Background())
	if !stateExists(e, "nebula-isolated") {
		t.Fatal("isolated latch missing on dataplane dead")
	}
	for _, ip := range []string{"10.8.0.1", "10.8.0.2"} {
		if !e.host.Ran("conntrack -D -p udp --dport 45670 -d " + ip) {
			t.Fatalf("no per-peer conntrack flush for %s, cmds=%v", ip, e.host.Cmds())
		}
	}
	if e.host.Ran("-d 10.8.1.1") || e.host.Ran("-d 10.8.1.2") {
		t.Fatalf("marker (overlay) IPs flushed — only underlay peers allowed, cmds=%v", e.host.Cmds())
	}
	// Edge-only: a second cycle still isolated must NOT re-flush.
	e.host.ClearLog()
	e.n.Cycle(context.Background())
	if got := countCmds(e, "conntrack -D -p udp --dport 45670 -d"); got != 0 {
		t.Fatalf("peer flush re-ran while already isolated (%d flushes), cmds=%v", got, e.host.Cmds())
	}
}

func TestEgressSwitchFlushesPeerConntrack(t *testing.T) {
	e := overlayEnv(t, nil)
	e.host.On("rule list pref 1500", "")
	// Underlay dead → committed state flips direct -> relay; the
	// peer's udp/<nebula-port> conntrack gets flushed.
	e.tcpOK["8.8.8.8:53"] = false
	e.pingOK["8.8.8.8|true"] = false
	e.n.Cycle(context.Background())
	if got := hostutil.ReadTrimmed(filepath.Join(e.state, "egress-state-8.8.8.8")); got != "relay" {
		t.Fatalf("committed=%q want relay", got)
	}
	if !e.host.Ran("conntrack -D -p udp --dport 45670 -d 8.8.8.8") {
		t.Fatalf("no per-peer conntrack flush on egress switch, cmds=%v", e.host.Cmds())
	}
}

func TestEgressRecoveryFlushesPeerConntrack(t *testing.T) {
	e := overlayEnv(t, nil)
	e.host.On("rule list pref 1500", "1500:\tfrom all to 8.8.8.8 lookup 100\n")
	testutil.WriteFile(t, filepath.Join(e.state, "egress-state-8.8.8.8"), "relay\n")
	e.pingOK["8.8.8.8|true"] = true // underlay back
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background()) // 2nd fresh probe → flip to direct
	if got := hostutil.ReadTrimmed(filepath.Join(e.state, "egress-state-8.8.8.8")); got != "direct" {
		t.Fatalf("committed=%q want direct", got)
	}
	if !e.host.Ran("conntrack -D -p udp --dport 45670 -d 8.8.8.8") {
		t.Fatalf("no per-peer conntrack flush on egress recovery, cmds=%v", e.host.Cmds())
	}
}

func TestPeerConntrackFlushHonoursNebulaPort(t *testing.T) {
	e := overlayEnv(t, func(wd *watchdogconf.Config) {
		wd.NebulaPort = 45671
	})
	e.host.On("rule list pref 1500", "")
	e.tcpOK["8.8.8.8:53"] = false
	e.pingOK["8.8.8.8|true"] = false
	e.n.Cycle(context.Background())
	if !e.host.Ran("conntrack -D -p udp --dport 45671 -d 8.8.8.8") {
		t.Fatalf("flush used wrong port, cmds=%v", e.host.Cmds())
	}
}

func TestPeerConntrackFlushBestEffort(t *testing.T) {
	e := overlayEnv(t, nil)
	e.host.On("rule list pref 1500", "")
	e.tcpOK["8.8.8.8:53"] = false
	e.pingOK["8.8.8.8|true"] = false
	e.host.FailOn("conntrack", errCmdFail) // binary absent → skip, never fail
	e.n.Cycle(context.Background())
	// The relay commit still lands — a missing conntrack binary must
	// never block the path switch.
	if got := hostutil.ReadTrimmed(filepath.Join(e.state, "egress-state-8.8.8.8")); got != "relay" {
		t.Fatalf("committed=%q want relay", got)
	}
	if !strings.Contains(logLines(t, e), "flush 8.8.8.8 skipped") {
		t.Fatalf("missing flush-skip log:\n%s", logLines(t, e))
	}
}
