// conntrack_test.go — conntrack-pressure hysteresis latch plus udp/53 and per-peer nebula flush triggers.

package nethealth

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// --- conntrack-port-pressure: insert_failed/drop spike → whole-UDP flush ---

// ranExactCmd reports whether the fake executed argv joined EXACTLY
// as cmd — "conntrack -D -p udp" must not match the longer
// "--dport 53" / peer flushes it prefixes.
func ranExactCmd(e *env, cmd string) bool {
	for _, c := range e.host.Cmds() {
		if strings.Join(c, " ") == cmd {
			return true
		}
	}
	return false
}

// conntrackStatBody renders a /proc/net/stat/nf_conntrack fixture
// with the given hex values in the insert_failed / drop /
// early_drop columns.
func conntrackStatBody(insertFailed, drop, earlyDrop string) string {
	return "  entries  searched found insert insert_failed drop early_drop\n" +
		"00000ed4  00000000 00000000 00000000 " +
		insertFailed + " " + drop + " " + earlyDrop + "\n"
}

func TestConntrackDropSpikeFlushesUDP(t *testing.T) {
	e := fixture(t, nil)
	e.n.cfg.ConntrackStatFile = filepath.Join(t.TempDir(), "nf_conntrack")
	testutil.WriteFile(t, e.n.cfg.ConntrackStatFile,
		conntrackStatBody("00000064", "0000000a", "00000000"))
	e.n.Cycle(context.Background()) // baseline read — never flushes
	if ranExactCmd(e, "conntrack -D -p udp") {
		t.Fatal("UDP flush fired on the baseline read")
	}
	// +0x46 = 70 new refuses across the summed columns → spike.
	testutil.WriteFile(t, e.n.cfg.ConntrackStatFile,
		conntrackStatBody("000000aa", "00000014", "00000000"))
	e.n.Cycle(context.Background())
	if !ranExactCmd(e, "conntrack -D -p udp") {
		t.Fatalf("UDP flush did not fire on a +70 spike, cmds=%v", e.host.Cmds())
	}
	e.host.ClearLog()
	// Same counters again — a 0-delta cycle must not re-flush.
	e.n.Cycle(context.Background())
	if ranExactCmd(e, "conntrack -D -p udp") {
		t.Fatal("UDP flush refired without a counter delta")
	}
}

func TestConntrackDropUnderThresholdNoFlush(t *testing.T) {
	e := fixture(t, nil)
	e.n.cfg.ConntrackStatFile = filepath.Join(t.TempDir(), "nf_conntrack")
	testutil.WriteFile(t, e.n.cfg.ConntrackStatFile,
		conntrackStatBody("0000000a", "00000000", "00000000"))
	e.n.Cycle(context.Background())
	// +0x32 = 50 — the threshold is strictly "> 50", so exactly 50
	// must not flush.
	testutil.WriteFile(t, e.n.cfg.ConntrackStatFile,
		conntrackStatBody("0000003c", "00000000", "00000000"))
	e.n.Cycle(context.Background())
	if ranExactCmd(e, "conntrack -D -p udp") {
		t.Fatal("UDP flush fired at exactly the 50 threshold")
	}
}

func TestConntrackDropSpikeMissingFileIdles(t *testing.T) {
	e := fixture(t, nil)
	// Module absent → no stat file: the detector idles, the
	// baseline resets so a re-appearing file can't false-spike.
	e.n.cfg.ConntrackStatFile = filepath.Join(t.TempDir(), "missing")
	e.n.Cycle(context.Background())
	if ranExactCmd(e, "conntrack -D -p udp") {
		t.Fatal("UDP flush fired without a stat file")
	}
	testutil.WriteFile(t, e.n.cfg.ConntrackStatFile,
		conntrackStatBody("00000100", "00000100", "00000100"))
	e.n.Cycle(context.Background()) // re-seeds the baseline only
	if ranExactCmd(e, "conntrack -D -p udp") {
		t.Fatal("UDP flush fired on a re-appearing baseline read")
	}
}

// The udp flush is a blunt instrument (live UDP flows re-track,
// WireGuard re-handshakes) — two triggers inside the cooldown must
// collapse into one conntrack -D, and the budget re-arms after it.
func TestConntrackFlushRateLimited(t *testing.T) {
	e := fixture(t, &watchdogconf.Config{
		DNSFallback: []watchdogconf.DNSEntry{
			{Name: "api.test.internal", Port: "6443",
				Candidates: []string{"10.0.0.2"}},
		},
	})
	testutil.WriteFile(t, e.resv, "nameserver 10.1.1.1\n")
	e.tcpOK["10.0.0.2:6443"] = true
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background()) // pin + first flush
	if !e.host.Ran("conntrack -D -p udp --dport 53") {
		t.Fatal("first flush missing")
	}
	n := strings.Count(e.host.Joined(), "--dport 53")
	// A second trigger inside the cooldown must not re-exec.
	e.n.flushStaleUDPConntrack(context.Background(), checkDNSFB)
	if got := strings.Count(e.host.Joined(), "--dport 53"); got != n {
		t.Fatalf("flush re-ran inside cooldown (%d → %d)", n, got)
	}
	// Past the budget a fresh flush is allowed (the fixture clock
	// closure reads e.now live).
	e.now = e.now.Add(conntrackFlushCooldown + time.Minute)
	e.n.flushStaleUDPConntrack(context.Background(), checkDNSFB)
	if got := strings.Count(e.host.Joined(), "--dport 53"); got != n+1 {
		t.Fatalf("flush not re-armed past cooldown (%d → %d)", n, got)
	}
}

// Unparseable count/max must abort the cycle WITHOUT touching the
// latch — a garbled sysfs read must not clear a real pressure
// incident, and a junk value must not arm one either.
func TestConntrackUnparseableValuesAbort(t *testing.T) {
	e := fixture(t, nil)
	testutil.WriteFile(t, e.ctcount, "not-a-number\n")
	testutil.WriteFile(t, e.ctmax, "262144\n")
	e.n.Cycle(context.Background())
	if stateExists(e, "conntrack-pressure") {
		t.Fatal("latch armed on unparseable count")
	}
	if !strings.Contains(logLines(t, e), "unparseable conntrack values") {
		t.Fatalf("missing parse-abort suspect line:\n%s", logLines(t, e))
	}
	// max <= 0 is equally unusable.
	testutil.WriteFile(t, e.ctcount, "100\n")
	testutil.WriteFile(t, e.ctmax, "0\n")
	e.n.Cycle(context.Background())
	if stateExists(e, "conntrack-pressure") {
		t.Fatal("latch armed on zero max")
	}
}

// conntrackStatSum unit contract: unreadable file and header
// without the wanted columns both read as "detector idles"; a
// malformed CPU row is skipped without poisoning the sum.
func TestConntrackStatSumParsing(t *testing.T) {
	if _, ok := conntrackStatSum(filepath.Join(t.TempDir(), "absent"),
		"insert_failed"); ok {
		t.Fatal("missing file must not parse")
	}
	dir := t.TempDir()
	noCols := filepath.Join(dir, "nocols")
	testutil.WriteFile(t, noCols, "entries searched found\n1 2 3\n")
	if _, ok := conntrackStatSum(noCols, "insert_failed"); ok {
		t.Fatal("header without wanted columns must not parse")
	}
	// Header-only file: not enough lines for a per-CPU table.
	testutil.WriteFile(t, noCols, "entries insert_failed\n")
	if _, ok := conntrackStatSum(noCols, "insert_failed"); ok {
		t.Fatal("header-only file must not parse")
	}
	// Row 2 has the wrong field count → skipped; row 3 counts.
	mixed := filepath.Join(dir, "mixed")
	testutil.WriteFile(t, mixed,
		"entries insert_failed drop\n"+
			"aa 00000010\n"+ // malformed — dropped
			"aa 00000010 00000005\n"+ // 16 + 5
			"aa 00000004 00000000\n") // + 4 = 25
	sum, ok := conntrackStatSum(mixed, "insert_failed", "drop")
	if !ok || sum != 25 {
		t.Fatalf("sum=%d ok=%v want 25 true", sum, ok)
	}
}

// The whole-table UDP flush honours the shared last-conntrack-flush
// cooldown: a spike landing inside an earlier flush's window is a
// no-op, and a failed `conntrack -D` is logged and absorbed.
func TestConntrackFlushAllCooldownAndFailure(t *testing.T) {
	e := fixture(t, nil)
	ctx := context.Background()
	// First call spends the 15m budget and runs the delete.
	e.n.flushStaleUDPConntrackAll(ctx, checkCT)
	if !ranExactCmd(e, "conntrack -D -p udp") {
		t.Fatalf("flush-all did not exec conntrack: %v", e.host.Cmds())
	}
	// Inside the cooldown: no second exec.
	e.host.ClearLog()
	e.n.flushStaleUDPConntrackAll(ctx, checkCT)
	if ranExactCmd(e, "conntrack -D -p udp") {
		t.Fatal("flush-all refired inside the cooldown")
	}
	// Past the cooldown but the binary fails: logged, no crash, no
	// metric — and the next window can retry.
	e.now = e.now.Add(conntrackFlushCooldown + time.Minute)
	e.host.FailOn("conntrack -D -p udp", errCmdFail)
	e.host.ClearLog()
	e.n.flushStaleUDPConntrackAll(ctx, checkCT)
	if !ranExactCmd(e, "conntrack -D -p udp") {
		t.Fatal("flush-all not attempted past the cooldown")
	}
	if !strings.Contains(logLines(t, e), "conntrack udp flush skipped") {
		t.Fatalf("missing flush-failure log:\n%s", logLines(t, e))
	}
}

// The per-peer flush defaults to the shared 45670 nebula port when
// the conf carries none, and skips blank/duplicate peers instead of
// fork-storming identical deletes. The conf is un-normalized
// (post-New) so the NebulaPort fallback actually runs.
func TestPeerConntrackFlushDefaultsAndDedup(t *testing.T) {
	e := fixture(t, nil)
	e.n.cfg.Watchdog = &watchdogconf.Config{} // NebulaPort unset
	e.n.flushPeerNebulaConntrack(context.Background(), checkCT,
		"", "10.0.0.2", " 10.0.0.2 ", "10.0.0.2")
	// One peer, two tuple directions, default port.
	delFor := func(sel string) int {
		n := 0
		for _, c := range e.host.Cmds() {
			joined := strings.Join(c, " ")
			if strings.Contains(joined, "--dport 45670") &&
				strings.Contains(joined, sel) {
				n++
			}
		}
		return n
	}
	if delFor("-d 10.0.0.2") != 1 || delFor("-s 10.0.0.2") != 1 {
		t.Fatalf("expected exactly one -d and one -s delete for 10.0.0.2, cmds=%v",
			e.host.Cmds())
	}
	if strings.Contains(e.host.Joined(), "--dport 53") {
		t.Fatal("peer flush must not use the :53 tuple")
	}
}

// --- W21-G7: surgical UNREPLIED udp flush ---

// unrepliedFlushCmds is the exact argv pair flushUnrepliedUDPConntrack
// must exec — :53 scoped first, then every unreplied UDP flow; the
// -u UNREPLIED state filter is what spares ASSURED entries
// (Nebula/WireGuard tunnels, live DNS exchanges).
var unrepliedFlushCmds = []string{
	"conntrack -D -p udp --dport 53 -u UNREPLIED",
	"conntrack -D -p udp -u UNREPLIED",
}

func ranAllExactCmds(e *env, cmds []string) bool {
	ran := map[string]bool{}
	for _, c := range e.host.Cmds() {
		ran[strings.Join(c, " ")] = true
	}
	for _, want := range cmds {
		if !ran[want] {
			return false
		}
	}
	return true
}

// insert_failed alone jumping >5 in one cycle fires the surgical
// UNREPLIED flush even though the combined spike stays under the
// blunt all-UDP threshold — refused inserts are the earliest
// pressure signal.
func TestConntrackInsertSpikeFlushesUnreplied(t *testing.T) {
	e := fixture(t, nil)
	e.n.cfg.ConntrackStatFile = filepath.Join(t.TempDir(), "nf_conntrack")
	testutil.WriteFile(t, e.n.cfg.ConntrackStatFile,
		conntrackStatBody("0000000a", "00000000", "00000000"))
	e.n.Cycle(context.Background()) // baseline read — never flushes
	if ranAllExactCmds(e, unrepliedFlushCmds) {
		t.Fatal("unreplied flush fired on the baseline read")
	}
	// insert_failed +7 (>5) while drop/early_drop stay flat — the
	// combined delta is also 7, far under the 50 blunt threshold.
	testutil.WriteFile(t, e.n.cfg.ConntrackStatFile,
		conntrackStatBody("00000011", "00000000", "00000000"))
	e.n.Cycle(context.Background())
	if !ranAllExactCmds(e, unrepliedFlushCmds) {
		t.Fatalf("unreplied flush did not fire on a +7 insert_failed spike, cmds=%v",
			e.host.Cmds())
	}
	if ranExactCmd(e, "conntrack -D -p udp") {
		t.Fatal("blunt all-UDP flush fired under its own threshold")
	}
	// A second spike inside the 15m budget must not re-exec.
	e.host.ClearLog()
	testutil.WriteFile(t, e.n.cfg.ConntrackStatFile,
		conntrackStatBody("00000030", "00000000", "00000000"))
	e.n.Cycle(context.Background())
	if ranAllExactCmds(e, unrepliedFlushCmds) {
		t.Fatal("unreplied flush refired inside the cooldown")
	}
}

// An insert_failed delta at or under 5 is normal churn — no flush.
func TestConntrackInsertSpikeUnderThreshold(t *testing.T) {
	e := fixture(t, nil)
	e.n.cfg.ConntrackStatFile = filepath.Join(t.TempDir(), "nf_conntrack")
	testutil.WriteFile(t, e.n.cfg.ConntrackStatFile,
		conntrackStatBody("0000000a", "00000000", "00000000"))
	e.n.Cycle(context.Background())
	testutil.WriteFile(t, e.n.cfg.ConntrackStatFile,
		conntrackStatBody("0000000f", "00000000", "00000000")) // +5 — not >5
	e.n.Cycle(context.Background())
	if ranAllExactCmds(e, unrepliedFlushCmds) {
		t.Fatal("unreplied flush fired at exactly the +5 threshold")
	}
}

// Table usage past the 90% enter ratio flushes unreplied UDP entries
// immediately — before any insert_failed evidence accumulates.
func TestConntrackRatioFlushesUnreplied(t *testing.T) {
	e := fixture(t, nil)
	testutil.WriteFile(t, e.ctmax, "1000\n")
	testutil.WriteFile(t, e.ctcount, "950\n") // 0.95 > 0.90
	e.n.Cycle(context.Background())
	if !stateExists(e, "conntrack-pressure") {
		t.Fatal("pressure latch missing above enter ratio")
	}
	if !ranAllExactCmds(e, unrepliedFlushCmds) {
		t.Fatalf("unreplied flush did not fire past the enter ratio, cmds=%v",
			e.host.Cmds())
	}
	// Sustained pressure inside the cooldown must not re-exec.
	e.host.ClearLog()
	e.n.Cycle(context.Background())
	if ranAllExactCmds(e, unrepliedFlushCmds) {
		t.Fatal("unreplied flush refired inside the cooldown")
	}
}

// The surgical flush is best-effort like its blunt siblings: a
// missing conntrack binary logs and moves on, and each of the two
// deletes is independent (a :53 failure must not skip the wildcard).
func TestFlushUnrepliedUDPConntrackBestEffort(t *testing.T) {
	e := fixture(t, nil)
	e.host.FailOn("conntrack", errCmdFail)
	e.n.flushUnrepliedUDPConntrack(context.Background(), checkCT)
	if !strings.Contains(logLines(t, e), "unreplied udp flush skipped") {
		t.Fatalf("missing flush-skip log:\n%s", logLines(t, e))
	}
}
