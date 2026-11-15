// neighbor_test.go — neighbor-table healer coverage: the ARP/NDISC
// entry counts, the gc_thresh3→gc_thresh2→gc_thresh1 write order,
// ceiling caps, the 30m rate budget, the FAILED-entry flush and the
// kmsg overflow trigger.
package kernelfail

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// neighFixture points the engine's neighbor seams at fixture files
// under the kfixture ProcRoot and returns the layout.
type neighFixture struct {
	v4dir   string
	v6dir   string
	arp     string
	ndisc   string
	argvLog [][]string
}

func seedNeighborFixture(t *testing.T, f *fixture) *neighFixture {
	t.Helper()
	nf := &neighFixture{
		v4dir: filepath.Join(f.deps.ProcRoot, "sys", "net", "ipv4", "neigh", "default"),
		v6dir: filepath.Join(f.deps.ProcRoot, "sys", "net", "ipv6", "neigh", "default"),
		arp:   filepath.Join(f.deps.ProcRoot, "1", "net", "arp"),
		ndisc: filepath.Join(f.deps.ProcRoot, "1", "net", "stat", "ndisc_cache"),
	}
	for _, d := range []string{nf.v4dir, nf.v6dir,
		filepath.Dir(nf.arp), filepath.Dir(nf.ndisc)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Kernel-default triplet on both families.
	for _, dir := range []string{nf.v4dir, nf.v6dir} {
		for i, knob := range []string{"gc_thresh1", "gc_thresh2", "gc_thresh3"} {
			vals := []string{"128", "512", "1024"}
			writePrefailFile(t, filepath.Join(dir, knob), vals[i]+"\n")
		}
	}
	// ARP table: header + a handful of entries (well under 80% of
	// gc_thresh3=1024).
	var b strings.Builder
	b.WriteString("IP address       HW type     Flags       HW address            Mask     Device\n")
	for i := 0; i < 10; i++ {
		fmt.Fprintf(&b, "10.0.0.%d        0x1         0x2         00:11:22:33:44:%02x     *        eth0\n", i, i)
	}
	writePrefailFile(t, nf.arp, b.String())
	// ndisc_cache stats: header + one row, entries=0x10.
	writePrefailFile(t, nf.ndisc,
		"entries  allocs   destroys hash_grows lookups  hits     res_failed rcv_probes_mcast rcv_probes_ucast periodic_gc_runs forced_gc_runs unresolved_discards table_fulls\n"+
			"00000010 00000020 00000001 00000000   00000000 00000000 00000000   00000000         00000000         00000010         00000000       00000000            00000000\n")
	// Capture host commands instead of exec'ing ip/flush.
	f.r.deps.RunHostCmd = func(_ context.Context, argv ...string) (string, error) {
		nf.argvLog = append(nf.argvLog, append([]string(nil), argv...))
		return "", nil
	}
	return nf
}

func neighValue(t *testing.T, dir, knob string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, knob))
	if err != nil {
		t.Fatalf("read %s/%s: %v", dir, knob, err)
	}
	return strings.TrimSpace(string(data))
}

func TestNeighborBelowThresholdNoBump(t *testing.T) {
	f := kfixture(t)
	nf := seedNeighborFixture(t, f)
	f.r.updateNeighborTable(context.Background())
	if len(nf.argvLog) != 0 {
		t.Fatalf("flush ran below threshold: %v", nf.argvLog)
	}
	for _, knob := range []string{"gc_thresh1", "gc_thresh2", "gc_thresh3"} {
		if got := neighValue(t, nf.v4dir, knob); got != map[string]string{
			"gc_thresh1": "128", "gc_thresh2": "512", "gc_thresh3": "1024"}[knob] {
			t.Fatalf("%s=%s — bump ran below threshold", knob, got)
		}
	}
}

func TestNeighborIPv4FillBumpsAndFlushes(t *testing.T) {
	f := kfixture(t)
	nf := seedNeighborFixture(t, f)
	// 900 entries >= 80% of gc_thresh3=1024.
	var b strings.Builder
	b.WriteString("IP address       HW type     Flags       HW address            Mask     Device\n")
	for i := 0; i < 900; i++ {
		fmt.Fprintf(&b, "10.1.%d.%d       0x1         0x2         00:11:22:33:44:%02x     *        eth0\n", i/256, i%256, i%256)
	}
	writePrefailFile(t, nf.arp, b.String())
	f.r.updateNeighborTable(context.Background())
	// Doubled triplet (128,512,1024)→(256,1024,2048), ceilings far away.
	for knob, want := range map[string]string{
		"gc_thresh1": "256", "gc_thresh2": "1024", "gc_thresh3": "2048"} {
		if got := neighValue(t, nf.v4dir, knob); got != want {
			t.Fatalf("ipv4 %s=%s want %s", knob, got, want)
		}
	}
	// IPv6 untouched (16 entries << 80% of 1024).
	if got := neighValue(t, nf.v6dir, "gc_thresh3"); got != "1024" {
		t.Fatalf("ipv6 gc_thresh3=%s — wrong family bumped", got)
	}
	// The FAILED-entry flush ran for ipv4 only.
	if len(nf.argvLog) != 1 ||
		strings.Join(nf.argvLog[0], " ") != "ip -4 neigh flush nud failed" {
		t.Fatalf("flush argv = %v", nf.argvLog)
	}
}

func TestNeighborCeilingCapsBump(t *testing.T) {
	f := kfixture(t)
	nf := seedNeighborFixture(t, f)
	// Triplet already at the default ceilings.
	for i, knob := range []string{"gc_thresh1", "gc_thresh2", "gc_thresh3"} {
		vals := []string{"1024", "4096", "8192"}
		writePrefailFile(t, filepath.Join(nf.v4dir, knob), vals[i]+"\n")
	}
	// Fill: 7000 >= 80% of 8192.
	var b strings.Builder
	b.WriteString("IP address       HW type     Flags       HW address            Mask     Device\n")
	for i := 0; i < 7000; i++ {
		fmt.Fprintf(&b, "10.2.%d.%d       0x1         0x2         00:11:22:33:44:%02x     *        eth0\n", i/256, i%256, i%256)
	}
	writePrefailFile(t, nf.arp, b.String())
	f.r.updateNeighborTable(context.Background())
	// At ceiling → values unchanged but the FAILED flush still ran.
	for knob, want := range map[string]string{
		"gc_thresh1": "1024", "gc_thresh2": "4096", "gc_thresh3": "8192"} {
		if got := neighValue(t, nf.v4dir, knob); got != want {
			t.Fatalf("ceiling %s=%s want %s", knob, got, want)
		}
	}
	if len(nf.argvLog) != 1 {
		t.Fatalf("flush at ceiling argv = %v", nf.argvLog)
	}
}

func TestNeighborCooldownBlocksSecondBump(t *testing.T) {
	f := kfixture(t)
	nf := seedNeighborFixture(t, f)
	var b strings.Builder
	b.WriteString("IP address       HW type     Flags       HW address            Mask     Device\n")
	for i := 0; i < 900; i++ {
		fmt.Fprintf(&b, "10.3.%d.%d       0x1         0x2         00:11:22:33:44:%02x     *        eth0\n", i/256, i%256, i%256)
	}
	writePrefailFile(t, nf.arp, b.String())
	f.r.updateNeighborTable(context.Background())
	if got := neighValue(t, nf.v4dir, "gc_thresh3"); got != "2048" {
		t.Fatalf("first bump gc_thresh3=%s", got)
	}
	// Still ≥80% of the NEW thresh3? 900/2048=44% — refill to force
	// a second trigger, then verify the 30m budget suppresses it.
	for i := 0; i < 1700; i++ {
		fmt.Fprintf(&b, "10.4.%d.%d       0x1         0x2         00:11:22:33:44:%02x     *        eth0\n", i/256, i%256, i%256)
	}
	writePrefailFile(t, nf.arp, b.String())
	f.r.updateNeighborTable(context.Background())
	if got := neighValue(t, nf.v4dir, "gc_thresh3"); got != "2048" {
		t.Fatalf("cooldown bypassed: gc_thresh3=%s", got)
	}
	if len(nf.argvLog) != 1 {
		t.Fatalf("second flush inside cooldown: %v", nf.argvLog)
	}
	// 31m later the budget reopens.
	now := time.Now()
	f.deps.Clock.Set(func() time.Time { return now })
	f.r.updateNeighborTable(context.Background()) // stamps budget at `now`
	now = now.Add(31 * time.Minute)
	f.r.updateNeighborTable(context.Background())
	if got := neighValue(t, nf.v4dir, "gc_thresh3"); got != "4096" {
		t.Fatalf("post-cooldown bump gc_thresh3=%s want 4096", got)
	}
}

func TestNeighborOverflowKmsgTriggersBump(t *testing.T) {
	f := kfixture(t)
	nf := seedNeighborFixture(t, f)
	// Below fill threshold — only the kmsg record should trigger.
	f.r.noteNeighborOverflow("neighbour: arp_cache: neighbor table overflow")
	f.r.updateNeighborTable(context.Background())
	if got := neighValue(t, nf.v4dir, "gc_thresh3"); got != "2048" {
		t.Fatalf("overflow record did not bump ipv4: gc_thresh3=%s", got)
	}
	if got := neighValue(t, nf.v6dir, "gc_thresh3"); got != "1024" {
		t.Fatalf("arp overflow bumped ipv6: gc_thresh3=%s", got)
	}
	// ndisc overflow → ipv6 family.
	f2 := kfixture(t)
	nf2 := seedNeighborFixture(t, f2)
	f2.r.noteNeighborOverflow("neighbour: ndisc_cache: neighbor table overflow")
	f2.r.updateNeighborTable(context.Background())
	if got := neighValue(t, nf2.v6dir, "gc_thresh3"); got != "2048" {
		t.Fatalf("ndisc overflow did not bump ipv6: gc_thresh3=%s", got)
	}
	if len(nf2.argvLog) != 1 ||
		strings.Join(nf2.argvLog[0], " ") != "ip -6 neigh flush nud failed" {
		t.Fatalf("ipv6 flush argv = %v", nf2.argvLog)
	}
}

// The pending-TTL regression: an overflow kmsg logged MID-cooldown
// must not ratchet gc_thresh again once the 30m budget reopens — by
// then the table has had half an hour to recover via GC and the
// evidence is stale. Without the timestamp the pending flag stayed
// armed forever and every cooldown expiry triggered another double.
func TestNeighborPendingOverflowExpires(t *testing.T) {
	f := kfixture(t)
	nf := seedNeighborFixture(t, f)
	now := time.Now()
	f.deps.Clock.Set(func() time.Time { return now })

	// T0: fill-triggered bump fills the 30m cooldown budget.
	var b strings.Builder
	b.WriteString("IP address       HW type     Flags       HW address            Mask     Device\n")
	for i := 0; i < 900; i++ {
		fmt.Fprintf(&b, "10.1.%d.%d       0x1         0x2         00:11:22:33:44:%02x     *        eth0\n", i/256, i%256, i%256)
	}
	writePrefailFile(t, nf.arp, b.String())
	f.r.updateNeighborTable(context.Background())
	if got := neighValue(t, nf.v4dir, "gc_thresh3"); got != "2048" {
		t.Fatalf("fill bump failed: gc_thresh3=%s", got)
	}

	// The table cools back under the fill ratio.
	var c strings.Builder
	c.WriteString("IP address       HW type     Flags       HW address            Mask     Device\n")
	for i := 0; i < 10; i++ {
		fmt.Fprintf(&c, "10.0.0.%d        0x1         0x2         00:11:22:33:44:%02x     *        eth0\n", i, i)
	}
	writePrefailFile(t, nf.arp, c.String())

	// T0+5m: a fresh overflow record lands — pending, but the bump
	// budget is still cooling down so nothing fires yet.
	now = now.Add(5 * time.Minute)
	f.r.noteNeighborOverflow("neighbour: arp_cache: neighbor table overflow")
	f.r.updateNeighborTable(context.Background())
	if got := neighValue(t, nf.v4dir, "gc_thresh3"); got != "2048" {
		t.Fatalf("cooldown bypassed: gc_thresh3=%s", got)
	}

	// T0+31m: cooldown expired AND the pending evidence is 26m old —
	// past neighPendingTTL — so the stale overflow must NOT bump.
	now = now.Add(26 * time.Minute)
	f.r.updateNeighborTable(context.Background())
	if got := neighValue(t, nf.v4dir, "gc_thresh3"); got != "2048" {
		t.Fatalf("stale pending overflow bumped after cooldown: gc_thresh3=%s", got)
	}
	if len(nf.argvLog) != 1 {
		t.Fatalf("extra flush ran on expired evidence: %v", nf.argvLog)
	}
}

func TestNeighborTripletOrderingAndCaps(t *testing.T) {
	// Kernel defaults double cleanly under default ceilings.
	got := neighBumpTriplet([3]uint64{128, 512, 1024},
		[3]int{DefaultNeighGCThresh1Ceiling, DefaultNeighGCThresh2Ceiling,
			DefaultNeighGCThresh3Ceiling})
	if got != [3]uint64{256, 1024, 2048} {
		t.Fatalf("triplet = %v", got)
	}
	// Ceilings clamp each knob independently.
	got = neighBumpTriplet([3]uint64{900, 4000, 8000},
		[3]int{1024, 4096, 8192})
	if got != [3]uint64{1024, 4096, 8192} {
		t.Fatalf("ceiling triplet = %v", got)
	}
	// An odd current triplet can never produce thresh1 > thresh2.
	got = neighBumpTriplet([3]uint64{2000, 2100, 2200},
		[3]int{1024, 4096, 8192})
	if got[0] > got[1] || got[1] > got[2] {
		t.Fatalf("ordering violated: %v", got)
	}
	// At ceiling nothing changes (flush-only path).
	got = neighBumpTriplet([3]uint64{1024, 4096, 8192},
		[3]int{1024, 4096, 8192})
	if got != [3]uint64{1024, 4096, 8192} {
		t.Fatalf("at-ceiling triplet moved: %v", got)
	}
}

func TestNeighborInconclusiveSkips(t *testing.T) {
	f := kfixture(t)
	nf := seedNeighborFixture(t, f)
	// Remove the ARP table — unreadable proc view must not bump.
	if err := os.Remove(nf.arp); err != nil {
		t.Fatal(err)
	}
	f.r.noteNeighborOverflow("neighbour: arp_cache: neighbor table overflow")
	f.r.updateNeighborTable(context.Background())
	if got := neighValue(t, nf.v4dir, "gc_thresh3"); got != "1024" {
		t.Fatalf("unreadable table bumped anyway: gc_thresh3=%s", got)
	}
	// The pending flag survives for the next readable tick.
	writePrefailFile(t, nf.arp,
		"IP address       HW type     Flags       HW address            Mask     Device\n")
	f.r.updateNeighborTable(context.Background())
	if got := neighValue(t, nf.v4dir, "gc_thresh3"); got != "2048" {
		t.Fatalf("pending overflow lost: gc_thresh3=%s", got)
	}
}

func TestNdiscCacheEntriesParse(t *testing.T) {
	// Two rows disagree — max wins.
	p := filepath.Join(t.TempDir(), "ndisc_cache")
	writePrefailFile(t, p,
		"entries  allocs   destroys\n"+
			"0000000a 00000001 00000000\n"+
			"00000063 00000002 00000000\n")
	got, ok := ndiscCacheEntries(p)
	if !ok || got != 0x63 {
		t.Fatalf("ndiscCacheEntries=%d ok=%v want 99", got, ok)
	}
	if _, ok := ndiscCacheEntries(filepath.Join(t.TempDir(), "missing")); ok {
		t.Fatal("missing file parsed")
	}
}

func TestArpTableEntriesCount(t *testing.T) {
	p := filepath.Join(t.TempDir(), "arp")
	writePrefailFile(t, p,
		"IP address       HW type     Flags       HW address            Mask     Device\n"+
			"10.0.0.1        0x1         0x2         00:11:22:33:44:55     *        eth0\n"+
			"10.0.0.2        0x1         0x0         00:00:00:00:00:00     *        eth0\n")
	got, ok := arpTableEntries(p)
	if !ok || got != 2 {
		t.Fatalf("arpTableEntries=%d ok=%v want 2", got, ok)
	}
	// Header-only table = 0 entries, still readable.
	writePrefailFile(t, p,
		"IP address       HW type     Flags       HW address            Mask     Device\n")
	got, ok = arpTableEntries(p)
	if !ok || got != 0 {
		t.Fatalf("empty arp table=%d ok=%v want 0", got, ok)
	}
}
