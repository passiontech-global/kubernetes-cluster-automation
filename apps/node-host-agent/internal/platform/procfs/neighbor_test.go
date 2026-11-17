// neighbor_test.go — coverage for the /proc neighbor-table
// parsers the P0.4 healer consumes: the /proc/net/arp row decode
// (flags → NUD state), the ndisc_cache stats header-by-name parse
// (multi-section tolerance, entries=max / table_fulls=sum), and
// the missing/short-file inconclusive verdicts.
package procfs

import (
	"os"
	"path/filepath"
	"testing"
)

func writeProcFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadARPTableDecodesNUDStates(t *testing.T) {
	dir := t.TempDir()
	// ATF flags low byte: 0x02 reachable, 0x20 failed, 0x04 stale,
	// 0x80 permanent — plus one row with an unparseable flag that
	// must be dropped, not counted.
	path := writeProcFile(t, dir, "arp", `IP address       HW type     Flags       HW address            Mask     Device
10.0.0.1         0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0
10.0.0.2         0x1         0x22        aa:bb:cc:dd:ee:02     *        eth0
10.0.0.3         0x1         0x4         aa:bb:cc:dd:ee:03     *        eth0
10.0.0.4         0x1         0x80        aa:bb:cc:dd:ee:04     *        eth0
10.0.0.5         0x1         0xZZ        aa:bb:cc:dd:ee:05     *        eth0
`)
	ents, ok := ReadARPTable(path)
	if !ok {
		t.Fatal("ReadARPTable inconclusive on a valid table")
	}
	if len(ents) != 4 {
		t.Fatalf("entries=%d want 4 (bad-flags row dropped)", len(ents))
	}
	// NUD is a bitmask over the flags low byte — assert bit
	// membership, not equality (real rows carry COM/PERM bits
	// alongside the NUD state bits).
	want := map[string]NUDState{
		"10.0.0.1": NUDReachable,
		"10.0.0.2": NUDFailed, // 0x22 keeps the 0x20 failed bit
		"10.0.0.3": NUDStale,
		"10.0.0.4": NUDPermanent,
	}
	for _, e := range ents {
		if e.NUD&want[e.IP] == 0 {
			t.Fatalf("%s NUD=%#x missing bit %#x", e.IP, e.NUD, want[e.IP])
		}
		if e.Device != "eth0" || e.HWAddr == "" {
			t.Fatalf("%s decode lost fields: %+v", e.IP, e)
		}
	}
}

func TestReadARPTableInconclusive(t *testing.T) {
	if _, ok := ReadARPTable(filepath.Join(t.TempDir(), "missing")); ok {
		t.Fatal("missing file must be inconclusive")
	}
	// Header-only is a valid empty table — ok with zero entries,
	// never a "no neighbors" fabrication either way.
	dir := t.TempDir()
	p := writeProcFile(t, dir, "arp",
		"IP address       HW type     Flags       HW address            Mask     Device\n")
	ents, ok := ReadARPTable(p)
	if !ok || len(ents) != 0 {
		t.Fatalf("header-only: ok=%v ents=%d want true/0", ok, len(ents))
	}
}

func TestReadNDISCStatsMultiSection(t *testing.T) {
	dir := t.TempDir()
	// The real file carries named sections (arp_cache + ndisc_cache)
	// each with its own header — the parser must re-base indices
	// per header and sum table_fulls across rows.
	path := writeProcFile(t, dir, "ndisc_cache", `arp_cache
entries  allocs   destroys hash_grows lookups  hits     res_failed rcv_probes_mcast rcv_probes_ucast periodic_gc_runs forced_gc_runs unresolved_discards table_fulls
0000000a 00000001 00000000 00000000   00000000 00000000 00000000   00000000         00000000         00000001         00000000       00000000            00000000
00000014 00000002 00000000 00000000   00000000 00000000 00000000   00000000         00000000         00000002         00000000       00000000            00000000
ndisc_cache
entries  allocs   destroys hash_grows lookups  hits     res_failed rcv_probes_mcast rcv_probes_ucast periodic_gc_runs forced_gc_runs unresolved_discards table_fulls
00000020 00000003 00000000 00000000   00000000 00000000 00000000   00000000         00000000         00000003         00000000       00000000            00000007
`)
	st, ok := ReadNDISCStats(path)
	if !ok {
		t.Fatal("multi-section stats inconclusive")
	}
	if st.Entries != 0x20 {
		t.Fatalf("entries=%#x want max 0x20", st.Entries)
	}
	if st.TableFulls != 7 {
		t.Fatalf("table_fulls=%d want 7", st.TableFulls)
	}
}

func TestReadNDISCStatsInconclusive(t *testing.T) {
	if _, ok := ReadNDISCStats(filepath.Join(t.TempDir(), "missing")); ok {
		t.Fatal("missing stats file must be inconclusive")
	}
	// A file with rows but no recognizable header — never fabricate.
	dir := t.TempDir()
	p := writeProcFile(t, dir, "ndisc_cache", "garbage line\nmore garbage\n")
	if _, ok := ReadNDISCStats(p); ok {
		t.Fatal("headerless stats must be inconclusive")
	}
}
