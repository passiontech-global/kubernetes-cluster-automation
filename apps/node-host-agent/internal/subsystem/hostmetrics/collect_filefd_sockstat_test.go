// collect_filefd_sockstat_test.go — H6 file-nr and sockstat pressure series.

package hostmetrics

import (
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// --- H6: FD + socket pressure (file-nr, sockstat) ---

// --- Mountinfo entries gauge ---

func TestMountinfoEntriesCount(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	// Absent file → no series (the collectFileFD rule: no fake 0).
	if _, ok := metricValue(t, c,
		"node_host_agent_mountinfo_entries_count", node); ok {
		t.Fatal("mountinfo gauge emitted without the file")
	}
	testutil.WriteFile(t, cfg.MountinfoFile,
		"36 35 98:0 / / rw - overlay x\n\n"+
			"37 35 98:1 / /proc rw - proc x\n"+
			"38 35 98:2 / /sys rw - sysfs x\n")
	if v, ok := metricValue(t, c,
		"node_host_agent_mountinfo_entries_count", node); !ok || v != 3 {
		t.Fatalf("mountinfo entries=%v ok=%v want 3 (blank lines skipped)", v, ok)
	}
}

func TestFileFDMetrics(t *testing.T) {
	cfg, _ := fixture(t)
	testutil.WriteFile(t, cfg.FileNRFile, "12345\t0\t9999999\n")
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	if v, ok := metricValue(t, c, "node_host_agent_filefd_allocated",
		node); !ok || v != 12345 {
		t.Fatalf("allocated=%v ok=%v want 12345", v, ok)
	}
	if v, ok := metricValue(t, c, "node_host_agent_filefd_maximum",
		node); !ok || v != 9999999 {
		t.Fatalf("maximum=%v ok=%v want 9999999", v, ok)
	}
	want := 12345.0 / 9999999.0
	if v, ok := metricValue(t, c, "node_host_agent_filefd_used_ratio",
		node); !ok || math.Abs(v-want) > 1e-9 {
		t.Fatalf("used_ratio=%v ok=%v want %v", v, ok, want)
	}
}

func TestFileFDAbsentOnMissingOrMalformed(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	names := []string{
		"node_host_agent_filefd_allocated",
		"node_host_agent_filefd_maximum",
		"node_host_agent_filefd_used_ratio",
	}
	for _, name := range names {
		if _, ok := metricValue(t, c, name, node); ok {
			t.Fatalf("%s emitted without the file", name)
		}
	}
	for _, content := range []string{
		"12345\n",         // too few fields
		"abc\t0\tdef\n",   // non-numeric
		"12345\t0\tmax\n", // non-numeric max
	} {
		testutil.WriteFile(t, cfg.FileNRFile, content)
		for _, name := range names {
			if _, ok := metricValue(t, c, name, node); ok {
				t.Fatalf("%s emitted for malformed %q", name, content)
			}
		}
	}
}

func TestFileFDZeroMaxSkipsRatio(t *testing.T) {
	cfg, _ := fixture(t)
	testutil.WriteFile(t, cfg.FileNRFile, "10\t0\t0\n")
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	if v, ok := metricValue(t, c, "node_host_agent_filefd_maximum",
		node); !ok || v != 0 {
		t.Fatalf("maximum=%v ok=%v want 0", v, ok)
	}
	if _, ok := metricValue(t, c, "node_host_agent_filefd_used_ratio",
		node); ok {
		t.Fatal("used_ratio emitted with a zero maximum (div-by-zero)")
	}
}

func TestSockstatMetrics(t *testing.T) {
	cfg, _ := fixture(t)
	testutil.WriteFile(t, cfg.SockstatFile,
		"sockets: used 1847\n"+
			"TCP: inuse 25 orphan 2 tw 4 alloc 1200 mem 456\n"+
			"UDP: inuse 10 mem 20\n"+
			"UDPLITE: inuse 0\n"+
			"RAW: inuse 0\n"+
			"FRAG: inuse 0 memory 0\n")
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	checks := map[string]float64{
		"node_host_agent_sockstat_sockets_used": 1847,
		"node_host_agent_sockstat_tcp_inuse":    25,
		"node_host_agent_sockstat_tcp_orphan":   2,
		"node_host_agent_sockstat_tcp_tw":       4,
	}
	for name, want := range checks {
		if v, ok := metricValue(t, c, name, node); !ok || v != want {
			t.Fatalf("%s=%v ok=%v want %v", name, v, ok, want)
		}
	}
}

func TestSockstatAbsentWithoutFile(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	for _, name := range []string{
		"node_host_agent_sockstat_sockets_used",
		"node_host_agent_sockstat_tcp_inuse",
		"node_host_agent_sockstat_tcp_orphan",
		"node_host_agent_sockstat_tcp_tw",
	} {
		if _, ok := metricValue(t, c, name, node); ok {
			t.Fatalf("%s emitted without sockstat", name)
		}
	}
}

func TestSockstatMissingAndMalformedSections(t *testing.T) {
	cfg, _ := fixture(t)
	// No TCP line at all — sockets_used still emits, the TCP series
	// stay absent rather than guessing 0.
	testutil.WriteFile(t, cfg.SockstatFile, "sockets: used 99\nUDP: inuse 3\n")
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	if v, ok := metricValue(t, c, "node_host_agent_sockstat_sockets_used",
		node); !ok || v != 99 {
		t.Fatalf("sockets_used=%v ok=%v want 99", v, ok)
	}
	if _, ok := metricValue(t, c, "node_host_agent_sockstat_tcp_inuse",
		node); ok {
		t.Fatal("tcp_inuse emitted without a TCP line")
	}

	// A malformed TCP line (odd field count / non-numeric value)
	// is skipped entirely — never emit junk.
	testutil.WriteFile(t, cfg.SockstatFile,
		"sockets: used 99\nTCP: inuse five orphan 0\nTCP: dangling\n")
	for _, name := range []string{
		"node_host_agent_sockstat_tcp_inuse",
		"node_host_agent_sockstat_tcp_orphan",
		"node_host_agent_sockstat_tcp_tw",
	} {
		if _, ok := metricValue(t, c, name, node); ok {
			t.Fatalf("%s emitted for malformed TCP lines", name)
		}
	}
}

// --- conntrack-port-pressure: ephemeral port saturation + CLOSE_WAIT count ---

func TestEphemeralPortSaturationRatio(t *testing.T) {
	cfg, _ := fixture(t)
	testutil.WriteFile(t, cfg.SockstatFile,
		"sockets: used 500\nTCP: inuse 100 orphan 0 tw 50 alloc 200 mem 10\n")
	dir := t.TempDir()
	cfg.LocalPortRangeFile = filepath.Join(dir, "ip_local_port_range")
	testutil.WriteFile(t, cfg.LocalPortRangeFile, "10240 65535\n")
	c := New(cfg)
	// width = 65535-10240+1 = 55296; (100+50)/55296.
	want := 150.0 / 55296.0
	if v, ok := metricValue(t, c,
		"node_sockstat_ephemeral_port_saturation_ratio",
		map[string]string{"node": "node-a"}); !ok || math.Abs(v-want) > 1e-9 {
		t.Fatalf("saturation=%v ok=%v want %v", v, ok, want)
	}
}

func TestEphemeralPortSaturationDefaultWidth(t *testing.T) {
	cfg, _ := fixture(t)
	testutil.WriteFile(t, cfg.SockstatFile,
		"TCP: inuse 14116 orphan 0 tw 14116 alloc 30000 mem 5\n")
	// Unreadable sysctl → the kernel's stock 28232-wide range.
	cfg.LocalPortRangeFile = filepath.Join(t.TempDir(), "missing")
	c := New(cfg)
	if v, ok := metricValue(t, c,
		"node_sockstat_ephemeral_port_saturation_ratio",
		map[string]string{"node": "node-a"}); !ok || math.Abs(v-1.0) > 1e-9 {
		t.Fatalf("saturation=%v ok=%v want 1.0 (28232/28232)", v, ok)
	}
}

func TestEphemeralPortSaturationNeedsBothLegs(t *testing.T) {
	cfg, _ := fixture(t)
	// sockstat with inuse but no tw → partial read stays absent.
	testutil.WriteFile(t, cfg.SockstatFile,
		"TCP: inuse 25 orphan 0 alloc 100 mem 5\n")
	cfg.LocalPortRangeFile = filepath.Join(t.TempDir(), "missing")
	c := New(cfg)
	if _, ok := metricValue(t, c,
		"node_sockstat_ephemeral_port_saturation_ratio",
		map[string]string{"node": "node-a"}); ok {
		t.Fatal("saturation emitted without the tw leg")
	}
}

func TestTCPCloseWaitSockets(t *testing.T) {
	cfg, _ := fixture(t)
	dir := t.TempDir()
	cfg.ProcNetTCP = filepath.Join(dir, "tcp")
	cfg.ProcNetTCP6 = filepath.Join(dir, "tcp6")
	testutil.WriteFile(t, cfg.ProcNetTCP,
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when\n"+
			"   0: 0100007F:0050 0100007F:1F90 01 00000000:00000000\n"+
			"   1: 0100007F:0051 0100007F:1F91 08 00000000:00000000\n"+ // CLOSE_WAIT
			"   2: 0100007F:0052 0100007F:1F92 06 00000000:00000000\n"+ // TIME_WAIT
			"   3: 0100007F:0053 0100007F:1F93 08 00000000:00000000\n") // CLOSE_WAIT
	testutil.WriteFile(t, cfg.ProcNetTCP6,
		"  sl  local_address                         rem_address                        st\n"+
			"   0: 0000000000000000000000000100007F:0050 0000000000000000000000000100007F:1F90 08\n")
	c := New(cfg)
	if v, ok := metricValue(t, c, "node_tcp_close_wait_sockets",
		map[string]string{"node": "node-a"}); !ok || v != 3 {
		t.Fatalf("close_wait=%v ok=%v want 3 (2 v4 + 1 v6)", v, ok)
	}
}

func TestTCPCloseWaitAbsentWithoutTables(t *testing.T) {
	cfg, _ := fixture(t)
	dir := t.TempDir() // neither tcp nor tcp6 exists
	cfg.ProcNetTCP = filepath.Join(dir, "tcp")
	cfg.ProcNetTCP6 = filepath.Join(dir, "tcp6")
	c := New(cfg)
	if _, ok := metricValue(t, c, "node_tcp_close_wait_sockets",
		map[string]string{"node": "node-a"}); ok {
		t.Fatal("close_wait emitted with no socket tables at all")
	}
	// A single readable family still counts — an IPv6-less host
	// legitimately lacks tcp6.
	testutil.WriteFile(t, cfg.ProcNetTCP,
		"  sl  local_address rem_address   st\n"+
			"   0: 0100007F:0050 0100007F:1F90 01\n")
	if v, ok := metricValue(t, c, "node_tcp_close_wait_sockets",
		map[string]string{"node": "node-a"}); !ok || v != 0 {
		t.Fatalf("close_wait=%v ok=%v want explicit 0", v, ok)
	}
}

// --- netstat/snmp kernel TCP/IP counters ---

const netstatFixture = `TcpExt: SyncookiesSent ListenOverflows ListenDrops TCPSynRetrans TCPTimeouts
TcpExt: 0 123 45 67 89
IpExt: InMcastPkts OutMcastPkts
IpExt: 1 2
`

const snmpFixture = `Ip: Forwarding DefaultTTL InReceives ReasmFails
Ip: 1 64 9999 13
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors
Udp: 100 0 2 100 5 0
`

func TestNetstatSNMPMetrics(t *testing.T) {
	cfg, _ := fixture(t)
	testutil.WriteFile(t, cfg.NetstatFile, netstatFixture)
	testutil.WriteFile(t, cfg.SNMPFile, snmpFixture)
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	checks := map[string]float64{
		"node_host_agent_netstat_tcp_listen_overflows_total": 123,
		"node_host_agent_netstat_tcp_listen_drops_total":     45,
		"node_host_agent_netstat_tcp_syn_retrans_total":      67,
		"node_host_agent_netstat_tcp_timeouts_total":         89,
		"node_host_agent_snmp_ip_reasm_fails_total":          13,
		"node_host_agent_snmp_udp_rcvbuf_errors_total":       5,
	}
	for name, want := range checks {
		if v, ok := metricValue(t, c, name, node); !ok || v != want {
			t.Fatalf("%s=%v ok=%v want %v", name, v, ok, want)
		}
	}
}

func TestNetstatSNMPAbsentWithoutFiles(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	for _, name := range []string{
		"node_host_agent_netstat_tcp_listen_overflows_total",
		"node_host_agent_netstat_tcp_listen_drops_total",
		"node_host_agent_netstat_tcp_syn_retrans_total",
		"node_host_agent_netstat_tcp_timeouts_total",
		"node_host_agent_snmp_ip_reasm_fails_total",
		"node_host_agent_snmp_udp_rcvbuf_errors_total",
	} {
		if _, ok := metricValue(t, c, name, node); ok {
			t.Fatalf("%s emitted without the source file", name)
		}
	}
}

func TestNetstatSNMPMissingAndMalformedSections(t *testing.T) {
	cfg, _ := fixture(t)
	// A values line that doesn't line up with its header is
	// skipped; a section carrying only SOME keys emits just those.
	testutil.WriteFile(t, cfg.NetstatFile,
		"TcpExt: ListenOverflows ListenDrops\nTcpExt: 7 8\n"+
			"TcpExt: TCPSynRetrans extra\nTcpExt: notanumber x\n")
	testutil.WriteFile(t, cfg.SNMPFile,
		"Udp: InDatagrams RcvbufErrors\nUdp: 9 nope\n")
	c := New(cfg)
	node := map[string]string{"node": "node-a"}
	if v, ok := metricValue(t, c,
		"node_host_agent_netstat_tcp_listen_overflows_total",
		node); !ok || v != 7 {
		t.Fatalf("overflows=%v ok=%v want 7", v, ok)
	}
	if v, ok := metricValue(t, c,
		"node_host_agent_netstat_tcp_listen_drops_total",
		node); !ok || v != 8 {
		t.Fatalf("drops=%v ok=%v want 8", v, ok)
	}
	if _, ok := metricValue(t, c,
		"node_host_agent_netstat_tcp_syn_retrans_total", node); ok {
		t.Fatal("syn_retrans emitted for a malformed values line")
	}
	if _, ok := metricValue(t, c,
		"node_host_agent_snmp_udp_rcvbuf_errors_total", node); ok {
		t.Fatal("rcvbuf_errors emitted for a malformed values line")
	}
}

// --- aio-pressure: kernel AIO table gauges ---

// TestCollectAIO: aio-nr/aio-max-nr gauges plus the used ratio; the
// ratio is 0 when the max reads 0 (never a division by zero) and
// the series stay absent when the files don't parse.
func TestCollectAIO(t *testing.T) {
	cfg, _ := fixture(t)
	root := t.TempDir()
	nrFile := filepath.Join(root, "aio-nr")
	maxFile := filepath.Join(root, "aio-max-nr")
	oldNr, oldMax := aioNrFile, aioMaxFile
	aioNrFile, aioMaxFile = nrFile, maxFile
	t.Cleanup(func() { aioNrFile, aioMaxFile = oldNr, oldMax })

	testutil.WriteFile(t, nrFile, "314572\n")
	testutil.WriteFile(t, maxFile, "1048576\n")
	c := New(cfg)
	if got, ok := metricValue(t, c, "node_host_agent_aio_allocated",
		map[string]string{"node": "node-a"}); !ok || got != 314572 {
		t.Fatalf("aio_allocated=%v ok=%v want 314572", got, ok)
	}
	if got, ok := metricValue(t, c, "node_host_agent_aio_maximum",
		map[string]string{"node": "node-a"}); !ok || got != 1048576 {
		t.Fatalf("aio_maximum=%v ok=%v want 1048576", got, ok)
	}
	if got, ok := metricValue(t, c, "node_host_agent_aio_used_ratio",
		map[string]string{"node": "node-a"}); !ok || got != 314572.0/1048576.0 {
		t.Fatalf("aio_used_ratio=%v ok=%v want %v", got, ok, 314572.0/1048576.0)
	}
	// max 0 → ratio 0, never NaN.
	testutil.WriteFile(t, maxFile, "0\n")
	if got, ok := metricValue(t, c, "node_host_agent_aio_used_ratio",
		map[string]string{"node": "node-a"}); !ok || got != 0 {
		t.Fatalf("aio_used_ratio with max 0 =%v ok=%v want 0", got, ok)
	}
	// Unreadable sources → no series at all.
	testutil.WriteFile(t, nrFile, "garbage\n")
	if err := os.Remove(maxFile); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"node_host_agent_aio_allocated",
		"node_host_agent_aio_maximum",
		"node_host_agent_aio_used_ratio",
	} {
		if _, ok := metricValue(t, c, name, map[string]string{"node": "node-a"}); ok {
			t.Fatalf("%s emitted with unparseable sources", name)
		}
	}
}

// TestCollectAIOBump: past 75% of the table with headroom left, the
// runtime bump doubles aio-max-nr in place (capped at the target) —
// and the maximum gauge shows the POST-bump ceiling, not the stale
// one. A failed sysctl write is silent: the gauges keep the truth.
func TestCollectAIOBump(t *testing.T) {
	cfg, _ := fixture(t)
	root := t.TempDir()
	nrFile := filepath.Join(root, "aio-nr")
	maxFile := filepath.Join(root, "aio-max-nr")
	oldNr, oldMax := aioNrFile, aioMaxFile
	aioNrFile, aioMaxFile = nrFile, maxFile
	t.Cleanup(func() { aioNrFile, aioMaxFile = oldNr, oldMax })
	labels := map[string]string{"node": "node-a"}

	// 100/100 → ratio 1.0 > 0.75 → doubled to 200 (far under the cap).
	testutil.WriteFile(t, nrFile, "100\n")
	testutil.WriteFile(t, maxFile, "100\n")
	c := New(cfg)
	if got, ok := metricValue(t, c, "node_host_agent_aio_maximum", labels); !ok || got != 200 {
		t.Fatalf("aio_maximum after bump=%v ok=%v want 200", got, ok)
	}
	if got, ok := metricValue(t, c, "node_host_agent_aio_used_ratio", labels); !ok || got != 0.5 {
		t.Fatalf("aio_used_ratio after bump=%v ok=%v want 0.5", got, ok)
	}

	// Near the target the bump caps at aioMaxTarget instead of
	// overshooting it.
	testutil.WriteFile(t, nrFile, "3000000\n")
	testutil.WriteFile(t, maxFile, "3000000\n")
	c2 := New(cfg)
	if got, ok := metricValue(t, c2, "node_host_agent_aio_maximum", labels); !ok || got != float64(aioMaxTarget) {
		t.Fatalf("aio_maximum capped=%v ok=%v want %d", got, ok, uint64(aioMaxTarget))
	}
	want := float64(3000000) / float64(aioMaxTarget)
	if got, ok := metricValue(t, c2, "node_host_agent_aio_used_ratio", labels); !ok || got != want {
		t.Fatalf("aio_used_ratio capped=%v ok=%v want %v", got, ok, want)
	}

	// An unwritable sysctl (read-only file — WriteFileDirect opens
	// the existing node in place, so a read-only parent dir alone
	// does not stop it) fails the bump silently — the gauges still
	// report the on-disk truth.
	roDir := filepath.Join(root, "ro")
	if err := os.MkdirAll(roDir, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(roDir, "aio-nr"), "3000000\n")
	testutil.WriteFile(t, filepath.Join(roDir, "aio-max-nr"), "3000000\n")
	aioNrFile, aioMaxFile = filepath.Join(roDir, "aio-nr"), filepath.Join(roDir, "aio-max-nr")
	if err := os.Chmod(aioMaxFile, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(aioMaxFile, 0o644) })
	c3 := New(cfg)
	if got, ok := metricValue(t, c3, "node_host_agent_aio_maximum", labels); !ok || got != 3000000 {
		t.Fatalf("aio_maximum through a failed bump=%v ok=%v want the read truth 3000000", got, ok)
	}
}

// TestCollectUserNSGauge: the userns ceiling gauge emits only while
// /proc/sys/user/max_user_namespaces parses.
func TestCollectUserNSGauge(t *testing.T) {
	cfg, _ := fixture(t)
	f := filepath.Join(t.TempDir(), "max_user_namespaces")
	old := maxUserNSFile
	maxUserNSFile = f
	t.Cleanup(func() { maxUserNSFile = old })

	c := New(cfg)
	if _, ok := metricValue(t, c, "node_host_agent_max_user_namespaces",
		map[string]string{"node": "node-a"}); ok {
		t.Fatal("userns ceiling emitted without the sysctl file")
	}
	testutil.WriteFile(t, f, "65536\n")
	if got, ok := metricValue(t, c, "node_host_agent_max_user_namespaces",
		map[string]string{"node": "node-a"}); !ok || got != 65536 {
		t.Fatalf("max_user_namespaces=%v ok=%v want 65536", got, ok)
	}
}

// TestEphemeralPortWidthDefaults pins the sysctl fallbacks: missing,
// short, malformed and inverted ranges all yield the kernel's stock
// span, a valid range yields its width.
func TestEphemeralPortWidthDefaults(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ip_local_port_range")
	if got := ephemeralPortWidth(filepath.Join(dir, "missing")); got != defaultEphemeralPortWidth {
		t.Fatalf("missing range width=%v want %v", got, defaultEphemeralPortWidth)
	}
	testutil.WriteFile(t, p, "10240\n")
	if got := ephemeralPortWidth(p); got != defaultEphemeralPortWidth {
		t.Fatalf("single-field range width=%v want %v", got, defaultEphemeralPortWidth)
	}
	testutil.WriteFile(t, p, "abc def\n")
	if got := ephemeralPortWidth(p); got != defaultEphemeralPortWidth {
		t.Fatalf("malformed range width=%v want %v", got, defaultEphemeralPortWidth)
	}
	testutil.WriteFile(t, p, "65535 1024\n")
	if got := ephemeralPortWidth(p); got != defaultEphemeralPortWidth {
		t.Fatalf("inverted range width=%v want %v", got, defaultEphemeralPortWidth)
	}
	testutil.WriteFile(t, p, "10240 65535\n")
	if got := ephemeralPortWidth(p); got != 55296 {
		t.Fatalf("10240-65535 width=%v want 55296", got)
	}
}

// TestSockstatCloseWaitAliasAndMalformed: kernels reporting "cw"
// instead of "close_wait" still feed the close-wait gauge; short
// even-field lines and non-numeric values are skipped, not emitted
// as junk.
func TestSockstatCloseWaitAliasAndMalformed(t *testing.T) {
	cfg, _ := fixture(t)
	testutil.WriteFile(t, cfg.SockstatFile,
		"TCP: inuse 25 orphan 2 tw 4 cw 9\n"+
			"sockets: used\n"+ // even field count → skipped
			"X: bad notanumber\n"+ // non-numeric value → skipped
			"TCP: inuse 1 2\n") // even field count → skipped
	c := New(cfg)
	if got, ok := metricValue(t, c, "node_host_agent_sockstat_tcp_close_wait",
		map[string]string{"node": "node-a"}); !ok || got != 9 {
		t.Fatalf("tcp_close_wait via cw alias=%v ok=%v want 9", got, ok)
	}
	if got, ok := metricValue(t, c, "node_host_agent_sockstat_tcp_tw",
		map[string]string{"node": "node-a"}); !ok || got != 4 {
		t.Fatalf("tcp_tw=%v ok=%v want 4", got, ok)
	}
}
