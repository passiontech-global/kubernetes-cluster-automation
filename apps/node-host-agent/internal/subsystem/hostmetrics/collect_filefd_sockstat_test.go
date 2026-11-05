// collect_filefd_sockstat_test.go — H6 file-nr and sockstat pressure series.

package hostmetrics

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"math"
	"testing"
)

// --- H6: FD + socket pressure (file-nr, sockstat) ---

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
