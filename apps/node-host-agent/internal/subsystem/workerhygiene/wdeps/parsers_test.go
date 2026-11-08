// parsers_test.go — the response parsers behind the Cilium group's
// derived reads: the wg allowed-ips count, the wg dump TSV, the
// /v1/healthz node count and the /v1/service backend reduction.
package wdeps_test

import (
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// TestParseWGAllowedIPs — one count per peer line; "(none)" peers
// and degenerate lines don't count.
func TestParseWGAllowedIPs(t *testing.T) {
	out := strings.Join([]string{
		"pubA\t10.0.0.2/32 10.0.0.3/32",
		"pubB\t(none)",
		"onlyakey",
		"",
		"pubC\t10.0.0.4/32",
	}, "\n")
	if got := wdeps.ParseWGAllowedIPs(out); got != 2 {
		t.Fatalf("got %d want 2", got)
	}
	if got := wdeps.ParseWGAllowedIPs(""); got != 0 {
		t.Fatalf("empty input=%d want 0", got)
	}
	if got := wdeps.ParseWGAllowedIPs("pubA\t(none)\npubB\t(none)"); got != 0 {
		t.Fatalf("all-wiped=%d want 0", got)
	}
}

// TestParseWGDump — TSV: interface row (4 columns) skipped, 8-column
// peer rows parsed, garbled rows never invent peer evidence.
func TestParseWGDump(t *testing.T) {
	out := "iface\tpsk\t12.0.0.9:51820\t(none)\n" +
		"pubA\tpsk\t12.0.0.9:51820\t10.0.0.2/32\t1700000000\t100\t200\t25\n" +
		"pubB\tpsk\t12.0.0.9:51820\t10.0.0.3/32\t0\t\t\t0\n" + // rx/tx blanks → 0
		"too\tfew\tcolumns\n" +
		"\tpsk\tep\tips\t1\t2\t3\t4\n" // empty pubkey row
	peers := wdeps.ParseWGDump(out)
	if len(peers) != 2 {
		t.Fatalf("peers=%d want 2: %+v", len(peers), peers)
	}
	a, b := peers[0], peers[1]
	if a.Pub != "pubA" || a.AllowedIPs != "10.0.0.2/32" ||
		a.Handshake != 1700000000 || a.RX != 100 || a.TX != 200 {
		t.Fatalf("peerA=%+v", a)
	}
	if b.Pub != "pubB" || b.AllowedIPs != "10.0.0.3/32" ||
		b.Handshake != 0 || b.RX != 0 || b.TX != 0 {
		t.Fatalf("peerB=%+v", b)
	}
	if wdeps.ParseWGDump("") != nil {
		t.Fatal("empty input must parse no peers")
	}
}

// TestParseCiliumHealthNodes — the cluster.nodes[] member count;
// absent/empty sections and garbage are ok=false (the caller falls
// back to ReadyNodes-1).
func TestParseCiliumHealthNodes(t *testing.T) {
	n, ok := wdeps.ParseCiliumHealthNodes([]byte(`{"cluster":{"nodes":[{},{},{},{}]}}`))
	if !ok || n != 4 {
		t.Fatalf("n=%d ok=%v want 4/true", n, ok)
	}
	for _, body := range []string{
		`{"cluster":{"nodes":[]}}`,
		`{}`,
		`{"cluster":null}`,
		`not json`,
	} {
		if n, ok := wdeps.ParseCiliumHealthNodes([]byte(body)); ok || n != 0 {
			t.Fatalf("body %q: n=%d ok=%v want 0/false", body, n, ok)
		}
	}
}

// TestParseCiliumServiceBackends — spec.name identity wins, flags
// nested identity is the older-build fallback, unnamed (l7lb)
// entries are skipped and backend counts SUM across per-transport
// entries of one service.
func TestParseCiliumServiceBackends(t *testing.T) {
	body := []byte(`[
	  {"spec":{"name":"kube-dns","namespace":"kube-system","backend-addresses":[{},{}]}},
	  {"spec":{"name":"kube-dns","namespace":"kube-system","backend-addresses":[{}]}},
	  {"spec":{"flags":{"name":"legacy-svc","namespace":"legacy-ns"},"backend-addresses":[{},{}]}},
	  {"spec":{"backend-addresses":[{},{}]}}
	]`)
	backends, err := wdeps.ParseCiliumServiceBackends(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if backends["kube-system/kube-dns"] != 3 {
		t.Fatalf("kube-dns backends=%d want 3 (UDP+TCP sum)", backends["kube-system/kube-dns"])
	}
	if backends["legacy-ns/legacy-svc"] != 2 {
		t.Fatalf("flags fallback backends=%d want 2", backends["legacy-ns/legacy-svc"])
	}
	if len(backends) != 2 {
		t.Fatalf("backends=%v want exactly the two named services", backends)
	}

	if _, err := wdeps.ParseCiliumServiceBackends([]byte("not json")); err == nil {
		t.Fatal("garbage payload must error")
	}
	if backends, err := wdeps.ParseCiliumServiceBackends([]byte(`[]`)); err != nil || len(backends) != 0 {
		t.Fatalf("empty list: %v %v", backends, err)
	}
}
