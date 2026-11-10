// nebula_cert_test.go — nebula-cert NotAfter wire parse and the cert-days-left latch.

package hostmetrics

import (
	"encoding/pem"
	"math"
	"os"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// --- nebula cert expiry ---

// pbVarint, pbTag, pbLenField, pbVarField hand-encode the protobuf
// wire fields the parser reads — keeps the test independent of a
// real nebula-cert binary while exercising the same wire shape:
// NebulaCertificate{Details(field 1, LEN)=details, Signature(2)},
// details{...,NotAfter(field 6, varint)}.
func pbVarint(v uint64) []byte {
	var b []byte
	for {
		c := byte(v & 0x7f)
		v >>= 7
		if v == 0 {
			return append(b, c)
		}
		b = append(b, c|0x80)
	}
}

func pbTag(field, wire int) []byte {
	return pbVarint(uint64(field<<3 | wire))
}

func pbLenField(field int, payload []byte) []byte {
	out := append(pbTag(field, 2), pbVarint(uint64(len(payload)))...)
	return append(out, payload...)
}

func pbVarField(field int, v uint64) []byte {
	return append(pbTag(field, 0), pbVarint(v)...)
}

// nebulaCertPEM builds a PEM "NEBULA CERTIFICATE" blob carrying
// notAfter — structurally identical to what nebula-cert writes.
func nebulaCertPEM(notAfter int64) []byte {
	var details []byte
	details = append(details, pbLenField(1, []byte("node-a"))...)
	details = append(details, pbVarField(5, 1_700_000_000)...)    // NotBefore
	details = append(details, pbVarField(6, uint64(notAfter))...) // NotAfter
	details = append(details, pbLenField(7, []byte{0xde, 0xad, 0xbe, 0xef})...)
	var cert []byte
	cert = append(cert, pbLenField(1, details)...)
	cert = append(cert, pbLenField(2, []byte{0x01, 0x02, 0x03})...)
	return pem.EncodeToMemory(&pem.Block{Type: "NEBULA CERTIFICATE", Bytes: cert})
}

func TestNebulaCertNotAfterParse(t *testing.T) {
	var details []byte
	details = append(details, pbLenField(1, []byte("x"))...)
	details = append(details, pbVarField(6, 1_800_000_000)...)
	cert := append(pbLenField(1, details), pbLenField(2, []byte{9})...)
	if got, ok := nebulaCertNotAfter(cert); !ok || got != 1_800_000_000 {
		t.Fatalf("nebulaCertNotAfter=%d,%v want 1800000000,true", got, ok)
	}
}

func TestNebulaCertNotAfterRejectsGarbage(t *testing.T) {
	cases := map[string][]byte{
		"empty":           {},
		"truncated tag":   {0x80},
		"details no f6":   append(pbLenField(1, pbLenField(1, []byte("x"))), pbLenField(2, []byte{1})...),
		"truncated len":   append(pbTag(1, 2), 0x7f, 0x01), // declared len beyond payload
		"bad wire in top": append(append(pbTag(1, 3), 0x01), pbLenField(2, []byte{1})...),
		"details f6 len":  pbLenField(1, append(pbTag(6, 2), 0x01, 0x00)), // f6 as LEN not varint
	}
	for name, der := range cases {
		if _, ok := nebulaCertNotAfter(der); ok {
			t.Fatalf("nebulaCertNotAfter(%s) want ok=false", name)
		}
	}
}

func TestNebulaCertDaysLeftMetric(t *testing.T) {
	cfg, _ := fixture(t)
	notAfter := time.Now().Unix() + 10*86400 + 3600 // ~10 days → <30 → expiring
	if err := os.WriteFile(cfg.NebulaCertFile, nebulaCertPEM(notAfter), 0o644); err != nil {
		t.Fatal(err)
	}
	c := New(cfg)
	if v, ok := metricValue(t, c, "node_host_agent_nebula_cert_days_left", nil); !ok || v != 10 {
		t.Fatalf("cert_days_left=%v ok=%v want 10", v, ok)
	}
	if v, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "nebula-cert-expiring"}); !ok || v != 1 {
		t.Fatalf("cert-expiring state=%v ok=%v want 1", v, ok)
	}
}

func TestNebulaCertHealthyEmitsZero(t *testing.T) {
	cfg, _ := fixture(t)
	notAfter := time.Now().Unix() + 90*86400 // ~90 days → no expiring
	if err := os.WriteFile(cfg.NebulaCertFile, nebulaCertPEM(notAfter), 0o644); err != nil {
		t.Fatal(err)
	}
	c := New(cfg)
	if v, ok := metricValue(t, c, "node_host_agent_nebula_cert_days_left", nil); !ok || v != 90 {
		t.Fatalf("cert_days_left=%v ok=%v want 90", v, ok)
	}
	// Alert contract: explicit 0 once the cert was readable.
	if v, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "nebula-cert-expiring"}); !ok || v != 0 {
		t.Fatalf("cert-expiring state=%v ok=%v want emitted 0", v, ok)
	}
}

func TestNebulaCertAbsentEmitsNothing(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	if _, ok := metricValue(t, c, "node_host_agent_nebula_cert_days_left", nil); ok {
		t.Fatal("cert_days_left emitted without cert")
	}
	if _, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "nebula-cert-expiring"}); ok {
		t.Fatal("cert-expiring emitted though the cert was never readable")
	}
}

func TestNebulaCertUnparseableEmitsNothing(t *testing.T) {
	cfg, _ := fixture(t)
	testutil.WriteFile(t, cfg.NebulaCertFile, "-----BEGIN NEBULA CERTIFICATE-----\nnot-base64!!!\n-----END NEBULA CERTIFICATE-----\n")
	c := New(cfg)
	if _, ok := metricValue(t, c, "node_host_agent_nebula_cert_days_left", nil); ok {
		t.Fatal("cert_days_left emitted for garbage PEM")
	}
}

func TestNebulaCertStatePersistsZeroAfterRemoval(t *testing.T) {
	cfg, _ := fixture(t)
	notAfter := time.Now().Unix() + 10*86400
	if err := os.WriteFile(cfg.NebulaCertFile, nebulaCertPEM(notAfter), 0o644); err != nil {
		t.Fatal(err)
	}
	c := New(cfg)
	// First scrape registers the state (value 1 while expiring).
	if v, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "nebula-cert-expiring"}); !ok || v != 1 {
		t.Fatalf("cert-expiring=%v ok=%v want 1", v, ok)
	}
	// Cert vanishes — the seenStates bookkeeping must keep the
	// series alive at 0 (auto-resolve), not drop it.
	if err := os.Remove(cfg.NebulaCertFile); err != nil {
		t.Fatal(err)
	}
	v, ok := metricValue(t, c, "node_host_agent_watchdog_state",
		map[string]string{"node": "node-a", "state": "nebula-cert-expiring"})
	if !ok || v != 0 {
		t.Fatalf("cert-expiring after removal=%v ok=%v want emitted 0", v, ok)
	}
	if _, ok := metricValue(t, c, "node_host_agent_nebula_cert_days_left", nil); ok {
		t.Fatal("cert_days_left emitted after cert removal")
	}
}

// TestReadVarintAndSkipWireEdges pins the wire-format guards the
// cert parsers rely on: truncated/overflowing varints, the fixed
// wire types' length windows and the rejected group wire types.
func TestReadVarintAndSkipWireEdges(t *testing.T) {
	if v, n := readVarint(nil); n != 0 || v != 0 {
		t.Fatalf("readVarint(nil)=%d,%d want 0,0", v, n)
	}
	// Ten continuation bytes → overflow, not a value.
	if _, n := readVarint([]byte{
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}); n != 0 {
		t.Fatal("all-continuation varint accepted")
	}
	// The 10th byte may carry only its lowest bit.
	if _, n := readVarint([]byte{
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02}); n != 0 {
		t.Fatal("10th byte carrying more than one bit accepted")
	}
	// The maximal 10-byte encoding decodes to MaxUint64.
	if v, n := readVarint([]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}); n != 10 || v != math.MaxUint64 {
		t.Fatalf("max varint=%d n=%d want MaxUint64,10", v, n)
	}

	// fixed64 (wire 1): exactly 8 bytes, else truncated.
	if n, ok := skipWire([]byte{1, 2, 3, 4, 5, 6, 7, 8}, 1); !ok || n != 8 {
		t.Fatalf("skipWire(fixed64)=%d,%v want 8,true", n, ok)
	}
	if _, ok := skipWire([]byte{1, 2, 3}, 1); ok {
		t.Fatal("short fixed64 accepted")
	}
	// fixed32 (wire 5): exactly 4 bytes.
	if n, ok := skipWire([]byte{1, 2, 3, 4}, 5); !ok || n != 4 {
		t.Fatalf("skipWire(fixed32)=%d,%v want 4,true", n, ok)
	}
	if _, ok := skipWire([]byte{1}, 5); ok {
		t.Fatal("short fixed32 accepted")
	}
	// Group/deprecated wire types are unparseable, not guessed.
	for _, w := range []int{3, 4, 6} {
		if _, ok := skipWire([]byte{0xff, 0xff}, w); ok {
			t.Fatalf("wire type %d accepted", w)
		}
	}
	// Length-delimited: a declared length past the buffer is a
	// truncation; an exact fit returns the full field span.
	if _, ok := skipWire([]byte{0x05, 'a', 'b'}, 2); ok {
		t.Fatal("overlong length-delimited field accepted")
	}
	if n, ok := skipWire([]byte{0x02, 'a', 'b'}, 2); !ok || n != 3 {
		t.Fatalf("skipWire(LEN)=%d,%v want 3,true", n, ok)
	}
}
