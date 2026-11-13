//go:build linux

// diag_bench_linux_test.go — benchmarks for the sock-diag hot path:
// the Wave-1-hardened parseDiagCensus fold over a synthetic inet_diag
// recv batch, and DiagEndpoint (the old hexSockAddr decode) rendering
// the census PerTuple keys. Both run on hand-assembled kernel wire
// layouts — no netlink socket involved.
package netlinkx

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

// benchDiagBatch assembles one realistic recv batch: n inet_diag
// messages, every 4th AF_INET6, states cycling the common TCP states,
// addresses spread over n/64 /32s with 3 ports each — mostly
// PerTuple-map HITS (a node holds many conns to few endpoints) with a
// fresh-insert on every group boundary.
func benchDiagBatch(n int) []byte {
	batch := make([]byte, 0, n*(16+diagMsg))
	for i := range n {
		family := uint8(unix.AF_INET)
		daddrLen := 4
		if i%4 == 3 {
			family = unix.AF_INET6
			daddrLen = 16
		}
		msg := inetDiagMsg(family, uint8(1+i%5), uint16(i), uint16(443+i%3))
		// daddr sits at sockid+20 — payload offset 24, msg offset 40.
		// v4 keys read 4 bytes of it, v6 keys all 16: spread over
		// n/64 distinct addresses either way.
		daddr := msg[16+24:]
		for j := range daddrLen {
			daddr[j] = byte(i / 64)
		}
		batch = append(batch, msg...)
	}
	return batch
}

// BenchmarkParseDiagCensus folds a 512-message recv batch (~45KB —
// the size a busy node answers with) per iteration: header walk,
// state bucketing and the PerTuple key build/lookup in one pass.
func BenchmarkParseDiagCensus(b *testing.B) {
	b.ReportAllocs()
	batch := benchDiagBatch(512)
	b.SetBytes(int64(len(batch)))
	for b.Loop() {
		out := TCPCensus{States: map[uint8]int{}, PerTuple: map[string]int{}}
		if _, err := parseDiagCensus(batch, &out); err != nil {
			b.Fatal(err)
		}
		if len(out.PerTuple) == 0 || len(out.States) == 0 {
			b.Fatal("census fold produced nothing")
		}
	}
}

// sinkStr keeps DiagEndpoint's result observable so the compiler
// cannot fold the benchmark away.
var sinkStr string

// BenchmarkDiagEndpoint renders census PerTuple keys — the
// a.b.c.d:port / [v6]:port decode every Prometheus label value for
// the TCP census pays per tuple per scrape.
func BenchmarkDiagEndpoint(b *testing.B) {
	b.ReportAllocs()
	keys := make([]string, 0, 512)
	for i := range 512 {
		v4 := []byte{byte(i), byte(i >> 8), byte(i >> 16), 10}
		v4 = binary.BigEndian.AppendUint16(v4, uint16(i))
		keys = append(keys, string(v4))

		v6 := make([]byte, 18)
		for j := range 16 {
			v6[j] = byte(i + j)
		}
		binary.BigEndian.PutUint16(v6[16:], uint16(i))
		keys = append(keys, string(v6))
	}
	for b.Loop() {
		for _, k := range keys {
			sinkStr = DiagEndpoint(k)
		}
	}
}
