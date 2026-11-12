// collect_tcp_tables.go — kernel TCP table census: the
// /proc/net/tcp{,6} + sock_diag state scan, per-tuple hotspot
// emission and the ephemeral-port width gauge. Split out of
// collect_filefd_sockstat.go — the fd/sockstat/netstat counters
// stay there; this file owns the connection-table evidence.

package hostmetrics

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// tcpStateNames maps the kernel idiag_state ids the sock_diag dump
// reports (include/net/tcp_states.h — the same numbering
// /proc/net/tcp's st column uses) to stable label values. States
// past CLOSING (NEW_SYN_RECV and friends) are kernel-internal and
// stay unlabeled — the census covers the operator-visible set.
var tcpStateNames = []struct {
	id   uint8
	name string
}{
	{1, "established"}, {2, "syn_sent"}, {3, "syn_recv"},
	{4, "fin_wait1"}, {5, "fin_wait2"}, {6, "time_wait"},
	{7, "close"}, {8, "close_wait"}, {9, "last_ack"},
	{10, "listen"}, {11, "closing"},
}

// collectTCPStates emits the NETLINK_SOCK_DIAG per-state histogram
// through the netlinkx seam — pid 1 is the host init under
// hostPID:true, the same convention every /proc/1/net read in this
// file follows. A failed dump emits nothing: inconclusive, never a
// fabricated zero census.
func (c *Collector) collectTCPStates(ch chan<- prometheus.Metric) {
	states, err := c.cfg.TCPStatesFn(1)
	if err != nil {
		return
	}
	for _, s := range tcpStateNames {
		ch <- prometheus.MustNewConstMetric(descSockTCPState,
			prometheus.GaugeValue, float64(states[s.id]),
			c.cfg.NodeName, s.name)
	}
}

// ephemeralPortWidth returns the ip_local_port_range span — the
// count of ports the kernel picks source ports from. The sysctl
// file carries "<low> <high>"; an unreadable/malformed file or an
// inverted range yields the stock 28232-wide default (the kernel
// compiled value — the range can never be narrower in practice).
func ephemeralPortWidth(path string) float64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return defaultEphemeralPortWidth
	}
	f := strings.Fields(string(data))
	if len(f) < 2 {
		return defaultEphemeralPortWidth
	}
	lo, errL := strconv.ParseUint(f[0], 10, 32)
	hi, errH := strconv.ParseUint(f[1], 10, 32)
	if errL != nil || errH != nil || hi <= lo {
		return defaultEphemeralPortWidth
	}
	return float64(hi - lo + 1)
}

// hotTupleSockets is the roadmap A6 threshold: one (dstIP, dstPort)
// endpoint holding more than this many sockets has exhausted its
// 4-tuple space on any realistic ephemeral range (55k ports) —
// clients toward it EADDRNOTAVAIL while every node-wide socket
// gauge looks healthy.
const hotTupleSockets = 40000

// hexSockAddr decodes a /proc/net/tcp address column — 8 or 32 hex
// chars (IPv4/IPv6, little-endian per u32 word) + ":port" — into
// host order "a.b.c.d:port" / "[v6]:port". An unparseable column
// yields the raw string (never a metric value fabricated from a
// guess).
func hexSockAddr(s string) string {
	host, port, found := strings.Cut(s, ":")
	if !found {
		return s
	}
	raw, err := hex.DecodeString(host)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return s
	}
	pn, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return s
	}
	if len(raw) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d:%d", raw[3], raw[2], raw[1], raw[0], pn)
	}
	// tcp6 prints the 16 in6_addr bytes as four u32 words, EACH in
	// host (little-endian) byte order — the same per-word shuffle
	// the v4 column gets, applied inside every 4-byte group. A
	// contiguous decode yields a wrong address (::1 reads back as
	// ::100:0), so reverse each word before handing to net.IP.
	var v6 [16]byte
	for i := 0; i < 4; i++ {
		v6[i*4+0] = raw[i*4+3]
		v6[i*4+1] = raw[i*4+2]
		v6[i*4+2] = raw[i*4+1]
		v6[i*4+3] = raw[i*4+0]
	}
	return fmt.Sprintf("[%s]:%d", net.IP(v6[:]).String(), pn)
}

// hexNibble decodes one hex digit without a string conversion —
// the st column parse stays allocation-free like the field split.
func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// tcpTableScan is one streaming pass over the /proc/net/tcp{,6}
// socket tables: per-state totals (the CLOSE_WAIT count) and the
// per-remote-endpoint counts (the roadmap A6 tuple hot-spot).
// ok=false when NO table read at all — a single readable family
// still counts (an IPv6-less host legitimately lacks tcp6).
//
// Zero-alloc discipline: fields split off sc.Bytes() (subslice
// views, never strings.Fields' per-line allocation), the st column
// parses nibble-by-nibble, and perTuple keys on the RAW rem_address
// column — the map-key string conversion copies only for NEW
// endpoints, so a 200k-socket table costs ~endpoint-count
// allocations, not socket-count. hexSockAddr decode is deferred to
// emit time and runs only for endpoints past hotTupleSockets.
func tcpTableScan(paths ...string) (stateCounts map[byte]int,
	perTuple map[string]int, ok bool) {
	stateCounts = map[byte]int{}
	perTuple = map[string]int{}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		ok = true
		sc := bufio.NewScanner(f)
		first := true
		for sc.Scan() {
			if first {
				first = false
				continue // column header
			}
			fields := bytes.Fields(sc.Bytes())
			if len(fields) < 4 || len(fields[3]) > 2 {
				continue
			}
			// st is a <=2-digit hex byte — ParseUint's string
			// conversion would allocate per line; the nibble
			// loop does not.
			var st uint64
			bad := false
			for _, c := range fields[3] {
				v, ok := hexNibble(c)
				if !ok {
					bad = true
					break
				}
				st = st<<4 | uint64(v)
			}
			if bad || st > 0xff {
				continue // malformed line — never emit junk
			}
			stateCounts[byte(st)]++
			perTuple[string(fields[2])]++
		}
		_ = f.Close()
	}
	return stateCounts, perTuple, ok
}

// emitPerTupleHotspot publishes the per-endpoint socket counts:
// the max-tuple gauge every readable scrape, plus a labelled gauge
// per endpoint past hotTupleSockets only (the 40k roadmap
// threshold — bounded series, and an un-hot node keeps its
// exposition flat). perTuple keys are the scan's RAW rem_address
// columns; hexSockAddr decode runs here, only for the hot few.
func (c *Collector) emitPerTupleHotspot(ch chan<- prometheus.Metric,
	perTuple map[string]int) {
	max := 0
	for dst, n := range perTuple {
		if n > max {
			max = n
		}
		if n > hotTupleSockets {
			ch <- prometheus.MustNewConstMetric(descTCPPerTupleHot,
				prometheus.GaugeValue, float64(n), c.cfg.NodeName,
				hexSockAddr(dst))
		}
	}
	ch <- prometheus.MustNewConstMetric(descTCPPerTupleMax,
		prometheus.GaugeValue, float64(max), c.cfg.NodeName)
}
