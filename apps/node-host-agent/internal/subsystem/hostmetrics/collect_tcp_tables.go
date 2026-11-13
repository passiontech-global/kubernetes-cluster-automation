// collect_tcp_tables.go — kernel TCP table census: the 1-pass
// NETLINK_SOCK_DIAG read behind the state histogram + per-tuple
// hot-spot emission and the ephemeral-port width gauge. Split out of
// collect_filefd_sockstat.go — the fd/sockstat/netstat counters
// stay there; this file owns the connection-table evidence. The
// census's ONE dump also feeds CLOSE_WAIT and the tuple hot-spot
// (collectSockstat calls into it), replacing the /proc/net/tcp{,6}
// text scan those used to run.

package hostmetrics

import (
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/netlinkx"
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

// collectTCPCensus emits the one-dump NETLINK_SOCK_DIAG census
// through the netlinkx seam — pid 1 is the host init under
// hostPID:true, the same convention every /proc/1/net read in this
// file follows: the per-state histogram, the CLOSE_WAIT gauge and
// the per-tuple hot-spot gauges all fold from the same
// TCPCensus. A failed dump emits nothing: inconclusive, never a
// fabricated zero census.
func (c *Collector) collectTCPCensus(ch chan<- prometheus.Metric) {
	census, err := c.cfg.TCPCensusFn(1)
	if err != nil {
		return
	}
	// conntrack-port-pressure: the CLOSE_WAIT count rides the same
	// dump — it must emit even when the sockstat file itself is
	// absent, exactly as the /proc-table read did.
	ch <- prometheus.MustNewConstMetric(descTCPCloseWaitSocks,
		prometheus.GaugeValue, float64(census.States[0x08]), c.cfg.NodeName)
	c.emitPerTupleHotspot(ch, census.PerTuple)
	for _, s := range tcpStateNames {
		ch <- prometheus.MustNewConstMetric(descSockTCPState,
			prometheus.GaugeValue, float64(census.States[s.id]),
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

// emitPerTupleHotspot publishes the per-endpoint socket counts:
// the max-tuple gauge every readable scrape, plus a labelled gauge
// per endpoint past hotTupleSockets only (the 40k roadmap
// threshold — bounded series, and an un-hot node keeps its
// exposition flat). perTuple keys are the census dump's RAW
// daddr+dport bytes; netlinkx.DiagEndpoint decode runs here, only
// for the hot few.
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
				netlinkx.DiagEndpoint(dst))
		}
	}
	ch <- prometheus.MustNewConstMetric(descTCPPerTupleMax,
		prometheus.GaugeValue, float64(max), c.cfg.NodeName)
}
