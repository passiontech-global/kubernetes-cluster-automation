// collect_filefd_sockstat.go — H6 fd + socket pressure:
// /proc/sys/fs/file-nr and /proc/1/net/sockstat. Split out of
// hostmetrics.go.
package hostmetrics

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	// H6 fd/socket sources.
	defaultFileNRFile   = "/proc/sys/fs/file-nr"
	defaultSockstatFile = "/proc/1/net/sockstat"
	// Tcp-level grey-failure sources — the kernel TCP/IP stack
	// counters node_exporter's netstat collector exposes. Read via
	// /proc/1/net (host netns through the init pid — same path
	// sockstat uses, and hostPID makes it the host view anyway).
	defaultNetstatFile = "/proc/1/net/netstat"
	defaultSNMPFile    = "/proc/1/net/snmp"
	// W12-KR3 sources: the ephemeral source-port range the
	// sockstat saturation ratio divides by, and the per-socket
	// tables the CLOSE_WAIT count scans (host netns via /proc/1).
	defaultLocalPortRangeFile = "/proc/sys/net/ipv4/ip_local_port_range"
	defaultProcNetTCP         = "/proc/1/net/tcp"
	defaultProcNetTCP6        = "/proc/1/net/tcp6"
	// defaultEphemeralPortWidth is the kernel's stock
	// ip_local_port_range span (32768-60999) — the fallback when
	// the sysctl itself can't be read (hostconfig widens it to
	// 10240-65535 = 55296).
	defaultEphemeralPortWidth = 28232
)

// --- H6: FD + socket pressure (file-nr, sockstat) ---

var (
	descFileFDAlloc = prometheus.NewDesc(
		"node_host_agent_filefd_allocated",
		"file-nr field 0 — file handles currently allocated.",
		[]string{"node"}, nil)
	descFileFDMax = prometheus.NewDesc(
		"node_host_agent_filefd_maximum",
		"file-nr field 2 — file handle limit.",
		[]string{"node"}, nil)
	descFileFDRatio = prometheus.NewDesc(
		"node_host_agent_filefd_used_ratio",
		"file-nr allocated/maximum (emitted only when file-nr parses and max > 0).",
		[]string{"node"}, nil)
	descSockTCPInuse = prometheus.NewDesc(
		"node_host_agent_sockstat_tcp_inuse",
		"sockstat TCP inuse — TCP sockets in use.",
		[]string{"node"}, nil)
	descSockTCPOrphan = prometheus.NewDesc(
		"node_host_agent_sockstat_tcp_orphan",
		"sockstat TCP orphan — orphaned (not attached to a socket) TCP connections.",
		[]string{"node"}, nil)
	descSockTCPTW = prometheus.NewDesc(
		"node_host_agent_sockstat_tcp_tw",
		"sockstat TCP tw — TCP sockets in TIME_WAIT.",
		[]string{"node"}, nil)
	descSockUsed = prometheus.NewDesc(
		"node_host_agent_sockstat_sockets_used",
		"sockstat 'sockets: used' — total sockets in use across protocols.",
		[]string{"node"}, nil)
	// W8: TCP close_wait — sockets stuck half-closed waiting for
	// local close().
	descSockTCPCW = prometheus.NewDesc(
		"node_host_agent_sockstat_tcp_close_wait",
		"sockstat TCP close_wait — sockets stuck half-closed waiting for local close().",
		[]string{"node"}, nil)
	// W12-KR3: ephemeral source-port saturation — (inuse + tw) over
	// the ip_local_port_range width. Past ~0.8 every new connect()
	// risks EADDRNOTAVAIL, which applications report as generic
	// "network is down" (the Cloudflare/Haplon/Envoy incident shape).
	descEphemeralPortSat = prometheus.NewDesc(
		"node_sockstat_ephemeral_port_saturation_ratio",
		"sockstat TCP inuse+tw divided by the ip_local_port_range width — ephemeral source-port pool saturation.",
		[]string{"node"}, nil)
	// W12-KR3: the per-socket CLOSE_WAIT count. sockstat doesn't
	// break the state out on every kernel, so /proc/1/net/tcp{,6}
	// is scanned directly — a growing count is a userspace
	// connection leak (linkerd-proxy/cilium-envoy class).
	descTCPCloseWaitSocks = prometheus.NewDesc(
		"node_tcp_close_wait_sockets",
		"Sockets in TCP_CLOSE_WAIT (state 08) across /proc/1/net/tcp and /proc/1/net/tcp6.",
		[]string{"node"}, nil)
	// Kernel TCP/IP stack counters (netstat TcpExt + snmp Ip/Udp) —
	// listen-queue overflows/drops present as accept flakes,
	// syn-retrans and timeouts as connect flakes, reassembly fails
	// as fragment loss, RcvbufErrors as UDP buffer exhaustion.
	descNetstatListenOverflows = prometheus.NewDesc(
		"node_host_agent_netstat_tcp_listen_overflows_total",
		"TcpExt ListenOverflows — SYNs dropped because the accept queue was full.",
		[]string{"node"}, nil)
	descNetstatListenDrops = prometheus.NewDesc(
		"node_host_agent_netstat_tcp_listen_drops_total",
		"TcpExt ListenDrops — connections dropped from a full listen backlog.",
		[]string{"node"}, nil)
	descNetstatSynRetrans = prometheus.NewDesc(
		"node_host_agent_netstat_tcp_syn_retrans_total",
		"TcpExt TCPSynRetrans — retransmitted SYNs.",
		[]string{"node"}, nil)
	descNetstatTCPTimeouts = prometheus.NewDesc(
		"node_host_agent_netstat_tcp_timeouts_total",
		"TcpExt TCPTimeouts — connections that timed out in any state.",
		[]string{"node"}, nil)
	descSNMPReasmFails = prometheus.NewDesc(
		"node_host_agent_snmp_ip_reasm_fails_total",
		"Ip ReasmFails — IP fragment reassembly failures.",
		[]string{"node"}, nil)
	descSNMPRcvbufErrors = prometheus.NewDesc(
		"node_host_agent_snmp_udp_rcvbuf_errors_total",
		"Udp RcvbufErrors — UDP datagrams dropped on a full receive buffer.",
		[]string{"node"}, nil)
)

// collectFileFD parses /proc/sys/fs/file-nr — "allocated unused
// max" (fields 0 and 2; the middle "unused" field is always ~0 on
// modern kernels). Absent/malformed → no series.
func (c *Collector) collectFileFD(ch chan<- prometheus.Metric) {
	data, err := os.ReadFile(c.cfg.FileNRFile)
	if err != nil {
		return
	}
	f := strings.Fields(string(data))
	if len(f) < 3 {
		return
	}
	alloc, errA := strconv.ParseFloat(f[0], 64)
	maxFD, errM := strconv.ParseFloat(f[2], 64)
	if errA != nil || errM != nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(descFileFDAlloc,
		prometheus.GaugeValue, alloc, c.cfg.NodeName)
	ch <- prometheus.MustNewConstMetric(descFileFDMax,
		prometheus.GaugeValue, maxFD, c.cfg.NodeName)
	if maxFD > 0 {
		ch <- prometheus.MustNewConstMetric(descFileFDRatio,
			prometheus.GaugeValue, alloc/maxFD, c.cfg.NodeName)
	}
}

// collectSockstat parses /proc/1/net/sockstat — section lines of
// "NAME: key N key N ..." pairs ("sockets: used 1847",
// "TCP: inuse 25 orphan 0 tw 4 alloc 1200 mem 456"). Each gauge
// emits only when its key parsed — a node missing a section keeps
// that series absent rather than 0.
func (c *Collector) collectSockstat(ch chan<- prometheus.Metric) {
	// W12-KR3: the CLOSE_WAIT count comes from the per-socket
	// tables, NOT sockstat — it must emit even when the sockstat
	// file itself is absent, so it runs before the early return.
	// ok=false only when NO family table read (a node with neither
	// file is inconclusive, not empty).
	if cw, ok := tcpStateCount(0x08,
		c.cfg.ProcNetTCP, c.cfg.ProcNetTCP6); ok {
		ch <- prometheus.MustNewConstMetric(descTCPCloseWaitSocks,
			prometheus.GaugeValue, cw, c.cfg.NodeName)
	}
	f, err := os.Open(c.cfg.SockstatFile)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	var tcpInuse, tcpOrphan, tcpTW, tcpCW, sockUsed float64
	var tcpInuseOK, tcpOrphanOK, tcpTWOK, tcpCWOK, sockUsedOK bool
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// "NAME:" + an even number of key/value fields → odd total.
		if len(fields) < 3 || len(fields)%2 == 0 {
			continue
		}
		kv := make(map[string]float64, len(fields)/2)
		good := true
		for i := 1; i+1 < len(fields); i += 2 {
			v, err := strconv.ParseFloat(fields[i+1], 64)
			if err != nil {
				good = false
				break
			}
			kv[fields[i]] = v
		}
		if !good {
			continue // malformed line — never emit junk
		}
		switch strings.TrimSuffix(fields[0], ":") {
		case "TCP":
			if v, ok := kv["inuse"]; ok {
				tcpInuse, tcpInuseOK = v, true
			}
			if v, ok := kv["orphan"]; ok {
				tcpOrphan, tcpOrphanOK = v, true
			}
			if v, ok := kv["tw"]; ok {
				tcpTW, tcpTWOK = v, true
			}
			// close_wait/cw — kernels that report it carry hung
			// half-closed sockets here (W8-KR3 companion metric).
			if v, ok := kv["close_wait"]; ok {
				tcpCW, tcpCWOK = v, true
			} else if v, ok := kv["cw"]; ok {
				tcpCW, tcpCWOK = v, true
			}
		case "sockets":
			if v, ok := kv["used"]; ok {
				sockUsed, sockUsedOK = v, true
			}
		}
	}
	if sockUsedOK {
		ch <- prometheus.MustNewConstMetric(descSockUsed,
			prometheus.GaugeValue, sockUsed, c.cfg.NodeName)
	}
	if tcpInuseOK {
		ch <- prometheus.MustNewConstMetric(descSockTCPInuse,
			prometheus.GaugeValue, tcpInuse, c.cfg.NodeName)
	}
	if tcpOrphanOK {
		ch <- prometheus.MustNewConstMetric(descSockTCPOrphan,
			prometheus.GaugeValue, tcpOrphan, c.cfg.NodeName)
	}
	if tcpTWOK {
		ch <- prometheus.MustNewConstMetric(descSockTCPTW,
			prometheus.GaugeValue, tcpTW, c.cfg.NodeName)
	}
	if tcpCWOK {
		ch <- prometheus.MustNewConstMetric(descSockTCPCW,
			prometheus.GaugeValue, tcpCW, c.cfg.NodeName)
	}
	// W12-KR3: ephemeral source-port saturation. The ratio needs
	// both sockstat legs (inuse + tw) — a partial read stays absent
	// rather than emit a falsely-low value. An unreadable sysctl
	// falls back to the kernel's stock 28232-wide range so the
	// series still reflects the compiled-in limit.
	if tcpInuseOK && tcpTWOK {
		width := ephemeralPortWidth(c.cfg.LocalPortRangeFile)
		ch <- prometheus.MustNewConstMetric(descEphemeralPortSat,
			prometheus.GaugeValue, (tcpInuse+tcpTW)/width, c.cfg.NodeName)
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

// tcpStateCount scans the /proc/net/tcp{,6} socket tables and
// counts entries whose `st` column (field 3, hex TCP state) equals
// state. ok=false when NO table read at all — a single readable
// family still counts (an IPv6-less host legitimately lacks
// tcp6).
func tcpStateCount(state byte, paths ...string) (float64, bool) {
	want := string([]byte{
		"0123456789ABCDEF"[state>>4], "0123456789ABCDEF"[state&0x0f]})
	var n float64
	var ok bool
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		ok = true
		for i, line := range strings.Split(string(data), "\n") {
			if i == 0 {
				continue // column header
			}
			f := strings.Fields(line)
			if len(f) > 3 && f[3] == want {
				n++
			}
		}
	}
	return n, ok
}

// --- netstat/snmp kernel TCP/IP counters ---

// parseNetstatPairs parses the two-line <Section>: key... /
// <Section>: val... pairs of /proc/1/net/{netstat,snmp} into
// per-section key→value maps (e.g. TcpExt: ListenOverflows 12 ...).
// A values line with a different field count than its header is
// skipped — never emit junk.
func parseNetstatPairs(data string) map[string]map[string]float64 {
	out := map[string]map[string]float64{}
	var pending string
	var pendingKeys []string
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		sect := strings.TrimSuffix(f[0], ":")
		if pending == sect && len(f) == len(pendingKeys)+1 {
			kv := make(map[string]float64, len(pendingKeys))
			good := true
			for i, k := range pendingKeys {
				v, err := strconv.ParseFloat(f[i+1], 64)
				if err != nil {
					good = false
					break
				}
				kv[k] = v
			}
			if good {
				out[sect] = kv
			}
			pending = ""
			continue
		}
		pending, pendingKeys = sect, f[1:]
	}
	return out
}

// collectNetstatSNMP emits the six kernel TCP/IP counters from
// /proc/1/net/netstat (TcpExt) and /proc/1/net/snmp (Ip/Udp) — each
// only when its key parses, same per-source rule as sockstat.
func (c *Collector) collectNetstatSNMP(ch chan<- prometheus.Metric) {
	if data, err := os.ReadFile(c.cfg.NetstatFile); err == nil {
		kv := parseNetstatPairs(string(data))["TcpExt"]
		emit := func(d *prometheus.Desc, key string) {
			if v, ok := kv[key]; ok {
				ch <- prometheus.MustNewConstMetric(d,
					prometheus.CounterValue, v, c.cfg.NodeName)
			}
		}
		emit(descNetstatListenOverflows, "ListenOverflows")
		emit(descNetstatListenDrops, "ListenDrops")
		emit(descNetstatSynRetrans, "TCPSynRetrans")
		emit(descNetstatTCPTimeouts, "TCPTimeouts")
	}
	if data, err := os.ReadFile(c.cfg.SNMPFile); err == nil {
		kv := parseNetstatPairs(string(data))
		if v, ok := kv["Ip"]["ReasmFails"]; ok {
			ch <- prometheus.MustNewConstMetric(descSNMPReasmFails,
				prometheus.CounterValue, v, c.cfg.NodeName)
		}
		if v, ok := kv["Udp"]["RcvbufErrors"]; ok {
			ch <- prometheus.MustNewConstMetric(descSNMPRcvbufErrors,
				prometheus.CounterValue, v, c.cfg.NodeName)
		}
	}
}
