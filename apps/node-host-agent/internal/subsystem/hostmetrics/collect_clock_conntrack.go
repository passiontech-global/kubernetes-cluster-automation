// collect_clock_conntrack.go — H1 clock sync (adjtimex) and the
// conntrack/ARP neighbour-table pressure signals (H2, W7-H5).
// Split out of hostmetrics.go.
package hostmetrics

import (
	"os"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/hostutil"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
)

const (
	// H2 conntrack table sources.
	defaultConntrackCountFile = "/proc/sys/net/netfilter/nf_conntrack_count"
	defaultConntrackMaxFile   = "/proc/sys/net/netfilter/nf_conntrack_max"
	// W7 sources: H5 conntrack per-CPU stats + ARP table.
	defaultConntrackStatFile = "/proc/net/stat/nf_conntrack"
	defaultARPTableFile      = "/proc/net/arp"
)

// --- H1: clock sync (adjtimex) ---

// collectClock emits the clock-sync gauges only when adjtimex
// succeeds — an absent series means the syscall failed
// (inconclusive), never a fake "synchronized" 0.
func (c *Collector) collectClock(ch chan<- prometheus.Metric) {
	var tx unix.Timex
	if _, err := c.cfg.adjtimexFn(&tx); err != nil {
		return
	}
	unsync := 0.0
	if tx.Status&unix.STA_UNSYNC != 0 {
		unsync = 1
	}
	ch <- prometheus.MustNewConstMetric(c.descClockUnsync,
		prometheus.GaugeValue, unsync, c.cfg.NodeName)
	// Timex.Esterror is microseconds — export seconds.
	ch <- prometheus.MustNewConstMetric(c.descClockEstErr,
		prometheus.GaugeValue, float64(tx.Esterror)/1e6, c.cfg.NodeName)
}

// --- H2: conntrack table pressure ---

// collectConntrack emits entries/limit each only when its own file
// parses (a node without the conntrack module has no files → absent
// series, not a fake 0) and the ratio only when both parsed and the
// limit is non-zero.
func (c *Collector) collectConntrack(ch chan<- prometheus.Metric) {
	count, countOK := hostutil.ReadUintFile(c.cfg.ConntrackCountFile)
	limit, limitOK := hostutil.ReadUintFile(c.cfg.ConntrackMaxFile)
	if countOK {
		ch <- prometheus.MustNewConstMetric(c.descCtEntries,
			prometheus.GaugeValue, float64(count), c.cfg.NodeName)
	}
	if limitOK {
		ch <- prometheus.MustNewConstMetric(c.descCtLimit,
			prometheus.GaugeValue, float64(limit), c.cfg.NodeName)
	}
	if countOK && limitOK && limit > 0 {
		ch <- prometheus.MustNewConstMetric(c.descCtRatio,
			prometheus.GaugeValue,
			float64(count)/float64(limit), c.cfg.NodeName)
	}
	// W7-H5: the per-CPU stat counters — insert_failed grows on the
	// UDP source-port tuple collision (A+AAAA race) long before the
	// table fills; drop counts the packets conntrack refused. Both
	// are cumulative kernel counters → CounterValue.
	if st, ok := conntrackStatCounters(c.cfg.ConntrackStatFile,
		"insert_failed", "drop"); ok {
		if v, found := st["insert_failed"]; found {
			ch <- prometheus.MustNewConstMetric(c.descCtInsertFail,
				prometheus.CounterValue, float64(v), c.cfg.NodeName)
		}
		if v, found := st["drop"]; found {
			ch <- prometheus.MustNewConstMetric(c.descCtDrops,
				prometheus.CounterValue, float64(v), c.cfg.NodeName)
		}
	}
}

// conntrackStatCounters parses /proc/net/stat/nf_conntrack — a
// header line of column names followed by one HEX value row per
// CPU; the named columns are summed across all CPUs. ok=false when
// the file is unreadable or the header carries none of the wanted
// columns (conntrack module absent → absent series, no fake 0).
func conntrackStatCounters(path string, keys ...string) (map[string]uint64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		return nil, false
	}
	header := strings.Fields(lines[0])
	idx := map[string]int{}
	for _, k := range keys {
		for i, name := range header {
			if name == k {
				idx[k] = i
			}
		}
	}
	if len(idx) == 0 {
		return nil, false
	}
	out := map[string]uint64{}
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) != len(header) {
			continue // malformed CPU row — never emit junk
		}
		for k, i := range idx {
			if v, err := strconv.ParseUint(f[i], 16, 64); err == nil {
				out[k] += v
			}
		}
	}
	return out, true
}

// collectARP counts /proc/net/arp entry rows (header skipped) — the
// ARP neighbour-table fill half of W7-H5 (gc_thresh overflow drops
// outbound packets while every other signal stays green). Emits
// only when the file reads.
func (c *Collector) collectARP(ch chan<- prometheus.Metric) {
	data, err := os.ReadFile(c.cfg.ARPTableFile)
	if err != nil {
		return
	}
	var n float64
	for i, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if i == 0 || len(strings.Fields(line)) == 0 {
			continue
		}
		n++
	}
	ch <- prometheus.MustNewConstMetric(c.descARPEntries,
		prometheus.GaugeValue, n, c.cfg.NodeName)
}
