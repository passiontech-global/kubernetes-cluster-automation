// collect_clock_conntrack.go — H1 clock sync (adjtimex) and the
// conntrack/ARP neighbour-table pressure signals (H2, conntrack-arp-pressure).
// Split out of hostmetrics.go.
package hostmetrics

import (
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
)

const (
	// H2 conntrack table sources.
	defaultConntrackCountFile = "/proc/sys/net/netfilter/nf_conntrack_count"
	defaultConntrackMaxFile   = "/proc/sys/net/netfilter/nf_conntrack_max"
	// telemetry sources: conntrack per-CPU stats + ARP table.
	defaultConntrackStatFile = "/proc/net/stat/nf_conntrack"
	defaultARPTableFile      = "/proc/net/arp"
	// Clocksource sources (sysfs clocksource0).
	defaultClocksourceCurrentFile   = "/sys/devices/system/clocksource/clocksource0/current_clocksource"
	defaultClocksourceAvailableFile = "/sys/devices/system/clocksource/clocksource0/available_clocksource"
)

// --- H1: clock sync (adjtimex) ---

// The gray-failure descs all carry the node label so a federated
// store can attribute them back to the agent host.
var (
	descClockUnsync = prometheus.NewDesc(
		"node_host_agent_clock_unsynchronized",
		"Kernel clock reports STA_UNSYNC via adjtimex (1 = not synchronized; emitted only when the syscall succeeds).",
		[]string{"node"}, nil)
	descClockEstErr = prometheus.NewDesc(
		"node_host_agent_clock_estimated_error_seconds",
		"adjtimex Timex.Esterror exported as seconds — the kernel's own bound on clock error.",
		[]string{"node"}, nil)
)

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
	ch <- prometheus.MustNewConstMetric(descClockUnsync,
		prometheus.GaugeValue, unsync, c.cfg.NodeName)
	// Timex.Esterror is microseconds — export seconds.
	ch <- prometheus.MustNewConstMetric(descClockEstErr,
		prometheus.GaugeValue, float64(tx.Esterror)/1e6, c.cfg.NodeName)
}

// --- Clocksource health ---

var descClocksourceNonTSC = prometheus.NewDesc(
	"node_host_agent_clocksource_non_tsc",
	"Kernel clocksource drifted off a fast vDSO-capable clock (1 = current is not tsc/kvm-clock despite one being available, or a slow fallback like hpet/acpi_pm/jiffies is active).",
	[]string{"node", "clocksource"}, nil)

// slowClocksources are the known-degraded fallback clocks — active
// use of one when a fast clock exists (or even when available
// unreadable) is the gray-failure signal. jiffies is listed because
// an active jiffies clocksource means the kernel never probed any
// hardware clock at all.
var slowClocksources = map[string]bool{
	"hpet": true, "acpi_pm": true, "jiffies": true,
}

// fastClocksources are the healthy vDSO-capable clocks — tsc on bare
// metal, kvm-clock on KVM guests. The drift gauge stays 0 only while
// one of these is active.
var fastClocksources = map[string]bool{
	"tsc": true, "kvm-clock": true,
}

// collectClocksource emits node_host_agent_clocksource_non_tsc and,
// when drifted, restores kvm-clock: on kernels where the
// hypervisor offers kvm-clock, an hpet/acpi_pm current_clocksource
// means the pvclock vDSO mapping was lost (host suspend/migration)
// — writing "kvm-clock" back re-arms the fast vDSO path. Idempotent:
// the write happens only when the drift condition holds.
func (c *Collector) collectClocksource(ch chan<- prometheus.Metric) {
	curB, err := os.ReadFile(c.cfg.ClocksourceCurrentFile)
	if err != nil {
		return // inconclusive — absent series, no fake 0
	}
	current := strings.TrimSpace(string(curB))
	availB, availErr := os.ReadFile(c.cfg.ClocksourceAvailableFile)

	var degraded bool
	if availErr == nil {
		available := map[string]bool{}
		for _, f := range strings.Fields(string(availB)) {
			available[f] = true
		}
		// Degraded only when a fast clock the hardware COULD offer
		// is not the active one — an arch without tsc/kvm-clock in
		// available (bare metal without invariant TSC, some ARM)
		// stays 0, never a false positive, and an active kvm-clock
		// (the desired clock on KVM guests) is healthy too.
		degraded = !fastClocksources[current] &&
			(available["tsc"] || available["kvm-clock"])
		// Restore path: a slow fallback with kvm-clock available is
		// exactly the lost-pvclock-vDSO drift — write it back.
		if slowClocksources[current] && available["kvm-clock"] {
			if err := os.WriteFile(c.cfg.ClocksourceCurrentFile,
				[]byte("kvm-clock\n"), 0o644); err != nil {
				logger().Warn("hostmetrics: clocksource kvm-clock restore write failed",
					"path", c.cfg.ClocksourceCurrentFile, "error", err)
			} else {
				logger().Warn("hostmetrics: clocksource drifted to "+current+
					" — restored kvm-clock", "path", c.cfg.ClocksourceCurrentFile)
			}
		}
	} else {
		// available unreadable: fall back to the current-clock name
		// alone — an active hpet/acpi_pm/jiffies is degraded; tsc or
		// anything unknown stays 0.
		degraded = slowClocksources[current]
	}
	v := 0.0
	if degraded {
		v = 1
	}
	ch <- prometheus.MustNewConstMetric(descClocksourceNonTSC,
		prometheus.GaugeValue, v, c.cfg.NodeName, current)
}

// --- H2: conntrack table pressure ---

var (
	descCtEntries = prometheus.NewDesc(
		"node_host_agent_conntrack_entries",
		"nf_conntrack_count — conntrack table entries currently tracked.",
		[]string{"node"}, nil)
	descCtLimit = prometheus.NewDesc(
		"node_host_agent_conntrack_limit",
		"nf_conntrack_max — conntrack table capacity.",
		[]string{"node"}, nil)
	descCtRatio = prometheus.NewDesc(
		"node_host_agent_conntrack_used_ratio",
		"Conntrack table fill ratio (entries/limit; emitted only when both files parse and limit > 0).",
		[]string{"node"}, nil)
	// conntrack-arp-pressure conntrack per-CPU stat counters + ARP table fill.
	descCtInsertFail = prometheus.NewDesc(
		"node_host_agent_conntrack_insert_failed_total",
		"Sum of the insert_failed column across all CPU rows of /proc/net/stat/nf_conntrack (UDP tuple-collision drops).",
		[]string{"node"}, nil)
	descCtDrops = prometheus.NewDesc(
		"node_host_agent_conntrack_drops_total",
		"Sum of the drop column across all CPU rows of /proc/net/stat/nf_conntrack.",
		[]string{"node"}, nil)
	// conntrack-port-pressure: the same counters under the node_exporter
	// nf_conntrack collector names — dashboards/alerts written for
	// node_exporter's conntrack module then port over without
	// translation. drop folds in early_drop: both count packets the
	// table refused (early_drop is the LRU eviction that still
	// loses the flow). CounterValue like the host_agent twins —
	// cumulative kernel counters.
	descCtStatInsertFail = prometheus.NewDesc(
		"node_nf_conntrack_stat_insert_failed_total",
		"Sum of the insert_failed column across all CPU rows of /proc/net/stat/nf_conntrack.",
		[]string{"node"}, nil)
	descCtStatDrop = prometheus.NewDesc(
		"node_nf_conntrack_stat_drop_total",
		"Sum of the drop + early_drop columns across all CPU rows of /proc/net/stat/nf_conntrack.",
		[]string{"node"}, nil)
	// Conntrack health: search_restart grows when a conntrack lookup has to
	// restart because the entry moved between buckets (hash-chain
	// contention under NAT-heavy workloads); invalid counts protocol
	// checks that rejected a packet's conntrack state.
	descCtSearchRestarts = prometheus.NewDesc(
		"node_host_agent_conntrack_search_restarts_total",
		"Sum of the search_restart column across all CPU rows of /proc/net/stat/nf_conntrack.",
		[]string{"node"}, nil)
	descCtInvalid = prometheus.NewDesc(
		"node_host_agent_conntrack_invalid_total",
		"Sum of the invalid column across all CPU rows of /proc/net/stat/nf_conntrack.",
		[]string{"node"}, nil)
)

// collectConntrack emits entries/limit each only when its own file
// parses (a node without the conntrack module has no files → absent
// series, not a fake 0) and the ratio only when both parsed and the
// limit is non-zero.
func (c *Collector) collectConntrack(ch chan<- prometheus.Metric) {
	count, countOK := hostutil.ReadUintFile(c.cfg.ConntrackCountFile)
	limit, limitOK := hostutil.ReadUintFile(c.cfg.ConntrackMaxFile)
	if countOK {
		ch <- prometheus.MustNewConstMetric(descCtEntries,
			prometheus.GaugeValue, float64(count), c.cfg.NodeName)
	}
	if limitOK {
		ch <- prometheus.MustNewConstMetric(descCtLimit,
			prometheus.GaugeValue, float64(limit), c.cfg.NodeName)
	}
	if countOK && limitOK && limit > 0 {
		ch <- prometheus.MustNewConstMetric(descCtRatio,
			prometheus.GaugeValue,
			float64(count)/float64(limit), c.cfg.NodeName)
	}
	// conntrack-arp-pressure: the per-CPU stat counters — insert_failed grows on the
	// UDP source-port tuple collision (A+AAAA race) long before the
	// table fills; drop counts the packets conntrack refused. Both
	// are cumulative kernel counters → CounterValue.
	if st, ok := conntrackStatCounters(c.cfg.ConntrackStatFile,
		"insert_failed", "drop", "early_drop", "search_restart", "invalid"); ok {
		if v, found := st["insert_failed"]; found {
			ch <- prometheus.MustNewConstMetric(descCtInsertFail,
				prometheus.CounterValue, float64(v), c.cfg.NodeName)
			ch <- prometheus.MustNewConstMetric(descCtStatInsertFail,
				prometheus.CounterValue, float64(v), c.cfg.NodeName)
		}
		// The legacy drops series stays strictly drop-column — a
		// kernel exposing only early_drop must not fabricate a 0
		// here; the node_exporter-named twin folds both columns.
		if v, found := st["drop"]; found {
			ch <- prometheus.MustNewConstMetric(descCtDrops,
				prometheus.CounterValue, float64(v), c.cfg.NodeName)
		}
		drops, dropOK := st["drop"]
		if v, found := st["early_drop"]; found {
			drops, dropOK = drops+v, true
		}
		if dropOK {
			ch <- prometheus.MustNewConstMetric(descCtStatDrop,
				prometheus.CounterValue, float64(drops), c.cfg.NodeName)
		}
		// Hash-chain contention and invalid-state counters —
		// each emitted only when its own column exists (an older
		// kernel missing the column → absent series, no fake 0).
		if v, found := st["search_restart"]; found {
			ch <- prometheus.MustNewConstMetric(descCtSearchRestarts,
				prometheus.CounterValue, float64(v), c.cfg.NodeName)
		}
		if v, found := st["invalid"]; found {
			ch <- prometheus.MustNewConstMetric(descCtInvalid,
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

var descARPEntries = prometheus.NewDesc(
	"node_host_agent_arp_entries",
	"Entries in /proc/net/arp — ARP neighbour-table fill vs gc_thresh headroom.",
	[]string{"node"}, nil)

// collectARP counts /proc/net/arp entry rows (header skipped) — the
// ARP neighbour-table fill half of conntrack-arp-pressure (gc_thresh overflow drops
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
	ch <- prometheus.MustNewConstMetric(descARPEntries,
		prometheus.GaugeValue, n, c.cfg.NodeName)
}
