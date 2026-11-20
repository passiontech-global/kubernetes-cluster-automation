// collect_ebpf.go — ebpf-inventory eBPF program/map inventory: unique
// prog_id/map_id across /proc/<pid>/fdinfo/* plus pinned objects
// under the bpffs mount — zero forks, the leak-audit counters a
// cilium/eBPF map leak grows against. The fd walk itself lives in
// collect_fdlinks.go, shared singleflighted with the inotify census.
package hostmetrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	// defaultEBPFScanInterval caches the fdinfo sweep — a full
	// /proc/*/fdinfo walk per scrape is too heavy (inotify parity).
	defaultEBPFScanInterval = 60 * time.Second
	defaultBpffsDir         = "/sys/fs/bpf"
)

var (
	descEBPFProgs = prometheus.NewDesc(
		"node_host_agent_ebpf_programs_count",
		"Unique eBPF prog_id referenced by /proc/<pid>/fdinfo.",
		[]string{"node"}, nil)
	descEBPFMaps = prometheus.NewDesc(
		"node_host_agent_ebpf_maps_count",
		"Unique eBPF map_id referenced by /proc/<pid>/fdinfo plus objects pinned in bpffs (a pin bpffs refuses to open counts once — the leak-audit signal).",
		[]string{"node"}, nil)
)

// ebpfSnapshotAt returns the eBPF half of the shared procfs.FDCache
// snapshot plus the cached bpffs pin count, re-walking at most once per
// EBPFScanInterval. Unresolved pins fold into the maps count — the
// leak-audit headline (a cilium map-pin leak grows that series even
// when bpffs refuses the opens an id harvest would need). A missing or
// partial proc walk (!snap.ProcOK || snap.Partial) returns scanned=false
// even when bpffsOK is true so neither collectEBPF emits bogus zero
// gauges nor kernelfail/updateEBPFPressure falsely resets ebpfStreak or
// clears LatchEBPFPressure. at is snap.At (the proc snapshot's stamp):
// a latch ticker running faster than the sweep must not count the same
// snapshot as fresh evidence N times (Wave-5 P0 — a 30s ticker
// re-reading a 60s cache latched after 3 ticks instead of 3 real scans).
func (c *Collector) ebpfSnapshotAt() (progs, maps int, scanned bool, at time.Time) {
	snap := c.fdCache().Snapshot(c.cfg.EBPFScanInterval)
	if snap == nil || !snap.ProcOK || snap.Partial {
		return 0, 0, false, time.Time{}
	}
	pins, _ := c.bpffsPins(c.cfg.EBPFScanInterval)
	return len(snap.BPFProgs), len(snap.BPFMaps) + pins,
		true, snap.At
}

// ebpfSnapshot is the metric-side wrapper — the collector emits every
// scrape and does not care about the stamp; only the latch consumer
// uses ebpfSnapshotAt.
func (c *Collector) ebpfSnapshot() (progs, maps int, scanned bool) {
	progs, maps, scanned, _ = c.ebpfSnapshotAt()
	return progs, maps, scanned
}

// collectEBPF emits the unique-id counts — 0 is real data (a node
// whose cilium datapath failed to load carries no programs), so the
// series emits whenever either source scanned.
func (c *Collector) collectEBPF(ch chan<- prometheus.Metric) {
	progs, maps, ok := c.ebpfSnapshot()
	if !ok {
		return
	}
	ch <- prometheus.MustNewConstMetric(descEBPFProgs,
		prometheus.GaugeValue, float64(progs), c.cfg.NodeName)
	ch <- prometheus.MustNewConstMetric(descEBPFMaps,
		prometheus.GaugeValue, float64(maps), c.cfg.NodeName)
}
