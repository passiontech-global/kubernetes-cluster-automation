// collect_ebpf.go — ebpf-inventory eBPF program/map inventory: unique
// prog_id/map_id across /proc/<pid>/fdinfo/* plus pinned objects
// under the bpffs mount — zero forks, the leak-audit counters a
// cilium/eBPF map leak grows against. The fd walk itself lives in
// collect_fdlinks.go, shared singleflighted with the inotify census.
package hostmetrics

import (
	"strconv"
	"strings"
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

// scanBPFIDLines harvests prog_id:/map_id: lines from one fdinfo
// blob into the dedup sets — a link fd can list several prog_ids.
func scanBPFIDLines(data []byte, progs, maps map[uint64]bool) {
	for line := range strings.SplitSeq(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		id, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch strings.TrimSuffix(f[0], ":") {
		case "prog_id":
			progs[id] = true
		case "map_id":
			maps[id] = true
		}
	}
}

// ebpfFDTarget is the /proc/<pid>/fd/<fd> symlink-target prefix the
// kernel gives a bpf object fd (anon_inode:bpf-prog / bpf-map /
// bpf-link) — the cheap pre-filter that keeps the sweep from
// opening every fdinfo file on the host (inotify sweep parity).
const ebpfFDTarget = "anon_inode:bpf-"

// ebpfSnapshot returns the eBPF half of the shared fd-link sweep
// (collect_fdlinks.go), re-walking at most once per
// EBPFScanInterval. Unresolved pins fold into the maps count — the
// leak-audit headline (a cilium map-pin leak grows that series even
// when bpffs refuses the opens an id harvest would need). scanned
// mirrors the old sweep's verdict: the proc root OR the bpffs dir
// listed.
func (c *Collector) ebpfSnapshot() (progs, maps int, scanned bool) {
	res := c.fdLinkSnapshot(c.cfg.EBPFScanInterval)
	return len(res.progs), len(res.maps) + res.pins,
		res.procOK || res.bpffsOK
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
