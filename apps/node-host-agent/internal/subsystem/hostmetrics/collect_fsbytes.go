// collect_fsbytes.go — run-tmpfs tmpfs/data-fs byte fill ratio. The
// inode gauges in collect_fs.go can't see a tmpfs that fills by
// BYTES (host /run carrying containerd.sock/dbus sockets, /dev/shm,
// the k0s data dir, the OpenEBS local root) — a full /run kills
// every unix socket while df on / still shows space.
package hostmetrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

var descFSBytesRatio = prometheus.NewDesc(
	"node_host_agent_filesystem_bytes_used_ratio",
	"Used-block share of the probed mount (1 - Bavail/Blocks via statfs; emitted only when statfs succeeds).",
	[]string{"node", "mount"}, nil)

// collectFSBytes emits the used-byte ratio for each FSBytesTargets
// mount from the per-scrape probe answers Collect computed once
// (scrapeFSProbes — the same bounded deadline probe the inode domain
// uses; a hung mount wedges the syscall, so the probe must stay
// bounded). Unreachable mounts emit nothing (absent vs 0 stays
// distinguishable).
func (c *Collector) collectFSBytes(ch chan<- prometheus.Metric, sc scrapeCtx) {
	for _, mount := range c.cfg.FSBytesTargets {
		pr := sc.fs[mount]
		if !pr.ok || pr.st.Blocks == 0 {
			continue
		}
		st := pr.st
		if st.Bavail > st.Blocks {
			continue // pseudo-fs nonsense — never emit junk
		}
		used := float64(st.Blocks-st.Bavail) / float64(st.Blocks)
		ch <- prometheus.MustNewConstMetric(descFSBytesRatio,
			prometheus.GaugeValue, used, c.cfg.NodeName, mount)
	}
}
