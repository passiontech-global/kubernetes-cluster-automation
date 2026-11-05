// collect_localpv.go — W9 OpenEBS LocalPV per-PVC dir bytes: a
// bounded du walk cached for LocalPVScanInterval. Split out of
// hostmetrics.go.
package hostmetrics

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	// W9 LocalPV telemetry: the openebs localpv-provisioner
	// hostPath root + the du-walk cache TTL + per-volume entry cap.
	defaultOpenEBSLocalDir  = "/var/openebs/local"
	defaultLocalPVScanEvery = 15 * time.Minute
	localPVMaxWalkEntries   = 20000
)

// --- W9: OpenEBS LocalPV per-PVC dir bytes ---

// collectLocalPVUsage emits node_host_agent_localpv_dir_bytes per
// pvc-* volume dir under OpenEBSLocalDir. The du walk is cached
// for LocalPVScanInterval — a node with hundreds of LocalPVs would
// otherwise pay a full filesystem walk per PVC per scrape. A
// missing/unreadable root emits nothing (absent, not 0 — "no
// local-path volumes here" must stay distinguishable from "zero
// bytes").
func (c *Collector) collectLocalPVUsage(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	fresh := c.lpvBytes != nil &&
		c.cfg.nowFn().Sub(c.lpvAt) < c.cfg.LocalPVScanInterval
	cached := c.lpvBytes
	c.mu.Unlock()
	bytes := cached
	if !fresh {
		if walked := c.walkLocalPVDirs(); walked != nil {
			c.mu.Lock()
			c.lpvBytes = walked
			c.lpvAt = c.cfg.nowFn()
			c.mu.Unlock()
			bytes = walked
		}
		// A failed walk (root unreadable) keeps serving the last
		// good snapshot rather than blanking every series.
	}
	for pvc, b := range bytes {
		ch <- prometheus.MustNewConstMetric(c.descLocalPVDirBytes,
			prometheus.GaugeValue, float64(b), c.cfg.NodeName, pvc)
	}
}

// walkLocalPVDirs sums the bytes under every pvc-* dir in
// OpenEBSLocalDir. Returns nil when the root can't be listed —
// callers keep the previous cache. Each volume's walk is bounded
// at localPVMaxWalkEntries entries: a runaway PVC with millions of
// files must not stall the scrape; the emitted count is then a
// partial sum (documented on the metric).
func (c *Collector) walkLocalPVDirs() map[string]int64 {
	entries, err := os.ReadDir(c.cfg.OpenEBSLocalDir)
	if err != nil {
		if !os.IsNotExist(err) {
			logger().Debug("hostmetrics: openebs local dir unreadable — "+
				"localpv metrics keep previous snapshot",
				"dir", c.cfg.OpenEBSLocalDir, "error", err)
		}
		return nil
	}
	out := map[string]int64{}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "pvc-") {
			continue
		}
		out[e.Name()] = dirSizeBytes(
			filepath.Join(c.cfg.OpenEBSLocalDir, e.Name()),
			localPVMaxWalkEntries)
	}
	return out
}

// dirSizeBytes is a bounded du: sums regular-file sizes under root,
// stopping after maxEntries entries. Unreadable entries are
// skipped — a permission-denied subtree under-counts rather than
// failing the whole volume.
func dirSizeBytes(root string, maxEntries int) int64 {
	var total int64
	n := 0
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // skip unreadable entries, never fatal
		}
		n++
		if n > maxEntries {
			return fs.SkipAll
		}
		if d.IsDir() {
			return nil
		}
		if fi, err := d.Info(); err == nil {
			total += fi.Size()
		}
		return nil
	})
	return total
}
