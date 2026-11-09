// collect_localpv.go — OpenEBS LocalPV per-PVC dir bytes: a
// bounded du walk cached for LocalPVScanInterval. Split out of
// hostmetrics.go.
package hostmetrics

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	// LocalPV telemetry: the openebs localpv-provisioner
	// hostPath root + the du-walk cache TTL + per-volume entry cap.
	defaultOpenEBSLocalDir  = "/var/openebs/local"
	defaultLocalPVScanEvery = 15 * time.Minute
	localPVMaxWalkEntries   = 20000
)

// --- OpenEBS LocalPV per-PVC dir bytes ---

// localpvCache is the per-PVC du-walk domain — one slice of what
// used to be the Collector's shared mu-guarded fields: the walk
// result cached for LocalPVScanInterval (walking every volume dir
// per scrape is too heavy on a node with hundreds of LocalPVs). The
// mutex is private.
type localpvCache struct {
	mu    sync.Mutex
	at    time.Time
	bytes map[string]int64
}

// snapshot returns the cached per-PVC bytes and whether they're
// still fresh — non-nil and younger than interval.
func (s *localpvCache) snapshot(now time.Time,
	interval time.Duration) (map[string]int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bytes, s.bytes != nil && now.Sub(s.at) < interval
}

// store replaces the cache with a fresh walk result stamped at now.
func (s *localpvCache) store(now time.Time, bytes map[string]int64) {
	s.mu.Lock()
	s.at, s.bytes = now, bytes
	s.mu.Unlock()
}

var descLocalPVDirBytes = prometheus.NewDesc(
	"node_host_agent_localpv_dir_bytes",
	"Bytes under the OpenEBS LocalPV pvc-* volume dir (bounded walk; emitted per pvc-* dir present).",
	[]string{"node", "pvc_volume"}, nil)

// collectLocalPVUsage emits node_host_agent_localpv_dir_bytes per
// pvc-* volume dir under OpenEBSLocalDir. The du walk is cached
// for LocalPVScanInterval — a node with hundreds of LocalPVs would
// otherwise pay a full filesystem walk per PVC per scrape. A
// missing/unreadable root emits nothing (absent, not 0 — "no
// local-path volumes here" must stay distinguishable from "zero
// bytes").
func (c *Collector) collectLocalPVUsage(ch chan<- prometheus.Metric) {
	cached, fresh := c.lpv.snapshot(c.cfg.Clock.Now(), c.cfg.LocalPVScanInterval)
	bytes := cached
	if !fresh {
		if walked := c.walkLocalPVDirs(); walked != nil {
			c.lpv.store(c.cfg.Clock.Now(), walked)
			bytes = walked
		}
		// A failed walk (root unreadable) keeps serving the last
		// good snapshot rather than blanking every series.
	}
	for pvc, b := range bytes {
		ch <- prometheus.MustNewConstMetric(descLocalPVDirBytes,
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
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			logger().Debug("hostmetrics: localpv walk entry skipped — unreadable",
				"path", path, "error", err)
			return nil // skip unreadable entries, never fatal
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
