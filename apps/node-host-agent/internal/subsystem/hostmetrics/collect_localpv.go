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
	// localPVMaxStaleWalks — how many consecutive failed walks the
	// last good snapshot still serves. Past it the series stop
	// until a walk succeeds: volumes deleted while the root is
	// unreadable must not emit forever (a stale per-PVC byte count
	// misreports disk pressure).
	localPVMaxStaleWalks = 3
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
	fails int // consecutive failed walks over the cached snapshot
}

// get returns the per-PVC bytes, walking at most once under the
// lock: a stale check and the walk that follows are ONE critical
// section, so two concurrent scrapes cannot both run the bounded du
// (the second queues and reuses the first's store) and a store can
// never land between the stale check and the failed-walk bump
// (which would miscount the streak against fresh data). The walk is
// deliberately inside the lock — bounded by localPVMaxWalkEntries,
// so the queueing second scrape pays a wait, not a second walk.
func (s *localpvCache) get(now time.Time, interval time.Duration,
	walk func() map[string]int64) (bytes map[string]int64, stopped bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bytes != nil && now.Sub(s.at) < interval {
		return s.bytes, false
	}
	if walked := walk(); walked != nil {
		s.at, s.bytes, s.fails = now, walked, 0
		return walked, false
	}
	return s.noteWalkFailedLocked()
}

// noteWalkFailedLocked records one failed du walk and returns the
// cached snapshot while it is still servable: the first
// localPVMaxStaleWalks failures keep serving the last good bytes,
// past them the cache is dropped (nil) until a successful walk
// stores again. stopped reports the just-crossed transition into
// the emit-nothing state so the caller logs it once; with nothing
// cached there is nothing to go stale and no transition ever fires.
// Callers must hold s.mu (get).
func (s *localpvCache) noteWalkFailedLocked() (bytes map[string]int64, stopped bool) {
	if s.bytes == nil {
		s.fails = 0
		return nil, false
	}
	s.fails++
	if s.fails <= localPVMaxStaleWalks {
		return s.bytes, false
	}
	s.bytes = nil
	return nil, s.fails == localPVMaxStaleWalks+1
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
// bytes"). A root that turns unreadable keeps serving the last
// good snapshot for localPVMaxStaleWalks failed walks, then stops
// emitting until a walk succeeds — a deleted PVC's stale byte
// count must not misreport disk pressure forever.
func (c *Collector) collectLocalPVUsage(ch chan<- prometheus.Metric) {
	bytes, stopped := c.lpv.get(c.cfg.Clock.Now(),
		c.cfg.LocalPVScanInterval, c.walkLocalPVDirs)
	if stopped {
		logger().Warn("hostmetrics: openebs local dir unreadable — "+
			"localpv metrics stopped until the root is readable again",
			"dir", c.cfg.OpenEBSLocalDir,
			"walks", localPVMaxStaleWalks+1)
	}
	for pvc, b := range bytes {
		ch <- prometheus.MustNewConstMetric(descLocalPVDirBytes,
			prometheus.GaugeValue, float64(b), c.cfg.NodeName, pvc)
	}
}

// walkLocalPVDirs sums the bytes under every pvc-* dir in
// OpenEBSLocalDir. Returns nil when the root can't be listed —
// callers serve the previous cache for localPVMaxStaleWalks failed
// walks, then emit nothing until a walk succeeds. Each volume's
// walk is bounded at localPVMaxWalkEntries entries: a runaway PVC
// with millions of files must not stall the scrape; the emitted
// count is then a partial sum (documented on the metric).
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
