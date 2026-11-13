// collect_k0sdrift.go — the node_k0s_config_drift collector: k0s.yaml
// drift check (removed flags, KCM extraArgs key-set diff, unreadable
// config) behind the k0scontroller.service gate, plus the mtime+size
// config cache. The drift semantics (defaults + scan) live in
// internal/domain/k0sconfig, shared with the check-k0s-drift CLI.
package hostmetrics

import (
	"os"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/yaml"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/k0sconfig"
)

// k0sDriftCache is the k0s.yaml read/parse cache — one slice of
// what used to be the Collector's shared mu-guarded fields. The
// file changes on k0s upgrades (rare), not per scrape — a
// stat+mtime+size check gates the re-read/re-parse. A failed stat
// serves no stale data. The mutex is private — the drift domain
// shares no state with the other domains.
type k0sDriftCache struct {
	mu     sync.Mutex
	loaded bool
	mtime  time.Time
	size   int64
	data   []byte
	parsed map[string]any
	ok     bool
}

// get returns the raw bytes and parsed form of the k0s.yaml at
// path, re-reading only when the file's mtime+size changed since
// the last call. ok=false means the file was unreadable or
// unparseable at read time — the caller keeps the old drift=1
// "unreadable" finding.
func (s *k0sDriftCache) get(path string) (data []byte,
	parsed map[string]any, ok bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, nil, false // gone/un-statable → never serve cache
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loaded && fi.ModTime().Equal(s.mtime) && fi.Size() == s.size {
		return s.data, s.parsed, s.ok
	}
	data, err = os.ReadFile(path)
	var p map[string]any
	var uerr error
	if err == nil {
		uerr = yaml.Unmarshal(data, &p)
	}
	ok = err == nil && uerr == nil
	if !ok {
		cause := err
		if cause == nil {
			cause = uerr
		}
		// Cached per mtime+size — this fires once per file change,
		// not once per scrape.
		logger().Debug("hostmetrics: k0s config unreadable/unparseable — "+
			"drift reports {unreadable,k0s.yaml}",
			"path", path,
			"error", cause)
	}
	s.loaded = true
	s.mtime = fi.ModTime()
	s.size = fi.Size()
	s.data = data
	s.parsed = p
	s.ok = ok
	return data, p, ok
}

var descK0sDrift = prometheus.NewDesc(
	"node_k0s_config_drift",
	"/etc/k0s/k0s.yaml drifted vs expected config (1=drift): "+
		"removed-flag still present, extra/missing KCM extraArgs key, "+
		"or unreadable config (emitted only on nodes running "+
		"k0scontroller.service).",
	[]string{"reason", "key"}, nil)

// collectK0sDrift emits node_k0s_config_drift{reason,key} on
// controller nodes (detected via the k0scontroller.service unit file).
// One series per finding at value 1; a clean config emits
// {reason="none",key="none"} 0.
func (c *Collector) collectK0sDrift(ch chan<- prometheus.Metric) {
	if _, err := os.Stat(c.cfg.K0sUnitFile); err != nil {
		return // not a k0s controller → no series
	}
	data, parsed, ok := c.k0s.get(c.cfg.K0sConfigFile)
	findings := k0sconfig.Scan(data, parsed, ok, c.removedFlagRe,
		c.expectedKCM, c.cfg.ExpectedKCMArgs)
	if len(findings) == 0 {
		ch <- prometheus.MustNewConstMetric(descK0sDrift,
			prometheus.GaugeValue, 0, "none", "none")
		return
	}
	for _, f := range findings {
		ch <- prometheus.MustNewConstMetric(descK0sDrift,
			prometheus.GaugeValue, 1, f.Reason, f.Key)
	}
}
