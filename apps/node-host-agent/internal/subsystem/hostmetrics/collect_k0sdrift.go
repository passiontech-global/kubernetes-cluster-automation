// collect_k0sdrift.go — k0s.yaml drift check (removed flags, KCM
// extraArgs key-set diff, unreadable config) behind the
// k0scontroller.service gate, plus the mtime+size config cache.
// Split out of hostmetrics.go.
package hostmetrics

import (
	"os"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/yaml"
)

const (
	defaultK0sConfigFile = "/etc/k0s/k0s.yaml"
	defaultK0sUnitFile   = "/etc/systemd/system/k0scontroller.service"
)

// defaultRemovedFlags are k0s config keys removed upstream whose
// presence means the rendered config drifted from the expected one.
var defaultRemovedFlags = []string{"concurrent-service-syncs"}

// defaultExpectedKCMArgs is the expected key set of
// spec.controllerManager.extraArgs — the 11 keys pinned identically in
// all three bootstrap/*/k0sctl.yaml (cicd/nonprod/production). A node
// carrying extra/missing keys vs this set drifts (extra-key/missing-key).
var defaultExpectedKCMArgs = []string{
	"concurrent-deployment-syncs",
	"concurrent-gc-syncs",
	"concurrent-replicaset-syncs",
	"kube-api-burst",
	"kube-api-qps",
	"leader-elect-lease-duration",
	"leader-elect-renew-deadline",
	"leader-elect-retry-period",
	"node-monitor-grace-period",
	"node-monitor-period",
	"terminated-pod-gc-threshold",
}

// kcmExtraArgKeys returns the sorted key set of
// spec.controllerManager.extraArgs in the parsed k0s.yaml — the same
// key list node-config-agent's drift task extracts with its awk block.
func kcmExtraArgKeys(parsed map[string]any) []string {
	spec, _ := parsed["spec"].(map[string]any)
	cm, _ := spec["controllerManager"].(map[string]any)
	ea, _ := cm["extraArgs"].(map[string]any)
	keys := make([]string, 0, len(ea))
	for k := range ea {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

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

// driftFinding is one k0s config drift result — reason is
// removed-flag / extra-key / missing-key / unreadable, key the flag
// or extraArgs key it fired on (the metric's {reason,key} labels).
type driftFinding struct{ reason, key string }

// scanK0sDrift computes every drift finding on one read of k0s.yaml —
// shared between the node_k0s_config_drift collector and the
// check-k0s-drift CLI. parseOK=false (unreadable/unparseable file)
// keeps the old drift=1 semantics as a single {unreadable,k0s.yaml}.
func scanK0sDrift(data []byte, parsed map[string]any, parseOK bool,
	removedRe map[string]*regexp.Regexp, expected map[string]bool,
	expectedOrder []string) []driftFinding {
	if !parseOK {
		return []driftFinding{{"unreadable", "k0s.yaml"}}
	}
	var findings []driftFinding
	for flag, re := range removedRe {
		if re.Match(data) {
			findings = append(findings, driftFinding{"removed-flag", flag})
		}
	}
	nodeKeys := kcmExtraArgKeys(parsed)
	nodeSet := make(map[string]bool, len(nodeKeys))
	for _, k := range nodeKeys {
		nodeSet[k] = true
		// A removed flag found in extraArgs reports only under
		// removed-flag — no double counting as extra-key.
		if _, isRemoved := removedRe[k]; !expected[k] && !isRemoved {
			findings = append(findings, driftFinding{"extra-key", k})
		}
	}
	for _, k := range expectedOrder {
		if !nodeSet[k] {
			findings = append(findings, driftFinding{"missing-key", k})
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].reason != findings[j].reason {
			return findings[i].reason < findings[j].reason
		}
		return findings[i].key < findings[j].key
	})
	return findings
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
	findings := scanK0sDrift(data, parsed, ok, c.removedFlagRe,
		c.expectedKCM, c.cfg.ExpectedKCMArgs)
	if len(findings) == 0 {
		ch <- prometheus.MustNewConstMetric(descK0sDrift,
			prometheus.GaugeValue, 0, "none", "none")
		return
	}
	for _, f := range findings {
		ch <- prometheus.MustNewConstMetric(descK0sDrift,
			prometheus.GaugeValue, 1, f.reason, f.key)
	}
}
