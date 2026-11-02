// Package hostmetrics exposes node-local filesystem state as
// Prometheus metrics, collected at scrape time.
//
// Sources (all paths configurable, host-mounted into the agent pod):
//
//   - Watchdog state latches: node-watchdog writes
//     /var/lib/node-watchdog/state-<name> while a failure signal is
//     active and deletes it on recovery (state_enter/state_exit in
//     watchdog/lib.sh). Each present latch exports
//     node_host_agent_watchdog_state{node,state}=1. States seen by an
//     earlier scrape keep exporting 0 after the latch clears, matching
//     the watchdog's own emit-0 semantics so alerts auto-resolve.
//   - Nebula interface: /sys/class/net/<neb1>/operstate →
//     node_host_agent_nebula_interface_up.
//   - Overlay route: any route via the nebula interface in the host
//     route table (/proc/1/net/route) →
//     node_host_agent_nebula_route_present.
//   - k0s config drift: mirrors the node-config-agent drift check —
//     on nodes where k0scontroller.service exists (control plane),
//     node_k0s_config_drift=1 when /etc/k0s/k0s.yaml is missing,
//     unparseable, or still contains a removed flag
//     (concurrent-service-syncs, dropped from k0s config schema).
//
// Emission policy (documented choice): watchdog_state emits for every
// latch ever observed (1 while latched, 0 after clear). The
// nebula_* metrics emit only when the interface exists — on non-nebula
// nodes they are absent rather than 0, so "interface missing" is
// distinguishable from "interface down". node_k0s_config_drift emits
// only where the k0s controller unit exists — workers carry no series.
package hostmetrics

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/yaml"
)

// Defaults — paths are the host mounts the DaemonSet provides.
const (
	defaultWatchdogStateDir = "/host/var/lib/node-watchdog"
	defaultSysClassNet      = "/sys/class/net"
	defaultNebulaIface      = "neb1"
	defaultRouteFile        = "/proc/1/net/route"
	defaultK0sConfigFile    = "/etc/k0s/k0s.yaml"
	defaultK0sUnitFile      = "/etc/systemd/system/k0scontroller.service"
)

// defaultRemovedFlags are k0s config keys removed upstream whose
// presence means the rendered config drifted from the expected one.
var defaultRemovedFlags = []string{"concurrent-service-syncs"}

// Config carries the host paths — all test-injectable.
type Config struct {
	NodeName         string
	WatchdogStateDir string
	SysClassNet      string
	NebulaIface      string
	RouteFile        string
	K0sConfigFile    string
	K0sUnitFile      string
	RemovedFlags     []string
}

func (c *Config) applyDefaults() {
	if c.WatchdogStateDir == "" {
		c.WatchdogStateDir = defaultWatchdogStateDir
	}
	if c.SysClassNet == "" {
		c.SysClassNet = defaultSysClassNet
	}
	if c.NebulaIface == "" {
		c.NebulaIface = defaultNebulaIface
	}
	if c.RouteFile == "" {
		c.RouteFile = defaultRouteFile
	}
	if c.K0sConfigFile == "" {
		c.K0sConfigFile = defaultK0sConfigFile
	}
	if c.K0sUnitFile == "" {
		c.K0sUnitFile = defaultK0sUnitFile
	}
	if len(c.RemovedFlags) == 0 {
		c.RemovedFlags = defaultRemovedFlags
	}
}

// Collector implements prometheus.Collector — all reads happen at
// scrape time, so no goroutine or refresh interval is needed.
type Collector struct {
	cfg Config

	mu         sync.Mutex
	seenStates map[string]bool

	descWatchdog *prometheus.Desc
	descNebUp    *prometheus.Desc
	descNebRoute *prometheus.Desc
	descK0sDrift *prometheus.Desc
}

// New returns the Collector. Register it on the agent's registry.
func New(cfg Config) *Collector {
	cfg.applyDefaults()
	c := &Collector{cfg: cfg, seenStates: map[string]bool{}}
	c.descWatchdog = prometheus.NewDesc(
		"node_host_agent_watchdog_state",
		"node-watchdog state-* latch present (1) or previously seen and cleared (0).",
		[]string{"node", "state"}, nil)
	c.descNebUp = prometheus.NewDesc(
		"node_host_agent_nebula_interface_up",
		"Nebula interface operstate is up (emitted only when the interface exists).",
		nil, nil)
	c.descNebRoute = prometheus.NewDesc(
		"node_host_agent_nebula_route_present",
		"A host route via the Nebula interface exists (emitted only when the interface exists).",
		nil, nil)
	c.descK0sDrift = prometheus.NewDesc(
		"node_k0s_config_drift",
		"k0s.yaml drifted: missing/unparseable or still carries a removed flag "+
			"(emitted only on nodes running k0scontroller.service).",
		nil, nil)
	return c
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.descWatchdog
	ch <- c.descNebUp
	ch <- c.descNebRoute
	ch <- c.descK0sDrift
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.collectWatchdog(ch)
	c.collectNebula(ch)
	c.collectK0sDrift(ch)
}

// collectWatchdog scans state-* latch files.
func (c *Collector) collectWatchdog(ch chan<- prometheus.Metric) {
	present := map[string]bool{}
	entries, err := os.ReadDir(c.cfg.WatchdogStateDir)
	if err == nil {
		for _, e := range entries {
			if !e.Type().IsRegular() {
				continue
			}
			if name, ok := strings.CutPrefix(e.Name(), "state-"); ok && name != "" {
				present[name] = true
			}
		}
	}
	c.mu.Lock()
	for name := range present {
		c.seenStates[name] = true
	}
	seen := make([]string, 0, len(c.seenStates))
	for name := range c.seenStates {
		seen = append(seen, name)
	}
	c.mu.Unlock()
	for _, name := range seen {
		v := 0.0
		if present[name] {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(c.descWatchdog,
			prometheus.GaugeValue, v, c.cfg.NodeName, name)
	}
}

// collectNebula emits interface + route state, only when the nebula
// interface exists on the node.
func (c *Collector) collectNebula(ch chan<- prometheus.Metric) {
	oper, err := os.ReadFile(
		filepath.Join(c.cfg.SysClassNet, c.cfg.NebulaIface, "operstate"))
	if err != nil {
		return // interface absent → metrics absent (documented choice)
	}
	up := 0.0
	switch strings.TrimSpace(string(oper)) {
	// TUN devices (neb1 is nebula's tun) often report "unknown" rather
	// than "up" — the link exists and is administratively up.
	case "up", "unknown":
		up = 1
	}
	ch <- prometheus.MustNewConstMetric(c.descNebUp,
		prometheus.GaugeValue, up)

	present := 0.0
	if f, err := os.Open(c.cfg.RouteFile); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			// /proc/net/route columns: Iface Destination Gateway ...
			if len(fields) >= 2 && fields[0] == c.cfg.NebulaIface {
				present = 1
				break
			}
		}
	}
	ch <- prometheus.MustNewConstMetric(c.descNebRoute,
		prometheus.GaugeValue, present)
}

// collectK0sDrift emits node_k0s_config_drift on controller nodes
// (detected via the k0scontroller.service unit file). drift=1 when
// k0s.yaml is missing, unparseable, or carries a removed flag.
func (c *Collector) collectK0sDrift(ch chan<- prometheus.Metric) {
	if _, err := os.Stat(c.cfg.K0sUnitFile); err != nil {
		return // not a k0s controller → no series
	}
	drift := 1.0
	data, err := os.ReadFile(c.cfg.K0sConfigFile)
	if err == nil {
		var parsed map[string]any
		if err := yaml.Unmarshal(data, &parsed); err == nil {
			drift = 0
			for _, flag := range c.cfg.RemovedFlags {
				// Anchored key match (same shape as the canonical
				// grep "^[[:space:]]*flag[[:space:]]*:") — a substring
				// match would fire on the name inside a comment or a
				// value.
				re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(flag) + `\s*:`)
				if re.Match(data) {
					drift = 1
					break
				}
			}
		}
	}
	ch <- prometheus.MustNewConstMetric(c.descK0sDrift,
		prometheus.GaugeValue, drift)
}
