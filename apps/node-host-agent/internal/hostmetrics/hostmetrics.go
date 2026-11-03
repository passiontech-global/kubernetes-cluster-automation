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
//     node_k0s_config_drift{reason,key}=1 per finding: a removed flag
//     still present, an unexpected/missing KCM extraArgs key vs
//     ExpectedKCMArgs, or an unreadable k0s.yaml.
//   - Nebula cert expiry: replaces the shell's `nebula-cert print`
//     fork — parses the PEM-wrapped protobuf NebulaCertificate
//     directly and exports node_host_agent_nebula_cert_days_left plus
//     the watchdog-state-style series
//     node_host_agent_watchdog_state{state="nebula-cert-expiring"}.
//
// Emission policy (documented choice): watchdog_state emits for every
// latch ever observed (1 while latched, 0 after clear). The
// nebula_* metrics emit only when the interface exists — on non-nebula
// nodes they are absent rather than 0, so "interface missing" is
// distinguishable from "interface down". The nebula cert days gauge
// emits only when the cert parses. node_k0s_config_drift emits
// only where the k0s controller unit exists — workers carry no series.
package hostmetrics

import (
	"bufio"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

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
	defaultNebulaCertFile   = "/host/etc/nebula/interdc/host.crt"
)

// nebulaCertWarnDays mirrors module 13-nebula-health: fewer than this
// many days to notAfter latches the nebula-cert-expiring signal.
const nebulaCertWarnDays = 30

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

// Config carries the host paths — all test-injectable.
type Config struct {
	NodeName         string
	WatchdogStateDir string
	SysClassNet      string
	NebulaIface      string
	RouteFile        string
	K0sConfigFile    string
	K0sUnitFile      string
	NebulaCertFile   string
	RemovedFlags     []string
	ExpectedKCMArgs  []string
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
	if c.NebulaCertFile == "" {
		c.NebulaCertFile = defaultNebulaCertFile
	}
	if len(c.RemovedFlags) == 0 {
		c.RemovedFlags = defaultRemovedFlags
	}
	if len(c.ExpectedKCMArgs) == 0 {
		c.ExpectedKCMArgs = defaultExpectedKCMArgs
	}
}

// Collector implements prometheus.Collector — all reads happen at
// scrape time, so no goroutine or refresh interval is needed.
type Collector struct {
	cfg Config

	mu         sync.Mutex
	seenStates map[string]bool

	descWatchdog    *prometheus.Desc
	descNebUp       *prometheus.Desc
	descNebRoute    *prometheus.Desc
	descNebCertDays *prometheus.Desc
	descK0sDrift    *prometheus.Desc
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
	c.descNebCertDays = prometheus.NewDesc(
		"node_host_agent_nebula_cert_days_left",
		"Days until the nebula host certificate notAfter (emitted only when the cert parses).",
		nil, nil)
	c.descK0sDrift = prometheus.NewDesc(
		"node_k0s_config_drift",
		"/etc/k0s/k0s.yaml drifted vs expected config (1=drift): "+
			"removed-flag still present, extra/missing KCM extraArgs key, "+
			"or unreadable config (emitted only on nodes running "+
			"k0scontroller.service).",
		[]string{"reason", "key"}, nil)
	return c
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.descWatchdog
	ch <- c.descNebUp
	ch <- c.descNebRoute
	ch <- c.descNebCertDays
	ch <- c.descK0sDrift
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	// The cert is parsed once per scrape and shared between the
	// watchdog-state latch bookkeeping and the days-left gauge.
	certDays, certOK := c.nebulaCertDaysLeft()
	c.collectWatchdog(ch, certDays, certOK)
	c.collectNebula(ch)
	c.collectNebulaCert(ch, certDays, certOK)
	c.collectK0sDrift(ch)
}

// collectWatchdog scans state-* latch files. certDays/certOK fold the
// agent-computed nebula cert expiry into the latch bookkeeping: the
// shell module 13 used to own the state-nebula-cert-expiring file —
// now the series is driven by cert parsing whenever the cert reads.
func (c *Collector) collectWatchdog(ch chan<- prometheus.Metric, certDays int64, certOK bool) {
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
	if certOK && certDays < nebulaCertWarnDays {
		present["nebula-cert-expiring"] = true
	}
	c.mu.Lock()
	for name := range present {
		c.seenStates[name] = true
	}
	if certOK {
		// Cert parsed once → the signal must emit an explicit 0 from
		// now on (alert contract), even if the cert later disappears
		// — the seenStates emit-0 bookkeeping covers that case.
		c.seenStates["nebula-cert-expiring"] = true
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

// collectNebulaCert emits the cert days-left gauge — only when the
// cert parses (absent/garbage cert → absent series, distinguishing
// "no cert" from "0 days").
func (c *Collector) collectNebulaCert(ch chan<- prometheus.Metric, daysLeft int64, ok bool) {
	if !ok {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.descNebCertDays,
		prometheus.GaugeValue, float64(daysLeft))
}

// nebulaCertDaysLeft returns days until notAfter, and ok=false when
// the cert is absent or unparseable. Integer-day truncation matches
// the shell's ((exp - now) / 86400).
func (c *Collector) nebulaCertDaysLeft() (int64, bool) {
	data, err := os.ReadFile(c.cfg.NebulaCertFile)
	if err != nil {
		return 0, false
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return 0, false
	}
	notAfter, ok := nebulaCertNotAfter(block.Bytes)
	if !ok {
		return 0, false
	}
	return (notAfter - time.Now().Unix()) / 86400, true
}

// --- minimal protobuf wire reader for NebulaCertificate ---
// host.crt is a PEM block ("-----BEGIN NEBULA CERTIFICATE-----")
// wrapping a protobuf NebulaCertificate. Only two fields matter:
//
//	NebulaCertificate        field 1 "details"  — wire type 2 (LEN)
//	NebulaCertificateDetails field 6 "not_after" — wire type 0 (varint int64)
//
// Any anomaly (truncation, bad wire type, missing field) → ok=false;
// the caller treats the cert as unreadable and emits nothing. This
// avoids pulling in the slackhq/nebula dependency for one field.

// readVarint decodes one protobuf varint; n=0 signals truncation or
// overflow (>10 bytes / >64 bits).
func readVarint(b []byte) (v uint64, n int) {
	for i := 0; i < len(b) && i < 10; i++ {
		c := b[i]
		if i == 9 && c > 1 { // 10th byte may only carry 1 bit
			return 0, 0
		}
		v |= uint64(c&0x7f) << (7 * i)
		if c < 0x80 {
			return v, i + 1
		}
	}
	return 0, 0
}

// skipWire returns the length in bytes of the protobuf value at b[0]
// for the given wire type. Only the four fixed types are supported —
// group wire types (3/4, deprecated) are treated as unparseable.
func skipWire(b []byte, wire int) (int, bool) {
	switch wire {
	case 0: // varint
		_, n := readVarint(b)
		return n, n > 0
	case 1: // fixed64
		if len(b) < 8 {
			return 0, false
		}
		return 8, true
	case 2: // length-delimited
		ln, n := readVarint(b)
		if n == 0 || uint64(len(b)-n) < ln {
			return 0, false
		}
		return n + int(ln), true
	case 5: // fixed32
		if len(b) < 4 {
			return 0, false
		}
		return 4, true
	}
	return 0, false
}

// nebulaCertNotAfter extracts not_after (unix seconds) from the DER
// body of a nebula PEM cert.
func nebulaCertNotAfter(der []byte) (int64, bool) {
	for len(der) > 0 {
		tag, n := readVarint(der)
		if n == 0 {
			return 0, false
		}
		der = der[n:]
		field, wire := int(tag>>3), int(tag&7)
		if field == 1 && wire == 2 {
			ln, m := readVarint(der)
			if m == 0 || uint64(len(der)-m) < ln {
				return 0, false
			}
			return nebulaDetailsNotAfter(der[m : m+int(ln)])
		}
		m, ok := skipWire(der, wire)
		if !ok {
			return 0, false
		}
		der = der[m:]
	}
	return 0, false
}

// nebulaDetailsNotAfter scans a NebulaCertificateDetails body for
// field 6 (not_after, varint int64). Skips every other field by wire
// type so unknown/added fields can't break the parse.
func nebulaDetailsNotAfter(b []byte) (int64, bool) {
	for len(b) > 0 {
		tag, n := readVarint(b)
		if n == 0 {
			return 0, false
		}
		b = b[n:]
		field, wire := int(tag>>3), int(tag&7)
		if field == 6 && wire == 0 {
			v, m := readVarint(b)
			if m == 0 {
				return 0, false
			}
			return int64(v), true
		}
		m, ok := skipWire(b, wire)
		if !ok {
			return 0, false
		}
		b = b[m:]
	}
	return 0, false
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

// collectK0sDrift emits node_k0s_config_drift{reason,key} on
// controller nodes (detected via the k0scontroller.service unit file).
// One series per finding at value 1; a clean config emits
// {reason="none",key="none"} 0. Missing/unparseable k0s.yaml keeps the
// old drift=1 semantics as {reason="unreadable",key="k0s.yaml"} 1.
func (c *Collector) collectK0sDrift(ch chan<- prometheus.Metric) {
	if _, err := os.Stat(c.cfg.K0sUnitFile); err != nil {
		return // not a k0s controller → no series
	}
	type finding struct{ reason, key string }
	var findings []finding
	data, err := os.ReadFile(c.cfg.K0sConfigFile)
	var parsed map[string]any
	if err != nil || yaml.Unmarshal(data, &parsed) != nil {
		findings = append(findings, finding{"unreadable", "k0s.yaml"})
	} else {
		removed := make(map[string]bool, len(c.cfg.RemovedFlags))
		for _, flag := range c.cfg.RemovedFlags {
			removed[flag] = true
			// Anchored key match (same shape as the canonical
			// grep "^[[:space:]]*flag[[:space:]]*:") over the raw
			// file — a removed flag may hide in ANY extraArgs
			// block (api/controllerManager/scheduler), and a
			// substring match would fire on comments or values.
			re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(flag) + `\s*:`)
			if re.Match(data) {
				findings = append(findings, finding{"removed-flag", flag})
			}
		}
		nodeKeys := kcmExtraArgKeys(parsed)
		nodeSet := make(map[string]bool, len(nodeKeys))
		expected := make(map[string]bool, len(c.cfg.ExpectedKCMArgs))
		for _, k := range c.cfg.ExpectedKCMArgs {
			expected[k] = true
		}
		for _, k := range nodeKeys {
			nodeSet[k] = true
			// A removed flag found in extraArgs reports only under
			// removed-flag — no double counting as extra-key.
			if !expected[k] && !removed[k] {
				findings = append(findings, finding{"extra-key", k})
			}
		}
		for _, k := range c.cfg.ExpectedKCMArgs {
			if !nodeSet[k] {
				findings = append(findings, finding{"missing-key", k})
			}
		}
	}
	if len(findings) == 0 {
		ch <- prometheus.MustNewConstMetric(c.descK0sDrift,
			prometheus.GaugeValue, 0, "none", "none")
		return
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].reason != findings[j].reason {
			return findings[i].reason < findings[j].reason
		}
		return findings[i].key < findings[j].key
	})
	for _, f := range findings {
		ch <- prometheus.MustNewConstMetric(c.descK0sDrift,
			prometheus.GaugeValue, 1, f.reason, f.key)
	}
}
