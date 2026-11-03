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
//   - PSI overload: /proc/pressure/cpu some avg60 →
//     node_watchdog_psi_cpu_some_avg60, and drives the
//     state-node-overloaded latch with hysteresis (>=40% enter,
//     <25% exit) — the runner's node-overloaded signal every restart
//     gate reads.
//   - cpu-delivered probe (lib.sh measure_cpu_delivered): a fixed
//     ~0.3 cpu-s busy loop on a locked thread (RUSAGE_THREAD) vs wall
//     clock → node_cpu_delivered_ratio +
//     node_cpu_delivered_probe_wall_seconds — the ground-truth
//     "how much of 1 vCPU did the hypervisor actually give" steal
//     canary guest accounting can't see.
//   - fail2ban banned counts: fail2ban-banned file ("jail=N ...")
//     written by the nethealth check → node_fail2ban_banned_ips{jail}.
//   - egress relay state: per OVERLAY_EGRESS_RELAYS target,
//     node_overlay_egress_relay_active{target} = 1 while
//     egress-state-<ip> is "relay" (emitted for every configured
//     target — absent vs 0 must stay distinguishable).
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
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
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
	defaultPSIFile          = "/proc/pressure/cpu"
	// psiOverloadedOn/Off are the node-overloaded hysteresis — the
	// runner's load15>4*ncpu test replaced by PSI some avg60 (actual
	// stall evidence, not raw load): enter the latch at >=40%,
	// release below 25%.
	psiOverloadedOn  = 40.0
	psiOverloadedOff = 25.0
	// cpuDeliveredTarget is the fixed busy-loop work (~0.3 cpu-s —
	// ~0.1% of a 5m cycle on a healthy node, ~6s wall at 95% steal).
	cpuDeliveredTarget    = 0.3
	cpuDeliveredMaxWall   = 60 * time.Second
	defaultCPUDeliveredIn = 2 * time.Minute
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
	// PSIFile is /proc/pressure/cpu — drives the overload gauge +
	// state-node-overloaded latch.
	PSIFile string
	// EgressRelays is OVERLAY_EGRESS_RELAYS (wired from watchdogconf
	// by main) — each target gets a relay-active gauge.
	EgressRelays []string
	// CPUDeliveredInterval bounds how often the busy-loop probe runs
	// (shell: once per 2m run).
	CPUDeliveredInterval time.Duration
	RemovedFlags         []string
	ExpectedKCMArgs      []string

	// nowFn supplies the current time — seam for tests.
	nowFn func() time.Time
	// cpuMeasure replaces the real RUSAGE_THREAD busy-loop for
	// tests: returns (ratio, wallSeconds, ok).
	cpuMeasure func() (ratio, wall float64, ok bool)
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
	if c.PSIFile == "" {
		c.PSIFile = defaultPSIFile
	}
	if c.CPUDeliveredInterval <= 0 {
		c.CPUDeliveredInterval = defaultCPUDeliveredIn
	}
	if c.nowFn == nil {
		c.nowFn = time.Now
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

	// Hoisted out of the scrape path in New(): drift regexes are
	// compiled once and the expected-KCM set is built once — the
	// per-scrape work left in collectK0sDrift is a stat + map lookups.
	removedFlagRe map[string]*regexp.Regexp
	expectedKCM   map[string]bool

	mu         sync.Mutex
	seenStates map[string]bool

	// k0s.yaml cache, guarded by mu: the file changes on k0s upgrades
	// (rare), not per-scrape — a stat+mtime+size check gates the
	// re-read/re-parse. A failed stat serves no stale data.
	k0sLoaded bool
	k0sMtime  time.Time
	k0sSize   int64
	k0sData   []byte
	k0sParsed map[string]any
	k0sOK     bool

	descWatchdog    *prometheus.Desc
	descNebUp       *prometheus.Desc
	descNebRoute    *prometheus.Desc
	descNebCertDays *prometheus.Desc
	descK0sDrift    *prometheus.Desc
	descPSI         *prometheus.Desc
	descCPURatio    *prometheus.Desc
	descCPUWall     *prometheus.Desc
	descF2B         *prometheus.Desc
	descEgressRelay *prometheus.Desc

	// cpu-delivered probe bookkeeping (mu): the busy-loop runs in a
	// goroutine — a scrape triggers it and serves the last result;
	// a scrape must never block up to ~6s on steal measurement.
	cpuRunning bool
	cpuLast    time.Time
	cpuRatio   float64
	cpuWall    float64
	cpuOK      bool
	cpuSink    uint64 // busy-loop sink, mu-guarded
}

// New returns the Collector. Register it on the agent's registry.
func New(cfg Config) *Collector {
	cfg.applyDefaults()
	c := &Collector{cfg: cfg, seenStates: map[string]bool{}}
	c.removedFlagRe = make(map[string]*regexp.Regexp, len(cfg.RemovedFlags))
	for _, flag := range cfg.RemovedFlags {
		// Anchored key match (same shape as the canonical
		// grep "^[[:space:]]*flag[[:space:]]*:") over the raw file —
		// a removed flag may hide in ANY extraArgs block
		// (api/controllerManager/scheduler), and a substring match
		// would fire on comments or values.
		c.removedFlagRe[flag] = regexp.MustCompile(
			`(?m)^\s*` + regexp.QuoteMeta(flag) + `\s*:`)
	}
	c.expectedKCM = make(map[string]bool, len(cfg.ExpectedKCMArgs))
	for _, k := range cfg.ExpectedKCMArgs {
		c.expectedKCM[k] = true
	}
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
	c.descPSI = prometheus.NewDesc(
		"node_watchdog_psi_cpu_some_avg60",
		"PSI cpu some avg60 — share of time runnable tasks stalled (runner's overload signal).",
		nil, nil)
	c.descCPURatio = prometheus.NewDesc(
		"node_cpu_delivered_ratio",
		"Share of 1 vCPU actually delivered by the hypervisor — busy-loop probe (~0.3 cpu-s, 1.0 = no steal).",
		nil, nil)
	c.descCPUWall = prometheus.NewDesc(
		"node_cpu_delivered_probe_wall_seconds",
		"Wall-clock the cpu-delivered probe ran — abnormal growth = the probe itself stalled.",
		nil, nil)
	c.descF2B = prometheus.NewDesc(
		"node_fail2ban_banned_ips",
		"Currently banned IPs per fail2ban jail (emitted only when the banned file exists).",
		[]string{"jail"}, nil)
	c.descEgressRelay = prometheus.NewDesc(
		"node_overlay_egress_relay_active",
		"Egress target currently routed via the overlay relay (1) or direct underlay (0).",
		[]string{"target"}, nil)
	return c
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.descWatchdog
	ch <- c.descNebUp
	ch <- c.descNebRoute
	ch <- c.descNebCertDays
	ch <- c.descK0sDrift
	ch <- c.descPSI
	ch <- c.descCPURatio
	ch <- c.descCPUWall
	ch <- c.descF2B
	ch <- c.descEgressRelay
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	// Side-effect probes run BEFORE the state-dir scan so a latch
	// they transition shows up in this scrape's watchdog_state.
	avg60, psiOK := c.psiAvg60()
	if psiOK {
		c.updateOverloadLatch(avg60)
	}
	c.maybeMeasureCPU()
	// The cert is parsed once per scrape and shared between the
	// watchdog-state latch bookkeeping and the days-left gauge.
	certDays, certOK := c.nebulaCertDaysLeft()
	c.updateCertLatch(certDays, certOK)
	c.collectWatchdog(ch, certDays, certOK)
	c.collectNebula(ch)
	c.collectNebulaCert(ch, certDays, certOK)
	c.collectK0sDrift(ch)
	c.collectPSI(ch, avg60, psiOK)
	c.collectCPUDelivered(ch)
	c.collectFail2ban(ch)
	c.collectEgressRelay(ch)
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

// updateCertLatch mirrors 13-nebula-health.sh's FILE contract — the
// nodereporter and prom filelog consumers read files, not metric
// series: state-nebula-cert-expiring is created (state_enter, epoch
// content, only while absent) when days < nebulaCertWarnDays and
// removed on recovery, and nebula-cert-days-left is rewritten on
// every parsed scrape (shell wrote it every run). An absent or
// unparseable cert CLEARS both files — the shell left the latch
// behind on `[ -s "$cert" ]` failure, but a permanent phantom latch
// breaks both the file consumers and the emit-0 alert contract (a
// gone cert cannot be "expiring").
func (c *Collector) updateCertLatch(days int64, ok bool) {
	dir := c.cfg.WatchdogStateDir
	latch := filepath.Join(dir, "state-nebula-cert-expiring")
	if !ok {
		_ = os.Remove(latch)
		_ = os.Remove(filepath.Join(dir, "nebula-cert-days-left"))
		return
	}
	daysPath := filepath.Join(dir, "nebula-cert-days-left")
	tmp := filepath.Join(dir, ".tmp-"+filepath.Base(daysPath))
	if err := os.WriteFile(tmp,
		[]byte(strconv.FormatInt(days, 10)+"\n"), 0o644); err == nil {
		_ = os.Rename(tmp, daysPath)
	}
	_, statErr := os.Stat(latch)
	switch {
	case days < nebulaCertWarnDays && statErr != nil:
		content := strconv.FormatInt(c.cfg.nowFn().Unix(), 10) + "\n"
		tmp = filepath.Join(dir, ".tmp-"+filepath.Base(latch))
		if os.WriteFile(tmp, []byte(content), 0o644) == nil {
			_ = os.Rename(tmp, latch)
		}
	case days >= nebulaCertWarnDays && statErr == nil:
		_ = os.Remove(latch)
	}
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

// k0sConfig returns the raw bytes and parsed form of k0s.yaml,
// re-reading only when the file's mtime+size changed since the last
// scrape. ok=false means the file was unreadable or unparseable at
// read time — the caller keeps the old drift=1 "unreadable" finding.
func (c *Collector) k0sConfig() (data []byte, parsed map[string]any, ok bool) {
	fi, err := os.Stat(c.cfg.K0sConfigFile)
	if err != nil {
		return nil, nil, false // gone/un-statable → never serve cache
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.k0sLoaded && fi.ModTime().Equal(c.k0sMtime) && fi.Size() == c.k0sSize {
		return c.k0sData, c.k0sParsed, c.k0sOK
	}
	data, err = os.ReadFile(c.cfg.K0sConfigFile)
	var p map[string]any
	ok = err == nil && yaml.Unmarshal(data, &p) == nil
	c.k0sLoaded = true
	c.k0sMtime = fi.ModTime()
	c.k0sSize = fi.Size()
	c.k0sData = data
	c.k0sParsed = p
	c.k0sOK = ok
	return data, p, ok
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
	data, parsed, ok := c.k0sConfig()
	if !ok {
		findings = append(findings, finding{"unreadable", "k0s.yaml"})
	} else {
		for flag, re := range c.removedFlagRe {
			if re.Match(data) {
				findings = append(findings, finding{"removed-flag", flag})
			}
		}
		nodeKeys := kcmExtraArgKeys(parsed)
		nodeSet := make(map[string]bool, len(nodeKeys))
		for _, k := range nodeKeys {
			nodeSet[k] = true
			// A removed flag found in extraArgs reports only under
			// removed-flag — no double counting as extra-key.
			if _, isRemoved := c.removedFlagRe[k]; !c.expectedKCM[k] && !isRemoved {
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

// --- PSI overload (runner's node-overloaded) ---

// psiAvg60 parses the "some avg60=" field of /proc/pressure/cpu.
// ok=false on a missing/malformed file — the latch is left untouched
// (inconclusive, like the other file-based signals).
func (c *Collector) psiAvg60() (float64, bool) {
	data, err := os.ReadFile(c.cfg.PSIFile)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "some" {
			continue
		}
		for _, kv := range f[1:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok || k != "avg60" {
				continue
			}
			x, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return 0, false
			}
			return x, true
		}
	}
	return 0, false
}

// updateOverloadLatch drives state-node-overloaded with hysteresis:
// >=psiOverloadedOn enters, <psiOverloadedOff exits, between the
// thresholds the current state persists. Written only on transition —
// the file content is when the condition STARTED.
func (c *Collector) updateOverloadLatch(avg60 float64) {
	p := filepath.Join(c.cfg.WatchdogStateDir, "state-node-overloaded")
	_, err := os.Stat(p)
	switch {
	case avg60 >= psiOverloadedOn && err != nil:
		content := strconv.FormatInt(c.cfg.nowFn().Unix(), 10) + "\n"
		tmp := filepath.Join(filepath.Dir(p), ".tmp-"+filepath.Base(p))
		if os.WriteFile(tmp, []byte(content), 0o644) == nil {
			_ = os.Rename(tmp, p)
		}
	case avg60 < psiOverloadedOff && err == nil:
		_ = os.Remove(p)
	}
}

// collectPSI emits the avg60 gauge only when PSI parsed.
func (c *Collector) collectPSI(ch chan<- prometheus.Metric, avg60 float64, ok bool) {
	if !ok {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.descPSI,
		prometheus.GaugeValue, avg60)
}

// --- cpu-delivered probe (lib.sh measure_cpu_delivered) ---

// maybeMeasureCPU re-arms the busy-loop probe every
// CPUDeliveredInterval. The probe itself runs in a goroutine so a
// scrape never blocks on wall-clock steal; the gauges serve the last
// completed measurement.
func (c *Collector) maybeMeasureCPU() {
	c.mu.Lock()
	if c.cpuRunning ||
		c.cfg.nowFn().Sub(c.cpuLast) < c.cfg.CPUDeliveredInterval {
		c.mu.Unlock()
		return
	}
	c.cpuRunning = true
	c.mu.Unlock()
	go func() {
		ratio, wall, ok := c.measureCPU()
		c.mu.Lock()
		c.cpuRunning = false
		c.cpuLast = c.cfg.nowFn()
		if ok {
			c.cpuRatio, c.cpuWall, c.cpuOK = ratio, wall, true
		}
		c.mu.Unlock()
	}()
}

// measureCPU burns a fixed ~0.3 cpu-s on a LOCKED thread and returns
// ratio = cpu_target / wall (capped 1.0 — jiffies overshoot can make
// wall slightly under target). RUSAGE_THREAD isolates the probe from
// other goroutines' CPU — the shell measured the whole-process
// jiffies; a locked thread is the closest Go equivalent.
func (c *Collector) measureCPU() (ratio, wall float64, ok bool) {
	if c.cfg.cpuMeasure != nil {
		return c.cfg.cpuMeasure()
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var ru0, ru1 unix.Rusage
	if unix.Getrusage(unix.RUSAGE_THREAD, &ru0) != nil {
		return 0, 0, false
	}
	cpuAt := func(r *unix.Rusage) float64 {
		return float64(r.Utime.Sec) + float64(r.Utime.Usec)/1e6 +
			float64(r.Stime.Sec) + float64(r.Stime.Usec)/1e6
	}
	wall0 := time.Now()
	var sink uint64
	for i := uint64(0); ; i++ {
		sink += i // any real work — jiffie-counted CPU
		if i%65536 == 0 {
			if unix.Getrusage(unix.RUSAGE_THREAD, &ru1) != nil {
				return 0, 0, false
			}
			if cpuAt(&ru1)-cpuAt(&ru0) >= cpuDeliveredTarget {
				break
			}
			if time.Since(wall0) > cpuDeliveredMaxWall {
				return 0, 0, false // probe itself stalled — no metric
			}
		}
	}
	c.mu.Lock()
	c.cpuSink = sink
	c.mu.Unlock()
	wall = time.Since(wall0).Seconds()
	if wall <= 0 {
		return 0, 0, false
	}
	ratio = cpuDeliveredTarget / wall
	if ratio > 1 {
		ratio = 1
	}
	return ratio, wall, true
}

// cpuDeliveredSink keeps the busy loop's work observable so the
// compiler can't optimize it away.
var cpuDeliveredSink uint64

// collectCPUDelivered emits the last completed probe — absent before
// the first measurement (shell: no cpu-delivered file → no metric,
// never a fake 0).
func (c *Collector) collectCPUDelivered(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	ok, ratio, wall := c.cpuOK, c.cpuRatio, c.cpuWall
	c.mu.Unlock()
	if !ok {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.descCPURatio,
		prometheus.GaugeValue, ratio)
	ch <- prometheus.MustNewConstMetric(c.descCPUWall,
		prometheus.GaugeValue, wall)
}

// --- fail2ban banned counts (50-fail2ban.sh + prom_emit) ---

// collectFail2ban emits node_fail2ban_banned_ips{jail} from the
// fail2ban-banned file — absent when the file is (node without
// fail2ban → absent series, never a fake 0).
func (c *Collector) collectFail2ban(ch chan<- prometheus.Metric) {
	data, err := os.ReadFile(
		filepath.Join(c.cfg.WatchdogStateDir, "fail2ban-banned"))
	if err != nil {
		return
	}
	for _, pair := range strings.Fields(string(data)) {
		jail, n, ok := strings.Cut(pair, "=")
		if !ok || jail == "" {
			continue
		}
		v, err := strconv.ParseFloat(n, 64)
		if err != nil {
			continue // malformed entry — never emit junk (file contract)
		}
		ch <- prometheus.MustNewConstMetric(c.descF2B,
			prometheus.GaugeValue, v, jail)
	}
}

// --- overlay egress relay state (12-overlay-egress + prom_emit) ---

// collectEgressRelay emits node_overlay_egress_relay_active for
// EVERY configured relay — a 0 while the target is direct vs an
// absent series for "never relayed" must stay distinguishable.
func (c *Collector) collectEgressRelay(ch chan<- prometheus.Metric) {
	for _, r := range c.cfg.EgressRelays {
		v := 0.0
		data, err := os.ReadFile(
			filepath.Join(c.cfg.WatchdogStateDir, "egress-state-"+r))
		if err == nil && strings.TrimSpace(string(data)) == "relay" {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(c.descEgressRelay,
			prometheus.GaugeValue, v, r)
	}
}
