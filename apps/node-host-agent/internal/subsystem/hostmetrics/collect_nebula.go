// collect_nebula.go — nebula interface/route state and the
// cert-expiry contract (days-left gauge +
// state-nebula-cert-expiring latch). The protobuf wire reader for
// the cert body lives in nebula_cert.go. Split out of
// hostmetrics.go.
package hostmetrics

import (
	"bufio"
	"encoding/pem"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
)

const (
	defaultRouteFile      = "/proc/1/net/route"
	defaultNebulaCertFile = "/host/etc/nebula/interdc/host.crt"
)

// nebulaCertWarnDays mirrors module 13-nebula-health: fewer than this
// many days to notAfter latches the nebula-cert-expiring signal.
const nebulaCertWarnDays = 30

var (
	descNebUp = prometheus.NewDesc(
		"node_host_agent_nebula_interface_up",
		"Nebula interface operstate is up (emitted only when the interface exists).",
		nil, nil)
	descNebRoute = prometheus.NewDesc(
		"node_host_agent_nebula_route_present",
		"A host route via the Nebula interface exists (emitted only when the interface exists).",
		nil, nil)
	descNebCertDays = prometheus.NewDesc(
		"node_host_agent_nebula_cert_days_left",
		"Days until the nebula host certificate notAfter (emitted only when the cert parses).",
		nil, nil)
)

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
	ch <- prometheus.MustNewConstMetric(descNebUp,
		prometheus.GaugeValue, up)

	present := 0.0
	if f, err := os.Open(c.cfg.RouteFile); err == nil {
		defer func() { _ = f.Close() }()
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
	ch <- prometheus.MustNewConstMetric(descNebRoute,
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
	latch := c.state.Path(hoststate.LatchNebulaCertExpiring)
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
		if werr := os.WriteFile(tmp, []byte(content), 0o644); werr != nil {
			logger().Warn("hostmetrics: nebula-cert-expiring latch write failed",
				"path", latch, "error", werr)
		} else if rerr := os.Rename(tmp, latch); rerr != nil {
			logger().Warn("hostmetrics: nebula-cert-expiring latch install failed",
				"path", latch, "error", rerr)
		} else {
			logger().Info("hostmetrics: nebula-cert-expiring latch set",
				"daysLeft", days,
				"warnDays", nebulaCertWarnDays, "path", latch)
		}
	case days >= nebulaCertWarnDays && statErr == nil:
		if rerr := os.Remove(latch); rerr != nil {
			logger().Warn("hostmetrics: nebula-cert-expiring latch remove failed",
				"path", latch, "error", rerr)
		} else {
			logger().Info("hostmetrics: nebula-cert-expiring latch cleared",
				"daysLeft", days, "path", latch)
		}
	}
}

// collectNebulaCert emits the cert days-left gauge — only when the
// cert parses (absent/garbage cert → absent series, distinguishing
// "no cert" from "0 days"). The parse result arrives via scrapeCtx
// — Collect already ran nebulaCertDaysLeft for the latch updaters.
func (c *Collector) collectNebulaCert(ch chan<- prometheus.Metric, sc scrapeCtx) {
	if !sc.certOK {
		return
	}
	ch <- prometheus.MustNewConstMetric(descNebCertDays,
		prometheus.GaugeValue, float64(sc.certDays))
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
