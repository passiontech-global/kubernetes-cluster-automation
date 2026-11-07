// collect_nebula.go — nebula interface/route state and the
// cert-expiry contract (days-left gauge +
// state-nebula-cert-expiring latch). The protobuf wire reader for
// the cert body lives in nebula_cert.go. Split out of
// hostmetrics.go.
package hostmetrics

import (
	"bufio"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
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
// removed on recovery, and nebula-cert-days-left tracks the last
// parsed day count. An absent or unparseable cert CLEARS both files
// — the shell left the latch behind on `[ -s "$cert" ]` failure,
// but a permanent phantom latch breaks both the file consumers and
// the emit-0 alert contract (a gone cert cannot be "expiring").
//
// Write discipline: this updater runs on BOTH the scrape path
// (Collect) and the 30s latch ticker (refreshLatches), so every
// write is gated on an actual change — the days file is
// read-compared before the tmp+rename (its content changes once a
// day, not once per scrape), and the latch moves only on a real
// enter/exit transition. A steady-state scrape therefore writes
// nothing to disk.
func (c *Collector) updateCertLatch(days int64, ok bool) {
	daysPath := filepath.Join(c.cfg.WatchdogStateDir, "nebula-cert-days-left")
	if !ok {
		c.state.Exit(hoststate.LatchNebulaCertExpiring, nil)
		_ = os.Remove(daysPath)
		return
	}
	daysContent := strconv.FormatInt(days, 10) + "\n"
	if cur, err := os.ReadFile(daysPath); err != nil || string(cur) != daysContent {
		if err := hostutil.WriteFileAtomic(daysPath, daysContent); err != nil {
			logger().Debug("hostmetrics: nebula-cert-days-left write failed",
				"path", daysPath, "error", err)
		}
	}
	switch {
	case days < nebulaCertWarnDays:
		c.state.Enter(hoststate.LatchNebulaCertExpiring,
			fmt.Sprintf("daysLeft=%d < warnDays=%d", days, nebulaCertWarnDays))
	default:
		c.state.Exit(hoststate.LatchNebulaCertExpiring, nil)
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
