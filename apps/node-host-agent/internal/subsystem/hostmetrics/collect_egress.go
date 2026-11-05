// collect_egress.go — overlay egress relay state per
// OVERLAY_EGRESS_RELAYS target (12-overlay-egress + prom_emit):
// the egress-state-<ip> files under the watchdog state dir. Split
// out of hostmetrics.go.
package hostmetrics

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

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
		// Legacy alias: prom_emit's node_watchdog_egress_relay{target}.
		ch <- prometheus.MustNewConstMetric(c.descEgressRelayLegacy,
			prometheus.GaugeValue, v, r)
	}
}
