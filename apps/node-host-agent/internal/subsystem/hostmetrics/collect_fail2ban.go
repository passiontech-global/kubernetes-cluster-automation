// collect_fail2ban.go — fail2ban banned-IP counts from the
// nethealth check's fail2ban-banned file (50-fail2ban.sh +
// prom_emit). Split out of hostmetrics.go.
package hostmetrics

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

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
