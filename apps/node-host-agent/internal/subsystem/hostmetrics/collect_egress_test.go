// collect_egress_test.go — overlay egress relay gauge and its legacy prom_emit alias.

package hostmetrics

import (
	"path/filepath"
	"testing"
)

// --- egress relay gauge ---

func TestEgressRelayGauge(t *testing.T) {
	cfg, dirs := fixture(t)
	cfg.EgressRelays = []string{"8.8.8.8", "1.1.1.1"}
	write(t, filepath.Join(dirs["state"], "egress-state-8.8.8.8"), "relay\n")
	write(t, filepath.Join(dirs["state"], "egress-state-1.1.1.1"), "direct\n")
	c := New(cfg)
	if v, ok := metricValue(t, c, "node_overlay_egress_relay_active",
		map[string]string{"target": "8.8.8.8"}); !ok || v != 1 {
		t.Fatalf("relay=%v,%v want 1", v, ok)
	}
	// Explicit 0 while direct — series always emitted per target.
	if v, ok := metricValue(t, c, "node_overlay_egress_relay_active",
		map[string]string{"target": "1.1.1.1"}); !ok || v != 0 {
		t.Fatalf("direct=%v,%v want 0", v, ok)
	}
}

// --- legacy prom_emit aliases (node_watchdog_state /
// node_watchdog_egress_relay — the fluxcd PrometheusRules contract) ---

func TestEgressRelayLegacyAlias(t *testing.T) {
	cfg, dirs := fixture(t)
	cfg.EgressRelays = []string{"8.8.8.8", "1.1.1.1"}
	write(t, filepath.Join(dirs["state"], "egress-state-8.8.8.8"), "relay\n")
	write(t, filepath.Join(dirs["state"], "egress-state-1.1.1.1"), "direct\n")
	c := New(cfg)

	if v, ok := metricValue(t, c, "node_watchdog_egress_relay",
		map[string]string{"target": "8.8.8.8"}); !ok || v != 1 {
		t.Fatalf("node_watchdog_egress_relay{8.8.8.8}=%v ok=%v want 1", v, ok)
	}
	if v, ok := metricValue(t, c, "node_watchdog_egress_relay",
		map[string]string{"target": "1.1.1.1"}); !ok || v != 0 {
		t.Fatalf("node_watchdog_egress_relay{1.1.1.1}=%v ok=%v want 0", v, ok)
	}
}
