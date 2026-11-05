// cilium_bpf_map_pressure_test.go — coverage for the
// cilium-bpf-map-pressure check (W10-NM1).
package nethealth

import (
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/health/probetest"
	"strings"
	"testing"

	"k8s.io/client-go/kubernetes/fake"
)

// ---------------------------------------------------------------------------
// W10-NM1 — cilium-bpf-map-pressure
// ---------------------------------------------------------------------------

func TestCiliumBPFMapPressureFailsAboveThreshold(t *testing.T) {
	srv, lastQuery := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		return []probetest.PromTestSample{{
			Labels: map[string]string{"node": "w1", "map_name": "ct4_global"},
			Value:  0.92,
		}}
	})
	p := testProber(fake.NewSimpleClientset())
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	res := mustCheck[*ciliumBPFMapPressureCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("expected FAIL above threshold, got %+v", res)
	}
	if !strings.Contains(res.Why, "ct4_global") || !strings.Contains(res.Why, "w1") {
		t.Fatalf("why missing node/map diagnostics: %q", res.Why)
	}
	if !strings.Contains(*lastQuery, "cilium_bpf_map_pressure") ||
		!strings.Contains(*lastQuery, "0.85") {
		t.Fatalf("query = %q, want cilium_bpf_map_pressure > 0.85", *lastQuery)
	}
	if m := probetest.FindMetric(t, "node_automation_cilium_bpf_map_pressure",
		map[string]string{"node": "w1", "map_name": "ct4_global"}); m == nil ||
		m.GetGauge().GetValue() != 0.92 {
		t.Fatalf("gauge missing/wrong: %+v", m)
	}
}

func TestCiliumBPFMapPressureEmptyPasses(t *testing.T) {
	srv, _ := probetest.PromTestServer(t, func(string) []probetest.PromTestSample { return nil })
	p := testProber(fake.NewSimpleClientset())
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	if res := mustCheck[*ciliumBPFMapPressureCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("empty result must pass: %+v", res)
	}
}

func TestCiliumBPFMapPressurePromDownInconclusive(t *testing.T) {
	p := testProber(fake.NewSimpleClientset()) // httpURL is dead by default
	if res := mustCheck[*ciliumBPFMapPressureCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("prometheus outage must be inconclusive-pass, got %+v", res)
	}
}
