// cilium_bpf_map_pressure_test.go — coverage for the
// cilium-bpf-map-pressure check (W10-NM1).
package clusterhealthprobes

import (
	"strings"
	"testing"

	"k8s.io/client-go/kubernetes/fake"
)

// ---------------------------------------------------------------------------
// W10-NM1 — cilium-bpf-map-pressure
// ---------------------------------------------------------------------------

func TestCiliumBPFMapPressureFailsAboveThreshold(t *testing.T) {
	srv, lastQuery := promTestServer(t, func(query string) []promTestSample {
		return []promTestSample{{
			labels: map[string]string{"node": "w1", "map_name": "ct4_global"},
			value:  0.92,
		}}
	})
	p := testProber(fake.NewSimpleClientset())
	p.cfg.httpURL = srv.URL
	p.httpClient = srv.Client()
	res := mustCheck[*ciliumBPFMapPressureCheck](t, p).run(ctx)
	if res.pass {
		t.Fatalf("expected FAIL above threshold, got %+v", res)
	}
	if !strings.Contains(res.why, "ct4_global") || !strings.Contains(res.why, "w1") {
		t.Fatalf("why missing node/map diagnostics: %q", res.why)
	}
	if !strings.Contains(*lastQuery, "cilium_bpf_map_pressure") ||
		!strings.Contains(*lastQuery, "0.85") {
		t.Fatalf("query = %q, want cilium_bpf_map_pressure > 0.85", *lastQuery)
	}
	if m := findMetric(t, "node_automation_cilium_bpf_map_pressure",
		map[string]string{"node": "w1", "map_name": "ct4_global"}); m == nil ||
		m.GetGauge().GetValue() != 0.92 {
		t.Fatalf("gauge missing/wrong: %+v", m)
	}
}

func TestCiliumBPFMapPressureEmptyPasses(t *testing.T) {
	srv, _ := promTestServer(t, func(string) []promTestSample { return nil })
	p := testProber(fake.NewSimpleClientset())
	p.cfg.httpURL = srv.URL
	p.httpClient = srv.Client()
	if res := mustCheck[*ciliumBPFMapPressureCheck](t, p).run(ctx); !res.pass {
		t.Fatalf("empty result must pass: %+v", res)
	}
}

func TestCiliumBPFMapPressurePromDownInconclusive(t *testing.T) {
	p := testProber(fake.NewSimpleClientset()) // httpURL is dead by default
	if res := mustCheck[*ciliumBPFMapPressureCheck](t, p).run(ctx); !res.pass {
		t.Fatalf("prometheus outage must be inconclusive-pass, got %+v", res)
	}
}
