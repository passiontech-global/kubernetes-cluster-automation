package cilium

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// Each datapath signature breaching fails the check and emits its
// reason series; a clean vector passes; a query failure is
// inconclusive (carry-forward, Infra) rather than "healthy".
func TestCiliumDatapathMapGuard(t *testing.T) {
	t.Run("breach flags reasons", func(t *testing.T) {
		srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
			if strings.Contains(query, "bpf_map_ops") ||
				strings.Contains(query, "unreachable_health") {
				return []probetest.PromTestSample{{Labels: map[string]string{}, Value: 1}}
			}
			return nil
		})
		p := testProber(fake.NewSimpleClientset())
		p.Cfg.HTTPContent.URL = srv.URL
		p.HTTPClient = srv.Client()
		chk := probetest.MustCheck[*ciliumDatapathMapCheck](t, p)

		res := chk.Run(probetest.SweepCtx(ctx))
		if res.Pass {
			t.Fatal("breached signatures must fail the check")
		}
		for _, r := range []string{"bpf_map_ops_fail", "unreachable_health_endpoints"} {
			if !ciliumDatapathDegradedGauge.DeleteLabelValues(r) {
				t.Fatalf("missing degraded series for %s", r)
			}
		}
		if ciliumDatapathDegradedGauge.DeleteLabelValues("endpoint_regeneration_fail") {
			t.Fatal("clean signature flagged degraded")
		}
	})

	t.Run("clean passes", func(t *testing.T) {
		srv, _ := probetest.PromTestServer(t, func(string) []probetest.PromTestSample { return nil })
		p := testProber(fake.NewSimpleClientset())
		p.Cfg.HTTPContent.URL = srv.URL
		p.HTTPClient = srv.Client()
		res := probetest.MustCheck[*ciliumDatapathMapCheck](t, p).Run(probetest.SweepCtx(ctx))
		if !res.Pass {
			t.Fatalf("clean datapath must pass: %+v", res)
		}
	})
}

// A query failure is inconclusive, not healthy: the check reports
// Infra and carries the previous gauge value forward; on the
// FIRST-EVER failure there is nothing to carry and nothing may be
// emitted.
func TestCiliumDatapathMapGuardQueryFailureCarryForward(t *testing.T) {
	testutil.CleanupMetric(t, ciliumDatapathDegradedGauge, "bpf_map_ops_fail")
	dead := prometheusDeadServer(t)

	t.Run("first-ever failure — infra, no emit", func(t *testing.T) {
		p := testProber(fake.NewSimpleClientset())
		p.Cfg.HTTPContent.URL = dead
		p.HTTPClient = http.DefaultClient
		res := probetest.MustCheck[*ciliumDatapathMapCheck](t, p).Run(probetest.SweepCtx(ctx))
		if res.Pass {
			t.Fatalf("failed queries must not read healthy: %+v", res)
		}
		if ciliumDatapathDegradedGauge.DeleteLabelValues("bpf_map_ops_fail") {
			t.Fatal("emitted a degraded series from a failed query")
		}
	})

	t.Run("carried forward after a breach", func(t *testing.T) {
		srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
			if strings.Contains(query, "bpf_map_ops") {
				return []probetest.PromTestSample{{Labels: map[string]string{}, Value: 1}}
			}
			return nil
		})
		p := testProber(fake.NewSimpleClientset())
		p.Cfg.HTTPContent.URL = srv.URL
		p.HTTPClient = srv.Client()
		chk := probetest.MustCheck[*ciliumDatapathMapCheck](t, p)
		if res := chk.Run(probetest.SweepCtx(ctx)); res.Pass {
			t.Fatalf("breach must fail: %+v", res)
		}

		// Prometheus goes away — the previous gauge value must hold.
		p.Cfg.HTTPContent.URL = dead
		p.HTTPClient = http.DefaultClient
		res := chk.Run(probetest.SweepCtx(ctx))
		if res.Pass {
			t.Fatalf("query outage must be Infra, not healthy: %+v", res)
		}
		m := probetest.FindMetric(t, "node_automation_cilium_datapath_degraded",
			map[string]string{"reason": "bpf_map_ops_fail"})
		if m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatal("degraded series dropped during the query outage — carry-forward broken")
		}
	})
}

// prometheusDeadServer returns the URL of a closed httptest server —
// every PromQuery against it fails at the transport layer.
func prometheusDeadServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()
	return url
}
