package nethealth

import (
	"strings"
	"testing"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
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

		res := chk.Run(ctx)
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
		res := probetest.MustCheck[*ciliumDatapathMapCheck](t, p).Run(ctx)
		if !res.Pass {
			t.Fatalf("clean datapath must pass: %+v", res)
		}
	})
}
