package cilium

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
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

		res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
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
		res := probetest.MustCheck[*ciliumDatapathMapCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
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
		res := probetest.MustCheck[*ciliumDatapathMapCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
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
		if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); res.Pass {
			t.Fatalf("breach must fail: %+v", res)
		}

		// Prometheus goes away — the previous gauge value must hold.
		p.Cfg.HTTPContent.URL = dead
		p.HTTPClient = http.DefaultClient
		res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
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

func TestCiliumDatapathMapGuardDropReasons(t *testing.T) {
	positives := []string{
		"No mapping for NAT masquerade",
		"CT: Map insertion failed",
		"SNAT port exhaustion",
		"conntrack table full",
		"NAT table full",
	}
	negatives := []string{
		"select",
		"packet",
		"rejected",
		"sctp",
		"direction",
		"Invalid packet",
		"Policy denied",
	}

	// 1. Validate PromQL regex escaping and RE2 matching directly from
	// the issued query, and reject false-positive negatives in Run().
	t.Run("negatives do not trigger and PromQL RE2 is properly escaped", func(t *testing.T) {
		testutil.CleanupMetric(t, ciliumDatapathDegradedGauge, "nat_ct_map_exhaustion")
		testutil.CleanupMetric(t, ciliumDatapathDegradedGauge, "invalid_identity_drops")
		var dropQuery string
		srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
			if strings.Contains(query, "cilium_drop_count_total") {
				dropQuery = query
				var samples []probetest.PromTestSample
				for _, r := range negatives {
					samples = append(samples, probetest.PromTestSample{
						Labels: map[string]string{"node": "n1", "reason": r}, Value: 5,
					})
				}
				return samples
			}
			return nil
		})
		p := testProber(fake.NewSimpleClientset())
		p.Cfg.HTTPContent.URL = srv.URL
		p.HTTPClient = srv.Client()
		res := probetest.MustCheck[*ciliumDatapathMapCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
		if !res.Pass {
			t.Fatalf("unrelated drop reasons must not fail the check: %+v", res)
		}

		// Extract reason=~"..." from PromQL and unquote as PromQL double-quoted string.
		const prefix = `reason=~`
		idx := strings.Index(dropQuery, prefix)
		if idx < 0 {
			t.Fatalf("drop query missing reason=~ matcher: %q", dropQuery)
		}
		rest := dropQuery[idx+len(prefix):]
		end := strings.IndexByte(rest[1:], '"')
		if end < 0 {
			t.Fatalf("unterminated reason=~ matcher in %q", dropQuery)
		}
		unquoted, err := strconv.Unquote(rest[:end+2])
		if err != nil {
			t.Fatalf("unquote PromQL matcher %q: %v", rest[:end+2], err)
		}
		promRE, err := regexp.Compile("^(?:" + unquoted + ")$")
		if err != nil {
			t.Fatalf("compile extracted PromQL regex %q: %v", unquoted, err)
		}
		for _, pos := range positives {
			if !promRE.MatchString(pos) {
				t.Errorf("PromQL regex %q failed to match %q", unquoted, pos)
			}
		}
		for _, neg := range negatives {
			if promRE.MatchString(neg) {
				t.Errorf("PromQL regex %q falsely matched %q", unquoted, neg)
			}
		}
	})

	// 2. Each positive NAT/CT drop reason with rate > 1 flags nat_ct_map_exhaustion.
	for _, pos := range positives {
		t.Run("positive_"+pos, func(t *testing.T) {
			testutil.CleanupMetric(t, ciliumDatapathDegradedGauge, "nat_ct_map_exhaustion")
			srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
				if strings.Contains(query, "cilium_drop_count_total") {
					return []probetest.PromTestSample{{
						Labels: map[string]string{"node": "n1", "reason": pos}, Value: 2,
					}}
				}
				return nil
			})
			p := testProber(fake.NewSimpleClientset())
			p.Cfg.HTTPContent.URL = srv.URL
			p.HTTPClient = srv.Client()
			res := probetest.MustCheck[*ciliumDatapathMapCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
			if res.Pass {
				t.Fatalf("NAT/CT drop reason %q (>1) must fail the check", pos)
			}
			m := probetest.FindMetric(t, "node_automation_cilium_datapath_degraded",
				map[string]string{"reason": "nat_ct_map_exhaustion"})
			if m == nil || m.GetGauge().GetValue() != 1 {
				t.Fatalf("missing nat_ct_map_exhaustion gauge for %q", pos)
			}
		})
	}

	// 3. invalid_identity_drops sums "Invalid identity" + "Unknown L3 target address" (>1 vs <=1).
	t.Run("invalid_identity_drops threshold", func(t *testing.T) {
		testutil.CleanupMetric(t, ciliumDatapathDegradedGauge, "invalid_identity_drops")
		val := 0.4
		srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
			if strings.Contains(query, "cilium_drop_count_total") {
				return []probetest.PromTestSample{
					{Labels: map[string]string{"node": "n1", "reason": "Invalid identity"}, Value: val},
					{Labels: map[string]string{"node": "n2", "reason": "Unknown L3 target address"}, Value: val},
				}
			}
			return nil
		})
		p := testProber(fake.NewSimpleClientset())
		p.Cfg.HTTPContent.URL = srv.URL
		p.HTTPClient = srv.Client()
		chk := probetest.MustCheck[*ciliumDatapathMapCheck](t, p)
		if res := chk.Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
			t.Fatalf("sum 0.8 <= 1 must pass: %+v", res)
		}
		val = 0.6
		if res := chk.Run(probetest.SweepCtx(ctx, p.Deps)); res.Pass {
			t.Fatal("sum 1.2 > 1 must fail invalid_identity_drops")
		}
	})
}
