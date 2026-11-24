package watchdogs

import (
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

func TestObservabilityCardinalityGuard(t *testing.T) {
	t.Run("absolute head_series breach emits gauges culprit and event, then cleans up on recovery", func(t *testing.T) {
		t.Setenv("NODE_AUTOMATION_OBS_HEAD_SERIES_WARN", "1000")
		t.Setenv("NODE_AUTOMATION_OBS_HEAD_SERIES_GROWTH_PER_HOUR", "500")

		var breached atomic.Bool
		breached.Store(true)
		var mu sync.Mutex
		var seenQueries []string

		srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
			mu.Lock()
			seenQueries = append(seenQueries, query)
			mu.Unlock()
			switch {
			case strings.Contains(query, "Watchdog"):
				return []probetest.PromTestSample{{Value: 1}}
			case query == obsHeadSeriesQuery:
				if breached.Load() {
					return []probetest.PromTestSample{{Value: 2000}}
				}
				return []probetest.PromTestSample{{Value: 500}}
			case query == obsHeadSeriesGrowthQuery:
				return []probetest.PromTestSample{{Value: 100}}
			case query == obsCardinalitySeriesAddedQuery:
				return []probetest.PromTestSample{
					{Labels: map[string]string{"job": "noisy-app", "namespace": "prod"}, Value: 1200},
					{Labels: map[string]string{"job": "other-app", "namespace": "staging"}, Value: 300},
				}
			case query == obsCardinalitySamplesScrapedQuery:
				return []probetest.PromTestSample{
					{Labels: map[string]string{"job": "noisy-app", "namespace": "prod"}, Value: 50000},
				}
			}
			return nil
		})

		cs := fake.NewSimpleClientset()
		p := testProber(cs)
		p.Cfg.HTTPContent.URL = srv.URL
		p.HTTPClient = srv.Client()
		chk := probetest.MustCheck[*observabilityPipelineCheck](t, p)

		// Cycle 1: breached.
		res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if res.Pass {
			t.Fatal("expected check FAIL when head_series exceeds warn threshold")
		}
		if m := probetest.FindMetric(t, "node_automation_prometheus_head_series", nil); m == nil || m.GetGauge().GetValue() != 2000 {
			t.Fatalf("head_series gauge = %v, want 2000", m)
		}
		if m := probetest.FindMetric(t, "node_automation_observability_pipeline_degraded", map[string]string{"component": "prometheus_cardinality"}); m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatalf("degraded{component=prometheus_cardinality} = %v, want 1", m)
		}
		if m := probetest.FindMetric(t, "node_automation_prometheus_cardinality_culprit", map[string]string{"job": "noisy-app", "namespace": "prod"}); m == nil || m.GetGauge().GetValue() != 1200 {
			t.Fatalf("culprit gauge missing or wrong value: %v", m)
		}
		evs, err := cs.EventsV1().Events(obsPipelineEventNS).List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(evs.Items) != 1 || evs.Items[0].Reason != obsCardinalityEventReason || evs.Items[0].Type != corev1.EventTypeWarning {
			t.Fatalf("unexpected events: %+v", evs.Items)
		}
		if !strings.Contains(evs.Items[0].Note, "prod/noisy-app") {
			t.Fatalf("event note missing culprit: %q", evs.Items[0].Note)
		}

		// Cycle 2 (still breached): event must be deduped (still 1 event).
		_ = chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		evs, _ = cs.EventsV1().Events(obsPipelineEventNS).List(ctx, metav1.ListOptions{})
		if len(evs.Items) != 1 {
			t.Fatalf("events = %d, want 1 (deduped)", len(evs.Items))
		}

		// Recovery: below threshold -> PASS, culprit series deleted, attribution NOT queried.
		breached.Store(false)
		mu.Lock()
		seenQueries = nil
		mu.Unlock()

		res = chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if !res.Pass {
			t.Fatalf("expected PASS on recovery, got %+v", res)
		}
		if m := probetest.FindMetric(t, "node_automation_prometheus_cardinality_culprit", map[string]string{"job": "noisy-app", "namespace": "prod"}); m != nil {
			t.Fatalf("stale culprit series not deleted on recovery: %v", m)
		}
		if m := probetest.FindMetric(t, "node_automation_observability_pipeline_degraded", map[string]string{"component": "prometheus_cardinality"}); m != nil {
			t.Fatalf("stale degraded series not deleted on recovery: %v", m)
		}
		mu.Lock()
		queried := slices.Clone(seenQueries)
		mu.Unlock()
		for _, q := range queried {
			if q == obsCardinalitySeriesAddedQuery || q == obsCardinalitySamplesScrapedQuery {
				t.Fatalf("attribution query %q called when below thresholds", q)
			}
		}
	})

	t.Run("growth deriv requires 2 consecutive cycles and skips attribution below threshold", func(t *testing.T) {
		t.Setenv("NODE_AUTOMATION_OBS_HEAD_SERIES_WARN", "1500000")
		t.Setenv("NODE_AUTOMATION_OBS_HEAD_SERIES_GROWTH_PER_HOUR", "200000")

		var mu sync.Mutex
		var seenQueries []string
		srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
			mu.Lock()
			seenQueries = append(seenQueries, query)
			mu.Unlock()
			switch {
			case strings.Contains(query, "Watchdog"):
				return []probetest.PromTestSample{{Value: 1}}
			case query == obsHeadSeriesQuery:
				return []probetest.PromTestSample{{Value: 100000}}
			case query == obsHeadSeriesGrowthQuery:
				return []probetest.PromTestSample{{Value: 350000}}
			case query == obsCardinalitySeriesAddedQuery:
				return []probetest.PromTestSample{{Labels: map[string]string{"job": "spike", "namespace": "ns"}, Value: 500}}
			}
			return nil
		})

		cs := fake.NewSimpleClientset()
		p := testProber(cs)
		p.Cfg.HTTPContent.URL = srv.URL
		p.HTTPClient = srv.Client()
		chk := probetest.MustCheck[*observabilityPipelineCheck](t, p)

		// Cycle 1: 1st growth breach -> PASS, no attribution query called.
		res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if !res.Pass {
			t.Fatalf("single-cycle deriv spike must not fail (hysteresis): %+v", res)
		}
		mu.Lock()
		for _, q := range seenQueries {
			if q == obsCardinalitySeriesAddedQuery || q == obsCardinalitySamplesScrapedQuery {
				t.Fatalf("attribution query %q called on single-cycle growth spike", q)
			}
		}
		mu.Unlock()

		// Cycle 2: 2nd consecutive growth breach -> FAIL + attribution + event.
		res = chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if res.Pass {
			t.Fatal("expected FAIL on 2nd consecutive growth breach")
		}
		if m := probetest.FindMetric(t, "node_automation_prometheus_cardinality_culprit", map[string]string{"job": "spike", "namespace": "ns"}); m == nil {
			t.Fatal("expected culprit series on 2nd consecutive growth breach")
		}
	})

	t.Run("inconclusive error preserves held culprit series and streak", func(t *testing.T) {
		t.Setenv("NODE_AUTOMATION_OBS_HEAD_SERIES_WARN", "1000")
		t.Setenv("NODE_AUTOMATION_OBS_HEAD_SERIES_GROWTH_PER_HOUR", "500")

		srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
			switch {
			case strings.Contains(query, "Watchdog"):
				return []probetest.PromTestSample{{Value: 1}}
			case query == obsHeadSeriesQuery:
				return []probetest.PromTestSample{{Value: 2000}}
			case query == obsHeadSeriesGrowthQuery:
				return []probetest.PromTestSample{{Value: 700}}
			case query == obsCardinalitySeriesAddedQuery:
				return []probetest.PromTestSample{{Labels: map[string]string{"job": "held", "namespace": "ns"}, Value: 999}}
			}
			return nil
		})
		cs := fake.NewSimpleClientset()
		p := testProber(cs)
		p.Cfg.HTTPContent.URL = srv.URL
		p.HTTPClient = srv.Client()
		chk := probetest.MustCheck[*observabilityPipelineCheck](t, p)

		// Cycle 1: establishes culprit series + growthStreak=1.
		_ = chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if chk.growthStreak.Count(obsCardinalityGrowthKey) != 1 {
			t.Fatalf("growthStreak = %d, want 1", chk.growthStreak.Count(obsCardinalityGrowthKey))
		}

		// Cycle 2: Prometheus unreachable -> inconclusive, preserves culprit + streak.
		p.HTTPClient = failingHTTPClient(t)
		res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if res.Pass || res.Infra == nil {
			t.Fatalf("expected inconclusive Infra failure, got %+v", res)
		}
		if chk.growthStreak.Count(obsCardinalityGrowthKey) != 1 {
			t.Fatalf("growthStreak mutated on inconclusive cycle: %d", chk.growthStreak.Count(obsCardinalityGrowthKey))
		}
		if m := probetest.FindMetric(t, "node_automation_prometheus_cardinality_culprit", map[string]string{"job": "held", "namespace": "ns"}); m == nil {
			t.Fatal("held culprit series was pruned on inconclusive cycle")
		}
	})

	t.Run("culprit jobs containing slash do not collide", func(t *testing.T) {
		t.Setenv("NODE_AUTOMATION_OBS_HEAD_SERIES_WARN", "1000")
		t.Setenv("NODE_AUTOMATION_OBS_HEAD_SERIES_GROWTH_PER_HOUR", "500")

		var breached atomic.Bool
		breached.Store(true)
		srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
			switch {
			case strings.Contains(query, "Watchdog"):
				return []probetest.PromTestSample{{Value: 1}}
			case query == obsHeadSeriesQuery:
				if breached.Load() {
					return []probetest.PromTestSample{{Value: 2000}}
				}
				return []probetest.PromTestSample{{Value: 500}}
			case query == obsHeadSeriesGrowthQuery:
				return []probetest.PromTestSample{{Value: 100}}
			case query == obsCardinalitySeriesAddedQuery:
				return []probetest.PromTestSample{
					{Labels: map[string]string{"job": "a/b", "namespace": "c"}, Value: 700},
					{Labels: map[string]string{"job": "a", "namespace": "b/c"}, Value: 300},
				}
			}
			return nil
		})
		cs := fake.NewSimpleClientset()
		p := testProber(cs)
		p.Cfg.HTTPContent.URL = srv.URL
		p.HTTPClient = srv.Client()
		chk := probetest.MustCheck[*observabilityPipelineCheck](t, p)

		res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if res.Pass {
			t.Fatal("expected FAIL when head_series exceeds warn")
		}
		if m := probetest.FindMetric(t, "node_automation_prometheus_cardinality_culprit", map[string]string{"job": "a/b", "namespace": "c"}); m == nil || m.GetGauge().GetValue() != 700 {
			t.Fatalf("expected culprit job=a/b ns=c value 700, got %v", m)
		}
		if m := probetest.FindMetric(t, "node_automation_prometheus_cardinality_culprit", map[string]string{"job": "a", "namespace": "b/c"}); m == nil || m.GetGauge().GetValue() != 300 {
			t.Fatalf("expected culprit job=a ns=b/c value 300, got %v", m)
		}

		breached.Store(false)
		res = chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if !res.Pass {
			t.Fatalf("expected PASS on recovery, got %+v", res)
		}
		if m := probetest.FindMetric(t, "node_automation_prometheus_cardinality_culprit", map[string]string{"job": "a/b", "namespace": "c"}); m != nil {
			t.Fatalf("stale series job=a/b ns=c not pruned: %v", m)
		}
		if m := probetest.FindMetric(t, "node_automation_prometheus_cardinality_culprit", map[string]string{"job": "a", "namespace": "b/c"}); m != nil {
			t.Fatalf("stale series job=a ns=b/c not pruned: %v", m)
		}
	})

	t.Run("VictoriaMetrics backend queries vm_cache_entries and scrape_samples_scraped with dynamic Regarding", func(t *testing.T) {
		t.Setenv("NODE_AUTOMATION_OBS_HEAD_SERIES_WARN", "1000")
		t.Setenv("NODE_AUTOMATION_OBS_HEAD_SERIES_GROWTH_PER_HOUR", "500")

		var breached atomic.Bool
		breached.Store(true)
		var mu sync.Mutex
		var seenQueries []string

		srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
			mu.Lock()
			seenQueries = append(seenQueries, query)
			mu.Unlock()
			switch {
			case query == "count(vm_app_version)":
				return []probetest.PromTestSample{{Value: 1}}
			case strings.Contains(query, "Watchdog"):
				return []probetest.PromTestSample{{Value: 1}}
			case query == vmHeadSeriesQuery:
				if breached.Load() {
					return []probetest.PromTestSample{{Value: 2500}}
				}
				return []probetest.PromTestSample{{Value: 400}}
			case query == vmHeadSeriesGrowthQuery:
				return []probetest.PromTestSample{{Value: 100}}
			case query == obsCardinalitySamplesScrapedQuery:
				return []probetest.PromTestSample{
					{Labels: map[string]string{"job": "vm-noisy", "namespace": "apps"}, Value: 88000},
				}
			}
			return nil
		})

		vmStoragePod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: obsVMEventNS, Name: "vmstorage-victoria-metrics-k8s-stack-0",
		}}
		cs := fake.NewSimpleClientset(vmStoragePod)
		p := testProber(cs)
		p.Cfg.HTTPContent.URL = srv.URL + "/health"
		p.HTTPClient = srv.Client()
		chk := probetest.MustCheck[*observabilityPipelineCheck](t, p)

		res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if res.Pass {
			t.Fatal("expected check FAIL when vm_cache_entries exceeds warn threshold")
		}
		if m := probetest.FindMetric(t, "node_automation_prometheus_head_series", nil); m == nil || m.GetGauge().GetValue() != 2500 {
			t.Fatalf("head_series gauge = %v, want 2500", m)
		}
		if m := probetest.FindMetric(t, "node_automation_prometheus_cardinality_culprit", map[string]string{"job": "vm-noisy", "namespace": "apps"}); m == nil || m.GetGauge().GetValue() != 88000 {
			t.Fatalf("culprit gauge missing or wrong value: %v", m)
		}
		mu.Lock()
		for _, q := range seenQueries {
			if q == obsCardinalitySeriesAddedQuery || q == obsHeadSeriesQuery {
				t.Fatalf("Prometheus-only query %q issued on VictoriaMetrics backend", q)
			}
		}
		mu.Unlock()

		evs, err := cs.EventsV1().Events(obsVMEventNS).List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(evs.Items) != 1 || evs.Items[0].Reason != obsCardinalityEventReason {
			t.Fatalf("unexpected events in %s: %+v", obsVMEventNS, evs.Items)
		}
		if evs.Items[0].Regarding.Kind != "VMCluster" || evs.Items[0].Regarding.Name != "victoria-metrics-k8s-stack" {
			t.Fatalf("unexpected Regarding: %+v", evs.Items[0].Regarding)
		}
		if !strings.Contains(evs.Items[0].Note, "apps/vm-noisy") {
			t.Fatalf("event note missing culprit: %q", evs.Items[0].Note)
		}

		// Recovery prunes gauges.
		breached.Store(false)
		res = chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if !res.Pass {
			t.Fatalf("expected PASS on VM cardinality recovery, got %+v", res)
		}
		if m := probetest.FindMetric(t, "node_automation_prometheus_cardinality_culprit", map[string]string{"job": "vm-noisy", "namespace": "apps"}); m != nil {
			t.Fatalf("stale VM culprit series not deleted on recovery: %v", m)
		}
	})
}
