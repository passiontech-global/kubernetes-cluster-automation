package watchdogs

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
)

// A missing Watchdog heartbeat or a rising error counter degrades
// the pipeline — gauge, check FAIL and the deduped Warning Event.
func TestObservabilityPipelineGuard(t *testing.T) {
	t.Run("degraded stages flag + event", func(t *testing.T) {
		srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
			switch {
			case strings.Contains(query, "Watchdog"):
				return nil // heartbeat absent — the worst signal
			case strings.Contains(query, "notifications_failed") ||
				strings.Contains(query, "dropped_records"):
				return []probetest.PromTestSample{{Labels: map[string]string{}, Value: 4}}
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
			t.Fatal("degraded pipeline must fail the check")
		}
		for _, c := range []string{"watchdog_heartbeat", "alertmanager_notifications", "fluentbit_drops"} {
			if !obsPipelineDegradedGauge.DeleteLabelValues(c) {
				t.Fatalf("missing degraded series for %s", c)
			}
		}
		if obsPipelineDegradedGauge.DeleteLabelValues("prometheus_tsdb_wal") {
			t.Fatal("quiet counter flagged degraded")
		}
		evs, err := cs.EventsV1().Events("prometheus-operator").List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(evs.Items) != 3 {
			t.Fatalf("warning events = %d, want 3", len(evs.Items))
		}
		for _, ev := range evs.Items {
			if ev.Reason != "ObservabilityPipelineDegraded" ||
				ev.Type != corev1.EventTypeWarning {
				t.Fatalf("bad event: %v/%v", ev.Reason, ev.Type)
			}
		}
	})

	t.Run("heartbeat + quiet counters pass", func(t *testing.T) {
		srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
			if strings.Contains(query, "Watchdog") {
				return []probetest.PromTestSample{{Labels: map[string]string{}, Value: 1}}
			}
			return nil
		})
		p := testProber(fake.NewSimpleClientset())
		p.Cfg.HTTPContent.URL = srv.URL
		p.HTTPClient = srv.Client()
		res := probetest.MustCheck[*observabilityPipelineCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
		if !res.Pass {
			t.Fatalf("healthy pipeline must pass: %+v", res)
		}
	})

	// observability-pipeline-guard — the Prometheus→Alertmanager leg: dropped notifications
	// and a zero discovered-alertmanager set both degrade even while
	// the Watchdog heartbeat and every other counter stay quiet.
	t.Run("prometheus→alertmanager delivery signals degrade", func(t *testing.T) {
		srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
			switch {
			case strings.Contains(query, "Watchdog"):
				return []probetest.PromTestSample{{Labels: map[string]string{}, Value: 1}}
			case strings.Contains(query, "notifications_dropped"):
				return []probetest.PromTestSample{{Labels: map[string]string{}, Value: 3}}
			case strings.Contains(query, "alertmanagers_discovered"):
				return []probetest.PromTestSample{{Labels: map[string]string{}, Value: 0}}
			}
			return nil
		})
		cs := fake.NewSimpleClientset()
		p := testProber(cs)
		p.Cfg.HTTPContent.URL = srv.URL
		p.HTTPClient = srv.Client()
		res := probetest.MustCheck[*observabilityPipelineCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
		if res.Pass {
			t.Fatal("dropped notifications + zero discovered alertmanagers must fail the check")
		}
		for _, c := range []string{"prometheus_notifications_dropped", "prometheus_alertmanagers_discovered"} {
			if !obsPipelineDegradedGauge.DeleteLabelValues(c) {
				t.Fatalf("missing degraded series for %s", c)
			}
		}
		if obsPipelineDegradedGauge.DeleteLabelValues("prometheus_tsdb_wal") {
			t.Fatal("quiet counter flagged degraded")
		}
		evs, err := cs.EventsV1().Events(obsPipelineEventNS).List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(evs.Items) != 2 {
			t.Fatalf("warning events = %d, want 2", len(evs.Items))
		}
	})
}

// The connect-sync probe flags a Running onepassword-connect pod whose
// connect-sync container is !Ready or crashlooping — even while
// connect-api stays Ready on stale data.
func TestOnePasswordConnectSyncProbe(t *testing.T) {
	degraded := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "external-secrets", Name: "onepassword-connect-aaa",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour))},
		Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: "connect-api"}, {Name: "connect-sync"}}},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "connect-api", Ready: true},
				{Name: "connect-sync", Ready: false},
			},
		},
	}
	healthy := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "onepassword", Name: "onepassword-connect-bbb"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: "connect-api"}, {Name: "connect-sync"}}},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "connect-api", Ready: true},
				{Name: "connect-sync", Ready: true},
			},
		},
	}
	cs := fake.NewSimpleClientset(degraded, healthy)
	p := testProber(cs)
	res := probetest.MustCheck[*onePasswordConnectSyncCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass {
		t.Fatal("degraded connect-sync must fail the check")
	}
	m := probetest.FindMetric(t, "node_automation_onepassword_connect_sync_unhealthy",
		map[string]string{"namespace": "external-secrets", "pod": "onepassword-connect-aaa"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("unhealthy series missing for the degraded pod")
	}
	if probetest.FindMetric(t, "node_automation_onepassword_connect_sync_unhealthy",
		map[string]string{"namespace": "onepassword", "pod": "onepassword-connect-bbb"}) != nil {
		t.Fatal("healthy pod flagged unhealthy")
	}
}

// Recovery prune: a degraded episode emits the Warning Event once;
// when the component recovers (a conclusive healthy cycle) the
// episode marker is pruned so a LATER relapse emits a fresh Event —
// a Prometheus flap mid-recovery must not re-arm it, though.
func TestObservabilityPipelineEventPrunedOnRecovery(t *testing.T) {
	var healthy atomic.Bool
	healthy.Store(false)
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if !strings.Contains(query, "Watchdog") {
			return nil // counters quiet in every cycle
		}
		if healthy.Load() {
			return []probetest.PromTestSample{{Labels: map[string]string{}, Value: 1}}
		}
		return nil // heartbeat absent — degraded
	})
	cs := fake.NewSimpleClientset()
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	chk := probetest.MustCheck[*observabilityPipelineCheck](t, p)

	// Episode 1 — degraded: one Warning Event, marker armed.
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); res.Pass {
		t.Fatal("degraded pipeline must fail")
	}
	if !chk.evented.Has("watchdog_heartbeat") {
		t.Fatal("episode marker not armed after the first emission")
	}
	// Inconclusive cycle (query error) — the marker must NOT be
	// pruned (a flap must not re-page the same episode).
	p.HTTPClient = failingHTTPClient(t)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); res.Pass {
		t.Fatal("inconclusive cycle must not pass")
	}
	if !chk.evented.Has("watchdog_heartbeat") {
		t.Fatal("episode marker pruned on an inconclusive cycle")
	}
	p.HTTPClient = srv.Client()
	// Recovery — conclusive healthy cycle prunes the marker.
	healthy.Store(true)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("healthy pipeline must pass: %+v", res)
	}
	if chk.evented.Has("watchdog_heartbeat") {
		t.Fatal("episode marker not pruned after recovery")
	}
	// Relapse — a FRESH event is emitted (marker re-armed).
	healthy.Store(false)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); res.Pass {
		t.Fatal("relapsed pipeline must fail")
	}
	evs, err := cs.EventsV1().Events(obsPipelineEventNS).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs.Items) != 2 {
		t.Fatalf("warning events = %d, want 2 (episode + relapse)", len(evs.Items))
	}
}

func TestObservabilityPipelineGuardVictoriaMetrics(t *testing.T) {
	t.Run("VMCluster detects VM-specific pipeline degradations and targets VMCluster", func(t *testing.T) {
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
			case strings.Contains(query, "vmalert_alerts_send_errors_total") ||
				strings.Contains(query, "vm_rows_ignored_total") ||
				strings.Contains(query, "vmagent_remotewrite_errors_total"):
				return []probetest.PromTestSample{{Value: 2}}
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
			t.Fatal("degraded VM pipeline must fail the check")
		}
		for _, c := range []string{"vmalert_notifications_dropped", "vmstorage_rows_ignored", "vmagent_remotewrite_errors"} {
			if !obsPipelineDegradedGauge.DeleteLabelValues(c) {
				t.Fatalf("missing degraded series for %s", c)
			}
		}
		mu.Lock()
		for _, q := range seenQueries {
			if strings.Contains(q, "prometheus_tsdb_wal_corruptions_total") ||
				strings.Contains(q, "prometheus_notifications_dropped_total") {
				t.Fatalf("Prometheus-only query %q issued on VictoriaMetrics backend", q)
			}
		}
		mu.Unlock()

		evs, err := cs.EventsV1().Events(obsVMEventNS).List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(evs.Items) != 3 {
			t.Fatalf("warning events in %s = %d, want 3", obsVMEventNS, len(evs.Items))
		}
		for _, ev := range evs.Items {
			if ev.Regarding.APIVersion != "operator.victoriametrics.com/v1beta1" ||
				ev.Regarding.Kind != "VMCluster" ||
				ev.Regarding.Name != "victoria-metrics-k8s-stack" ||
				ev.Regarding.Namespace != obsVMEventNS {
				t.Fatalf("unexpected Regarding: %+v", ev.Regarding)
			}
		}
	})

	t.Run("VMSingle resolves Regarding Kind=VMSingle when vmsingle pod exists", func(t *testing.T) {
		const wantScrapesFailedQuery = `(sum(increase(vm_promscrape_scrapes_failed_total[10m])) / clamp_min(sum(increase(vm_promscrape_scrape_requests_total[10m])) or vector(1), 1)) > 0.05 and sum(increase(vm_promscrape_scrapes_failed_total[10m])) > 10`
		var sawExactQuery atomic.Bool
		srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
			switch {
			case query == "count(vm_app_version)":
				return []probetest.PromTestSample{{Value: 1}}
			case strings.Contains(query, "Watchdog"):
				return []probetest.PromTestSample{{Value: 1}}
			case query == wantScrapesFailedQuery:
				sawExactQuery.Store(true)
				return []probetest.PromTestSample{{Value: 0.12}}
			}
			return nil
		})
		vmSinglePod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: obsVMEventNS, Name: "vmsingle-victoria-metrics-k8s-stack-0",
		}}
		cs := fake.NewSimpleClientset(vmSinglePod)
		p := testProber(cs)
		p.Cfg.HTTPContent.URL = srv.URL + "/health"
		p.HTTPClient = srv.Client()
		chk := probetest.MustCheck[*observabilityPipelineCheck](t, p)

		res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if res.Pass {
			t.Fatal("degraded VMSingle pipeline must fail the check")
		}
		if !sawExactQuery.Load() {
			t.Fatalf("expected vmagent_scrapes_failed query %q to be issued", wantScrapesFailedQuery)
		}
		if !obsPipelineDegradedGauge.DeleteLabelValues("vmagent_scrapes_failed") {
			t.Fatal("missing degraded series for vmagent_scrapes_failed")
		}
		evs, err := cs.EventsV1().Events(obsVMEventNS).List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(evs.Items) != 1 || evs.Items[0].Regarding.Kind != "VMSingle" {
			t.Fatalf("events = %+v, want 1 event Regarding Kind=VMSingle", evs.Items)
		}
	})

	t.Run("vmagent_scrapes_failed uses ratio+floor query and stays quiet below threshold", func(t *testing.T) {
		var mu sync.Mutex
		var scrapeQuery string
		srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
			if strings.Contains(query, "vm_promscrape_scrapes_failed_total") {
				mu.Lock()
				scrapeQuery = query
				mu.Unlock()
				// Empty vector models Prometheus/VM filtering out transient
				// scrape errors below the >5% ratio and >10 failures floor.
				return nil
			}
			switch {
			case query == "count(vm_app_version)":
				return []probetest.PromTestSample{{Value: 1}}
			case strings.Contains(query, "Watchdog"):
				return []probetest.PromTestSample{{Value: 1}}
			}
			return nil
		})
		cs := fake.NewSimpleClientset()
		p := testProber(cs)
		p.Cfg.HTTPContent.URL = srv.URL + "/health"
		p.HTTPClient = srv.Client()
		res := probetest.MustCheck[*observabilityPipelineCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
		if !res.Pass {
			t.Fatalf("below-threshold vmagent scrape noise must pass: %+v", res)
		}
		mu.Lock()
		got := scrapeQuery
		mu.Unlock()
		want := `(sum(increase(vm_promscrape_scrapes_failed_total[10m])) / clamp_min(sum(increase(vm_promscrape_scrape_requests_total[10m])) or vector(1), 1)) > 0.05 and sum(increase(vm_promscrape_scrapes_failed_total[10m])) > 10`
		if got != want {
			t.Fatalf("vmagent_scrapes_failed query = %q, want %q", got, want)
		}
		if obsPipelineDegradedGauge.DeleteLabelValues("vmagent_scrapes_failed") {
			t.Fatal("below-threshold scrape error wrongly emitted degraded gauge")
		}
	})

	t.Run("healthy VictoriaMetrics pipeline passes", func(t *testing.T) {
		srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
			switch {
			case query == "count(vm_app_version)":
				return []probetest.PromTestSample{{Value: 1}}
			case strings.Contains(query, "Watchdog"):
				return []probetest.PromTestSample{{Value: 1}}
			}
			return nil
		})
		p := testProber(fake.NewSimpleClientset())
		p.Cfg.HTTPContent.URL = srv.URL + "/health"
		p.HTTPClient = srv.Client()
		res := probetest.MustCheck[*observabilityPipelineCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
		if !res.Pass {
			t.Fatalf("healthy VM pipeline must pass: %+v", res)
		}
	})

	t.Run("vmagent_scrapes_failed suppressed when 100% of down targets are tier=tenant namespaces", func(t *testing.T) {
		srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
			switch {
			case query == "count(vm_app_version)":
				return []probetest.PromTestSample{{Value: 1}}
			case strings.Contains(query, "Watchdog"):
				return []probetest.PromTestSample{{Value: 1}}
			case strings.Contains(query, "vm_promscrape_scrapes_failed_total"):
				return []probetest.PromTestSample{{Value: 0.25}}
			case query == obsVMDownTargetsByNSQuery:
				return []probetest.PromTestSample{
					{Labels: map[string]string{"namespace": "passiontech-production"}, Value: 67},
					{Labels: map[string]string{"namespace": "gsw-production"}, Value: 12},
				}
			}
			return nil
		})
		cs := fake.NewSimpleClientset(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
				Name:   "passiontech-production",
				Labels: map[string]string{labelPlatformTier: tierTenant},
			}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
				Name:   "gsw-production",
				Labels: map[string]string{labelPlatformTier: tierTenant},
			}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
				Name:   "kube-system",
				Labels: map[string]string{labelPlatformTier: "platform"},
			}},
		)
		p := testProber(cs)
		p.Cfg.HTTPContent.URL = srv.URL + "/health"
		p.HTTPClient = srv.Client()

		res := probetest.MustCheck[*observabilityPipelineCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
		if !res.Pass {
			t.Fatalf("tenant-only vmagent_scrapes_failed must not degrade platform pipeline: %+v", res)
		}
		if obsPipelineDegradedGauge.DeleteLabelValues("vmagent_scrapes_failed") {
			t.Fatal("tenant-only scrape failures wrongly emitted vmagent_scrapes_failed degraded gauge")
		}
		evs, err := cs.EventsV1().Events(obsVMEventNS).List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(evs.Items) != 0 {
			t.Fatalf("tenant-only scrape failures must emit 0 warning events, got %d", len(evs.Items))
		}
	})

	t.Run("vmagent_scrapes_failed still degrades when platform or unlabeled target is down", func(t *testing.T) {
		cases := []struct {
			name    string
			samples []probetest.PromTestSample
		}{
			{
				name: "mixed tenant + platform namespace",
				samples: []probetest.PromTestSample{
					{Labels: map[string]string{"namespace": "passiontech-production"}, Value: 67},
					{Labels: map[string]string{"namespace": "kube-system"}, Value: 1},
				},
			},
			{
				name: "unlabeled namespace",
				samples: []probetest.PromTestSample{
					{Labels: map[string]string{"namespace": "unlabeled-ns"}, Value: 2},
				},
			},
			{
				name: "empty namespace label (cluster-scoped target)",
				samples: []probetest.PromTestSample{
					{Labels: map[string]string{"namespace": "passiontech-production"}, Value: 67},
					{Labels: map[string]string{}, Value: 1},
				},
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
					switch {
					case query == "count(vm_app_version)":
						return []probetest.PromTestSample{{Value: 1}}
					case strings.Contains(query, "Watchdog"):
						return []probetest.PromTestSample{{Value: 1}}
					case strings.Contains(query, "vm_promscrape_scrapes_failed_total"):
						return []probetest.PromTestSample{{Value: 0.20}}
					case query == obsVMDownTargetsByNSQuery:
						return tc.samples
					}
					return nil
				})
				cs := fake.NewSimpleClientset(
					&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
						Name:   "passiontech-production",
						Labels: map[string]string{labelPlatformTier: tierTenant},
					}},
					&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
						Name:   "kube-system",
						Labels: map[string]string{labelPlatformTier: "platform"},
					}},
					&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
						Name: "unlabeled-ns",
					}},
				)
				p := testProber(cs)
				p.Cfg.HTTPContent.URL = srv.URL + "/health"
				p.HTTPClient = srv.Client()

				res := probetest.MustCheck[*observabilityPipelineCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
				if res.Pass {
					t.Fatalf("case %q must still degrade pipeline", tc.name)
				}
				if !obsPipelineDegradedGauge.DeleteLabelValues("vmagent_scrapes_failed") {
					t.Fatalf("case %q missing degraded gauge for vmagent_scrapes_failed", tc.name)
				}
			})
		}
	})

	t.Run("vmagent_scrapes_failed fails closed when up==0 query is empty or errors", func(t *testing.T) {
		t.Run("empty up==0 series", func(t *testing.T) {
			srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
				switch {
				case query == "count(vm_app_version)":
					return []probetest.PromTestSample{{Value: 1}}
				case strings.Contains(query, "Watchdog"):
					return []probetest.PromTestSample{{Value: 1}}
				case strings.Contains(query, "vm_promscrape_scrapes_failed_total"):
					return []probetest.PromTestSample{{Value: 0.15}}
				case query == obsVMDownTargetsByNSQuery:
					return nil
				}
				return nil
			})
			cs := fake.NewSimpleClientset(
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
					Name:   "passiontech-production",
					Labels: map[string]string{labelPlatformTier: tierTenant},
				}},
			)
			p := testProber(cs)
			p.Cfg.HTTPContent.URL = srv.URL + "/health"
			p.HTTPClient = srv.Client()

			res := probetest.MustCheck[*observabilityPipelineCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
			if res.Pass {
				t.Fatal("empty up==0 result must fail closed and still degrade")
			}
			if !obsPipelineDegradedGauge.DeleteLabelValues("vmagent_scrapes_failed") {
				t.Fatal("missing degraded gauge for vmagent_scrapes_failed on empty up==0")
			}
		})

		t.Run("up==0 query returns HTTP error", func(t *testing.T) {
			srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
				switch {
				case query == "count(vm_app_version)":
					return []probetest.PromTestSample{{Value: 1}}
				case strings.Contains(query, "Watchdog"):
					return []probetest.PromTestSample{{Value: 1}}
				case strings.Contains(query, "vm_promscrape_scrapes_failed_total"):
					return []probetest.PromTestSample{{Value: 0.15}}
				}
				return nil
			})
			baseRT := srv.Client().Transport
			if baseRT == nil {
				baseRT = http.DefaultTransport
			}
			client := &http.Client{Transport: obsPipelineRTFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/api/v1/query" && r.URL.Query().Get("query") == obsVMDownTargetsByNSQuery {
					return &http.Response{
						StatusCode: http.StatusInternalServerError,
						Body:       io.NopCloser(strings.NewReader("query error")),
						Header:     make(http.Header),
					}, nil
				}
				return baseRT.RoundTrip(r)
			})}
			cs := fake.NewSimpleClientset(
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
					Name:   "passiontech-production",
					Labels: map[string]string{labelPlatformTier: tierTenant},
				}},
			)
			p := testProber(cs)
			p.Cfg.HTTPContent.URL = srv.URL + "/health"
			p.HTTPClient = client

			res := probetest.MustCheck[*observabilityPipelineCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
			if res.Pass {
				t.Fatal("up==0 query error must fail closed and still degrade")
			}
			if !obsPipelineDegradedGauge.DeleteLabelValues("vmagent_scrapes_failed") {
				t.Fatal("missing degraded gauge for vmagent_scrapes_failed on query error")
			}
		})
	})
}

// failingHTTPClient returns an HTTP client whose transport always
// errors — the Prometheus-unreachable posture for the inconclusive
// cycle in the recovery-prune test.
func failingHTTPClient(t *testing.T) *http.Client {
	t.Helper()
	return &http.Client{Transport: failingRoundTripper{}}
}

type failingRoundTripper struct{}

func (failingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("prometheus unreachable")
}

type obsPipelineRTFunc func(*http.Request) (*http.Response, error)

func (f obsPipelineRTFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestObservabilityPipelineAllDownNoProbeStorm(t *testing.T) {
	t.Run("all 3 candidate health endpoints and query return 503", func(t *testing.T) {
		promq.InvalidateAutoDetectCache()
		t.Cleanup(promq.InvalidateAutoDetectCache)

		var healthProbes atomic.Int32
		client := &http.Client{Transport: obsPipelineRTFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/-/healthy" || r.URL.Path == "/health" {
				healthProbes.Add(1)
			}
			return &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Body:       io.NopCloser(strings.NewReader("down")),
				Header:     make(http.Header),
			}, nil
		})}

		p := testProber(fake.NewSimpleClientset())
		p.Cfg.HTTPContent = probefw.HTTPContentConfig{AutoDetect: true}
		p.Cfg.ObsBackendMode = promq.ObsBackendAuto
		p.HTTPClient = client
		chk := probetest.MustCheck[*observabilityPipelineCheck](t, p)

		res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if res.Pass {
			t.Fatalf("expected FAIL when all endpoints return 503, got %+v", res)
		}
		if got := healthProbes.Load(); got > 3 {
			t.Fatalf("single sweep fired %d health probes, want <= 3", got)
		}
	})

	t.Run("all 3 candidate health endpoints timeout then recover next sweep", func(t *testing.T) {
		promq.InvalidateAutoDetectCache()
		t.Cleanup(promq.InvalidateAutoDetectCache)

		var healthProbes atomic.Int32
		var vmHealthy atomic.Bool
		client := &http.Client{Transport: obsPipelineRTFunc(func(r *http.Request) (*http.Response, error) {
			isHealth := r.URL.Path == "/-/healthy" || r.URL.Path == "/health"
			if isHealth {
				healthProbes.Add(1)
			}
			if vmHealthy.Load() && r.URL.Host == "vmauth-victoria-metrics-k8s-stack.victoria-metrics.svc:8427" {
				if r.URL.Path == "/health" {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader("OK")),
						Header:     make(http.Header),
					}, nil
				}
				if r.URL.Path == "/api/v1/query" {
					_ = r.ParseForm()
					q := r.FormValue("query")
					body := `{"status":"success","data":{"resultType":"vector","result":[]}}`
					if strings.Contains(q, "Watchdog") {
						body = `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"1"]}]}}`
					}
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(body)),
						Header:     make(http.Header),
					}, nil
				}
			}
			if isHealth {
				time.Sleep(15 * time.Millisecond)
			}
			return nil, fmt.Errorf("connect timeout: %s", r.URL.Host)
		})}

		p := testProber(fake.NewSimpleClientset())
		p.Cfg.HTTPContent = probefw.HTTPContentConfig{AutoDetect: true}
		p.Cfg.ObsBackendMode = promq.ObsBackendAuto
		p.HTTPClient = client
		chk := probetest.MustCheck[*observabilityPipelineCheck](t, p)

		res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if res.Pass {
			t.Fatalf("expected FAIL when all endpoints timeout, got %+v", res)
		}
		if got := healthProbes.Load(); got > 3 {
			t.Fatalf("single timeout sweep fired %d health probes, want <= 3", got)
		}

		// Recovery on next sweep without needing InvalidateAutoDetectCache.
		vmHealthy.Store(true)
		res2 := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if !res2.Pass {
			t.Fatalf("expected recovery on sweep 2 once VMAuth is healthy, got %+v", res2)
		}
	})
}
