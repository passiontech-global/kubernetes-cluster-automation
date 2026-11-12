package watchdogs

import (
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
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

		res := chk.Run(probetest.SweepCtx(ctx))
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
		res := probetest.MustCheck[*observabilityPipelineCheck](t, p).Run(probetest.SweepCtx(ctx))
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
		res := probetest.MustCheck[*observabilityPipelineCheck](t, p).Run(probetest.SweepCtx(ctx))
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
	res := probetest.MustCheck[*onePasswordConnectSyncCheck](t, p).Run(probetest.SweepCtx(ctx))
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
	if res := chk.Run(probetest.SweepCtx(ctx)); res.Pass {
		t.Fatal("degraded pipeline must fail")
	}
	if !chk.evented.Has("watchdog_heartbeat") {
		t.Fatal("episode marker not armed after the first emission")
	}
	// Inconclusive cycle (query error) — the marker must NOT be
	// pruned (a flap must not re-page the same episode).
	p.HTTPClient = failingHTTPClient(t)
	if res := chk.Run(probetest.SweepCtx(ctx)); res.Pass {
		t.Fatal("inconclusive cycle must not pass")
	}
	if !chk.evented.Has("watchdog_heartbeat") {
		t.Fatal("episode marker pruned on an inconclusive cycle")
	}
	p.HTTPClient = srv.Client()
	// Recovery — conclusive healthy cycle prunes the marker.
	healthy.Store(true)
	if res := chk.Run(probetest.SweepCtx(ctx)); !res.Pass {
		t.Fatalf("healthy pipeline must pass: %+v", res)
	}
	if chk.evented.Has("watchdog_heartbeat") {
		t.Fatal("episode marker not pruned after recovery")
	}
	// Relapse — a FRESH event is emitted (marker re-armed).
	healthy.Store(false)
	if res := chk.Run(probetest.SweepCtx(ctx)); res.Pass {
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
