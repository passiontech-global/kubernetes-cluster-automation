package watchdogs

import (
	"strings"
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

		res := chk.Run(ctx)
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
		evs, err := cs.EventsV1().Events("monitoring").List(ctx, metav1.ListOptions{})
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
		res := probetest.MustCheck[*observabilityPipelineCheck](t, p).Run(ctx)
		if !res.Pass {
			t.Fatalf("healthy pipeline must pass: %+v", res)
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
	res := probetest.MustCheck[*onePasswordConnectSyncCheck](t, p).Run(ctx)
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
