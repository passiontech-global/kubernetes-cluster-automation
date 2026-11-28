package watchdogs

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

func promVectorServer(t *testing.T, fn func(query string) []map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.FormValue("query")
		res := fn(q)
		if res == nil {
			res = []map[string]any{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data": map[string]any{
				"resultType": "vector",
				"result":     res,
			},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAPIServerAdmissionTokenGuardDetectionAndPruning(t *testing.T) {
	base := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	active := true

	srv := promVectorServer(t, func(query string) []map[string]any {
		if !active {
			return nil
		}
		switch {
		case strings.Contains(query, "apiserver_admission_webhook_admission_duration_seconds_bucket"):
			return []map[string]any{{
				"metric": map[string]string{"name": "slow-webhook.example.com", "type": "validating"},
				"value":  []any{float64(base.Unix()), "3.45"},
			}}
		case strings.Contains(query, `subresource="token"`):
			return []map[string]any{{
				"metric": map[string]string{"client": "system:serviceaccount:apps:burst-sa"},
				"value":  []any{float64(base.Unix()), "24.5"},
			}}
		case strings.Contains(query, "apiserver_flowcontrol_rejected_requests_total"):
			return []map[string]any{{
				"metric": map[string]string{"flow_schema": "workload-high", "priority_level": "workload-high"},
				"value":  []any{float64(base.Unix()), "1.2"},
			}}
		default:
			return nil
		}
	})

	cs := fake.NewSimpleClientset()
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	chk := probetest.MustCheck[*apiserverAdmissionTokenGuardCheck](t, p)

	// Sweep 1: tracked in FirstSeenLedger -> pass before 10m.
	probetest.FreezeNow(p.Deps, base)
	res1 := probetest.RunCheck(ctx, p.Deps, chk)
	if !res1.Pass {
		t.Fatalf("sweep 1 expected pass before 10m persistence, got %+v", res1)
	}

	// Sweep 2: >=10m -> fail + 3 gauges + Warning Events.
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	res2 := probetest.RunCheck(ctx, p.Deps, chk)
	if res2.Pass {
		t.Fatalf("sweep 2 expected failure >=10m, got pass")
	}
	for _, want := range []struct{ kind, target string }{
		{anomalyKindWebhookLatency, "validating/slow-webhook.example.com"},
		{anomalyKindTokenBurst, "system:serviceaccount:apps:burst-sa"},
		{anomalyKindAPFRejected, "workload-high"},
	} {
		if m := probetest.FindMetric(t, "node_automation_apiserver_admission_token_anomaly", map[string]string{
			"kind": want.kind, "target": want.target,
		}); m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatalf("expected gauge=1 for %+v, got %v", want, m)
		}
	}
	evs, err := cs.EventsV1().Events(admissionTokenEventNamespace).List(ctx, metav1.ListOptions{})
	if err != nil || len(evs.Items) != 3 {
		t.Fatalf("expected 3 APIServerAdmissionTokenAnomaly events, got %d err=%v", len(evs.Items), err)
	}

	// Sweep 3: Prometheus temporarily unavailable -> carry forward existing gauges without error.
	p.Cfg.HTTPContent.URL = "http://127.0.0.1:1/"
	probetest.FreezeNow(p.Deps, base.Add(13*time.Minute))
	resCarry := probetest.RunCheck(ctx, p.Deps, chk)
	if !resCarry.Pass || resCarry.Infra != nil {
		t.Fatalf("expected graceful pass on prom unavailable, got %+v", resCarry)
	}
	if m := probetest.FindMetric(t, "node_automation_apiserver_admission_token_anomaly", map[string]string{
		"kind": anomalyKindWebhookLatency, "target": "validating/slow-webhook.example.com",
	}); m == nil {
		t.Fatal("expected carried gauge during transient Prometheus outage")
	}

	// Sweep 4: Prometheus recovers and anomalies cleared -> pass + gauges pruned.
	p.Cfg.HTTPContent.URL = srv.URL
	active = false
	probetest.FreezeNow(p.Deps, base.Add(16*time.Minute))
	resClear := probetest.RunCheck(ctx, p.Deps, chk)
	if !resClear.Pass {
		t.Fatalf("expected pass after anomalies clear, got %+v", resClear)
	}
	if m := probetest.FindMetric(t, "node_automation_apiserver_admission_token_anomaly", map[string]string{
		"kind": anomalyKindWebhookLatency, "target": "validating/slow-webhook.example.com",
	}); m != nil {
		t.Fatalf("expected pruned gauge after recovery, got %v", m)
	}
}

func TestAPIServerAdmissionTokenGuardPromUnavailableSkipsCleanly(t *testing.T) {
	cs := fake.NewSimpleClientset()
	p := testProber(cs) // points at 127.0.0.1:1
	chk := probetest.MustCheck[*apiserverAdmissionTokenGuardCheck](t, p)
	res := probetest.RunCheck(ctx, p.Deps, chk)
	if !res.Pass || res.Infra != nil {
		t.Fatalf("expected graceful pass when Prometheus unavailable, got %+v", res)
	}
}
