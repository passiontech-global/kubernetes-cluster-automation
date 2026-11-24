package promq

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

func TestParseObsBackendModeAndEnv(t *testing.T) {
	cases := []struct {
		raw    string
		want   ObsBackendMode
		wantOK bool
	}{
		{"", ObsBackendAuto, true},
		{"auto", ObsBackendAuto, true},
		{" AUTO ", ObsBackendAuto, true},
		{"prometheus", ObsBackendPrometheus, true},
		{"Prometheus", ObsBackendPrometheus, true},
		{"victoriametrics", ObsBackendVictoriaMetrics, true},
		{"VictoriaMetrics", ObsBackendVictoriaMetrics, true},
		{"thanos", ObsBackendAuto, false},
	}
	for _, tc := range cases {
		got, ok := ParseObsBackendMode(tc.raw)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("ParseObsBackendMode(%q) = (%q, %v), want (%q, %v)",
				tc.raw, got, ok, tc.want, tc.wantOK)
		}
	}

	t.Run("invalid env warns via envx.Warnf and falls back to auto", func(t *testing.T) {
		var warned atomic.Bool
		envx.SetWarnf(func(msg string, _ ...any) {
			if strings.Contains(msg, ObsBackendEnvKey) {
				warned.Store(true)
			}
		})
		t.Cleanup(func() { envx.SetWarnf(nil) })

		t.Setenv(ObsBackendEnvKey, "invalid-backend")
		if got := EnvObsBackendMode(); got != ObsBackendAuto {
			t.Fatalf("EnvObsBackendMode() = %q, want auto", got)
		}
		if !warned.Load() {
			t.Fatal("expected envx.Warnf warning on invalid NODE_AUTOMATION_OBS_BACKEND")
		}
	})

	t.Run("valid env sets mode without warning", func(t *testing.T) {
		var warned atomic.Bool
		envx.SetWarnf(func(string, ...any) { warned.Store(true) })
		t.Cleanup(func() { envx.SetWarnf(nil) })

		t.Setenv(ObsBackendEnvKey, "victoriametrics")
		if got := EnvObsBackendMode(); got != ObsBackendVictoriaMetrics {
			t.Fatalf("EnvObsBackendMode() = %q, want victoriametrics", got)
		}
		if warned.Load() {
			t.Fatal("unexpected warning on valid NODE_AUTOMATION_OBS_BACKEND")
		}
	})
}

func TestDetectBackendURLHints(t *testing.T) {
	// URL hints must resolve without issuing any HTTP query.
	failClient := &Client{HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unexpected HTTP call when URL heuristic matches")
		return nil, nil
	})}}
	cases := []struct {
		url  string
		want BackendKind
	}{
		{"http://vmauth-victoria-metrics-k8s-stack.victoria-metrics.svc:8427/api/v1/query", BackendVictoriaMetrics},
		{"http://vmsingle-victoria-metrics-k8s-stack.victoria-metrics.svc:8428/api/v1/query", BackendVictoriaMetrics},
		{"http://vmselect-victoria-metrics-k8s-stack.victoria-metrics.svc:8481/select/0/prometheus/api/v1/query", BackendVictoriaMetrics},
		{"http://custom.example.com/victoria-metrics/api/v1/query", BackendVictoriaMetrics},
		{"http://kube-prometheus-stack-prometheus.prometheus-operator.svc:9090/api/v1/query", BackendPrometheus},
		{"http://prom.prometheus-operator.svc:9090/api/v1/query", BackendPrometheus},
	}
	for _, tc := range cases {
		got, err := DetectBackend(t.Context(), failClient, tc.url)
		if err != nil || got != tc.want {
			t.Fatalf("DetectBackend(%q) = (%v, %v), want (%v, nil)", tc.url, got, err, tc.want)
		}
	}
}

func TestDetectBackendBySeparateInstantQueries(t *testing.T) {
	t.Run("detects VictoriaMetrics and never uses label-stripping or query", func(t *testing.T) {
		var mu sync.Mutex
		var seen []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			q := r.FormValue("query")
			mu.Lock()
			seen = append(seen, q)
			mu.Unlock()
			if strings.Contains(q, " or ") {
				t.Errorf("forbidden label-stripping `or` query issued: %q", q)
			}
			if q == "count(vm_app_version)" {
				_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"2"]}]}}`))
				return
			}
			_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
		}))
		defer srv.Close()

		got, err := DetectBackend(t.Context(), &Client{HTTP: srv.Client()}, srv.URL+"/api/v1/query")
		if err != nil || got != BackendVictoriaMetrics {
			t.Fatalf("DetectBackend = (%v, %v), want (BackendVictoriaMetrics, nil)", got, err)
		}
		if len(seen) != 2 {
			t.Fatalf("queries = %v, want 2 separate queries", seen)
		}
	})

	t.Run("detects Prometheus when only prometheus_build_info is present", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			if r.FormValue("query") == "count(prometheus_build_info)" {
				_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"1"]}]}}`))
				return
			}
			_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
		}))
		defer srv.Close()

		got, err := DetectBackend(t.Context(), &Client{HTTP: srv.Client()}, srv.URL+"/api/v1/query")
		if err != nil || got != BackendPrometheus {
			t.Fatalf("DetectBackend = (%v, %v), want (BackendPrometheus, nil)", got, err)
		}
	})

	t.Run("returns BackendUnknown when both queries return empty", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
		}))
		defer srv.Close()

		got, err := DetectBackend(t.Context(), &Client{HTTP: srv.Client()}, srv.URL+"/api/v1/query")
		if err != nil || got != BackendUnknown {
			t.Fatalf("DetectBackend = (%v, %v), want (BackendUnknown, nil)", got, err)
		}
	})

	t.Run("prefers VictoriaMetrics when both metrics exist on untyped URL", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"1"]}]}}`))
		}))
		defer srv.Close()

		got, err := DetectBackend(t.Context(), &Client{HTTP: srv.Client()}, srv.URL+"/api/v1/query")
		if err != nil || got != BackendVictoriaMetrics {
			t.Fatalf("DetectBackend = (%v, %v), want (BackendVictoriaMetrics, nil)", got, err)
		}
	})

	t.Run("propagates error on transport failure", func(t *testing.T) {
		badClient := &Client{HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, io.EOF
		})}}
		got, err := DetectBackend(t.Context(), badClient, "http://127.0.0.1:1/api/v1/query")
		if err == nil || got != BackendUnknown {
			t.Fatalf("DetectBackend = (%v, %v), want (BackendUnknown, non-nil err)", got, err)
		}
	})
}

func TestTargetDetectorPriorityFailoverAndModes(t *testing.T) {
	var promUp, vmAuthUp, vmSingleUp atomic.Bool
	promUp.Store(true)
	vmAuthUp.Store(true)
	vmSingleUp.Store(true)

	var promHits, vmAuthHits, vmSingleHits atomic.Int32
	promSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		promHits.Add(1)
		if !promUp.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("Prometheus Server is Healthy.\n"))
	}))
	defer promSrv.Close()

	vmAuthSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vmAuthHits.Add(1)
		if !vmAuthUp.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("OK\n"))
	}))
	defer vmAuthSrv.Close()

	vmSingleSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vmSingleHits.Add(1)
		if !vmSingleUp.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("OK"))
	}))
	defer vmSingleSrv.Close()

	now := time.Unix(1_700_000_000, 0)
	var mu sync.Mutex
	curNow := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		now = now.Add(d)
		mu.Unlock()
	}

	targets := []ObsTarget{
		{
			Backend:       BackendPrometheus,
			HealthURL:     promSrv.URL + "/-/healthy",
			ExpectedBody:  "Healthy",
			QueryURL:      promSrv.URL + "/api/v1/query",
			DNSHost:       "kube-prometheus-stack-prometheus.prometheus-operator.svc.cluster.local",
			Namespace:     "prometheus-operator",
			DefaultCRName: "kube-prometheus-stack-prometheus",
		},
		{
			Backend:       BackendVictoriaMetrics,
			HealthURL:     vmAuthSrv.URL + "/health",
			ExpectedBody:  "OK",
			QueryURL:      vmAuthSrv.URL + "/api/v1/query",
			DNSHost:       "vmauth-victoria-metrics-k8s-stack.victoria-metrics.svc.cluster.local",
			Namespace:     "victoria-metrics",
			DefaultCRName: "victoria-metrics-k8s-stack",
		},
		{
			Backend:       BackendVictoriaMetrics,
			HealthURL:     vmSingleSrv.URL + "/health",
			ExpectedBody:  "OK",
			QueryURL:      vmSingleSrv.URL + "/api/v1/query",
			DNSHost:       "vmsingle-victoria-metrics-k8s-stack.victoria-metrics.svc.cluster.local",
			Namespace:     "victoria-metrics",
			DefaultCRName: "victoria-metrics-k8s-stack",
		},
	}

	detector := &TargetDetector{
		Targets:      targets,
		ProbeTimeout: 500 * time.Millisecond,
		TTL:          2 * time.Minute,
		Now:          curNow,
	}

	// 1. Auto prefers Prometheus when both Prometheus and VM are healthy.
	got, detected := detector.Detect(t.Context(), promSrv.Client(), ObsBackendAuto)
	if !detected || got.Backend != BackendPrometheus || got.HealthURL != targets[0].HealthURL {
		t.Fatalf("auto initial = (%+v, %v), want Prometheus", got, detected)
	}
	if promHits.Load() != 1 || vmAuthHits.Load() != 0 || vmSingleHits.Load() != 0 {
		t.Fatalf("unexpected probe counts: prom=%d vmauth=%d vmsingle=%d",
			promHits.Load(), vmAuthHits.Load(), vmSingleHits.Load())
	}

	// 2. Second call within 2m TTL hits cache without probing.
	advance(time.Minute)
	got, detected = detector.Detect(t.Context(), promSrv.Client(), ObsBackendAuto)
	if !detected || got.Backend != BackendPrometheus || promHits.Load() != 1 {
		t.Fatalf("expected cache hit within TTL: (%+v, %v), promHits=%d", got, detected, promHits.Load())
	}

	// 3. Explicit victoriametrics mode on the SAME client probes VMAuth directly even while Prom is cached.
	got, detected = detector.Detect(t.Context(), promSrv.Client(), ObsBackendVictoriaMetrics)
	if !detected || got.Backend != BackendVictoriaMetrics || got.HealthURL != targets[1].HealthURL {
		t.Fatalf("vm mode = (%+v, %v), want VMAuth", got, detected)
	}

	// 4. Cutover failover: Prometheus goes down, TTL expires -> auto seamlessly fails over to VMAuth.
	promUp.Store(false)
	advance(2 * time.Minute)
	got, detected = detector.Detect(t.Context(), promSrv.Client(), ObsBackendAuto)
	if !detected || got.Backend != BackendVictoriaMetrics || got.HealthURL != targets[1].HealthURL {
		t.Fatalf("failover to VMAuth = (%+v, %v)", got, detected)
	}

	// 5. VMAuth goes down -> auto fails over to VMSingle after TTL expiry.
	vmAuthUp.Store(false)
	advance(3 * time.Minute)
	got, detected = detector.Detect(t.Context(), promSrv.Client(), ObsBackendAuto)
	if !detected || got.Backend != BackendVictoriaMetrics || got.HealthURL != targets[2].HealthURL {
		t.Fatalf("failover to VMSingle = (%+v, %v)", got, detected)
	}

	// 6. Prometheus mode does NOT fall back to VM when Prometheus is down.
	got, detected = detector.Detect(t.Context(), promSrv.Client(), ObsBackendPrometheus)
	if detected || got.Backend != BackendPrometheus {
		t.Fatalf("prometheus mode when down = (%+v, %v), want (Prometheus, false)", got, detected)
	}

	// 7. Distinct *http.Client has isolated cache even in same mode.
	otherClient := &http.Client{Transport: promSrv.Client().Transport}
	promUp.Store(true)
	got, detected = detector.Detect(t.Context(), otherClient, ObsBackendAuto)
	if !detected || got.Backend != BackendPrometheus {
		t.Fatalf("otherClient detect = (%+v, %v), want fresh Prometheus detection", got, detected)
	}

	// 8. All down -> returns primary fallback + detected=false (not cached).
	promUp.Store(false)
	vmAuthUp.Store(false)
	vmSingleUp.Store(false)
	detector.Invalidate()
	got, detected = detector.Detect(t.Context(), promSrv.Client(), ObsBackendAuto)
	if detected || got.HealthURL != targets[0].HealthURL {
		t.Fatalf("all down = (%+v, %v), want (fallback target, false)", got, detected)
	}
	// Negative result must not poison cache when VMAuth recovers immediately.
	vmAuthUp.Store(true)
	got, detected = detector.Detect(t.Context(), promSrv.Client(), ObsBackendAuto)
	if !detected || got.HealthURL != targets[1].HealthURL {
		t.Fatalf("recovery after negative detect = (%+v, %v), want (VMAuth, true)", got, detected)
	}
}

func TestAutoDetectTargetDefaultTargetsAndClientIsolation(t *testing.T) {
	InvalidateAutoDetectCache()
	t.Cleanup(InvalidateAutoDetectCache)

	// Custom RoundTripper maps the 3 canonical cluster hostnames without any live DNS/network.
	mkClient := func(promHealthy, vmAuthHealthy bool) *http.Client {
		return &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				switch r.URL.Host {
				case "kube-prometheus-stack-prometheus.prometheus-operator.svc:9090":
					if promHealthy && r.URL.Path == "/-/healthy" {
						return textResp(http.StatusOK, "Prometheus Server is Healthy."), nil
					}
					return textResp(http.StatusServiceUnavailable, "down"), nil
				case "vmauth-victoria-metrics-k8s-stack.victoria-metrics.svc:8427":
					if vmAuthHealthy && r.URL.Path == "/health" {
						return textResp(http.StatusOK, "OK"), nil
					}
					return textResp(http.StatusServiceUnavailable, "down"), nil
				case "vmsingle-victoria-metrics-k8s-stack.victoria-metrics.svc:8428":
					if r.URL.Path == "/health" {
						return textResp(http.StatusOK, "OK"), nil
					}
					return textResp(http.StatusServiceUnavailable, "down"), nil
				default:
					return textResp(http.StatusNotFound, "unknown"), nil
				}
			}),
		}
	}

	cProm := mkClient(true, true)
	cVM := mkClient(false, true)
	cVMSingle := mkClient(false, false)

	got1, ok1 := AutoDetectTarget(t.Context(), cProm, ObsBackendAuto)
	got2, ok2 := AutoDetectTarget(t.Context(), cVM, ObsBackendAuto)
	got3, ok3 := AutoDetectTarget(t.Context(), cVMSingle, ObsBackendAuto)

	if !ok1 || got1.Backend != BackendPrometheus || got1.Namespace != "prometheus-operator" {
		t.Fatalf("cProm = (%+v, %v)", got1, ok1)
	}
	if !ok2 || got2.Backend != BackendVictoriaMetrics || got2.DNSHost != DefaultVMAuthTarget().DNSHost {
		t.Fatalf("cVM = (%+v, %v)", got2, ok2)
	}
	if !ok3 || got3.Backend != BackendVictoriaMetrics || got3.DNSHost != DefaultVMSingleTarget().DNSHost {
		t.Fatalf("cVMSingle = (%+v, %v)", got3, ok3)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func textResp(code int, body string) *http.Response {
	return &http.Response{
		StatusCode: code,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}
