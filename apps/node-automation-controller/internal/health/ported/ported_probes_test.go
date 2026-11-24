// ported_probes_test.go — the five ported kuberhealthy checks
// driven through an injectable DNS seam, an httptest target and the
// fake clientset (apiserver reads only — no envtest needed).
package ported

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
)

func chPod(ns, name string, phase corev1.PodPhase, age time.Duration) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
		},
		Status: corev1.PodStatus{Phase: phase},
	}
}

// ---------------------------------------------------------------------------
// dns-status-internal
// ---------------------------------------------------------------------------

func TestProbeDNS(t *testing.T) {
	t.Setenv("HEALTH_DNS_HOSTNAMES", "svc-a.ns.svc,svc-b.ns.svc")
	p := testProber(fake.NewSimpleClientset())
	if res := probetest.MustCheck[*dnsStatusCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("expected pass, got %+v", res)
	}

	// Any single lookup failure fails the whole check.
	p.LookupHost = func(_ context.Context, host string) ([]string, error) {
		if host == "svc-b.ns.svc" {
			return nil, errors.New("NXDOMAIN")
		}
		return []string{"10.0.0.1"}, nil
	}
	res := probetest.MustCheck[*dnsStatusCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass || res.Infra != nil {
		t.Fatalf("expected clean FAIL, got %+v", res)
	}
	if res.Why == "" {
		t.Fatal("FAIL without a reason")
	}
}

// ---------------------------------------------------------------------------
// http-content-check
// ---------------------------------------------------------------------------

func TestProbeHTTPContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "Prometheus Server is Healthy.")
	}))
	t.Cleanup(srv.Close)

	p := testProber(fake.NewSimpleClientset())
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()

	if res := probetest.MustCheck[*httpContentCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("expected pass on 'Healthy' body, got %+v", res)
	}

	// Expected substring missing -> FAIL.
	p.Cfg.HTTPContent.Expected = "Absolutely"
	if res := probetest.MustCheck[*httpContentCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); res.Pass {
		t.Fatal("expected FAIL when body lacks the expected content")
	}
}

func TestProbeHTTPContentNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)

	p := testProber(fake.NewSimpleClientset())
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	if res := probetest.MustCheck[*httpContentCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); res.Pass {
		t.Fatal("expected FAIL on non-200")
	}
}

// A body that fills the 1MiB read cap WITHOUT containing the expected
// string is inconclusive, not a clean FAIL — the expected substring
// may sit past the cap — so it reports Infra instead. A match inside
// the capped window still passes however big the body behind it is.
func TestProbeHTTPContentBodyCapInconclusive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), httpBodyReadCap+1))
	}))
	t.Cleanup(srv.Close)

	p := testProber(fake.NewSimpleClientset())
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	res := probetest.MustCheck[*httpContentCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass || res.Why != "" || res.Infra == nil {
		t.Fatalf("cap-filling body must read inconclusive, got %+v", res)
	}
	if !strings.Contains(res.Infra.Error(), "truncated") {
		t.Fatalf("Infra = %v, want the truncation notice", res.Infra)
	}

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), httpBodyReadCap-8))
		_, _ = fmt.Fprint(w, "Healthy")
		_, _ = w.Write(bytes.Repeat([]byte("x"), httpBodyReadCap))
	}))
	t.Cleanup(srv2.Close)
	p.Cfg.HTTPContent.URL = srv2.URL
	if res := probetest.MustCheck[*httpContentCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("match within the capped window must pass, got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// pod-restarts
// ---------------------------------------------------------------------------

func TestProbePodRestarts(t *testing.T) {
	// pinned-volume-guard: an over-threshold RestartCount only FAILs while the
	// restarts are live signal — a recent last termination or a
	// container currently Waiting (CrashLoopBackOff).
	over := chPod("kube-system", "restarty", corev1.PodRunning, time.Hour)
	over.Status.ContainerStatuses = []corev1.ContainerStatus{
		{Name: "c", RestartCount: 11, // > max(10)
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					FinishedAt: metav1.NewTime(time.Now().Add(-time.Hour)),
				},
			}},
	}
	p := testProber(fake.NewSimpleClientset(over))
	if res := probetest.MustCheck[*podRestartsCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); res.Pass {
		t.Fatal("expected FAIL on RestartCount 11 with a recent termination")
	}

	// A CrashLoopBackOff Waiting state is live signal even with no
	// LastTerminationState recorded.
	waiting := chPod("kube-system", "crashloop", corev1.PodRunning, time.Hour)
	waiting.Status.ContainerStatuses = []corev1.ContainerStatus{
		{Name: "c", RestartCount: 11,
			State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
				Reason: "CrashLoopBackOff"}}},
	}
	if res := probetest.MustCheck[*podRestartsCheck](t, testProber(fake.NewSimpleClientset(waiting))).Run(probetest.SweepCtx(ctx, p.Deps)); res.Pass {
		t.Fatal("expected FAIL on CrashLoopBackOff over threshold")
	}

	// pinned-volume-guard: the same count with a STALE last termination (>24h)
	// and a Running state is historical — the check must recover.
	stale := chPod("kube-system", "oldcrash", corev1.PodRunning, time.Hour)
	stale.Status.ContainerStatuses = []corev1.ContainerStatus{
		{Name: "c", RestartCount: 11,
			State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					FinishedAt: metav1.NewTime(time.Now().Add(-48 * time.Hour)),
				},
			}},
	}
	if res := probetest.MustCheck[*podRestartsCheck](t, testProber(fake.NewSimpleClientset(stale))).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatal("stale (>24h) termination must not FAIL the check")
	}

	// Boundary: exactly at the limit is still a pass.
	over.Status.ContainerStatuses[0].RestartCount = 10
	cs := fake.NewSimpleClientset(over)
	if res := probetest.MustCheck[*podRestartsCheck](t, testProber(cs)).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatal("RestartCount == max must pass")
	}

	// Init containers count too (a crash-looping initContainer never
	// reaches the app statuses).
	init := chPod("kube-system", "initcrash", corev1.PodRunning, time.Hour)
	init.Status.InitContainerStatuses = []corev1.ContainerStatus{
		{Name: "init", RestartCount: 42,
			LastTerminationState: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{
					FinishedAt: metav1.NewTime(time.Now()),
				},
			}},
	}
	if res := probetest.MustCheck[*podRestartsCheck](t, testProber(fake.NewSimpleClientset(init))).Run(probetest.SweepCtx(ctx, p.Deps)); res.Pass {
		t.Fatal("expected FAIL on init-container restarts")
	}
}

// ---------------------------------------------------------------------------
// pod-status-check
// ---------------------------------------------------------------------------

func TestProbePodStatus(t *testing.T) {
	p := testProber(fake.NewSimpleClientset(
		chPod("kube-system", "stuck", corev1.PodPending, 15*time.Minute)))
	if res := probetest.MustCheck[*podStatusCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); res.Pass {
		t.Fatal("expected FAIL on old Pending pod")
	}

	// Younger than SKIP_DURATION -> ignored (image still pulling).
	p = testProber(fake.NewSimpleClientset(
		chPod("kube-system", "fresh", corev1.PodPending, 5*time.Minute)))
	if res := probetest.MustCheck[*podStatusCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatal("young Pending pod must be skipped")
	}

	for _, phase := range []corev1.PodPhase{corev1.PodFailed, corev1.PodUnknown} {
		p = testProber(fake.NewSimpleClientset(
			chPod("kube-system", "dead", phase, time.Hour)))
		if res := probetest.MustCheck[*podStatusCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); res.Pass {
			t.Fatalf("expected FAIL on phase %s", phase)
		}
	}

	p = testProber(fake.NewSimpleClientset(
		chPod("kube-system", "ok", corev1.PodRunning, time.Hour),
		chPod("kube-system", "done", corev1.PodSucceeded, time.Hour)))
	if res := probetest.MustCheck[*podStatusCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatal("Running+Succeeded must pass")
	}
}

// ---------------------------------------------------------------------------
// resource-quota-check
// ---------------------------------------------------------------------------

func quota(ns, name, used, hard string) *corev1.ResourceQuota {
	q := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Status: corev1.ResourceQuotaStatus{
			Hard: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse(hard)},
		},
	}
	if used != "" {
		q.Status.Used = corev1.ResourceList{corev1.ResourceCPU: resource.MustParse(used)}
	}
	return q
}

func TestProbeResourceQuota(t *testing.T) {
	// 95% of hard -> FAIL.
	p := testProber(fake.NewSimpleClientset(quota("a", "q", "950m", "1")))
	if res := probetest.MustCheck[*resourceQuotaCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); res.Pass {
		t.Fatal("expected FAIL at 0.95 used/hard")
	}

	// Boundary: exactly at threshold is a pass (only '>' fails).
	p = testProber(fake.NewSimpleClientset(quota("a", "q", "900m", "1")))
	if res := probetest.MustCheck[*resourceQuotaCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatal("used/hard == threshold must pass")
	}

	// No usage recorded -> used=0 -> pass.
	p = testProber(fake.NewSimpleClientset(quota("a", "q", "", "1")))
	if res := probetest.MustCheck[*resourceQuotaCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatal("absent Used entry must pass")
	}

	// Wire request carries ResourceVersion=0.
	var rqRV string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rqRV = r.URL.Query().Get("resourceVersion")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"ResourceQuotaList","items":[]}`))
	}))
	defer srv.Close()
	cs, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	d := probetest.NewDeps(cs, nil)
	chk := NewResourceQuotaCheck(d)
	if res := chk.Run(probetest.SweepCtx(ctx, d)); !res.Pass || res.Infra != nil {
		t.Fatalf("expected clean pass, got %+v", res)
	}
	if rqRV != "0" {
		t.Fatalf("resourcequotas resourceVersion = %q, want \"0\"", rqRV)
	}
}

type portedRTFunc func(*http.Request) (*http.Response, error)

func (f portedRTFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPortedAutoDetectAndFailover(t *testing.T) {
	promq.InvalidateAutoDetectCache()
	t.Cleanup(promq.InvalidateAutoDetectCache)
	blankPortedEnv(t)

	var promUp atomic.Bool
	promUp.Store(true)

	client := &http.Client{Transport: portedRTFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Host {
		case "kube-prometheus-stack-prometheus.prometheus-operator.svc:9090":
			if promUp.Load() {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("Prometheus Server is Healthy.")),
					Header:     make(http.Header),
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Body:       io.NopCloser(strings.NewReader("down")),
				Header:     make(http.Header),
			}, nil
		case "vmauth-victoria-metrics-k8s-stack.victoria-metrics.svc:8427":
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("OK")),
				Header:     make(http.Header),
			}, nil
		default:
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     make(http.Header),
			}, nil
		}
	})}

	var mu sync.Mutex
	var lookedUp []string
	p := testProber(fake.NewSimpleClientset())
	p.Cfg.HTTPContent = HTTPContentConfigFromEnv()
	p.Cfg.ObsBackendMode = promq.ObsBackendAuto
	p.HTTPClient = client
	p.LookupHost = func(_ context.Context, host string) ([]string, error) {
		mu.Lock()
		lookedUp = append(lookedUp, host)
		mu.Unlock()
		return []string{"10.0.0.1"}, nil
	}

	dnsChk := NewDNSStatusCheck(p.Deps)
	httpChk := NewHTTPContentCheck(p.Deps)

	// Sweep 1: Prometheus healthy -> resolves Prom DNS & checks Healthy.
	if res := httpChk.Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("http-content-check sweep 1 = %+v, want pass", res)
	}
	if res := dnsChk.Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("dns-status-internal sweep 1 = %+v, want pass", res)
	}
	mu.Lock()
	if len(lookedUp) != 2 || lookedUp[1] != promq.DefaultPrometheusTarget().DNSHost {
		t.Fatalf("sweep 1 DNS hostnames = %v", lookedUp)
	}
	lookedUp = nil
	mu.Unlock()

	// Sweep 2 (cutover): Prometheus down -> cache invalidated -> failover to VMAuth ("OK" + vmauth DNS).
	promUp.Store(false)
	promq.InvalidateAutoDetectCache()
	sctx := probetest.SweepCtx(ctx, p.Deps)
	if res := httpChk.Run(sctx); !res.Pass {
		t.Fatalf("http-content-check failover = %+v, want pass on VMAuth", res)
	}
	if res := dnsChk.Run(sctx); !res.Pass {
		t.Fatalf("dns-status-internal failover = %+v, want pass on VMAuth", res)
	}
	mu.Lock()
	if len(lookedUp) != 2 || lookedUp[1] != promq.DefaultVMAuthTarget().DNSHost {
		t.Fatalf("sweep 2 DNS hostnames = %v, want VMAuth DNS", lookedUp)
	}
	mu.Unlock()

	// Explicit HEALTH_DNS_HOSTNAMES overrides auto-detected DNS hostnames.
	t.Setenv("HEALTH_DNS_HOSTNAMES", "custom.svc.cluster.local")
	explicitDNS := NewDNSStatusCheck(p.Deps)
	mu.Lock()
	lookedUp = nil
	mu.Unlock()
	if res := explicitDNS.Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("explicit DNS check = %+v", res)
	}
	mu.Lock()
	if len(lookedUp) != 1 || lookedUp[0] != "custom.svc.cluster.local" {
		t.Fatalf("explicit DNS looked up %v, want [custom.svc.cluster.local]", lookedUp)
	}
	mu.Unlock()
}

func TestDNSStatusExplicitURLAndBackendMode(t *testing.T) {
	t.Run("explicit HEALTH_HTTP_CONTENT_URL to VMAuth with HEALTH_DNS_HOSTNAMES unset", func(t *testing.T) {
		blankPortedEnv(t)
		t.Setenv("HEALTH_HTTP_CONTENT_URL", "http://vmauth-victoria-metrics-k8s-stack.victoria-metrics.svc:8427/health")

		var mu sync.Mutex
		var lookedUp []string
		p := testProber(fake.NewSimpleClientset())
		p.Cfg.HTTPContent = HTTPContentConfigFromEnv()
		p.Cfg.ObsBackendMode = promq.ObsBackendVictoriaMetrics
		p.HTTPClient = &http.Client{Transport: portedRTFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("unexpected HTTP probe when HEALTH_HTTP_CONTENT_URL is explicit")
			return nil, nil
		})}
		p.LookupHost = func(_ context.Context, host string) ([]string, error) {
			mu.Lock()
			lookedUp = append(lookedUp, host)
			mu.Unlock()
			return []string{"10.0.0.1"}, nil
		}

		chk := NewDNSStatusCheck(p.Deps)
		if res := chk.Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
			t.Fatalf("dns-status-internal = %+v, want pass", res)
		}
		want := []string{
			"kubernetes.default.svc.cluster.local",
			"vmauth-victoria-metrics-k8s-stack.victoria-metrics.svc",
		}
		mu.Lock()
		defer mu.Unlock()
		if !reflect.DeepEqual(lookedUp, want) {
			t.Fatalf("lookedUp = %v, want %v", lookedUp, want)
		}
	})

	t.Run("explicit HEALTH_HTTP_CONTENT_URL deduplicates identical k8s host and ignores IP or localhost", func(t *testing.T) {
		cases := []struct {
			name string
			url  string
			mode promq.ObsBackendMode
			want []string
		}{
			{
				name: "identical kubernetes host deduplicated",
				url:  "https://kubernetes.default.svc.cluster.local:443/healthz",
				mode: promq.ObsBackendAuto,
				want: []string{"kubernetes.default.svc.cluster.local"},
			},
			{
				name: "IP literal falls back to default",
				url:  "http://127.0.0.1:8427/health",
				mode: promq.ObsBackendAuto,
				want: []string{
					"kubernetes.default.svc.cluster.local",
					promq.DefaultPrometheusTarget().DNSHost,
				},
			},
			{
				name: "localhost falls back to VM target when mode is victoriametrics",
				url:  "http://localhost:8427/health",
				mode: promq.ObsBackendVictoriaMetrics,
				want: []string{
					"kubernetes.default.svc.cluster.local",
					promq.DefaultVMAuthTarget().DNSHost,
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				blankPortedEnv(t)
				t.Setenv("HEALTH_HTTP_CONTENT_URL", tc.url)

				var lookedUp []string
				p := testProber(fake.NewSimpleClientset())
				p.Cfg.HTTPContent = HTTPContentConfigFromEnv()
				p.Cfg.ObsBackendMode = tc.mode
				p.LookupHost = func(_ context.Context, host string) ([]string, error) {
					lookedUp = append(lookedUp, host)
					return []string{"10.0.0.1"}, nil
				}

				chk := NewDNSStatusCheck(p.Deps)
				if res := chk.Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
					t.Fatalf("dns-status-internal = %+v, want pass", res)
				}
				if !reflect.DeepEqual(lookedUp, tc.want) {
					t.Fatalf("lookedUp = %v, want %v", lookedUp, tc.want)
				}
			})
		}
	})

	t.Run("NODE_AUTOMATION_OBS_BACKEND=victoriametrics with HEALTH_DNS_HOSTNAMES unset", func(t *testing.T) {
		blankPortedEnv(t)

		var lookedUp []string
		p := testProber(fake.NewSimpleClientset())
		p.Cfg.ObsBackendMode = promq.ObsBackendVictoriaMetrics
		p.HTTPClient = &http.Client{Transport: portedRTFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("unexpected HTTP probe when AutoDetect is false")
			return nil, nil
		})}
		p.LookupHost = func(_ context.Context, host string) ([]string, error) {
			lookedUp = append(lookedUp, host)
			return []string{"10.0.0.1"}, nil
		}

		chk := NewDNSStatusCheck(p.Deps)
		if res := chk.Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
			t.Fatalf("dns-status-internal = %+v, want pass", res)
		}
		want := []string{
			"kubernetes.default.svc.cluster.local",
			promq.DefaultTargetForMode(promq.ObsBackendVictoriaMetrics).DNSHost,
		}
		if !reflect.DeepEqual(lookedUp, want) {
			t.Fatalf("lookedUp = %v, want %v", lookedUp, want)
		}
	})

	t.Run("probetest.NewDeps stays inert and uses default hostnames without HTTP probes", func(t *testing.T) {
		blankPortedEnv(t)

		var lookedUp []string
		d := probetest.NewDeps(fake.NewSimpleClientset(), nil)
		d.HTTPClient = &http.Client{Transport: portedRTFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("unexpected HTTP probe from probetest.NewDeps")
			return nil, nil
		})}
		d.LookupHost = func(_ context.Context, host string) ([]string, error) {
			lookedUp = append(lookedUp, host)
			return []string{"10.0.0.1"}, nil
		}

		chk := NewDNSStatusCheck(d)
		if res := chk.Run(probetest.SweepCtx(ctx, d)); !res.Pass {
			t.Fatalf("dns-status-internal = %+v, want pass", res)
		}
		want := []string{
			"kubernetes.default.svc.cluster.local",
			promq.DefaultPrometheusTarget().DNSHost,
		}
		if !reflect.DeepEqual(lookedUp, want) {
			t.Fatalf("lookedUp = %v, want %v", lookedUp, want)
		}
	})
}
