// ported_probes_test.go — the five ported kuberhealthy checks
// driven through an injectable DNS seam, an httptest target and the
// fake clientset (apiserver reads only — no envtest needed).
package ported

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
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
	p := testProber(fake.NewSimpleClientset())
	if res := probetest.MustCheck[*dnsStatusCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("expected pass, got %+v", res)
	}

	// Any single lookup failure fails the whole check.
	p.LookupHost = func(_ context.Context, host string) ([]string, error) {
		if host == "svc-b.ns.svc" {
			return nil, errors.New("NXDOMAIN")
		}
		return []string{"10.0.0.1"}, nil
	}
	res := probetest.MustCheck[*dnsStatusCheck](t, p).Run(ctx)
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

	if res := probetest.MustCheck[*httpContentCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("expected pass on 'Healthy' body, got %+v", res)
	}

	// Expected substring missing -> FAIL.
	p.Cfg.HTTPContent.Expected = "Absolutely"
	if res := probetest.MustCheck[*httpContentCheck](t, p).Run(ctx); res.Pass {
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
	if res := probetest.MustCheck[*httpContentCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("expected FAIL on non-200")
	}
}

// ---------------------------------------------------------------------------
// pod-restarts
// ---------------------------------------------------------------------------

func TestProbePodRestarts(t *testing.T) {
	// W10-FIX5: an over-threshold RestartCount only FAILs while the
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
	if res := probetest.MustCheck[*podRestartsCheck](t, p).Run(ctx); res.Pass {
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
	if res := probetest.MustCheck[*podRestartsCheck](t, testProber(fake.NewSimpleClientset(waiting))).Run(ctx); res.Pass {
		t.Fatal("expected FAIL on CrashLoopBackOff over threshold")
	}

	// W10-FIX5: the same count with a STALE last termination (>24h)
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
	if res := probetest.MustCheck[*podRestartsCheck](t, testProber(fake.NewSimpleClientset(stale))).Run(ctx); !res.Pass {
		t.Fatal("stale (>24h) termination must not FAIL the check")
	}

	// Boundary: exactly at the limit is still a pass.
	over.Status.ContainerStatuses[0].RestartCount = 10
	cs := fake.NewSimpleClientset(over)
	if res := probetest.MustCheck[*podRestartsCheck](t, testProber(cs)).Run(ctx); !res.Pass {
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
	if res := probetest.MustCheck[*podRestartsCheck](t, testProber(fake.NewSimpleClientset(init))).Run(ctx); res.Pass {
		t.Fatal("expected FAIL on init-container restarts")
	}
}

// ---------------------------------------------------------------------------
// pod-status-check
// ---------------------------------------------------------------------------

func TestProbePodStatus(t *testing.T) {
	p := testProber(fake.NewSimpleClientset(
		chPod("kube-system", "stuck", corev1.PodPending, 15*time.Minute)))
	if res := probetest.MustCheck[*podStatusCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("expected FAIL on old Pending pod")
	}

	// Younger than SKIP_DURATION -> ignored (image still pulling).
	p = testProber(fake.NewSimpleClientset(
		chPod("kube-system", "fresh", corev1.PodPending, 5*time.Minute)))
	if res := probetest.MustCheck[*podStatusCheck](t, p).Run(ctx); !res.Pass {
		t.Fatal("young Pending pod must be skipped")
	}

	for _, phase := range []corev1.PodPhase{corev1.PodFailed, corev1.PodUnknown} {
		p = testProber(fake.NewSimpleClientset(
			chPod("kube-system", "dead", phase, time.Hour)))
		if res := probetest.MustCheck[*podStatusCheck](t, p).Run(ctx); res.Pass {
			t.Fatalf("expected FAIL on phase %s", phase)
		}
	}

	p = testProber(fake.NewSimpleClientset(
		chPod("kube-system", "ok", corev1.PodRunning, time.Hour),
		chPod("kube-system", "done", corev1.PodSucceeded, time.Hour)))
	if res := probetest.MustCheck[*podStatusCheck](t, p).Run(ctx); !res.Pass {
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
	if res := probetest.MustCheck[*resourceQuotaCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("expected FAIL at 0.95 used/hard")
	}

	// Boundary: exactly at threshold is a pass (only '>' fails).
	p = testProber(fake.NewSimpleClientset(quota("a", "q", "900m", "1")))
	if res := probetest.MustCheck[*resourceQuotaCheck](t, p).Run(ctx); !res.Pass {
		t.Fatal("used/hard == threshold must pass")
	}

	// No usage recorded -> used=0 -> pass.
	p = testProber(fake.NewSimpleClientset(quota("a", "q", "", "1")))
	if res := probetest.MustCheck[*resourceQuotaCheck](t, p).Run(ctx); !res.Pass {
		t.Fatal("absent Used entry must pass")
	}
}
