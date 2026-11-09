// coredns_upstream_test.go — coverage for the coredns-upstream
// check (coredns-upstream): isolated-failure pod delete, fleet-wide
// detection-only, readiness fallback.
package nethealth

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

func TestCoreDNSUpstreamDeletesIsolatedFailingPod(t *testing.T) {
	srv := coreDNSUpstreamPromServer(t)
	bad := probetest.PodWithPhase("kube-system", "coredns-bad", corev1.PodRunning, false, time.Hour)
	good := probetest.PodWithPhase("kube-system", "coredns-good", corev1.PodRunning, true, time.Hour)
	cs := fake.NewSimpleClientset(bad, good)
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()

	res := probetest.MustCheck[*coreDNSUpstreamCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("isolated upstream failure must fail: %+v", res)
	}
	if !strings.Contains(res.Why, "coredns-bad") {
		t.Fatalf("why missing pod: %q", res.Why)
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, "coredns-bad", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("isolated failing pod should be deleted, err=%v", err)
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, "coredns-good", metav1.GetOptions{}); err != nil {
		t.Fatalf("healthy sibling must survive: %v", err)
	}
}

func TestCoreDNSUpstreamFleetWideDoesNotDelete(t *testing.T) {
	// Both dns pods flagged -> no healthy sibling -> detection only.
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "ForwardHealthcheckFailureCount") {
			return []probetest.PromTestSample{
				{Labels: map[string]string{"pod": "coredns-a", "namespace": "kube-system"}, Value: 1},
				{Labels: map[string]string{"pod": "coredns-b", "namespace": "kube-system"}, Value: 1},
			}
		}
		return nil
	})
	a := probetest.PodWithPhase("kube-system", "coredns-a", corev1.PodRunning, true, time.Hour)
	b := probetest.PodWithPhase("kube-system", "coredns-b", corev1.PodRunning, true, time.Hour)
	cs := fake.NewSimpleClientset(a, b)
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()

	res := probetest.MustCheck[*coreDNSUpstreamCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("fleet-wide failure must fail: %+v", res)
	}
	for _, name := range []string{"coredns-a", "coredns-b"} {
		if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, name, metav1.GetOptions{}); err != nil {
			t.Fatalf("fleet-wide failure must not delete %s: %v", name, err)
		}
	}
}

func TestCoreDNSFallbackUnreadyPod(t *testing.T) {
	// Prometheus dead -> readiness fallback: unready >10m + sibling.
	bad := probetest.PodWithPhase("kube-system", "node-local-dns-x1", corev1.PodPending, false, 15*time.Minute)
	good := probetest.PodWithPhase("kube-system", "node-local-dns-x2", corev1.PodRunning, true, time.Hour)
	cs := fake.NewSimpleClientset(bad, good)
	p := testProber(cs) // dead httpURL -> both prom queries fail

	res := probetest.MustCheck[*coreDNSUpstreamCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("fallback must detect the unready dns pod: %+v", res)
	}
	if !strings.Contains(res.Why, "node-local-dns-x1") {
		t.Fatalf("why missing pod: %q", res.Why)
	}
}

// coreDNSUpstreamPromServer answers the two coredns queries: the healthcheck
// query reports pod "bad" failing; the SERVFAIL query reports none.
func coreDNSUpstreamPromServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "ForwardHealthcheckFailureCount") {
			return []probetest.PromTestSample{{
				Labels: map[string]string{"pod": "coredns-bad", "namespace": "kube-system"},
				Value:  1.4,
			}}
		}
		return nil
	})
	return srv
}

// Two dns pods sharing a bare name across namespaces must each be
// attributed to their own namespace — a bare-name census key would
// collapse them and silently drop one namespace's flag.
func TestCoreDNSUpstreamDuplicateNamesAcrossNamespaces(t *testing.T) {
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "ForwardHealthcheckFailureCount") {
			return []probetest.PromTestSample{
				{Labels: map[string]string{"pod": "coredns-dup", "namespace": "kube-system"}, Value: 1},
				{Labels: map[string]string{"pod": "coredns-dup", "namespace": "dns-secondary"}, Value: 1},
			}
		}
		return nil
	})
	kube1 := probetest.PodWithPhase("kube-system", "coredns-dup", corev1.PodRunning, true, time.Hour)
	kube2 := probetest.PodWithPhase("dns-secondary", "coredns-dup", corev1.PodRunning, true, time.Hour)
	cs := fake.NewSimpleClientset(kube1, kube2)
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()

	res := probetest.MustCheck[*coreDNSUpstreamCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("both flagged pods must fail the check: %+v", res)
	}
	for _, key := range []string{"kube-system/coredns-dup", "dns-secondary/coredns-dup"} {
		if !strings.Contains(res.Why, key) {
			t.Fatalf("why missing %s (cross-ns name collision misattributed): %q", key, res.Why)
		}
	}
}
