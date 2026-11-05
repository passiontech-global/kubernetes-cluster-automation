// coredns_upstream_test.go — coverage for the coredns-upstream
// check (W10-NM5): isolated-failure pod delete, fleet-wide
// detection-only, readiness fallback.
package clusterhealthprobes

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestCoreDNSUpstreamDeletesIsolatedFailingPod(t *testing.T) {
	srv := coreDNSUpstreamPromServer(t)
	bad := podWithPhase("kube-system", "coredns-bad", corev1.PodRunning, false, time.Hour)
	good := podWithPhase("kube-system", "coredns-good", corev1.PodRunning, true, time.Hour)
	cs := fake.NewSimpleClientset(bad, good)
	p := testProber(cs)
	p.cfg.httpURL = srv.URL
	p.httpClient = srv.Client()

	res := p.coreDNS.run(ctx)
	if res.pass {
		t.Fatalf("isolated upstream failure must fail: %+v", res)
	}
	if !strings.Contains(res.why, "coredns-bad") {
		t.Fatalf("why missing pod: %q", res.why)
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
	srv, _ := promTestServer(t, func(query string) []promTestSample {
		if strings.Contains(query, "ForwardHealthcheckFailureCount") {
			return []promTestSample{
				{labels: map[string]string{"pod": "coredns-a", "namespace": "kube-system"}, value: 1},
				{labels: map[string]string{"pod": "coredns-b", "namespace": "kube-system"}, value: 1},
			}
		}
		return nil
	})
	a := podWithPhase("kube-system", "coredns-a", corev1.PodRunning, true, time.Hour)
	b := podWithPhase("kube-system", "coredns-b", corev1.PodRunning, true, time.Hour)
	cs := fake.NewSimpleClientset(a, b)
	p := testProber(cs)
	p.cfg.httpURL = srv.URL
	p.httpClient = srv.Client()

	res := p.coreDNS.run(ctx)
	if res.pass {
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
	bad := podWithPhase("kube-system", "node-local-dns-x1", corev1.PodPending, false, 15*time.Minute)
	good := podWithPhase("kube-system", "node-local-dns-x2", corev1.PodRunning, true, time.Hour)
	cs := fake.NewSimpleClientset(bad, good)
	p := testProber(cs) // dead httpURL -> both prom queries fail

	res := p.coreDNS.run(ctx)
	if res.pass {
		t.Fatalf("fallback must detect the unready dns pod: %+v", res)
	}
	if !strings.Contains(res.why, "node-local-dns-x1") {
		t.Fatalf("why missing pod: %q", res.why)
	}
}
