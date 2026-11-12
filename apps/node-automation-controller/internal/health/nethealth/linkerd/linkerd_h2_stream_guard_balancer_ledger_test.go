// linkerd_h2_stream_guard_balancer_ledger_test.go — regression for
// the emitted-gauge ledger granularity bug: the wedged-balancer
// gauge declares only (namespace, pod) but the ledger keyed per
// target_addr, so a pod with TWO wedged targets lost its series the
// sweep ONE of them recovered — Reconcile pruned the vanished
// target's key and DeleteLabelValues(ns, pod) took the still-wedged
// sibling target's metric down with it.
package linkerd

import (
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// Two targets wedged on the same pod emit ONE (namespace, pod)
// series; when one target recovers, the other still-wedged target's
// series must survive the ledger prune.
func TestLinkerdBalancerPartialRecoveryKeepsGauge(t *testing.T) {
	base := time.Now()
	// No Ready sibling: the heal is always skipped, so the pod lives
	// through every run and only the gauge lifecycle is under test.
	bad := meshedPod("apps", "web-1", true, types.UID("rs-solo"))
	cs := fake.NewSimpleClientset(
		bad,
		// Both target Services stay healthy — each wedge is
		// client-side, never a real outage.
		probetest.EndpointSliceForService("backend", "db-svc", "10.244.0.9"),
		probetest.EndpointSliceForService("backend", "api-svc", "10.244.0.10"))
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"linkerd-proxy INFO connection established\n", nil))

	targets := []string{
		"db-svc.backend.svc.cluster.local:5432",
		"api-svc.backend.svc.cluster.local:443",
	}
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if !strings.Contains(query, "outbound_http_balancer_endpoints") ||
			strings.Contains(query, `state="ready"`) {
			return nil
		}
		var out []probetest.PromTestSample
		for _, target := range targets {
			out = append(out, probetest.PromTestSample{
				Labels: map[string]string{
					"namespace":   "apps",
					"pod":         "web-1",
					"target_addr": target,
				},
				Value: 3,
			})
		}
		return out
	})
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	chk := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, base)
	if res := chk.Run(probetest.SweepCtx(ctx)); !res.Pass {
		t.Fatalf("first-seen wedges must pass (inside window): %+v", res)
	}
	probetest.FreezeNow(p.Deps, base.Add(linkerdBalancerWedgeMinAge+time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx)); res.Pass {
		t.Fatal("two persisted wedges must fail")
	}
	m := probetest.FindMetric(t, "node_automation_linkerd_outbound_balancer_wedged",
		map[string]string{"namespace": "apps", "pod": "web-1"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("balancer-wedged gauge = %v, want 1", m)
	}
	t.Cleanup(func() {
		linkerdOutboundBalancerWedgedGauge.DeleteLabelValues("apps", "web-1")
	})

	// One of the two targets recovers: the still-wedged target must
	// keep the pod's series — the ledger prune must not delete it.
	targets = targets[:1]
	res := chk.Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("the surviving wedge must still fail")
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-1", metav1.GetOptions{}); err != nil {
		t.Fatalf("sibling-less pod must not be deleted: %v", err)
	}
	m = probetest.FindMetric(t, "node_automation_linkerd_outbound_balancer_wedged",
		map[string]string{"namespace": "apps", "pod": "web-1"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("balancer-wedged gauge = %v after partial recovery, want 1 "+
			"(ledger pruned the still-wedged target's series)", m)
	}
}
