// cilium_pod_apiserver_blackhole_test.go — coverage for silent
// pod->apiserver (10.96.0.1:443) blackhole detection & minority
// cilium agent bounce inside cilium-datapath-map-guard.
package cilium

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

func blackholeWorker(name string, age time.Duration, msg string, extra ...corev1.NodeCondition) *corev1.Node {
	now := time.Now()
	conds := []corev1.NodeCondition{
		{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
	}
	if msg != "" {
		conds = append(conds, corev1.NodeCondition{
			Type:               nodecond.ClusterNetworkProblem,
			Status:             corev1.ConditionTrue,
			Reason:             "ClusterNetworkProblem",
			Message:            msg,
			LastTransitionTime: metav1.NewTime(now.Add(-age)),
			LastHeartbeatTime:  metav1.NewTime(now),
		})
	}
	conds = append(conds, extra...)
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status:     corev1.NodeStatus{Conditions: conds},
	}
}

func ciliumAgentPod(node string, age time.Duration) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "kube-system",
			Name:              "cilium-" + node,
			UID:               types.UID("uid-cilium-" + node),
			Labels:            map[string]string{"k8s-app": "cilium"},
			CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
		},
		Spec:   corev1.PodSpec{NodeName: node},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func TestCiliumPodAPIServerBlackholeMinorityHeals(t *testing.T) {
	testutil.CleanupMetric(t, ciliumDatapathDegradedGauge, ciliumPodAPIServerBlackholeReason)
	srv, _ := probetest.PromTestServer(t, func(string) []probetest.PromTestSample { return nil })

	cs := fake.NewSimpleClientset(
		blackholeWorker("w1", 15*time.Minute, "probe https-p2api-int failed: i/o timeout"),
		blackholeWorker("w2", 0, ""),
		blackholeWorker("w3", 0, ""),
		ciliumAgentPod("w1", 2*time.Hour),
		ciliumAgentPod("w2", 2*time.Hour),
		ciliumAgentPod("w3", 2*time.Hour),
	)
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()

	chk := probetest.MustCheck[*ciliumDatapathMapCheck](t, p)
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatal("sustained pod->apiserver blackhole must fail the check")
	}
	m := probetest.FindMetric(t, "node_automation_cilium_datapath_degraded",
		map[string]string{"reason": ciliumPodAPIServerBlackholeReason})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("missing pod_apiserver_blackhole gauge series")
	}
	if testutil.PodExistsStrict(t, cs, "kube-system", "cilium-w1") {
		t.Fatal("expected minority blackholed worker cilium-w1 pod to be deleted")
	}
	if !testutil.PodExistsStrict(t, cs, "kube-system", "cilium-w2") {
		t.Fatal("healthy worker cilium-w2 must not be touched")
	}
}

func TestCiliumPodAPIServerBlackholeGuards(t *testing.T) {
	srv, _ := probetest.PromTestServer(t, func(string) []probetest.PromTestSample { return nil })

	t.Run("fresh condition below 10m passes", func(t *testing.T) {
		testutil.CleanupMetric(t, ciliumDatapathDegradedGauge, ciliumPodAPIServerBlackholeReason)
		cs := fake.NewSimpleClientset(
			blackholeWorker("w1", 4*time.Minute, "probe https-p2api-int failed"),
			blackholeWorker("w2", 0, ""),
			blackholeWorker("w3", 0, ""),
			ciliumAgentPod("w1", 2*time.Hour),
		)
		p := testProber(cs)
		p.Cfg.HTTPContent.URL = srv.URL
		p.HTTPClient = srv.Client()
		res := probetest.MustCheck[*ciliumDatapathMapCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
		if !res.Pass {
			t.Fatalf("fresh (<10m) condition must pass: %+v", res)
		}
		if !testutil.PodExistsStrict(t, cs, "kube-system", "cilium-w1") {
			t.Fatal("fresh condition deleted cilium pod")
		}
	})

	t.Run("CiliumAgentDown skips blackhole heal", func(t *testing.T) {
		testutil.CleanupMetric(t, ciliumDatapathDegradedGauge, ciliumPodAPIServerBlackholeReason)
		cs := fake.NewSimpleClientset(
			blackholeWorker("w1", 20*time.Minute, "probe https-p2api-int failed", corev1.NodeCondition{
				Type:   nodecond.CiliumAgentDown,
				Status: corev1.ConditionTrue,
			}),
			blackholeWorker("w2", 0, ""),
			blackholeWorker("w3", 0, ""),
			ciliumAgentPod("w1", 2*time.Hour),
		)
		p := testProber(cs)
		p.Cfg.HTTPContent.URL = srv.URL
		p.HTTPClient = srv.Client()
		res := probetest.MustCheck[*ciliumDatapathMapCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
		if !res.Pass {
			t.Fatalf("CiliumAgentDown=True should defer to host agent: %+v", res)
		}
		if !testutil.PodExistsStrict(t, cs, "kube-system", "cilium-w1") {
			t.Fatal("CiliumAgentDown=True node should not be bounced by blackhole check")
		}
	})

	t.Run("majority blackhole emits gauge without deleting pods", func(t *testing.T) {
		testutil.CleanupMetric(t, ciliumDatapathDegradedGauge, ciliumPodAPIServerBlackholeReason)
		cs := fake.NewSimpleClientset(
			blackholeWorker("w1", 20*time.Minute, "probe https-p2api-int failed"),
			blackholeWorker("w2", 20*time.Minute, "probe https-p2api-int failed"),
			blackholeWorker("w3", 0, ""),
			ciliumAgentPod("w1", 2*time.Hour),
			ciliumAgentPod("w2", 2*time.Hour),
			ciliumAgentPod("w3", 2*time.Hour),
		)
		p := testProber(cs)
		p.Cfg.HTTPContent.URL = srv.URL
		p.HTTPClient = srv.Client()
		res := probetest.MustCheck[*ciliumDatapathMapCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
		if res.Pass {
			t.Fatal("majority blackhole must still fail check and emit gauge")
		}
		if !testutil.PodExistsStrict(t, cs, "kube-system", "cilium-w1") ||
			!testutil.PodExistsStrict(t, cs, "kube-system", "cilium-w2") {
			t.Fatal("majority blast-radius guard must not delete cilium pods")
		}
	})

	t.Run("non-Cilium cluster ignores condition", func(t *testing.T) {
		testutil.CleanupMetric(t, ciliumDatapathDegradedGauge, ciliumPodAPIServerBlackholeReason)
		cs := fake.NewSimpleClientset(
			blackholeWorker("w1", 20*time.Minute, "probe https-p2api-int failed"),
			blackholeWorker("w2", 0, ""),
			blackholeWorker("w3", 0, ""),
		)
		p := testProber(cs)
		p.Cfg.HTTPContent.URL = srv.URL
		p.HTTPClient = srv.Client()
		res := probetest.MustCheck[*ciliumDatapathMapCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
		if !res.Pass {
			t.Fatalf("non-Cilium cluster must pass cleanly: %+v", res)
		}
	})
}
