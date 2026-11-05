// cilium_node_ipam_exhaustion_test.go — coverage for the
// cilium-node-ipam-exhaustion check (W10-NM6): exhaustion FAIL +
// terminal-pod reap, healthy node, podCIDR capacity math.
package nethealth

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// W10-NM6 — cilium-node-ipam-exhaustion
// ---------------------------------------------------------------------------

func TestCiliumIPAMExhaustionFailsAndReapsTerminalPods(t *testing.T) {
	// /30 podCIDR -> 2 usable IPs; 2 running pods exhaust it.
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "w-exhaust"},
		Spec: corev1.NodeSpec{PodCIDR: "10.240.0.0/30"}}
	p1 := probetest.PodWithPhase("apps", "app-1", corev1.PodRunning, true, time.Hour)
	p1.Spec.NodeName = "w-exhaust"
	p2 := probetest.PodWithPhase("apps", "app-2", corev1.PodRunning, true, time.Hour)
	p2.Spec.NodeName = "w-exhaust"
	dead := probetest.PodWithPhase("apps", "app-dead", corev1.PodSucceeded, false, time.Hour)
	dead.Spec.NodeName = "w-exhaust"
	cs := fake.NewSimpleClientset(node, p1, p2, dead)
	// The fake ignores field selectors — teach it spec.nodeName so
	// the per-node reap list stays scoped like the real apiserver.
	testutil.EmulatePodNodeNameSelector(cs)
	p := testProber(cs) // dead prom -> pod-count fallback

	res := mustCheck[*ciliumNodeIPAMExhaustionCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("exhausted node must fail: %+v", res)
	}
	if !strings.Contains(res.Why, "w-exhaust") {
		t.Fatalf("why missing node: %q", res.Why)
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "app-dead", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("terminal pod should be reaped, err=%v", err)
	}
	for _, name := range []string{"app-1", "app-2"} {
		if _, err := cs.CoreV1().Pods("apps").Get(ctx, name, metav1.GetOptions{}); err != nil {
			t.Fatalf("live pod %s must survive: %v", name, err)
		}
	}
}

func TestCiliumIPAMHealthyNodePasses(t *testing.T) {
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "w-ok"},
		Spec: corev1.NodeSpec{PodCIDR: "10.240.1.0/24"}}
	cs := fake.NewSimpleClientset(node)
	p := testProber(cs)
	if res := mustCheck[*ciliumNodeIPAMExhaustionCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("empty /24 must pass: %+v", res)
	}
}

func TestPodCIDRCapacity(t *testing.T) {
	if got, ok := podCIDRCapacity("10.0.0.0/24"); !ok || got != 254 {
		t.Fatalf("/24 capacity = %d,%v want 254,true", got, ok)
	}
	if _, ok := podCIDRCapacity("fd00::/64"); ok {
		t.Fatal("IPv6 podCIDR must be skipped")
	}
	if _, ok := podCIDRCapacity(""); ok {
		t.Fatal("empty podCIDR must be skipped")
	}
}
