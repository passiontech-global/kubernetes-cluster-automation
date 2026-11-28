// cloudflared_wedge_test.go — the durable heal-cooldown stamp's
// error accounting: a failed ReplicaSet patch leaves the delivered
// delete (and its in-RAM cooldown) standing, but the tolerated
// sub-failure must still be metered on the module's queue.
package cftunnelproxywatchdog

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func TestStampHealPersistedFailureMetered(t *testing.T) {
	const queue = "cf-tunnel-wedge-stamp-test"
	now := time.Now()
	pod := rsOwnedPod("proxy-wedged", "rs-wedged", now.Add(-time.Hour), now.Add(-10*time.Minute))
	cs := fake.NewSimpleClientset(pod, healRs("rs-wedged", nil))
	cs.PrependReactor("patch", "replicasets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	w := &cfTunnelProxyWatchdog{cs: cs, queue: queue,
		now: func() time.Time { return now }}

	before := testutil.QueueErrorCount(t, queue)
	w.stampHealPersisted(t.Context(), pod, now)
	if got := testutil.QueueErrorCount(t, queue) - before; got != 1 {
		t.Fatalf("failed durable stamp not metered once: delta = %v", got)
	}
}

func TestCloudflaredWedgeCooldownSkipsRSGetAndLogRead(t *testing.T) {
	now := time.Now()
	pod := rsOwnedPod("proxy-wedged", "rs-wedged", now.Add(-time.Hour), now.Add(-10*time.Minute))
	cs := fake.NewSimpleClientset(pod, healRs("rs-wedged", nil))
	var rsGets, logGets atomic.Int32
	cs.PrependReactor("get", "replicasets", func(ktesting.Action) (bool, runtime.Object, error) {
		rsGets.Add(1)
		return false, nil, nil
	})
	cs.PrependReactor("get", "pods", func(a ktesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() == "log" {
			logGets.Add(1)
		}
		return false, nil, nil
	})
	w := &cfTunnelProxyWatchdog{
		cs:        cs,
		namespace: pod.Namespace,
		queue:     "cf-tunnel-cooldown-test",
		now:       func() time.Time { return now },
	}
	w.lastHeal.Stamp(kube.PodControllerKey(pod), now.Add(-time.Minute))
	wedges, err := w.scanConnectorTarget(t.Context(), cfTunnelConnectorTarget{
		namespace: pod.Namespace,
		selector:  cfTunnelProxyPodSelector,
	}, now, logr.Discard())
	if err != nil {
		t.Fatalf("scanConnectorTarget: %v", err)
	}
	if len(wedges) != 0 {
		t.Fatalf("expected 0 wedges while cooled down, got %d", len(wedges))
	}
	if rsGets.Load() != 0 || logGets.Load() != 0 {
		t.Fatalf("cooled-down controller read RS=%d logs=%d, want 0/0", rsGets.Load(), logGets.Load())
	}
}
