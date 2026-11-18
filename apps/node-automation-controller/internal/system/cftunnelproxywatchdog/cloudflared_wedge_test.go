// cloudflared_wedge_test.go — the durable heal-cooldown stamp's
// error accounting: a failed ReplicaSet patch leaves the delivered
// delete (and its in-RAM cooldown) standing, but the tolerated
// sub-failure must still be metered on the module's queue.
package cftunnelproxywatchdog

import (
	"errors"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

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
