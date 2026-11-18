// stale_recover_nodename_test.go — the stale-pod eviction's L1 yield:
// recover() must carry Spec.NodeName from the census onto the
// synthetic pod, or heal.EvictPod's local-remediation hold reads an
// unscheduled pod and skips the yield entirely.
package corednswatchdog

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

// A stale pod on a node inside the node-host-agent's self-heal window
// must be left alone: the eviction's L1<->L3 yield needs the pod's
// node, which only the sweep census can supply.
func TestCoreDNSRecoverYieldsToNodeLocalRemediation(t *testing.T) {
	now := time.Now()
	node := testutil.Node("n1", corev1.ConditionTrue, nil)
	node.Annotations = map[string]string{
		nodecond.AnnoLocalRemediationUntil: metav1.NewTime(
			now.Add(3 * time.Minute)).Format(time.RFC3339),
	}
	cs := fake.NewSimpleClientset(node,
		cdnsPod("cdns-a", "10.0.0.1"), cdnsPod("cdns-b", "10.0.0.2"),
		cdnsDeployment(2, 2, nil))
	w := newCDNSWatchdog(cs)
	w.now = shared.SystemClock

	if err := w.recover(ctx, []string{"cdns-a"}, nil,
		map[string]string{"cdns-a": "n1"}, 2); err != nil {
		t.Fatal(err)
	}
	if !testutil.PodExists(t, cs, corednsNS, "cdns-a") {
		t.Fatal("stale pod evicted while its node is inside L1 local remediation")
	}
}

// Same shape without the node in the map: the hold has no node to
// inspect, so this is the pre-fix baseline — the pod is evicted.
// Kept as a guard that the test above really exercises the seam.
func TestCoreDNSRecoverWithoutNodeHasNoHold(t *testing.T) {
	cs := fake.NewSimpleClientset(
		cdnsPod("cdns-a", "10.0.0.1"), cdnsPod("cdns-b", "10.0.0.2"),
		cdnsDeployment(2, 2, nil))
	w := newCDNSWatchdog(cs)
	if err := w.recover(ctx, []string{"cdns-a"}, nil, nil, 2); err != nil {
		t.Fatal(err)
	}
	if testutil.PodExists(t, cs, corednsNS, "cdns-a") {
		t.Fatal("baseline: a stale pod with no node evidence must be evicted")
	}
}
