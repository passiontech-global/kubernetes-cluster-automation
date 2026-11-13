// partition_evictor_errors_test.go — census list failures: a node
// list error aborts the whole sweep, a per-node pod list error only
// skips that node.
package partitionevictor

import (
	"errors"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// A node list failure aborts the sweep — flagging on a partial view
// could read a mesh-wide outage as node-local.
func TestPartitionEvictorNodeListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err == nil {
		t.Fatal("expected error when the node list fails")
	}
}

// A pod list failure on one flagged node logs + continues: the run
// still nils out and the other flagged node is fully processed.
func TestPartitionEvictorPodListErrorContinues(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	objs := []runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
		pePartitionedNode("p2", "HostNetworkProblems", 20*time.Minute),
		pePod("flux-system", "p1", "victim-p1"),
		pePod("flux-system", "p2", "victim-p2"),
	}
	objs = append(objs, peHealthyNodes("h", 3)...)
	cs := fake.NewSimpleClientset(objs...)
	peEmulateEviction(cs)
	// The fake ignores spec.nodeName field selectors — emulate them
	// (helper shared with the cilium-taint-reaper tests) so a failure
	// scoped to p1 cannot leak p2's pods into p1's list result.
	testutil.EmulatePodNodeNameSelector(cs)
	// Fail the pod list only when scoped to p1's nodeName selector.
	cs.PrependReactor("list", "pods",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			la, ok := action.(ktesting.ListAction)
			if !ok {
				return false, nil, nil
			}
			if fields := la.GetListRestrictions().Fields; fields != nil {
				if nn, found := fields.RequiresExactMatch("spec.nodeName"); found && nn == "p1" {
					return true, nil, errors.New("pod list boom")
				}
			}
			return false, nil, nil
		})
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatalf("a per-node pod list failure must not abort the run: %v", err)
	}
	if !testutil.PodExistsStrict(t, cs, "flux-system", "victim-p1") {
		t.Fatal("p1's pod vanished although its list failed")
	}
	if testutil.PodExistsStrict(t, cs, "flux-system", "victim-p2") {
		t.Fatal("p2's pod not evicted — sibling node skipped after p1's error")
	}
	for _, name := range []string{"p1", "p2"} {
		if !kube.HasTaint(testutil.GetNode(t, cs, name).Spec.Taints, partitionTaintKey) {
			t.Fatalf("flagged node %s not tainted", name)
		}
	}
}
