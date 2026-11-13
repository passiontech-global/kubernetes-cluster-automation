// partition_evictor_flagging_test.go — condition-flagging scenarios:
// the min-age and timestamp guards, agent-latch zombie heartbeats,
// the control-plane exemptions and the mesh-wide 50% guard.
package partitionevictor

import (
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// A True network condition that flipped less than partitionMinAge ago
// must not flag the node: no taint, no eviction.
func TestPartitionEvictorFreshConditionNotFlagged(t *testing.T) {
	fresh := pePartitionedNode("p1", "HostNetworkProblems", time.Minute) // 60s < 600s
	objs := append([]runtime.Object{fresh, pePod("flux-system", "p1", "src-ctrl")},
		peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "p1").Spec.Taints, partitionTaintKey) {
		t.Fatal("node with a fresh (<10m) condition must not be tainted")
	}
	if !testutil.PodExistsStrict(t, cs, "flux-system", "src-ctrl") {
		t.Fatal("pod evicted off a node that was never flagged")
	}
}

// A True condition with a zero LastTransitionTime does NOT flag the
// node — the bash `[ -n "$ts" ]` guard: no timestamp, no flag.
func TestPartitionEvictorZeroTimestampNotFlagged(t *testing.T) {
	n := testutil.Node("p1", corev1.ConditionTrue, nil)
	n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
		Type:   "ClusterNetworkProblem",
		Status: corev1.ConditionTrue,
		// LastTransitionTime deliberately zero
	})
	objs := append([]runtime.Object{n, pePod("flux-system", "p1", "src-ctrl")},
		peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "p1").Spec.Taints, partitionTaintKey) {
		t.Fatal("node with timestamp-less condition must not be flagged")
	}
	if !testutil.PodExistsStrict(t, cs, "flux-system", "src-ctrl") {
		t.Fatal("pod evicted off a node that was never flagged")
	}
}

// Two flagged nodes under the 50% guard: each is tainted and flux-system
// pods are evicted off both.
func TestPartitionEvictorMultipleFlaggedUnderHalf(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	objs := []runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
		pePartitionedNode("p2", "HostNetworkProblem", 20*time.Minute), // singular spelling
		pePod("flux-system", "p1", "pod-p1"),
		pePod("flux-system", "p2", "pod-p2"),
	}
	objs = append(objs, peHealthyNodes("h", 3)...) // 2/5 flagged < 50%
	cs := fake.NewSimpleClientset(objs...)
	peEmulateEviction(cs)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"p1", "p2"} {
		if !kube.HasTaint(testutil.GetNode(t, cs, name).Spec.Taints, partitionTaintKey) {
			t.Fatalf("flagged node %s not tainted", name)
		}
	}
	for _, pod := range []string{"pod-p1", "pod-p2"} {
		if testutil.PodExistsStrict(t, cs, "flux-system", pod) {
			t.Fatalf("flux-system pod %s not evicted", pod)
		}
	}
}

// A partitioned control-plane node is never flagged: k0s control
// planes run no evictable workload, so they must be neither tainted
// nor counted toward the mesh-wide guard.
func TestPartitionEvictorSkipsControlPlane(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	cp := pePartitionedNode("cp1", "HostNetworkProblems", 20*time.Minute)
	cp.Labels = map[string]string{"node-role.kubernetes.io/control-plane": ""}
	objs := append([]runtime.Object{cp,
		pePod("flux-system", "cp1", "cp-pod")},
		peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "cp1").Spec.Taints, partitionTaintKey) {
		t.Fatal("control-plane node tainted")
	}
	if !testutil.PodExistsStrict(t, cs, "flux-system", "cp-pod") {
		t.Fatal("pod evicted off a control-plane node")
	}
}

// The mesh-wide guard's denominator counts only EVICTABLE nodes:
// on a 3CP+3worker cluster with all 3 workers partitioned,
// flagged*2 > workers (6>3) must abort — counting CPs (6>6) would
// proceed to taint+evict on a fully-partitioned workforce.
func TestPartitionEvictorMeshGuardIgnoresControlPlanes(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	var objs []runtime.Object
	for i := range 3 {
		cp := peHealthyNodes(fmt.Sprintf("cp%d", i+1), 1)[0].(*corev1.Node)
		cp.Labels = map[string]string{"node-role.kubernetes.io/control-plane": ""}
		objs = append(objs, cp)
	}
	for i := range 3 {
		objs = append(objs,
			pePartitionedNode(fmt.Sprintf("w%d", i+1), "HostNetworkProblems", 20*time.Minute),
			pePod("flux-system", fmt.Sprintf("w%d", i+1), fmt.Sprintf("pod-w%d", i+1)))
	}
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		name := fmt.Sprintf("w%d", i)
		if kube.HasTaint(testutil.GetNode(t, cs, name).Spec.Taints, partitionTaintKey) {
			t.Fatalf("worker %s tainted on a mesh-wide partition", name)
		}
		if !testutil.PodExistsStrict(t, cs, "flux-system", "pod-"+name) {
			t.Fatalf("pod evicted off %s on a mesh-wide partition", name)
		}
	}
}

// Eviction is node-scoped: an allow-listed (or annotated) pod sitting
// on a HEALTHY node is never touched — the spec.nodeName selector
// must hold even when the fake clientset would leak it.
func TestPartitionEvictorLeavesPodsOnHealthyNodes(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	optedIn := pePod("apps", "h-0", "healthy-node-pod")
	optedIn.Annotations = map[string]string{partitionEvictAnno: "true"}
	objs := append([]runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
		pePod("flux-system", "p1", "victim"),
		pePod("flux-system", "h-0", "healthy-listed"),
		optedIn,
	}, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	peEmulateEviction(cs)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if testutil.PodExistsStrict(t, cs, "flux-system", "victim") {
		t.Fatal("pod on partitioned node not evicted")
	}
	for _, p := range [][2]string{{"flux-system", "healthy-listed"}, {"apps", "healthy-node-pod"}} {
		if !testutil.PodExistsStrict(t, cs, p[0], p[1]) {
			t.Fatalf("pod %s/%s on a healthy node was evicted", p[0], p[1])
		}
	}
}

// clock-skew-precordon — NebulaPMTUBlackhole (the node-host-agent PMTU latch) flags
// the node for partition eviction exactly like NebulaIsolated.
func TestPartitionEvictorNebulaPMTUBlackhole(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	objs := append([]runtime.Object{
		pePartitionedNode("p1", "NebulaPMTUBlackhole", 20*time.Minute),
		pePod("flux-system", "p1", "victim"),
	}, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	peEmulateEviction(cs)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "p1").Spec.Taints, partitionTaintKey) {
		t.Fatal("PMTU-blackholed node not tainted")
	}
	if testutil.PodExistsStrict(t, cs, "flux-system", "victim") {
		t.Fatal("pod not evicted off a PMTU-blackholed node")
	}
}

// A NebulaIsolated latch whose heartbeat froze is a zombie — the
// wedged nodereporter cannot vouch for the partition anymore, so the
// node is neither tainted nor its pods evicted. The NWPD monitor
// spellings are not agent-managed: a frozen heartbeat on
// HostNetworkProblems still flags the node.
func TestPartitionEvictorZombieHeartbeatNotFlagged(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	stale := pePartitionedNode("p1", "NebulaIsolated", 20*time.Minute)
	for i := range stale.Status.Conditions {
		if stale.Status.Conditions[i].Type == "NebulaIsolated" {
			stale.Status.Conditions[i].LastHeartbeatTime =
				metav1.NewTime(time.Now().Add(-2 * partitionCondHeartbeatMaxAge))
		}
	}
	// Same fleet, NWPD spelling with NO heartbeat at all — still flags.
	nwpd := pePartitionedNode("p2", "HostNetworkProblems", 20*time.Minute)
	nwpd.Status.Conditions[1].LastHeartbeatTime = metav1.Time{}
	objs := append([]runtime.Object{
		stale, nwpd,
		pePod("flux-system", "p1", "zombie-victim"),
		pePod("flux-system", "p2", "nwpd-victim"),
	}, peHealthyNodes("h", 4)...) // 2/6 flagged < 50%
	cs := fake.NewSimpleClientset(objs...)
	peEmulateEviction(cs)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "p1").Spec.Taints, partitionTaintKey) {
		t.Fatal("zombie overlay latch tainted the node")
	}
	if !testutil.PodExistsStrict(t, cs, "flux-system", "zombie-victim") {
		t.Fatal("pod evicted on a zombie partition latch")
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "p2").Spec.Taints, partitionTaintKey) {
		t.Fatal("NWPD condition (not agent-managed) stopped flagging on a missing heartbeat")
	}
	if testutil.PodExistsStrict(t, cs, "flux-system", "nwpd-victim") {
		t.Fatal("pod not evicted off a NWPD-partitioned node")
	}
}
