package partitionevictor

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// ---------------------------------------------------------------------------
// Builders (pe-prefixed to stay unique across sibling test files)
// ---------------------------------------------------------------------------

// pePartitionedNode builds a node whose given NWPD condition has been
// True for `age` (already exceeds partitionMinAge when age > 10m).
func pePartitionedNode(name string, condType corev1.NodeConditionType, age time.Duration, taints ...corev1.Taint) *corev1.Node {
	n := testutil.Node(name, corev1.ConditionTrue, nil, taints...)
	n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
		Type:               condType,
		Status:             corev1.ConditionTrue,
		LastTransitionTime: metav1.NewTime(time.Now().Add(-age)),
	})
	return n
}

func pePod(ns, nodeName, name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       corev1.PodSpec{NodeName: nodeName},
	}
}

// peHealthyNodes returns n plain Ready nodes named prefix-0..prefix-(n-1).
func peHealthyNodes(prefix string, n int) []runtime.Object {
	objs := make([]runtime.Object, 0, n)
	for i := 0; i < n; i++ {
		objs = append(objs, testutil.Node(fmt.Sprintf("%s-%d", prefix, i), corev1.ConditionTrue, nil))
	}
	return objs
}

func peCountTaintsWithKey(taints []corev1.Taint, key string) int {
	n := 0
	for _, t := range taints {
		if t.Key == key {
			n++
		}
	}
	return n
}

// pePodExists reports whether a pod still exists in the fake cluster.
func pePodExists(t *testing.T, cs *fake.Clientset, ns, name string) bool {
	t.Helper()
	_, err := cs.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		return true
	}
	if apierrors.IsNotFound(err) {
		return false
	}
	t.Fatalf("get pod %s/%s: %v", ns, name, err)
	return false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
	if !pePodExists(t, cs, "flux-system", "src-ctrl") {
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
	if !pePodExists(t, cs, "flux-system", "src-ctrl") {
		t.Fatal("pod evicted off a node that was never flagged")
	}
}

// The eviction cap bounds churn at partitionEvictCap (8) pods per run:
// with 9 flux-system pods on the flagged node exactly 8 are deleted.
func TestPartitionEvictorEvictionCap(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	objs := []runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
	}
	objs = append(objs, peHealthyNodes("h", 2)...)
	for i := 0; i < partitionEvictCap+1; i++ {
		objs = append(objs, pePod("flux-system", "p1", fmt.Sprintf("pod-%02d", i)))
	}
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "p1").Spec.Taints, partitionTaintKey) {
		t.Fatal("flagged node not tainted")
	}
	remaining, err := cs.CoreV1().Pods(partitionPodNS).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining.Items) != 1 {
		t.Fatalf("expected exactly 1 survivor after cap=%d, got %d: %v",
			partitionEvictCap, len(remaining.Items), remaining.Items)
	}
}

// Pods outside flux-system on a flagged node are never evicted, while
// the flux-system pod on the same node is.
func TestPartitionEvictorLeavesOtherNamespaces(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	objs := []runtime.Object{
		pePartitionedNode("p1", "ClusterNetworkProblems", 30*time.Minute),
		pePod("flux-system", "p1", "victim"),
		pePod("default", "p1", "unrelated"),
		pePod("monitoring", "p1", "prom-agent"),
	}
	objs = append(objs, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if pePodExists(t, cs, "flux-system", "victim") {
		t.Fatal("flux-system pod on flagged node not evicted")
	}
	for _, p := range [][2]string{{"default", "unrelated"}, {"monitoring", "prom-agent"}} {
		if !pePodExists(t, cs, p[0], p[1]) {
			t.Fatalf("pod %s/%s outside %s must not be evicted", p[0], p[1], partitionPodNS)
		}
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
		if pePodExists(t, cs, "flux-system", pod) {
			t.Fatalf("flux-system pod %s not evicted", pod)
		}
	}
}

// The eviction cap bounds pod churn, never fencing: when the first
// flagged node alone exhausts partitionEvictCap, every OTHER flagged
// node must still be tainted in the same run (previously a cap-break
// skipped their taint until the next cycle).
func TestPartitionEvictorTaintsAllFlaggedBeforeCap(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	objs := []runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
		pePartitionedNode("p2", "HostNetworkProblems", 20*time.Minute),
	}
	objs = append(objs, peHealthyNodes("h", 3)...) // 2/5 flagged < 50%
	for i := 0; i < partitionEvictCap+1; i++ {
		objs = append(objs, pePod("flux-system", "p1", fmt.Sprintf("pod-%02d", i)))
	}
	objs = append(objs, pePod("flux-system", "p2", "pod-p2"))
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"p1", "p2"} {
		if !kube.HasTaint(testutil.GetNode(t, cs, name).Spec.Taints, partitionTaintKey) {
			t.Fatalf("flagged node %s left untainted by the eviction cap", name)
		}
	}
	// The cap still held: p1's 9 pods shed exactly cap victims and
	// p2's pod never got a turn this run.
	if !pePodExists(t, cs, "flux-system", "pod-p2") {
		t.Fatal("cap broke — p2's pod was evicted")
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
	if !pePodExists(t, cs, "flux-system", "cp-pod") {
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
	for i := 0; i < 3; i++ {
		cp := peHealthyNodes(fmt.Sprintf("cp%d", i+1), 1)[0].(*corev1.Node)
		cp.Labels = map[string]string{"node-role.kubernetes.io/control-plane": ""}
		objs = append(objs, cp)
	}
	for i := 0; i < 3; i++ {
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
		if !pePodExists(t, cs, "flux-system", "pod-"+name) {
			t.Fatalf("pod evicted off %s on a mesh-wide partition", name)
		}
	}
}

// The pod delete carries a UID precondition — a same-named pod
// recreated after the list must never be killed in the victim's place.
func TestPartitionEvictorDeleteCarriesUIDPrecondition(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	victim := pePod("flux-system", "p1", "victim")
	victim.UID = "uid-victim-123"
	objs := append([]runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
		victim,
	}, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	var got *metav1.Preconditions
	cs.PrependReactor("delete", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			if da, ok := a.(ktesting.DeleteAction); ok {
				opts := da.GetDeleteOptions()
				got = opts.Preconditions
			}
			return false, nil, nil
		})
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got == nil || got.UID == nil || *got.UID != victim.UID {
		t.Fatalf("delete missing UID precondition, got %+v", got)
	}
}

// Untaint runs before the flagged path: a recovered node loses the
// partition taint while a still-flagged node keeps it (and is not
// tainted twice).
func TestPartitionEvictorUntaintsRecoveredKeepsFlaggedTaint(t *testing.T) {
	partitionTaint := corev1.Taint{
		Key:    partitionTaintKey,
		Value:  "true",
		Effect: corev1.TaintEffectNoSchedule,
	}
	recovered := testutil.Node("r1", corev1.ConditionTrue, nil, partitionTaint) // tainted, no condition
	flagged := pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute, partitionTaint)
	objs := append([]runtime.Object{recovered, flagged}, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "r1").Spec.Taints, partitionTaintKey) {
		t.Fatal("recovered node kept its partition taint")
	}
	taints := testutil.GetNode(t, cs, "p1").Spec.Taints
	if !kube.HasTaint(taints, partitionTaintKey) {
		t.Fatal("still-flagged node lost its partition taint")
	}
	if n := peCountTaintsWithKey(taints, partitionTaintKey); n != 1 {
		t.Fatalf("partition taint duplicated on flagged node: %d entries", n)
	}
}

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
	if !pePodExists(t, cs, "flux-system", "victim-p1") {
		t.Fatal("p1's pod vanished although its list failed")
	}
	if pePodExists(t, cs, "flux-system", "victim-p2") {
		t.Fatal("p2's pod not evicted — sibling node skipped after p1's error")
	}
	for _, name := range []string{"p1", "p2"} {
		if !kube.HasTaint(testutil.GetNode(t, cs, name).Spec.Taints, partitionTaintKey) {
			t.Fatalf("flagged node %s not tainted", name)
		}
	}
}

// A failed pod delete is tolerated (logged, counted) — the run must
// not error and the taint is still applied.
func TestPartitionEvictorPodDeleteErrorTolerated(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	objs := append([]runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
		pePod("flux-system", "p1", "undeletable"),
	}, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	cs.PrependReactor("delete", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("finalizer wedged")
		})
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatalf("a pod delete failure must not error the run: %v", err)
	}
	if !pePodExists(t, cs, "flux-system", "undeletable") {
		t.Fatal("pod deleted despite the failing delete call")
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "p1").Spec.Taints, partitionTaintKey) {
		t.Fatal("flagged node not tainted")
	}
}

// A failed recovery-untaint is logged and the sweep continues —
// per-node errors are never fatal (same as bash).
func TestPartitionEvictorUntaintErrorTolerated(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("h1", corev1.ConditionTrue, nil,
			corev1.Taint{Key: partitionTaintKey, Value: "true",
				Effect: corev1.TaintEffectNoSchedule}))
	cs.PrependReactor("patch", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatalf("untaint failure must not fail the run: %v", err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "h1").Spec.Taints, partitionTaintKey) {
		t.Fatal("taint removed despite the rejected patch")
	}
}

// A failed partition taint is logged ("taint failed") and the node
// still gets its pod sweep — the pod list afterwards must not be
// skipped by the taint error.
func TestPartitionEvictorTaintErrorStillSweepsPods(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	objs := append(
		[]runtime.Object{
			pePartitionedNode("p1", "ClusterNetworkProblems", 20*time.Minute),
			pePod("flux-system", "p1", "src-ctrl"),
		},
		peHealthyNodes("h", 3)...)
	cs := fake.NewSimpleClientset(objs...)
	cs.PrependReactor("patch", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatalf("taint failure must not fail the run: %v", err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "p1").Spec.Taints, partitionTaintKey) {
		t.Fatal("taint applied despite the rejected patch")
	}
	if pePodExists(t, cs, "flux-system", "src-ctrl") {
		t.Fatal("pod on partitioned node not evicted after the taint failure")
	}
}

// ---------------------------------------------------------------------------
// QW3 — PARTITION_EVICT_NAMESPACES allow-list + opt-in annotation.
// ---------------------------------------------------------------------------

// partitionEvictNamespaces: unset and whitespace-only values keep the
// bash default (flux-system); a real value REPLACES it — the flag is
// an allow-list, not an append-list.
func TestPartitionEvictNamespacesParsing(t *testing.T) {
	// Unset: save + clear the ambient value so the default branch is
	// deterministic regardless of the shell the test runs under.
	if old, had := os.LookupEnv(partitionNSsEnv); had {
		t.Cleanup(func() { _ = os.Setenv(partitionNSsEnv, old) })
	}
	if err := os.Unsetenv(partitionNSsEnv); err != nil {
		t.Fatal(err)
	}
	got := partitionEvictNamespaces()
	if len(got) != 1 || !nsSetHas(got, partitionPodNS) {
		t.Fatalf("unset env produced %v, want {%s}", got, partitionPodNS)
	}

	// Whitespace-only is the same as unset — a ConfigMap value of
	// " " must not become a namespace named " ".
	t.Setenv(partitionNSsEnv, "   ")
	got = partitionEvictNamespaces()
	if len(got) != 1 || !nsSetHas(got, partitionPodNS) {
		t.Fatalf("whitespace env produced %v, want {%s}", got, partitionPodNS)
	}

	// Comma-separated with stray whitespace and empty entries —
	// "a, ,b," must parse to exactly {a, b} (no phantom namespace).
	t.Setenv(partitionNSsEnv, " apps , ,monitoring,")
	got = partitionEvictNamespaces()
	if len(got) != 2 || !nsSetHas(got, "apps") || !nsSetHas(got, "monitoring") {
		t.Fatalf("env ' apps , ,monitoring,' produced %v, want {apps monitoring}", got)
	}
	if nsSetHas(got, partitionPodNS) {
		t.Fatal("explicit allow-list must replace the flux-system default")
	}
}

func nsSetHas(set map[string]struct{}, ns string) bool {
	_, ok := set[ns]
	return ok
}

// A pod carrying node.ops/evict-on-partition=true in an UNLISTED
// namespace is evicted off the flagged node; an identical unannotated
// pod in the same namespace is left alone.
func TestPartitionEvictorAnnotatedPodInUnlistedNamespace(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	optedIn := pePod("apps", "p1", "webhook-svc")
	optedIn.Annotations = map[string]string{partitionEvictAnno: "true"}
	objs := append([]runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
		optedIn,
		pePod("apps", "p1", "unannotated"),
		pePod("flux-system", "p1", "listed-victim"),
	}, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if pePodExists(t, cs, "apps", "webhook-svc") {
		t.Fatal("annotated pod in unlisted namespace not evicted")
	}
	if pePodExists(t, cs, "flux-system", "listed-victim") {
		t.Fatal("listed-namespace pod not evicted")
	}
	if !pePodExists(t, cs, "apps", "unannotated") {
		t.Fatal("unannotated pod in unlisted namespace evicted — annotation leaked")
	}
}

// The annotation opts IN the pod, it never overrides the safety
// classes: terminal pods, DaemonSet pods and static mirror pods are
// skipped even when annotated.
func TestPartitionEvictorAnnotationSkipsProtectedPods(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	anno := map[string]string{partitionEvictAnno: "true"}

	terminal := pePod("flux-system", "p1", "done-job")
	terminal.Status.Phase = corev1.PodSucceeded
	terminal.Annotations = anno

	failed := pePod("flux-system", "p1", "crashed")
	failed.Status.Phase = corev1.PodFailed
	failed.Annotations = anno

	ds := pePod("flux-system", "p1", "daemon-xyz")
	ds.Annotations = anno
	ds.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "apps/v1", Kind: "DaemonSet", Name: "daemon", UID: "u1",
	}}

	mirror := pePod("flux-system", "p1", "static-etcd")
	mirror.Annotations = map[string]string{
		partitionEvictAnno: "true",
		mirrorPodAnno:      "0123456789abcdef",
	}

	objs := append([]runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
		terminal, failed, ds, mirror,
	}, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"done-job", "crashed", "daemon-xyz", "static-etcd"} {
		if !pePodExists(t, cs, "flux-system", name) {
			t.Fatalf("protected pod flux-system/%s was evicted", name)
		}
	}
}

// The cap is global per run — annotated pods from other namespaces
// share the same budget as allow-listed pods: 5 listed + 5 annotated
// must still stop at partitionEvictCap deletions.
func TestPartitionEvictorCapCoversAnnotatedPods(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	objs := []runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
	}
	objs = append(objs, peHealthyNodes("h", 2)...)
	for i := 0; i < 5; i++ {
		objs = append(objs, pePod("flux-system", "p1", fmt.Sprintf("listed-%02d", i)))
	}
	for i := 0; i < 5; i++ {
		p := pePod("apps", "p1", fmt.Sprintf("opted-%02d", i))
		p.Annotations = map[string]string{partitionEvictAnno: "true"}
		objs = append(objs, p)
	}
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	remaining := 0
	for _, ns := range []string{"flux-system", "apps"} {
		l, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		remaining += len(l.Items)
	}
	if want := 10 - partitionEvictCap; remaining != want {
		t.Fatalf("cap not respected across membership classes: %d pods left, want %d", remaining, want)
	}
}

// An explicit allow-list REPLACES the flux-system default — with
// PARTITION_EVICT_NAMESPACES=monitoring a flux-system pod is left
// alone while the monitoring pod is evicted.
func TestPartitionEvictorEnvAllowListReplacesDefault(t *testing.T) {
	t.Setenv(partitionNSsEnv, "monitoring, logging")
	objs := append([]runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
		pePod("flux-system", "p1", "no-longer-listed"),
		pePod("monitoring", "p1", "prom-victim"),
		pePod("logging", "p1", "fluent-victim"),
		pePod("default", "p1", "still-unlisted"),
	}, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, p := range [][2]string{{"monitoring", "prom-victim"}, {"logging", "fluent-victim"}} {
		if pePodExists(t, cs, p[0], p[1]) {
			t.Fatalf("listed-namespace pod %s/%s not evicted", p[0], p[1])
		}
	}
	for _, p := range [][2]string{{"flux-system", "no-longer-listed"}, {"default", "still-unlisted"}} {
		if !pePodExists(t, cs, p[0], p[1]) {
			t.Fatalf("unlisted-namespace pod %s/%s evicted", p[0], p[1])
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
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if pePodExists(t, cs, "flux-system", "victim") {
		t.Fatal("pod on partitioned node not evicted")
	}
	for _, p := range [][2]string{{"flux-system", "healthy-listed"}, {"apps", "healthy-node-pod"}} {
		if !pePodExists(t, cs, p[0], p[1]) {
			t.Fatalf("pod %s/%s on a healthy node was evicted", p[0], p[1])
		}
	}
}

// ---------------------------------------------------------------------------
// W10-FIX5 — node-pinned volumes are never evicted.
// ---------------------------------------------------------------------------

// pePVC builds a PVC bound to a storage class; sc "" leaves
// spec.storageClassName unset.
func pePVC(ns, name, sc string) *corev1.PersistentVolumeClaim {
	p := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
	}
	if sc != "" {
		p.Spec.StorageClassName = &sc
	}
	return p
}

// pePodWithPVC is pePod plus a volume mounting the named PVC.
func pePodWithPVC(ns, nodeName, name, pvc string) *corev1.Pod {
	p := pePod(ns, nodeName, name)
	p.Spec.Volumes = []corev1.Volume{{
		Name: "data",
		VolumeSource: corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: pvc,
			},
		},
	}}
	return p
}

// Pods on node-pinned volumes (local-path AND openebs-hostpath) are
// skipped: their PVs carry node affinity, so the replacement would
// land on the same broken node — pure churn. A pod on a cluster
// SC (or a PVC in another namespace) still evicts.
func TestPartitionEvictorSkipsNodePinnedPVC(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	objs := []runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
		pePVC("flux-system", "data-local", "local-path"),
		pePVC("flux-system", "data-openebs", "openebs-hostpath"),
		pePVC("flux-system", "data-csi", "longhorn"),
		pePodWithPVC("flux-system", "p1", "local-pod", "data-local"),
		pePodWithPVC("flux-system", "p1", "openebs-pod", "data-openebs"),
		pePodWithPVC("flux-system", "p1", "csi-pod", "data-csi"),
		// Same claim name in another namespace must not match — the
		// pinned set is keyed ns/name.
		pePodWithPVC("default", "p1", "foreign-pod", "data-local"),
	}
	objs = append(objs, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"local-pod", "openebs-pod"} {
		if !pePodExists(t, cs, "flux-system", name) {
			t.Fatalf("node-pinned pod %s evicted — replacement cannot leave the node", name)
		}
	}
	if pePodExists(t, cs, "flux-system", "csi-pod") {
		t.Fatal("cluster-SC pod not evicted")
	}
	// "default" is not in the allow-list and the pod is unannotated —
	// it survives on membership grounds, not the PVC check.
	if !pePodExists(t, cs, "default", "foreign-pod") {
		t.Fatal("unlisted-namespace pod evicted")
	}
}

// An annotated opt-in pod on a node-pinned volume is skipped too —
// the annotation opts into eviction, it cannot move a volume that is
// physically bound to the node.
func TestPartitionEvictorPinnedPVCBeatsAnnotation(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	p := pePodWithPVC("apps", "p1", "pinned-opted", "data-openebs")
	p.Annotations = map[string]string{partitionEvictAnno: "true"}
	objs := append([]runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
		pePVC("apps", "data-openebs", "openebs-hostpath"),
		p,
	}, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !pePodExists(t, cs, "apps", "pinned-opted") {
		t.Fatal("annotated node-pinned pod evicted — volume is bound to the node")
	}
}

// A PVC list failure fails the eviction pass closed: taints still
// land (they fence scheduling) but no pod is deleted on an
// unverifiable volume view.
func TestPartitionEvictorPVCListErrorSkipsEviction(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	objs := append([]runtime.Object{
		pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute),
		pePod("flux-system", "p1", "victim"),
	}, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	cs.PrependReactor("list", "persistentvolumeclaims",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("pvc api down")
		})
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatalf("pvc list failure must not error the run: %v", err)
	}
	if !pePodExists(t, cs, "flux-system", "victim") {
		t.Fatal("pod evicted although the pinned-PVC view was unverifiable")
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "p1").Spec.Taints, partitionTaintKey) {
		t.Fatal("flagged node not tainted")
	}
}

// W9-CP3 — NebulaPMTUBlackhole (the node-host-agent PMTU latch) flags
// the node for partition eviction exactly like NebulaIsolated.
func TestPartitionEvictorNebulaPMTUBlackhole(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	objs := append([]runtime.Object{
		pePartitionedNode("p1", "NebulaPMTUBlackhole", 20*time.Minute),
		pePod("flux-system", "p1", "victim"),
	}, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "p1").Spec.Taints, partitionTaintKey) {
		t.Fatal("PMTU-blackholed node not tainted")
	}
	if pePodExists(t, cs, "flux-system", "victim") {
		t.Fatal("pod not evicted off a PMTU-blackholed node")
	}
}
