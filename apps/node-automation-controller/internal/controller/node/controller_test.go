package node

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/controller/shared"
)

// ---------------------------------------------------------------------------
// descheduler-storm-gate
// ---------------------------------------------------------------------------

func TestStormGateScalesDownAndBack(t *testing.T) {
	cs := fake.NewSimpleClientset(
		node("n1", corev1.ConditionTrue, nil),
		node("n2", corev1.ConditionFalse, nil), // storm
		deschedulerDeploy(1, nil))
	r := &deschedulerStormGate{cs: cs}

	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 0 {
		t.Fatalf("expected scale to 0 during storm, got %d", got)
	}
	d, _ := cs.AppsV1().Deployments("kube-system").
		Get(ctx, "descheduler", metav1.GetOptions{})
	if d.Annotations[stormGateDecisionAnno] == "" {
		t.Fatal("decision annotation not recorded")
	}

	// Node recovers -> scale back to 1.
	n2, _ := cs.CoreV1().Nodes().Get(ctx, "n2", metav1.GetOptions{})
	n2.Status.Conditions[0].Status = corev1.ConditionTrue
	if _, err := cs.CoreV1().Nodes().UpdateStatus(ctx, n2, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 1 {
		t.Fatalf("expected scale back to 1 when clear, got %d", got)
	}
}

func TestStormGateHold(t *testing.T) {
	cs := fake.NewSimpleClientset(
		node("n1", corev1.ConditionFalse, nil),
		deschedulerDeploy(1, map[string]string{stormGateHoldAnno: "true"}))
	r := &deschedulerStormGate{cs: cs}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 1 {
		t.Fatalf("hold must skip scaling, replicas=%d", got)
	}
}

// ---------------------------------------------------------------------------
// cilium-taint-reaper
// ---------------------------------------------------------------------------

func TestCiliumTaintReaper(t *testing.T) {
	stale := corev1.Taint{Key: "node.cilium.io/agent-not-ready", Effect: corev1.TaintEffectNoSchedule}

	// Disabled: never touches taints.
	cs := fake.NewSimpleClientset(node("n1", corev1.ConditionTrue, nil, stale))
	r := &ciliumTaintReaper{cs: cs, enabled: false}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if !shared.HasTaint(getNode(t, cs, "n1").Spec.Taints, stale.Key) {
		t.Fatal("disabled reaper removed taint")
	}

	// Enabled + healthy agent -> taint reaped.
	cs = fake.NewSimpleClientset(
		node("n1", corev1.ConditionTrue, nil, stale),
		ciliumPod("n1", corev1.PodRunning, true))
	r = &ciliumTaintReaper{cs: cs, enabled: true}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if shared.HasTaint(getNode(t, cs, "n1").Spec.Taints, stale.Key) {
		t.Fatal("stale taint not reaped with healthy agent")
	}

	// Enabled + agent not ready -> taint kept.
	cs = fake.NewSimpleClientset(
		node("n1", corev1.ConditionTrue, nil, stale),
		ciliumPod("n1", corev1.PodPending, false))
	r = &ciliumTaintReaper{cs: cs, enabled: true}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if !shared.HasTaint(getNode(t, cs, "n1").Spec.Taints, stale.Key) {
		t.Fatal("taint removed while agent still not ready")
	}
}

// ---------------------------------------------------------------------------
// node-labeler
// ---------------------------------------------------------------------------

func TestNodeLabeler(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "labels.txt")
	if err := os.WriteFile(cfg,
		[]byte("# comment\n\npassiontech.dev/workload=app w1 w2 gone-node\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cs := fake.NewSimpleClientset(
		node("cp1", corev1.ConditionTrue,
			map[string]string{"node-role.kubernetes.io/control-plane": ""}),
		node("w1", corev1.ConditionTrue, nil),
		node("w2", corev1.ConditionTrue,
			map[string]string{"node-role.kubernetes.io/worker": ""}),
	)
	r := &nodeLabeler{cs: cs, configPath: cfg}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}

	if _, ok := getNode(t, cs, "cp1").Labels["node-role.kubernetes.io/worker"]; ok {
		t.Fatal("control-plane got a worker label")
	}
	if _, ok := getNode(t, cs, "w1").Labels["node-role.kubernetes.io/worker"]; !ok {
		t.Fatal("worker role label not asserted")
	}
	if got := getNode(t, cs, "w1").Labels["passiontech.dev/workload"]; got != "app" {
		t.Fatalf("labels.txt entry not applied, got %q", got)
	}
	if got := getNode(t, cs, "w2").Labels["passiontech.dev/workload"]; got != "app" {
		t.Fatalf("labels.txt entry not applied on w2, got %q", got)
	}
	// gone-node does not exist -> warn+continue, no error.
}

// ---------------------------------------------------------------------------
// partition-pod-evictor
// ---------------------------------------------------------------------------

func TestPartitionEvictor(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	old := metav1.NewTime(time.Now().Add(-20 * time.Minute))
	partitioned := node("p1", corev1.ConditionTrue, nil)
	partitioned.Status.Conditions = append(partitioned.Status.Conditions,
		corev1.NodeCondition{
			Type:               "HostNetworkProblems",
			Status:             corev1.ConditionTrue,
			LastTransitionTime: old,
		})
	healthy := node("h1", corev1.ConditionTrue, nil)
	others := []*corev1.Node{
		node("h2", corev1.ConditionTrue, nil),
		node("h3", corev1.ConditionTrue, nil),
	}
	podOnP1 := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "src-ctrl", Namespace: "flux-system"},
		Spec: corev1.PodSpec{NodeName: "p1"}}

	objs := []runtime.Object{partitioned, healthy, podOnP1}
	for _, n := range others {
		objs = append(objs, n)
	}
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}

	if !shared.HasTaint(getNode(t, cs, "p1").Spec.Taints, "node.ops/network-partitioned") {
		t.Fatal("partitioned node not tainted")
	}
	_, err := cs.CoreV1().Pods("flux-system").Get(ctx, "src-ctrl", metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		t.Fatal("flux-system pod not evicted off partitioned node")
	}

	// Recovery: condition cleared -> taint removed on next sweep.
	p1 := getNode(t, cs, "p1")
	p1.Status.Conditions[1].Status = corev1.ConditionFalse
	if _, err := cs.CoreV1().Nodes().UpdateStatus(ctx, p1, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if shared.HasTaint(getNode(t, cs, "p1").Spec.Taints, "node.ops/network-partitioned") {
		t.Fatal("taint not removed after recovery")
	}
}

func TestPartitionEvictorAbortsOnMajorityPartition(t *testing.T) {
	old := metav1.NewTime(time.Now().Add(-20 * time.Minute))
	var objs []runtime.Object
	for _, name := range []string{"a", "b"} {
		n := node(name, corev1.ConditionTrue, nil)
		n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
			Type:               "ClusterNetworkProblems",
			Status:             corev1.ConditionTrue,
			LastTransitionTime: old,
		})
		objs = append(objs, n)
	}
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b"} {
		if shared.HasTaint(getNode(t, cs, name).Spec.Taints, "node.ops/network-partitioned") {
			t.Fatalf("node %s tainted during a majority partition — guard failed", name)
		}
	}
}
