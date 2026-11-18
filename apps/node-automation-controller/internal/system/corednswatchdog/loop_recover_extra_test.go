// loop_recover_extra_test.go — Wave-5B regressions for the plugin/loop
// delete storm: node-keyed cooldown, per-pass cap, L1 yield, 409 races,
// and the Previous-log container pin.
package corednswatchdog

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

func loopRecoveryFixture(now time.Time, replicas int, nodes ...*corev1.Node) (*fake.Clientset, *coreDNSWatchdog) {
	reps := int32(replicas)
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: corednsNS, Name: "coredns", Generation: 1},
		Spec:       appsv1.DeploymentSpec{Replicas: &reps},
		Status: appsv1.DeploymentStatus{
			ObservedGeneration: 1, UpdatedReplicas: reps, ReadyReplicas: 1, Replicas: reps,
		},
	}
	objs := []runtime.Object{deploy}
	for _, n := range nodes {
		objs = append(objs, n)
	}
	cs := fake.NewSimpleClientset(objs...)
	w := &coreDNSWatchdog{
		cs: cs, dyn: testutil.NewDynamicClient(),
		queue: "coredns-stale-watchdog",
		now:   func() time.Time { return now },
	}
	return cs, w
}

func loopPod(name, uid, node string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: corednsNS, Name: name, UID: types.UID(uid),
			Labels: map[string]string{"k8s-app": "kube-dns"},
		},
		Spec: corev1.PodSpec{NodeName: node},
	}
}

func readyLoopNode(name string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{
			Type: corev1.NodeReady, Status: corev1.ConditionTrue,
		}}},
	}
}

func podGone(t *testing.T, cs *fake.Clientset, name string) bool {
	_, err := cs.CoreV1().Pods(corednsNS).Get(context.Background(), name, metav1.GetOptions{})
	return apierrors.IsNotFound(err)
}

// The cooldown key is node-based, not UID-based: deleting a pod gives
// it a fresh UID, so the old key never matched its replacement and the
// watchdog re-killed a node's DNS pod every minute.
func TestLoopRecoveryCooldownKeyedByNodeNotUID(t *testing.T) {
	heal.ConfigureTargetBreaker(0, 0)
	t.Cleanup(func() { heal.ConfigureTargetBreaker(0, 0) })
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	cs, w := loopRecoveryFixture(now, 4, readyLoopNode("node-1"))
	p1, p2 := loopPod("p1", "uid-1", "node-1"), loopPod("p2", "uid-2", "node-1")
	_, _ = cs.CoreV1().Pods(corednsNS).Create(context.Background(), p1, metav1.CreateOptions{})
	_, _ = cs.CoreV1().Pods(corednsNS).Create(context.Background(), p2, metav1.CreateOptions{})
	uids := map[string]types.UID{"p1": p1.UID, "p2": p2.UID}
	nodes := map[string]string{"p1": "node-1", "p2": "node-1"}

	if err := w.recoverLoopCrashPods(context.Background(), []string{"p1", "p2"}, uids, nodes, 4); err != nil {
		t.Fatalf("recoverLoopCrashPods: %v", err)
	}
	if !podGone(t, cs, "p1") {
		t.Fatal("first loop pod on the node must be deleted")
	}
	if podGone(t, cs, "p2") {
		t.Fatal("second loop pod on the SAME node must be held by the node-keyed cooldown")
	}
	if !w.podHeals.CooledDown("loop-node/node-1", corednsCooldownS*time.Second, now) {
		t.Fatal("node-keyed cooldown was not stamped")
	}
}

// A single pass must never delete more than half the fleet.
func TestLoopRecoveryPerPassCap(t *testing.T) {
	heal.ConfigureTargetBreaker(0, 0)
	t.Cleanup(func() { heal.ConfigureTargetBreaker(0, 0) })
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	cs, w := loopRecoveryFixture(now, 4, readyLoopNode("node-1"))
	uids, nodes := map[string]types.UID{}, map[string]string{}
	var names []string
	// Distinct nodes so the node-keyed cooldown is not the limiter.
	for i, name := range []string{"p1", "p2", "p3", "p4"} {
		node := "node-" + name
		p := loopPod(name, "uid-"+name, node)
		_, _ = cs.CoreV1().Pods(corednsNS).Create(context.Background(), p, metav1.CreateOptions{})
		_, _ = cs.CoreV1().Nodes().Create(context.Background(), readyLoopNode(node), metav1.CreateOptions{})
		_ = i
		names = append(names, name)
		uids[name] = p.UID
		nodes[name] = node
	}
	if err := w.recoverLoopCrashPods(context.Background(), names, uids, nodes, 4); err != nil {
		t.Fatalf("recoverLoopCrashPods: %v", err)
	}
	deleted := 0
	for _, n := range names {
		if podGone(t, cs, n) {
			deleted++
		}
	}
	if deleted != 2 {
		t.Fatalf("deleted %d loop pods, want cap max(1, 4/2) = 2", deleted)
	}
}

func TestLoopRecoveryYieldsToL1Remediation(t *testing.T) {
	heal.ConfigureTargetBreaker(0, 0)
	t.Cleanup(func() { heal.ConfigureTargetBreaker(0, 0) })
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	node := readyLoopNode("node-1")
	node.Status.Conditions = append(node.Status.Conditions, corev1.NodeCondition{
		Type:              corev1.NodeConditionType(nodecond.CondLocalRemediation),
		Status:            corev1.ConditionTrue,
		LastHeartbeatTime: metav1.NewTime(now),
	})
	cs, w := loopRecoveryFixture(now, 4, node)
	p := loopPod("p1", "uid-1", "node-1")
	_, _ = cs.CoreV1().Pods(corednsNS).Create(context.Background(), p, metav1.CreateOptions{})
	err := w.recoverLoopCrashPods(context.Background(), []string{"p1"},
		map[string]types.UID{"p1": p.UID}, map[string]string{"p1": "node-1"}, 4)
	if err != nil {
		t.Fatalf("recoverLoopCrashPods: %v", err)
	}
	if podGone(t, cs, "p1") {
		t.Fatal("L1 LocalRemediationInProgress must defer the plugin/loop delete")
	}
}

func TestLoopRecoveryIgnoresConflict(t *testing.T) {
	heal.ConfigureTargetBreaker(0, 0)
	t.Cleanup(func() { heal.ConfigureTargetBreaker(0, 0) })
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	cs, w := loopRecoveryFixture(now, 4, readyLoopNode("node-1"))
	p1, p2 := loopPod("p1", "uid-1", "node-1"), loopPod("p2", "uid-2", "node-2")
	_, _ = cs.CoreV1().Pods(corednsNS).Create(context.Background(), p1, metav1.CreateOptions{})
	_, _ = cs.CoreV1().Pods(corednsNS).Create(context.Background(), p2, metav1.CreateOptions{})
	_, _ = cs.CoreV1().Nodes().Create(context.Background(), readyLoopNode("node-2"), metav1.CreateOptions{})
	conflicts := 0
	cs.PrependReactor("delete", "pods", func(a ktesting.Action) (bool, runtime.Object, error) {
		if a.(ktesting.DeleteAction).GetName() != "p1" {
			return false, nil, nil
		}
		conflicts++
		return true, nil, apierrors.NewConflict(
			schema.GroupResource{Resource: "pods"}, "p1", context.Canceled)
	})
	err := w.recoverLoopCrashPods(context.Background(), []string{"p1", "p2"},
		map[string]types.UID{"p1": p1.UID, "p2": p2.UID},
		map[string]string{"p1": "node-1", "p2": "node-2"}, 4)
	if err != nil {
		t.Fatalf("409 Conflict must be benign, got %v", err)
	}
	if conflicts != 1 || !podGone(t, cs, "p2") {
		t.Fatalf("conflicts=%d secondPodDeleted=%v — a 409 must not abort the batch",
			conflicts, podGone(t, cs, "p2"))
	}
}

// The Previous log must come from the coredns container, never from a
// sidecar chosen by ResolveDefaultContainer / default-container anno.
func TestPreviousLoopLogPinsCorednsContainer(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	cs := fake.NewSimpleClientset()
	var seen *corev1.PodLogOptions
	cs.PrependReactor("get", "pods", func(a ktesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() != "log" {
			return false, nil, nil
		}
		if ga, ok := a.(ktesting.GenericAction); ok {
			seen, _ = ga.GetValue().(*corev1.PodLogOptions)
		}
		return true, &runtime.Unknown{Raw: []byte("[FATAL] plugin/loop: Loop (127.0.0.1:53 -> :53) detected for zone \".\"\n")}, nil
	})
	w := &coreDNSWatchdog{cs: cs, now: func() time.Time { return now }}
	hit := w.previousLogLoopHit(context.Background(), &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: corednsNS, Name: "coredns-looping",
			Annotations: map[string]string{"kubectl.kubernetes.io/default-container": "sidecar"},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "sidecar"}, {Name: "coredns"}}},
	})
	if hit == "" {
		t.Fatal("expected the plugin/loop signature from the Previous log")
	}
	if seen == nil || !seen.Previous || seen.Container != "coredns" {
		t.Fatalf("Previous log options = %+v, want Previous=true Container=coredns", seen)
	}
}
