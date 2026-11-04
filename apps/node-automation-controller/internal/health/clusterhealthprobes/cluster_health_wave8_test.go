// cluster_health_wave8_test.go — coverage for the Wave-8 checks in
// cluster_health_wave8.go (and the W4 db-operator masterless heal).
package clusterhealthprobes

import (
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

// w8Worker builds a Ready, schedulable worker node with optional
// extra conditions (FilesystemReadOnly/KernelHungTasks latched `age`
// ago for the hang check).
func w8Worker(name string, cond corev1.NodeConditionType, condAge time.Duration, unschedulable bool) *corev1.Node {
	n := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.NodeSpec{Unschedulable: unschedulable},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{
			{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}},
	}
	if cond != "" {
		n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
			Type:               cond,
			Status:             corev1.ConditionTrue,
			LastTransitionTime: metav1.NewTime(time.Now().Add(-condAge)),
		})
	}
	return n
}

// w8PendingPod builds a Pending pod that was never assigned — no
// nodeName, and when scheduled=false no PodScheduled condition at
// all (the scheduler-freeze signature).
func w8PendingPod(ns, name string, age time.Duration, scheduled bool) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
		},
		Status: corev1.PodStatus{Phase: corev1.PodPending},
	}
	if scheduled {
		p.Status.Conditions = []corev1.PodCondition{{
			Type:   corev1.PodScheduled,
			Status: corev1.ConditionFalse}}
	}
	return p
}

// W8-CP3 — a pod Pending >5m with no PodScheduled condition while
// Ready workers exist fails the check and raises the frozen gauge;
// a healthy shape passes and clears it.
func TestCheckSchedulerFrozen(t *testing.T) {
	cs := fake.NewSimpleClientset(
		w8Worker("w1", "", 0, false),
		w8PendingPod("apps", "stuck-1", 10*time.Minute, false))
	p := testProberDyn(cs, shOpDyn())
	if res := p.checkSchedulerFrozen(ctx); res.pass {
		t.Fatal("frozen scheduler shape passed")
	}
	m := findMetric(t, "node_automation_scheduler_frozen", map[string]string{})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("scheduler_frozen=%v, want 1", m)
	}
}

func TestCheckSchedulerFrozenHealthy(t *testing.T) {
	cs := fake.NewSimpleClientset(
		w8Worker("w1", "", 0, false),
		w8PendingPod("apps", "verdict", 10*time.Minute, true))
	p := testProberDyn(cs, shOpDyn())
	if res := p.checkSchedulerFrozen(ctx); !res.pass {
		t.Fatalf("PodScheduled=False verdict pod misread as frozen: %+v", res)
	}
}

// W8-ST2 — a hung worker gets spec.unschedulable patched; an already-
// cordoned worker is left alone.
func TestCheckNodeHangPreCordon(t *testing.T) {
	cs := fake.NewSimpleClientset(
		w8Worker("w-hang", "KernelHungTasks", 5*time.Minute, false),
		w8Worker("w-ok", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := p.checkNodeHangPreCordon(ctx); res.pass {
		t.Fatal("hung node did not fail the check")
	}
	n, err := cs.CoreV1().Nodes().Get(ctx, "w-hang", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !n.Spec.Unschedulable {
		t.Fatal("hung node not cordoned")
	}
	n2, err := cs.CoreV1().Nodes().Get(ctx, "w-ok", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if n2.Spec.Unschedulable {
		t.Fatal("healthy node cordoned")
	}
}

// W8-ST2 — a latch that is too fresh does not trigger the cordon.
func TestCheckNodeHangPreCordonTooFresh(t *testing.T) {
	cs := fake.NewSimpleClientset(
		w8Worker("w1", "FilesystemReadOnly", time.Minute, false),
		w8Worker("w2", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := p.checkNodeHangPreCordon(ctx); !res.pass {
		t.Fatalf("fresh latch failed the check: %+v", res)
	}
	n, _ := cs.CoreV1().Nodes().Get(ctx, "w1", metav1.GetOptions{})
	if n.Spec.Unschedulable {
		t.Fatal("fresh-latch node cordoned too early")
	}
}

// W8-NM3 — a wedged linkerd pod (started, never Ready, >5m) is
// deleted to force a re-roll, matching Deployment-suffixed pod names.
func TestCheckMeshLinkerdWedgedHeals(t *testing.T) {
	started := true
	podName := linkerdDestinationName + "-7f8b9c6d4-abcde"
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: linkerdNS, Name: podName,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
			UID:               types.UID("u-dest"),
			Labels: map[string]string{
				"linkerd.io/control-plane-component": "destination",
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "destination", Started: &started, Ready: false}},
		},
	}
	cs := fake.NewSimpleClientset(w8Worker("w1", "", 0, false), pod)
	p := testProberDyn(cs, shOpDyn())
	if res := p.checkMeshControlPlane(ctx); res.pass {
		t.Fatal("wedged linkerd pod passed")
	}
	if _, err := cs.CoreV1().Pods(linkerdNS).
		Get(ctx, podName, metav1.GetOptions{}); err == nil {
		t.Fatal("wedged linkerd pod not deleted")
	}
}

// W4 — dbOperatorFor matches a pod-template label carrying the
// operator name; a generic STS matches nothing.
func TestDBOperatorFor(t *testing.T) {
	sts := &appsv1.StatefulSet{
		Spec: appsv1.StatefulSetSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app.kubernetes.io/managed-by": "pxc-operator"}}}},
	}
	if got := dbOperatorFor(sts); got != "pxc-operator" {
		t.Fatalf("dbOperatorFor=%q, want pxc-operator", got)
	}
	if got := dbOperatorFor(&appsv1.StatefulSet{}); got != "" {
		t.Fatalf("dbOperatorFor=%q, want empty", got)
	}
}

// findMetric/healthGauge/testProberDyn live in
// cluster_health_probes_test.go — same package.
