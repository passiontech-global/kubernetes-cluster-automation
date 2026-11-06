package kube

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

var ctx = context.Background()

func node(name string, ready corev1.ConditionStatus, labels map[string]string, taints ...corev1.Taint) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		Spec:       corev1.NodeSpec{Taints: taints},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{
			Type:   corev1.NodeReady,
			Status: ready,
		}}},
	}
}

func getNode(t *testing.T, cs *fake.Clientset, name string) *corev1.Node {
	t.Helper()
	n, err := cs.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get node %s: %v", name, err)
	}
	return n
}

func settledDaemonSet() *appsv1.DaemonSet {
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Generation: 3},
		Status: appsv1.DaemonSetStatus{
			ObservedGeneration:     3,
			DesiredNumberScheduled: 4,
			UpdatedNumberScheduled: 4,
			NumberReady:            4,
		},
	}
}

// BUG-C4 — NodeActivelyCordoned: only a FRESH cordon counts as an
// active drain; a statically-cordoned node (>45m) does not.
func TestNodeActivelyCordoned(t *testing.T) {
	now := time.Now()
	fresh := metav1.NewTime(now.Add(-10 * time.Minute))
	old := metav1.NewTime(now.Add(-time.Hour))
	for _, tc := range []struct {
		name          string
		unschedulable bool
		taints        []corev1.Taint
		want          bool
	}{
		{"schedulable", false, nil, false},
		{"cordoned no taint (unverifiable)", true, nil, true},
		{"cordoned nil TimeAdded", true,
			[]corev1.Taint{{Key: UnschedulableTaintKey}}, true},
		{"cordoned 10m ago", true,
			[]corev1.Taint{{Key: UnschedulableTaintKey, TimeAdded: &fresh}}, true},
		{"static cordon 60m ago", true,
			[]corev1.Taint{{Key: UnschedulableTaintKey, TimeAdded: &old}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := &corev1.Node{Spec: corev1.NodeSpec{
				Unschedulable: tc.unschedulable, Taints: tc.taints}}
			if got := NodeActivelyCordoned(n, now); got != tc.want {
				t.Fatalf("NodeActivelyCordoned=%v, want %v", got, tc.want)
			}
		})
	}
}

// W12 P0-1 — a node pre-cordoned by node-hang-precordon
// (AnnoPreCordonedBy) is the controller's own defensive quarantine
// of a sick worker, not an operator drain: its fresh unschedulable
// taint must NOT trip the active-cordon verdict or the maintenance
// mutex would lock every heal cluster-wide for 45m.
func TestNodeActivelyCordonedPreCordonExempt(t *testing.T) {
	now := time.Now()
	fresh := metav1.NewTime(now.Add(-time.Minute))
	for _, tc := range []struct {
		name  string
		annos map[string]string
		want  bool
	}{
		{"precordoned by node-hang-precordon",
			map[string]string{AnnoPreCordonedBy: "node-hang-precordon"}, false},
		{"precordoned by anything counts as exempt",
			map[string]string{AnnoPreCordonedBy: "other-controller"}, false},
		{"empty precordon anno is an operator cordon",
			map[string]string{AnnoPreCordonedBy: ""}, true},
		{"no precordon anno is an operator cordon", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Annotations: tc.annos},
				Spec: corev1.NodeSpec{
					Unschedulable: true,
					Taints: []corev1.Taint{
						{Key: UnschedulableTaintKey, TimeAdded: &fresh}}},
			}
			if got := NodeActivelyCordoned(n, now); got != tc.want {
				t.Fatalf("NodeActivelyCordoned=%v, want %v", got, tc.want)
			}
		})
	}
}
