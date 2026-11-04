package shared

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
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

// reconcileErrorCount reads the native error counter for module `name`
// off the controller-runtime registry (the one metrics.init registers
// into) — end-to-end proof the periodic loop calls IncError. Kept
// local (not testutil) because shared must stay a leaf: testutil
// already imports shared.
func reconcileErrorCount(t *testing.T, name string) float64 {
	t.Helper()
	mfs, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather registry: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "node_automation_reconcile_errors_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "controller" && lp.GetValue() == name {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
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
