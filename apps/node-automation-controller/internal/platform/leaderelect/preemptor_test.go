// preemptor_test.go — the dead-leader lease preemptor's contract:
// preempt ONLY on provably-dead holders (pod gone/terminating,
// node NotReady or unreachable-tainted) with a stale renewTime;
// preserve the 180s tolerance for a live leader; stay idempotent
// once the Lease is already shortened.
package leaderelect

import (
	"context"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

var testNow = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

func staleLease() *coordinationv1.Lease {
	renew := metav1.NewMicroTime(testNow.Add(-time.Minute))
	holder := "node-automation-controller-abc12_0123-uuid"
	dur := int32(180)
	return &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: DefaultNamespace, Name: DefaultLeaseName},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity:       &holder,
			LeaseDurationSeconds: &dur,
			RenewTime:            &renew,
		},
	}
}

func TestSweepLeaseMissing(t *testing.T) {
	p := &Preemptor{CS: fake.NewSimpleClientset(),
		Now: timex.NewClock(func() time.Time { return testNow })}
	reason, err := p.Sweep(context.Background())
	if err != nil || reason != "" {
		t.Fatalf("missing lease: reason=%q err=%v, want no-op", reason, err)
	}
}

func TestSweepFreshRenewNoPreempt(t *testing.T) {
	lease := staleLease()
	fresh := metav1.NewMicroTime(testNow.Add(-5 * time.Second))
	lease.Spec.RenewTime = &fresh
	p := &Preemptor{CS: fake.NewSimpleClientset(lease),
		Now: timex.NewClock(func() time.Time { return testNow })}
	reason, err := p.Sweep(context.Background())
	if err != nil || reason != "" {
		t.Fatalf("fresh renew: reason=%q err=%v, want no-op", reason, err)
	}
}

func TestSweepDeadHolderReasons(t *testing.T) {
	pod := func(nodeName string, deleting bool) *corev1.Pod {
		p := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: DefaultNamespace, Name: "node-automation-controller-abc12"},
			Spec: corev1.PodSpec{NodeName: nodeName},
		}
		if deleting {
			now := metav1.NewTime(testNow)
			p.DeletionTimestamp = &now
		}
		return p
	}
	readyNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{
			Type: corev1.NodeReady, Status: corev1.ConditionTrue}}},
	}
	notReadyNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-b"},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{
			Type: corev1.NodeReady, Status: corev1.ConditionFalse}}},
	}
	taintedNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-c"},
		Spec: corev1.NodeSpec{Taints: []corev1.Taint{{
			Key:    "node.kubernetes.io/unreachable",
			Effect: corev1.TaintEffectNoSchedule}}},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{
			Type: corev1.NodeReady, Status: corev1.ConditionTrue}}},
	}

	cases := []struct {
		name string
		objs []runtime.Object
		want string
	}{
		{"pod missing", []runtime.Object{staleLease()}, ReasonPodMissing},
		{"pod terminating", []runtime.Object{
			staleLease(), pod("node-a", true)}, ReasonPodTerminating},
		{"node not ready", []runtime.Object{
			staleLease(), pod("node-b", false), notReadyNode}, ReasonNodeNotReady},
		{"node unreachable taint", []runtime.Object{
			staleLease(), pod("node-c", false), taintedNode}, ReasonNodeUnreachable},
		{"live leader untouched", []runtime.Object{
			staleLease(), pod("node-a", false), readyNode}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Preemptor{CS: fake.NewSimpleClientset(tc.objs...),
				Now: timex.NewClock(func() time.Time { return testNow })}
			reason, err := p.Sweep(context.Background())
			if err != nil {
				t.Fatalf("sweep: %v", err)
			}
			if reason != tc.want {
				t.Fatalf("reason=%q want %q", reason, tc.want)
			}
			lease, _ := p.CS.CoordinationV1().Leases(DefaultNamespace).
				Get(context.Background(), DefaultLeaseName, metav1.GetOptions{})
			if tc.want == "" {
				if *lease.Spec.LeaseDurationSeconds != 180 {
					t.Fatalf("live leader lease mutated: %v",
						*lease.Spec.LeaseDurationSeconds)
				}
			} else if *lease.Spec.LeaseDurationSeconds != PreemptLeaseDurationSeconds {
				t.Fatalf("leaseDuration=%v want %d",
					*lease.Spec.LeaseDurationSeconds, PreemptLeaseDurationSeconds)
			}
		})
	}
}

func TestSweepIdempotentAfterPreempt(t *testing.T) {
	lease := staleLease()
	dur := int32(1)
	lease.Spec.LeaseDurationSeconds = &dur
	p := &Preemptor{CS: fake.NewSimpleClientset(lease),
		Now: timex.NewClock(func() time.Time { return testNow })}
	reason, err := p.Sweep(context.Background())
	if err != nil || reason != "" {
		t.Fatalf("already-preempted: reason=%q err=%v, want no-op", reason, err)
	}
}
