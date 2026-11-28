package watchdogs

import (
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

func schedulingGatePod(ns, name, uid, gate string, created time.Time, annos map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			UID:               types.UID("uid-" + uid),
			CreationTimestamp: metav1.NewTime(created),
			Annotations:       annos,
		},
		Spec: corev1.PodSpec{
			SchedulingGates: []corev1.PodSchedulingGate{{Name: gate}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodPending},
	}
}

func TestSchedulingGateWedgeGuardDetectionAndPruning(t *testing.T) {
	t.Setenv("NODE_AUTOMATION_SCHEDULING_GATE_HEAL_ENABLED", "false")
	base := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)

	young := schedulingGatePod("apps", "young-0", "1", "example.com/hold", base.Add(-5*time.Minute), nil)
	old := schedulingGatePod("apps", "old-0", "2", "example.com/hold", base.Add(-20*time.Minute), nil)

	cs := fake.NewSimpleClientset(young, old)
	p := testProber(cs)
	chk := probetest.MustCheck[*schedulingGateWedgeGuardCheck](t, p)
	probetest.FreezeNow(p.Deps, base)

	res := probetest.RunCheck(ctx, p.Deps, chk)
	if res.Pass || !strings.Contains(res.Why, "apps/old-0") || strings.Contains(res.Why, "young-0") {
		t.Fatalf("expected only apps/old-0 flagged, got %+v", res)
	}
	if m := probetest.FindMetric(t, "node_automation_pod_scheduling_gate_wedged", map[string]string{
		"namespace": "apps", "gate": "example.com/hold",
	}); m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("expected gauge=1, got %v", m)
	}
	evs, err := cs.EventsV1().Events("apps").List(ctx, metav1.ListOptions{})
	if err != nil || len(evs.Items) != 1 || evs.Items[0].Reason != schedulingGateEventReason {
		t.Fatalf("expected 1 SchedulingGateWedged event, got %d err=%v", len(evs.Items), err)
	}

	// Gate cleared -> pass and gauge pruned.
	oldCopy := old.DeepCopy()
	oldCopy.Spec.SchedulingGates = nil
	if _, err := cs.CoreV1().Pods("apps").Update(ctx, oldCopy, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update pod: %v", err)
	}
	probetest.FreezeNow(p.Deps, base.Add(5*time.Minute))
	res2 := probetest.RunCheck(ctx, p.Deps, chk)
	if !res2.Pass {
		t.Fatalf("expected pass after gate removed, got %+v", res2)
	}
	if m := probetest.FindMetric(t, "node_automation_pod_scheduling_gate_wedged", map[string]string{
		"namespace": "apps", "gate": "example.com/hold",
	}); m != nil {
		t.Fatalf("expected pruned gauge, got %v", m)
	}
}

func TestSchedulingGateWedgeGuardOptInHeal(t *testing.T) {
	t.Setenv("NODE_AUTOMATION_SCHEDULING_GATE_HEAL_ENABLED", "true")
	base := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)

	unopted := schedulingGatePod("apps", "unopted-0", "u1", "example.com/hold", base.Add(-20*time.Minute), nil)
	opted := schedulingGatePod("apps", "opted-0", "o1", "example.com/hold", base.Add(-20*time.Minute), map[string]string{
		schedulingGateHealAnno: "true",
	})
	cordoned := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
		Spec: corev1.NodeSpec{
			Unschedulable: true,
			Taints: []corev1.Taint{{
				Key:       kube.UnschedulableTaintKey,
				Effect:    corev1.TaintEffectNoSchedule,
				TimeAdded: new(metav1.NewTime(base.Add(-10 * time.Minute))),
			}},
		},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}},
	}

	cs := fake.NewSimpleClientset(unopted, opted, cordoned)
	p := testProber(cs)
	chk := probetest.MustCheck[*schedulingGateWedgeGuardCheck](t, p)
	probetest.FreezeNow(p.Deps, base)

	// Under active maintenance hold -> no patch.
	_ = probetest.RunCheck(ctx, p.Deps, chk)
	gotOpted, _ := cs.CoreV1().Pods("apps").Get(ctx, "opted-0", metav1.GetOptions{})
	if len(gotOpted.Spec.SchedulingGates) == 0 {
		t.Fatal("expected schedulingGates preserved during maintenance hold")
	}

	// Release hold -> opted-0 gate removed, unopted-0 untouched.
	cordoned.Spec.Unschedulable = false
	cordoned.Spec.Taints = nil
	if _, err := cs.CoreV1().Nodes().Update(ctx, cordoned, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update node: %v", err)
	}
	probetest.FreezeNow(p.Deps, base.Add(2*time.Minute))
	_ = probetest.RunCheck(ctx, p.Deps, chk)

	gotOpted, _ = cs.CoreV1().Pods("apps").Get(ctx, "opted-0", metav1.GetOptions{})
	if len(gotOpted.Spec.SchedulingGates) != 0 {
		t.Fatalf("expected opted-0 schedulingGates cleared, got %+v", gotOpted.Spec.SchedulingGates)
	}
	gotUnopted, _ := cs.CoreV1().Pods("apps").Get(ctx, "unopted-0", metav1.GetOptions{})
	if len(gotUnopted.Spec.SchedulingGates) == 0 {
		t.Fatal("expected unopted-0 schedulingGates untouched")
	}
}

func TestSchedulingGateWedgeGuardListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("boom")
	})
	p := testProber(cs)
	chk := probetest.MustCheck[*schedulingGateWedgeGuardCheck](t, p)
	res := probetest.RunCheck(ctx, p.Deps, chk)
	if res.Pass || res.Infra == nil {
		t.Fatalf("expected Infra error on pod list failure, got %+v", res)
	}
}
