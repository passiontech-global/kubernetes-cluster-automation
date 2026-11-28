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

func readinessGatePod(ns, name, uid, gate string, gateStatus corev1.ConditionStatus, annos map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   ns,
			Name:        name,
			UID:         types.UID("uid-" + uid),
			Annotations: annos,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1",
				Kind:       "ReplicaSet",
				Name:       name + "-rs",
				UID:        types.UID("rs-uid-" + uid),
				Controller: new(true),
			}},
		},
		Spec: corev1.PodSpec{
			NodeName: "worker-1",
			ReadinessGates: []corev1.PodReadinessGate{
				{ConditionType: corev1.PodConditionType(gate)},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{
				{Type: corev1.ContainersReady, Status: corev1.ConditionTrue},
				{Type: corev1.PodReady, Status: corev1.ConditionFalse},
				{Type: corev1.PodConditionType(gate), Status: gateStatus},
			},
		},
	}
}

func TestReadinessGateWedgeGuardDetectionAndPruning(t *testing.T) {
	t.Setenv("NODE_AUTOMATION_READINESS_GATE_HEAL_ENABLED", "false")
	base := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)

	wedged := readinessGatePod("apps", "web-0", "1", "target-health.alb.ingress.k8s.aws/tg", corev1.ConditionFalse, nil)
	healthy := readinessGatePod("apps", "ok-0", "2", "custom.io/ready", corev1.ConditionTrue, nil)
	healthy.Status.Conditions[1].Status = corev1.ConditionTrue

	cs := fake.NewSimpleClientset(wedged, healthy)
	p := testProber(cs)
	chk := probetest.MustCheck[*readinessGateWedgeGuardCheck](t, p)

	// Sweep 1: first-seen tracked, not yet 10m -> pass, no gauge.
	probetest.FreezeNow(p.Deps, base)
	res1 := probetest.RunCheck(ctx, p.Deps, chk)
	if !res1.Pass {
		t.Fatalf("sweep 1 expected pass before 10m persistence, got %+v", res1)
	}
	if m := probetest.FindMetric(t, "node_automation_pod_readiness_gate_wedged", map[string]string{
		"namespace": "apps", "pod": "web-0", "gate": "target-health.alb.ingress.k8s.aws/tg",
	}); m != nil {
		t.Fatalf("unexpected gauge before 10m window: %v", m)
	}

	// Sweep 2: >=10m -> fail + gauge + Warning Event, no pod delete (heal disabled).
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	res2 := probetest.RunCheck(ctx, p.Deps, chk)
	if res2.Pass || !strings.Contains(res2.Why, "apps/web-0") {
		t.Fatalf("sweep 2 expected failure for apps/web-0, got %+v", res2)
	}
	if m := probetest.FindMetric(t, "node_automation_pod_readiness_gate_wedged", map[string]string{
		"namespace": "apps", "pod": "web-0", "gate": "target-health.alb.ingress.k8s.aws/tg",
	}); m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("expected gauge=1, got %v", m)
	}
	evs, err := cs.EventsV1().Events("apps").List(ctx, metav1.ListOptions{})
	if err != nil || len(evs.Items) != 1 || evs.Items[0].Reason != readinessGateEventReason {
		t.Fatalf("expected 1 ReadinessGateWedged event, got %v err=%v", len(evs.Items), err)
	}

	// Sweep 3: gate satisfied -> pass & gauge pruned.
	wedgedUpdated := wedged.DeepCopy()
	wedgedUpdated.Status.Conditions[1].Status = corev1.ConditionTrue
	wedgedUpdated.Status.Conditions[2].Status = corev1.ConditionTrue
	if _, err := cs.CoreV1().Pods("apps").UpdateStatus(ctx, wedgedUpdated, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update status: %v", err)
	}
	probetest.FreezeNow(p.Deps, base.Add(16*time.Minute))
	res3 := probetest.RunCheck(ctx, p.Deps, chk)
	if !res3.Pass {
		t.Fatalf("sweep 3 expected pass after gate satisfied, got %+v", res3)
	}
	if m := probetest.FindMetric(t, "node_automation_pod_readiness_gate_wedged", map[string]string{
		"namespace": "apps", "pod": "web-0", "gate": "target-health.alb.ingress.k8s.aws/tg",
	}); m != nil {
		t.Fatalf("expected pruned gauge after recovery, got %v", m)
	}
}

func TestReadinessGateWedgeGuardOptInHealAndGates(t *testing.T) {
	t.Setenv("NODE_AUTOMATION_READINESS_GATE_HEAL_ENABLED", "true")
	base := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)

	unopted := readinessGatePod("apps", "unopted-0", "u1", "gate.io/g", corev1.ConditionFalse, nil)
	opted := readinessGatePod("apps", "opted-0", "o1", "gate.io/g", corev1.ConditionFalse, map[string]string{
		readinessGateHealAnno: "true",
	})
	otherOpted := readinessGatePod("apps", "opted-1", "o2", "gate.io/g", corev1.ConditionFalse, map[string]string{
		readinessGateHealAnno: "true",
	})

	// Hold maintenance via an actively cordoned node first to verify HealAllowed blocks heal.
	cordonedNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
		Spec: corev1.NodeSpec{
			Unschedulable: true,
			Taints: []corev1.Taint{{
				Key:       kube.UnschedulableTaintKey,
				Effect:    corev1.TaintEffectNoSchedule,
				TimeAdded: new(metav1.NewTime(base.Add(5 * time.Minute))),
			}},
		},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}},
	}

	cs := fake.NewSimpleClientset(unopted, opted, otherOpted, cordonedNode)
	var deletedPods []string
	cs.PrependReactor("delete", "pods", func(a ktesting.Action) (bool, runtime.Object, error) {
		da := a.(ktesting.DeleteAction)
		deletedPods = append(deletedPods, da.GetNamespace()+"/"+da.GetName())
		return false, nil, nil
	})

	p := testProber(cs)
	chk := probetest.MustCheck[*readinessGateWedgeGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, base)
	_ = probetest.RunCheck(ctx, p.Deps, chk)

	// Past 10m while maintenance hold active -> no delete.
	probetest.FreezeNow(p.Deps, base.Add(12*time.Minute))
	_ = probetest.RunCheck(ctx, p.Deps, chk)
	if len(deletedPods) != 0 {
		t.Fatalf("expected 0 deletes during maintenance hold, got %v", deletedPods)
	}

	// Clear maintenance hold, advance past hold -> opted-0 deleted (UID-preconditioned), unopted-0 untouched.
	cordonedNode.Spec.Unschedulable = false
	cordonedNode.Spec.Taints = nil
	if _, err := cs.CoreV1().Nodes().Update(ctx, cordonedNode, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update node: %v", err)
	}

	// Pre-reserve workload disruption slot on opted-1's controller to prove disruption-slot gating.
	sctx := probetest.SweepCtx(ctx, p.Deps)
	if !kube.TryReserveWorkloadDisruption(sctx, otherOpted) {
		t.Fatal("failed to pre-reserve workload disruption slot")
	}
	probetest.FreezeNow(p.Deps, base.Add(15*time.Minute))
	_ = chk.Run(sctx)
	probetest.VerifySweep(sctx)

	if len(deletedPods) != 1 || deletedPods[0] != "apps/opted-0" {
		t.Fatalf("expected only apps/opted-0 deleted (unopted skipped, opted-1 disruption-slot deferred), got %v", deletedPods)
	}

	// Verify ReplicaSet/owner cooldown prevents immediate re-delete of recreated pod under same controller.
	// Remove opted-1 so only the recreated pod under opted-0's controller is evaluated.
	_ = cs.CoreV1().Pods("apps").Delete(ctx, "opted-1", metav1.DeleteOptions{})
	recreated := readinessGatePod("apps", "opted-0", "o1-new", "gate.io/g", corev1.ConditionFalse, map[string]string{
		readinessGateHealAnno: "true",
	})
	recreated.OwnerReferences[0].Name = "opted-0-rs"
	recreated.OwnerReferences[0].UID = "rs-uid-o1"
	_ = cs.CoreV1().Pods("apps").Delete(ctx, "opted-0", metav1.DeleteOptions{})
	if _, err := cs.CoreV1().Pods("apps").Create(ctx, recreated, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create recreated pod: %v", err)
	}
	deletedPods = nil
	probetest.FreezeNow(p.Deps, base.Add(20*time.Minute))
	_ = probetest.RunCheck(ctx, p.Deps, chk)
	probetest.FreezeNow(p.Deps, base.Add(31*time.Minute))
	_ = probetest.RunCheck(ctx, p.Deps, chk)
	if len(deletedPods) != 0 {
		t.Fatalf("expected 0 deletes inside 30m controller cooldown, got %v", deletedPods)
	}
}

func TestReadinessGateWedgeGuardListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("boom")
	})
	p := testProber(cs)
	chk := probetest.MustCheck[*readinessGateWedgeGuardCheck](t, p)
	res := probetest.RunCheck(ctx, p.Deps, chk)
	if res.Pass || res.Infra == nil {
		t.Fatalf("expected Infra error on pod list failure, got %+v", res)
	}
}
