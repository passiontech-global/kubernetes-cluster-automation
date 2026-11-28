package nodehealth

import (
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

func TestClusterHygieneGuardDetectionAndPruning(t *testing.T) {
	t.Setenv("NODE_AUTOMATION_CLUSTER_HYGIENE_GC_ENABLED", "false")
	base := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)

	forgottenNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-forgotten", UID: "n1"},
		Spec: corev1.NodeSpec{
			Unschedulable: true,
			Taints: []corev1.Taint{{
				Key:       kube.UnschedulableTaintKey,
				Effect:    corev1.TaintEffectNoSchedule,
				TimeAdded: new(metav1.NewTime(base.Add(-25 * time.Hour))),
			}},
		},
	}
	precordonedNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "worker-precordon",
			Annotations: map[string]string{kube.AnnoPreCordonedBy: "node-hang-precordon"},
		},
		Spec: corev1.NodeSpec{
			Unschedulable: true,
			Taints: []corev1.Taint{{
				Key:       kube.UnschedulableTaintKey,
				Effect:    corev1.TaintEffectNoSchedule,
				TimeAdded: new(metav1.NewTime(base.Add(-30 * time.Hour))),
			}},
		},
	}
	kuredNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-kured"},
		Spec: corev1.NodeSpec{
			Unschedulable: true,
			Taints: []corev1.Taint{
				{Key: kube.TaintKuredNodeReboot, Effect: corev1.TaintEffectNoSchedule},
				{Key: kube.UnschedulableTaintKey, Effect: corev1.TaintEffectNoSchedule, TimeAdded: new(metav1.NewTime(base.Add(-30 * time.Hour)))},
			},
		},
	}
	youngCordonNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-young"},
		Spec: corev1.NodeSpec{
			Unschedulable: true,
			Taints: []corev1.Taint{{
				Key:       kube.UnschedulableTaintKey,
				Effect:    corev1.TaintEffectNoSchedule,
				TimeAdded: new(metav1.NewTime(base.Add(-2 * time.Hour))),
			}},
		},
	}

	debugPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default", Name: "node-debugger-worker-1-abc", UID: "p1",
			CreationTimestamp: metav1.NewTime(base.Add(-26 * time.Hour)),
		},
		Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
	}
	ephemPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "app-with-debug", UID: "p2",
			CreationTimestamp: metav1.NewTime(base.Add(-26 * time.Hour)),
		},
		Spec: corev1.PodSpec{
			EphemeralContainers: []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "dbg", Image: "busybox"}}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}

	cs := fake.NewSimpleClientset(forgottenNode, precordonedNode, kuredNode, youngCordonNode, debugPod, ephemPod)
	p := testProber(cs)
	chk := probetest.MustCheck[*clusterHygieneGuardCheck](t, p)
	probetest.FreezeNow(p.Deps, base)

	res := probetest.RunCheck(ctx, p.Deps, chk)
	if res.Pass {
		t.Fatalf("expected failure for forgotten cordon and orphan debug pods, got pass")
	}
	if strings.Contains(res.Why, "worker-precordon") || strings.Contains(res.Why, "worker-kured") || strings.Contains(res.Why, "worker-young") {
		t.Fatalf("unexpected exempt/young node in Why: %s", res.Why)
	}
	for _, want := range []struct{ target, reason string }{
		{"worker-forgotten", hygieneReasonForgottenCordon},
		{"default/node-debugger-worker-1-abc", hygieneReasonOrphanDebugPod},
		{"apps/app-with-debug", hygieneReasonOrphanDebugPod},
	} {
		if m := probetest.FindMetric(t, "node_automation_cluster_hygiene_issue", map[string]string{
			"target": want.target, "reason": want.reason,
		}); m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatalf("expected gauge=1 for %+v, got %v", want, m)
		}
	}

	// GC disabled: terminal debug pod must remain.
	if _, err := cs.CoreV1().Pods("default").Get(ctx, "node-debugger-worker-1-abc", metav1.GetOptions{}); err != nil {
		t.Fatalf("expected terminal debug pod preserved when GC disabled: %v", err)
	}

	// Uncordon + delete debug pods -> pass & gauges pruned.
	fnCopy := forgottenNode.DeepCopy()
	fnCopy.Spec.Unschedulable = false
	fnCopy.Spec.Taints = nil
	_, _ = cs.CoreV1().Nodes().Update(ctx, fnCopy, metav1.UpdateOptions{})
	_ = cs.CoreV1().Pods("default").Delete(ctx, "node-debugger-worker-1-abc", metav1.DeleteOptions{})
	_ = cs.CoreV1().Pods("apps").Delete(ctx, "app-with-debug", metav1.DeleteOptions{})

	probetest.FreezeNow(p.Deps, base.Add(1*time.Hour))
	res2 := probetest.RunCheck(ctx, p.Deps, chk)
	if !res2.Pass {
		t.Fatalf("expected pass after cleanup, got %+v", res2)
	}
	if m := probetest.FindMetric(t, "node_automation_cluster_hygiene_issue", map[string]string{
		"target": "worker-forgotten", "reason": hygieneReasonForgottenCordon,
	}); m != nil {
		t.Fatalf("expected pruned gauge, got %v", m)
	}
}

func TestClusterHygieneGuardOptInGCOnlyTerminalDebugPods(t *testing.T) {
	t.Setenv("NODE_AUTOMATION_CLUSTER_HYGIENE_GC_ENABLED", "true")
	base := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)

	termDebug := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default", Name: "kubectl-debug-xyz", UID: "t1",
			CreationTimestamp: metav1.NewTime(base.Add(-25 * time.Hour)),
		},
		Status: corev1.PodStatus{Phase: corev1.PodFailed},
	}
	runningDebug := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default", Name: "node-debugger-live", UID: "r1",
			CreationTimestamp: metav1.NewTime(base.Add(-25 * time.Hour)),
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	ephemTerminal := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "job-with-ephem", UID: "e1",
			CreationTimestamp: metav1.NewTime(base.Add(-25 * time.Hour)),
		},
		Spec: corev1.PodSpec{
			EphemeralContainers: []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "dbg", Image: "busybox"}}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
	}

	cs := fake.NewSimpleClientset(termDebug, runningDebug, ephemTerminal)
	var deleted []string
	cs.PrependReactor("delete", "pods", func(a ktesting.Action) (bool, runtime.Object, error) {
		da := a.(ktesting.DeleteAction)
		deleted = append(deleted, da.GetNamespace()+"/"+da.GetName())
		return false, nil, nil
	})

	p := testProber(cs)
	chk := probetest.MustCheck[*clusterHygieneGuardCheck](t, p)
	probetest.FreezeNow(p.Deps, base)

	_ = probetest.RunCheck(ctx, p.Deps, chk)
	if len(deleted) != 1 || deleted[0] != "default/kubectl-debug-xyz" {
		t.Fatalf("expected ONLY terminal kubectl-debug-xyz GC'd, got %v", deleted)
	}
}

func TestClusterHygieneGuardListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "nodes", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("boom")
	})
	p := testProber(cs)
	chk := probetest.MustCheck[*clusterHygieneGuardCheck](t, p)
	res := probetest.RunCheck(ctx, p.Deps, chk)
	if res.Pass || res.Infra == nil {
		t.Fatalf("expected Infra error on node list failure, got %+v", res)
	}
}
