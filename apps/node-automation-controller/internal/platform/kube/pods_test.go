// pods_test.go — tests for pods.go: the DaemonSet "rollout settled"
// verdict and the pod Ready-condition probe.
package kube

import (
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

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

// ---------------------------------------------------------------------------
// DaemonSetSettled — every lagging field must veto "settled".
// ---------------------------------------------------------------------------

func TestDaemonSetSettledFields(t *testing.T) {
	t.Run("settled", func(t *testing.T) {
		if !DaemonSetSettled(settledDaemonSet()) {
			t.Fatal("fully caught-up DaemonSet not settled")
		}
	})
	t.Run("observedGeneration lag", func(t *testing.T) {
		ds := settledDaemonSet()
		ds.Status.ObservedGeneration = 2 // controller hasn't seen gen 3
		if DaemonSetSettled(ds) {
			t.Fatal("settled despite stale observedGeneration")
		}
	})
	t.Run("updatedNumberScheduled lag", func(t *testing.T) {
		ds := settledDaemonSet()
		ds.Status.UpdatedNumberScheduled = 3 // old pod template on one node
		if DaemonSetSettled(ds) {
			t.Fatal("settled despite pods still on the old revision")
		}
	})
	t.Run("numberReady lag", func(t *testing.T) {
		ds := settledDaemonSet()
		ds.Status.NumberReady = 3 // updated but not ready yet
		if DaemonSetSettled(ds) {
			t.Fatal("settled despite unready pod")
		}
	})
}

func TestDaemonSetSettled(t *testing.T) {
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Generation: 3},
		Status: appsv1.DaemonSetStatus{
			ObservedGeneration:     3,
			DesiredNumberScheduled: 4,
			UpdatedNumberScheduled: 4,
			NumberReady:            4,
		},
	}
	if !DaemonSetSettled(ds) {
		t.Fatal("expected settled")
	}
	ds.Status.NumberReady = 3
	if DaemonSetSettled(ds) {
		t.Fatal("expected not settled when a replica is not ready")
	}
}

// PodReadyCond mirrors the bash Ready=True probe: absent condition and
// Ready=False both count as not ready.
func TestPodReadyCond(t *testing.T) {
	p := &corev1.Pod{}
	if PodReadyCond(p) {
		t.Fatal("pod with no conditions reported ready")
	}
	p.Status.Conditions = []corev1.PodCondition{
		{Type: corev1.PodReady, Status: corev1.ConditionFalse},
	}
	if PodReadyCond(p) {
		t.Fatal("Ready=False pod reported ready")
	}
	p.Status.Conditions[0].Status = corev1.ConditionTrue
	if !PodReadyCond(p) {
		t.Fatal("Ready=True pod reported not ready")
	}
}

// PodControllerKey keys a workload pod's cooldown on its controller
// (stable across the replacement-name churn) and a standalone pod on
// itself — the distinction the per-pod heal cooldowns rely on so a
// recreated Deployment pod does not read as a brand-new target.
func TestPodControllerKey(t *testing.T) {
	ctrl := true
	deploymentPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "apps", Name: "web-6f4b-x7q2p",
		OwnerReferences: []metav1.OwnerReference{{
			Kind: "ReplicaSet", Name: "web-6f4b",
			Controller: &ctrl}}},
	}
	if got := PodControllerKey(deploymentPod); got != "apps/web-6f4b" {
		t.Fatalf("PodControllerKey = %q, want apps/web-6f4b", got)
	}
	// A recreated pod under the same ReplicaSet must map to the SAME
	// key — the whole point of the helper.
	deploymentPod.Name = "web-6f4b-m9zkw"
	if got := PodControllerKey(deploymentPod); got != "apps/web-6f4b" {
		t.Fatalf("recreated pod keyed %q, want stable apps/web-6f4b", got)
	}
	standalone := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "apps", Name: "debug-shell"}}
	if got := PodControllerKey(standalone); got != "apps/debug-shell" {
		t.Fatalf("standalone pod keyed %q, want apps/debug-shell", got)
	}
	// A non-controller owner reference (e.g. a plain "owned-by" link)
	// does not re-create pods — the pod's own name is the key.
	nonCtrl := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "apps", Name: "orphan",
		OwnerReferences: []metav1.OwnerReference{{
			Kind: "ConfigMap", Name: "settings"}}},
	}
	if got := PodControllerKey(nonCtrl); got != "apps/orphan" {
		t.Fatalf("non-controller-owned pod keyed %q, want apps/orphan", got)
	}
}

// ---------------------------------------------------------------------------
// PodSpecHasContainer / PodReadySince / PodUnreadyFor / PodMergePatcher.
// ---------------------------------------------------------------------------

func TestPodSpecHasContainer(t *testing.T) {
	ps := &corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}, {Name: "sidecar"}}}
	if !PodSpecHasContainer(ps, "app") {
		t.Fatal("present container reported missing")
	}
	if PodSpecHasContainer(ps, "proxy") {
		t.Fatal("absent container reported present")
	}
	if PodSpecHasContainer(&corev1.PodSpec{}, "app") {
		t.Fatal("empty spec reported present")
	}
}

func readyPod(since metav1.Time) *corev1.Pod {
	return &corev1.Pod{Status: corev1.PodStatus{Conditions: []corev1.PodCondition{
		{Type: corev1.PodReady, Status: corev1.ConditionTrue, LastTransitionTime: since},
	}}}
}

func TestPodReadySince(t *testing.T) {
	ts := metav1.NewTime(time.Unix(1700000000, 0))
	t.Run("ready with transition time", func(t *testing.T) {
		got, ok := PodReadySince(readyPod(ts))
		if !ok || !got.Equal(ts.Time) {
			t.Fatalf("got (%v, %v), want (%v, true)", got, ok, ts.Time)
		}
	})
	t.Run("not ready fails closed", func(t *testing.T) {
		p := readyPod(ts)
		p.Status.Conditions[0].Status = corev1.ConditionFalse
		if since, ok := PodReadySince(p); ok || !since.IsZero() {
			t.Fatalf("unready pod reported ready since (%v, %v)", since, ok)
		}
	})
	t.Run("zero transition time fails closed", func(t *testing.T) {
		p := readyPod(metav1.Time{})
		if _, ok := PodReadySince(p); ok {
			t.Fatal("zero transition time treated as verifiable")
		}
	})
	t.Run("missing Ready condition", func(t *testing.T) {
		if _, ok := PodReadySince(&corev1.Pod{}); ok {
			t.Fatal("conditionless pod reported ready")
		}
	})
}

func TestPodUnreadyFor(t *testing.T) {
	since := metav1.NewTime(time.Unix(1000, 0))
	now := time.Unix(1300, 0)
	t.Run("unready counts", func(t *testing.T) {
		p := readyPod(since)
		p.Status.Conditions[0].Status = corev1.ConditionFalse
		d, ok := PodUnreadyFor(p, now)
		if !ok || d != 300*time.Second {
			t.Fatalf("got (%v, %v), want (300s, true)", d, ok)
		}
	})
	t.Run("ready fails closed", func(t *testing.T) {
		if d, ok := PodUnreadyFor(readyPod(since), now); ok || d != 0 {
			t.Fatalf("ready pod counted unready (%v, %v)", d, ok)
		}
	})
	t.Run("zero transition time fails closed", func(t *testing.T) {
		p := readyPod(metav1.Time{})
		p.Status.Conditions[0].Status = corev1.ConditionFalse
		if d, ok := PodUnreadyFor(p, now); ok || d != 0 {
			t.Fatalf("zero transition counted (%v, %v)", d, ok)
		}
	})
	t.Run("missing condition fails closed", func(t *testing.T) {
		if d, ok := PodUnreadyFor(&corev1.Pod{}, now); ok || d != 0 {
			t.Fatalf("conditionless pod counted (%v, %v)", d, ok)
		}
	})
}

func TestPodMergePatcher(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "web"}}
	cs := fake.NewSimpleClientset(pod)
	patch := PodMergePatcher(cs, pod)
	data := []byte(`{"metadata":{"annotations":{"k":"v"}}}`)
	if err := patch(t.Context(), data); err != nil {
		t.Fatalf("patch failed: %v", err)
	}
	got, err := cs.CoreV1().Pods("ns").Get(t.Context(), "web", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get after patch: %v", err)
	}
	if got.Annotations["k"] != "v" {
		t.Fatalf("annotation not applied: %v", got.Annotations)
	}
	if err := patch(t.Context(), []byte(`not json`)); err == nil {
		t.Fatal("invalid patch data accepted")
	}
}
