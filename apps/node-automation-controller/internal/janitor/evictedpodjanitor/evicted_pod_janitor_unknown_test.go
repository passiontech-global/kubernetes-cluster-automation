// evicted_pod_janitor_unknown_test.go — coverage for reaping
// controller-owned ContainerStatusUnknown / PodUnknown pods on Ready
// nodes after unknownPodMinAge.
package evictedpodjanitor

import (
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/maintenance"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func epjNode(name string, ready bool) *corev1.Node {
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: status}},
		},
	}
}

func epjUnknownPod(ns, name, node string, owned bool, phase corev1.PodPhase, containerReason string) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
			UID:       types.UID("uid-" + name),
		},
		Spec: corev1.PodSpec{NodeName: node},
		Status: corev1.PodStatus{
			Phase: phase,
		},
	}
	if owned {
		ctrl := true
		p.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: "apps/v1",
			Kind:       "ReplicaSet",
			Name:       "rs-1",
			UID:        "uid-rs-1",
			Controller: &ctrl,
		}}
	}
	if containerReason != "" {
		p.Status.ContainerStatuses = []corev1.ContainerStatus{{
			Name: "app",
			State: corev1.ContainerState{
				Terminated: &corev1.ContainerStateTerminated{Reason: containerReason},
			},
		}}
	}
	return p
}

func TestEvictedPodJanitorReapsStrandedUnknownPodAfterMinAge(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	cs := fake.NewSimpleClientset(
		epjNode("w1", true),
		epjNode("w-down", false),
		epjUnknownPod("ns-a", "owned-unknown", "w1", true, corev1.PodFailed, "ContainerStatusUnknown"),
		epjUnknownPod("ns-a", "phase-unknown", "w1", true, corev1.PodUnknown, ""),
		epjUnknownPod("ns-a", "standalone-unknown", "w1", false, corev1.PodFailed, "ContainerStatusUnknown"),
		epjUnknownPod("ns-a", "notready-node-unknown", "w-down", true, corev1.PodFailed, "ContainerStatusUnknown"),
	)
	j := &evictedPodJanitor{
		cs:    cs,
		queue: "evicted-pod-janitor",
		now:   func() time.Time { return now },
	}

	// First sweep: records first-seen timestamp — nothing deleted yet.
	if err := j.run(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"owned-unknown", "phase-unknown", "standalone-unknown", "notready-node-unknown"} {
		if !testutil.PodExistsStrict(t, cs, "ns-a", name) {
			t.Fatalf("pod %s deleted before unknownPodMinAge", name)
		}
	}

	// Advance clock past 15m -> only controller-owned pods on Ready node are reaped.
	now = now.Add(unknownPodMinAge + time.Minute)
	if err := j.run(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"owned-unknown", "phase-unknown"} {
		if testutil.PodExistsStrict(t, cs, "ns-a", name) {
			t.Fatalf("stranded controller-owned pod %s was not deleted", name)
		}
	}
	for _, name := range []string{"standalone-unknown", "notready-node-unknown"} {
		if !testutil.PodExistsStrict(t, cs, "ns-a", name) {
			t.Fatalf("pod %s must be kept untouched", name)
		}
	}
}

func TestEvictedPodJanitorUnknownRespectsRunningContainerAndCap(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	objs := []runtime.Object{epjNode("w1", true)}
	for i := 0; i < unknownPodCap+2; i++ {
		objs = append(objs, epjUnknownPod("ns-a", fmt.Sprintf("u-%02d", i), "w1", true, corev1.PodFailed, "ContainerStatusUnknown"))
	}
	mixed := epjUnknownPod("ns-a", "mixed-running", "w1", true, corev1.PodFailed, "ContainerStatusUnknown")
	mixed.Status.ContainerStatuses = append(mixed.Status.ContainerStatuses, corev1.ContainerStatus{
		Name:  "sidecar",
		State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
	})
	objs = append(objs, mixed)

	cs := fake.NewSimpleClientset(objs...)
	j := &evictedPodJanitor{
		cs:    cs,
		queue: "evicted-pod-janitor",
		now:   func() time.Time { return now },
	}
	if err := j.run(t.Context()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(unknownPodMinAge + time.Minute)
	if err := j.run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !testutil.PodExistsStrict(t, cs, "ns-a", "mixed-running") {
		t.Fatal("pod with a Running container must not be deleted")
	}
	remaining, err := cs.CoreV1().Pods("ns-a").List(t.Context(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// 12 eligible - 10 capped = 2 + 1 mixed-running = 3 survivors.
	if len(remaining.Items) != 3 {
		t.Fatalf("survivors = %d, want 3 (2 capped + 1 mixed-running)", len(remaining.Items))
	}
}

func TestEvictedPodJanitorUnknownHeldDuringMaintenance(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	cordonNode := epjNode("w1", true)
	cordonNode.Spec.Unschedulable = true // active operator cordon triggers maintenance mutex
	cs := fake.NewSimpleClientset(
		cordonNode,
		epjUnknownPod("ns-a", "owned-unknown", "w1", true, corev1.PodFailed, "ContainerStatusUnknown"),
	)
	j := &evictedPodJanitor{
		cs:      cs,
		dyn:     testutil.NewDynamicClient(),
		verdict: &maintenance.Verdict{},
		queue:   "evicted-pod-janitor",
		now:     func() time.Time { return now },
	}
	if err := j.run(t.Context()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(unknownPodMinAge + time.Minute)
	if err := j.run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !testutil.PodExistsStrict(t, cs, "ns-a", "owned-unknown") {
		t.Fatal("maintenance mutex must hold unknown-pod deletes")
	}
}
