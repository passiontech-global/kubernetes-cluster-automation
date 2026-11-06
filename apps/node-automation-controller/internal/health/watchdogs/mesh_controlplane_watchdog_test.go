// mesh_controlplane_watchdog_test.go — coverage for the
// mesh-controlplane-watchdog check (W8-NM2/NM3): wedged linkerd
// control-plane pod heal and the healNamedPod maintenance gate.
package watchdogs

import (
	"testing"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// W8-NM3 — a wedged linkerd pod (started, never Ready, >5m) is
// deleted to force a re-roll, matching Deployment-suffixed pod names.
func TestCheckMeshLinkerdWedgedHeals(t *testing.T) {
	started := true
	podName := probefw.LinkerdDestinationName + "-7f8b9c6d4-abcde"
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: probefw.LinkerdNS, Name: podName,
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
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false), pod)
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*meshControlPlaneCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("wedged linkerd pod passed")
	}
	if _, err := cs.CoreV1().Pods(probefw.LinkerdNS).
		Get(ctx, podName, metav1.GetOptions{}); err == nil {
		t.Fatal("wedged linkerd pod not deleted")
	}
}

// ---------------------------------------------------------------------------
// healNamedPod — maintenance gate (W8-ST2)
// ---------------------------------------------------------------------------

// A wedged control-plane pod is NOT deleted while maintenance is in
// flight — the direct healNamedPod path (linkerd re-roll) respects
// the same mutex as healComponentPod.
func TestHealNamedPodDefersDuringMaintenance(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         probefw.LinkerdNS,
			Name:              probefw.LinkerdDestinationName + "-aaa-111",
			UID:               types.UID("u-dest"),
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
		},
	}
	// kured holding its node-lock = a reboot drain in flight.
	kured := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{
		Namespace:   "kube-system",
		Name:        "kured",
		Annotations: map[string]string{kube.KuredLockAnno: "w1"},
	}}
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false), kured, pod)
	p := testProberDyn(cs, probetest.OpDyn())
	probetest.MustCheck[*meshControlPlaneCheck](t, p).healNamedPod(ctx, logr.Discard(), probefw.LinkerdDestinationName,
		pod.Namespace+"/"+pod.Name, pod, linkerdHealCooldown, time.Now())
	if _, err := cs.CoreV1().Pods(probefw.LinkerdNS).
		Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted during maintenance — heal must defer")
	}
}

// Without a maintenance signal the same call deletes the pod.
func TestHealNamedPodDeletesWithoutMaintenance(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         probefw.LinkerdNS,
			Name:              probefw.LinkerdDestinationName + "-bbb-222",
			UID:               types.UID("u-dest2"),
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
		},
	}
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false), pod)
	p := testProberDyn(cs, probetest.OpDyn())
	probetest.MustCheck[*meshControlPlaneCheck](t, p).healNamedPod(ctx, logr.Discard(), probefw.LinkerdDestinationName,
		pod.Namespace+"/"+pod.Name, pod, linkerdHealCooldown, time.Now())
	if _, err := cs.CoreV1().Pods(probefw.LinkerdNS).
		Get(ctx, pod.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("pod not deleted outside maintenance")
	}
}
