package nethealth

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

// oomPod builds a Running pod whose linkerd-proxy (init or classic
// container) shows an OOMKilled termination `age` ago.
func oomPod(ns, name string, init bool, age time.Duration, restarts int32) *corev1.Pod {
	st := corev1.ContainerStatus{
		Name:         "linkerd-proxy",
		RestartCount: restarts,
		LastTerminationState: corev1.ContainerState{
			Terminated: &corev1.ContainerStateTerminated{
				Reason:     "OOMKilled",
				FinishedAt: metav1.NewTime(time.Now().Add(-age)),
			},
		},
	}
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	if init {
		p.Status.InitContainerStatuses = []corev1.ContainerStatus{st}
	} else {
		p.Status.ContainerStatuses = []corev1.ContainerStatus{st}
	}
	return p
}

// A linkerd-proxy OOMKilled inside 30m flags the pod (gauge + check
// FAIL + Warning Event); nativeSidecar initContainerStatuses and
// classic containerStatuses are both scanned; stale kills pass.
func TestLinkerdSidecarOOMGuard(t *testing.T) {
	cs := fake.NewSimpleClientset(
		oomPod("apps", "web-1", true, 5*time.Minute, 2),
		oomPod("apps", "web-2", false, 10*time.Minute, 4),
		oomPod("apps", "web-3", true, 2*time.Hour, 9), // stale — passes
		probetest.PodWithPhase("apps", "web-4", corev1.PodRunning, true, time.Hour))
	p := testProber(cs)
	chk := probetest.MustCheck[*linkerdSidecarOOMCheck](t, p)

	res := chk.Run(ctx)
	if res.Pass || res.Why == "" {
		t.Fatalf("OOM pods must fail the check: %+v", res)
	}
	for _, pod := range []string{"web-1", "web-2"} {
		if !linkerdSidecarOOMGauge.DeleteLabelValues("apps", pod) {
			t.Fatalf("missing OOM series for %s", pod)
		}
	}
	if linkerdSidecarOOMGauge.DeleteLabelValues("apps", "web-3") {
		t.Fatal("stale OOM kill flagged")
	}
	// Warning Events emitted per flagged pod.
	evs, err := cs.EventsV1().Events("apps").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs.Items) != 2 {
		t.Fatalf("warning events = %d, want 2", len(evs.Items))
	}
	for _, ev := range evs.Items {
		if ev.Reason != "LinkerdSidecarOOMKilled" ||
			ev.Type != corev1.EventTypeWarning {
			t.Fatalf("bad event: %v/%v", ev.Reason, ev.Type)
		}
	}
}
