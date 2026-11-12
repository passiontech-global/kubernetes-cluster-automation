// onepassword_connect_sync_probe_test.go — coverage for the
// onepassword-connect-sync-probe degraded predicate: the crashloop
// ceiling fires only while the container is crashlooping NOW or its
// last termination is recent, and freshly started pods get a grace
// pass.
package watchdogs

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

// connSyncPod builds a Running onepassword-connect pod (past the
// start grace) with a connect-api + connect-sync container pair.
func connSyncPod(created time.Time) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "external-secrets", Name: "onepassword-connect-aaa",
			CreationTimestamp: metav1.NewTime(created),
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: "connect-api"}, {Name: "connect-sync"}}},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "connect-api", Ready: true},
			},
		},
	}
}

func connSyncStatus(cs corev1.ContainerStatus) []corev1.ContainerStatus {
	return append(
		[]corev1.ContainerStatus{{Name: "connect-api", Ready: true}}, cs)
}

// CrashLoopBackOff + restarts past the ceiling → degraded, even with
// the container's current Ready snapshot true.
func TestConnectSyncCrashloopBackOffDegraded(t *testing.T) {
	now := time.Now()
	pod := connSyncPod(now.Add(-time.Hour))
	pod.Status.ContainerStatuses = connSyncStatus(corev1.ContainerStatus{
		Name: esConnectSyncContainer, Ready: true, RestartCount: 5,
		State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
			Reason: "CrashLoopBackOff"}},
	})
	why, bad := connectSyncDegraded(pod, now)
	if !bad {
		t.Fatal("CrashLoopBackOff past the restart ceiling must be degraded")
	}
	if why != "connect-sync container crashlooping" {
		t.Fatalf("why = %q", why)
	}
}

// A recent termination (inside the 15m window) with restarts past the
// ceiling is still a live crashloop — degraded.
func TestConnectSyncRecentTerminationDegraded(t *testing.T) {
	now := time.Now()
	pod := connSyncPod(now.Add(-time.Hour))
	pod.Status.ContainerStatuses = connSyncStatus(corev1.ContainerStatus{
		Name: esConnectSyncContainer, Ready: true, RestartCount: 3,
		State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
		LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
			FinishedAt: metav1.NewTime(now.Add(-5 * time.Minute))}},
	})
	if _, bad := connectSyncDegraded(pod, now); !bad {
		t.Fatal("termination 5m ago past the restart ceiling must be degraded")
	}
}

// The historical-crashloop false positive: restarts past the ceiling
// but the last termination is 2h old and the container is Running —
// the pod stabilized, it is NOT degraded.
func TestConnectSyncStaleCrashloopNotDegraded(t *testing.T) {
	now := time.Now()
	pod := connSyncPod(now.Add(-3 * time.Hour))
	pod.Status.ContainerStatuses = connSyncStatus(corev1.ContainerStatus{
		Name: esConnectSyncContainer, Ready: true, RestartCount: 7,
		State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
		LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
			FinishedAt: metav1.NewTime(now.Add(-2 * time.Hour))}},
	})
	if _, bad := connectSyncDegraded(pod, now); bad {
		t.Fatal("a stabilized pod with old restarts must not be degraded")
	}
}

// Grace window: a pod younger than esConnectStartGrace is never
// degraded — a just-started pod is legitimately !Ready while its
// restart counter ticks through init churn.
func TestConnectSyncStartGraceNotDegraded(t *testing.T) {
	now := time.Now()
	pod := connSyncPod(now.Add(-time.Minute))
	pod.Status.ContainerStatuses = connSyncStatus(corev1.ContainerStatus{
		Name: esConnectSyncContainer, Ready: false, RestartCount: 4,
		State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
			Reason: "CrashLoopBackOff"}},
	})
	if _, bad := connectSyncDegraded(pod, now); bad {
		t.Fatal("newly started pod must get the grace pass")
	}
}

// End-to-end: the crashlooping pod fails the check (the metric the
// externalsecret-nudge auto-heal reads), the stabilized one doesn't.
func TestOnePasswordConnectSyncCrashloopWindow(t *testing.T) {
	now := time.Now()
	live := connSyncPod(now.Add(-time.Hour))
	live.Name = "onepassword-connect-live"
	live.Status.ContainerStatuses = connSyncStatus(corev1.ContainerStatus{
		Name: esConnectSyncContainer, Ready: true, RestartCount: 5,
		State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
			Reason: "CrashLoopBackOff"}},
	})
	stable := connSyncPod(now.Add(-3 * time.Hour))
	stable.Name = "onepassword-connect-stable"
	stable.Status.ContainerStatuses = connSyncStatus(corev1.ContainerStatus{
		Name: esConnectSyncContainer, Ready: true, RestartCount: 7,
		State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
		LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
			FinishedAt: metav1.NewTime(now.Add(-2 * time.Hour))}},
	})
	cs := fake.NewSimpleClientset(live, stable)
	p := testProber(cs)
	p.Now = func() time.Time { return now }
	res := probetest.MustCheck[*onePasswordConnectSyncCheck](t, p).Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatal("live crashloop must fail the check")
	}
	if m := probetest.FindMetric(t, "node_automation_onepassword_connect_sync_unhealthy",
		map[string]string{"namespace": "external-secrets", "pod": "onepassword-connect-live"}); m == nil ||
		m.GetGauge().GetValue() != 1 {
		t.Fatal("unhealthy series missing for the crashlooping pod")
	}
	if probetest.FindMetric(t, "node_automation_onepassword_connect_sync_unhealthy",
		map[string]string{"namespace": "external-secrets", "pod": "onepassword-connect-stable"}) != nil {
		t.Fatal("stabilized pod flagged unhealthy")
	}
}
