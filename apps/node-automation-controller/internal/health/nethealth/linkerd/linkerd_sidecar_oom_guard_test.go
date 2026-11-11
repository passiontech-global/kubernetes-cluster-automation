package linkerd

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

// ---------------------------------------------------------------------------
// linkerd-init-deadlock — linkerdInitSidecarDeadlock
// ---------------------------------------------------------------------------

// deadlockPod builds a Pending pod with the injected init order
// (app init → linkerd-init → linkerd-proxy) where linkerd-init has
// completed exit 0, the app init reads Init:CrashLoopBackOff with
// `restarts`, and the proxy is still PodInitializing.
func deadlockPod(ns, name string, restarts int32) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Status: corev1.PodStatus{
			Phase: corev1.PodPending,
			InitContainerStatuses: []corev1.ContainerStatus{
				{
					Name:         "mesh-setup",
					RestartCount: restarts,
					State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
						Reason: initWaitReasonCrashLoop}},
				},
				{
					Name: linkerdInitContainer,
					State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
						ExitCode: 0}},
				},
				{
					Name: linkerdProxyContainer,
					State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
						Reason: "PodInitializing"}},
				},
			},
		},
	}
}

// TestLinkerdInitDeadlockShape — each leg of the shape predicate:
// pending phase, completed linkerd-init, proxy after the app inits,
// stuck waiting reason, offender pick.
func TestLinkerdInitDeadlockShape(t *testing.T) {
	// Full shape holds; offender is the worst-crashing app init.
	pod := deadlockPod("apps", "web-1", 3)
	offender, ok := linkerdInitDeadlockShape(pod)
	if !ok || offender.Name != "mesh-setup" || offender.RestartCount != 3 {
		t.Fatalf("shape=(%v,%+v), want mesh-setup/3", ok, offender)
	}
	// Not pending → no.
	pod.Status.Phase = corev1.PodRunning
	if _, ok := linkerdInitDeadlockShape(pod); ok {
		t.Fatal("running pod must not match")
	}
	// linkerd-init NOT completed → no.
	pod = deadlockPod("apps", "web-2", 3)
	pod.Status.InitContainerStatuses[1].State = corev1.ContainerState{
		Terminated: &corev1.ContainerStateTerminated{ExitCode: 1}}
	if _, ok := linkerdInitDeadlockShape(pod); ok {
		t.Fatal("incomplete linkerd-init must not match")
	}
	// No linkerd-proxy init → no.
	pod = deadlockPod("apps", "web-3", 3)
	pod.Status.InitContainerStatuses = pod.Status.InitContainerStatuses[:2]
	if _, ok := linkerdInitDeadlockShape(pod); ok {
		t.Fatal("meshless pod must not match")
	}
	// No stuck init reason → no.
	pod = deadlockPod("apps", "web-4", 3)
	pod.Status.InitContainerStatuses[0].State = corev1.ContainerState{
		Waiting: &corev1.ContainerStateWaiting{Reason: "PodInitializing"}}
	if _, ok := linkerdInitDeadlockShape(pod); ok {
		t.Fatal("non-backoff init must not match")
	}
	// Init:Error counts as stuck too.
	pod.Status.InitContainerStatuses[0].State = corev1.ContainerState{
		Waiting: &corev1.ContainerStateWaiting{Reason: initWaitReasonError}}
	if _, ok := linkerdInitDeadlockShape(pod); !ok {
		t.Fatal("Init:Error must match")
	}
	// linkerd-init ordered AFTER the proxy is not the injected order.
	pod = deadlockPod("apps", "web-5", 3)
	inits := pod.Status.InitContainerStatuses
	inits[1], inits[2] = inits[2], inits[1]
	if _, ok := linkerdInitDeadlockShape(pod); ok {
		t.Fatal("reordered init chain must not match")
	}
}

// TestLinkerdInitDeadlockFlagsAndClears — a pod past the 5m window
// with a crash-looping app init flags the gauge + Warning Event; a
// pod inside the window stays quiet; a pod that leaves the state
// has its series reconciled away.
func TestLinkerdInitDeadlockFlagsAndClears(t *testing.T) {
	old := deadlockPod("apps", "web-old", 2)
	young := deadlockPod("apps", "web-young", 2)
	healthy := deadlockPod("apps", "web-ok", 0) // no restarts, no log → quiet
	cs := fake.NewSimpleClientset(old, young, healthy)
	p := testProber(cs)
	chk := probetest.MustCheck[*linkerdSidecarOOMCheck](t, p)

	// Seed the old pod's signature past the 5m window (the young one
	// stays unstamped → first sight).
	chk.deadlockSince.Seed("apps/web-old", time.Now().Add(-10*time.Minute))
	res := chk.Run(ctx)
	if res.Pass || res.Why == "" {
		t.Fatalf("deadlocked pod must fail the check: %+v", res)
	}
	if !linkerdInitDeadlockGauge.DeleteLabelValues("apps", "web-old") {
		t.Fatal("missing deadlock series for web-old")
	}
	if linkerdInitDeadlockGauge.DeleteLabelValues("apps", "web-young") ||
		linkerdInitDeadlockGauge.DeleteLabelValues("apps", "web-ok") {
		t.Fatal("in-window or quiet pod flagged")
	}
	evs, err := cs.EventsV1().Events("apps").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs.Items) != 1 || evs.Items[0].Reason != linkerdInitDeadlockEventReason ||
		evs.Items[0].Type != corev1.EventTypeWarning {
		t.Fatalf("warning events = %d, want 1 LinkerdInitSidecarOrderDeadlock", len(evs.Items))
	}

	// The young pod crosses the window on its next sweep.
	chk.deadlockSince.Seed("apps/web-young", time.Now().Add(-6*time.Minute))
	if res := chk.Run(ctx); res.Pass ||
		!linkerdInitDeadlockGauge.DeleteLabelValues("apps", "web-young") {
		t.Fatalf("young pod must flag once persisted: %+v", res)
	}

	// A pod that leaves the deadlock state has its series reconciled
	// away (the gauge ledger deletes it) and its window re-arms;
	// web-young still deadlocks and keeps its series.
	old.Status.Phase = corev1.PodRunning
	if _, err := cs.CoreV1().Pods("apps").UpdateStatus(ctx, old,
		metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	res = chk.Run(ctx)
	if res.Pass ||
		linkerdInitDeadlockGauge.DeleteLabelValues("apps", "web-old") {
		t.Fatalf("healed pod's series must be reconciled away: %+v", res)
	}
	if !linkerdInitDeadlockGauge.DeleteLabelValues("apps", "web-young") {
		t.Fatal("still-deadlocked pod lost its series")
	}
}

// Regression (linkerd-init-deadlock): the 5m first-seen window must mature ACROSS
// sweeps — the sweep-end ledger prune keys on the shape-match set,
// not the fired set. Pre-fix, the prune deleted the stamp every
// sweep and the detector could never fire without a test seeder.
func TestLinkerdInitDeadlockWindowMaturesAcrossSweeps(t *testing.T) {
	pod := deadlockPod("apps", "web", 2)
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	chk := probetest.MustCheck[*linkerdSidecarOOMCheck](t, p)

	base := time.Now()
	probetest.FreezeNow(chk.Deps, base)
	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("first sweep stamps the signature — must stay quiet: %+v", res)
	}
	if linkerdInitDeadlockGauge.DeleteLabelValues("apps", "web") {
		t.Fatal("first sweep must not flag (window not matured)")
	}

	// A later sweep with the shape still holding crosses the window
	// on the stamp laid by the FIRST sweep — no seeding allowed.
	probetest.FreezeNow(chk.Deps, base.Add(6*time.Minute))
	res := chk.Run(ctx)
	if res.Pass || res.Why == "" {
		t.Fatalf("deadlock must flag once the window matured: %+v", res)
	}
	if !linkerdInitDeadlockGauge.DeleteLabelValues("apps", "web") {
		t.Fatal("missing deadlock series after window matured")
	}
}
