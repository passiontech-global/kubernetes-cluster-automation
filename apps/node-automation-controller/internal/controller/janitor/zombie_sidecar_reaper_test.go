package janitor

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

// ---------------------------------------------------------------------------
// Builders (zsr-prefixed)
// ---------------------------------------------------------------------------

func zsrJobOwner() metav1.OwnerReference {
	return metav1.OwnerReference{Kind: "Job", Name: "job-x"}
}

// zsrPod builds a Running Job pod with one app container (terminated
// `termAgo` ago, exit `exitCode`) and one linkerd-proxy sidecar still
// Running.
func zsrPod(ns, name string, termAgo time.Duration, exitCode int32) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name, UID: types.UID("uid-" + name),
			OwnerReferences:   []metav1.OwnerReference{zsrJobOwner()},
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{
				{Name: "app"},
				{Name: "linkerd-proxy"},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			PodIP: "10.0.0.9",
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name: "app",
					State: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{
							ExitCode:   exitCode,
							FinishedAt: metav1.NewTime(time.Now().Add(-termAgo)),
						},
					},
				},
				{
					Name: "linkerd-proxy",
					State: corev1.ContainerState{
						Running: &corev1.ContainerStateRunning{
							StartedAt: metav1.NewTime(time.Now().Add(-time.Hour)),
						},
					},
				},
			},
		},
	}
	return p
}

func zsrPodExists(t *testing.T, cs *fake.Clientset, ns, name string) bool {
	t.Helper()
	_, err := cs.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
	return err == nil
}

type zsrShutdownProbe struct {
	calls []string
	err   error
}

func (s *zsrShutdownProbe) fn(_ context.Context, podIP string) error {
	s.calls = append(s.calls, podIP)
	return s.err
}

func zsrReaper(cs *fake.Clientset, probe *zsrShutdownProbe) *zombieSidecarReaper {
	return &zombieSidecarReaper{cs: cs, nowFn: time.Now,
		shutdownFn: probe.fn, poked: map[string]bool{}}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// The two-step reap: cycle 1 POSTs /shutdown and keeps the pod;
// a pod still qualifying next cycle is deleted and counted.
func TestZombieSidecarGraceThenDelete(t *testing.T) {
	metrics.ZombieSidecarPodsReapedTotal.DeleteLabelValues("jobs")
	t.Cleanup(func() { metrics.ZombieSidecarPodsReapedTotal.DeleteLabelValues("jobs") })

	cs := fake.NewSimpleClientset(zsrPod("jobs", "job-x-abcde", 10*time.Minute, 0))
	probe := &zsrShutdownProbe{}
	r := zsrReaper(cs, probe)

	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(probe.calls) != 1 || probe.calls[0] != "10.0.0.9" {
		t.Fatalf("/shutdown calls = %v, want [10.0.0.9]", probe.calls)
	}
	if !zsrPodExists(t, cs, "jobs", "job-x-abcde") {
		t.Fatal("pod deleted on the graceful cycle — must survive one /shutdown")
	}

	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if zsrPodExists(t, cs, "jobs", "job-x-abcde") {
		t.Fatal("pod still alive after the graceful cycle — should be reaped")
	}
	if got := ptestutil.ToFloat64(
		metrics.ZombieSidecarPodsReapedTotal.WithLabelValues("jobs")); got != 1 {
		t.Fatalf("reaped counter = %v, want 1", got)
	}
	if len(probe.calls) != 1 {
		t.Fatal("/shutdown called again on the delete cycle — should go straight to reap")
	}
}

// A failed /shutdown call deletes immediately — graceful is
// unreachable so there is nothing to wait a cycle for.
func TestZombieSidecarShutdownFailureDeletesNow(t *testing.T) {
	metrics.ZombieSidecarPodsReapedTotal.DeleteLabelValues("jobs")
	t.Cleanup(func() { metrics.ZombieSidecarPodsReapedTotal.DeleteLabelValues("jobs") })

	cs := fake.NewSimpleClientset(zsrPod("jobs", "job-x-abcde", 10*time.Minute, 0))
	probe := &zsrShutdownProbe{err: errors.New("connection refused")}
	r := zsrReaper(cs, probe)

	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if zsrPodExists(t, cs, "jobs", "job-x-abcde") {
		t.Fatal("pod survived a failed /shutdown — should delete immediately")
	}
	if got := ptestutil.ToFloat64(
		metrics.ZombieSidecarPodsReapedTotal.WithLabelValues("jobs")); got != 1 {
		t.Fatalf("reaped counter = %v, want 1", got)
	}
}

// A pod honoring /shutdown exits within seconds — the next cycle sees
// no Running zombie and prunes the ledger instead of deleting.
func TestZombieSidecarHonoredShutdownNotReaped(t *testing.T) {
	cs := fake.NewSimpleClientset(zsrPod("jobs", "job-x-abcde", 10*time.Minute, 0))
	probe := &zsrShutdownProbe{}
	r := zsrReaper(cs, probe)

	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	// Simulate the sidecar exiting: pod leaves phase Running.
	p, err := cs.CoreV1().Pods("jobs").Get(ctx, "job-x-abcde", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p.Status.Phase = corev1.PodSucceeded
	if _, err := cs.CoreV1().Pods("jobs").UpdateStatus(ctx, p, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !zsrPodExists(t, cs, "jobs", "job-x-abcde") {
		t.Fatal("pod deleted after honoring /shutdown")
	}
	if len(r.poked) != 0 {
		t.Fatal("poked ledger kept an entry for a pod that exited")
	}
}

// Qualification matrix — every clause must hold or the pod is left
// alone and /shutdown is never even attempted.
func TestZombieSidecarQualification(t *testing.T) {
	base := zsrPod("jobs", "z", 10*time.Minute, 0)

	notJob := zsrPod("jobs", "not-job", 10*time.Minute, 0)
	notJob.OwnerReferences = nil

	notRunning := zsrPod("jobs", "not-running", 10*time.Minute, 0)
	notRunning.Status.Phase = corev1.PodSucceeded

	freshTerm := zsrPod("jobs", "fresh-term", 2*time.Minute, 0)

	appAlive := zsrPod("jobs", "app-alive", 10*time.Minute, 0)
	appAlive.Status.ContainerStatuses[0].State = corev1.ContainerState{
		Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(time.Now().Add(-time.Hour))}}

	sidecarDead := zsrPod("jobs", "sidecar-dead", 10*time.Minute, 0)
	sidecarDead.Status.ContainerStatuses[1].State = corev1.ContainerState{
		Terminated: &corev1.ContainerStateTerminated{
			ExitCode: 0, FinishedAt: metav1.NewTime(time.Now().Add(-time.Hour))}}

	// Non-zero exit + restartPolicy Never is still a terminal app
	// exit — qualifies.
	failedApp := zsrPod("jobs", "failed-app", 10*time.Minute, 1)

	// Non-zero exit + OnFailure: the kubelet restarts the container —
	// the Terminated status is a blip, not a zombie.
	restartable := zsrPod("jobs", "restartable", 10*time.Minute, 1)
	restartable.Spec.RestartPolicy = corev1.RestartPolicyOnFailure

	// A second app container still Running means the job has not
	// actually finished — the pod is not a zombie.
	twoApps := zsrPod("jobs", "two-apps", 10*time.Minute, 0)
	twoApps.Spec.Containers = append(twoApps.Spec.Containers,
		corev1.Container{Name: "app2"})
	twoApps.Status.ContainerStatuses = append(twoApps.Status.ContainerStatuses,
		corev1.ContainerStatus{
			Name: "app2",
			State: corev1.ContainerState{
				Running: &corev1.ContainerStateRunning{
					StartedAt: metav1.NewTime(time.Now().Add(-time.Hour))}}})

	// Already terminating — a delete is in flight and the reaper
	// must not pile on.
	terminating := zsrPod("jobs", "terminating", 10*time.Minute, 0)
	termAt := metav1.NewTime(time.Now())
	terminating.DeletionTimestamp = &termAt

	cs := fake.NewSimpleClientset(
		base, notJob, notRunning, freshTerm, appAlive, sidecarDead,
		failedApp, restartable, twoApps, terminating)
	probe := &zsrShutdownProbe{}
	r := zsrReaper(cs, probe)
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}

	// Only the qualifying pods got poked.
	wantPoked := map[string]bool{
		zombieKey(base):      true,
		zombieKey(failedApp): true,
	}
	for _, p := range []*corev1.Pod{base, notJob, notRunning, freshTerm,
		appAlive, sidecarDead, failedApp, restartable, twoApps, terminating} {
		_, poked := r.poked[zombieKey(p)]
		if wantPoked[zombieKey(p)] && !poked {
			t.Fatalf("pod %s qualifies but was not poked", p.Name)
		}
		if !wantPoked[zombieKey(p)] && poked {
			t.Fatalf("pod %s does NOT qualify but was poked", p.Name)
		}
	}
	if len(probe.calls) != 2 {
		t.Fatalf("/shutdown called %d times, want 2 (qualifying pods only)", len(probe.calls))
	}
}

// The /shutdown URL must bracket IPv6 podIPs — fmt's %s:%d produces
// "http://::1:4191/", which is unparseable.
func TestZombieSidecarShutdownIPv6(t *testing.T) {
	l, err := net.Listen("tcp", "[::1]:4191")
	if err != nil {
		t.Skipf("IPv6 loopback :4191 unavailable: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/shutdown" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}))
	srv.Listener = l
	srv.Start()
	defer srv.Close()

	if err := zombieSidecarShutdown(ctx, "::1"); err != nil {
		t.Fatalf("IPv6 /shutdown failed: %v", err)
	}
}

// A pod list failure is a real run error.
func TestZombieSidecarPodListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("api down")
	})
	r := zsrReaper(cs, &zsrShutdownProbe{})
	if err := r.run(ctx); err == nil {
		t.Fatal("expected error when the pod list fails")
	}
}
