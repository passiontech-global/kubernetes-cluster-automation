package zombiesidecarreaper

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
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

func (s *zsrShutdownProbe) fn(_ context.Context, podIP, _ string) error {
	s.calls = append(s.calls, podIP)
	return s.err
}

func zsrReaper(cs *fake.Clientset, probe *zsrShutdownProbe) *zombieSidecarReaper {
	return &zombieSidecarReaper{cs: cs, now: time.Now,
		shutdownFn: probe.fn, poked: map[string]bool{}}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// The two-step reap: cycle 1 POSTs /shutdown and keeps the pod;
// a pod still qualifying next cycle is deleted and counted.
func TestZombieSidecarGraceThenDelete(t *testing.T) {
	testutil.CleanupMetric(t, metrics.ZombieSidecarPodsReapedTotal, "jobs")

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
	testutil.CleanupMetric(t, metrics.ZombieSidecarPodsReapedTotal, "jobs")

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

// Native sidecars live in spec.initContainers (restartPolicy:Always)
// with status in initContainerStatuses — an istio/linkerd proxy
// there must count for liveness exactly like the injected regular
// container does.
func TestZombieSidecarNativeSidecarQualifies(t *testing.T) {
	always := corev1.ContainerRestartPolicyAlways
	native := zsrPod("jobs", "native-istio", 10*time.Minute, 0)
	native.Spec.Containers = []corev1.Container{{Name: "app"}}
	native.Spec.InitContainers = []corev1.Container{
		{Name: "istio-proxy", RestartPolicy: &always}}
	native.Status.ContainerStatuses = native.Status.ContainerStatuses[:1] // app only
	native.Status.InitContainerStatuses = []corev1.ContainerStatus{{
		Name: "istio-proxy",
		State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{
			StartedAt: metav1.NewTime(time.Now().Add(-time.Hour))}},
	}}

	// A finished plain init container must not disqualify an
	// otherwise-good zombie (normal pods run init containers to
	// completion before the app starts).
	withInit := zsrPod("jobs", "init-done", 10*time.Minute, 0)
	withInit.Spec.InitContainers = []corev1.Container{{Name: "init-db"}}
	withInit.Status.InitContainerStatuses = []corev1.ContainerStatus{{
		Name: "init-db",
		State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
			ExitCode: 0, FinishedAt: metav1.NewTime(time.Now().Add(-time.Hour))}},
	}}

	// A non-mesh always-restart init container still Running is not
	// the zombie shape this reaper owns — fail closed.
	other := zsrPod("jobs", "other-native", 10*time.Minute, 0)
	other.Spec.Containers = []corev1.Container{{Name: "app"}}
	other.Spec.InitContainers = []corev1.Container{
		{Name: "custom-agent", RestartPolicy: &always}}
	other.Status.ContainerStatuses = other.Status.ContainerStatuses[:1]
	other.Status.InitContainerStatuses = []corev1.ContainerStatus{{
		Name: "custom-agent",
		State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{
			StartedAt: metav1.NewTime(time.Now().Add(-time.Hour))}},
	}}

	cs := fake.NewSimpleClientset(native, withInit, other)
	probe := &zsrShutdownProbe{}
	r := zsrReaper(cs, probe)
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, p := range []*corev1.Pod{native, withInit} {
		if !r.poked[zombieKey(p)] {
			t.Fatalf("pod %s (native sidecar) qualifies but was not poked", p.Name)
		}
	}
	if r.poked[zombieKey(other)] {
		t.Fatal("non-mesh always-restart init was poked — fail closed violated")
	}
	if len(probe.calls) != 2 {
		t.Fatalf("/shutdown called %d times, want 2", len(probe.calls))
	}
}

// The reap delete carries a UID precondition — the zombie we vetted
// is the object deleted, never a same-named replacement.
func TestZombieSidecarDeleteUIDPrecondition(t *testing.T) {
	pod := zsrPod("jobs", "job-x-abcde", 10*time.Minute, 0)
	pod.Status.PodIP = "" // no admin endpoint → straight to delete
	cs := fake.NewSimpleClientset(pod)
	var gotUID *types.UID
	cs.PrependReactor("delete", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			opts := a.(ktesting.DeleteAction).GetDeleteOptions()
			if opts.Preconditions != nil {
				gotUID = opts.Preconditions.UID
			}
			return false, nil, nil // fall through to the tracker
		})
	r := zsrReaper(cs, &zsrShutdownProbe{})
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if gotUID == nil || *gotUID != pod.UID {
		t.Fatalf("delete missing the UID precondition: %v", gotUID)
	}
	if zsrPodExists(t, cs, "jobs", "job-x-abcde") {
		t.Fatal("zombie pod not reaped")
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

	if err := zombieSidecarShutdown(ctx, "::1", "linkerd-proxy"); err != nil {
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

// BUG-C1 — an exit-0 pod whose Job is NOT Complete yet must survive
// the forced-delete paths: deleting a still-Running pod makes the
// job-controller recreate it and re-run the Job.
func TestZombieSidecarJobNotCompleteKept(t *testing.T) {
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{
		Namespace: "jobs", Name: "job-x"}} // Status.Succeeded = 0 — not complete
	cs := fake.NewSimpleClientset(zsrPod("jobs", "job-x-abcde", 10*time.Minute, 0), job)
	probe := &zsrShutdownProbe{err: errors.New("connection refused")}
	r := zsrReaper(cs, probe)
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !zsrPodExists(t, cs, "jobs", "job-x-abcde") {
		t.Fatal("exit-0 pod deleted while its Job was still incomplete — would re-run the Job")
	}
}

// Same shape but the Job already counted the success — the forced
// delete is safe and fires.
func TestZombieSidecarJobCompleteReaped(t *testing.T) {
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Namespace: "jobs", Name: "job-x"},
		Status:     batchv1.JobStatus{Succeeded: 1}}
	cs := fake.NewSimpleClientset(zsrPod("jobs", "job-x-abcde", 10*time.Minute, 0), job)
	probe := &zsrShutdownProbe{err: errors.New("connection refused")}
	r := zsrReaper(cs, probe)
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if zsrPodExists(t, cs, "jobs", "job-x-abcde") {
		t.Fatal("pod kept although its Job already completed")
	}
}

// A non-zero app exit needs no Job gate — job-controller retries are
// the Job's own semantics.
func TestZombieSidecarNonZeroExitReaped(t *testing.T) {
	cs := fake.NewSimpleClientset(zsrPod("jobs", "job-x-abcde", 10*time.Minute, 1))
	probe := &zsrShutdownProbe{err: errors.New("connection refused")}
	r := zsrReaper(cs, probe)
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if zsrPodExists(t, cs, "jobs", "job-x-abcde") {
		t.Fatal("non-zero-exit pod kept — Job gate must not apply")
	}
}

// W10-FIX3 — a failed direct pod-IP shutdown falls back to the
// apiserver pods/<name>:<port>/proxy subresource: the pod is poked
// (one graceful cycle) instead of deleted on the spot, and the next
// cycle still reaps it when it keeps qualifying.
func TestZombieSidecarProxyFallbackOnDirectFailure(t *testing.T) {
	testutil.CleanupMetric(t, metrics.ZombieSidecarPodsReapedTotal, "jobs")

	pod := zsrPod("jobs", "job-x-abcde", 10*time.Minute, 0)
	cs := fake.NewSimpleClientset(pod)
	probe := &zsrShutdownProbe{err: errors.New("dial tcp 10.0.0.9:4191: i/o timeout")}
	proxyCalls := 0
	r := &zombieSidecarReaper{cs: cs, now: time.Now,
		shutdownFn: probe.fn,
		proxyFn: func(_ context.Context, p *corev1.Pod, sidecar string) error {
			proxyCalls++
			if p.Name != "job-x-abcde" || p.Namespace != "jobs" ||
				sidecar != "linkerd-proxy" {
				t.Errorf("proxyFn args = %s/%s %q", p.Namespace, p.Name, sidecar)
			}
			return nil
		},
		poked: map[string]bool{}, tried: map[string]bool{}}

	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if proxyCalls != 1 {
		t.Fatalf("proxy fallback calls = %d, want 1", proxyCalls)
	}
	if !zsrPodExists(t, cs, "jobs", "job-x-abcde") {
		t.Fatal("pod deleted on the graceful-proxy cycle — must survive one shutdown")
	}
	if !r.poked[zombieKey(pod)] {
		t.Fatal("pod not recorded in poked ledger after proxy shutdown")
	}

	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if zsrPodExists(t, cs, "jobs", "job-x-abcde") {
		t.Fatal("pod still alive after the graceful cycle — should be reaped")
	}
	if proxyCalls != 1 {
		t.Fatal("proxy shutdown retried on the delete cycle")
	}
}

// A pod with no podIP cannot take the direct admin call at all —
// the proxy fallback is the only graceful path and must run.
func TestZombieSidecarProxyFallbackNoPodIP(t *testing.T) {
	pod := zsrPod("jobs", "job-x-abcde", 10*time.Minute, 0)
	pod.Status.PodIP = ""
	cs := fake.NewSimpleClientset(pod)
	probe := &zsrShutdownProbe{}
	proxyCalls := 0
	r := zsrReaper(cs, probe)
	r.proxyFn = func(_ context.Context, _ *corev1.Pod, _ string) error {
		proxyCalls++
		return nil
	}
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(probe.calls) != 0 {
		t.Fatalf("direct shutdown called %d times with no podIP", len(probe.calls))
	}
	if proxyCalls != 1 {
		t.Fatalf("proxy fallback calls = %d, want 1", proxyCalls)
	}
	if !zsrPodExists(t, cs, "jobs", "job-x-abcde") {
		t.Fatal("pod deleted on the graceful cycle")
	}
}

// W10-FIX3 — backoffLimit==0 Jobs spawn no replacement pod, so an
// all-exit-0 zombie may be reaped even while job.Status.Succeeded is
// still 0 — but only AFTER a shutdown attempt already ran.
func TestZombieSidecarBackoffLimitZeroReap(t *testing.T) {
	zero := int32(0)
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Namespace: "jobs", Name: "job-x"},
		Spec:       batchv1.JobSpec{BackoffLimit: &zero},
		// Status.Succeeded stays 0 — the zombie pod never let the
		// Job controller count the completion.
	}

	t.Run("graceful-then-reap", func(t *testing.T) {
		testutil.CleanupMetric(t, metrics.ZombieSidecarPodsReapedTotal, "jobs")
		cs := fake.NewSimpleClientset(
			zsrPod("jobs", "job-x-abcde", 10*time.Minute, 0), job.DeepCopy())
		r := zsrReaper(cs, &zsrShutdownProbe{})
		if err := r.run(ctx); err != nil {
			t.Fatal(err)
		}
		if !zsrPodExists(t, cs, "jobs", "job-x-abcde") {
			t.Fatal("pod reaped on the graceful cycle")
		}
		if err := r.run(ctx); err != nil {
			t.Fatal(err)
		}
		if zsrPodExists(t, cs, "jobs", "job-x-abcde") {
			t.Fatal("backoffLimit=0 zombie kept after the shutdown cycle")
		}
	})

	t.Run("failed-shutdown-prior-cycle", func(t *testing.T) {
		testutil.CleanupMetric(t, metrics.ZombieSidecarPodsReapedTotal, "jobs")
		cs := fake.NewSimpleClientset(
			zsrPod("jobs", "job-x-abcde", 10*time.Minute, 0), job.DeepCopy())
		r := zsrReaper(cs, &zsrShutdownProbe{err: errors.New("refused")})
		r.proxyFn = func(_ context.Context, _ *corev1.Pod, _ string) error {
			return errors.New("proxy refused")
		}
		// Cycle 1: both shutdown paths failed but NO prior attempt
		// exists — the pod is kept (the plan's "prior cycle" rule).
		if err := r.run(ctx); err != nil {
			t.Fatal(err)
		}
		if !zsrPodExists(t, cs, "jobs", "job-x-abcde") {
			t.Fatal("reaped on first sight — shutdown attempt must precede")
		}
		// Cycle 2: a shutdown attempt ran last cycle — reap now.
		if err := r.run(ctx); err != nil {
			t.Fatal(err)
		}
		if zsrPodExists(t, cs, "jobs", "job-x-abcde") {
			t.Fatal("backoffLimit=0 zombie kept after a prior shutdown attempt")
		}
	})

	t.Run("nonzero-backofflimit-still-kept", func(t *testing.T) {
		three := int32(3)
		j := job.DeepCopy()
		j.Spec.BackoffLimit = &three
		cs := fake.NewSimpleClientset(
			zsrPod("jobs", "job-x-abcde", 10*time.Minute, 0), j)
		r := zsrReaper(cs, &zsrShutdownProbe{})
		for i := 0; i < 3; i++ {
			if err := r.run(ctx); err != nil {
				t.Fatal(err)
			}
		}
		if !zsrPodExists(t, cs, "jobs", "job-x-abcde") {
			t.Fatal("backoffLimit=3 zombie reaped — Job could respawn it")
		}
	})
}

// The proxy fallback must hit the real apiserver path
// POST /api/v1/namespaces/<ns>/pods/<name>:<port>/proxy/<path> —
// verified against a clientset pointed at httptest (the fake
// clientset's RESTClient is a typed nil).
func TestZombieSidecarProxyShutdownRequest(t *testing.T) {
	var gotMethod, gotPath string
	cs := testutil.ProbeClientset(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		w.WriteHeader(http.StatusOK)
	})
	r := &zombieSidecarReaper{cs: cs}
	p := zsrPod("jobs", "job-x-abcde", time.Minute, 0)
	if err := r.proxyShutdown(ctx, p, "linkerd-proxy"); err != nil {
		t.Fatalf("proxyShutdown: %v", err)
	}
	want := "/api/v1/namespaces/jobs/pods/job-x-abcde:4191/proxy/shutdown"
	if gotMethod != http.MethodPost || gotPath != want {
		t.Fatalf("proxy request = %s %s, want POST %s", gotMethod, gotPath, want)
	}
}

// BUG-C1 — the shutdown endpoint is selected per sidecar: istio gets
// :15000/quitquitquit, linkerd :4191/shutdown.
func TestZombieSidecarShutdownTargets(t *testing.T) {
	istio := zombieSidecarShutdownTargets["istio-proxy"]
	if istio.port != 15000 || istio.path != "/quitquitquit" {
		t.Fatalf("istio target = %+v, want :15000/quitquitquit", istio)
	}
	linkerd := zombieSidecarShutdownTargets["linkerd-proxy"]
	if linkerd.port != 4191 || linkerd.path != "/shutdown" {
		t.Fatalf("linkerd target = %+v, want :4191/shutdown", linkerd)
	}
	// An istio zombie pod gets poked through the istio endpoint.
	p := zsrPod("jobs", "istio-job-abcde", 10*time.Minute, 0)
	p.Spec.Containers[1] = corev1.Container{Name: "istio-proxy"}
	p.Status.ContainerStatuses[1] = corev1.ContainerStatus{
		Name: "istio-proxy",
		State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{
			StartedAt: metav1.NewTime(time.Now().Add(-time.Hour))}},
	}
	cs := fake.NewSimpleClientset(p)
	var gotSidecar string
	r := &zombieSidecarReaper{cs: cs, now: time.Now,
		shutdownFn: func(_ context.Context, _ string, sidecar string) error {
			gotSidecar = sidecar
			return nil
		}, poked: map[string]bool{}}
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if gotSidecar != "istio-proxy" {
		t.Fatalf("shutdown called with sidecar %q, want istio-proxy", gotSidecar)
	}
}
