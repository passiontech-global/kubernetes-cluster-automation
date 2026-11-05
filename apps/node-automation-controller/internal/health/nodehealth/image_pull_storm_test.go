// image_pull_storm_test.go — coverage for the image-pull-storm
// check (W10-GI5): single-namespace vs registry-outage
// classification, fresh-pod fuse, healthy pass.
package nodehealth

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestImagePullStormSingleNamespace(t *testing.T) {
	pod := imagePullWaitingPod("team-a", "web-1", "ImagePullBackOff",
		"Back-off pulling image \"registry.example.com/app:v1\"", 15*time.Minute)
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	res := mustCheck[*imagePullStormCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("pull backoff must fail: %+v", res)
	}
	if !strings.Contains(res.Why, "workload_image_pull_backoff") {
		t.Fatalf("why missing workload detail: %q", res.Why)
	}
}

func TestImagePullStormMultiNamespaceIsOutage(t *testing.T) {
	p1 := imagePullWaitingPod("team-a", "web-1", "ImagePullBackOff", "not found", 15*time.Minute)
	p2 := imagePullWaitingPod("team-b", "api-1", "ErrImagePull", "manifest unknown", 20*time.Minute)
	cs := fake.NewSimpleClientset(p1, p2)
	p := testProber(cs)
	res := mustCheck[*imagePullStormCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("multi-namespace pull failures must fail: %+v", res)
	}
	if !strings.Contains(res.Why, "cluster_registry_pull_outage") {
		t.Fatalf("why missing outage detail: %q", res.Why)
	}
	if m := probetest.FindMetric(t, "node_automation_registry_pull_outage", map[string]string{}); m == nil ||
		m.GetGauge().GetValue() != 1 {
		t.Fatalf("outage gauge absent/not 1")
	}
}

func TestImagePullStormRegistryMarkerIsOutage(t *testing.T) {
	// Single namespace but a 429 marker flips it to outage.
	pod := imagePullWaitingPod("team-a", "web-1", "ImagePullBackOff",
		"failed to pull: 429 Too Many Requests", 15*time.Minute)
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	res := mustCheck[*imagePullStormCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("registry-rate-limit message must fail: %+v", res)
	}
	if !strings.Contains(res.Why, "cluster_registry_pull_outage") {
		t.Fatalf("why missing outage detail: %q", res.Why)
	}
}

func TestImagePullStormFreshPodIgnored(t *testing.T) {
	pod := imagePullWaitingPod("team-a", "web-1", "ImagePullBackOff", "pulling", 2*time.Minute)
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	if res := mustCheck[*imagePullStormCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("fresh pull failure must pass: %+v", res)
	}
}

func TestImagePullStormHealthyPasses(t *testing.T) {
	pod := probetest.PodWithPhase("team-a", "web-1", corev1.PodRunning, true, time.Hour)
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name:  "app",
		State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
	}}
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	if res := mustCheck[*imagePullStormCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("healthy pod must pass: %+v", res)
	}
}

// imagePullWaitingPod builds a Pending pod whose container waits in the given
// reason, created `age` ago.
func imagePullWaitingPod(ns, name, reason, message string, age time.Duration) *corev1.Pod {
	pod := probetest.PodWithPhase(ns, name, corev1.PodPending, false, age)
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name: "app",
		State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
			Reason:  reason,
			Message: message,
		}},
	}}
	return pod
}
