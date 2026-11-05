// image_pull_storm_test.go — coverage for the image-pull-storm
// check (W10-GI5): single-namespace vs registry-outage
// classification, fresh-pod fuse, healthy pass.
package clusterhealthprobes

import (
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
	res := p.imagePull.run(ctx)
	if res.pass {
		t.Fatalf("pull backoff must fail: %+v", res)
	}
	if !strings.Contains(res.why, "workload_image_pull_backoff") {
		t.Fatalf("why missing workload detail: %q", res.why)
	}
}

func TestImagePullStormMultiNamespaceIsOutage(t *testing.T) {
	p1 := imagePullWaitingPod("team-a", "web-1", "ImagePullBackOff", "not found", 15*time.Minute)
	p2 := imagePullWaitingPod("team-b", "api-1", "ErrImagePull", "manifest unknown", 20*time.Minute)
	cs := fake.NewSimpleClientset(p1, p2)
	p := testProber(cs)
	res := p.imagePull.run(ctx)
	if res.pass {
		t.Fatalf("multi-namespace pull failures must fail: %+v", res)
	}
	if !strings.Contains(res.why, "cluster_registry_pull_outage") {
		t.Fatalf("why missing outage detail: %q", res.why)
	}
	if m := findMetric(t, "node_automation_registry_pull_outage", map[string]string{}); m == nil ||
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
	res := p.imagePull.run(ctx)
	if res.pass {
		t.Fatalf("registry-rate-limit message must fail: %+v", res)
	}
	if !strings.Contains(res.why, "cluster_registry_pull_outage") {
		t.Fatalf("why missing outage detail: %q", res.why)
	}
}

func TestImagePullStormFreshPodIgnored(t *testing.T) {
	pod := imagePullWaitingPod("team-a", "web-1", "ImagePullBackOff", "pulling", 2*time.Minute)
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	if res := p.imagePull.run(ctx); !res.pass {
		t.Fatalf("fresh pull failure must pass: %+v", res)
	}
}

func TestImagePullStormHealthyPasses(t *testing.T) {
	pod := podWithPhase("team-a", "web-1", corev1.PodRunning, true, time.Hour)
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name:  "app",
		State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
	}}
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	if res := p.imagePull.run(ctx); !res.pass {
		t.Fatalf("healthy pod must pass: %+v", res)
	}
}
