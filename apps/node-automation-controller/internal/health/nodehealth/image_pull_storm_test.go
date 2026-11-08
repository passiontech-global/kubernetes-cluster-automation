// image_pull_storm_test.go — coverage for the image-pull-storm
// check (W10-GI5): first-seen persistence window, single-namespace
// vs registry-outage classification, healthy pass.
package nodehealth

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

func TestImagePullStormSingleNamespace(t *testing.T) {
	pod := imagePullWaitingPod("team-a", "web-1", "ImagePullBackOff",
		"Back-off pulling image \"registry.example.com/app:v1\"", 15*time.Minute)
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	base := time.Now()
	p.Now = func() time.Time { return base }

	// First sighting stamps the first-seen ledger — inside 10m.
	if res := probetest.MustCheck[*imagePullStormCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("first sighting inside the window must pass: %+v", res)
	}
	base = base.Add(11 * time.Minute)
	res := probetest.MustCheck[*imagePullStormCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("pull backoff persisting past the window must fail: %+v", res)
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
	base := time.Now()
	p.Now = func() time.Time { return base }

	probetest.MustCheck[*imagePullStormCheck](t, p).Run(ctx)
	base = base.Add(11 * time.Minute)
	res := probetest.MustCheck[*imagePullStormCheck](t, p).Run(ctx)
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
	// Single namespace but a rate-limit marker flips it to outage.
	pod := imagePullWaitingPod("team-a", "web-1", "ImagePullBackOff",
		"failed to pull: 429 Too Many Requests", 15*time.Minute)
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	base := time.Now()
	p.Now = func() time.Time { return base }

	probetest.MustCheck[*imagePullStormCheck](t, p).Run(ctx)
	base = base.Add(11 * time.Minute)
	res := probetest.MustCheck[*imagePullStormCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("registry-rate-limit message must fail: %+v", res)
	}
	if !strings.Contains(res.Why, "cluster_registry_pull_outage") {
		t.Fatalf("why missing outage detail: %q", res.Why)
	}
}

// Marker precision: a healthy Harbor URL or a bare "429" inside an
// unrelated message must NOT flip the cluster outage — installing
// Harbor is not an outage and a lone number is not rate-limit
// evidence; the precise markers (toomanyrequests / "429 too many
// requests" / proxyconnect tcp) still are.
func TestImagePullStormMarkerPrecision(t *testing.T) {
	quietMessages := []string{
		`back-off pulling image "harbor.example.com/team/app:v1": not found`,
		`pull failed: unexpected 429-byte response body`,
	}
	for _, msg := range quietMessages {
		t.Run(msg, func(t *testing.T) {
			pod := imagePullWaitingPod("team-a", "web-1",
				"ImagePullBackOff", msg, 15*time.Minute)
			cs := fake.NewSimpleClientset(pod)
			p := testProber(cs)
			base := time.Now()
			p.Now = func() time.Time { return base }
			probetest.MustCheck[*imagePullStormCheck](t, p).Run(ctx)
			base = base.Add(11 * time.Minute)
			res := probetest.MustCheck[*imagePullStormCheck](t, p).Run(ctx)
			if res.Pass {
				t.Fatalf("single-namespace pull failure must still fail: %+v", res)
			}
			if strings.Contains(res.Why, "cluster_registry_pull_outage") {
				t.Fatalf("quiet message %q flipped the cluster outage: %q", msg, res.Why)
			}
			if m := probetest.FindMetric(t, "node_automation_registry_pull_outage",
				map[string]string{}); m != nil && m.GetGauge().GetValue() == 1 {
				t.Fatalf("quiet message %q set the outage gauge", msg)
			}
			t.Cleanup(func() {
				registryPullOutageGauge.Set(0)
			})
		})
	}
	loudMessages := []string{
		"toomanyrequests: You have reached your pull rate limit",
		"Get \"https://proxy\": proxyconnect tcp: dial tcp: connection refused",
	}
	for _, msg := range loudMessages {
		t.Run(msg, func(t *testing.T) {
			pod := imagePullWaitingPod("team-a", "web-1",
				"ImagePullBackOff", msg, 15*time.Minute)
			cs := fake.NewSimpleClientset(pod)
			p := testProber(cs)
			base := time.Now()
			p.Now = func() time.Time { return base }
			probetest.MustCheck[*imagePullStormCheck](t, p).Run(ctx)
			base = base.Add(11 * time.Minute)
			res := probetest.MustCheck[*imagePullStormCheck](t, p).Run(ctx)
			if !strings.Contains(res.Why, "cluster_registry_pull_outage") {
				t.Fatalf("outage marker %q missed: %q", msg, res.Why)
			}
			t.Cleanup(func() {
				registryPullOutageGauge.Set(0)
			})
		})
	}
}

func TestImagePullStormOldPodNewStormInsideWindow(t *testing.T) {
	// The failure the first-seen ledger fixes: an hours-old pod
	// whose container only JUST fell into ImagePullBackOff — pod
	// age used to satisfy the 10m floor instantly. The storm itself
	// must persist the window.
	pod := imagePullWaitingPod("team-a", "web-1", "ImagePullBackOff", "pulling", time.Hour)
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	base := time.Now()
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*imagePullStormCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("old pod with a fresh pull failure must pass: %+v", res)
	}
	base = base.Add(11 * time.Minute)
	if res := probetest.MustCheck[*imagePullStormCheck](t, p).Run(ctx); res.Pass {
		t.Fatalf("storm persisting past the window must fail: %+v", res)
	}
}

func TestImagePullStormRecoveredContainerReArms(t *testing.T) {
	// A container that leaves the pull-failure state drops its
	// ledger entry on Prune — the next storm starts a fresh window,
	// it does not inherit the old stamp.
	pod := imagePullWaitingPod("team-a", "web-1", "ImagePullBackOff", "pulling", time.Hour)
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	base := time.Now()
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*imagePullStormCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("first sighting must pass: %+v", res)
	}
	// Container recovers, then storms again — the re-armed window
	// must hold it quiet past the ORIGINAL first-seen.
	pod.Status.ContainerStatuses[0].State = corev1.ContainerState{
		Running: &corev1.ContainerStateRunning{}}
	if _, err := cs.CoreV1().Pods("team-a").UpdateStatus(ctx, pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	base = base.Add(9 * time.Minute)
	if res := probetest.MustCheck[*imagePullStormCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("recovered pod must pass: %+v", res)
	}
	pod.Status.ContainerStatuses[0].State = corev1.ContainerState{
		Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff", Message: "pulling"}}
	if _, err := cs.CoreV1().Pods("team-a").UpdateStatus(ctx, pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	base = base.Add(2 * time.Minute)
	if res := probetest.MustCheck[*imagePullStormCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("re-armed storm inside its own window must pass: %+v", res)
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
	if res := probetest.MustCheck[*imagePullStormCheck](t, p).Run(ctx); !res.Pass {
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
