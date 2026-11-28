// imagepull_test.go — the image-pull-storm-gate/maintenance-hold-stale stall predicate and cluster
// census: only CURRENT container waiting states count, all three
// container slots are scanned, and the census counts pods and
// distinct namespaces.
package kube

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// pullStalledPod builds a pod with one container status waiting in
// `reason` in the given slot ("" = regular containers).
func pullStalledPod(ns, name, reason, slot string) *corev1.Pod {
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
	st := corev1.ContainerStatus{
		Name: "app",
		State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
			Reason: reason}},
	}
	switch slot {
	case "init":
		p.Status.InitContainerStatuses = []corev1.ContainerStatus{st}
	case "ephemeral":
		p.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{st}
	default:
		p.Status.ContainerStatuses = []corev1.ContainerStatus{st}
	}
	return p
}

func TestImagePullStallReasonSlots(t *testing.T) {
	for _, slot := range []string{"", "init", "ephemeral"} {
		p := pullStalledPod("apps", "p", "ImagePullBackOff", slot)
		if got := ImagePullStallReason(p); got != "ImagePullBackOff" {
			t.Fatalf("slot %q: reason = %q, want ImagePullBackOff", slot, got)
		}
		if !PodImagePullStalled(p) {
			t.Fatalf("slot %q: pod must read as stalled", slot)
		}
	}
}

func TestImagePullStallReasonIgnoresHealthyAndOtherReasons(t *testing.T) {
	// A running container and non-pull waiting reasons are not stalls.
	running := &corev1.Pod{}
	running.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name:  "app",
		State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
	}}
	if got := ImagePullStallReason(running); got != "" {
		t.Fatalf("running container read as stall %q", got)
	}
	crash := pullStalledPod("apps", "p", "CrashLoopBackOff", "")
	if got := ImagePullStallReason(crash); got != "" {
		t.Fatalf("CrashLoopBackOff read as stall %q", got)
	}
	// A RECOVERED pull failure (last termination state only) is not
	// a current stall.
	recovered := &corev1.Pod{}
	recovered.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name: "app",
		LastTerminationState: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
			Reason: "ImagePullBackOff"}},
		State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
	}}
	if got := ImagePullStallReason(recovered); got != "" {
		t.Fatalf("recovered pull failure read as stall %q", got)
	}
}

func TestCountImagePullStalledPods(t *testing.T) {
	cs := fake.NewSimpleClientset(
		pullStalledPod("apps", "a", "ImagePullBackOff", ""),
		pullStalledPod("apps", "b", "ErrImagePull", ""),
		pullStalledPod("db", "c", "ImagePullBackOff", "init"),
		pullStalledPod("db", "healthy", "CrashLoopBackOff", ""),
		pullStalledPod("kube-system", "fine", "", ""),
	)
	pods, namespaces, err := CountImagePullStalledPods(t.Context(), cs)
	if err != nil {
		t.Fatal(err)
	}
	if pods != 3 {
		t.Fatalf("podCount = %d, want 3", pods)
	}
	if namespaces != 2 {
		t.Fatalf("namespaceCount = %d, want 2", namespaces)
	}
}

func outageStalledPod(ns, name, image, reason, msg, slot string) *corev1.Pod {
	p := pullStalledPod(ns, name, reason, slot)
	switch slot {
	case "init":
		p.Spec.InitContainers = []corev1.Container{{Name: "app", Image: image}}
		p.Status.InitContainerStatuses[0].Image = image
		p.Status.InitContainerStatuses[0].State.Waiting.Message = msg
	case "ephemeral":
		p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{
			EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "app", Image: image},
		}}
		p.Status.EphemeralContainerStatuses[0].Image = image
		p.Status.EphemeralContainerStatuses[0].State.Waiting.Message = msg
	default:
		p.Spec.Containers = []corev1.Container{{Name: "app", Image: image}}
		p.Status.ContainerStatuses[0].Image = image
		p.Status.ContainerStatuses[0].State.Waiting.Message = msg
	}
	return p
}

func TestNormalizedRegistryHost(t *testing.T) {
	cases := []struct {
		image string
		want  string
	}{
		{"", ""},
		{"nginx:1.25", "docker.io"},
		{"library/nginx:1.25", "docker.io"},
		{"myorg/myapp@sha256:abcdef", "docker.io"},
		{"docker.io/library/nginx:latest", "docker.io"},
		{"index.docker.io/library/nginx:latest", "docker.io"},
		{"registry-1.docker.io/library/nginx:latest", "docker.io"},
		{"GHCR.IO/org/app:v1", "ghcr.io"},
		{"quay.io/jetstack/cert-manager:v1.14.0", "quay.io"},
		{"localhost:5000/app:dev", "localhost:5000"},
		{"LOCALHOST/app:dev", "localhost"},
		{"LOCALHOST:5000/app:dev", "localhost:5000"},
		{"registry.k8s.io/pause:3.9", "registry.k8s.io"},
		{"registry.k8s.io/pause", "registry.k8s.io"},
		{"myregistry:5000/foo", "myregistry:5000"},
		{"nginx", "docker.io"},
		{"myorg/app:5000", "docker.io"},
		{"registry.internal:5000/team/svc:v2", "registry.internal:5000"},
	}
	for _, tc := range cases {
		if got := NormalizedRegistryHost(tc.image); got != tc.want {
			t.Errorf("NormalizedRegistryHost(%q) = %q, want %q", tc.image, got, tc.want)
		}
	}
}

func TestIsRegistryOutageMessage(t *testing.T) {
	positives := []string{
		"rpc error: code = Unknown desc = failed to pull: HTTP 429",
		`failed to pull image "ghcr.io/org/svc-429:v1": unexpected status: 429 Too Many Requests`,
		"toomanyrequests: You have reached your pull rate limit",
		"429 Too Many Requests",
		"rate limit exceeded",
		"received unexpected HTTP status: 503 Service Unavailable",
		"status=503",
		"(502) Bad Gateway",
		"502 Bad Gateway",
		"504 Gateway Timeout",
		"net/http: TLS handshake timeout",
		"dial tcp 10.0.0.1:443: connect: connection refused",
		"i/o timeout",
		"lookup ghcr.io: no such host",
		"unexpected EOF",
		"read tcp 10.0.0.1:443: EOF",
		"EOF",
	}
	for _, msg := range positives {
		if !IsRegistryOutageMessage(msg) {
			t.Errorf("IsRegistryOutageMessage(%q) = false, want true", msg)
		}
	}
	negatives := []string{
		"",
		"back-off pulling image",
		"manifest for ghcr.io/org/app:badtag not found: manifest unknown",
		"pull access denied, repository does not exist or may require authorization",
		`manifest for ghcr.io/org/app@sha256:429deadbeef5031234567890abcdef502504 not found: manifest unknown`,
		`Failed to pull image "ghcr.io/org/svc-429:v1": manifest unknown`,
		`Failed to pull image "ghcr.io/org/app:503": unauthorized`,
		`Failed to pull image "ghcr.io/org/app:1.429.0": manifest unknown`,
		`Failed to pull image "registry.internal:5030/org/app:v1": unauthorized`,
		`Failed to pull image "ghcr.io/org/videofile:v1": manifest unknown`,
		`Failed to pull image "ghcr.io/org/app-eof:v1": manifest unknown`,
		`Failed to pull image "ghcr.io/org/app:eof": manifest unknown`,
		"lack thereof in repository",
	}
	for _, msg := range negatives {
		if IsRegistryOutageMessage(msg) {
			t.Errorf("IsRegistryOutageMessage(%q) = true, want false", msg)
		}
	}
}

func TestCountImagePullRegistryOutage(t *testing.T) {
	termNow := metav1.Now()
	failedPod := outageStalledPod("infra", "p-failed", "ghcr.io/org/svc:v1", "ImagePullBackOff",
		"503 Service Unavailable", "")
	failedPod.Status.Phase = corev1.PodFailed
	succeededPod := outageStalledPod("infra", "p-done", "ghcr.io/org/svc:v1", "ImagePullBackOff",
		"503 Service Unavailable", "")
	succeededPod.Status.Phase = corev1.PodSucceeded
	deletingPod := outageStalledPod("infra", "p-del", "ghcr.io/org/svc:v1", "ImagePullBackOff",
		"503 Service Unavailable", "")
	deletingPod.DeletionTimestamp = &termNow

	cs := fake.NewSimpleClientset(
		outageStalledPod("apps", "p1", "nginx:1.25", "ImagePullBackOff",
			"toomanyrequests: You have reached your pull rate limit", ""),
		outageStalledPod("jobs", "p2", "library/busybox:latest", "ErrImagePull",
			"429 Too Many Requests", "init"),
		outageStalledPod("jobs", "p3", "docker.io/bitnami/redis:7", "ImagePullBackOff",
			"rate limit exceeded", ""),
		outageStalledPod("infra", "p4", "ghcr.io/org/svc:v1", "ImagePullBackOff",
			"dial tcp 1.2.3.4:443: i/o timeout", ""),
		outageStalledPod("infra", "p5", "ghcr.io/org/other:v1", "ErrImagePull",
			"manifest unknown", ""),
		failedPod,
		succeededPod,
		deletingPod,
	)
	outages, err := CountImagePullRegistryOutage(t.Context(), cs)
	if err != nil {
		t.Fatal(err)
	}
	if len(outages) != 2 {
		t.Fatalf("outages len = %d, want 2 (%+v)", len(outages), outages)
	}
	if outages[0].Registry != "docker.io" || outages[0].PodCount != 3 || outages[0].NamespaceCount != 2 {
		t.Fatalf("outages[0] = %+v, want docker.io 3 pods 2 ns", outages[0])
	}
	if outages[1].Registry != "ghcr.io" || outages[1].PodCount != 1 || outages[1].NamespaceCount != 1 {
		t.Fatalf("outages[1] = %+v, want ghcr.io 1 pod 1 ns", outages[1])
	}
}
