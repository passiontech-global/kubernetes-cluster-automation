// linkerd_protocol_detection_stall_test.go — coverage for the
// linkerd-protocol-detection-stall check (W10-NM3): opaque-ports
// heal patch + pod re-roll, skip-inbound coverage, port-set
// parsing.
package nethealth

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"
)

// ---------------------------------------------------------------------------
// W10-NM3 — linkerd-protocol-detection-stall
// ---------------------------------------------------------------------------

func TestLinkerdOpaquePortsHealPatchesTemplateAndDeletesPod(t *testing.T) {
	sts := emptyStatefulSet("apps", "cache")
	pod := meshedPodWithPorts("apps", "cache-0", []int32{6379, 8080}, "", "")
	setPodOwnerStatefulSet(pod, "cache")
	cs := fake.NewSimpleClientset(sts, pod)
	p := testProber(cs)

	res := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("unannotated binary port must fail: %+v", res)
	}
	if !strings.Contains(res.Why, "6379") {
		t.Fatalf("why missing port diagnostics: %q", res.Why)
	}
	got, err := cs.AppsV1().StatefulSets("apps").Get(ctx, "cache", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Spec.Template.Annotations["config.linkerd.io/opaque-ports"] != "6379" {
		t.Fatalf("template opaque-ports = %q, want 6379",
			got.Spec.Template.Annotations["config.linkerd.io/opaque-ports"])
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "cache-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("pod should be deleted after template patch, err=%v", err)
	}
	if m := probetest.FindMetric(t, "node_automation_linkerd_opaque_port_missing",
		map[string]string{"namespace": "apps", "pod": "cache-0", "port": "6379"}); m == nil {
		t.Fatal("opaque-port-missing gauge absent")
	}
}

func TestLinkerdOpaquePortsAnnotatedPasses(t *testing.T) {
	pod := meshedPodWithPorts("apps", "cache-0", []int32{6379}, "6379", "")
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	if res := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("annotated port must pass: %+v", res)
	}
}

func TestLinkerdSkipInboundCoversPort(t *testing.T) {
	pod := meshedPodWithPorts("apps", "cache-0", []int32{6379}, "", "6379")
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	if res := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("skip-inbound-ports must cover the port: %+v", res)
	}
}

func TestLinkerdNonBinaryPortPasses(t *testing.T) {
	pod := meshedPodWithPorts("apps", "web-0", []int32{8080, 9090}, "", "")
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	if res := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("non-binary ports must pass: %+v", res)
	}
}

func TestParsePortSetRanges(t *testing.T) {
	got := parsePortSet("6379, 8000-8002")
	for _, want := range []int{6379, 8000, 8001, 8002} {
		if !got[want] {
			t.Fatalf("port %d missing from %v", want, got)
		}
	}
	if len(got) != 4 {
		t.Fatalf("unexpected ports: %v", got)
	}
}

// meshedPodWithPorts builds a Running meshed pod exposing the given
// container ports, optionally carrying linkerd port annotations.
func meshedPodWithPorts(ns, name string, ports []int32, opaque, skip string) *corev1.Pod {
	pod := probetest.PodWithPhase(ns, name, corev1.PodRunning, true, time.Hour)
	containers := []corev1.Container{{Name: "app"}}
	for _, port := range ports {
		containers[0].Ports = append(containers[0].Ports, corev1.ContainerPort{
			ContainerPort: port,
			Protocol:      corev1.ProtocolTCP,
		})
	}
	containers = append(containers, corev1.Container{Name: "linkerd-proxy"})
	pod.Spec.Containers = containers
	pod.Annotations = map[string]string{}
	if opaque != "" {
		pod.Annotations["config.linkerd.io/opaque-ports"] = opaque
	}
	if skip != "" {
		pod.Annotations["config.linkerd.io/skip-inbound-ports"] = skip
	}
	return pod
}

// setPodOwnerStatefulSet gives the pod a controller ownerRef to a StatefulSet —
// the realistic shape for stateful meshed workloads.
func setPodOwnerStatefulSet(pod *corev1.Pod, stsName string) {
	pod.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "apps/v1",
		Kind:       "StatefulSet",
		Name:       stsName,
		Controller: ptr.To(true),
	}}
}

// emptyStatefulSet builds a bare StatefulSet with an empty pod template —
// the heal target for the linkerd opaque-ports patch.
func emptyStatefulSet(ns, name string) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: appsv1.StatefulSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
			},
		},
	}
}
