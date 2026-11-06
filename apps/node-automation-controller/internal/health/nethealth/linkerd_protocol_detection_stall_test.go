// linkerd_protocol_detection_stall_test.go — coverage for the
// linkerd-protocol-detection-stall check (W10-NM3): opaque-ports
// heal patch + pod re-roll, skip-inbound coverage, port-set
// parsing.
package nethealth

import (
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
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

// W12-P0-6: skip-outbound-ports is the client-side escape — a meshed
// pod INITIATING to a binary port with only that annotation must not
// read as missing (the static gate and VAP both accept it).
func TestLinkerdSkipOutboundCoversPort(t *testing.T) {
	pod := meshedPodWithPorts("apps", "pgbouncer-0", []int32{5432}, "", "")
	pod.Annotations["config.linkerd.io/skip-outbound-ports"] = "5432"
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	if res := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("skip-outbound-ports must cover the port: %+v", res)
	}
}

// The template patch stamps the durable cooldown annotation on the
// WORKLOAD metadata (not the template) — the GitOps-drift detector's
// "we touched this at T" evidence.
func TestLinkerdTemplatePatchStampsWorkload(t *testing.T) {
	dep := emptyDeployment("apps", "web", nil, nil)
	pod := meshedPodWithPorts("apps", "web-abc12-x1", []int32{5432}, "", "")
	setPodOwnerDeployment(pod, "web")
	cs := fake.NewSimpleClientset(dep, pod)
	p := testProber(cs)

	if res := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p).Run(ctx); res.Pass {
		t.Fatalf("unannotated binary port must fail: %+v", res)
	}
	got, err := cs.AppsV1().Deployments("apps").Get(ctx, "web", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Spec.Template.Annotations["config.linkerd.io/opaque-ports"] != "5432" {
		t.Fatalf("template opaque-ports = %q, want 5432",
			got.Spec.Template.Annotations["config.linkerd.io/opaque-ports"])
	}
	stamp, ok := kube.AnnoTime(got, kube.AnnoLastLinkerdOpaquePatch)
	if !ok || time.Since(stamp) > time.Minute {
		t.Fatalf("durable patch stamp = %v (%v), want a fresh RFC3339", stamp, ok)
	}
}

// W12-P0-6: a GitOps-managed (Flux kustomization-labeled) Deployment
// that ALREADY carries the patch stamp yet lost opaque-ports again is
// drift — the check must NOT re-patch, must NOT delete the pod, and
// must emit node_automation_linkerd_gitops_opaque_drift.
func TestLinkerdGitOpsDriftNotRepatch(t *testing.T) {
	dep := emptyDeployment("apps", "web",
		map[string]string{"kustomize.toolkit.fluxcd.io/name": "apps"},
		map[string]string{
			kube.AnnoLastLinkerdOpaquePatch: time.Now().UTC().Format(time.RFC3339),
		})
	pod := meshedPodWithPorts("apps", "web-abc12-x1", []int32{5432}, "", "")
	setPodOwnerDeployment(pod, "web")
	cs := fake.NewSimpleClientset(dep, pod)
	p := testProber(cs)

	res := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("drifted GitOps workload must still fail (ports missing)")
	}
	got, err := cs.AppsV1().Deployments("apps").Get(ctx, "web", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, patched := got.Spec.Template.Annotations["config.linkerd.io/opaque-ports"]; patched {
		t.Fatal("GitOps-managed drifted template was re-patched — revert fight")
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted while GitOps owns the template — rollout fight")
	}
	m := probetest.FindMetric(t, "node_automation_linkerd_gitops_opaque_drift",
		map[string]string{"namespace": "apps", "kind": "deployment", "name": "web"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("drift gauge = %v, want 1", m)
	}
	if !strings.Contains(res.Why, "GitOps") {
		t.Fatalf("finding missing the drift report: %q", res.Why)
	}
}

// The ArgoCD provenance variant of the same drift: tracking-id
// annotation instead of the flux labels.
func TestLinkerdGitOpsDriftArgoCD(t *testing.T) {
	dep := emptyDeployment("apps", "web", nil,
		map[string]string{
			"argocd.argoproj.io/tracking-id": "apps:apps/Deployment:apps/web",
			kube.AnnoLastLinkerdOpaquePatch:  time.Now().UTC().Format(time.RFC3339),
		})
	pod := meshedPodWithPorts("apps", "web-abc12-x1", []int32{5432}, "", "")
	setPodOwnerDeployment(pod, "web")
	cs := fake.NewSimpleClientset(dep, pod)
	p := testProber(cs)

	if res := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("drifted GitOps workload must fail")
	}
	if m := probetest.FindMetric(t, "node_automation_linkerd_gitops_opaque_drift",
		map[string]string{"namespace": "apps", "kind": "deployment", "name": "web"}); m == nil {
		t.Fatal("drift gauge absent for an ArgoCD-tracked workload")
	}
}

// A NON-GitOps workload reverted inside the 6h stamp window is still
// not re-patched (someone else owns the annotation — the window
// bounds the fight), it just does not emit the drift gauge.
func TestLinkerdNonGitOpsRevertHonorsCooldown(t *testing.T) {
	dep := emptyDeployment("apps", "web", nil,
		map[string]string{
			kube.AnnoLastLinkerdOpaquePatch: time.Now().UTC().Format(time.RFC3339),
		})
	pod := meshedPodWithPorts("apps", "web-abc12-x1", []int32{5432}, "", "")
	setPodOwnerDeployment(pod, "web")
	cs := fake.NewSimpleClientset(dep, pod)
	p := testProber(cs)

	if res := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("reverted workload must still fail (ports missing)")
	}
	got, err := cs.AppsV1().Deployments("apps").Get(ctx, "web", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, patched := got.Spec.Template.Annotations["config.linkerd.io/opaque-ports"]; patched {
		t.Fatal("re-patched inside the 6h stamp window")
	}
	if m := probetest.FindMetric(t, "node_automation_linkerd_gitops_opaque_drift",
		map[string]string{"namespace": "apps", "kind": "deployment", "name": "web"}); m != nil {
		t.Fatal("drift gauge emitted for a non-GitOps workload")
	}
}

// A stamp older than the 6h window expires the cooldown — the heal
// retries the template patch once more (bounded: at most one patch
// per window per workload).
func TestLinkerdStaleStampAllowsRepatch(t *testing.T) {
	dep := emptyDeployment("apps", "web",
		map[string]string{"kustomize.toolkit.fluxcd.io/name": "apps"},
		map[string]string{
			kube.AnnoLastLinkerdOpaquePatch: time.Now().Add(-7 * time.Hour).UTC().Format(time.RFC3339),
		})
	pod := meshedPodWithPorts("apps", "web-abc12-x1", []int32{5432}, "", "")
	setPodOwnerDeployment(pod, "web")
	cs := fake.NewSimpleClientset(dep, pod)
	p := testProber(cs)

	if res := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("unannotated binary port must fail")
	}
	got, err := cs.AppsV1().Deployments("apps").Get(ctx, "web", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Spec.Template.Annotations["config.linkerd.io/opaque-ports"] != "5432" {
		t.Fatalf("stale stamp did not allow re-patch: %v", got.Spec.Template.Annotations)
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

// setPodOwnerDeployment gives the pod a controller ownerRef straight
// to a Deployment (skipping the ReplicaSet hop the production path
// also handles — the direct kind branch covers the same verdict).
func setPodOwnerDeployment(pod *corev1.Pod, depName string) {
	pod.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "apps/v1",
		Kind:       "Deployment",
		Name:       depName,
		Controller: ptr.To(true),
	}}
}

// emptyDeployment builds a bare Deployment with the given metadata
// labels/annotations and an empty pod template — the heal target for
// the linkerd opaque-ports patch.
func emptyDeployment(ns, name string, lbls, annos map[string]string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name, Labels: lbls, Annotations: annos,
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
			},
		},
	}
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
