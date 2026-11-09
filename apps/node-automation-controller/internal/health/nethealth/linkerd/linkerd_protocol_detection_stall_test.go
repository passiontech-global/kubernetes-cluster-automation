// linkerd_protocol_detection_stall_test.go — coverage for the
// linkerd-protocol-detection-stall check (W10-NM3): opaque-ports
// heal patch + pod re-roll, skip-inbound coverage, port-set
// parsing.
package linkerd

import (
	"maps"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// W10-NM3 — linkerd-protocol-detection-stall
// ---------------------------------------------------------------------------

// The heal patches the workload template and leaves the pod running —
// the workload controller's rolling update replaces every pod with the
// corrected config itself; no mass pod delete.
func TestLinkerdOpaquePortsHealPatchesTemplateAndRolls(t *testing.T) {
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
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "cache-0", metav1.GetOptions{}); err != nil {
		t.Fatalf("pod must NOT be mass-deleted — the controller rolls it: %v", err)
	}
	if m := probetest.FindMetric(t, "node_automation_linkerd_opaque_port_missing",
		map[string]string{"namespace": "apps", "pod": "cache-0", "port": "6379"}); m == nil {
		t.Fatal("opaque-port-missing gauge absent")
	}
}

// A template that ALREADY covers the ports (patched earlier, pre-rollout
// pod still running) deletes the pod — the restart is the heal, and the
// bookkeeping annotation lands only once the delete is delivered.
func TestLinkerdOpaquePortsCoveredTemplateDeletesPod(t *testing.T) {
	sts := emptyStatefulSet("apps", "cache")
	sts.Spec.Template.Annotations = map[string]string{
		"config.linkerd.io/opaque-ports": "6379",
	}
	pod := meshedPodWithPorts("apps", "cache-0", []int32{6379, 8080}, "", "")
	setPodOwnerStatefulSet(pod, "cache")
	cs := fake.NewSimpleClientset(sts, pod)
	p := testProber(cs)

	res := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("stale pre-rollout pod must still fail: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "cache-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("covered-template pod should be re-rolled, err=%v", err)
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

// W16-G1 — a Rollout-owned ReplicaSet resolves to the parent Rollout:
// the opaque-ports merge-patch lands on the Rollout's pod template via
// the dynamic client, with the same durable stamp on the Rollout.
func TestLinkerdTemplatePatchPatchesRollout(t *testing.T) {
	pod := meshedPodWithPorts("apps", "api-abc12-x1", []int32{5432}, "", "")
	pod.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "apps/v1", Kind: "ReplicaSet",
		Name: "api-abc12", Controller: ptr.To(true)}}
	rollout := map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Rollout",
		"metadata":   map[string]any{"namespace": "apps", "name": "api"},
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": "api"}},
			},
		},
	}
	kinds := maps.Clone(testutil.DynListKinds())
	kinds[kube.GVRArgoRollout] = "RolloutList"
	dyn := testutil.NewFakeDyn(kinds,
		&unstructured.Unstructured{Object: rollout})
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: "apps", Name: "api-abc12",
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "argoproj.io/v1alpha1", Kind: "Rollout",
			Name: "api", UID: "uid-rollout", Controller: ptr.To(true)}},
	}}
	cs := fake.NewSimpleClientset(pod, rs)
	p := testProberDyn(cs, dyn)

	if res := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p).Run(ctx); res.Pass {
		t.Fatalf("unannotated Rollout binary port must fail: %+v", res)
	}
	got, err := dyn.Resource(kube.GVRArgoRollout).Namespace("apps").
		Get(ctx, "api", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	annos, _, _ := unstructured.NestedStringMap(got.Object,
		"spec", "template", "metadata", "annotations")
	if annos["config.linkerd.io/opaque-ports"] != "5432" {
		t.Fatalf("Rollout template opaque-ports = %v, want 5432", annos)
	}
	if _, ok := kube.AnnoTime(got, kube.AnnoLastLinkerdOpaquePatch); !ok {
		t.Fatal("durable patch stamp missing on the Rollout")
	}
}

// setPodOwnerReplicaSet gives the pod a controller ownerRef to a
// ReplicaSet — the production shape for Deployment pods (the RS hop
// patchLinkerdTemplate resolves to its parent Deployment).
func setPodOwnerReplicaSet(pod *corev1.Pod, rsName string) {
	pod.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "apps/v1",
		Kind:       "ReplicaSet",
		Name:       rsName,
		Controller: ptr.To(true),
	}}
}

func replicaSetOf(ns, name, depName string) *appsv1.ReplicaSet {
	return &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: ns, Name: name,
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "apps/v1", Kind: "Deployment",
			Name: depName, UID: types.UID("uid-" + depName), Controller: ptr.To(true)}},
	}}
}

// Two stalled pods of ONE Deployment in the same sweep: the first
// lands the template patch and stamps the controller-keyed cooldown —
// the second must be refused at that cooldown, spending exactly ONE
// budget token and issuing exactly ONE patch. Without the stamp the
// second pod passed the un-stamped cooldown, spent a second token and
// re-PATCHed the Deployment from the snapshot's stale pre-write copy.
func TestLinkerdOpaquePortsSecondStalledPodSpendsOneToken(t *testing.T) {
	heal.ConfigureBudget(2, time.Hour)
	t.Cleanup(func() { heal.ConfigureBudget(0, 0) })

	dep := emptyDeployment("apps", "web", nil, nil)
	podA := meshedPodWithPorts("apps", "web-abc12-x1", []int32{5432}, "", "")
	setPodOwnerDeployment(podA, "web")
	podB := meshedPodWithPorts("apps", "web-abc12-x2", []int32{5432}, "", "")
	setPodOwnerDeployment(podB, "web")
	cs := fake.NewSimpleClientset(dep, podA, podB)
	p := testProber(cs)
	chk := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p)

	// Under a sweep snapshot the Deployment census memoizes — the
	// serial sweep reads no apiserver echo of pod A's patch, exactly
	// the production shape this pins.
	sweepCtx := probefw.WithSweepSnapshot(ctx)
	if res := chk.Run(sweepCtx); res.Pass {
		t.Fatalf("stalled pods must fail: %+v", res)
	}
	patches := 0
	for _, a := range cs.Actions() {
		if a.GetVerb() == "patch" && a.GetResource().Resource == "deployments" {
			patches++
		}
	}
	if patches != 1 {
		t.Fatalf("deployment patches = %d, want exactly 1 — the second pod must ride the stamped cooldown", patches)
	}
	if _, ok := chk.Heals.Last(probefw.SelfHealKey(
		CheckNameLinkerdOpaqueStall, "apps/web")); !ok {
		t.Fatal("patched path must stamp the controller-keyed cooldown")
	}
}

// The in-memory mirror: the second stalled pod rides a DIFFERENT
// ReplicaSet of the same Deployment (the mid-rollout two-RS shape) —
// a different controller key evades the stamped cooldown, so the
// mirrored template annotation must make patchTemplatePorts report
// the template covered WITHOUT a second patch, re-rolling only the
// stale pod.
func TestLinkerdOpaquePortsMirrorCoversSecondReplicaSet(t *testing.T) {
	dep := emptyDeployment("apps", "web", nil, nil)
	podA := meshedPodWithPorts("apps", "web-abc12-x1", []int32{5432}, "", "")
	setPodOwnerReplicaSet(podA, "web-abc12")
	podB := meshedPodWithPorts("apps", "web-def34-x1", []int32{5432}, "", "")
	setPodOwnerReplicaSet(podB, "web-def34")
	cs := fake.NewSimpleClientset(dep,
		replicaSetOf("apps", "web-abc12", "web"),
		replicaSetOf("apps", "web-def34", "web"),
		podA, podB)
	p := testProber(cs)

	// Under a sweep snapshot the Deployment census memoizes — the
	// second RS's pod must be judged against the mirrored in-memory
	// annotation, not a fresh apiserver read.
	sweepCtx := probefw.WithSweepSnapshot(ctx)
	if res := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p).Run(sweepCtx); res.Pass {
		t.Fatalf("stalled pods must fail: %+v", res)
	}
	patches := 0
	for _, a := range cs.Actions() {
		if a.GetVerb() == "patch" && a.GetResource().Resource == "deployments" {
			patches++
		}
	}
	if patches != 1 {
		t.Fatalf("deployment patches = %d, want exactly 1 — the mirrored annotation must cover the second RS's pod", patches)
	}
	if _, err := cs.CoreV1().Pods("apps").
		Get(ctx, podB.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("stale second-RS pod should be re-rolled on the covered template, err=%v", err)
	}
	if _, err := cs.CoreV1().Pods("apps").
		Get(ctx, podA.Name, metav1.GetOptions{}); err != nil {
		t.Fatalf("the patch-path pod must stay running (workload controller rolls it): %v", err)
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
