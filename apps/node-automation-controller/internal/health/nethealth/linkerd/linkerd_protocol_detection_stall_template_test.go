// linkerd_protocol_detection_stall_template_test.go — owner-kind
// dispatch coverage for patchLinkerdTemplate: the Job/CronJob patch
// shapes, the fail-closed census/get/patch misses, and the
// patchTemplatePorts coverage union.
package linkerd

import (
	"errors"
	"maps"
	"testing"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// patchPod builds a bare pod carrying one controller ownerRef of the
// given kind/name — the dispatch key patchLinkerdTemplate switches on.
func patchPod(ns, name, ownerKind, ownerName string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: ns, Name: name,
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "apps/v1", Kind: ownerKind,
			Name: ownerName, Controller: ptr.To(true),
		}},
	}}
}

// patchTemplate drives one patchLinkerdTemplate call against missing
// port 5432 and returns its (covered, patched) verdict.
func patchTemplate(t *testing.T, chk *linkerdProtocolDetectionStallCheck,
	pod *corev1.Pod, cs *fake.Clientset) (bool, bool) {
	t.Helper()
	return chk.patchLinkerdTemplate(ctx, logr.Discard(), pod,
		[]int{5432}, time.Now(), &probefw.SweepReport{}, map[string][]string{})
}

// A pod with no controller ownerRef resolves no workload — fail
// closed: no coverage claim, no patch, and the caller must not
// delete the pod.
func TestPatchLinkerdTemplateNoOwnerRef(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "bare"}}
	cs := fake.NewSimpleClientset()
	p := testProber(cs)
	chk := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p)

	covered, patched := patchTemplate(t, chk, pod, cs)
	if covered || patched {
		t.Fatalf("ownerless pod resolved a template patch: covered=%v patched=%v", covered, patched)
	}
}

// The Job branch patches spec.template (not jobTemplate) and stamps
// the durable cooldown on the Job's own metadata.
func TestPatchLinkerdTemplateJob(t *testing.T) {
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "etl"},
		Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "etl"}},
		}}}
	pod := patchPod("apps", "etl-abc", "Job", "etl")
	cs := fake.NewSimpleClientset(job)
	p := testProber(cs)
	chk := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p)

	covered, patched := patchTemplate(t, chk, pod, cs)
	if !covered || !patched {
		t.Fatalf("job template patch: covered=%v patched=%v, want both", covered, patched)
	}
	got, err := cs.BatchV1().Jobs("apps").Get(ctx, "etl", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Spec.Template.Annotations["config.linkerd.io/opaque-ports"] != "5432" {
		t.Fatalf("job template opaque-ports = %v", got.Spec.Template.Annotations)
	}
	if _, ok := kube.AnnoTime(got, kube.AnnoLastLinkerdOpaquePatch); !ok {
		t.Fatal("durable patch stamp missing on the Job")
	}
}

// The CronJob branch nests the annotation under
// spec.jobTemplate.spec.template — the one payload shape that differs
// from every other workload kind.
func TestPatchLinkerdTemplateCronJob(t *testing.T) {
	cj := &batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "nightly"},
		Spec: batchv1.CronJobSpec{JobTemplate: batchv1.JobTemplateSpec{
			Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "nightly"}},
			}}}}}
	pod := patchPod("apps", "nightly-abc", "CronJob", "nightly")
	cs := fake.NewSimpleClientset(cj)
	p := testProber(cs)
	chk := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p)

	covered, patched := patchTemplate(t, chk, pod, cs)
	if !covered || !patched {
		t.Fatalf("cronjob template patch: covered=%v patched=%v, want both", covered, patched)
	}
	got, err := cs.BatchV1().CronJobs("apps").Get(ctx, "nightly", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	annos := got.Spec.JobTemplate.Spec.Template.Annotations
	if annos["config.linkerd.io/opaque-ports"] != "5432" {
		t.Fatalf("cronjob jobTemplate opaque-ports = %v", annos)
	}
	if _, ok := kube.AnnoTime(got, kube.AnnoLastLinkerdOpaquePatch); !ok {
		t.Fatal("durable patch stamp missing on the CronJob")
	}
}

// An owner kind outside the dispatch table (bare pod, custom
// controller) resolves nothing — fail closed.
func TestPatchLinkerdTemplateUnknownOwnerKind(t *testing.T) {
	pod := patchPod("apps", "x-abc", "Widget", "w1")
	cs := fake.NewSimpleClientset()
	p := testProber(cs)
	chk := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p)

	covered, patched := patchTemplate(t, chk, pod, cs)
	if covered || patched {
		t.Fatalf("unknown owner kind resolved a patch: covered=%v patched=%v", covered, patched)
	}
}

// ReplicaSet hop failures all fail closed: the RS itself unreadable,
// the RS carrying no controller owner, and the RS owned by a kind
// that is neither Deployment nor Rollout.
func TestPatchLinkerdTemplateReplicaSetHopFailures(t *testing.T) {
	rsNoOwner := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: "apps", Name: "web-rs"}}
	rsForeign := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: "apps", Name: "web-rs2",
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "apps/v1", Kind: "Foo",
			Name: "bar", Controller: ptr.To(true),
		}}}}

	cases := []struct {
		name string
		pod  *corev1.Pod
		objs []runtime.Object
	}{
		{"rs-get-fails", patchPod("apps", "p1", "ReplicaSet", "ghost-rs"), nil},
		{"rs-no-controller", patchPod("apps", "p2", "ReplicaSet", "web-rs"),
			[]runtime.Object{rsNoOwner}},
		{"rs-foreign-owner", patchPod("apps", "p3", "ReplicaSet", "web-rs2"),
			[]runtime.Object{rsForeign}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset(tc.objs...)
			p := testProber(cs)
			chk := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p)
			covered, patched := patchTemplate(t, chk, tc.pod, cs)
			if covered || patched {
				t.Fatalf("%s resolved a patch: covered=%v patched=%v", tc.name, covered, patched)
			}
		})
	}
}

// A Rollout-owned ReplicaSet whose Rollout is absent from the dynamic
// census fails closed — the get went through the per-sweep snapshot,
// so "gone" reads exactly like a deleted workload.
func TestPatchLinkerdTemplateRolloutGoneFromCensus(t *testing.T) {
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: "apps", Name: "api-rs",
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "argoproj.io/v1alpha1", Kind: "Rollout",
			Name: "api", UID: "uid-ro", Controller: ptr.To(true),
		}}}}
	pod := patchPod("apps", "api-x1", "ReplicaSet", "api-rs")
	cs := fake.NewSimpleClientset(rs)
	kinds := maps.Clone(testutil.DynListKinds())
	kinds[kube.GVRArgoRollout] = "RolloutList"
	p := testProberDyn(cs, testutil.NewFakeDyn(kinds))
	chk := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p)

	covered, patched := patchTemplate(t, chk, pod, cs)
	if covered || patched {
		t.Fatalf("missing rollout resolved a patch: covered=%v patched=%v", covered, patched)
	}
}

// Every workload census miss fails closed the same way: the owner
// resolves to a kind whose snapshot census carries no such object.
func TestPatchLinkerdTemplateCensusMisses(t *testing.T) {
	cases := []struct {
		name      string
		ownerKind string
		ownerName string
	}{
		{"deployment", "Deployment", "ghost-dep"},
		{"statefulset", "StatefulSet", "ghost-sts"},
		{"daemonset", "DaemonSet", "ghost-ds"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset()
			p := testProber(cs)
			chk := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p)
			pod := patchPod("apps", "p-"+tc.name, tc.ownerKind, tc.ownerName)
			covered, patched := patchTemplate(t, chk, pod, cs)
			if covered || patched {
				t.Fatalf("%s census miss resolved a patch: covered=%v patched=%v",
					tc.name, covered, patched)
			}
		})
	}
}

// A failed Deployment census (list error) fails the heal closed —
// the snapshot read is the only Deployment source, so an apiserver
// flap must not read as "workload gone".
func TestPatchLinkerdTemplateCensusError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "deployments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	p := testProber(cs)
	chk := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p)

	pod := patchPod("apps", "p1", "Deployment", "web")
	covered, patched := patchTemplate(t, chk, pod, cs)
	if covered || patched {
		t.Fatalf("failed census resolved a patch: covered=%v patched=%v", covered, patched)
	}
}

// The same census failure one hop down: pod → ReplicaSet →
// Deployment, with the Deployment LIST erroring.
func TestPatchLinkerdTemplateRSDeploymentCensusError(t *testing.T) {
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: "apps", Name: "web-rs",
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "apps/v1", Kind: "Deployment",
			Name: "web", UID: "uid-web", Controller: ptr.To(true),
		}}}}
	pod := patchPod("apps", "web-x1", "ReplicaSet", "web-rs")
	cs := fake.NewSimpleClientset(rs)
	cs.PrependReactor("list", "deployments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	p := testProber(cs)
	chk := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p)

	covered, patched := patchTemplate(t, chk, pod, cs)
	if covered || patched {
		t.Fatalf("failed census resolved a patch: covered=%v patched=%v", covered, patched)
	}
}

// A patch refusal (RBAC Forbidden until the rollout lands patch on
// the kind) fails closed — covered=false keeps the pod running,
// since a pod-side annotation cannot reach a live proxy.
func TestPatchLinkerdTemplatePatchRefused(t *testing.T) {
	dep := emptyDeployment("apps", "web", nil, nil)
	pod := patchPod("apps", "web-x1", "Deployment", "web")
	cs := fake.NewSimpleClientset(dep)
	cs.PrependReactor("patch", "deployments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("forbidden")
		})
	p := testProber(cs)
	chk := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p)

	covered, patched := patchTemplate(t, chk, pod, cs)
	if covered || patched {
		t.Fatalf("refused patch resolved coverage: covered=%v patched=%v", covered, patched)
	}
}

// A Job whose GET fails (deleted between census and patch) fails
// closed the same way.
func TestPatchLinkerdTemplateJobGetFails(t *testing.T) {
	pod := patchPod("apps", "etl-x1", "Job", "ghost-job")
	cs := fake.NewSimpleClientset()
	p := testProber(cs)
	chk := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p)

	covered, patched := patchTemplate(t, chk, pod, cs)
	if covered || patched {
		t.Fatalf("missing job resolved a patch: covered=%v patched=%v", covered, patched)
	}
}

// ---------------------------------------------------------------------------
// patchTemplatePorts — coverage union and the already-covered verdict
// ---------------------------------------------------------------------------

// skip-inbound-ports already covering every missing port reports
// covered WITHOUT patching — the pod only needs its restart (the
// workload controller's, on the patched=true path's sibling).
func TestPatchTemplatePortsSkipInboundAlreadyCovers(t *testing.T) {
	dep := emptyDeployment("apps", "web", nil, nil)
	cs := fake.NewSimpleClientset(dep)
	p := testProber(cs)
	chk := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p)

	existing := map[string]string{
		"config.linkerd.io/skip-inbound-ports": "5432",
	}
	covered, patched := chk.patchTemplatePorts(ctx, logr.Discard(), dep,
		"deployment", "apps", "web", existing, []int{5432},
		false, time.Now(), &probefw.SweepReport{}, map[string][]string{})
	if !covered || patched {
		t.Fatalf("skip-inbound-covered template: covered=%v patched=%v, want covered only", covered, patched)
	}
	patches := 0
	for _, a := range cs.Actions() {
		if a.GetVerb() == "patch" {
			patches++
		}
	}
	if patches != 0 {
		t.Fatalf("covered template issued %d patches, want 0", patches)
	}
}

// skip-outbound-ports is the client-side escape — a template carrying
// it for the missing port is covered the same way.
func TestPatchTemplatePortsSkipOutboundAlreadyCovers(t *testing.T) {
	dep := emptyDeployment("apps", "web", nil, nil)
	cs := fake.NewSimpleClientset(dep)
	p := testProber(cs)
	chk := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p)

	existing := map[string]string{
		"config.linkerd.io/skip-outbound-ports": "5432",
	}
	covered, patched := chk.patchTemplatePorts(ctx, logr.Discard(), dep,
		"deployment", "apps", "web", existing, []int{5432},
		false, time.Now(), &probefw.SweepReport{}, map[string][]string{})
	if !covered || patched {
		t.Fatalf("skip-outbound-covered template: covered=%v patched=%v, want covered only", covered, patched)
	}
}

// A partial cover merges, never replaces: the existing opaque-ports
// value survives the patch alongside the newly missing port — the
// annotation is a union, not a rewrite.
func TestPatchTemplatePortsMergesExistingCoverage(t *testing.T) {
	dep := emptyDeployment("apps", "web", nil, nil)
	cs := fake.NewSimpleClientset(dep)
	p := testProber(cs)
	chk := probetest.MustCheck[*linkerdProtocolDetectionStallCheck](t, p)

	existing := map[string]string{
		"config.linkerd.io/opaque-ports": "6379",
	}
	covered, patched := chk.patchTemplatePorts(ctx, logr.Discard(), dep,
		"deployment", "apps", "web", existing, []int{5432},
		false, time.Now(), &probefw.SweepReport{}, map[string][]string{})
	if !covered || !patched {
		t.Fatalf("partial cover patch: covered=%v patched=%v, want both", covered, patched)
	}
	got, err := cs.AppsV1().Deployments("apps").Get(ctx, "web", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	set := parsePortSet(got.Spec.Template.Annotations["config.linkerd.io/opaque-ports"])
	for _, want := range []int{6379, 5432} {
		if !set[want] {
			t.Fatalf("merged opaque-ports %q lost port %d",
				got.Spec.Template.Annotations["config.linkerd.io/opaque-ports"], want)
		}
	}
}
