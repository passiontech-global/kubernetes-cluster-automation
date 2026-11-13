package deschedulerstormgate

import (
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// image-pull-storm-gate — image-pull storm (storm signal (e))
// ---------------------------------------------------------------------------

// stalledPod builds a pod whose app container is currently waiting
// in `reason` (ImagePullBackOff / ErrImagePull / "" for healthy).
func stalledPod(ns, name, reason string) *corev1.Pod {
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
	if reason != "" {
		p.Status.ContainerStatuses = []corev1.ContainerStatus{{
			Name: "app",
			State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
				Reason:  reason,
				Message: "back-off pulling image"}},
		}}
	}
	return p
}

// Signal (e): stormImagePullMinPods stuck pods gate the descheduler
// exactly like a node storm — rescheduling pods whose images cannot
// land just spreads unrunnable pods across more nodes — and the
// decision annotation records the image-pull-stall reason.
func TestStormGateImagePullStormGates(t *testing.T) {
	objs := []runtime.Object{
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil),
		stalledPod("apps", "a", "ImagePullBackOff"),
		stalledPod("apps", "b", "ImagePullBackOff"),
		stalledPod("apps", "c", "ErrImagePull"),
	}
	cs := fake.NewSimpleClientset(objs...)
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 0 {
		t.Fatalf("image-pull storm must gate the descheduler, replicas=%d", got)
	}
	decision := getDescheduler(t, cs).Annotations[stormGateDecisionAnno]
	if !strings.Contains(decision, "image-pull-stall") ||
		!strings.Contains(decision, "verdict=storm") ||
		!strings.Contains(decision, "imagepull=[") {
		t.Fatalf("decision missing the image-pull-stall signal: %q", decision)
	}
}

// Under the thresholds — 2 stuck pods in ONE namespace — is an
// ordinary broken Deployment, not a storm: the descheduler keeps
// running.
func TestStormGateImagePullUnderThresholdIsClear(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil),
		stalledPod("apps", "a", "ImagePullBackOff"),
		stalledPod("apps", "b", "ErrImagePull"),
	)
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 1 {
		t.Fatalf("under-threshold pull stalls must not gate, replicas=%d", got)
	}
	if decision := getDescheduler(t, cs).Annotations[stormGateDecisionAnno]; strings.Contains(decision, "image-pull-stall") {
		t.Fatalf("under-threshold verdict recorded a storm signal: %q", decision)
	}
}

// The namespace half of the threshold: stuck pods in TWO namespaces
// gate even below stormImagePullMinPods — two unrelated workloads
// failing to pull points at the cluster (registry/network), not one
// bad Deployment.
func TestStormGateImagePullTwoNamespacesGate(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil),
		stalledPod("apps", "a", "ImagePullBackOff"),
		stalledPod("db", "b", "ErrImagePull"),
	)
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDeschedulerReplicas(t, cs); got != 0 {
		t.Fatalf("pull stalls in 2 namespaces must gate, replicas=%d", got)
	}
}

// A pod-list failure aborts the reconcile — never a "clear" verdict
// on blind data (same posture as the node/events list failures).
func TestStormGateImagePullListError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil))
	cs.PrependReactor("list", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake()}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the pod census list fails")
	}
	if got := getDeschedulerReplicas(t, cs); got != 1 {
		t.Fatalf("replicas changed on blind data: %d", got)
	}
}
