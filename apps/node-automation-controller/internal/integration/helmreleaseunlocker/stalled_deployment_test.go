// stalled_deployment_test.go — coverage for stalledDeployment's
// resolution shapes: the explicit Deployment/<name> token, the
// gone-from-cluster refusal, the release-namespace
// ProgressDeadlineExceeded scan (zero/one/ambiguous), and the
// condition predicate itself.
package helmreleaseunlocker

import (
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	kfake "k8s.io/client-go/kubernetes/fake"
)

// ---------------------------------------------------------------------------
// deploymentProgressDeadlineExceeded — the rollout-gave-up predicate
// ---------------------------------------------------------------------------

func TestDeploymentProgressDeadlineExceeded(t *testing.T) {
	mk := func(conds ...appsv1.DeploymentCondition) *appsv1.Deployment {
		return &appsv1.Deployment{Status: appsv1.DeploymentStatus{Conditions: conds}}
	}
	pde := appsv1.DeploymentCondition{
		Type:   appsv1.DeploymentProgressing,
		Status: corev1.ConditionFalse,
		Reason: "ProgressDeadlineExceeded",
	}

	if !deploymentProgressDeadlineExceeded(mk(pde)) {
		t.Fatal("Progressing=False/ProgressDeadlineExceeded must match")
	}
	// Every field of the signature is load-bearing.
	if deploymentProgressDeadlineExceeded(mk(appsv1.DeploymentCondition{
		Type:   appsv1.DeploymentProgressing,
		Status: corev1.ConditionTrue,
		Reason: "ProgressDeadlineExceeded",
	})) {
		t.Fatal("Progressing=True must not match")
	}
	if deploymentProgressDeadlineExceeded(mk(appsv1.DeploymentCondition{
		Type:   appsv1.DeploymentAvailable,
		Status: corev1.ConditionFalse,
		Reason: "ProgressDeadlineExceeded",
	})) {
		t.Fatal("non-Progressing type must not match")
	}
	if deploymentProgressDeadlineExceeded(mk(appsv1.DeploymentCondition{
		Type:   appsv1.DeploymentProgressing,
		Status: corev1.ConditionFalse,
		Reason: "MinimumReplicasUnavailable",
	})) {
		t.Fatal("other Progressing reason must not match")
	}
	if deploymentProgressDeadlineExceeded(mk()) {
		t.Fatal("no conditions must not match")
	}
}

// ---------------------------------------------------------------------------
// stalledDeployment — resolution shapes
// ---------------------------------------------------------------------------

// hrWithStallMessage builds an HR whose Ready condition carries msg —
// the surface stalledWorkloadRe scans.
func hrWithStallMessage(msg string) *unstructured.Unstructured {
	hr := hrObj("ops", "connect", "v2")
	hrTarget(hr, "onepassword")
	hr.Object["status"] = map[string]any{"conditions": []any{
		map[string]any{
			"type":    "Ready",
			"status":  "False",
			"reason":  "RollbackSucceeded",
			"message": msg,
		},
	}}
	return hr
}

func TestStalledDeploymentExplicitToken(t *testing.T) {
	dep := stalledDeploy("onepassword", "connect", 2)
	cs := kfake.NewSimpleClientset(dep)
	dyn := newDynFake()
	u := newStallUnlocker(cs, dyn, time.Hour, "")

	got, refuse, err := u.stalledDeployment(ctx,
		hrWithStallMessage("failed early due to stalled resources: [Deployment/connect status: 'Failed']"))
	if err != nil || refuse != "" {
		t.Fatalf("stalledDeployment = (%v,%q,%v), want (dep,,nil)", got, refuse, err)
	}
	if got == nil || got.Name != "connect" {
		t.Fatalf("resolved deployment = %+v, want onepassword/connect", got)
	}
}

func TestStalledDeploymentExplicitTokenGone(t *testing.T) {
	cs := kfake.NewSimpleClientset()
	u := newStallUnlocker(cs, newDynFake(), time.Hour, "")

	got, refuse, err := u.stalledDeployment(ctx,
		hrWithStallMessage("stalled resources: [Deployment/ghost status: 'Failed']"))
	if err != nil {
		t.Fatalf("gone workload must refuse, not error: %v", err)
	}
	if got != nil || refuse == "" {
		t.Fatalf("stalledDeployment = (%v,%q), want (nil,refusal)", got, refuse)
	}
}

func TestStalledDeploymentListFallback(t *testing.T) {
	// One ProgressDeadlineExceeded Deployment in the release
	// namespace → resolved without any message token.
	dep := stalledDeploy("onepassword", "connect", 2)
	cs := kfake.NewSimpleClientset(dep)
	u := newStallUnlocker(cs, newDynFake(), time.Hour, "")

	got, refuse, err := u.stalledDeployment(ctx,
		hrWithStallMessage("upgrade retries exhausted — no workload named"))
	if err != nil || refuse != "" {
		t.Fatalf("stalledDeployment = (%v,%q,%v)", got, refuse, err)
	}
	if got == nil || got.Name != "connect" {
		t.Fatalf("fallback resolved %+v, want onepassword/connect", got)
	}
}

func TestStalledDeploymentListFallbackNone(t *testing.T) {
	// A Deployment without the ProgressDeadlineExceeded condition is
	// not a stall candidate → refusal.
	healthy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "onepassword", Name: "connect"},
		Status: appsv1.DeploymentStatus{Conditions: []appsv1.DeploymentCondition{{
			Type:   appsv1.DeploymentProgressing,
			Status: corev1.ConditionTrue,
			Reason: "NewReplicaSetAvailable",
		}}},
	}
	cs := kfake.NewSimpleClientset(healthy)
	u := newStallUnlocker(cs, newDynFake(), time.Hour, "")

	got, refuse, err := u.stalledDeployment(ctx,
		hrWithStallMessage("upgrade retries exhausted — no workload named"))
	if err != nil {
		t.Fatalf("no candidates must refuse, not error: %v", err)
	}
	if got != nil || refuse == "" {
		t.Fatalf("stalledDeployment = (%v,%q), want (nil,refusal)", got, refuse)
	}
}

func TestStalledDeploymentListFallbackAmbiguous(t *testing.T) {
	// Two ProgressDeadlineExceeded Deployments → guessing is not a
	// remediation: refusal naming both candidates.
	a := stalledDeploy("onepassword", "alpha", 2)
	b := stalledDeploy("onepassword", "beta", 2)
	cs := kfake.NewSimpleClientset(a, b)
	u := newStallUnlocker(cs, newDynFake(), time.Hour, "")

	got, refuse, err := u.stalledDeployment(ctx,
		hrWithStallMessage("upgrade retries exhausted — no workload named"))
	if err != nil {
		t.Fatalf("ambiguous candidates must refuse, not error: %v", err)
	}
	if got != nil || refuse == "" {
		t.Fatalf("stalledDeployment = (%v,%q), want (nil,refusal)", got, refuse)
	}
	if !strings.Contains(refuse, "alpha") || !strings.Contains(refuse, "beta") {
		t.Fatalf("refusal should name both candidates: %q", refuse)
	}
}
