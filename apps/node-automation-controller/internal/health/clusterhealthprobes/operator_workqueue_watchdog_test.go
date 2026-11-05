// operator_workqueue_watchdog_test.go — W7-C2/W10-CP3 coverage
// for the operator-workqueue-watchdog target list completeness and
// the never-reconciled stuck predicates.
package clusterhealthprobes

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

// ---------------------------------------------------------------------------
// W7-C2 — operator watchdog expansion
// ---------------------------------------------------------------------------

// The watchdog must cover the original five plus the W7-C2 additions
// and the W10-CP3 expansion — notification-controller IS a target
// again but carries ZERO resources: its v1beta3 Alert/Provider/
// Receiver objects are static (no reconciler writes status on them),
// so no stuck signature can ever be accurate — the entry exists for
// lease liveness parity only — and never a duplicate name (a dup
// would share a first-seen keyspace and double-report).
func TestOperatorWatchdogTargetsComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, op := range operatorTargets {
		if seen[op.name] {
			t.Fatalf("duplicate operator target %q", op.name)
		}
		seen[op.name] = true
	}
	if len(operatorTargets) != 23 {
		t.Fatalf("operatorTargets = %d, want 23", len(operatorTargets))
	}
	for _, want := range []string{
		"source-controller", "cert-manager",
		"external-secrets", "rabbitmq-cluster-operator", "keda-operator",
		"argocd-operator", "kargo-controller", "everest-operator",
		"shipwright-build-controller",
		// W10-CP3 additions.
		"notification-controller", "node-healthcheck-operator",
		"self-node-remediation-operator",
		"percona-xtradb-cluster-operator", "percona-postgresql-operator",
		"percona-server-mongodb-operator", "fluent-operator",
		"tekton-pipelines-controller", "shipwright-operator",
	} {
		if !seen[want] {
			t.Fatalf("missing operator target %q", want)
		}
	}
	// notification-controller may only ever watch the Lease — any
	// CR resource on it would resurrect the static-object false
	// positive the W7-C2 incident fix removed.
	for _, op := range operatorTargets {
		if op.name == "notification-controller" && len(op.resources) != 0 {
			t.Fatalf("notification-controller must carry no CR resources, got %d",
				len(op.resources))
		}
	}
}

// The two new never-reconciled predicates: empty status.conditions
// reads stuck, any condition reads healthy; an absent/empty
// status.phase reads stuck, any phase reads healthy.
func TestOperatorStuckPredicateShapes(t *testing.T) {
	bare := shUnstructured("cert-manager.io/v1", "Certificate", "cm", "c", 1, 0)
	if !noStatusConditions(bare) {
		t.Fatal("Certificate with no status.conditions must read stuck")
	}
	_ = unstructured.SetNestedSlice(bare.Object,
		[]any{map[string]any{"type": "Ready", "status": "False"}},
		"status", "conditions")
	if noStatusConditions(bare) {
		t.Fatal("Certificate carrying conditions must not read stuck")
	}

	argocd := shUnstructured("argoproj.io/v1beta1", "ArgoCD", "cd", "arg", 1, 0)
	if !emptyStatusPhase(argocd) {
		t.Fatal("ArgoCD with no status.phase must read stuck")
	}
	_ = unstructured.SetNestedField(argocd.Object, "Available", "status", "phase")
	if emptyStatusPhase(argocd) {
		t.Fatal("ArgoCD with a phase must not read stuck")
	}
}

// A new watchdog target end-to-end: source-controller renewing its
// Lease while a GitRepository sits unreconciled past the window →
// frozen gauge + leader pod deleted.
func TestCheckOperatorWorkqueuesSourceControllerHeals(t *testing.T) {
	metrics.OperatorWorkqueueFrozen.DeleteLabelValues("source-controller", kcmReasonStaleGen)
	t.Cleanup(func() {
		metrics.OperatorWorkqueueFrozen.DeleteLabelValues("source-controller", kcmReasonStaleGen)
	})
	base := time.Now()
	leader := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "flux-system", Name: "source-controller-7d9f",
		UID:    types.UID("sc-uid-1"),
		Labels: map[string]string{"app": "source-controller"},
	}}
	cs := fake.NewSimpleClientset(
		shLease("flux-system", "source-controller-leader-election",
			"source-controller-7d9f_3f2a1", 2*time.Second, base),
		leader)
	stuck := shUnstructured("source.toolkit.fluxcd.io/v1", "GitRepository",
		"apps", "repo", 5, 3)
	p := testProberDyn(cs, shOpDyn(stuck))
	p.now = func() time.Time { return base }
	mustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen["source-controller/gitrepositories/apps/repo"] = base.Add(-time.Hour)

	if res := mustCheck[*operatorWorkqueueCheck](t, p).run(ctx); res.pass {
		t.Fatal("stuck gitrepository with a renewing lease must FAIL")
	}
	if v, _ := shOpFrozenGauge(t, "source-controller", kcmReasonStaleGen); v != 1 {
		t.Fatalf("frozen gauge = %v, want 1", v)
	}
	if _, err := cs.CoreV1().Pods("flux-system").
		Get(ctx, "source-controller-7d9f", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("leader pod must be deleted, err=%v", err)
	}
}

// A cert-manager Certificate never reconciled (no status.conditions)
// freezes under the no_status_conditions reason.
func TestCheckOperatorWorkqueuesCertManagerNoConditions(t *testing.T) {
	metrics.OperatorWorkqueueFrozen.DeleteLabelValues("cert-manager", opReasonNoConditions)
	t.Cleanup(func() {
		metrics.OperatorWorkqueueFrozen.DeleteLabelValues("cert-manager", opReasonNoConditions)
	})
	base := time.Now()
	cs := fake.NewSimpleClientset(
		// cert-manager elects leaders in kube-system (helm chart
		// default global.leaderElection.namespace).
		shLease("kube-system", "cert-manager-controller",
			"cert-manager-abc_uid", 2*time.Second, base))
	stuck := shUnstructured("cert-manager.io/v1", "Certificate", "apps", "tls", 1, 0)
	p := testProberDyn(cs, shOpDyn(stuck))
	p.now = func() time.Time { return base }
	mustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen["cert-manager/certificates/apps/tls"] = base.Add(-time.Hour)

	if res := mustCheck[*operatorWorkqueueCheck](t, p).run(ctx); res.pass {
		t.Fatal("never-reconciled Certificate must FAIL")
	}
	if v, _ := shOpFrozenGauge(t, "cert-manager", opReasonNoConditions); v != 1 {
		t.Fatalf("frozen gauge = %v, want 1", v)
	}
}

// A shipwright-operator ShipwrightBuild never reconciled (no
// status.conditions) freezes under the no_status_conditions reason —
// this exercises the operator.shipwright.io GVR row end-to-end so the
// shOpDyn registration cannot silently drift from production again.
func TestCheckOperatorWorkqueuesShipwrightOperatorNoConditions(t *testing.T) {
	metrics.OperatorWorkqueueFrozen.DeleteLabelValues("shipwright-operator", opReasonNoConditions)
	t.Cleanup(func() {
		metrics.OperatorWorkqueueFrozen.DeleteLabelValues("shipwright-operator", opReasonNoConditions)
	})
	base := time.Now()
	cs := fake.NewSimpleClientset(
		shLease("operators", "01a9b2d1.shipwright.io",
			"shipwright-operator-abc_uid", 2*time.Second, base))
	stuck := shUnstructured("operator.shipwright.io/v1alpha1", "ShipwrightBuild",
		"", "build-1", 1, 0)
	p := testProberDyn(cs, shOpDyn(stuck))
	p.now = func() time.Time { return base }
	mustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen["shipwright-operator/shipwrightbuilds//build-1"] = base.Add(-time.Hour)

	if res := mustCheck[*operatorWorkqueueCheck](t, p).run(ctx); res.pass {
		t.Fatal("never-reconciled ShipwrightBuild must FAIL")
	}
	if v, _ := shOpFrozenGauge(t, "shipwright-operator", opReasonNoConditions); v != 1 {
		t.Fatalf("frozen gauge = %v, want 1", v)
	}
}
