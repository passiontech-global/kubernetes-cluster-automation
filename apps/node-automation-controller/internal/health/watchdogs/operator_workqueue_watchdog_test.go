// operator_workqueue_watchdog_test.go — operator-watchdog-targets/operator-workqueue-watchdog coverage
// for the operator-workqueue-watchdog target list completeness and
// the never-reconciled stuck predicates.
package watchdogs

import (
	"context"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// ---------------------------------------------------------------------------
// operator-watchdog-targets — operator watchdog expansion
// ---------------------------------------------------------------------------

// The watchdog must cover the original five plus the operator-watchdog-targets additions
// and the operator-workqueue-watchdog expansion — notification-controller IS a target
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
	if len(operatorTargets) != 29 {
		t.Fatalf("operatorTargets = %d, want 29", len(operatorTargets))
	}
	for _, want := range []string{
		"source-controller", "cert-manager",
		"external-secrets", "rabbitmq-cluster-operator", "keda-operator",
		"argocd-operator", "kargo-controller", "everest-operator",
		"shipwright-build-controller",
		// operator-workqueue-watchdog additions.
		"notification-controller", "node-healthcheck-operator",
		"self-node-remediation-operator",
		"percona-xtradb-cluster-operator", "percona-postgresql-operator",
		"percona-server-mongodb-operator", "fluent-operator",
		"tekton-pipelines-controller", "shipwright-operator",
		// rollout-scale-flap additions.
		"argo-rollouts-controller", "cloudflare-tunnel-gateway-controller",
		// W20-CP4 operator-watchdog additions.
		"cloudnative-pg", "velero", "fence-agents-remediation-operator",
		"liqo-controller-manager",
	} {
		if !seen[want] {
			t.Fatalf("missing operator target %q", want)
		}
	}
	// notification-controller may only ever watch the Lease — any
	// CR resource on it would resurrect the static-object false
	// positive the operator-watchdog-targets incident fix removed.
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
	bare := probetest.UnstructuredObj("cert-manager.io/v1", "Certificate", "cm", "c", 1, 0)
	if !noStatusConditions(bare) {
		t.Fatal("Certificate with no status.conditions must read stuck")
	}
	_ = unstructured.SetNestedSlice(bare.Object,
		[]any{map[string]any{"type": "Ready", "status": "False"}},
		"status", "conditions")
	if noStatusConditions(bare) {
		t.Fatal("Certificate carrying conditions must not read stuck")
	}

	argocd := probetest.UnstructuredObj("argoproj.io/v1beta1", "ArgoCD", "cd", "arg", 1, 0)
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
	testutil.CleanupMetric(t, operatorWorkqueueFrozenGauge, "source-controller", kcmReasonStaleGen)
	base := time.Now()
	leader := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "flux-system", Name: "source-controller-7d9f",
		UID:             types.UID("sc-uid-1"),
		Labels:          map[string]string{"app": "source-controller"},
		OwnerReferences: shCtlrOwned("source-controller-7d9f"),
	},
		Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	cs := fake.NewSimpleClientset(
		shLease("flux-system", "source-controller-leader-election",
			"source-controller-7d9f_3f2a1", 2*time.Second, base),
		leader)
	stuck := probetest.UnstructuredObj("source.toolkit.fluxcd.io/v1", "GitRepository",
		"apps", "repo", 5, 3)
	p := testProberDyn(cs, probetest.OpDyn(stuck))
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen.
		Observe("source-controller/gitrepositories/apps/repo/"+kcmReasonStaleGen, base.Add(-time.Hour))

	if res := probetest.MustCheck[*operatorWorkqueueCheck](t, p).Run(ctx); res.Pass {
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
	testutil.CleanupMetric(t, operatorWorkqueueFrozenGauge, "cert-manager", opReasonNoConditions)
	base := time.Now()
	cs := fake.NewSimpleClientset(
		// cert-manager elects leaders in kube-system (helm chart
		// default global.leaderElection.namespace).
		shLease("kube-system", "cert-manager-controller",
			"cert-manager-abc_uid", 2*time.Second, base))
	stuck := probetest.UnstructuredObj("cert-manager.io/v1", "Certificate", "apps", "tls", 1, 0)
	p := testProberDyn(cs, probetest.OpDyn(stuck))
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen.
		Observe("cert-manager/certificates/apps/tls/"+opReasonNoConditions, base.Add(-time.Hour))

	if res := probetest.MustCheck[*operatorWorkqueueCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("never-reconciled Certificate must FAIL")
	}
	if v, _ := shOpFrozenGauge(t, "cert-manager", opReasonNoConditions); v != 1 {
		t.Fatalf("frozen gauge = %v, want 1", v)
	}
}

// Restart-resume: a Certificate carrying a persisted first-seen
// stamp older than stuckMinAge trips the window on the FIRST sweep —
// the in-RAM ledger is empty (operator restarted) but the annotation
// proves the signature held continuously.
func TestCheckOperatorWorkqueuesPersistedFirstSeenResume(t *testing.T) {
	testutil.CleanupMetric(t, operatorWorkqueueFrozenGauge, "cert-manager", opReasonNoConditions)
	base := time.Now()
	cs := fake.NewSimpleClientset(
		shLease("kube-system", "cert-manager-controller",
			"cert-manager-abc_uid", 2*time.Second, base))
	stuck := probetest.UnstructuredObj("cert-manager.io/v1", "Certificate",
		"apps", "tls", 1, 0)
	stuck.SetAnnotations(map[string]string{
		kube.AnnoFirstSeenOperatorWorkqueue: `{"cert-manager/certificates/apps/tls/` +
			opReasonNoConditions + `":"` +
			base.Add(-time.Hour).UTC().Format(time.RFC3339) + `"}`,
	})
	p := testProberDyn(cs, probetest.OpDyn(stuck))
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*operatorWorkqueueCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("persisted first-seen must trip on the first post-restart sweep")
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
	testutil.CleanupMetric(t, operatorWorkqueueFrozenGauge, "shipwright-operator", opReasonNoConditions)
	base := time.Now()
	cs := fake.NewSimpleClientset(
		shLease("operators", "01a9b2d1.shipwright.io",
			"shipwright-operator-abc_uid", 2*time.Second, base))
	stuck := probetest.UnstructuredObj("operator.shipwright.io/v1alpha1", "ShipwrightBuild",
		"", "build-1", 1, 0)
	p := testProberDyn(cs, probetest.OpDyn(stuck))
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen.
		Observe("shipwright-operator/shipwrightbuilds//build-1/"+opReasonNoConditions, base.Add(-time.Hour))

	if res := probetest.MustCheck[*operatorWorkqueueCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("never-reconciled ShipwrightBuild must FAIL")
	}
	if v, _ := shOpFrozenGauge(t, "shipwright-operator", opReasonNoConditions); v != 1 {
		t.Fatalf("frozen gauge = %v, want 1", v)
	}
}

// limitRecordingDyn records the List options reaching the dynamic
// interface — the fake's ROOT list action strips Limit/Continue
// (client-go's NewRootListActionWithOptions keeps only the
// selectors), so the requested page bound is only observable here.
type limitRecordingDyn struct {
	dynamic.Interface
	listOpts []metav1.ListOptions
	listGvrs []schema.GroupVersionResource
}

func (d *limitRecordingDyn) Resource(gvr schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
	return &limitRecordingRI{NamespaceableResourceInterface: d.Interface.Resource(gvr), d: d, gvr: gvr}
}

type limitRecordingRI struct {
	dynamic.NamespaceableResourceInterface
	d   *limitRecordingDyn
	gvr schema.GroupVersionResource
}

func (r *limitRecordingRI) Namespace(ns string) dynamic.ResourceInterface {
	return &limitRecordingNS{
		ResourceInterface: r.NamespaceableResourceInterface.Namespace(ns), d: r.d, gvr: r.gvr}
}

type limitRecordingNS struct {
	dynamic.ResourceInterface
	d   *limitRecordingDyn
	gvr schema.GroupVersionResource
}

func (r *limitRecordingRI) List(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	r.d.listOpts = append(r.d.listOpts, opts)
	r.d.listGvrs = append(r.d.listGvrs, r.gvr)
	return r.NamespaceableResourceInterface.List(ctx, opts)
}

func (r *limitRecordingNS) List(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	r.d.listOpts = append(r.d.listOpts, opts)
	r.d.listGvrs = append(r.d.listGvrs, r.gvr)
	return r.ResourceInterface.List(ctx, opts)
}

// The CR scan pages its cluster-wide Lists: the first page request
// carries the shared Limit (an unpaged List would read whole CRDs on
// every 5m sweep), and sibling rows watching the same GVR (BUG-C5)
// still reuse one fetch — cert-manager watches certificates under
// two signatures, so exactly ONE paged List must fire while both
// signatures evaluate the objects.
func TestOperatorCRScanPagesListRequests(t *testing.T) {
	base := time.Now()
	stuck := probetest.UnstructuredObj("cert-manager.io/v1", "Certificate",
		"apps", "tls", 1, 0)
	dyn := &limitRecordingDyn{Interface: probetest.OpDyn(stuck)}
	p := testProberDyn(fake.NewSimpleClientset(), dyn)
	var certTarget operatorTarget
	for _, op := range operatorTargets {
		if op.name == "cert-manager" {
			certTarget = op
			break
		}
	}
	chk := probetest.MustCheck[*operatorWorkqueueCheck](t, p)
	var rep probefw.SweepReport
	// The CR scan reads through the sweep-wide snapshot (Deps.
	// AllUnstructured) — the test runs under a sweep ctx so the
	// memo is live and both signature rows share one paged List.
	scanCtx := probefw.WithSweepSnapshot(ctx)
	scan := chk.scanOperatorResources(scanCtx, logf.FromContext(ctx), certTarget, base, &rep)
	if scan.evalFailed {
		t.Fatal("paged CR scan reported an infra failure")
	}
	if len(dyn.listOpts) != 1 {
		t.Fatalf("certificate List requests = %d, want 1 (one fetch shared by both signatures)", len(dyn.listOpts))
	}
	if dyn.listOpts[0].Limit != kube.DefaultListPageSize {
		t.Fatalf("List Limit = %d, want DefaultListPageSize (%d)",
			dyn.listOpts[0].Limit, kube.DefaultListPageSize)
	}
	for _, reason := range []string{opReasonNoConditions, kcmReasonStaleGen} {
		if !scan.live["cert-manager/certificates/apps/tls/"+reason] {
			t.Fatalf("stuck Certificate not judged live under %q: %v", reason, scan.live)
		}
	}
}

// ---------------------------------------------------------------------------
// opFrozenFlipZero / carryFrozen — the emitted-ledger prune action and
// the carry-forward the skip paths re-assert
// ---------------------------------------------------------------------------

// opFrozenFlipZero is the GaugeLedger delete func: a held "operator/
// reason" series that stopped being emitted flips to 0 rather than
// disappearing — the resolved edge stays visible on /metrics.
func TestOpFrozenFlipZero(t *testing.T) {
	const (
		op     = "unit-test-operator"
		reason = "unit-test-reason"
	)
	defer testutil.CleanupMetric(t,
		operatorWorkqueueFrozenGauge, op, reason)
	operatorWorkqueueFrozenGauge.WithLabelValues(op, reason).Set(1)

	if !opFrozenFlipZero(op, reason) {
		t.Fatal("flip must report the series handled (return true)")
	}
	m := probetest.FindMetric(t, "node_automation_operator_workqueue_frozen",
		map[string]string{"operator": op, "reason": reason})
	if m == nil || m.GetGauge().GetValue() != 0 {
		t.Fatalf("frozen gauge = %v, want a 0-valued series", m)
	}
}

// carryFrozen re-registers one operator's held tuples on the sweep
// report so the sweep-end prune keeps them — an operator skipped
// before evaluation (lease read error, dead pod) must not read as
// "resolved" and flap its series to 0.
func TestCarryFrozen(t *testing.T) {
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn())
	chk := probetest.MustCheck[*operatorWorkqueueCheck](t, p)

	// Seed the ledger's emitted set the way a prior sweep's
	// Reconcile leaves it: two operators' frozen tuples.
	chk.opFrozen.Reconcile(map[string][]string{
		"op-a/no_status": {"op-a", "no_status"},
		"op-b/stale_gen": {"op-b", "stale_gen"},
	}, func(...string) bool { return true })

	var rep probefw.SweepReport
	chk.carryFrozen(&rep, "op-a")

	// Only op-a's tuple may be carried — op-b's was never evaluated
	// either, but carryFrozen is scoped to the skipped operator.
	if rep.Flagged() != 1 {
		t.Fatalf("carried tuples = %d, want 1", rep.Flagged())
	}
	var ledger state.GaugeLedger[string]
	rep.Result(&ledger, func(...string) bool { return true }, "", ", ")
	last := ledger.Last()
	if _, ok := last["op-a/no_status"]; !ok {
		t.Fatalf("op-a tuple not carried into the ledger: %v", last)
	}
	if _, ok := last["op-b/stale_gen"]; ok {
		t.Fatalf("op-b tuple leaked into the report: %v", last)
	}
}
