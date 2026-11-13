package deschedulerstormgate

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// maintenance-hold-stale — forgotten maintenance holds (MaintenanceHoldStale)
// ---------------------------------------------------------------------------

// drainMaintenanceHoldStale counts the recorder's queued
// MaintenanceHoldStale events — NewFakeRecorder delivers synchronously,
// so the count is deterministic right after Reconcile returns.
func drainMaintenanceHoldStale(rec *events.FakeRecorder) int {
	n := 0
	for {
		select {
		case e := <-rec.Events:
			if strings.Contains(e, maintenanceHoldStaleReason) {
				n++
			}
		default:
			return n
		}
	}
}

// holdAnnos builds the descheduler Deployment annotations for a hold
// whose first-seen stamp says it has been "true" for `age` ("" age =
// no stamp — a hold the controller just started tracking).
func holdAnnos(age time.Duration) map[string]string {
	annos := map[string]string{stormGateHoldAnno: "true"}
	if age != 0 {
		annos[kube.AnnoFirstSeenStormGateHold] = fmt.Sprintf(
			`{"%s":"%s"}`, stormHoldLedgerKey,
			time.Now().Add(-age).UTC().Format(time.RFC3339))
	}
	return annos
}

// A hold kept "true" past the stale window fires exactly ONE
// MaintenanceHoldStale Warning — repeat reconciles must not spam.
func TestStormGateStaleHoldWarnsOnce(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, holdAnnos(3*time.Hour)))
	rec := events.NewFakeRecorder(16)
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake(), recorder: rec}

	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := drainMaintenanceHoldStale(rec); got != 1 {
		t.Fatalf("stale hold warnings = %d, want 1", got)
	}
	// The hold path still skips scaling.
	if got := getDeschedulerReplicas(t, cs); got != 1 {
		t.Fatalf("hold must skip scaling, replicas=%d", got)
	}
	// Repeat reconciles of the SAME stale hold must stay silent.
	for range 2 {
		if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
			t.Fatal(err)
		}
	}
	if got := drainMaintenanceHoldStale(rec); got != 0 {
		t.Fatalf("repeated reconciles spammed %d extra warnings", got)
	}
}

// A hold inside the stale window (fresh stamp, or none yet) warns
// nothing — the annotation has to HOLD past 2h first.
func TestStormGateFreshHoldDoesNotWarn(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, holdAnnos(time.Hour)))
	rec := events.NewFakeRecorder(16)
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake(), recorder: rec}
	for range 2 {
		if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
			t.Fatal(err)
		}
	}
	if got := drainMaintenanceHoldStale(rec); got != 0 {
		t.Fatalf("fresh hold warned %d times, want 0", got)
	}
}

// Releasing the hold clears the persisted stamp and re-arms: a NEW
// hold starts a fresh 2h window instead of inheriting the old one.
func TestStormGateHoldReleaseReArms(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, holdAnnos(3*time.Hour)))
	rec := events.NewFakeRecorder(16)
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake(), recorder: rec}

	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := drainMaintenanceHoldStale(rec); got != 1 {
		t.Fatalf("stale hold warnings = %d, want 1", got)
	}

	// Release the hold: the next sweep must clear the stamp...
	d := getDescheduler(t, cs)
	d.Annotations[stormGateHoldAnno] = "false"
	if _, err := cs.AppsV1().Deployments("kube-system").
		Update(ctx, d, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := getDescheduler(t, cs).Annotations[kube.AnnoFirstSeenStormGateHold]; got != "" {
		t.Fatalf("released hold left first-seen stamp behind: %q", got)
	}

	// ...and a NEW hold starts fresh: stamped at now, no warning.
	d = getDescheduler(t, cs)
	d.Annotations[stormGateHoldAnno] = "true"
	if _, err := cs.AppsV1().Deployments("kube-system").
		Update(ctx, d, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := drainMaintenanceHoldStale(rec); got != 0 {
		t.Fatalf("re-armed hold warned %d times, want 0", got)
	}
	if got := getDescheduler(t, cs).Annotations[kube.AnnoFirstSeenStormGateHold]; got == "" {
		t.Fatal("new hold was not stamped with a fresh first-seen")
	}
}

// nhcCR builds a NodeHealthCheck fixture — pauseRequests nil renders
// no spec at all (a healthy, unpaused NHC). The slice is []any: the
// dynamic fake deep-copies fixture JSON, which chokes on typed
// slices.
func nhcCR(name string, pauseRequests []string) *unstructured.Unstructured {
	fields := map[string]any{}
	if pauseRequests != nil {
		reqs := make([]any, len(pauseRequests))
		for i, r := range pauseRequests {
			reqs[i] = r
		}
		fields["spec"] = map[string]any{"pauseRequests": reqs}
	}
	return testutil.Unstructured(
		kube.GVRNodeHealthCheck.GroupVersion().WithKind("NodeHealthCheck"),
		"", name, fields)
}

func nhcPauseAnno(name string, age time.Duration) map[string]string {
	return map[string]string{
		kube.AnnoFirstSeenNHCPause: fmt.Sprintf(
			`{"%s":"%s"}`, name,
			time.Now().Add(-age).UTC().Format(time.RFC3339)),
	}
}

// A NodeHealthCheck paused via spec.pauseRequests past the stale
// window fires exactly ONE MaintenanceHoldStale Warning on the NHC —
// repeat sweeps must not spam.
func TestStormGateNHCPauseStaleWarnsOnce(t *testing.T) {
	nhc := nhcCR("nhc", []string{"runbook pause"})
	nhc.SetAnnotations(nhcPauseAnno("nhc", 3*time.Hour))
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil))
	rec := events.NewFakeRecorder(16)
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake(nhc), recorder: rec}

	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := drainMaintenanceHoldStale(rec); got != 1 {
		t.Fatalf("stale NHC pause warnings = %d, want 1", got)
	}
	for range 2 {
		if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
			t.Fatal(err)
		}
	}
	if got := drainMaintenanceHoldStale(rec); got != 0 {
		t.Fatalf("repeated sweeps spammed %d extra warnings", got)
	}
}

// A fresh (or untracked) pause warns nothing until the window holds.
func TestStormGateNHCPauseFreshDoesNotWarn(t *testing.T) {
	nhc := nhcCR("nhc", []string{"runbook pause"})
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil))
	rec := events.NewFakeRecorder(16)
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake(nhc), recorder: rec}
	for i := 0; i < 2; i++ {
		if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
			t.Fatal(err)
		}
	}
	if got := drainMaintenanceHoldStale(rec); got != 0 {
		t.Fatalf("fresh pause warned %d times, want 0", got)
	}
}

// Releasing the pause clears the persisted stamp on the NHC and
// re-arms the window; re-pausing warns nothing until it holds again.
func TestStormGateNHCPauseReleaseClearsStamp(t *testing.T) {
	nhc := nhcCR("nhc", []string{"runbook pause"})
	nhc.SetAnnotations(nhcPauseAnno("nhc", 3*time.Hour))
	dyn := stormGateDynFake(nhc)
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil))
	rec := events.NewFakeRecorder(16)
	r := &deschedulerStormGate{cs: cs, dyn: dyn, recorder: rec}

	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := drainMaintenanceHoldStale(rec); got != 1 {
		t.Fatalf("stale NHC pause warnings = %d, want 1", got)
	}

	// Release the pause — the next sweep clears the stamp.
	if _, err := dyn.Resource(kube.GVRNodeHealthCheck).
		Update(ctx, nhcCR("nhc", nil), metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	obj, err := dyn.Resource(kube.GVRNodeHealthCheck).
		Get(ctx, "nhc", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := obj.GetAnnotations()[kube.AnnoFirstSeenNHCPause]; got != "" {
		t.Fatalf("released pause left first-seen stamp behind: %q", got)
	}

	// A NEW pause starts fresh — no immediate warning.
	if _, err := dyn.Resource(kube.GVRNodeHealthCheck).
		Update(ctx, nhcCR("nhc", []string{"again"}), metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := drainMaintenanceHoldStale(rec); got != 0 {
		t.Fatalf("re-armed pause warned %d times, want 0", got)
	}
}

// A cluster without the medik8s CRD is an empty scan — the probe
// must not error the reconcile (same posture as the mutex's absent
// autopilot/medik8s CRDs). The fake needs the list kind REGISTERED
// (an unregistered List panics before reactors run), so the absent
// CRD is simulated with the error a real absent CRD produces.
func TestStormGateNHCCRDAbsentIsClear(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil))
	dyn := testutil.NewFakeDyn(map[schema.GroupVersionResource]string{
		kube.GVRNodeHealthCheck: "NodeHealthCheckList",
		// The reconcile continues into the maintenance mutex after
		// the probe — the fake needs every GVR that later List
		// touches registered or it panics before any reactor runs.
		kube.AutopilotPlanGVR:          "PlanList",
		kube.GVRSelfNodeRemediation:    "SelfNodeRemediationList",
		kube.GVRFenceAgentsRemediation: "FenceAgentsRemediationList",
		kube.GVRNodeMaintenance:        "NodeMaintenanceList",
	})
	dyn.PrependReactor("list", "nodehealthchecks",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, &meta.NoKindMatchError{
				GroupKind: schema.GroupKind{
					Group: kube.GVRNodeHealthCheck.Group, Kind: "NodeHealthCheck"},
			}
		})
	rec := events.NewFakeRecorder(16)
	r := &deschedulerStormGate{cs: cs, dyn: dyn, recorder: rec}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatalf("absent NHC CRD must not error the reconcile: %v", err)
	}
	if got := drainMaintenanceHoldStale(rec); got != 0 {
		t.Fatalf("absent CRD warned %d times, want 0", got)
	}
}

// A real NHC list failure errors the reconcile — never a silent
// "nothing paused".
func TestStormGateNHCListError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil))
	dyn := stormGateDynFake()
	dyn.PrependReactor("list", "nodehealthchecks",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	r := &deschedulerStormGate{cs: cs, dyn: dyn}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the NHC list fails")
	}
}

// ---------------------------------------------------------------------------
// maintenance-hold-stale — the stamping branches (uncovered half).
// ---------------------------------------------------------------------------

// A hold with NO first-seen stamp yet (the controller just started
// tracking it) gets stamped via the deploy merge-patch — and stays
// silent until the window holds out. The patch must be the annotation
// merge-patch contract: MergePatchType, carrying the first-seen
// annotation keyed by the hold's ledger key.
func TestStormGateHoldWithoutStampStampsAndStaysSilent(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, holdAnnos(0))) // hold "true", no stamp
	rec := events.NewFakeRecorder(16)
	r := &deschedulerStormGate{cs: cs, dyn: stormGateDynFake(), recorder: rec}

	var patchBody []byte
	var patchType types.PatchType
	cs.PrependReactor("patch", "deployments",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			pa := a.(ktesting.PatchAction)
			if pa.GetName() != "descheduler" || pa.GetNamespace() != "kube-system" {
				t.Fatalf("patched %s/%s, want kube-system/descheduler",
					pa.GetNamespace(), pa.GetName())
			}
			patchType = pa.GetPatchType()
			patchBody = pa.GetPatch()
			return false, nil, nil // let the fake apply it
		})

	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if patchType != types.MergePatchType {
		t.Fatalf("first-seen stamp used %s, want merge patch", patchType)
	}
	if !strings.Contains(string(patchBody), kube.AnnoFirstSeenStormGateHold) ||
		!strings.Contains(string(patchBody), stormHoldLedgerKey) {
		t.Fatalf("patch body missing first-seen annotation for %s: %s",
			stormHoldLedgerKey, patchBody)
	}
	if got := getDescheduler(t, cs).
		Annotations[kube.AnnoFirstSeenStormGateHold]; got == "" {
		t.Fatal("fresh hold was not stamped with a first-seen")
	}
	if got := drainMaintenanceHoldStale(rec); got != 0 {
		t.Fatalf("just-stamped hold warned %d times, want 0", got)
	}

	// A second reconcile inside the window stays silent too.
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if got := drainMaintenanceHoldStale(rec); got != 0 {
		t.Fatalf("reconciles after stamping warned %d times, want 0", got)
	}
}

// A FRESH NHC pause (no first-seen annotation yet) gets its stamp
// patched through the dynamic client and warns nothing — the window
// only opens when the stamp says the pause has aged past 2h.
func TestStormGateNHCPauseFreshStampsFirstSeen(t *testing.T) {
	nhc := nhcCR("nhc", []string{"runbook pause"}) // pause, no stamp
	dyn := stormGateDynFake(nhc)
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil),
		deschedulerDeploy(1, nil))
	rec := events.NewFakeRecorder(16)
	r := &deschedulerStormGate{cs: cs, dyn: dyn, recorder: rec}

	for range 2 {
		if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
			t.Fatal(err)
		}
	}
	obj, err := dyn.Resource(kube.GVRNodeHealthCheck).
		Get(ctx, "nhc", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	stamp, ok := obj.GetAnnotations()[kube.AnnoFirstSeenNHCPause]
	if !ok || stamp == "" {
		t.Fatalf("fresh pause was not stamped: annotations %v", obj.GetAnnotations())
	}
	if !strings.Contains(stamp, "nhc") {
		t.Fatalf("stamp %q does not carry the NHC ledger key", stamp)
	}
	if got := drainMaintenanceHoldStale(rec); got != 0 {
		t.Fatalf("fresh pause warned %d times, want 0", got)
	}
}
