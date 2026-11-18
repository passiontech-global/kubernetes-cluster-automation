// localpv_heals_test.go — coverage for the localpv-stranded-pods
// auto-heals (localpv-stranded-pods): the ephemeral PVC+pod rescue's
// cooldown and error paths — each tolerated failure must be counted
// and must leave the survivors untouched.
package localpv

import (
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// strandedFixture builds the pod+PVC pair one strandedHeal carries —
// the pod opted into disposable localpv via the annotation the sweep
// gates on.
func strandedFixture(ns, name string) (*corev1.Pod, *corev1.PersistentVolumeClaim) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name, UID: types.UID("pod-" + name),
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name, UID: types.UID("pvc-" + name),
		},
		Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
	}
	return pod, pvc
}

func strandedProber(cs *fake.Clientset) (*probetest.Prober, *localPVStrandedCheck) {
	p := probetest.NewCheckProber(cs, probetest.OpDyn(), NewLocalPVStrandedCheck)
	return p, p.Checks[0].(*localPVStrandedCheck)
}

func strandedRunErrors(t *testing.T, p *probetest.Prober) float64 {
	t.Helper()
	m := probetest.FindMetric(t, "shell_operator_hook_run_errors_total",
		map[string]string{"queue": p.Name})
	if m == nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

// An RBAC-denied PVC delete is permanent for this check (the claim
// delete is only granted via the concourse Role) — the heal stamps
// the cooldown instead of error-looping every sweep, keeps the pod,
// and surfaces once.
func TestHealStrandedEphemeralForbiddenPVCStamps(t *testing.T) {
	pod, pvc := strandedFixture("app", "data-0")
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w1", "", 0, false), pod, pvc)
	cs.PrependReactor("delete", "persistentvolumeclaims",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(
				schema.GroupResource{Resource: "persistentvolumeclaims"},
				"data-0", errors.New("rbac deny"))
		})
	p, ch := strandedProber(cs)
	now := time.Now()
	before := strandedRunErrors(t, p)
	ch.healStrandedEphemeral(ctx, logr.Discard(),
		[]strandedHeal{{pod: pod, pvc: pvc, node: "dead-1",
			reason: "missing-node"}}, now)

	if _, err := cs.CoreV1().Pods("app").Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted although the claim release was refused")
	}
	if _, ok := ch.localPVHealed.Last("app/data-0"); !ok {
		t.Fatal("forbidden PVC delete did not stamp the cooldown — the check will error-loop every sweep")
	}
	if got := strandedRunErrors(t, p) - before; got != 1 {
		t.Fatalf("run_errors delta = %v, want 1 — the permanent denial surfaces once", got)
	}
}

// A transient PVC delete failure is counted and NOT stamped — the
// next sweep must retry rather than sit out the cooldown window.
func TestHealStrandedEphemeralPVCErrorRetries(t *testing.T) {
	pod, pvc := strandedFixture("app", "data-0")
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w1", "", 0, false), pod, pvc)
	cs.PrependReactor("delete", "persistentvolumeclaims",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	p, ch := strandedProber(cs)
	before := strandedRunErrors(t, p)
	ch.healStrandedEphemeral(ctx, logr.Discard(),
		[]strandedHeal{{pod: pod, pvc: pvc, node: "dead-1",
			reason: "missing-node"}}, time.Now())

	if _, err := cs.CoreV1().Pods("app").Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted although the claim release failed")
	}
	if _, ok := ch.localPVHealed.Last("app/data-0"); ok {
		t.Fatal("transient PVC delete failure stamped the cooldown — the heal would be suppressed for 30m")
	}
	if got := strandedRunErrors(t, p) - before; got != 1 {
		t.Fatalf("run_errors delta = %v, want 1", got)
	}
}

// The pod half failing after a delivered claim release is counted
// and unstamped — the release already landed so the retry window
// stays open for the orphaned pod.
func TestHealStrandedEphemeralPodErrorRetries(t *testing.T) {
	pod, pvc := strandedFixture("app", "data-0")
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w1", "", 0, false), pod, pvc)
	cs.PrependReactor("delete", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	p, ch := strandedProber(cs)
	before := strandedRunErrors(t, p)
	ch.healStrandedEphemeral(ctx, logr.Discard(),
		[]strandedHeal{{pod: pod, pvc: pvc, node: "dead-1",
			reason: "missing-node"}}, time.Now())

	if _, err := cs.CoreV1().PersistentVolumeClaims("app").
		Get(ctx, pvc.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("PVC kept although its delete succeeded")
	}
	if _, err := cs.CoreV1().Pods("app").Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted although the apiserver rejected it")
	}
	if _, ok := ch.localPVHealed.Last("app/data-0"); ok {
		t.Fatal("pod delete failure stamped the cooldown — the orphaned pod would wait 30m for a retry")
	}
	if got := strandedRunErrors(t, p) - before; got != 1 {
		t.Fatalf("run_errors delta = %v, want 1", got)
	}
}

// The second half of the rescue re-confirms the pod on the live
// apiserver: a pod that got scheduled onto a live node in the minutes
// since the census is a live workload, not a stranded orphan — the
// PVC release stands but the pod must not be killed.
func TestHealStrandedEphemeralScheduledPodKept(t *testing.T) {
	pod, pvc := strandedFixture("app", "data-0")
	pod.Spec.NodeName = "live-1"
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w1", "", 0, false), pod, pvc)
	p, ch := strandedProber(cs)
	before := strandedRunErrors(t, p)
	ch.healStrandedEphemeral(ctx, logr.Discard(),
		[]strandedHeal{{pod: pod, pvc: pvc, node: "dead-1",
			reason: "missing-node"}}, time.Now())

	if _, err := cs.CoreV1().Pods("app").Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted after it was scheduled onto a live node")
	}
	if got := strandedRunErrors(t, p) - before; got != 0 {
		t.Fatalf("legitimate live-confirm veto metered as an error: delta = %v", got)
	}
}

// A same-name pod recreated under a new UID must not inherit the
// dead pod's heal verdict.
func TestHealStrandedEphemeralPodUIDMismatchKept(t *testing.T) {
	pod, pvc := strandedFixture("app", "data-0")
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w1", "", 0, false), pod, pvc)
	cs.PrependReactor("get", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			live := pod.DeepCopy()
			live.UID = types.UID("pod-recreated")
			return true, live, nil
		})
	p, ch := strandedProber(cs)
	before := strandedRunErrors(t, p)
	ch.healStrandedEphemeral(ctx, logr.Discard(),
		[]strandedHeal{{pod: pod, pvc: pvc, node: "dead-1",
			reason: "missing-node"}}, time.Now())

	if _, err := cs.CoreV1().Pods("app").Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("recreated pod deleted on the old pod's verdict")
	}
	if got := strandedRunErrors(t, p) - before; got != 0 {
		t.Fatalf("UID-mismatch veto metered as an error: delta = %v", got)
	}
}

// An unverifiable live confirm fails closed: the pod stays and the
// tolerated API failure is metered once (the run absorbs it).
func TestHealStrandedEphemeralPodConfirmErrorFailsClosed(t *testing.T) {
	pod, pvc := strandedFixture("app", "data-0")
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w1", "", 0, false), pod, pvc)
	failGet := true
	cs.PrependReactor("get", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			if failGet {
				return true, nil, errors.New("api down")
			}
			return false, nil, nil
		})
	p, ch := strandedProber(cs)
	before := strandedRunErrors(t, p)
	ch.healStrandedEphemeral(ctx, logr.Discard(),
		[]strandedHeal{{pod: pod, pvc: pvc, node: "dead-1",
			reason: "missing-node"}}, time.Now())
	failGet = false

	if _, err := cs.CoreV1().Pods("app").Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted while its live confirm failed")
	}
	if got := strandedRunErrors(t, p) - before; got != 1 {
		t.Fatalf("failed live confirm not metered once: delta = %v", got)
	}
}

// A stamped cooldown short-circuits before the mutex preamble — no
// delete is attempted, nothing is counted.
func TestHealStrandedEphemeralCooldownSkips(t *testing.T) {
	pod, pvc := strandedFixture("app", "data-0")
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w1", "", 0, false), pod, pvc)
	p, ch := strandedProber(cs)
	now := time.Now()
	ch.localPVHealed.Stamp("app/data-0", now.Add(-time.Minute))
	before := strandedRunErrors(t, p)
	ch.healStrandedEphemeral(ctx, logr.Discard(),
		[]strandedHeal{{pod: pod, pvc: pvc, node: "dead-1",
			reason: "missing-node"}}, now)

	if _, err := cs.CoreV1().PersistentVolumeClaims("app").
		Get(ctx, pvc.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("PVC deleted inside the heal cooldown")
	}
	if _, err := cs.CoreV1().Pods("app").Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted inside the heal cooldown")
	}
	if got := strandedRunErrors(t, p) - before; got != 0 {
		t.Fatalf("run_errors delta = %v, want 0 — a cooled target attempts nothing", got)
	}
}

// A 409 Conflict on the PVC delete is a race with the claim's owner,
// not an apiserver failure: no error count, and the unused heal grant
// is handed back so the next target in the same sweep can still heal
// (budget=1 here would otherwise deny it).
func TestHealStrandedEphemeralPVCConflictRefundsGrant(t *testing.T) {
	heal.ConfigureBudget(1, time.Hour)
	t.Cleanup(func() { heal.ConfigureBudget(0, 0) })

	podA, pvcA := strandedFixture("app", "raced-0")
	podB, pvcB := strandedFixture("app", "next-0")
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w1", "", 0, false), podA, pvcA, podB, pvcB)
	cs.PrependReactor("delete", "persistentvolumeclaims",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			if a.(ktesting.DeleteAction).GetName() == pvcA.Name {
				return true, nil, apierrors.NewConflict(
					schema.GroupResource{Resource: "persistentvolumeclaims"},
					pvcA.Name, errors.New("uid changed"))
			}
			return false, nil, nil
		})
	p, ch := strandedProber(cs)
	before := strandedRunErrors(t, p)
	ch.healStrandedEphemeral(ctx, logr.Discard(), []strandedHeal{
		{pod: podA, pvc: pvcA, node: "dead-1", reason: "missing-node"},
		{pod: podB, pvc: pvcB, node: "dead-1", reason: "missing-node"},
	}, time.Now())

	if got := strandedRunErrors(t, p) - before; got != 0 {
		t.Fatalf("409 Conflict must not IncError: delta = %v", got)
	}
	if _, err := cs.CoreV1().Pods("app").Get(ctx, podA.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("pod of the raced claim was deleted")
	}
	if _, err := cs.CoreV1().Pods("app").Get(ctx, podB.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("second heal was denied — the conflicted grant was not refunded")
	}
}

// The pod vanished after the claim release: heal.DeletePod reports
// (false, nil). That still freed the stranded slot, so the cooldown
// is stamped and the heal counted instead of re-detecting forever.
func TestHealStrandedEphemeralPodVanishesStillCounts(t *testing.T) {
	pod, pvc := strandedFixture("app", "gone-0")
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w1", "", 0, false), pod, pvc)
	// The live confirm finds the pod; the delete races with its
	// removal and heal.DeletePod swallows NotFound into (false, nil).
	cs.PrependReactor("delete", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(
				schema.GroupResource{Resource: "pods"}, pod.Name)
		})
	_, ch := strandedProber(cs)
	testutil.CleanupMetric(t, localPVEphemeralHealsTotal,
		"app", "gone-0", "dead-1")
	before := promtest.ToFloat64(
		localPVEphemeralHealsTotal.WithLabelValues("app", "gone-0", "dead-1"))
	ch.healStrandedEphemeral(ctx, logr.Discard(),
		[]strandedHeal{{pod: pod, pvc: pvc, node: "dead-1",
			reason: "missing-node"}}, time.Now())

	if _, ok := ch.localPVHealed.Last("app/gone-0"); !ok {
		t.Fatal("vanished pod did not stamp the heal cooldown")
	}
	if got := promtest.ToFloat64(
		localPVEphemeralHealsTotal.WithLabelValues("app", "gone-0", "dead-1")) - before; got != 1 {
		t.Fatalf("vanished pod heal not counted: delta = %v", got)
	}
}

// A provisioner pod that is still Pending (or already terminal) is
// not the wedged controller the bounce exists to restart — only a
// Running replica may be picked.
func TestPVCStalledProvisionerBounceSkipsNonRunningPods(t *testing.T) {
	t.Cleanup(func() {
		pvcProvisioningStalledGauge.DeleteLabelValues("apps", "data-x", "openebs-hostpath")
		pvcProvisionerHealsTotal.DeleteLabelValues(openebsProvisionerName)
	})
	base := time.Now()
	owner := []metav1.OwnerReference{{
		APIVersion: "apps/v1", Kind: "ReplicaSet",
		Name: "openebs-localpv-provisioner-7d9f", UID: "rs-p1",
		Controller: ptr.To(true),
	}}
	prov := func(name string, phase corev1.PodPhase) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: openebsProvisionerNS, Name: name, UID: types.UID(name),
				OwnerReferences: owner,
			},
			Status: corev1.PodStatus{Phase: phase},
		}
	}
	pending := prov("openebs-localpv-provisioner-pending", corev1.PodPending)
	running := prov("openebs-localpv-provisioner-running", corev1.PodRunning)
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Namespace: openebsProvisionerNS, Name: openebsProvisionerName}}
	cs := fake.NewSimpleClientset(testutil.Node("w1", corev1.ConditionTrue, nil),
		pending, running, dep,
		pendingPodForPVC("apps", "web-0", "data-x", 20*time.Minute, base),
		stalledHostpathPVC("apps", "data-x"))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*localPVStrandedCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))

	if _, err := cs.CoreV1().Pods(openebsProvisionerNS).
		Get(ctx, pending.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("Pending provisioner pod was bounced")
	}
	if _, err := cs.CoreV1().Pods(openebsProvisionerNS).
		Get(ctx, running.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("Running provisioner pod was not bounced: %v", err)
	}
}

// An unverifiable maintenance verdict fails every target in the
// batch closed — counted once per target, nothing touched.
func TestHealStrandedEphemeralUnverifiable(t *testing.T) {
	pod, pvc := strandedFixture("app", "data-0")
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w1", "", 0, false), pod, pvc)
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	p, ch := strandedProber(cs)
	before := strandedRunErrors(t, p)
	ch.healStrandedEphemeral(ctx, logr.Discard(),
		[]strandedHeal{{pod: pod, pvc: pvc, node: "dead-1",
			reason: "missing-node"}}, time.Now())

	if _, err := cs.CoreV1().PersistentVolumeClaims("app").
		Get(ctx, pvc.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("PVC deleted while the maintenance check was unverifiable")
	}
	if _, err := cs.CoreV1().Pods("app").Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted while the maintenance check was unverifiable")
	}
	if got := strandedRunErrors(t, p) - before; got != 1 {
		t.Fatalf("run_errors delta = %v, want 1 — fail closed is counted", got)
	}
}
