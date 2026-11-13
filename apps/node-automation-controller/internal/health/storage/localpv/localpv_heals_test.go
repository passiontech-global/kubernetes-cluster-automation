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
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
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
