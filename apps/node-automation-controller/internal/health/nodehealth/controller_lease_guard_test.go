// controller_lease_guard_test.go — coverage for the
// controller-lease-guard check: the leaseTransitions flap detector,
// the expired-lease-with-running-pods bounce (incl. the 30m cooldown
// and the maintenance-mutex gate), the healthy/fresh-lease no-ops
// and the kube-state-metrics 401-wedge persistence window + bounce.
package nodehealth

import (
	"context"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// leaseGuardProber builds the prober carrying ONLY this check — the
// package's shared testProber list stays untouched while the check
// still rides the standard Deps/OpDyn wiring.
func leaseGuardProber(cs *fake.Clientset) (*probetest.Prober, *controllerLeaseGuardCheck) {
	p := probetest.NewCheckProber(cs, probetest.OpDyn(), NewControllerLeaseGuardCheck)
	return p, p.Checks[0].(*controllerLeaseGuardCheck)
}

// cpLease builds a control-plane Lease whose renewTime is renewAge
// old (relative to at), holder is the holderIdentity ("" leaves it
// unset) and transitions the spec.leaseTransitions counter.
func cpLease(ns, name, holder string, renewAge time.Duration,
	transitions int32, at time.Time) *coordinationv1.Lease {

	rt := metav1.NewMicroTime(at.Add(-renewAge))
	l := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: coordinationv1.LeaseSpec{
			RenewTime:        &rt,
			LeaseTransitions: ptr.To(transitions),
		},
	}
	if holder != "" {
		l.Spec.HolderIdentity = ptr.To(holder)
	}
	return l
}

// A lease whose transitions climbed >=5 inside the flap window is
// election churn — FAIL + gauge; the counter needs two samples, so
// the first sighting passes before the jump is observed.
func TestLeaseGuardFlapping(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset(
		cpLease("kube-system", "flux-leader", "a_1", time.Minute, 0, base))
	p, ch := leaseGuardProber(cs)
	probetest.FreezeNow(p.Deps, base)

	if res := ch.Run(ctx); !res.Pass {
		t.Fatalf("first transitions sighting must pass: %+v", res)
	}

	l, err := cs.CoordinationV1().Leases("kube-system").
		Get(ctx, "flux-leader", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	*l.Spec.LeaseTransitions = 6
	if _, err := cs.CoordinationV1().Leases("kube-system").
		Update(ctx, l, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	probetest.FreezeNow(p.Deps, base.Add(5*time.Minute))

	if res := ch.Run(ctx); res.Pass {
		t.Fatal("flapping lease did not fail the check")
	}
	m := probetest.FindMetric(t, "node_automation_controller_lease_unhealthy",
		map[string]string{"namespace": "kube-system",
			"lease": "flux-leader", "reason": "flapping"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("lease_unhealthy flapping series = %v, want 1", m)
	}
}

// A stale renewTime (>10m, <2h) while the holder's pods still run is
// the wedged-elector signature — FAIL + gauge and the oldest Running
// controller pod gets a UID-preconditioned delete.
func TestLeaseGuardExpiredLeaseBouncesHolder(t *testing.T) {
	cs := fake.NewSimpleClientset(
		cpLease("kube-system", "cilium-operator",
			"cilium-operator-7d9f4d5b8c-x1_abc", 20*time.Minute, 1, time.Now()),
		probetest.ReadyPodWithIP("kube-system",
			"cilium-operator-7d9f4d5b8c-x1", "10.0.0.9", nil))
	_, ch := leaseGuardProber(cs)

	if res := ch.Run(ctx); res.Pass {
		t.Fatal("expired lease with running pods must fail")
	}
	if _, err := cs.CoreV1().Pods("kube-system").
		Get(ctx, "cilium-operator-7d9f4d5b8c-x1", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("wedged holder pod was not bounced: %v", err)
	}
	m := probetest.FindMetric(t, "node_automation_controller_lease_unhealthy",
		map[string]string{"namespace": "kube-system",
			"lease": "cilium-operator", "reason": "expired_with_running_pods"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("lease_unhealthy expired series = %v, want 1", m)
	}
}

// The 30m cooldown suppresses a repeat bounce: the lease is still
// stale (still FAIL) but the respawned holder pod survives.
func TestLeaseGuardExpiredLeaseCooldown(t *testing.T) {
	cs := fake.NewSimpleClientset(
		cpLease("kube-system", "cool-op",
			"cool-op-5bd4f9b7c9-x2_def", 20*time.Minute, 1, time.Now()),
		probetest.ReadyPodWithIP("kube-system",
			"cool-op-5bd4f9b7c9-x2", "10.0.0.11", nil))
	_, ch := leaseGuardProber(cs)

	if res := ch.Run(ctx); res.Pass {
		t.Fatal("expired lease with running pods must fail")
	}
	if _, err := cs.CoreV1().Pods("kube-system").
		Get(ctx, "cool-op-5bd4f9b7c9-x2", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("first bounce never landed: %v", err)
	}

	// The controller respawns the pod — a second sweep inside the
	// cooldown must not delete it again.
	respawn := probetest.ReadyPodWithIP("kube-system",
		"cool-op-5bd4f9b7c9-x2", "10.0.0.12", nil)
	respawn.UID = types.UID("uid-respawn")
	if _, err := cs.CoreV1().Pods("kube-system").
		Create(ctx, respawn, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if res := ch.Run(ctx); res.Pass {
		t.Fatal("still-stale lease must keep failing")
	}
	if _, err := cs.CoreV1().Pods("kube-system").
		Get(ctx, "cool-op-5bd4f9b7c9-x2", metav1.GetOptions{}); err != nil {
		t.Fatalf("cooldown did not suppress the repeat bounce: %v", err)
	}
}

// Deliberate maintenance (kured holding the node lock) gates the
// bounce — the stale lease still FAILs + reports, but no pod dies
// mid-drain.
func TestLeaseGuardExpiredLeaseMaintenanceGate(t *testing.T) {
	cs := fake.NewSimpleClientset(
		cpLease("kube-system", "gated-op",
			"gated-op-7f9c4dbb68-y3_ghi", 20*time.Minute, 1, time.Now()),
		probetest.ReadyPodWithIP("kube-system",
			"gated-op-7f9c4dbb68-y3", "10.0.0.13", nil),
		&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system", Name: "kured",
			Annotations: map[string]string{kube.KuredLockAnno: "w1"}}})
	_, ch := leaseGuardProber(cs)

	if res := ch.Run(ctx); res.Pass {
		t.Fatal("expired lease must still fail under maintenance")
	}
	if _, err := cs.CoreV1().Pods("kube-system").
		Get(ctx, "gated-op-7f9c4dbb68-y3", metav1.GetOptions{}); err != nil {
		t.Fatalf("maintenance mutex did not gate the bounce: %v", err)
	}
}

// W12-SC2 — a jump of 4 transitions inside 10m is thrashing: the
// dedicated gauge fires and the check fails, but below the flap
// threshold (5/15m) no unhealthy flapping series appears.
func TestLeaseGuardThrashing(t *testing.T) {
	testutil.CleanupMetric(t, controllerLeaseThrashingGauge, "kube-system", "thrash-op")
	base := time.Now()
	cs := fake.NewSimpleClientset(
		cpLease("kube-system", "thrash-op", "a_1", time.Minute, 0, base))
	p, ch := leaseGuardProber(cs)
	probetest.FreezeNow(p.Deps, base)

	if res := ch.Run(ctx); !res.Pass {
		t.Fatalf("first transitions sighting must pass: %+v", res)
	}

	l, err := cs.CoordinationV1().Leases("kube-system").
		Get(ctx, "thrash-op", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	*l.Spec.LeaseTransitions = 4
	if _, err := cs.CoordinationV1().Leases("kube-system").
		Update(ctx, l, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	probetest.FreezeNow(p.Deps, base.Add(8*time.Minute))

	res := ch.Run(ctx)
	if res.Pass {
		t.Fatal("4 transitions inside 10m did not fail the check")
	}
	m := probetest.FindMetric(t, "node_automation_controller_lease_thrashing",
		map[string]string{"namespace": "kube-system", "lease": "thrash-op"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("thrashing gauge = %v, want 1", m)
	}
	// Below the flap threshold — no flapping series.
	if m := probetest.FindMetric(t, "node_automation_controller_lease_unhealthy",
		map[string]string{"namespace": "kube-system",
			"lease": "thrash-op", "reason": "flapping"}); m != nil {
		t.Fatal("4/10m must not emit the flapping reason")
	}
}

// A lease renewing normally (fresh renewTime) with running pods is
// healthy — no finding, no delete.
func TestLeaseGuardFreshLeaseNoAction(t *testing.T) {
	cs := fake.NewSimpleClientset(
		cpLease("kube-system", "fresh-op",
			"fresh-op-6cd9e7f5a4-z4_jkl", time.Minute, 2, time.Now()),
		probetest.ReadyPodWithIP("kube-system",
			"fresh-op-6cd9e7f5a4-z4", "10.0.0.14", nil))
	_, ch := leaseGuardProber(cs)

	if res := ch.Run(ctx); !res.Pass {
		t.Fatalf("fresh lease must pass: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("kube-system").
		Get(ctx, "fresh-op-6cd9e7f5a4-z4", metav1.GetOptions{}); err != nil {
		t.Fatalf("healthy controller pod deleted: %v", err)
	}
}

// A lease stale past the 2h ceiling is an abandoned corpse, not a
// wedged elector — no finding even with pods running.
func TestLeaseGuardLongStaleLeaseIgnored(t *testing.T) {
	cs := fake.NewSimpleClientset(
		cpLease("node-ops", "corpse-op",
			"corpse-op-8bf4d7c9a5-w5_mno", 3*time.Hour, 4, time.Now()),
		probetest.ReadyPodWithIP("node-ops",
			"corpse-op-8bf4d7c9a5-w5", "10.0.0.15", nil))
	_, ch := leaseGuardProber(cs)

	if res := ch.Run(ctx); !res.Pass {
		t.Fatalf("lease stale past the ceiling must pass: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("node-ops").
		Get(ctx, "corpse-op-8bf4d7c9a5-w5", metav1.GetOptions{}); err != nil {
		t.Fatalf("corpse-lease pod deleted: %v", err)
	}
}

// A kube-state-metrics pod whose log tail shows a stuck 401 /
// expired SA token must persist the persistence window before the
// bounce fires — first sighting passes, past 10m the pod is deleted
// and the gauge reports the wedge.
func TestLeaseGuardKSMWedgeBounce(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset(
		probetest.ReadyPodWithIP("monitoring",
			"kube-state-metrics-6cc5c9d9b4-x1", "10.0.0.7",
			map[string]string{"app.kubernetes.io/name": "kube-state-metrics"}))
	p, ch := leaseGuardProber(cs)
	ch.ksmLogProbe = func(context.Context, *corev1.Pod) (string, error) {
		return leaseReasonKSMUnauthorized, nil
	}
	probetest.FreezeNow(p.Deps, base)

	if res := ch.Run(ctx); !res.Pass {
		t.Fatalf("first wedge sighting inside the window must pass: %+v", res)
	}
	probetest.FreezeNow(p.Deps, base.Add(ksmWedgeMinAge+time.Minute))

	if res := ch.Run(ctx); res.Pass {
		t.Fatal("persisted ksm wedge did not fail the check")
	}
	if _, err := cs.CoreV1().Pods("monitoring").
		Get(ctx, "kube-state-metrics-6cc5c9d9b4-x1", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("wedged ksm pod was not bounced: %v", err)
	}
	m := probetest.FindMetric(t, "node_automation_controller_lease_unhealthy",
		map[string]string{"namespace": "monitoring",
			"lease": "kube-state-metrics-6cc5c9d9b4-x1", "reason": "ksm_unauthorized"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("lease_unhealthy ksm series = %v, want 1", m)
	}
}

// The persisted twin of TestLeaseGuardKSMWedgeBounce: an operator
// restart wiped the in-RAM ledger, but the pod carries a first-seen
// stamp already past ksmWedgeMinAge — the first post-restart sweep
// resumes the window and the bounce fires without a fresh 10m wait.
func TestLeaseGuardKSMWedgeRestartResume(t *testing.T) {
	pod := probetest.ReadyPodWithIP("monitoring",
		"kube-state-metrics-6cc5c9d9b4-x2", "10.0.0.8",
		map[string]string{"app.kubernetes.io/name": "kube-state-metrics"})
	pod.Annotations = map[string]string{
		kube.AnnoFirstSeenKSMWedge: `{"monitoring/kube-state-metrics-6cc5c9d9b4-x2":"` +
			time.Now().Add(-(ksmWedgeMinAge + time.Minute)).
				UTC().Format(time.RFC3339) + `"}`}
	cs := fake.NewSimpleClientset(pod)
	_, ch := leaseGuardProber(cs)
	ch.ksmLogProbe = func(context.Context, *corev1.Pod) (string, error) {
		return leaseReasonKSMUnauthorized, nil
	}

	if res := ch.Run(ctx); res.Pass {
		t.Fatal("persisted wedge window did not resume on the first post-restart sweep")
	}
	if _, err := cs.CoreV1().Pods("monitoring").
		Get(ctx, "kube-state-metrics-6cc5c9d9b4-x2", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("wedged ksm pod was not bounced on the resumed window: %v", err)
	}
}
