// controller_lease_guard_test.go — coverage for the
// controller-lease-guard check: the leaseTransitions flap detector,
// the expired-lease-with-running-pods bounce (incl. the 30m cooldown
// and the maintenance-mutex gate), the healthy/fresh-lease no-ops
// and the kube-state-metrics 401-wedge persistence window + bounce.
package nodehealth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// pure helpers — leaseStaleWindow / controllerRunningPods / pruneTransitions
// ---------------------------------------------------------------------------

// The wedge window is [10m, 2h): nil renewTime can't be judged, and
// the 2h ceiling excludes an abandoned corpse.
func TestLeaseStaleWindowBoundaries(t *testing.T) {
	now := time.Now()
	build := func(renewAge time.Duration) *coordinationv1.Lease {
		l := cpLease("kube-system", "l", "h", renewAge, 0, now)
		if renewAge < 0 { // negative → nil renewTime
			l.Spec.RenewTime = nil
		}
		return l
	}
	cases := []struct {
		name      string
		renewAge  time.Duration
		nilRenew  bool
		wantStale bool
	}{
		{"nil renewTime", 0, true, false},
		{"exactly 10m — window opens inclusive", 10 * time.Minute, false, true},
		{"9m59s — still fresh", 9*time.Minute + 59*time.Second, false, false},
		{"exactly 2h — max excluded (corpse)", 2 * time.Hour, false, false},
		{"2h minus 1s — inside window", 2*time.Hour - time.Second, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var l *coordinationv1.Lease
			if tc.nilRenew {
				l = build(-1)
			} else {
				l = build(tc.renewAge)
			}
			if got := leaseStaleWindow(l, now); got != tc.wantStale {
				t.Fatalf("leaseStaleWindow = %v, want %v", got, tc.wantStale)
			}
		})
	}
}

// controllerRunningPods attributes Running pods to the lease's
// controller: holder named directly (verbatim and "<pod>_<uuid>"
// stripped), siblings via the shared controller owner UID, the
// "<lease>-*" fallback when the holder pod is gone — and refuses
// mirror-annotated, Pending and terminating pods.
func TestControllerRunningPodsAttribution(t *testing.T) {
	lease := cpLease("kube-system", "kube-controller-manager", "kube-controller-manager-pod_abc-123", 0, 0, time.Now())

	holder := corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "kube-controller-manager-pod", UID: "pod-uid",
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs",
			UID: "rs-uid", Controller: ptr.To(true),
		}},
	}}
	holder.Status.Phase = corev1.PodRunning
	sibling := corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "kube-controller-manager-pod-xyz", UID: "sib-uid",
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs",
			UID: "rs-uid", Controller: ptr.To(true),
		}},
	}}
	sibling.Status.Phase = corev1.PodRunning
	otherController := corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "unrelated", UID: "other-uid",
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "other",
			UID: "other-rs-uid", Controller: ptr.To(true),
		}},
	}}
	mirror := corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "kube-controller-manager-node1", Annotations: map[string]string{
			"kubernetes.io/config.mirror": "true",
		},
	}}
	pending := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "kube-controller-manager-pending"}}
	pending.Status.Phase = corev1.PodPending
	terminating := corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name:              "kube-controller-manager-dying",
		DeletionTimestamp: &metav1.Time{Time: time.Now()},
	}}
	unrelatedFallback := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "kube-controller-manager-orphan"}}
	unrelatedFallback.Status.Phase = corev1.PodRunning

	pods := []corev1.Pod{holder, sibling, otherController, mirror,
		pending, terminating, unrelatedFallback}

	got := controllerRunningPods(lease, pods)
	names := map[string]bool{}
	for _, p := range got {
		names[p.Name] = true
	}
	for _, want := range []string{"kube-controller-manager-pod", "kube-controller-manager-pod-xyz",
		"kube-controller-manager-orphan"} {
		if !names[want] {
			t.Fatalf("controller pod %s missing from %v", want, names)
		}
	}
	for _, unwant := range []string{"unrelated", "kube-controller-manager-node1",
		"kube-controller-manager-pending", "kube-controller-manager-dying"} {
		if names[unwant] {
			t.Fatalf("pod %s must not be attributed (got %v)", unwant, names)
		}
	}
	// The "<lease>-*" prefix fallback fires by name shape alone —
	// "orphan" rides it even while the holder pod still resolves.

	// Holder pod gone: pods named "<lease name>-*" are still the
	// wedged controller's targets.
	gone := controllerRunningPods(lease, []corev1.Pod{unrelatedFallback, mirror})
	if len(gone) != 1 || gone[0].Name != "kube-controller-manager-orphan" {
		t.Fatalf("holder-gone fallback = %v, want only the <lease>-* pod", gone)
	}

	// Verbatim holder identity without the "_<uuid>" suffix matches.
	verbatimLease := cpLease("kube-system", "l", "pod_abc-123", 0, 0, time.Now())
	plainPod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod_abc-123", UID: "u"}}
	plainPod.Status.Phase = corev1.PodRunning
	if got := controllerRunningPods(verbatimLease, []corev1.Pod{plainPod}); len(got) != 1 {
		t.Fatalf("verbatim holder identity not matched: %v", got)
	}

	// Empty/nil holder identity and no "<lease>-*" pods → nothing.
	emptyLease := cpLease("kube-system", "empty", "", 0, 0, time.Now())
	if got := controllerRunningPods(emptyLease, pods); len(got) != 0 {
		t.Fatalf("empty holder identity attributed pods: %v", got)
	}
}

// pruneTransitions drops only keys absent from the live set; a nil
// live map clears everything (live[k] is false for all keys).
func TestPruneTransitions(t *testing.T) {
	t.Run("stale removed, live retained", func(t *testing.T) {
		p := &controllerLeaseGuardCheck{transitions: map[string][]leaseTransitionSample{
			"gone":  {{transitions: 1}},
			"alive": {{transitions: 2}},
		}}
		p.pruneTransitions(map[string]bool{"alive": true})
		if _, ok := p.transitions["gone"]; ok {
			t.Fatal("stale entry not pruned")
		}
		if _, ok := p.transitions["alive"]; !ok {
			t.Fatal("live entry pruned")
		}
	})
	t.Run("empty live map clears history", func(t *testing.T) {
		p := &controllerLeaseGuardCheck{transitions: map[string][]leaseTransitionSample{
			"a": {}, "b": {},
		}}
		p.pruneTransitions(map[string]bool{})
		if len(p.transitions) != 0 {
			t.Fatalf("empty live map must clear history, kept %v", p.transitions)
		}
	})
	t.Run("nil live map behaves as empty (clears)", func(t *testing.T) {
		p := &controllerLeaseGuardCheck{transitions: map[string][]leaseTransitionSample{
			"a": {},
		}}
		p.pruneTransitions(nil)
		if len(p.transitions) != 0 {
			t.Fatalf("nil live map must clear history, kept %v", p.transitions)
		}
	})
}

// leaseGuardProber builds the prober carrying ONLY this check — the
// package's shared testProber list stays untouched while the check
// still rides the standard Deps/OpDyn wiring.
func leaseGuardProber(cs *fake.Clientset) (*probetest.Prober, *controllerLeaseGuardCheck) {
	p := probetest.NewCheckProber(cs, probetest.OpDyn(), NewControllerLeaseGuardCheck)
	return p, p.Checks[0].(*controllerLeaseGuardCheck)
}

// ksmOwnerRef builds the ReplicaSet controller ownerRef a real
// kube-state-metrics pod carries — the bounce heal refuses a
// controller-less pod (deleting it would never be recreated).
func ksmOwnerRef(rsName string) []metav1.OwnerReference {
	return []metav1.OwnerReference{{
		APIVersion: "apps/v1", Kind: "ReplicaSet",
		Name: rsName, UID: types.UID("rs-" + rsName), Controller: ptr.To(true),
	}}
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

// stateful-split-brain — a jump of 4 transitions inside 10m is thrashing: the
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
	pod := probetest.ReadyPodWithIP("monitoring",
		"kube-state-metrics-6cc5c9d9b4-x1", "10.0.0.7",
		map[string]string{"app.kubernetes.io/name": "kube-state-metrics"})
	pod.OwnerReferences = ksmOwnerRef("kube-state-metrics-6cc5c9d9b4")
	cs := fake.NewSimpleClientset(pod)
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
	pod.OwnerReferences = ksmOwnerRef("kube-state-metrics-6cc5c9d9b4")
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

// A pods-list failure in one namespace infra-fails the sweep with ONE
// grouped error + carry-forward per namespace — not once per stale
// lease sharing the same memoized failed list — and namespaces whose
// pod lists still work keep judging their leases: the flux-system
// transitions jump still lands as flapping on the following sweep.
func TestLeaseGuardPodsListErrorOncePerNamespace(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset(
		cpLease("kube-system", "op-a", "op-a-x_1", 20*time.Minute, 0, base),
		cpLease("kube-system", "op-b", "op-b-x_2", 20*time.Minute, 0, base),
		cpLease("flux-system", "flux-op", "flux-op-x_3", time.Minute, 0, base),
	)
	podLists := 0
	cs.PrependReactor("list", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			// The lease-side census lists cluster-wide (the snapshot
			// census shape) — count every pod LIST the sweep pays.
			podLists++
			return true, nil, errors.New("api down")
		})
	p, ch := leaseGuardProber(cs)
	probetest.FreezeNow(p.Deps, base)

	res := ch.Run(ctx)
	if res.Pass || res.Infra == nil {
		t.Fatalf("pods list failure must infra-fail the sweep: %+v", res)
	}
	if !strings.Contains(res.Infra.Error(), "list pods in kube-system") {
		t.Fatalf("Infra = %v, want the kube-system pods list error", res.Infra)
	}
	if podLists != 2 {
		t.Fatalf("pods listed %d times in one sweep, want 2 — one census for the lease loop (memoized across kube-system's stale leases) and one for the KSM wedge scan", podLists)
	}

	// kube-system's stale leases are skipped (no pods to judge the
	// expired signature against) but stay live in the ledger; a
	// namespace with working lists keeps being judged — the flux
	// lease's transitions jump lands as flapping next sweep.
	l, err := cs.CoordinationV1().Leases("flux-system").
		Get(ctx, "flux-op", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	*l.Spec.LeaseTransitions = 7
	if _, err := cs.CoordinationV1().Leases("flux-system").
		Update(ctx, l, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	probetest.FreezeNow(p.Deps, base.Add(5*time.Minute))

	if res := ch.Run(ctx); res.Pass {
		t.Fatal("flux-system flap must still fail the sweep")
	}
	m := probetest.FindMetric(t, "node_automation_controller_lease_unhealthy",
		map[string]string{"namespace": "flux-system",
			"lease": "flux-op", "reason": leaseReasonFlapping})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("flux-system flap series = %v, want 1", m)
	}
}

// ---------------------------------------------------------------------------
// carryNamespace — "not evaluated" must not read as "resolved"
// ---------------------------------------------------------------------------

// A namespace whose scan never ran this sweep (a list error) carries
// its HELD state forward: the emitted gauge tuples re-register under
// the same keys so Prune keeps the series, and the flap-history keys
// stay live so the persistence window is not re-armed. Only the
// failed namespace's keys carry — a working namespace's state is
// never the carry's business.
func TestCarryNamespaceRestoresHeldState(t *testing.T) {
	_, ch := leaseGuardProber(fake.NewSimpleClientset())

	// Land the state a completed sweep leaves behind, in TWO
	// namespaces so the prefix filter is exercised: one unhealthy
	// tuple + one thrashing tuple + flap history on kube-system,
	// matching state on flux-system.
	var rep, thrashRep probefw.SweepReport
	rep.Flag(controllerLeaseUnhealthyGauge,
		"kube-system/op-a/"+leaseReasonExpiredRunningPods,
		[]string{"kube-system", "op-a", leaseReasonExpiredRunningPods})
	rep.Flag(controllerLeaseUnhealthyGauge,
		"flux-system/op-b/"+leaseReasonFlapping,
		[]string{"flux-system", "op-b", leaseReasonFlapping})
	thrashRep.Flag(controllerLeaseThrashingGauge, "kube-system/op-a",
		[]string{"kube-system", "op-a"})
	thrashRep.Flag(controllerLeaseThrashingGauge, "flux-system/op-b",
		[]string{"flux-system", "op-b"})
	rep.Close(&ch.emitted, controllerLeaseUnhealthyGauge.DeleteLabelValues)
	thrashRep.Close(&ch.thrashEmitted,
		controllerLeaseThrashingGauge.DeleteLabelValues)
	ch.transitions = map[string][]leaseTransitionSample{
		"kube-system/op-a": {{at: time.Now(), transitions: 7}},
		"flux-system/op-b": {{at: time.Now(), transitions: 2}},
	}

	var carryRep, carryThrash probefw.SweepReport
	liveLeases := map[string]bool{}
	ch.carryNamespace(&carryRep, &carryThrash, liveLeases, "kube-system")

	if got := carryRep.Flagged(); got != 1 {
		t.Fatalf("carried unhealthy tuples = %d, want 1 — kube-system's tuple only", got)
	}
	if got := carryThrash.Flagged(); got != 1 {
		t.Fatalf("carried thrashing tuples = %d, want 1 — kube-system's tuple only", got)
	}
	if !liveLeases["kube-system/op-a"] {
		t.Fatal("kube-system's flap history dropped — the window would re-arm on one API flap")
	}
	if liveLeases["flux-system/op-b"] {
		t.Fatal("flux-system's transitions leaked into kube-system's carry")
	}
}
