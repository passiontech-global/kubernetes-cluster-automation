// operator_watchdog_regressions_test.go — regression coverage for the
// 2026-11-04 operator-watchdog fixes:
//   - helmRepoStaleGen: the type=oci carve-out on the
//     source-controller helmrepositories entry — OCI HelmRepositories
//     are static references since Flux v2.2 (no reconciler writes
//     status on them), so the generic stale-generation signature
//     flagged every healthy OCI repo forever.
//   - notification-controller carries ZERO CR resources — its
//     v1beta3 Alert/Provider/Receiver are static objects (operator-workqueue-watchdog
//     restored the target for lease liveness only; the
//     passiontech-k0s-nonprod false-positive incident still applies).
//   - leaderPods selector fallback capped at ONE pod (the oldest)
//     instead of deleting every matched replica — the cilium-operator
//     triple-delete that wedged the operator outright.
package watchdogs

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

// shHelmRepo builds a HelmRepository carrying a generation and an
// optional status.observedGeneration (og=0 leaves it absent — the
// state source-controller leaves on type=oci repos forever), plus the
// optional spec.type and spec.suspend knobs the predicate reads.
func shHelmRepo(name string, gen, og int64, typ string, suspend bool) *unstructured.Unstructured {
	o := probetest.UnstructuredObj("source.toolkit.fluxcd.io/v1", "HelmRepository",
		"flux-system", name, gen, og)
	if typ != "" {
		_ = unstructured.SetNestedField(o.Object, typ, "spec", "type")
	}
	if suspend {
		_ = unstructured.SetNestedField(o.Object, true, "spec", "suspend")
	}
	return o
}

// shOpPod builds an operator replica pod with a fixed
// creationTimestamp — distinct ages are how the oldest-first cap in
// the selector fallback is exercised. The pod is Running and
// ReplicaSet-owned: healOperatorLeader only deletes Running pods with
// a controller owner (something recreates them), so fixtures must
// carry that shape.
func shOpPod(ns, name string, labels map[string]string, created time.Time) *corev1.Pod {
	ctlr := true
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			UID:               types.UID("uid-" + name),
			Labels:            labels,
			CreationTimestamp: metav1.NewTime(created),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "ReplicaSet",
				Name: name + "-rs", UID: types.UID("uid-" + name + "-rs"),
				Controller: &ctlr,
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

// shScyllaTarget returns the live scylla-operator entry so the
// leaderPods tests exercise the real selector, not a copy that could
// drift from operatorTargets.
func shScyllaTarget(t *testing.T) operatorTarget {
	t.Helper()
	for _, op := range operatorTargets {
		if op.name == "scylla-operator" {
			return op
		}
	}
	t.Fatal("scylla-operator target missing from operatorTargets")
	return operatorTarget{}
}

// ---------------------------------------------------------------------------
// helmRepoStaleGen — the type=oci carve-out
// ---------------------------------------------------------------------------

// The predicate is fluxUnsuspendedStaleGen plus "type=oci is never
// stuck": an OCI HelmRepository's absent observedGeneration is its
// healthy steady state, not a stuck signal. The suspend parking
// brake and the default/http path must be untouched.
func TestHelmRepoStaleGenOCI(t *testing.T) {
	for _, tc := range []struct {
		name  string
		repo  *unstructured.Unstructured
		stuck bool
	}{
		// THE regression case: type=oci + no status at all —
		// observedGeneration absent reads 0 < gen under the generic
		// signature, so every healthy OCI repo flagged forever.
		{"oci repo with no status is never stuck",
			shHelmRepo("oci-repo", 1, 0, "oci", false), false},
		{"oci repo with a stale generation is never stuck",
			shHelmRepo("oci-repo-stale", 5, 3, "oci", false), false},
		{"default repo with a stale generation is stuck",
			shHelmRepo("http-repo", 5, 3, "default", false), true},
		{"type-absent repo with a stale generation is stuck",
			shHelmRepo("plain-repo", 5, 3, "", false), true},
		{"suspended stale repo is parked, not stuck",
			shHelmRepo("parked-repo", 5, 3, "", true), false},
		{"suspended oci repo stays ignored",
			shHelmRepo("suspended-oci", 5, 3, "oci", true), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := helmRepoStaleGen(tc.repo); got != tc.stuck {
				t.Fatalf("helmRepoStaleGen = %v, want %v", got, tc.stuck)
			}
		})
	}
}

// End-to-end on the same carve-out: a renewing source-controller
// lease beside an OCI HelmRepository carrying NO status keeps the
// check quiet and leaves nothing tracked. A stale type=default repo
// right beside it still freezes past the window — the carve-out is
// scoped to OCI, not a blanket disable of the helmrepositories entry.
func TestCheckOperatorWorkqueuesOCIHelmRepoIgnored(t *testing.T) {
	testutil.CleanupMetric(t, operatorWorkqueueFrozenGauge, "source-controller", kcmReasonStaleGen)
	base := time.Now()
	cs := fake.NewSimpleClientset(
		shLease("flux-system", "source-controller-leader-election",
			"source-controller-aa_uid", 2*time.Second, base))
	// Exactly what source-controller leaves on an OCI HelmRepository
	// forever — no status block, observedGeneration absent.
	ociRepo := shHelmRepo("oci-repo", 1, 0, "oci", false)
	p := testProberDyn(cs, probetest.OpDyn(ociRepo))
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*operatorWorkqueueCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("OCI HelmRepository must not freeze the check: %+v", res)
	}
	for _, k := range probetest.LedgerKeys(&probetest.MustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen) {
		if strings.HasPrefix(k, "source-controller/helmrepositories/") {
			t.Fatalf("OCI repo must not be tracked: %v", k)
		}
	}

	// Sanity — the entry itself still works: a stale default-type
	// repo past the 20m window freezes the check.
	stale := shHelmRepo("http-repo", 5, 3, "default", false)
	p2 := testProberDyn(cs, probetest.OpDyn(ociRepo, stale))
	p2.Now = func() time.Time { return base }
	probetest.MustCheck[*operatorWorkqueueCheck](t, p2).opFirstSeen.
		Observe("source-controller/helmrepositories/flux-system/http-repo/"+kcmReasonStaleGen,
			base.Add(-time.Hour))
	if res := probetest.MustCheck[*operatorWorkqueueCheck](t, p2).Run(ctx); res.Pass {
		t.Fatal("stale type=default HelmRepository must still FAIL")
	}
	if v, _ := shOpFrozenGauge(t, "source-controller", kcmReasonStaleGen); v != 1 {
		t.Fatalf("frozen gauge = %v, want 1", v)
	}
}

// ---------------------------------------------------------------------------
// leaderPods selector fallback — capped at one pod
// ---------------------------------------------------------------------------

// When holderIdentity resolves to no pod, the selector fallback
// cannot tell the leader from its standbys — it must return at most
// ONE pod, the oldest by creationTimestamp, never every matched
// replica (the 2026-11-04 cilium-operator triple-delete). A
// holderIdentity that DOES resolve still wins over age — the named
// leader is returned even when an older standby exists.
func TestLeaderPodsSelectorFallbackCapsAtOne(t *testing.T) {
	base := time.Now()
	op := shScyllaTarget(t)
	labels := map[string]string{"app.kubernetes.io/name": "scylla-operator"}

	oldest := shOpPod("scylla-operator", "scylla-operator-0", labels, base.Add(-3*time.Hour))
	mid := shOpPod("scylla-operator", "scylla-operator-1", labels, base.Add(-2*time.Hour))
	newest := shOpPod("scylla-operator", "scylla-operator-2", labels, base.Add(-time.Hour))
	// Create order shuffled — the cap must pick by timestamp, not by
	// list order.
	cs := fake.NewSimpleClientset(newest, oldest, mid)
	p := testProberDyn(cs, probetest.OpDyn())
	lease := shLease("scylla-operator", "scylla-operator-lock",
		"missing-pod_uuid", 2*time.Second, base)

	pods, err := probetest.MustCheck[*operatorWorkqueueCheck](t, p).leaderPods(ctx, op, lease)
	if err != nil {
		t.Fatalf("leaderPods: %v", err)
	}
	if len(pods) != 1 {
		t.Fatalf("selector fallback returned %d pods, want exactly 1", len(pods))
	}
	if pods[0].Name != oldest.Name {
		t.Fatalf("selector fallback picked %q, want the oldest %q",
			pods[0].Name, oldest.Name)
	}

	// A holderIdentity naming a real pod resolves it directly — the
	// older standby must NOT be preferred.
	leader := shOpPod("scylla-operator", "scylla-operator-leader", labels, base.Add(-time.Hour))
	standby := shOpPod("scylla-operator", "scylla-operator-standby", labels, base.Add(-3*time.Hour))
	cs2 := fake.NewSimpleClientset(standby, leader)
	p2 := testProberDyn(cs2, probetest.OpDyn())
	lease2 := shLease("scylla-operator", "scylla-operator-lock",
		"scylla-operator-leader_9f8e", 2*time.Second, base)

	pods, err = probetest.MustCheck[*operatorWorkqueueCheck](t, p2).leaderPods(ctx, op, lease2)
	if err != nil {
		t.Fatalf("leaderPods: %v", err)
	}
	if len(pods) != 1 || pods[0].Name != leader.Name {
		t.Fatalf("resolvable holderIdentity must return %q, got %v",
			leader.Name, pods)
	}
}

// The cap end-to-end: a stuck ScyllaCluster past the window with an
// unresolvable holderIdentity deletes ONE operator replica — the
// oldest — and the heals counter moves by 1. Two replicas survive.
func TestCheckOperatorWorkqueuesHealsOneReplicaOnly(t *testing.T) {
	testutil.CleanupMetric(t, operatorWorkqueueFrozenGauge, "scylla-operator", kcmReasonStaleGen)
	base := time.Now()
	labels := map[string]string{"app.kubernetes.io/name": "scylla-operator"}
	oldest := shOpPod("scylla-operator", "scylla-operator-0", labels, base.Add(-3*time.Hour))
	mid := shOpPod("scylla-operator", "scylla-operator-1", labels, base.Add(-2*time.Hour))
	newest := shOpPod("scylla-operator", "scylla-operator-2", labels, base.Add(-time.Hour))
	cs := fake.NewSimpleClientset(
		// Holder names a pod that doesn't exist — forces the
		// selector fallback, the path that used to delete all three.
		shLease("scylla-operator", "scylla-operator-lock",
			"missing_uid", 2*time.Second, base),
		newest, mid, oldest)
	stuck := probetest.UnstructuredObj("scylla.scylladb.com/v1", "ScyllaCluster",
		"scylla", "db", 9, 4)
	p := testProberDyn(cs, probetest.OpDyn(stuck))
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen.
		Observe("scylla-operator/scyllaclusters/scylla/db/"+kcmReasonStaleGen, base.Add(-time.Hour))
	before := shOpHealsCount(t, "scylla-operator", kcmReasonStaleGen)

	if res := probetest.MustCheck[*operatorWorkqueueCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("stuck ScyllaCluster past 20m with a renewing lease must FAIL")
	}

	// Exactly the oldest replica is deleted; the other two survive.
	if _, err := cs.CoreV1().Pods("scylla-operator").
		Get(ctx, oldest.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("oldest replica %q must be the one deleted, err=%v",
			oldest.Name, err)
	}
	for _, name := range []string{mid.Name, newest.Name} {
		if _, err := cs.CoreV1().Pods("scylla-operator").
			Get(ctx, name, metav1.GetOptions{}); err != nil {
			t.Fatalf("survivor %q deleted — the fallback must kill ONE pod only", name)
		}
	}
	if got := shOpHealsCount(t, "scylla-operator", kcmReasonStaleGen); got != before+1 {
		t.Fatalf("heals total = %v, want %v", got, before+1)
	}
}

// ---------------------------------------------------------------------------
// notification-controller — zero CR resources (operator-workqueue-watchdog)
// ---------------------------------------------------------------------------

// The notification-controller target is back for lease-liveness
// parity but watches NO CRs: a renewing notification lease beside
// never-reconciled v1beta3 Alert/Provider/Receiver objects keeps the
// check quiet AND leaves nothing tracked — the objects are static
// (no reconciler writes status on them since the API dropped the
// reconcilers), so watching them could only produce permanent false
// positives.
func TestCheckOperatorWorkqueuesNotificationObjectsIgnored(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset(
		shLease("flux-system", "notification-controller-leader-election",
			"notification-controller-aa_uid", 2*time.Second, base))
	alert := probetest.UnstructuredObj("notification.toolkit.fluxcd.io/v1beta3", "Alert",
		"flux-system", "oncall", 5, 0)
	provider := probetest.UnstructuredObj("notification.toolkit.fluxcd.io/v1beta3", "Provider",
		"flux-system", "slack", 5, 0)
	receiver := probetest.UnstructuredObj("notification.toolkit.fluxcd.io/v1beta3", "Receiver",
		"flux-system", "all", 5, 0)
	p := testProberDyn(cs, probetest.OpDyn(alert, provider, receiver))
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*operatorWorkqueueCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("static notification objects must keep the check quiet: %+v", res)
	}
	// Zero resources means nothing is even scanned — no first-seen
	// keys may be stamped for the static notification objects.
	for _, k := range probetest.LedgerKeys(&probetest.MustCheck[*operatorWorkqueueCheck](t, p).opFirstSeen) {
		if strings.HasPrefix(k, "notification-controller/") {
			t.Fatalf("notification objects must not be tracked: %v", k)
		}
	}
}
