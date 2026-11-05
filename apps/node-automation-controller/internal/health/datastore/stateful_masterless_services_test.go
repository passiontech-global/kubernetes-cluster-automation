// stateful_masterless_services_test.go — coverage for the
// stateful-masterless-services check: the W7-C3 dragonfly
// dual-replica deadlock heal and the W4/W10-FIX4 db-operator pod
// prefix resolution.
package datastore

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// W4 — dbOperatorFor matches a pod-template label carrying the
// operator name; a generic STS matches nothing.
func TestDBOperatorFor(t *testing.T) {
	sts := &appsv1.StatefulSet{
		Spec: appsv1.StatefulSetSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app.kubernetes.io/managed-by": "pxc-operator"}}}},
	}
	if got := dbOperatorFor(sts); got != "pxc-operator" {
		t.Fatalf("dbOperatorFor=%q, want pxc-operator", got)
	}
	if got := dbOperatorFor(&appsv1.StatefulSet{}); got != "" {
		t.Fatalf("dbOperatorFor=%q, want empty", got)
	}
}

// W10-FIX4 — dbOperatorPodPrefixes resolves BOTH spellings of a
// Percona operator to the same alias group: the long Deployment
// name AND the short chart alias must yield every pod-name prefix,
// whichever spelling dbOperatorFor matched.
func TestDBOperatorPodPrefixes(t *testing.T) {
	want := []string{"percona-xtradb-cluster-operator", "pxc-operator"}
	for _, in := range []string{
		"percona-xtradb-cluster-operator", "pxc-operator"} {
		got := dbOperatorPodPrefixes(in)
		if len(got) != len(want) {
			t.Fatalf("dbOperatorPodPrefixes(%q)=%v, want %v", in, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("dbOperatorPodPrefixes(%q)=%v, want %v", in, got, want)
			}
		}
	}
	// Non-aliased operator → bare name only.
	if got := dbOperatorPodPrefixes("scylla-operator"); len(got) != 1 ||
		got[0] != "scylla-operator" {
		t.Fatalf("dbOperatorPodPrefixes(scylla)=%v, want [scylla-operator]", got)
	}
}

// ---------------------------------------------------------------------------
// W7-C3 — dragonfly dual-replica deadlock heal
// ---------------------------------------------------------------------------

// dragonflyRolePod builds a Ready STS pod with the given role label
// ("" = no role label — the dual-replica wedge).
func dragonflyRolePod(ns, name, role string, ready bool) *corev1.Pod {
	labels := map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"}
	if role != "" {
		labels["role"] = role
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name, UID: types.UID(name), Labels: labels,
		},
	}
	if ready {
		pod.Status.Conditions = []corev1.PodCondition{{
			Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	}
	return pod
}

// Deadlock end-to-end: 12m masterless streak, operator heal landed
// 4m ago, both pods Ready with role=replica → ordinal-0 deleted,
// counter bumped, stamp persisted on the STS.
func TestDeadlockDeletesLowestOrdinal(t *testing.T) {
	metrics.DragonflyMasterlessPodHealsTotal.DeleteLabelValues("db", "dragonfly")
	t.Cleanup(func() {
		metrics.DragonflyMasterlessPodHealsTotal.DeleteLabelValues("db", "dragonfly")
		metrics.StatefulServiceZeroEndpoints.DeleteLabelValues("db", "dragonfly-master", "dragonfly")
	})
	base := time.Now()
	sts := shSTS("db", "dragonfly", 2,
		map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"})
	svc := shMasterSvc("db", "dragonfly-master",
		map[string]string{"app": "dragonfly", "role": "master"})
	cs := fake.NewSimpleClientset(sts, svc,
		dragonflyRolePod("db", "dragonfly-0", "replica", true),
		dragonflyRolePod("db", "dragonfly-1", "replica", true))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	mustCheck[*statefulMasterlessCheck](t, p).stsZeroSince.
		Observe("db/dragonfly-master/dragonfly", base.Add(-12*time.Minute))
	mustCheck[*statefulMasterlessCheck](t, p).drOpHealAt = base.Add(-4 * time.Minute)

	if res := mustCheck[*statefulMasterlessCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("deadlocked masterless service must FAIL")
	}
	if _, err := cs.CoreV1().Pods("db").
		Get(ctx, "dragonfly-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("ordinal-0 pod must be deleted, err=%v", err)
	}
	if _, err := cs.CoreV1().Pods("db").
		Get(ctx, "dragonfly-1", metav1.GetOptions{}); err != nil {
		t.Fatal("only the lowest ordinal may be reaped")
	}
	m := probetest.FindMetric(t, "node_automation_dragonfly_masterless_pod_heals_total",
		map[string]string{"namespace": "db", "statefulset": "dragonfly"})
	if m == nil || m.GetCounter().GetValue() != 1 {
		t.Fatal("deadlock heals counter = 0, want 1")
	}
	gotSTS, err := cs.AppsV1().StatefulSets("db").Get(ctx, "dragonfly", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if gotSTS.Annotations[dragonflyPodHealAnno] == "" {
		t.Fatal("pod-heal stamp annotation missing on the STS")
	}
}

// The step-2 heal must wait for the operator restart to settle — a
// 1m-old operator heal keeps ordinal-0 alive.
func TestDeadlockWaitsForOperatorSettle(t *testing.T) {
	base := time.Now()
	sts := shSTS("db", "dragonfly", 2,
		map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"})
	svc := shMasterSvc("db", "dragonfly-master",
		map[string]string{"app": "dragonfly", "role": "master"})
	cs := fake.NewSimpleClientset(sts, svc,
		dragonflyRolePod("db", "dragonfly-0", "replica", true),
		dragonflyRolePod("db", "dragonfly-1", "replica", true))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	mustCheck[*statefulMasterlessCheck](t, p).stsZeroSince.
		Observe("db/dragonfly-master/dragonfly", base.Add(-12*time.Minute))
	mustCheck[*statefulMasterlessCheck](t, p).drOpHealAt = base.Add(-time.Minute)

	_ = mustCheck[*statefulMasterlessCheck](t, p).Run(ctx)
	if _, err := cs.CoreV1().Pods("db").
		Get(ctx, "dragonfly-0", metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted while the operator heal is still settling")
	}
}

// No operator heal on record at all — step 1 never landed, so the
// pod kill must not skip ahead.
func TestDeadlockRequiresOperatorHeal(t *testing.T) {
	base := time.Now()
	sts := shSTS("db", "dragonfly", 2,
		map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"})
	svc := shMasterSvc("db", "dragonfly-master",
		map[string]string{"app": "dragonfly", "role": "master"})
	cs := fake.NewSimpleClientset(sts, svc,
		dragonflyRolePod("db", "dragonfly-0", "replica", true))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	mustCheck[*statefulMasterlessCheck](t, p).stsZeroSince.
		Observe("db/dragonfly-master/dragonfly", base.Add(-12*time.Minute))

	_ = mustCheck[*statefulMasterlessCheck](t, p).Run(ctx)
	if _, err := cs.CoreV1().Pods("db").
		Get(ctx, "dragonfly-0", metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted with no operator heal on record")
	}
}

// A pod already carrying role=master is a live re-election — the
// kill would fight it.
func TestDeadlockSkipsWhenMasterPresent(t *testing.T) {
	base := time.Now()
	sts := shSTS("db", "dragonfly", 2,
		map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"})
	svc := shMasterSvc("db", "dragonfly-master",
		map[string]string{"app": "dragonfly", "role": "master"})
	cs := fake.NewSimpleClientset(sts, svc,
		dragonflyRolePod("db", "dragonfly-0", "master", true),
		dragonflyRolePod("db", "dragonfly-1", "replica", true))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	mustCheck[*statefulMasterlessCheck](t, p).stsZeroSince.
		Observe("db/dragonfly-master/dragonfly", base.Add(-12*time.Minute))
	mustCheck[*statefulMasterlessCheck](t, p).drOpHealAt = base.Add(-4 * time.Minute)

	_ = mustCheck[*statefulMasterlessCheck](t, p).Run(ctx)
	if _, err := cs.CoreV1().Pods("db").
		Get(ctx, "dragonfly-0", metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted while a pod already holds the master role")
	}
}

// The 30m pod-heal cooldown (in-RAM half) keeps a second delete
// from firing.
func TestDeadlockHealCooldown(t *testing.T) {
	base := time.Now()
	sts := shSTS("db", "dragonfly", 2,
		map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"})
	svc := shMasterSvc("db", "dragonfly-master",
		map[string]string{"app": "dragonfly", "role": "master"})
	cs := fake.NewSimpleClientset(sts, svc,
		dragonflyRolePod("db", "dragonfly-0", "replica", true))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	mustCheck[*statefulMasterlessCheck](t, p).stsZeroSince.
		Observe("db/dragonfly-master/dragonfly", base.Add(-12*time.Minute))
	mustCheck[*statefulMasterlessCheck](t, p).drOpHealAt = base.Add(-4 * time.Minute)
	mustCheck[*statefulMasterlessCheck](t, p).drPodHealed.
		Stamp("db/dragonfly", base.Add(-10*time.Minute))

	_ = mustCheck[*statefulMasterlessCheck](t, p).Run(ctx)
	if _, err := cs.CoreV1().Pods("db").
		Get(ctx, "dragonfly-0", metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted inside the 30m deadlock cooldown")
	}
}

// Deliberate maintenance (a cordoned node) defers the pod kill.
func TestDeadlockMaintenanceDefers(t *testing.T) {
	base := time.Now()
	cordoned := testutil.Node("w1", corev1.ConditionTrue, nil)
	cordoned.Spec.Unschedulable = true
	sts := shSTS("db", "dragonfly", 2,
		map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"})
	svc := shMasterSvc("db", "dragonfly-master",
		map[string]string{"app": "dragonfly", "role": "master"})
	cs := fake.NewSimpleClientset(cordoned, sts, svc,
		dragonflyRolePod("db", "dragonfly-0", "replica", true))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	mustCheck[*statefulMasterlessCheck](t, p).stsZeroSince.
		Observe("db/dragonfly-master/dragonfly", base.Add(-12*time.Minute))
	mustCheck[*statefulMasterlessCheck](t, p).drOpHealAt = base.Add(-4 * time.Minute)

	_ = mustCheck[*statefulMasterlessCheck](t, p).Run(ctx)
	if _, err := cs.CoreV1().Pods("db").
		Get(ctx, "dragonfly-0", metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted during maintenance")
	}
}
