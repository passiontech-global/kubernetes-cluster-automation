package watchdogs

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

// stsUnstickFixture builds the wedged-rollout world: one
// RollingUpdate/OrderedReady StatefulSet mid-rollout plus the pods
// the test shapes. now is the frozen sweep clock.
func stsUnstickFixture(t *testing.T, now time.Time,
	sts *appsv1.StatefulSet, pods ...*corev1.Pod) (*fake.Clientset, *stsRolloutUnstickCheck) {

	t.Helper()
	objs := []runtime.Object{sts}
	for _, p := range pods {
		objs = append(objs, p)
	}
	cs := fake.NewSimpleClientset(objs...)
	d := probetest.NewDeps(cs, probetest.OpDyn())
	probetest.FreezeNow(d, now)
	return cs, &stsRolloutUnstickCheck{Deps: d, healEnabled: true}
}

// rollingSTS builds a StatefulSet mid-RollingUpdate: currentRevision
// behind updateRevision.
func rollingSTS(ns, name string) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: appsv1.StatefulSetSpec{
			Replicas:            ptr.To(int32(1)),
			PodManagementPolicy: appsv1.OrderedReadyPodManagement,
			UpdateStrategy: appsv1.StatefulSetUpdateStrategy{
				Type: appsv1.RollingUpdateStatefulSetStrategyType,
			},
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}},
		},
		Status: appsv1.StatefulSetStatus{
			CurrentRevision: "rev-old",
			UpdateRevision:  "rev-new",
		},
	}
}

// stsPod builds an STS-owned pod at the given controller-revision-hash
// with the given waiting reason ("" = running, ready).
func stsPod(ns, stsName, name, rev, waitReason string, ready bool) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name,
			Labels: map[string]string{
				"app":                      stsName,
				"controller-revision-hash": rev,
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "StatefulSet",
				Name: stsName, Controller: ptr.To(true),
			}},
		},
		Spec: corev1.PodSpec{NodeName: "node-1"},
	}
	if ready {
		pod.Status.Conditions = []corev1.PodCondition{{
			Type: corev1.PodReady, Status: corev1.ConditionTrue,
			LastTransitionTime: metav1.NewTime(time.Now().Add(-time.Hour)),
		}}
	} else {
		pod.Status.Conditions = []corev1.PodCondition{{
			Type: corev1.PodReady, Status: corev1.ConditionFalse,
			LastTransitionTime: metav1.NewTime(time.Now().Add(-time.Hour)),
		}}
		if waitReason != "" {
			pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
				Name: "c",
				State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
					Reason: waitReason,
				}},
			}}
		}
	}
	return pod
}

// A pod stuck CrashLoopBackOff on the OLD revision wedges the roll:
// first sighting arms the 15m window (no flag, no delete), the aged
// signature flags the gauge and deletes exactly that pod.
func TestStatefulSetRolloutUnstickHealsWedgedPod(t *testing.T) {
	now := time.Now()
	sts := rollingSTS("app", "db")
	wedged := stsPod("app", "db", "db-0", "rev-old", "CrashLoopBackOff", false)
	cs, chk := stsUnstickFixture(t, now, sts, wedged)

	// First sighting — inside the window, no verdict yet.
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if !res.Pass {
		t.Fatalf("first sighting must not flag: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("app").Get(ctx, "db-0", metav1.GetOptions{}); err != nil {
		t.Fatalf("pod deleted inside window: %v", err)
	}

	// Age past the 15m fuse.
	probetest.FreezeNow(chk.Deps, now.Add(16*time.Minute))
	res = chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatalf("aged wedge must flag: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("app").Get(ctx, "db-0", metav1.GetOptions{}); err == nil {
		t.Fatal("wedged pod was not deleted")
	}
	if got := testutil.ToFloat64(stsRolloutWedgedGauge.WithLabelValues("app", "db", "db-0")); got != 1 {
		t.Fatalf("wedge gauge = %v, want 1", got)
	}
}

// Negative: a pod already at updateRevision, a Ready pod, or a pod
// in a transient ContainerCreating state must never flag or heal.
func TestStatefulSetRolloutUnstickLeavesHealthyPods(t *testing.T) {
	now := time.Now()
	sts := rollingSTS("app", "db")
	pods := []*corev1.Pod{
		stsPod("app", "db", "db-0", "rev-new", "", true), // new rev, ready
		stsPod("app", "db", "db-1", "rev-old", "", true), // old rev but ready
		stsPod("app", "db", "db-2", "rev-old", "ContainerCreating", false),
	}
	cs, chk := stsUnstickFixture(t, now, sts, pods...)
	probetest.FreezeNow(chk.Deps, now.Add(time.Hour))

	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if !res.Pass {
		t.Fatalf("healthy roll must pass: %+v", res)
	}
	for _, name := range []string{"db-0", "db-1", "db-2"} {
		if _, err := cs.CoreV1().Pods("app").Get(ctx, name, metav1.GetOptions{}); err != nil {
			t.Fatalf("healthy pod %s deleted: %v", name, err)
		}
	}
}

// A converged set (currentRevision == updateRevision) is never
// touched even with a CrashLoopBackOff member.
func TestStatefulSetRolloutUnstickIgnoresSettledSet(t *testing.T) {
	now := time.Now()
	sts := rollingSTS("app", "db")
	sts.Status.CurrentRevision = "rev-new"
	pod := stsPod("app", "db", "db-0", "rev-new", "CrashLoopBackOff", false)
	cs, chk := stsUnstickFixture(t, now, sts, pod)
	probetest.FreezeNow(chk.Deps, now.Add(time.Hour))

	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if !res.Pass {
		t.Fatalf("settled set must pass: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("app").Get(ctx, "db-0", metav1.GetOptions{}); err != nil {
		t.Fatalf("settled-set pod deleted: %v", err)
	}
}

// K8s #67250 rollback shape: the operator rolled v1→v2, pod-(N-1)
// CrashLooped, then the template was rolled back so
// CurrentRevision == UpdateRevision == rev-v1 — while the wedged pod
// still carries the rev-v2 controller-revision-hash. The per-pod
// hash mismatch is the detector; revision inequality is NOT required.
func TestStatefulSetRolloutUnstickHealsRollbackShape(t *testing.T) {
	now := time.Now()
	sts := rollingSTS("app", "db")
	sts.Status.CurrentRevision = "rev-v1"
	sts.Status.UpdateRevision = "rev-v1" // converged revisions, stale pod remains
	wedged := stsPod("app", "db", "db-0", "rev-v2", "CrashLoopBackOff", false)
	cs, chk := stsUnstickFixture(t, now, sts, wedged)

	chk.Run(probetest.SweepCtx(ctx, chk.Deps)) // arm the 15m window
	probetest.FreezeNow(chk.Deps, now.Add(16*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatalf("rollback-shaped wedge must flag: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("app").Get(ctx, "db-0", metav1.GetOptions{}); err == nil {
		t.Fatal("rollback-wedged pod was not deleted")
	}
}

// RollingUpdate.Partition is the canary contract: pods with ordinal
// below the partition intentionally keep the old revision and must
// never be treated as wedged.
func TestStatefulSetRolloutUnstickRespectsPartition(t *testing.T) {
	now := time.Now()
	sts := rollingSTS("app", "db")
	sts.Spec.UpdateStrategy.RollingUpdate = &appsv1.RollingUpdateStatefulSetStrategy{
		Partition: ptr.To(int32(2)),
	}
	// db-0 and db-1 are below the partition — old rev is CORRECT for
	// them even in a CrashLoop; db-2 is at/above it and wedged.
	pods := []*corev1.Pod{
		stsPod("app", "db", "db-0", "rev-old", "CrashLoopBackOff", false),
		stsPod("app", "db", "db-1", "rev-old", "ImagePullBackOff", false),
		stsPod("app", "db", "db-2", "rev-old", "CrashLoopBackOff", false),
	}
	cs, chk := stsUnstickFixture(t, now, sts, pods...)
	chk.Run(probetest.SweepCtx(ctx, chk.Deps)) // arm the 15m window
	probetest.FreezeNow(chk.Deps, now.Add(time.Hour))

	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatalf("above-partition wedge must flag: %+v", res)
	}
	for _, name := range []string{"db-0", "db-1"} {
		if _, err := cs.CoreV1().Pods("app").Get(ctx, name, metav1.GetOptions{}); err != nil {
			t.Fatalf("below-partition pod %s deleted: %v", name, err)
		}
	}
	if _, err := cs.CoreV1().Pods("app").Get(ctx, "db-2", metav1.GetOptions{}); err == nil {
		t.Fatal("above-partition wedged pod was not deleted")
	}
}

// An explicit replicas=0 skips the set entirely — no roll can be in
// flight, even when a pod still carries a hard-error revision.
func TestStatefulSetRolloutUnstickSkipsZeroReplicaSet(t *testing.T) {
	now := time.Now()
	sts := rollingSTS("app", "db")
	sts.Spec.Replicas = ptr.To(int32(0))
	wedged := stsPod("app", "db", "db-0", "rev-old", "CrashLoopBackOff", false)
	cs, chk := stsUnstickFixture(t, now, sts, wedged)
	probetest.FreezeNow(chk.Deps, now.Add(time.Hour))

	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("zero-replica StatefulSet must not flag: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("app").Get(ctx, "db-0", metav1.GetOptions{}); err != nil {
		t.Fatalf("zero-replica StatefulSet pod was deleted: %v", err)
	}
}

// The sort comparator must be a strict weak ordering: deciding the
// parseable/unparseable split BEFORE the name tie-break keeps it
// transitive even when an unparseable pod's name sorts between two
// parseable ordinals ("db-0" < "db-aaa" < "db-5").
func TestStatefulSetRolloutOrdinalComparatorIsStrictWeakOrdering(t *testing.T) {
	a := stsPod("app", "db", "db-0", "rev-old", "", false)
	b := stsPod("app", "db", "db-aaa", "rev-old", "", false) // unparseable ordinal
	c := stsPod("app", "db", "db-5", "rev-old", "", false)
	pods := []*corev1.Pod{a, b, c}
	for i := range pods {
		for j := range pods {
			ab := stsPodOrdinalCompare("db", pods[i], pods[j])
			ba := stsPodOrdinalCompare("db", pods[j], pods[i])
			if (ab < 0) == (ba < 0) && i != j {
				t.Fatalf("antisymmetry violated for %s vs %s: %d / %d",
					pods[i].Name, pods[j].Name, ab, ba)
			}
			if (ab == 0) != (ba == 0) {
				t.Fatalf("reflexivity violated for %s vs %s: %d / %d",
					pods[i].Name, pods[j].Name, ab, ba)
			}
		}
	}
	// Highest parseable ordinal first; unparseable last.
	if stsPodOrdinalCompare("db", c, a) >= 0 ||
		stsPodOrdinalCompare("db", a, b) >= 0 ||
		stsPodOrdinalCompare("db", c, b) >= 0 {
		t.Fatal("expected c < a < b (highest ordinal first, unparseable last)")
	}
}

// healEnabled=false leaves the wedge detected (gauge + FAIL) but
// never deletes.
func TestStatefulSetRolloutUnstickReportOnly(t *testing.T) {
	now := time.Now()
	sts := rollingSTS("app", "db")
	wedged := stsPod("app", "db", "db-0", "rev-old", "ImagePullBackOff", false)
	cs := fake.NewSimpleClientset(sts, wedged)
	d := probetest.NewDeps(cs, probetest.OpDyn())
	probetest.FreezeNow(d, now)
	chk := &stsRolloutUnstickCheck{Deps: d, healEnabled: false}

	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	probetest.FreezeNow(d, now.Add(16*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatalf("report-only wedge must still flag: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("app").Get(ctx, "db-0", metav1.GetOptions{}); err != nil {
		t.Fatalf("report-only mode deleted the pod: %v", err)
	}
}
