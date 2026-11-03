package system

import (
	"errors"
	"strconv"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

// ---------------------------------------------------------------------------
// Builders (sr-prefixed to stay unique across sibling test files)
// ---------------------------------------------------------------------------

func srSTS(ns, name string, optedIn bool) *appsv1.StatefulSet {
	annos := map[string]string{}
	if optedIn {
		annos[stsAutoRollAnno] = "true"
	}
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Annotations: annos},
		Spec: appsv1.StatefulSetSpec{
			UpdateStrategy: appsv1.StatefulSetUpdateStrategy{
				Type: appsv1.OnDeleteStatefulSetStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": name},
				},
			},
		},
		Status: appsv1.StatefulSetStatus{
			CurrentRevision: "rev-old",
			UpdateRevision:  "rev-new",
		},
	}
}

// srPod builds a Ready, STS-owned pod on `revision`, Ready since
// `readyAgo` ago.
func srPod(stsName string, ord int, revision string, readyAgo time.Duration) *corev1.Pod {
	name := stsName + "-" + strconv.Itoa(ord)
	isController := true
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: name,
			Labels: map[string]string{
				"app":                stsName,
				stsRevisionHashLabel: revision,
			},
			OwnerReferences: []metav1.OwnerReference{{
				Kind: "StatefulSet", Name: stsName, Controller: &isController,
			}},
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
		},
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{{
				Type:               corev1.PodReady,
				Status:             corev1.ConditionTrue,
				LastTransitionTime: metav1.NewTime(time.Now().Add(-readyAgo)),
			}},
		},
	}
}

func srPodExists(t *testing.T, cs *fake.Clientset, ns, name string) bool {
	t.Helper()
	_, err := cs.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
	return err == nil
}

func srRoller(cs *fake.Clientset, now time.Time) *statefulSetOnDeleteRoller {
	return &statefulSetOnDeleteRoller{cs: cs,
		nowFn: func() time.Time { return now }, driftSince: map[string]time.Time{}}
}

// srNodes returns n Ready workers.
func srNodes(n int) []runtime.Object {
	var out []runtime.Object
	for i := 0; i < n; i++ {
		out = append(out, node("w"+strconv.Itoa(i), corev1.ConditionTrue, nil))
	}
	return out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// Full happy path: drift held >=30m, all gates pass — the
// highest-ordinal stale pod is deleted and counted; the new-revision
// pod and the lower-ordinal stale pod stay.
func TestStatefulSetRollerDeletesHighestStaleOrdinal(t *testing.T) {
	metrics.StatefulSetOnDeletePodsRolledTotal.DeleteLabelValues("apps", "db")
	t.Cleanup(func() {
		metrics.StatefulSetOnDeletePodsRolledTotal.DeleteLabelValues("apps", "db")
	})

	t0 := time.Now()
	objs := srNodes(2)
	objs = append(objs,
		srSTS("apps", "db", true),
		srPod("db", 0, "rev-old", 30*time.Minute),
		srPod("db", 1, "rev-old", 30*time.Minute),
		srPod("db", 2, "rev-new", 30*time.Minute))
	cs := fake.NewSimpleClientset(objs...)
	r := srRoller(cs, t0)

	if err := r.run(ctx); err != nil { // seeds driftSince
		t.Fatal(err)
	}
	if !srPodExists(t, cs, "apps", "db-1") {
		t.Fatal("pod deleted before the 30m drift window")
	}
	r.nowFn = func() time.Time { return t0.Add(31 * time.Minute) }
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if srPodExists(t, cs, "apps", "db-1") {
		t.Fatal("highest stale-ordinal pod not deleted")
	}
	for _, name := range []string{"db-0", "db-2"} {
		if !srPodExists(t, cs, "apps", name) {
			t.Fatalf("pod %s wrongly deleted — only one roll per cycle", name)
		}
	}
	if got := ptestutil.ToFloat64(metrics.StatefulSetOnDeletePodsRolledTotal.
		WithLabelValues("apps", "db")); got != 1 {
		t.Fatalf("rolled counter = %v, want 1", got)
	}
}

// An unannotated OnDelete StatefulSet is a manual-roll policy — never
// tracked, never touched.
func TestStatefulSetRollerRequiresOptIn(t *testing.T) {
	t0 := time.Now()
	objs := srNodes(1)
	objs = append(objs,
		srSTS("apps", "db", false), // no annotation
		srPod("db", 0, "rev-old", 30*time.Minute))
	cs := fake.NewSimpleClientset(objs...)
	r := srRoller(cs, t0)
	for _, when := range []time.Duration{0, time.Hour} {
		r.nowFn = func() time.Time { return t0.Add(when) }
		if err := r.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if !srPodExists(t, cs, "apps", "db-0") {
		t.Fatal("unannotated StatefulSet rolled")
	}
	if len(r.driftSince) != 0 {
		t.Fatal("unannotated StatefulSet tracked for drift")
	}
}

// RollingUpdate StatefulSets are never candidates even with the
// annotation — the strategy field decides, not the opt-in.
func TestStatefulSetRollerRequiresOnDelete(t *testing.T) {
	t0 := time.Now()
	sts := srSTS("apps", "db", true)
	sts.Spec.UpdateStrategy.Type = appsv1.RollingUpdateStatefulSetStrategyType
	objs := srNodes(1)
	objs = append(objs, sts, srPod("db", 0, "rev-old", 30*time.Minute))
	cs := fake.NewSimpleClientset(objs...)
	r := srRoller(cs, t0)
	r.nowFn = func() time.Time { return t0.Add(time.Hour) }
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !srPodExists(t, cs, "apps", "db-0") {
		t.Fatal("RollingUpdate StatefulSet rolled")
	}
}

// A cordoned node vetoes the whole sweep — the workload must not
// lose a member while the cluster cannot reschedule it.
func TestStatefulSetRollerCordonedNodeGate(t *testing.T) {
	t0 := time.Now()
	cordoned := node("w1", corev1.ConditionTrue, nil)
	cordoned.Spec.Unschedulable = true
	objs := []runtime.Object{cordoned}
	objs = append(objs,
		srSTS("apps", "db", true),
		srPod("db", 0, "rev-old", 30*time.Minute))
	cs := fake.NewSimpleClientset(objs...)
	r := srRoller(cs, t0)
	r.driftSince["apps/db"] = t0.Add(-time.Hour) // pre-aged drift
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !srPodExists(t, cs, "apps", "db-0") {
		t.Fatal("pod deleted while a node is cordoned")
	}
}

// A matching PDB with disruptionsAllowed=0 blocks the roll; a PDB
// that does not select the pod does not.
func TestStatefulSetRollerPDBGate(t *testing.T) {
	t0 := time.Now()
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "db-pdb"},
		Spec: policyv1.PodDisruptionBudgetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "db"}},
		},
		Status: policyv1.PodDisruptionBudgetStatus{DisruptionsAllowed: 0},
	}
	objs := srNodes(1)
	objs = append(objs,
		srSTS("apps", "db", true),
		srPod("db", 0, "rev-old", 30*time.Minute),
		pdb)
	cs := fake.NewSimpleClientset(objs...)
	r := srRoller(cs, t0)
	r.driftSince["apps/db"] = t0.Add(-time.Hour)
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !srPodExists(t, cs, "apps", "db-0") {
		t.Fatal("pod deleted while a matching PDB allows 0 disruptions")
	}

	// Open the disruption window — the next sweep rolls.
	p, err := cs.PolicyV1().PodDisruptionBudgets("apps").
		Get(ctx, "db-pdb", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p.Status.DisruptionsAllowed = 1
	if _, err := cs.PolicyV1().PodDisruptionBudgets("apps").
		UpdateStatus(ctx, p, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if srPodExists(t, cs, "apps", "db-0") {
		t.Fatal("pod not deleted once the PDB allows a disruption")
	}
}

// An EMPTY policy/v1 PDB selector matches every pod in the
// namespace (a nil selector matches none) — disruptionsAllowed=0
// on a {} selector must block the roll exactly like a named one.
func TestStatefulSetRollerPDBEmptySelectorGate(t *testing.T) {
	t0 := time.Now()
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "all-pdb"},
		Spec: policyv1.PodDisruptionBudgetSpec{
			Selector: &metav1.LabelSelector{}},
		Status: policyv1.PodDisruptionBudgetStatus{DisruptionsAllowed: 0},
	}
	objs := srNodes(1)
	objs = append(objs,
		srSTS("apps", "db", true),
		srPod("db", 0, "rev-old", 30*time.Minute),
		pdb)
	cs := fake.NewSimpleClientset(objs...)
	r := srRoller(cs, t0)
	r.driftSince["apps/db"] = t0.Add(-time.Hour)
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !srPodExists(t, cs, "apps", "db-0") {
		t.Fatal("pod deleted while an empty-selector PDB allows 0 disruptions")
	}
}

// A pod missing the controller-revision-hash label is not on the
// new revision — it is treated as stale and rolled like any old pod.
func TestStatefulSetRollerMissingRevisionLabel(t *testing.T) {
	t0 := time.Now()
	unlabeled := srPod("db", 1, "", 30*time.Minute)
	delete(unlabeled.Labels, stsRevisionHashLabel)
	objs := srNodes(1)
	objs = append(objs,
		srSTS("apps", "db", true),
		srPod("db", 0, "rev-old", 30*time.Minute),
		unlabeled)
	cs := fake.NewSimpleClientset(objs...)
	r := srRoller(cs, t0)
	r.driftSince["apps/db"] = t0.Add(-time.Hour)
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if srPodExists(t, cs, "apps", "db-1") {
		t.Fatal("highest-ordinal unlabeled pod not deleted")
	}
	if !srPodExists(t, cs, "apps", "db-0") {
		t.Fatal("db-0 wrongly deleted — only one roll per cycle")
	}
}

// A member already terminating is excluded entirely: never a delete
// candidate (the delete is in flight) and never a gate blocker (a
// wedged-terminating member must not pin the roll forever).
func TestStatefulSetRollerTerminatingPodIgnored(t *testing.T) {
	t0 := time.Now()
	terminating := srPod("db", 2, "rev-old", 30*time.Minute)
	termAt := metav1.NewTime(t0)
	terminating.DeletionTimestamp = &termAt
	terminating.Status.Conditions[0].Status = corev1.ConditionFalse
	objs := srNodes(1)
	objs = append(objs,
		srSTS("apps", "db", true),
		srPod("db", 0, "rev-old", 30*time.Minute),
		srPod("db", 1, "rev-new", 30*time.Minute),
		terminating)
	cs := fake.NewSimpleClientset(objs...)
	r := srRoller(cs, t0)
	r.driftSince["apps/db"] = t0.Add(-time.Hour)
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if srPodExists(t, cs, "apps", "db-0") {
		t.Fatal("stale pod not deleted — terminating member blocked the gates")
	}
	if !srPodExists(t, cs, "apps", "db-2") {
		t.Fatal("terminating pod double-deleted")
	}
}

// A newest pod that just went Ready is still settling — the roll
// waits out the 5m stability window.
func TestStatefulSetRollerNewestPodStabilityGate(t *testing.T) {
	t0 := time.Now()
	fresh := srPod("db", 2, "rev-new", 2*time.Minute) // Ready only 2m
	fresh.CreationTimestamp = metav1.NewTime(t0.Add(-3 * time.Minute))
	objs := srNodes(1)
	objs = append(objs,
		srSTS("apps", "db", true),
		srPod("db", 0, "rev-old", 30*time.Minute),
		fresh)
	cs := fake.NewSimpleClientset(objs...)
	r := srRoller(cs, t0)
	r.driftSince["apps/db"] = t0.Add(-time.Hour)
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !srPodExists(t, cs, "apps", "db-0") {
		t.Fatal("pod deleted while the newest member was still settling")
	}
}

// Any single not-Ready member vetoes the roll — the set is already
// degraded.
func TestStatefulSetRollerAllReadyGate(t *testing.T) {
	t0 := time.Now()
	broken := srPod("db", 1, "rev-old", 30*time.Minute)
	broken.Status.Conditions[0].Status = corev1.ConditionFalse
	objs := srNodes(1)
	objs = append(objs,
		srSTS("apps", "db", true),
		srPod("db", 0, "rev-old", 30*time.Minute),
		broken)
	cs := fake.NewSimpleClientset(objs...)
	r := srRoller(cs, t0)
	r.driftSince["apps/db"] = t0.Add(-time.Hour)
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !srPodExists(t, cs, "apps", "db-0") {
		t.Fatal("pod deleted while a member is not Ready")
	}
}

// Drift that heals before 30m re-arms: the ledger entry prunes when
// revisions agree again.
func TestStatefulSetRollerDriftReArms(t *testing.T) {
	t0 := time.Now()
	sts := srSTS("apps", "db", true)
	objs := srNodes(1)
	objs = append(objs, sts, srPod("db", 0, "rev-old", 30*time.Minute))
	cs := fake.NewSimpleClientset(objs...)
	r := srRoller(cs, t0)

	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.driftSince["apps/db"]; !ok {
		t.Fatal("drift not tracked on first sighting")
	}

	// Rollout completes on its own — drift clears, ledger prunes.
	got, err := cs.AppsV1().StatefulSets("apps").Get(ctx, "db", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got.Status.CurrentRevision = got.Status.UpdateRevision
	if _, err := cs.AppsV1().StatefulSets("apps").
		UpdateStatus(ctx, got, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.driftSince["apps/db"]; ok {
		t.Fatal("settled drift still tracked")
	}
	if !srPodExists(t, cs, "apps", "db-0") {
		t.Fatal("pod deleted after drift settled")
	}
}

// A statefulset list failure is a real run error.
func TestStatefulSetRollerListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "statefulsets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	r := srRoller(cs, time.Now())
	if err := r.run(ctx); err == nil {
		t.Fatal("expected error when the statefulset list fails")
	}
}
