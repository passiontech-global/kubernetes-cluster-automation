package statefulsetroller

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
	natestutil "github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// srTrackedCount reports how many keys a FirstSeenLedger holds —
// the ledger exposes no Len, so a keep-all Prune does the counting.
func srTrackedCount(l *state.FirstSeenLedger) int {
	n := 0
	l.Prune(func(string) bool { n++; return true })
	return n
}

// srDBDriftKey is the revision-qualified ledger key the roller uses
// for the srSTS fixture — ns/name@<updateRevision>, updateRevision
// "rev-new" per srSTS.
const srDBDriftKey = "apps/db@rev-new"

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
			// BUG-C3: the membership gate requires spec.replicas —
			// tests adjust it (and status.readyReplicas) to match
			// their pod fixtures via srSetMembership.
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": name}},
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

// srSetMembership pins the StatefulSet's desired/ready membership —
// the BUG-C3 rollOne gate refuses to evict while
// len(ownedPods) != spec.replicas or readyReplicas != spec.replicas.
func srSetMembership(sts *appsv1.StatefulSet, replicas int32) {
	sts.Spec.Replicas = &replicas
	sts.Status.ReadyReplicas = replicas
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
		// NewDynamicClient (not StubDyn): the maintenance mutex's
		// autopilot-Plan signal must be verifiable or every roll
		// defers fail-closed.
		dyn: natestutil.NewDynamicClient(),
		now: func() time.Time { return now }}
}

// emulateEviction teaches the fake clientset the apiserver's
// pods/eviction contract: the fake tracker records a pods/eviction
// CREATE but never deletes the pod (fixture.go only applies
// same-type subresource writes, and an Eviction is not a Pod), so
// tests asserting the pod is gone wire the delete themselves. PDB
// budget enforcement is apiserver-only and stays untested here —
// the gate-2 pre-check remains the observable contract.
func emulateEviction(cs *fake.Clientset) {
	cs.PrependReactor("create", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			ca, ok := a.(ktesting.CreateAction)
			if !ok || ca.GetSubresource() != "eviction" {
				return false, nil, nil // a real pod create — let the tracker take it
			}
			ev := ca.GetObject().(*policyv1.Eviction)
			return true, ev, cs.Tracker().Delete(
				corev1.SchemeGroupVersion.WithResource("pods"),
				ca.GetNamespace(), ev.Name)
		})
}

// srNodes returns n Ready workers.
func srNodes(n int) []runtime.Object {
	var out []runtime.Object
	for i := 0; i < n; i++ {
		out = append(out, natestutil.Node("w"+strconv.Itoa(i), corev1.ConditionTrue, nil))
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
	natestutil.CleanupMetric(t, metrics.StatefulSetOnDeletePodsRolledTotal, "apps", "db")

	t0 := time.Now()
	sts := srSTS("apps", "db", true)
	srSetMembership(sts, 3)
	objs := srNodes(2)
	objs = append(objs,
		sts,
		srPod("db", 0, "rev-old", 30*time.Minute),
		srPod("db", 1, "rev-old", 30*time.Minute),
		srPod("db", 2, "rev-new", 30*time.Minute))
	cs := fake.NewSimpleClientset(objs...)
	emulateEviction(cs)
	r := srRoller(cs, t0)

	if err := r.run(ctx); err != nil { // seeds driftSince
		t.Fatal(err)
	}
	if !srPodExists(t, cs, "apps", "db-1") {
		t.Fatal("pod deleted before the 30m drift window")
	}
	r.now = func() time.Time { return t0.Add(31 * time.Minute) }
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if srPodExists(t, cs, "apps", "db-1") {
		t.Fatal("highest stale-ordinal pod not deleted")
	}
	// The roll must go through the eviction subresource (PDB budget
	// enforced+consumed atomically), never a raw pod delete.
	evicts, deletes := 0, 0
	for _, a := range cs.Actions() {
		if a.GetResource().Resource != "pods" {
			continue
		}
		if a.GetVerb() == "create" && a.GetSubresource() == "eviction" {
			evicts++
		}
		if a.GetVerb() == "delete" {
			deletes++
		}
	}
	if evicts != 1 || deletes != 0 {
		t.Fatalf("pod actions: %d evictions, %d raw deletes — want 1/0", evicts, deletes)
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
		r.now = func() time.Time { return t0.Add(when) }
		if err := r.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if !srPodExists(t, cs, "apps", "db-0") {
		t.Fatal("unannotated StatefulSet rolled")
	}
	if srTrackedCount(&r.driftSince) != 0 {
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
	r.now = func() time.Time { return t0.Add(time.Hour) }
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
	cordoned := natestutil.Node("w1", corev1.ConditionTrue, nil)
	cordoned.Spec.Unschedulable = true
	objs := []runtime.Object{cordoned}
	objs = append(objs,
		srSTS("apps", "db", true),
		srPod("db", 0, "rev-old", 30*time.Minute))
	cs := fake.NewSimpleClientset(objs...)
	r := srRoller(cs, t0)
	r.driftSince.Observe(srDBDriftKey, t0.Add(-time.Hour)) // pre-aged drift
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
	sts := srSTS("apps", "db", true)
	srSetMembership(sts, 1)
	objs := srNodes(1)
	objs = append(objs,
		sts,
		srPod("db", 0, "rev-old", 30*time.Minute),
		pdb)
	cs := fake.NewSimpleClientset(objs...)
	emulateEviction(cs)
	r := srRoller(cs, t0)
	r.driftSince.Observe(srDBDriftKey, t0.Add(-time.Hour))
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
	sts := srSTS("apps", "db", true)
	srSetMembership(sts, 1)
	objs := srNodes(1)
	objs = append(objs,
		sts,
		srPod("db", 0, "rev-old", 30*time.Minute),
		pdb)
	cs := fake.NewSimpleClientset(objs...)
	r := srRoller(cs, t0)
	r.driftSince.Observe(srDBDriftKey, t0.Add(-time.Hour))
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
	sts := srSTS("apps", "db", true)
	srSetMembership(sts, 2)
	objs := srNodes(1)
	objs = append(objs,
		sts,
		srPod("db", 0, "rev-old", 30*time.Minute),
		unlabeled)
	cs := fake.NewSimpleClientset(objs...)
	emulateEviction(cs)
	r := srRoller(cs, t0)
	r.driftSince.Observe(srDBDriftKey, t0.Add(-time.Hour))
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

// BUG-C3: a member still Terminating means the previous eviction has
// not landed — evicting again takes two members down at once, so the
// roll holds until the set is full and Ready again.
func TestStatefulSetRollerTerminatingPodBlocksRoll(t *testing.T) {
	t0 := time.Now()
	terminating := srPod("db", 2, "rev-old", 30*time.Minute)
	termAt := metav1.NewTime(t0)
	terminating.DeletionTimestamp = &termAt
	terminating.Status.Conditions[0].Status = corev1.ConditionFalse
	sts := srSTS("apps", "db", true)
	srSetMembership(sts, 3)
	objs := srNodes(1)
	objs = append(objs,
		sts,
		srPod("db", 0, "rev-old", 30*time.Minute),
		srPod("db", 1, "rev-new", 30*time.Minute),
		terminating)
	cs := fake.NewSimpleClientset(objs...)
	emulateEviction(cs)
	r := srRoller(cs, t0)
	r.driftSince.Observe(srDBDriftKey, t0.Add(-time.Hour))
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !srPodExists(t, cs, "apps", "db-0") {
		t.Fatal("pod evicted while a member is still terminating — membership gate must hold")
	}
	if !srPodExists(t, cs, "apps", "db-2") {
		t.Fatal("terminating pod double-deleted")
	}
}

// 2.1.6: the opt-in annotation also lands on the pod template —
// operators propagate spec.annotations into the template without
// annotating the StatefulSet object itself.
func TestStatefulSetRollerPodTemplateAnnotationOptIn(t *testing.T) {
	t0 := time.Now()
	sts := srSTS("apps", "db", false) // STS object NOT annotated
	sts.Spec.Template.Annotations = map[string]string{stsAutoRollAnno: "true"}
	srSetMembership(sts, 1)
	objs := srNodes(1)
	objs = append(objs, sts, srPod("db", 0, "rev-old", 30*time.Minute))
	cs := fake.NewSimpleClientset(objs...)
	emulateEviction(cs)
	r := srRoller(cs, t0)
	r.driftSince.Observe(srDBDriftKey, t0.Add(-time.Hour))
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if srPodExists(t, cs, "apps", "db-0") {
		t.Fatal("pod not rolled — pod-template opt-in annotation ignored")
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
	r.driftSince.Observe(srDBDriftKey, t0.Add(-time.Hour))
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
	r.driftSince.Observe(srDBDriftKey, t0.Add(-time.Hour))
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
	if _, ok := r.driftSince.Seen(srDBDriftKey, time.Now()); !ok {
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
	if _, ok := r.driftSince.Seen(srDBDriftKey, time.Now()); ok {
		t.Fatal("settled drift still tracked")
	}
	if !srPodExists(t, cs, "apps", "db-0") {
		t.Fatal("pod deleted after drift settled")
	}
}

// ownedPods scopes the server-side List to sts.Spec.Selector: an
// owned pod whose labels no longer match the selector is excluded,
// and same-namespace pods of other sets never leave etcd. Without
// the selector every STS would drag the whole namespace's pod list
// per sweep.
func TestStatefulSetRollerOwnedPodsScopedBySelector(t *testing.T) {
	sts := srSTS("apps", "db", true) // selector app=db
	mislabeled := srPod("db", 1, "rev-old", 30*time.Minute)
	mislabeled.Labels = map[string]string{"app": "other"} // owned but off-selector
	cs := fake.NewSimpleClientset(
		sts,
		srPod("db", 0, "rev-old", 30*time.Minute),
		mislabeled,
		srPod("other", 0, "rev-old", 30*time.Minute)) // other STS entirely
	r := srRoller(cs, time.Now())
	pods, err := r.ownedPods(ctx, sts)
	if err != nil {
		t.Fatalf("ownedPods: %v", err)
	}
	if len(pods) != 1 || pods[0].Name != "db-0" {
		names := []string{}
		for _, p := range pods {
			names = append(names, p.Name)
		}
		t.Fatalf("ownedPods = %v, want [db-0]", names)
	}
}

// A selector that cannot parse must fail closed — an error skips the
// roll rather than listing (and maybe deleting) from an unfiltered
// pod set.
func TestStatefulSetRollerSelectorParseErrorFailsClosed(t *testing.T) {
	sts := srSTS("apps", "db", true)
	sts.Spec.Selector = &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: "app", Operator: "BogusOperator"}}}
	cs := fake.NewSimpleClientset(sts, srPod("db", 0, "rev-old", 30*time.Minute))
	r := srRoller(cs, time.Now())
	if _, err := r.ownedPods(ctx, sts); err == nil {
		t.Fatal("expected error on an unparseable STS selector")
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

// The 30m drift clock is keyed per (StatefulSet, updateRevision): a
// NEW revision landing mid-window opens a fresh continuity window —
// drift elapsed on the old revision must not carry a new template
// straight to a delete.
func TestStatefulSetRollerNewRevisionResetsDriftClock(t *testing.T) {
	t0 := time.Now()
	sts := srSTS("apps", "db", true) // updateRevision rev-new
	srSetMembership(sts, 1)
	objs := srNodes(1)
	objs = append(objs, sts, srPod("db", 0, "rev-old", 30*time.Minute))
	cs := fake.NewSimpleClientset(objs...)
	emulateEviction(cs)
	r := srRoller(cs, t0)
	// rev-new drift observed a full window ago — under the old
	// name-only key this sweep would roll immediately.
	r.driftSince.Observe(srDBDriftKey, t0.Add(-time.Hour))

	// The workload ships a new template mid-window: updateRevision
	// becomes rev-newer.
	got, err := cs.AppsV1().StatefulSets("apps").Get(ctx, "db", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got.Status.UpdateRevision = "rev-newer"
	if _, err := cs.AppsV1().StatefulSets("apps").
		UpdateStatus(ctx, got, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	// Even well past 30m from the OLD revision's first sighting, the
	// new revision's clock just started — no roll, and only the fresh
	// key is tracked.
	r.now = func() time.Time { return t0.Add(45 * time.Minute) }
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !srPodExists(t, cs, "apps", "db-0") {
		t.Fatal("pod rolled on a revision whose drift window just opened")
	}
	if _, ok := r.driftSince.Seen("apps/db@rev-newer", t0.Add(45*time.Minute)); !ok {
		t.Fatal("new revision not tracked under its own key")
	}
	if _, ok := r.driftSince.Seen(srDBDriftKey, t0.Add(45*time.Minute)); ok {
		t.Fatal("stale revision key not pruned from the ledger")
	}

	// 30m of CONTINUOUS drift on rev-newer: the roll proceeds.
	r.now = func() time.Time { return t0.Add(76 * time.Minute) }
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if srPodExists(t, cs, "apps", "db-0") {
		t.Fatal("pod not rolled after 30m of drift on the new revision")
	}
}

// Gate 3 checks Ready stability on EVERY pod of the set, not just
// the newest-CreationTimestamp one: a lower-ordinal member that
// flipped Ready a minute ago (kubelet restart, transient NotReady)
// vetoes the roll even though the youngest pod has been up for hours.
func TestStatefulSetRollerStaleUnreadyBlocksRoll(t *testing.T) {
	t0 := time.Now()
	sts := srSTS("apps", "db", true)
	srSetMembership(sts, 2)
	// db-1 is the NEWEST pod (created 30m ago) and long-settled;
	// db-0 only went Ready 2m ago.
	recent := srPod("db", 0, "rev-old", 2*time.Minute)
	recent.CreationTimestamp = metav1.NewTime(t0.Add(-30 * time.Minute))
	objs := srNodes(1)
	objs = append(objs, sts, recent)
	cs := fake.NewSimpleClientset(objs...)
	emulateEviction(cs)
	r := srRoller(cs, t0)
	r.driftSince.Observe(srDBDriftKey, t0.Add(-time.Hour))
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !srPodExists(t, cs, "apps", "db-0") {
		t.Fatal("pod rolled while a non-newest member was still settling")
	}
}

// maintenance-hold-stale image-pull gate: an owned pod waiting in
// ImagePullBackOff/ErrImagePull defers the whole StatefulSet's roll
// for the cycle — fail-safe, no error, no eviction attempted, the
// rolled counter must not move.
func TestStatefulSetRollerDefersOnImagePullStall(t *testing.T) {
	natestutil.CleanupMetric(t, metrics.StatefulSetOnDeletePodsRolledTotal, "apps", "db")

	t0 := time.Now()
	sts := srSTS("apps", "db", true)
	srSetMembership(sts, 2)
	// db-1 is Ready as a whole (the membership + stability gates
	// pass) but its sidecar is wedged pulling its image — the roll
	// must defer on the pull stall alone.
	stuck := srPod("db", 1, "rev-old", 30*time.Minute)
	stuck.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name: "sidecar",
		State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
			Reason:  "ImagePullBackOff",
			Message: "back-off pulling image"}},
	}}
	objs := srNodes(1)
	objs = append(objs, sts,
		srPod("db", 0, "rev-old", 30*time.Minute),
		stuck)
	cs := fake.NewSimpleClientset(objs...)
	emulateEviction(cs)
	r := srRoller(cs, t0)
	r.driftSince.Observe(srDBDriftKey, t0.Add(-time.Hour))
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"db-0", "db-1"} {
		if !srPodExists(t, cs, "apps", name) {
			t.Fatalf("pod %s deleted despite the image-pull defer gate", name)
		}
	}
	if got := ptestutil.ToFloat64(metrics.StatefulSetOnDeletePodsRolledTotal.
		WithLabelValues("apps", "db")); got != 0 {
		t.Fatalf("rolled counter = %v, want 0 (a defer is not a roll)", got)
	}
	for _, a := range cs.Actions() {
		if a.GetResource().Resource == "pods" &&
			a.GetVerb() == "create" && a.GetSubresource() == "eviction" {
			t.Fatal("eviction attempted despite the image-pull defer gate")
		}
	}
}

// ---------------------------------------------------------------------------
// rollOne residual branches — direct run()-level coverage
// ---------------------------------------------------------------------------

// podOrdinal parses "<sts>-<N>" strictly: a name that does not carry
// the sts prefix, or a non-numeric suffix, is not an ordinal member.
func TestPodOrdinal(t *testing.T) {
	for _, tc := range []struct {
		pod  string
		want int
		ok   bool
	}{
		{"db-3", 3, true},
		{"db-0", 0, true},
		{"db-x", 0, false},    // non-numeric suffix
		{"other-3", 0, false}, // missing the sts prefix entirely
	} {
		got, ok := podOrdinal("db", tc.pod)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("podOrdinal(db, %q) = %d,%v want %d,%v",
				tc.pod, got, ok, tc.want, tc.ok)
		}
	}
}

// An opted-in drifting StatefulSet owning no pods has nothing to
// roll — the empty census is a skip, not an error.
func TestStatefulSetRollerNoOwnedPods(t *testing.T) {
	t0 := time.Now()
	sts := srSTS("apps", "db", true)
	srSetMembership(sts, 0)
	objs := srNodes(1)
	objs = append(objs, sts)
	cs := fake.NewSimpleClientset(objs...)
	r := srRoller(cs, t0)
	r.driftSince.Observe(srDBDriftKey, t0.Add(-time.Hour))
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
}

// Every owned pod already on the update revision means status lags —
// there is no stale ordinal to evict.
func TestStatefulSetRollerAllPodsOnNewRevision(t *testing.T) {
	t0 := time.Now()
	sts := srSTS("apps", "db", true)
	srSetMembership(sts, 1)
	objs := srNodes(1)
	objs = append(objs, sts, srPod("db", 0, "rev-new", 30*time.Minute))
	cs := fake.NewSimpleClientset(objs...)
	emulateEviction(cs)
	r := srRoller(cs, t0)
	r.driftSince.Observe(srDBDriftKey, t0.Add(-time.Hour))
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !srPodExists(t, cs, "apps", "db-0") {
		t.Fatal("pod evicted although every member is already on the new revision")
	}
}

// A Ready=True pod whose transition timestamp sits in the FUTURE is
// clock-skewed, not settled — the stability gate refuses it.
func TestStatefulSetRollerFutureReadyTimestampSkips(t *testing.T) {
	t0 := time.Now()
	future := srPod("db", 0, "rev-old", 30*time.Minute)
	future.Status.Conditions[0].LastTransitionTime =
		metav1.NewTime(t0.Add(time.Hour))
	sts := srSTS("apps", "db", true)
	srSetMembership(sts, 1)
	objs := srNodes(1)
	objs = append(objs, sts, future)
	cs := fake.NewSimpleClientset(objs...)
	emulateEviction(cs)
	r := srRoller(cs, t0)
	r.driftSince.Observe(srDBDriftKey, t0.Add(-time.Hour))
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !srPodExists(t, cs, "apps", "db-0") {
		t.Fatal("pod evicted on a future-dated Ready transition")
	}
}

// spec.replicas unset makes the membership gate inconclusive — no
// roll on an unverifiable desired count.
func TestStatefulSetRollerNilReplicasSkips(t *testing.T) {
	t0 := time.Now()
	sts := srSTS("apps", "db", true)
	sts.Spec.Replicas = nil
	objs := srNodes(1)
	objs = append(objs, sts, srPod("db", 0, "rev-old", 30*time.Minute))
	cs := fake.NewSimpleClientset(objs...)
	emulateEviction(cs)
	r := srRoller(cs, t0)
	r.driftSince.Observe(srDBDriftKey, t0.Add(-time.Hour))
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !srPodExists(t, cs, "apps", "db-0") {
		t.Fatal("pod evicted with spec.replicas unset")
	}
}

// The owned-pods list failing is a tolerated per-STS failure: the
// sweep IncErrors and continues rather than aborting the run.
func TestStatefulSetRollerPodsListError(t *testing.T) {
	t0 := time.Now()
	sts := srSTS("apps", "db", true)
	srSetMembership(sts, 1)
	objs := srNodes(1)
	objs = append(objs, sts, srPod("db", 0, "rev-old", 30*time.Minute))
	cs := fake.NewSimpleClientset(objs...)
	cs.PrependReactor("list", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	r := srRoller(cs, t0)
	r.queue = "statefulset-ondelete-roller"
	r.driftSince.Observe(srDBDriftKey, t0.Add(-time.Hour))
	before := natestutil.QueueErrorCount(t, r.queue)
	if err := r.run(ctx); err != nil {
		t.Fatalf("pods list failure must not fail the sweep: %v", err)
	}
	if d := natestutil.QueueErrorCount(t, r.queue) - before; d != 1 {
		t.Fatalf("IncError delta = %v, want 1", d)
	}
}

// The PDB census failing is likewise a tolerated per-STS error.
func TestStatefulSetRollerPDBListError(t *testing.T) {
	t0 := time.Now()
	sts := srSTS("apps", "db", true)
	srSetMembership(sts, 1)
	objs := srNodes(1)
	objs = append(objs, sts, srPod("db", 0, "rev-old", 30*time.Minute))
	cs := fake.NewSimpleClientset(objs...)
	cs.PrependReactor("list", "poddisruptionbudgets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	emulateEviction(cs)
	r := srRoller(cs, t0)
	r.queue = "statefulset-ondelete-roller"
	r.driftSince.Observe(srDBDriftKey, t0.Add(-time.Hour))
	before := natestutil.QueueErrorCount(t, r.queue)
	if err := r.run(ctx); err != nil {
		t.Fatalf("PDB list failure must not fail the sweep: %v", err)
	}
	if !srPodExists(t, cs, "apps", "db-0") {
		t.Fatal("pod evicted although the PDB census was unreadable")
	}
	if d := natestutil.QueueErrorCount(t, r.queue) - before; d != 1 {
		t.Fatalf("IncError delta = %v, want 1", d)
	}
}

// A PDB whose selector matches nothing in the namespace is not a
// gate — the roll proceeds past it.
func TestStatefulSetRollerNonMatchingPDBAllowsRoll(t *testing.T) {
	t0 := time.Now()
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "other-pdb"},
		Spec: policyv1.PodDisruptionBudgetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "other"}}},
		Status: policyv1.PodDisruptionBudgetStatus{DisruptionsAllowed: 0},
	}
	sts := srSTS("apps", "db", true)
	srSetMembership(sts, 1)
	objs := srNodes(1)
	objs = append(objs, sts, srPod("db", 0, "rev-old", 30*time.Minute), pdb)
	cs := fake.NewSimpleClientset(objs...)
	emulateEviction(cs)
	r := srRoller(cs, t0)
	r.driftSince.Observe(srDBDriftKey, t0.Add(-time.Hour))
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if srPodExists(t, cs, "apps", "db-0") {
		t.Fatal("non-matching PDB blocked the roll")
	}
}

// An unparseable PDB selector fails CLOSED as labels.Everything() —
// a disruptionsAllowed=0 PDB with a bogus selector still vetoes.
func TestStatefulSetRollerUnparseablePDBSelectorFailsClosed(t *testing.T) {
	t0 := time.Now()
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "bad-pdb"},
		Spec: policyv1.PodDisruptionBudgetSpec{
			Selector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key: "app", Operator: "BogusOperator"}}}},
		Status: policyv1.PodDisruptionBudgetStatus{DisruptionsAllowed: 0},
	}
	sts := srSTS("apps", "db", true)
	srSetMembership(sts, 1)
	objs := srNodes(1)
	objs = append(objs, sts, srPod("db", 0, "rev-old", 30*time.Minute), pdb)
	cs := fake.NewSimpleClientset(objs...)
	emulateEviction(cs)
	r := srRoller(cs, t0)
	r.driftSince.Observe(srDBDriftKey, t0.Add(-time.Hour))
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !srPodExists(t, cs, "apps", "db-0") {
		t.Fatal("unparseable-selector PDB did not fail closed")
	}
}

// A refused eviction is a tolerated per-STS failure: IncError, the
// pod stays, the sweep continues.
func TestStatefulSetRollerEvictError(t *testing.T) {
	t0 := time.Now()
	sts := srSTS("apps", "db", true)
	srSetMembership(sts, 1)
	objs := srNodes(1)
	objs = append(objs, sts, srPod("db", 0, "rev-old", 30*time.Minute))
	cs := fake.NewSimpleClientset(objs...)
	emulateEviction(cs)
	cs.PrependReactor("create", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			ca, ok := a.(ktesting.CreateAction)
			if !ok || ca.GetSubresource() != "eviction" {
				return false, nil, nil
			}
			return true, nil, errors.New("eviction refused")
		})
	r := srRoller(cs, t0)
	r.queue = "statefulset-ondelete-roller"
	r.driftSince.Observe(srDBDriftKey, t0.Add(-time.Hour))
	before := natestutil.QueueErrorCount(t, r.queue)
	if err := r.run(ctx); err != nil {
		t.Fatalf("evict failure must not fail the sweep: %v", err)
	}
	if !srPodExists(t, cs, "apps", "db-0") {
		t.Fatal("pod deleted although the eviction was refused")
	}
	if d := natestutil.QueueErrorCount(t, r.queue) - before; d != 1 {
		t.Fatalf("IncError delta = %v, want 1", d)
	}
}

// When Evict returns 429 TooManyRequests (a PDB race after the gate-2
// pre-check), rollStatefulSet calls heal.RefundGrant(now) so the
// unused grant is returned to the fleet budget.
func TestStatefulSetRollerPDB429RefundsBudget(t *testing.T) {
	heal.ConfigureBudget(1, time.Hour)
	t.Cleanup(func() { heal.ConfigureBudget(0, 0) })

	t0 := time.Now()
	sts := srSTS("apps", "db", true)
	srSetMembership(sts, 1)
	objs := srNodes(1)
	objs = append(objs, sts, srPod("db", 0, "rev-old", 30*time.Minute))
	cs := fake.NewSimpleClientset(objs...)
	cs.PrependReactor("create", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			if ca, ok := a.(ktesting.CreateAction); ok && ca.GetSubresource() == "eviction" {
				return true, nil, apierrors.NewTooManyRequests("pdb race", 0)
			}
			return false, nil, nil
		})
	r := srRoller(cs, t0)
	r.queue = "statefulset-ondelete-roller"
	r.driftSince.Observe(srDBDriftKey, t0.Add(-time.Hour))
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	proceed, unverifiable := heal.Gate(ctx, logr.Discard(), nil, cs, natestutil.NewDynamicClient(), "probe", t0)
	if !proceed || unverifiable {
		t.Fatalf("PDB-429 Evict did not refund budget grant: Gate = (%v,%v)",
			proceed, unverifiable)
	}
}

// ---------------------------------------------------------------------------
// D16 dragonfly cold-start gate (dragonfly_sync_gate.go)
// ---------------------------------------------------------------------------

// srDragonflySTS builds a opted-in, OnDelete, Dragonfly-labeled
// 2-replica StatefulSet whose both members are Ready and stale.
func srDragonflySTS(t *testing.T) *appsv1.StatefulSet {
	t.Helper()
	sts := srSTS("apps", "cache", true)
	sts.Spec.Template.Labels["app.kubernetes.io/name"] = "dragonfly"
	srSetMembership(sts, 2)
	return sts
}

// srPromStub serves one instant-query response: series maps
// "<ns>/<pod>" → link status value (an empty map = empty vector).
func srPromStub(t *testing.T, status int, series map[string]float64) *httptest.Server {
	t.Helper()
	type envelope struct {
		Status string `json:"status"`
		Data   struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Value  []json.RawMessage `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		var env envelope
		env.Status = "success"
		for k, v := range series {
			bar := strings.IndexByte(k, '/')
			env.Data.Result = append(env.Data.Result, struct {
				Metric map[string]string `json:"metric"`
				Value  []json.RawMessage `json:"value"`
			}{
				Metric: map[string]string{
					"namespace": k[:bar], "pod": k[bar+1:],
				},
				Value: []json.RawMessage{json.RawMessage("1770000000"),
					// Prometheus ships sample values as JSON STRINGS.
					json.RawMessage(strconv.Quote(strconv.FormatFloat(v, 'f', -1, 64)))},
			})
		}
		_ = json.NewEncoder(w).Encode(env)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// srRollerWithProm wires the roller's dragonfly gate seam to the stub.
func srRollerWithProm(cs *fake.Clientset, now time.Time, srv *httptest.Server) *statefulSetOnDeleteRoller {
	r := srRoller(cs, now)
	r.prom = dragonflyPromSeam{
		endpoint: srv.URL + "/api/v1/query",
		client:   promq.Client{HTTP: srv.Client(), Timeout: 2 * time.Second},
		ok:       true,
	}
	return r
}

// A Dragonfly member whose master link is still down (mid-FULL-SYNC —
// Ready only proves the port answers) defers the OnDelete roll and
// counts the skip; the same stub over a non-dragonfly set rolls.
func TestStatefulSetRollerDragonflyUnsyncedGate(t *testing.T) {
	natestutil.CleanupMetric(t, metrics.StatefulSetOnDeleteDragonflyUnsyncedSkipped, "apps", "cache")
	srv := srPromStub(t, http.StatusOK, map[string]float64{"apps/cache-1": 0})

	t0 := time.Now()
	sts := srDragonflySTS(t)
	objs := srNodes(1)
	objs = append(objs, sts,
		srPod("cache", 0, "rev-old", 30*time.Minute),
		srPod("cache", 1, "rev-old", 30*time.Minute))
	cs := fake.NewSimpleClientset(objs...)
	emulateEviction(cs)
	r := srRollerWithProm(cs, t0, srv)

	if err := r.run(ctx); err != nil { // seeds driftSince
		t.Fatal(err)
	}
	r.now = func() time.Time { return t0.Add(31 * time.Minute) }
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !srPodExists(t, cs, "apps", "cache-1") {
		t.Fatal("pod rolled while a replica's master link was down (mid-FULL-SYNC)")
	}
	if n := ptestutil.ToFloat64(metrics.StatefulSetOnDeleteDragonflyUnsyncedSkipped.
		WithLabelValues("apps", "cache")); n == 0 {
		t.Fatal("unsynced skip not counted")
	}

	// The gate is dragonfly-scoped: the identical signature over a
	// plain StatefulSet must NOT block the roll.
	db := srSTS("apps", "db", true)
	srSetMembership(db, 2)
	objs = srNodes(1)
	objs = append(objs, db,
		srPod("db", 0, "rev-old", 30*time.Minute),
		srPod("db", 1, "rev-old", 30*time.Minute))
	cs2 := fake.NewSimpleClientset(objs...)
	emulateEviction(cs2)
	r2 := srRollerWithProm(cs2, t0, srv)
	r2.driftSince.Observe("apps/db@rev-new", t0.Add(-time.Hour))
	if err := r2.run(ctx); err != nil {
		t.Fatal(err)
	}
	if srPodExists(t, cs2, "apps", "db-1") {
		t.Fatal("non-dragonfly set blocked by the dragonfly gate")
	}
}

// Sync complete (no link-down series) rolls through the gate; a
// Prometheus outage (non-200) is tolerated — the gate defers to the
// other gates rather than pinning the roll on a monitoring failure.
func TestStatefulSetRollerDragonflySyncedRollsAndOutageTolerated(t *testing.T) {
	t0 := time.Now()

	// Synced: empty vector — the roll lands.
	srvUp := srPromStub(t, http.StatusOK, nil)
	sts := srDragonflySTS(t)
	objs := srNodes(1)
	objs = append(objs, sts,
		srPod("cache", 0, "rev-old", 30*time.Minute),
		srPod("cache", 1, "rev-old", 30*time.Minute))
	cs := fake.NewSimpleClientset(objs...)
	emulateEviction(cs)
	r := srRollerWithProm(cs, t0, srvUp)
	r.driftSince.Observe("apps/cache@rev-new", t0.Add(-time.Hour))
	if err := r.run(ctx); err != nil {
		t.Fatal(err)
	}
	if srPodExists(t, cs, "apps", "cache-1") {
		t.Fatal("roll deferred while every replica read master_link_status up")
	}

	// Outage: non-200 — tolerated, roll still lands.
	srvDown := srPromStub(t, http.StatusInternalServerError, nil)
	sts2 := srDragonflySTS(t)
	objs2 := srNodes(1)
	objs2 = append(objs2, sts2,
		srPod("cache", 0, "rev-old", 30*time.Minute),
		srPod("cache", 1, "rev-old", 30*time.Minute))
	cs2 := fake.NewSimpleClientset(objs2...)
	emulateEviction(cs2)
	r2 := srRollerWithProm(cs2, t0, srvDown)
	r2.driftSince.Observe("apps/cache@rev-new", t0.Add(-time.Hour))
	if err := r2.run(ctx); err != nil {
		t.Fatal(err)
	}
	if srPodExists(t, cs2, "apps", "cache-1") {
		t.Fatal("roll pinned by a Prometheus outage — the gate must tolerate it")
	}
}
