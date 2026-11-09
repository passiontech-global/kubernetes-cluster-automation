package helmreleaseunlocker

import (
	"strconv"
	"testing"
	"time"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/fake"
	kfake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// Stalled-rollout fixtures — the 2026-11-04 1password/connect scene:
// HR ops/connect (targetNamespace onepassword) terminal in
// Stalled=True/RetriesExceeded behind a Deployment whose OLD
// ReplicaSet pods hold required podAntiAffinity on both schedulable
// nodes while the new surge pod sits Pending.
// ---------------------------------------------------------------------------

// stalledHR builds the incident HR: Ready=False on the helm stalled-
// resources message plus the terminal Stalled/Released/Remediated
// bookkeeping helm-controller leaves after the retries run out.
func stalledHR(ns, name, targetNS, readyMsg string) *unstructured.Unstructured {
	hr := hrObj(ns, name, "v2")
	if targetNS != "" {
		hrTarget(hr, targetNS)
	}
	ts := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	cond := func(tpe, status, reason, msg string) map[string]any {
		return map[string]any{
			"type": tpe, "status": status, "reason": reason,
			"message": msg, "lastTransitionTime": ts,
		}
	}
	hr.Object["status"] = map[string]any{"conditions": []any{
		cond("Ready", "False", "RollbackSucceeded", readyMsg),
		cond("Stalled", "True", "RetriesExceeded",
			"stalled reconciliation"),
		cond("Released", "False", "UpgradeFailed",
			"Helm upgrade failed for release connect/connect: failed early due to stalled resources"),
		cond("Remediated", "True", "RollbackSucceeded",
			"Helm rollback to previous release version succeeded"),
	}}
	return hr
}

// stalledDeploy builds the rollout-deadlocked Deployment — replicas=2
// with the apiserver-default RollingUpdate (maxUnavailable resolves
// to 0 at this size) and a ProgressDeadlineExceeded condition like
// helm's waiter read.
func stalledDeploy(ns, name string, replicas int32) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(replicas),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "onepassword-connect"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": "onepassword-connect"}},
			},
		},
		Status: appsv1.DeploymentStatus{
			Conditions: []appsv1.DeploymentCondition{{
				Type:   appsv1.DeploymentProgressing,
				Status: corev1.ConditionFalse,
				Reason: "ProgressDeadlineExceeded",
			}},
		},
	}
}

// stallRS builds a Deployment-owned ReplicaSet. requiredAA=true gives
// the pod template the OLD chart's hard podAntiAffinity; false gives
// only the NEW chart's preferred term (never a blocker).
func stallRS(ns, name, deployName string, rev int, replicas int32, requiredAA bool) *appsv1.ReplicaSet {
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
			Annotations: map[string]string{
				"deployment.kubernetes.io/revision": strconv.Itoa(rev)},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
				Name:       deployName,
				Controller: ptr.To(true),
			}},
		},
		Spec: appsv1.ReplicaSetSpec{
			Replicas: ptr.To(replicas),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "onepassword-connect"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": "onepassword-connect"}},
			},
		},
	}
	term := corev1.PodAffinityTerm{
		LabelSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"app": "onepassword-connect"}},
		TopologyKey: "kubernetes.io/hostname",
	}
	if requiredAA {
		rs.Spec.Template.Spec.Affinity = &corev1.Affinity{
			PodAntiAffinity: &corev1.PodAntiAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{term},
			},
		}
	} else {
		rs.Spec.Template.Spec.Affinity = &corev1.Affinity{
			PodAntiAffinity: &corev1.PodAntiAffinity{
				PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{{
					Weight: 100, PodAffinityTerm: term,
				}},
			},
		}
	}
	return rs
}

// stallPod builds a pod owned by rsName. node == "" produces the
// Pending unschedulable surge pod; unschedMsg is its PodScheduled=
// False scheduler message.
func stallPod(ns, name, rsName, node, unschedMsg string) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
			Labels:    map[string]string{"app": "onepassword-connect"},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1",
				Kind:       "ReplicaSet",
				Name:       rsName,
				Controller: ptr.To(true),
			}},
		},
		Spec:   corev1.PodSpec{NodeName: node},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	if node == "" {
		p.Status.Phase = corev1.PodPending
		p.Status.Conditions = []corev1.PodCondition{{
			Type:    corev1.PodScheduled,
			Status:  corev1.ConditionFalse,
			Reason:  "Unschedulable",
			Message: unschedMsg,
		}}
	}
	return p
}

// stallFixture builds the full incident scene: stalled HR + the
// surge-deadlocked Deployment + old/new ReplicaSets + pods.
// Returns the HR and the workload objects for the fake clientset.
func stallFixture() (*unstructured.Unstructured, []runtime.Object) {
	hr := stalledHR("ops", "connect", "onepassword",
		"Helm upgrade failed for release connect/connect with chart connect@2.4.2: "+
			"failed early due to stalled resources: [Deployment/connect status: 'Failed']")
	objs := []runtime.Object{
		stalledDeploy("onepassword", "connect", 2),
		stallRS("onepassword", "connect-old", "connect", 1, 2, true),
		stallRS("onepassword", "connect-new", "connect", 2, 1, false),
		stallPod("onepassword", "connect-old-a", "connect-old", "node-a", ""),
		stallPod("onepassword", "connect-old-b", "connect-old", "node-b", ""),
		stallPod("onepassword", "connect-new-1", "connect-new", "",
			"0/2 nodes are available: 2 didn't satisfy existing pods anti-affinity rules."),
	}
	return hr, objs
}

// newStallUnlocker mirrors newUnlocker for the stall signature: the
// opt-in gate on and the stall.firstSeen ledger pre-aged past the 30m
// window for key.
func newStallUnlocker(cs *kfake.Clientset, dyn *fake.FakeDynamicClient,
	stuckFor time.Duration, key string) *helmReleaseUnlocker {
	u := &helmReleaseUnlocker{queue: "helmrelease-unlocker",
		cs:    cs,
		dyn:   dyn,
		stall: stallState{enabled: true},
	}
	if key != "" {
		u.stall.firstSeen.Observe(key, time.Now().Add(-stuckFor))
	}
	return u
}

func rsReplicas(t *testing.T, cs *kfake.Clientset, ns, name string) int32 {
	t.Helper()
	rs, err := cs.AppsV1().ReplicaSets(ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		t.Fatalf("replicaset %s/%s missing", ns, name)
	}
	if err != nil {
		t.Fatalf("get replicaset %s/%s: %v", ns, name, err)
	}
	return ptr.Deref(rs.Spec.Replicas, -1)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// Happy path: Stalled/RetriesExceeded HR + the surge-deadlocked
// Deployment → the OLD ReplicaSet is scaled down by exactly the
// minimum (2→1 frees one node) and the HR gets requestedAt + resetAt
// + forceAt (same token) plus the persisted cooldown stamp.
func TestHelmStallUnwedgeHappyPath(t *testing.T) {
	hr, objs := stallFixture()
	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(objs...)
	u := newStallUnlocker(cs, dyn, time.Hour, "ops/connect")

	before := promtestutil.ToFloat64(
		metrics.HelmStallUnwedgesTotal.WithLabelValues("onepassword", "connect"))
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := rsReplicas(t, cs, "onepassword", "connect-old"); got != 1 {
		t.Fatalf("old ReplicaSet replicas = %d, want 1", got)
	}
	if got := rsReplicas(t, cs, "onepassword", "connect-new"); got != 1 {
		t.Fatalf("new ReplicaSet touched: replicas = %d, want 1", got)
	}
	token := hrAnnotation(t, dyn, helmReleaseGVRs[0], "ops", "connect", fluxReconcileAnno)
	if token == "" {
		t.Fatal("reconcile.fluxcd.io/requestedAt not stamped")
	}
	for _, anno := range []string{fluxResetAnno, fluxForceAnno, helmLastStallUnwedgeAnno} {
		got := hrAnnotation(t, dyn, helmReleaseGVRs[0], "ops", "connect", anno)
		if got != token {
			t.Fatalf("annotation %s = %q, want the shared token %q", anno, got, token)
		}
	}
	if !u.stall.unwedged.CooledDown("ops/connect", helmUnlockCooldown, time.Now()) {
		t.Fatal("HR not recorded in the unwedged ledger")
	}
	if got := promtestutil.ToFloat64(
		metrics.HelmStallUnwedgesTotal.WithLabelValues("onepassword", "connect")) - before; got != 1 {
		t.Fatalf("HelmStallUnwedgesTotal delta = %v, want 1", got)
	}
}

// New-RS pods Pending for a NON-affinity reason (insufficient cpu,
// image pull, taints) → refuse: scaling the old RS would not help and
// the HR stays for a human. One IncError for visibility, no writes.
func TestHelmStallUnwedgePendingOtherReasonSkipped(t *testing.T) {
	hr, objs := stallFixture()
	// Swap the surge pod's scheduler message for a resource shortage.
	for i, o := range objs {
		if p, ok := o.(*corev1.Pod); ok && p.Name == "connect-new-1" {
			p.Status.Conditions[0].Message =
				"0/2 nodes are available: 2 Insufficient cpu."
			objs[i] = p
		}
	}
	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(objs...)
	u := newStallUnlocker(cs, dyn, time.Hour, "ops/connect")

	before := testutil.ReconcileErrorCount(t, "helmrelease-unlocker")
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := rsReplicas(t, cs, "onepassword", "connect-old"); got != 2 {
		t.Fatalf("old ReplicaSet scaled despite non-affinity pending: %d, want 2", got)
	}
	if got := hrAnnotation(t, dyn, helmReleaseGVRs[0], "ops", "connect", fluxReconcileAnno); got != "" {
		t.Fatal("HR annotated despite refusal")
	}
	if got := testutil.ReconcileErrorCount(t, "helmrelease-unlocker"); got != before+1 {
		t.Fatalf("refusal did not IncError for visibility: got %v, want %v", got, before+1)
	}
}

// A covering PDB that cannot tolerate the removal → refuse. Scaling
// an RS bypasses the eviction API, so the check must happen here.
func TestHelmStallUnwedgePDBBlocked(t *testing.T) {
	hr, objs := stallFixture()
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Namespace: "onepassword", Name: "connect"},
		Spec: policyv1.PodDisruptionBudgetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "onepassword-connect"}},
		},
		Status: policyv1.PodDisruptionBudgetStatus{
			ExpectedPods:       2,
			DesiredHealthy:     2,
			CurrentHealthy:     2,
			DisruptionsAllowed: 0,
		},
	}
	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(append(objs, pdb)...)
	u := newStallUnlocker(cs, dyn, time.Hour, "ops/connect")

	before := testutil.ReconcileErrorCount(t, "helmrelease-unlocker")
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := rsReplicas(t, cs, "onepassword", "connect-old"); got != 2 {
		t.Fatalf("old ReplicaSet scaled past a blocking PDB: %d, want 2", got)
	}
	if got := hrAnnotation(t, dyn, helmReleaseGVRs[0], "ops", "connect", fluxReconcileAnno); got != "" {
		t.Fatal("HR annotated despite the PDB refusal")
	}
	if got := testutil.ReconcileErrorCount(t, "helmrelease-unlocker"); got != before+1 {
		t.Fatalf("PDB refusal did not IncError: got %v, want %v", got, before+1)
	}
}

// replicas==1 has no surge window — removing the only old pod would
// be a full outage, so the signature refuses outright.
func TestHelmStallUnwedgeSingleReplicaSkipped(t *testing.T) {
	hr, objs := stallFixture()
	for i, o := range objs {
		if d, ok := o.(*appsv1.Deployment); ok {
			d.Spec.Replicas = ptr.To(int32(1))
			objs[i] = d
		}
	}
	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(objs...)
	u := newStallUnlocker(cs, dyn, time.Hour, "ops/connect")

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := rsReplicas(t, cs, "onepassword", "connect-old"); got != 2 {
		t.Fatalf("old ReplicaSet scaled on a single-replica deployment: %d, want 2", got)
	}
	if got := hrAnnotation(t, dyn, helmReleaseGVRs[0], "ops", "connect", fluxReconcileAnno); got != "" {
		t.Fatal("HR annotated despite the replicas==1 refusal")
	}
}

// The NEW chart flipped to preferred anti-affinity — but this test
// makes the OLD RS preferred-only too: preferred terms never
// hard-block scheduling, so the shape is not the deadlock and the
// module must refuse.
func TestHelmStallUnwedgePreferredOnlySkipped(t *testing.T) {
	hr, objs := stallFixture()
	for i, o := range objs {
		if rs, ok := o.(*appsv1.ReplicaSet); ok && rs.Name == "connect-old" {
			*rs = *stallRS("onepassword", "connect-old", "connect", 1, 2, false)
			objs[i] = rs
		}
	}
	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(objs...)
	u := newStallUnlocker(cs, dyn, time.Hour, "ops/connect")

	before := testutil.ReconcileErrorCount(t, "helmrelease-unlocker")
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := rsReplicas(t, cs, "onepassword", "connect-old"); got != 2 {
		t.Fatalf("old ReplicaSet scaled on preferred-only anti-affinity: %d, want 2", got)
	}
	if got := testutil.ReconcileErrorCount(t, "helmrelease-unlocker"); got != before+1 {
		t.Fatalf("preferred-only refusal did not IncError: got %v, want %v", got, before+1)
	}
}

// The 24h cooldown — in-RAM ledger AND the persisted
// passiontech.dev/last-helm-stall-unwedge stamp — suppresses a second
// unwedge and alerts once per window; a re-stall inside the window
// means the previous unwedge did not fix it.
func TestHelmStallUnwedgeCooldownHonored(t *testing.T) {
	t.Run("in-memory ledger", func(t *testing.T) {
		hr, objs := stallFixture()
		dyn := newDynFake(hr)
		cs := kfake.NewSimpleClientset(objs...)
		u := newStallUnlocker(cs, dyn, time.Hour, "ops/connect")
		u.stall.unwedged.Stamp("ops/connect", time.Now().Add(-time.Hour))

		before := testutil.ReconcileErrorCount(t, "helmrelease-unlocker")
		if err := u.run(ctx); err != nil {
			t.Fatal(err)
		}
		if got := rsReplicas(t, cs, "onepassword", "connect-old"); got != 2 {
			t.Fatalf("old ReplicaSet scaled inside the cooldown: %d, want 2", got)
		}
		if got := testutil.ReconcileErrorCount(t, "helmrelease-unlocker"); got != before+1 {
			t.Fatalf("re-stall inside cooldown did not IncError: got %v, want %v", got, before+1)
		}
		// A second sweep inside the same window must NOT re-alert.
		if err := u.run(ctx); err != nil {
			t.Fatal(err)
		}
		if got := testutil.ReconcileErrorCount(t, "helmrelease-unlocker"); got != before+1 {
			t.Fatalf("alert dedup broke — repeated IncError inside cooldown: got %v, want %v", got, before+1)
		}
	})

	t.Run("persisted annotation", func(t *testing.T) {
		hr, objs := stallFixture()
		hr.SetAnnotations(map[string]string{
			helmLastStallUnwedgeAnno: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		})
		dyn := newDynFake(hr)
		cs := kfake.NewSimpleClientset(objs...)
		u := newStallUnlocker(cs, dyn, time.Hour, "ops/connect")

		if err := u.run(ctx); err != nil {
			t.Fatal(err)
		}
		if got := rsReplicas(t, cs, "onepassword", "connect-old"); got != 2 {
			t.Fatalf("old ReplicaSet scaled inside the persisted cooldown: %d, want 2", got)
		}
	})

	t.Run("expired cooldown re-arms", func(t *testing.T) {
		hr, objs := stallFixture()
		dyn := newDynFake(hr)
		cs := kfake.NewSimpleClientset(objs...)
		u := newStallUnlocker(cs, dyn, time.Hour, "ops/connect")
		u.stall.unwedged.Stamp("ops/connect", time.Now().Add(-25*time.Hour))

		if err := u.run(ctx); err != nil {
			t.Fatal(err)
		}
		if got := rsReplicas(t, cs, "onepassword", "connect-old"); got != 1 {
			t.Fatalf("old ReplicaSet not scaled after cooldown expiry: %d, want 1", got)
		}
	})
}

// The 30m first-seen window applies to the stall signature too — a
// live upgrade legitimately sits on the stalled-resources message for
// minutes while helm waits.
func TestHelmStallUnwedgeFirstSeenGate(t *testing.T) {
	hr, objs := stallFixture()
	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(objs...)
	u := newStallUnlocker(cs, dyn, 0, "")

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := u.stall.firstSeen.Seen("ops/connect", time.Now()); !ok {
		t.Fatal("stalled HR not tracked in stall.firstSeen")
	}
	if got := rsReplicas(t, cs, "onepassword", "connect-old"); got != 2 {
		t.Fatalf("acted before the 30m window: %d, want 2", got)
	}
	u.stall.firstSeen.Forget("ops/connect")
	u.stall.firstSeen.Observe("ops/connect", time.Now().Add(-helmStuckThreshold-time.Minute))
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := rsReplicas(t, cs, "onepassword", "connect-old"); got != 1 {
		t.Fatalf("old ReplicaSet not scaled after the window: %d, want 1", got)
	}
}

// Disabled (HELM_STALL_UNWEDGE_ENABLED absent): the stalled HR is not
// even tracked, and nothing is scaled — while the rest of the module
// still runs.
func TestHelmStallUnwedgeDisabledGate(t *testing.T) {
	hr, objs := stallFixture()
	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(objs...)
	u := newStallUnlocker(cs, dyn, time.Hour, "ops/connect")
	u.stall.enabled = false

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := u.stall.firstSeen.Seen("ops/connect", time.Now()); ok {
		t.Fatal("disabled module tracked the stalled HR")
	}
	if got := rsReplicas(t, cs, "onepassword", "connect-old"); got != 2 {
		t.Fatalf("disabled module scaled the old ReplicaSet: %d, want 2", got)
	}
}

// No Deployment token in the messages → the release-namespace scan
// finds the single ProgressDeadlineExceeded Deployment and remediates
// the same way.
func TestHelmStallUnwedgeListFallback(t *testing.T) {
	hr, objs := stallFixture()
	// Scrub the explicit Deployment/<name> token from every message.
	if conds, ok, _ := unstructured.NestedSlice(hr.Object, "status", "conditions"); ok {
		for _, c := range conds {
			if m, ok := c.(map[string]any); ok {
				m["message"] = "upgrade retries exhausted — no workload named"
			}
		}
	}
	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(objs...)
	u := newStallUnlocker(cs, dyn, time.Hour, "ops/connect")

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := rsReplicas(t, cs, "onepassword", "connect-old"); got != 1 {
		t.Fatalf("fallback resolution did not scale the old ReplicaSet: %d, want 1", got)
	}
}

// helm-stall-unwedge attempt budget: a REFUSAL consumes one of the
// stallMaxAttemptsPerRevision tries just like an action does —
// otherwise a permanently refused signature would re-run the full
// workload-layer analysis every sweep and never reach the cap. At
// the cap the HR is not analyzed at all (zero Deployment reads).
func TestHelmStallUnwedgeRefusalConsumesAttempt(t *testing.T) {
	hr, objs := stallFixture()
	// Refusal shape: the surge pod is pending on a resource
	// shortage, not anti-affinity — never scaled for that.
	for i, o := range objs {
		if p, ok := o.(*corev1.Pod); ok && p.Name == "connect-new-1" {
			p.Status.Conditions[0].Message =
				"0/2 nodes are available: 2 Insufficient cpu."
			objs[i] = p
		}
	}
	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(objs...)
	u := newStallUnlocker(cs, dyn, time.Hour, "ops/connect")

	// Refusal #1 burns attempt 1.
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	att := u.stall.attempts["ops/connect"]
	if att == nil || att.count != 1 {
		t.Fatalf("refusal did not consume an attempt: %+v", att)
	}

	// Refusal #2 — past the 6h attempt gap — hits the per-revision cap.
	att.last = time.Now().Add(-stallAttemptCooldown - time.Minute)
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if att.count != stallMaxAttemptsPerRevision {
		t.Fatalf("second refusal: count = %d, want %d",
			att.count, stallMaxAttemptsPerRevision)
	}

	// At the cap the HR must not be analyzed at all — a Deployment
	// Get would mean unwedge() ran.
	depReads := 0
	cs.PrependReactor("get", "deployments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			depReads++
			return false, nil, nil
		})
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if depReads != 0 {
		t.Fatalf("capped HR still analyzed: %d deployment reads, want 0", depReads)
	}
}

// Stalled=True alone triggers analysis but a Deployment that does not
// show the deadlock shape (healthy new RS, no pending pods) is a
// refusal — the HR signature is necessary but not sufficient.
func TestHelmStallUnwedgeNonDeadlockShapeSkipped(t *testing.T) {
	hr, objs := stallFixture()
	// Remove the pending surge pod — the rollout already settled.
	var kept []runtime.Object
	for _, o := range objs {
		if p, ok := o.(*corev1.Pod); ok && p.Name == "connect-new-1" {
			continue
		}
		kept = append(kept, o)
	}
	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(kept...)
	u := newStallUnlocker(cs, dyn, time.Hour, "ops/connect")

	before := testutil.ReconcileErrorCount(t, "helmrelease-unlocker")
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := rsReplicas(t, cs, "onepassword", "connect-old"); got != 2 {
		t.Fatalf("old ReplicaSet scaled without pending pods: %d, want 2", got)
	}
	if got := testutil.ReconcileErrorCount(t, "helmrelease-unlocker"); got != before+1 {
		t.Fatalf("shape refusal did not IncError: got %v, want %v", got, before+1)
	}
}

// The helm-stall-unwedge retry ledger has no stamps to age out — its entries die
// with the HR: a vanished HR's stallAttempt is deleted at the next
// sweep-end prune, a still-listed HR keeps its entry (and its count).
func TestHelmStallAttemptsPrunedWhenHRVanishes(t *testing.T) {
	live := hrObj("apps", "myapp", "v2")
	hrReady(live, "True", "Reconciliation finished")
	dyn := newDynFake(live)
	u := newUnlocker(kfake.NewSimpleClientset(), dyn, 0, "")
	u.stall.attempts = map[string]*stallAttempt{
		"apps/gone":  {revision: "3", count: 2, last: time.Now()},
		"apps/myapp": {revision: "7", count: 1, last: time.Now()},
	}

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := u.stall.attempts["apps/gone"]; ok {
		t.Fatal("stallAttempt for a deleted HR not pruned after the sweep")
	}
	if att := u.stall.attempts["apps/myapp"]; att == nil || att.revision != "7" {
		t.Fatalf("listed HR lost its stallAttempt entry: %+v", att)
	}
}
