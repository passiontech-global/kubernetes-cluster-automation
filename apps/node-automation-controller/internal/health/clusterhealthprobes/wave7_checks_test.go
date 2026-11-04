// wave7_checks_test.go — the W7-C2 operator watchdog expansion, the
// W7-C3 dragonfly dual-replica deadlock heal, the W7-C4
// localpv-stranded-pods check and the W7-C5 olm-subscription-health
// check, driven through the fake clientset + fake dynamic client.
package clusterhealthprobes

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// W7-C2 — operator watchdog expansion
// ---------------------------------------------------------------------------

// The watchdog must cover the original five plus the ten W7-C2
// additions — and never a duplicate name (a dup would share a
// first-seen keyspace and double-report).
func TestOperatorWatchdogTargetsComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, op := range operatorTargets {
		if seen[op.name] {
			t.Fatalf("duplicate operator target %q", op.name)
		}
		seen[op.name] = true
	}
	if len(operatorTargets) != 15 {
		t.Fatalf("operatorTargets = %d, want 15", len(operatorTargets))
	}
	for _, want := range []string{
		"source-controller", "notification-controller", "cert-manager",
		"external-secrets", "rabbitmq-cluster-operator", "keda-operator",
		"argocd-operator", "kargo-controller", "everest-operator",
		"shipwright-build-controller",
	} {
		if !seen[want] {
			t.Fatalf("missing operator target %q", want)
		}
	}
}

// The two new never-reconciled predicates: empty status.conditions
// reads stuck, any condition reads healthy; an absent/empty
// status.phase reads stuck, any phase reads healthy.
func TestWave7StuckPredicates(t *testing.T) {
	bare := shUnstructured("cert-manager.io/v1", "Certificate", "cm", "c", 1, 0)
	if !noStatusConditions(bare) {
		t.Fatal("Certificate with no status.conditions must read stuck")
	}
	_ = unstructured.SetNestedSlice(bare.Object,
		[]any{map[string]any{"type": "Ready", "status": "False"}},
		"status", "conditions")
	if noStatusConditions(bare) {
		t.Fatal("Certificate carrying conditions must not read stuck")
	}

	argocd := shUnstructured("argoproj.io/v1beta1", "ArgoCD", "cd", "arg", 1, 0)
	if !emptyStatusPhase(argocd) {
		t.Fatal("ArgoCD with no status.phase must read stuck")
	}
	_ = unstructured.SetNestedField(argocd.Object, "Available", "status", "phase")
	if emptyStatusPhase(argocd) {
		t.Fatal("ArgoCD with a phase must not read stuck")
	}
}

// A new watchdog target end-to-end: source-controller renewing its
// Lease while a GitRepository sits unreconciled past the window →
// frozen gauge + leader pod deleted.
func TestCheckOperatorWorkqueuesSourceControllerHeals(t *testing.T) {
	metrics.OperatorWorkqueueFrozen.DeleteLabelValues("source-controller", kcmReasonStaleGen)
	t.Cleanup(func() {
		metrics.OperatorWorkqueueFrozen.DeleteLabelValues("source-controller", kcmReasonStaleGen)
	})
	base := time.Now()
	leader := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "flux-system", Name: "source-controller-7d9f",
		UID:    types.UID("sc-uid-1"),
		Labels: map[string]string{"app": "source-controller"},
	}}
	cs := fake.NewSimpleClientset(
		shLease("flux-system", "source-controller-leader-election",
			"source-controller-7d9f_3f2a1", 2*time.Second, base),
		leader)
	stuck := shUnstructured("source.toolkit.fluxcd.io/v1", "GitRepository",
		"apps", "repo", 5, 3)
	p := testProberDyn(cs, shOpDyn(stuck))
	p.now = func() time.Time { return base }
	p.opFirstSeen["source-controller/gitrepositories/apps/repo"] = base.Add(-time.Hour)

	if res := p.checkOperatorWorkqueues(ctx); res.pass {
		t.Fatal("stuck gitrepository with a renewing lease must FAIL")
	}
	if v, _ := shOpFrozenGauge(t, "source-controller", kcmReasonStaleGen); v != 1 {
		t.Fatalf("frozen gauge = %v, want 1", v)
	}
	if _, err := cs.CoreV1().Pods("flux-system").
		Get(ctx, "source-controller-7d9f", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("leader pod must be deleted, err=%v", err)
	}
}

// A cert-manager Certificate never reconciled (no status.conditions)
// freezes under the no_status_conditions reason.
func TestCheckOperatorWorkqueuesCertManagerNoConditions(t *testing.T) {
	metrics.OperatorWorkqueueFrozen.DeleteLabelValues("cert-manager", opReasonNoConditions)
	t.Cleanup(func() {
		metrics.OperatorWorkqueueFrozen.DeleteLabelValues("cert-manager", opReasonNoConditions)
	})
	base := time.Now()
	cs := fake.NewSimpleClientset(
		// cert-manager elects leaders in kube-system (helm chart
		// default global.leaderElection.namespace).
		shLease("kube-system", "cert-manager-controller",
			"cert-manager-abc_uid", 2*time.Second, base))
	stuck := shUnstructured("cert-manager.io/v1", "Certificate", "apps", "tls", 1, 0)
	p := testProberDyn(cs, shOpDyn(stuck))
	p.now = func() time.Time { return base }
	p.opFirstSeen["cert-manager/certificates/apps/tls"] = base.Add(-time.Hour)

	if res := p.checkOperatorWorkqueues(ctx); res.pass {
		t.Fatal("never-reconciled Certificate must FAIL")
	}
	if v, _ := shOpFrozenGauge(t, "cert-manager", opReasonNoConditions); v != 1 {
		t.Fatalf("frozen gauge = %v, want 1", v)
	}
}

// ---------------------------------------------------------------------------
// W7-C3 — dragonfly dual-replica deadlock heal
// ---------------------------------------------------------------------------

// shDragonflyPod builds a Ready STS pod with the given role label
// ("" = no role label — the dual-replica wedge).
func shDragonflyPod(ns, name, role string, ready bool) *corev1.Pod {
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
		shDragonflyPod("db", "dragonfly-0", "replica", true),
		shDragonflyPod("db", "dragonfly-1", "replica", true))
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }
	p.stsZeroSince["db/dragonfly-master/dragonfly"] = base.Add(-12 * time.Minute)
	p.drHealed["dragonfly-operator-system/dragonfly-operator-controller-manager-x"] =
		base.Add(-4 * time.Minute)

	if res := p.checkStatefulMasterlessServices(ctx); res.pass {
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
	m := findMetric(t, "node_automation_dragonfly_masterless_pod_heals_total",
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
		shDragonflyPod("db", "dragonfly-0", "replica", true),
		shDragonflyPod("db", "dragonfly-1", "replica", true))
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }
	p.stsZeroSince["db/dragonfly-master/dragonfly"] = base.Add(-12 * time.Minute)
	p.drHealed["dragonfly-operator-system/x"] = base.Add(-time.Minute)

	_ = p.checkStatefulMasterlessServices(ctx)
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
		shDragonflyPod("db", "dragonfly-0", "replica", true))
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }
	p.stsZeroSince["db/dragonfly-master/dragonfly"] = base.Add(-12 * time.Minute)

	_ = p.checkStatefulMasterlessServices(ctx)
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
		shDragonflyPod("db", "dragonfly-0", "master", true),
		shDragonflyPod("db", "dragonfly-1", "replica", true))
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }
	p.stsZeroSince["db/dragonfly-master/dragonfly"] = base.Add(-12 * time.Minute)
	p.drHealed["dragonfly-operator-system/x"] = base.Add(-4 * time.Minute)

	_ = p.checkStatefulMasterlessServices(ctx)
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
		shDragonflyPod("db", "dragonfly-0", "replica", true))
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }
	p.stsZeroSince["db/dragonfly-master/dragonfly"] = base.Add(-12 * time.Minute)
	p.drHealed["dragonfly-operator-system/x"] = base.Add(-4 * time.Minute)
	p.drPodHealed["db/dragonfly"] = base.Add(-10 * time.Minute)

	_ = p.checkStatefulMasterlessServices(ctx)
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
		shDragonflyPod("db", "dragonfly-0", "replica", true))
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }
	p.stsZeroSince["db/dragonfly-master/dragonfly"] = base.Add(-12 * time.Minute)
	p.drHealed["dragonfly-operator-system/x"] = base.Add(-4 * time.Minute)

	_ = p.checkStatefulMasterlessServices(ctx)
	if _, err := cs.CoreV1().Pods("db").
		Get(ctx, "dragonfly-0", metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted during maintenance")
	}
}

// ---------------------------------------------------------------------------
// W7-C4 — localpv-stranded-pods
// ---------------------------------------------------------------------------

// w7PV builds a hostpath PV nodeAffinity-pinned to hostname.
func w7PV(name, hostname string) *corev1.PersistentVolume {
	return &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.PersistentVolumeSpec{
			NodeAffinity: &corev1.VolumeNodeAffinity{
				Required: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{{
						MatchExpressions: []corev1.NodeSelectorRequirement{{
							Key:      corev1.LabelHostname,
							Operator: corev1.NodeSelectorOpIn,
							Values:   []string{hostname},
						}},
					}},
				},
			},
		},
	}
}

// w7PVC builds a bound (or Pending) PVC pointing at pvName/sc.
func w7PVC(ns, name, pvName, sc string, phase corev1.PersistentVolumeClaimPhase) *corev1.PersistentVolumeClaim {
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(name)},
		Status:     corev1.PersistentVolumeClaimStatus{Phase: phase},
	}
	if pvName != "" {
		pvc.Spec.VolumeName = pvName
	}
	if sc != "" {
		pvc.Spec.StorageClassName = &sc
	}
	return pvc
}

// w7PendingPod builds a Pending pod aged `age` claiming pvcName.
func w7PendingPod(ns, name, pvcName string, age time.Duration, at time.Time) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name, UID: types.UID(name),
			CreationTimestamp: metav1.NewTime(at.Add(-age)),
		},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{{
				Name: "data",
				VolumeSource: corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
						ClaimName: pvcName}},
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodPending},
	}
}

// A concourse-worker stranded on a MISSING node past 10m: gauge
// fires AND the disposable PVC+pod are reaped so the STS rebinds.
func TestLocalPVStrandedConcourseHeals(t *testing.T) {
	metrics.LocalPVEphemeralHealsTotal.DeleteLabelValues("concourse", "concourse-work-dir-concourse-worker-0", "dead-node")
	t.Cleanup(func() {
		metrics.LocalPVStrandedPods.DeleteLabelValues(
			"concourse", "concourse-worker-0", "concourse-work-dir-concourse-worker-0", "dead-node", strandedReasonMissingNode)
		metrics.LocalPVEphemeralHealsTotal.DeleteLabelValues("concourse", "concourse-work-dir-concourse-worker-0", "dead-node")
	})
	base := time.Now()
	cs := fake.NewSimpleClientset(
		w7PendingPod("concourse", "concourse-worker-0",
			"concourse-work-dir-concourse-worker-0", 12*time.Minute, base),
		w7PVC("concourse", "concourse-work-dir-concourse-worker-0",
			"pvc-aaa", "", corev1.ClaimBound),
		w7PV("pvc-aaa", "dead-node"))
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }

	res := p.checkLocalPVStrandedPods(ctx)
	if res.pass {
		t.Fatal("stranded pod must FAIL")
	}
	m := findMetric(t, "node_automation_localpv_stranded_pods",
		map[string]string{"namespace": "concourse", "pod": "concourse-worker-0",
			"pvc":  "concourse-work-dir-concourse-worker-0",
			"node": "dead-node", "reason": strandedReasonMissingNode})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("stranded gauge missing/0, want 1")
	}
	if _, err := cs.CoreV1().PersistentVolumeClaims("concourse").
		Get(ctx, "concourse-work-dir-concourse-worker-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("dead PVC must be deleted, err=%v", err)
	}
	if _, err := cs.CoreV1().Pods("concourse").
		Get(ctx, "concourse-worker-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("stranded pod must be deleted, err=%v", err)
	}
	m = findMetric(t, "node_automation_localpv_ephemeral_heals_total",
		map[string]string{"namespace": "concourse",
			"pvc": "concourse-work-dir-concourse-worker-0", "node": "dead-node"})
	if m == nil || m.GetCounter().GetValue() != 1 {
		t.Fatal("ephemeral heals counter = 0, want 1")
	}
}

// A non-ephemeral workload (a database) on a missing node gets the
// gauge but never the delete — its volume is the data.
func TestLocalPVStrandedDatabaseNoHeal(t *testing.T) {
	t.Cleanup(func() {
		metrics.LocalPVStrandedPods.DeleteLabelValues(
			"scylla", "scylla-0", "data-scylla-0", "dead-node", strandedReasonMissingNode)
	})
	base := time.Now()
	cs := fake.NewSimpleClientset(
		w7PendingPod("scylla", "scylla-0", "data-scylla-0", 30*time.Minute, base),
		w7PVC("scylla", "data-scylla-0", "pv-1", "", corev1.ClaimBound),
		w7PV("pv-1", "dead-node"))
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }

	if res := p.checkLocalPVStrandedPods(ctx); res.pass {
		t.Fatal("stranded database pod must FAIL")
	}
	if _, err := cs.CoreV1().PersistentVolumeClaims("scylla").
		Get(ctx, "data-scylla-0", metav1.GetOptions{}); err != nil {
		t.Fatal("database PVC must never be deleted")
	}
	if _, err := cs.CoreV1().Pods("scylla").
		Get(ctx, "scylla-0", metav1.GetOptions{}); err != nil {
		t.Fatal("database pod must never be deleted")
	}
}

// An annotated ephemeral workload heals on an out-of-service node
// even outside the concourse namespace.
func TestLocalPVStrandedAnnotatedEphemeralHeals(t *testing.T) {
	t.Cleanup(func() {
		metrics.LocalPVStrandedPods.DeleteLabelValues(
			"apps", "cache-0", "data-cache-0", "node-f", strandedReasonOutOfService)
		metrics.LocalPVEphemeralHealsTotal.DeleteLabelValues("apps", "data-cache-0", "node-f")
	})
	base := time.Now()
	fenced := testutil.Node("node-f", corev1.ConditionFalse, nil,
		corev1.Taint{Key: corev1.TaintNodeOutOfService, Effect: corev1.TaintEffectNoExecute})
	pod := w7PendingPod("apps", "cache-0", "data-cache-0", 15*time.Minute, base)
	pvc := w7PVC("apps", "data-cache-0", "pv-1", "", corev1.ClaimBound)
	pvc.Annotations = map[string]string{localPVEphemeralAnno: "true"}
	cs := fake.NewSimpleClientset(fenced, pod, pvc, w7PV("pv-1", "node-f"))
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }

	_ = p.checkLocalPVStrandedPods(ctx)
	m := findMetric(t, "node_automation_localpv_stranded_pods",
		map[string]string{"namespace": "apps", "pod": "cache-0",
			"pvc": "data-cache-0", "node": "node-f", "reason": strandedReasonOutOfService})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("stranded gauge missing on the out-of-service node")
	}
	if _, err := cs.CoreV1().PersistentVolumeClaims("apps").
		Get(ctx, "data-cache-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatal("annotated ephemeral PVC must be deleted")
	}
}

// The heal refuses soft states — NotReady and cordoned nodes can
// come back; only missing/fenced confirms the node is gone.
func TestLocalPVStrandedSoftStatesAlertOnly(t *testing.T) {
	for _, tc := range []struct {
		name   string
		node   *corev1.Node
		reason string
	}{
		{"not_ready",
			testutil.Node("n1", corev1.ConditionFalse, nil),
			strandedReasonNotReady},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := time.Now()
			cs := fake.NewSimpleClientset(tc.node,
				w7PendingPod("concourse", "concourse-worker-0",
					"pvc-w", 30*time.Minute, base),
				w7PVC("concourse", "pvc-w", "pv-1", "", corev1.ClaimBound),
				w7PV("pv-1", "n1"))
			p := testProberDyn(cs, shOpDyn())
			p.now = func() time.Time { return base }
			defer metrics.LocalPVStrandedPods.DeleteLabelValues(
				"concourse", "concourse-worker-0", "pvc-w", "n1", tc.reason)

			if res := p.checkLocalPVStrandedPods(ctx); res.pass {
				t.Fatal("stranded pod must FAIL")
			}
			if _, err := cs.CoreV1().PersistentVolumeClaims("concourse").
				Get(ctx, "pvc-w", metav1.GetOptions{}); err != nil {
				t.Fatal("PVC deleted on a recoverable node state")
			}
		})
	}
}

// A stranded pod under the 10m ephemeral window keeps its PVC — the
// gauge fires but the heal waits.
func TestLocalPVStrandedTooYoungForHeal(t *testing.T) {
	t.Cleanup(func() {
		metrics.LocalPVStrandedPods.DeleteLabelValues(
			"concourse", "concourse-worker-0", "pvc-w", "dead-node", strandedReasonMissingNode)
	})
	base := time.Now()
	cs := fake.NewSimpleClientset(
		w7PendingPod("concourse", "concourse-worker-0", "pvc-w", 6*time.Minute, base),
		w7PVC("concourse", "pvc-w", "pv-1", "", corev1.ClaimBound),
		w7PV("pv-1", "dead-node"))
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }

	if res := p.checkLocalPVStrandedPods(ctx); res.pass {
		t.Fatal("stranded pod must FAIL")
	}
	if _, err := cs.CoreV1().PersistentVolumeClaims("concourse").
		Get(ctx, "pvc-w", metav1.GetOptions{}); err != nil {
		t.Fatal("PVC deleted before the 10m heal window")
	}
}

// Deliberate maintenance gates the ephemeral heal.
func TestLocalPVStrandedMaintenanceDefers(t *testing.T) {
	base := time.Now()
	cordoned := testutil.Node("w1", corev1.ConditionTrue, nil)
	cordoned.Spec.Unschedulable = true
	cs := fake.NewSimpleClientset(cordoned,
		w7PendingPod("concourse", "concourse-worker-0", "pvc-w", 30*time.Minute, base),
		w7PVC("concourse", "pvc-w", "pv-1", "", corev1.ClaimBound),
		w7PV("pv-1", "dead-node"))
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }

	_ = p.checkLocalPVStrandedPods(ctx)
	if _, err := cs.CoreV1().PersistentVolumeClaims("concourse").
		Get(ctx, "pvc-w", metav1.GetOptions{}); err != nil {
		t.Fatal("PVC deleted during maintenance")
	}
}

// Branch B: a Pending PVC on openebs-hostpath while a Ready worker
// exists → stalled gauge + provisioner pod bounce.
func TestPVCStalledProvisionerHeals(t *testing.T) {
	t.Cleanup(func() {
		metrics.PVCProvisioningStalled.DeleteLabelValues("apps", "data-x", "openebs-hostpath")
		metrics.PVCProvisionerHealsTotal.DeleteLabelValues("openebs-localpv-provisioner")
	})
	base := time.Now()
	worker := testutil.Node("w1", corev1.ConditionTrue, nil)
	provPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "openebs", Name: "openebs-localpv-provisioner-abc", UID: "p1"}}
	cs := fake.NewSimpleClientset(worker, provPod,
		w7PendingPod("apps", "web-0", "data-x", 20*time.Minute, base),
		w7PVC("apps", "data-x", "", "openebs-hostpath", corev1.ClaimPending))
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }

	if res := p.checkLocalPVStrandedPods(ctx); res.pass {
		t.Fatal("stalled provisioning must FAIL")
	}
	m := findMetric(t, "node_automation_pvc_provisioning_stalled",
		map[string]string{"namespace": "apps", "pvc": "data-x", "storageclass": "openebs-hostpath"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("stalled gauge missing/0, want 1")
	}
	if _, err := cs.CoreV1().Pods("openebs").
		Get(ctx, "openebs-localpv-provisioner-abc", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("wedged provisioner must be deleted, err=%v", err)
	}
}

// No Ready+schedulable worker → the pending claim is expected, not
// stalled: no gauge, no heal.
func TestPVCStalledNeedsAWorker(t *testing.T) {
	base := time.Now()
	provPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "openebs", Name: "openebs-localpv-provisioner-abc", UID: "p1"}}
	cs := fake.NewSimpleClientset(provPod,
		w7PendingPod("apps", "web-0", "data-x", 20*time.Minute, base),
		w7PVC("apps", "data-x", "", "openebs-hostpath", corev1.ClaimPending))
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }

	if res := p.checkLocalPVStrandedPods(ctx); !res.pass {
		t.Fatalf("no schedulable worker must pass quietly: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("openebs").
		Get(ctx, "openebs-localpv-provisioner-abc", metav1.GetOptions{}); err != nil {
		t.Fatal("provisioner deleted with no schedulable worker")
	}
}

// ---------------------------------------------------------------------------
// W7-C5 — olm-subscription-health
// ---------------------------------------------------------------------------

// w7Unstructured builds an OLM object with the fields the check
// reads, supplied by the caller as nested status fields.
func w7OLM(apiVersion, kind, ns, name string, status map[string]any) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata":   map[string]any{"namespace": ns, "name": name},
	}}
	for k, v := range status {
		_ = unstructured.SetNestedField(obj.Object, v, "status", k)
	}
	return obj
}

// Absent OLM CRDs read as "not installed" — the check stays quiet.
func TestCheckOLMHealthAbsentCRDsQuiet(t *testing.T) {
	dyn := shOpDyn()
	dyn.PrependReactor("list", "clusterserviceversions",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(
				olmCSVGVR.GroupResource(), "")
		})
	dyn.PrependReactor("list", "subscriptions",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(
				olmSubGVR.GroupResource(), "")
		})
	p := testProberDyn(fake.NewSimpleClientset(), dyn)
	if res := p.checkOLMHealth(ctx); !res.pass {
		t.Fatalf("absent OLM CRDs must pass quietly: %+v", res)
	}
}

// A CSV stuck off Succeeded past 15m fires the gauge; past 20m the
// olm-operator leader gets bounced to force re-reconciliation.
func TestCheckOLMHealthStuckCSVHeals(t *testing.T) {
	metrics.OLMUnhealthyResources.DeleteLabelValues(
		olmKindCSV, "operators", "rabbitmq.v1.2.3", olmReasonCSVStuck)
	t.Cleanup(func() {
		metrics.OLMUnhealthyResources.DeleteLabelValues(
			olmKindCSV, "operators", "rabbitmq.v1.2.3", olmReasonCSVStuck)
		metrics.OLMOperatorHealsTotal.DeleteLabelValues(olmReasonCSVStuck)
	})
	base := time.Now()
	opPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "olm", Name: "olm-operator-77dc", UID: "o1"}}
	cs := fake.NewSimpleClientset(opPod)
	csv := w7OLM("operators.coreos.com/v1alpha1", "ClusterServiceVersion",
		"operators", "rabbitmq.v1.2.3", map[string]any{"phase": "Installing"})
	p := testProberDyn(cs, shOpDyn(csv))
	p.now = func() time.Time { return base }

	// First sighting — tracked, quiet.
	if res := p.checkOLMHealth(ctx); !res.pass {
		t.Fatalf("first-seen CSV must pass: %+v", res)
	}

	// 16m — gauge fires, still under the heal window.
	at := base.Add(16 * time.Minute)
	p.now = func() time.Time { return at }
	if res := p.checkOLMHealth(ctx); res.pass {
		t.Fatal("CSV stuck >=15m must FAIL")
	}
	m := findMetric(t, "node_automation_olm_unhealthy_resources",
		map[string]string{"kind": olmKindCSV, "namespace": "operators",
			"name": "rabbitmq.v1.2.3", "reason": olmReasonCSVStuck})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("olm unhealthy gauge missing/0, want 1")
	}
	if _, err := cs.CoreV1().Pods("olm").
		Get(ctx, "olm-operator-77dc", metav1.GetOptions{}); err != nil {
		t.Fatal("olm-operator deleted before the 20m heal window")
	}

	// 21m — the operator is bounced.
	at = base.Add(21 * time.Minute)
	p.now = func() time.Time { return at }
	if res := p.checkOLMHealth(ctx); res.pass {
		t.Fatal("still stuck — must keep FAILING")
	}
	if _, err := cs.CoreV1().Pods("olm").
		Get(ctx, "olm-operator-77dc", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("olm-operator must be deleted past 20m, err=%v", err)
	}
}

// A Subscription carrying CatalogSourcesUnhealthy=True flags after
// the window but never triggers the operator heal — that's the
// CSV-scoped path.
func TestCheckOLMHealthUnhealthySubscription(t *testing.T) {
	t.Cleanup(func() {
		metrics.OLMUnhealthyResources.DeleteLabelValues(
			olmKindSubscription, "operators", "keda", olmReasonCatalogUnhealthy)
	})
	base := time.Now()
	opPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "olm", Name: "olm-operator-77dc", UID: "o1"}}
	cs := fake.NewSimpleClientset(opPod)
	sub := w7OLM("operators.coreos.com/v1alpha1", "Subscription",
		"operators", "keda", map[string]any{
			"conditions": []any{map[string]any{
				"type": "CatalogSourcesUnhealthy", "status": "True"}},
		})
	p := testProberDyn(cs, shOpDyn(sub))
	p.now = func() time.Time { return base }
	p.olmFirstSeen["Subscription/operators/keda/"+olmReasonCatalogUnhealthy] =
		base.Add(-time.Hour)

	if res := p.checkOLMHealth(ctx); res.pass {
		t.Fatal("unhealthy subscription must FAIL")
	}
	if _, err := cs.CoreV1().Pods("olm").
		Get(ctx, "olm-operator-77dc", metav1.GetOptions{}); err != nil {
		t.Fatal("olm-operator deleted for a subscription-only failure")
	}
}

// An expired certsRotateAt counts the same as a wedged phase — the
// webhook certs OLM owes the operand never landed.
func TestCheckOLMHealthCertRotationOverdue(t *testing.T) {
	t.Cleanup(func() {
		metrics.OLMUnhealthyResources.DeleteLabelValues(
			olmKindCSV, "operators", "nhc.v1", olmReasonCertOverdue)
		metrics.OLMOperatorHealsTotal.DeleteLabelValues(olmReasonCertOverdue)
	})
	base := time.Now()
	opPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "olm", Name: "olm-operator-77dc", UID: "o1"}}
	cs := fake.NewSimpleClientset(opPod)
	csv := w7OLM("operators.coreos.com/v1alpha1", "ClusterServiceVersion",
		"operators", "nhc.v1", map[string]any{
			"phase":         "Succeeded",
			"certsRotateAt": base.Add(-30 * time.Minute).UTC().Format(time.RFC3339),
		})
	p := testProberDyn(cs, shOpDyn(csv))
	p.now = func() time.Time { return base }
	p.olmFirstSeen["ClusterServiceVersion/operators/nhc.v1/"+olmReasonCertOverdue] =
		base.Add(-25 * time.Minute)

	if res := p.checkOLMHealth(ctx); res.pass {
		t.Fatal("overdue cert rotation past the heal window must FAIL")
	}
	if _, err := cs.CoreV1().Pods("olm").
		Get(ctx, "olm-operator-77dc", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("olm-operator must be deleted, err=%v", err)
	}
}

// A healthy CSV + clean subscription pass quietly.
func TestCheckOLMHealthHealthyPasses(t *testing.T) {
	csv := w7OLM("operators.coreos.com/v1alpha1", "ClusterServiceVersion",
		"operators", "nhc.v1", map[string]any{"phase": "Succeeded"})
	p := testProberDyn(fake.NewSimpleClientset(), shOpDyn(csv))
	if res := p.checkOLMHealth(ctx); !res.pass {
		t.Fatalf("healthy OLM state must pass: %+v", res)
	}
	if len(p.olmFirstSeen) != 0 {
		t.Fatalf("healthy objects must not be tracked: %v", p.olmFirstSeen)
	}
}
