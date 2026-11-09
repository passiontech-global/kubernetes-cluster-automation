// localpv_stranded_pods_test.go — coverage for the
// localpv-stranded-pods check (localpv-stranded-pods): stranded-pod detection,
// ephemeral-PVC reap gating, and the stalled-provisioning branch.
package nodehealth

import (
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// localpv-stranded-pods — localpv-stranded-pods
// ---------------------------------------------------------------------------

// nodePinnedPV builds a hostpath PV nodeAffinity-pinned to hostname.
func nodePinnedPV(name, hostname string) *corev1.PersistentVolume {
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

// testPVC builds a bound (or Pending) PVC pointing at pvName/sc.
func testPVC(ns, name, pvName, sc string, phase corev1.PersistentVolumeClaimPhase) *corev1.PersistentVolumeClaim {
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

// pendingPodForPVC builds a Pending pod aged `age` claiming pvcName.
func pendingPodForPVC(ns, name, pvcName string, age time.Duration, at time.Time) *corev1.Pod {
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

// stalledHostpathPVC builds a Pending openebs-hostpath PVC the
// provisioner already selected a node for — the
// volume.kubernetes.io/selected-node annotation the stalled branch
// requires (a claim without it was never selected and is not wedge
// evidence).
func stalledHostpathPVC(ns, name string) *corev1.PersistentVolumeClaim {
	pvc := testPVC(ns, name, "", "openebs-hostpath", corev1.ClaimPending)
	pvc.Annotations = map[string]string{
		kube.AnnoVolumeSelectedNode: "node-w1"}
	return pvc
}

// A concourse-worker stranded on a MISSING node past 10m: gauge
// fires AND the disposable PVC+pod are reaped so the STS rebinds.
func TestLocalPVStrandedConcourseHeals(t *testing.T) {
	localPVEphemeralHealsTotal.DeleteLabelValues("concourse", "concourse-work-dir-concourse-worker-0", "dead-node")
	t.Cleanup(func() {
		localPVStrandedPodsGauge.DeleteLabelValues(
			"concourse", "concourse-worker-0", "concourse-work-dir-concourse-worker-0", "dead-node", strandedReasonMissingNode)
		localPVEphemeralHealsTotal.DeleteLabelValues("concourse", "concourse-work-dir-concourse-worker-0", "dead-node")
	})
	base := time.Now()
	cs := fake.NewSimpleClientset(
		pendingPodForPVC("concourse", "concourse-worker-0",
			"concourse-work-dir-concourse-worker-0", 12*time.Minute, base),
		testPVC("concourse", "concourse-work-dir-concourse-worker-0",
			"pvc-aaa", "", corev1.ClaimBound),
		nodePinnedPV("pvc-aaa", "dead-node"))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	res := probetest.MustCheck[*localPVStrandedCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("stranded pod must FAIL")
	}
	m := probetest.FindMetric(t, "node_automation_localpv_stranded_pods",
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
	m = probetest.FindMetric(t, "node_automation_localpv_ephemeral_heals_total",
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
		localPVStrandedPodsGauge.DeleteLabelValues(
			"scylla", "scylla-0", "data-scylla-0", "dead-node", strandedReasonMissingNode)
	})
	base := time.Now()
	cs := fake.NewSimpleClientset(
		pendingPodForPVC("scylla", "scylla-0", "data-scylla-0", 30*time.Minute, base),
		testPVC("scylla", "data-scylla-0", "pv-1", "", corev1.ClaimBound),
		nodePinnedPV("pv-1", "dead-node"))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*localPVStrandedCheck](t, p).Run(ctx); res.Pass {
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
		localPVStrandedPodsGauge.DeleteLabelValues(
			"apps", "cache-0", "data-cache-0", "node-f", strandedReasonOutOfService)
		localPVEphemeralHealsTotal.DeleteLabelValues("apps", "data-cache-0", "node-f")
	})
	base := time.Now()
	fenced := testutil.Node("node-f", corev1.ConditionFalse, nil,
		corev1.Taint{Key: corev1.TaintNodeOutOfService, Effect: corev1.TaintEffectNoExecute})
	pod := pendingPodForPVC("apps", "cache-0", "data-cache-0", 15*time.Minute, base)
	pvc := testPVC("apps", "data-cache-0", "pv-1", "", corev1.ClaimBound)
	pvc.Annotations = map[string]string{localPVEphemeralAnno: "true"}
	cs := fake.NewSimpleClientset(fenced, pod, pvc, nodePinnedPV("pv-1", "node-f"))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	_ = probetest.MustCheck[*localPVStrandedCheck](t, p).Run(ctx)
	m := probetest.FindMetric(t, "node_automation_localpv_stranded_pods",
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
				pendingPodForPVC("concourse", "concourse-worker-0",
					"pvc-w", 30*time.Minute, base),
				testPVC("concourse", "pvc-w", "pv-1", "", corev1.ClaimBound),
				nodePinnedPV("pv-1", "n1"))
			p := testProberDyn(cs, probetest.OpDyn())
			p.Now = func() time.Time { return base }
			defer localPVStrandedPodsGauge.DeleteLabelValues(
				"concourse", "concourse-worker-0", "pvc-w", "n1", tc.reason)

			if res := probetest.MustCheck[*localPVStrandedCheck](t, p).Run(ctx); res.Pass {
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
		localPVStrandedPodsGauge.DeleteLabelValues(
			"concourse", "concourse-worker-0", "pvc-w", "dead-node", strandedReasonMissingNode)
	})
	base := time.Now()
	cs := fake.NewSimpleClientset(
		pendingPodForPVC("concourse", "concourse-worker-0", "pvc-w", 6*time.Minute, base),
		testPVC("concourse", "pvc-w", "pv-1", "", corev1.ClaimBound),
		nodePinnedPV("pv-1", "dead-node"))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*localPVStrandedCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("stranded pod must FAIL")
	}
	if _, err := cs.CoreV1().PersistentVolumeClaims("concourse").
		Get(ctx, "pvc-w", metav1.GetOptions{}); err != nil {
		t.Fatal("PVC deleted before the 10m heal window")
	}
}

// stateful-split-brain — a NON-ephemeral workload stranded on a confirmed-dead
// node fires the dedicated stateful gauge naming the dead node;
// ephemeral pods stay on the generic gauge only.
func TestLocalPVStrandedStatefulPodGauge(t *testing.T) {
	localPVStrandedStatefulPodGauge.DeleteLabelValues("db", "pg-0", "dead-node")
	t.Cleanup(func() {
		localPVStrandedStatefulPodGauge.DeleteLabelValues("db", "pg-0", "dead-node")
		localPVStrandedPodsGauge.DeleteLabelValues(
			"db", "pg-0", "data-pg-0", "dead-node", strandedReasonMissingNode)
	})
	base := time.Now()
	cs := fake.NewSimpleClientset(
		pendingPodForPVC("db", "pg-0", "data-pg-0", 30*time.Minute, base),
		testPVC("db", "data-pg-0", "pv-1", "", corev1.ClaimBound),
		nodePinnedPV("pv-1", "dead-node"))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*localPVStrandedCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("stranded stateful pod must FAIL")
	}
	m := probetest.FindMetric(t, "node_automation_localpv_stranded_stateful_pod",
		map[string]string{"namespace": "db", "pod": "pg-0", "dead_node": "dead-node"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("stranded_stateful_pod gauge missing/0, want 1")
	}
	// The data volume is never touched — pod and PVC survive.
	if _, err := cs.CoreV1().PersistentVolumeClaims("db").
		Get(ctx, "data-pg-0", metav1.GetOptions{}); err != nil {
		t.Fatal("stateful PVC must never be deleted")
	}
	if _, err := cs.CoreV1().Pods("db").
		Get(ctx, "pg-0", metav1.GetOptions{}); err != nil {
		t.Fatal("stateful pod must never be deleted")
	}
}

// An EPHEMERAL workload on a dead node does NOT fire the stateful
// gauge — its class is covered by the heal, not the alert.
func TestLocalPVStrandedEphemeralNoStatefulGauge(t *testing.T) {
	t.Cleanup(func() {
		localPVStrandedPodsGauge.DeleteLabelValues(
			"concourse", "concourse-worker-0", "pvc-w", "dead-node", strandedReasonMissingNode)
	})
	base := time.Now()
	cs := fake.NewSimpleClientset(
		pendingPodForPVC("concourse", "concourse-worker-0", "pvc-w", 30*time.Minute, base),
		testPVC("concourse", "pvc-w", "pv-1", "", corev1.ClaimBound),
		nodePinnedPV("pv-1", "dead-node"))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	_ = probetest.MustCheck[*localPVStrandedCheck](t, p).Run(ctx)
	if m := probetest.FindMetric(t, "node_automation_localpv_stranded_stateful_pod",
		map[string]string{"namespace": "concourse", "pod": "concourse-worker-0",
			"dead_node": "dead-node"}); m != nil {
		t.Fatal("ephemeral pod must not fire the stateful gauge")
	}
}

// Deliberate maintenance gates the ephemeral heal.
func TestLocalPVStrandedMaintenanceDefers(t *testing.T) {
	base := time.Now()
	cordoned := testutil.Node("w1", corev1.ConditionTrue, nil)
	cordoned.Spec.Unschedulable = true
	cs := fake.NewSimpleClientset(cordoned,
		pendingPodForPVC("concourse", "concourse-worker-0", "pvc-w", 30*time.Minute, base),
		testPVC("concourse", "pvc-w", "pv-1", "", corev1.ClaimBound),
		nodePinnedPV("pv-1", "dead-node"))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	_ = probetest.MustCheck[*localPVStrandedCheck](t, p).Run(ctx)
	if _, err := cs.CoreV1().PersistentVolumeClaims("concourse").
		Get(ctx, "pvc-w", metav1.GetOptions{}); err != nil {
		t.Fatal("PVC deleted during maintenance")
	}
}

// Branch B: a Pending PVC on openebs-hostpath while a Ready worker
// exists → stalled gauge + provisioner pod bounce.
func TestPVCStalledProvisionerHeals(t *testing.T) {
	t.Cleanup(func() {
		pvcProvisioningStalledGauge.DeleteLabelValues("apps", "data-x", "openebs-hostpath")
		pvcProvisionerHealsTotal.DeleteLabelValues("openebs-localpv-provisioner")
	})
	base := time.Now()
	worker := testutil.Node("w1", corev1.ConditionTrue, nil)
	provPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "openebs", Name: "openebs-localpv-provisioner-abc", UID: "p1"}}
	cs := fake.NewSimpleClientset(worker, provPod,
		pendingPodForPVC("apps", "web-0", "data-x", 20*time.Minute, base),
		stalledHostpathPVC("apps", "data-x"))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*localPVStrandedCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("stalled provisioning must FAIL")
	}
	m := probetest.FindMetric(t, "node_automation_pvc_provisioning_stalled",
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
		pendingPodForPVC("apps", "web-0", "data-x", 20*time.Minute, base),
		testPVC("apps", "data-x", "", "openebs-hostpath", corev1.ClaimPending))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*localPVStrandedCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("no schedulable worker must pass quietly: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("openebs").
		Get(ctx, "openebs-localpv-provisioner-abc", metav1.GetOptions{}); err != nil {
		t.Fatal("provisioner deleted with no schedulable worker")
	}
}

// A Pending openebs-hostpath claim the provisioner never SELECTED a
// node for (no volume.kubernetes.io/selected-node annotation) is not
// wedge evidence even past the window with workers available — it
// could be fresh, queued, or waiting on scheduler gating.
func TestPVCStalledWithoutSelectedNodeIsQuiet(t *testing.T) {
	base := time.Now()
	worker := testutil.Node("w1", corev1.ConditionTrue, nil)
	provPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "openebs", Name: "openebs-localpv-provisioner-abc", UID: "p1"}}
	cs := fake.NewSimpleClientset(worker, provPod,
		pendingPodForPVC("apps", "web-0", "data-x", 20*time.Minute, base),
		testPVC("apps", "data-x", "", "openebs-hostpath", corev1.ClaimPending))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*localPVStrandedCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("unselected pending claim must pass quietly: %+v", res)
	}
	if m := probetest.FindMetric(t, "node_automation_pvc_provisioning_stalled",
		map[string]string{"namespace": "apps", "pvc": "data-x", "storageclass": "openebs-hostpath"}); m != nil {
		t.Fatal("claim without a selected node must not fire the stalled gauge")
	}
	if _, err := cs.CoreV1().Pods("openebs").
		Get(ctx, "openebs-localpv-provisioner-abc", metav1.GetOptions{}); err != nil {
		t.Fatal("provisioner deleted over an unselected claim")
	}
}

// The provisioner heal stamps
// passiontech.dev/last-localpv-provisioner-heal on the provisioner
// Deployment, and a fresh post-restart process reads it back: a
// stamp inside the 1h window defers the bounce with an empty in-RAM
// ledger — then bounces once the window clears.
func TestPVCStalledProvisionerHealStampPersisted(t *testing.T) {
	t.Cleanup(func() {
		pvcProvisioningStalledGauge.DeleteLabelValues("apps", "data-x", "openebs-hostpath")
		pvcProvisionerHealsTotal.DeleteLabelValues("openebs-localpv-provisioner")
	})
	build := func(base, healStamp time.Time) (*fake.Clientset, *probetest.Prober) {
		provPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "openebs", Name: "openebs-localpv-provisioner-abc", UID: "p1"}}
		dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
			Namespace: openebsProvisionerNS, Name: openebsProvisionerName}}
		if !healStamp.IsZero() {
			dep.Annotations = map[string]string{
				pvcProvHealAnno: healStamp.UTC().Format(time.RFC3339)}
		}
		cs := fake.NewSimpleClientset(testutil.Node("w1", corev1.ConditionTrue, nil),
			provPod, dep,
			pendingPodForPVC("apps", "web-0", "data-x", 20*time.Minute, base),
			stalledHostpathPVC("apps", "data-x"))
		p := testProberDyn(cs, probetest.OpDyn())
		p.Now = func() time.Time { return base }
		return cs, p
	}

	// Healed 10m ago (annotation only — fresh process): deferred.
	cs, p := build(time.Now(), time.Now().Add(-10*time.Minute))
	if res := probetest.MustCheck[*localPVStrandedCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("stalled provisioning must FAIL even under the persisted cooldown")
	}
	if _, err := cs.CoreV1().Pods("openebs").
		Get(ctx, "openebs-localpv-provisioner-abc", metav1.GetOptions{}); err != nil {
		t.Fatal("post-restart bounce ignored the persisted Deployment stamp")
	}

	// No stamp: the heal fires and stamps the Deployment on delivery.
	cs2, p2 := build(time.Now(), time.Time{})
	if res := probetest.MustCheck[*localPVStrandedCheck](t, p2).Run(ctx); res.Pass {
		t.Fatal("stalled provisioning must FAIL")
	}
	if _, err := cs2.CoreV1().Pods("openebs").
		Get(ctx, "openebs-localpv-provisioner-abc", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("wedged provisioner must be deleted, err=%v", err)
	}
	depGot, err := cs2.AppsV1().Deployments(openebsProvisionerNS).
		Get(ctx, openebsProvisionerName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := kube.AnnoTime(depGot, pvcProvHealAnno); !ok {
		t.Fatalf("deployment missing %s stamp", pvcProvHealAnno)
	}

	// Healed 2h ago: window cleared, the bounce resumes.
	cs3, p3 := build(time.Now(), time.Now().Add(-2*time.Hour))
	if res := probetest.MustCheck[*localPVStrandedCheck](t, p3).Run(ctx); res.Pass {
		t.Fatal("stalled provisioning must FAIL past the expired stamp")
	}
	if _, err := cs3.CoreV1().Pods("openebs").
		Get(ctx, "openebs-localpv-provisioner-abc", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("bounce did not resume after the persisted stamp expired, err=%v", err)
	}
}
