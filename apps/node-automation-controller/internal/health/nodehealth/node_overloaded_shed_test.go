// node_overloaded_shed_test.go — unit tests for sustained NodeOverloaded
// pre-cordon, auto-uncordon, and guarded stateless Deployment pod shedding.
package nodehealth

import (
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

func makeDeployChain(ns, deployName string, readyReplicas int32, nodeName, podName string) (*appsv1.Deployment, *appsv1.ReplicaSet, *corev1.Pod) {
	depUID := types.UID("dep-" + ns + "-" + deployName)
	rsUID := types.UID("rs-" + ns + "-" + deployName)
	rsName := deployName + "-rs"
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: deployName, Namespace: ns, UID: depUID},
		Status:     appsv1.DeploymentStatus{ReadyReplicas: readyReplicas},
	}
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      rsName,
			Namespace: ns,
			UID:       rsUID,
			OwnerReferences: []metav1.OwnerReference{{
				Kind:       "Deployment",
				Name:       deployName,
				UID:        depUID,
				Controller: ptr.To(true),
			}},
		},
	}
	pod := probetest.PodWithPhase(ns, podName, corev1.PodRunning, true, 30*time.Minute)
	pod.UID = types.UID("pod-" + ns + "-" + podName)
	pod.Spec.NodeName = nodeName
	pod.Labels = map[string]string{"app": deployName}
	pod.OwnerReferences = []metav1.OwnerReference{{
		Kind:       "ReplicaSet",
		Name:       rsName,
		UID:        rsUID,
		Controller: ptr.To(true),
	}}
	return dep, rs, pod
}

func captureEvictions(cs *fake.Clientset) *[]string {
	var evicted []string
	cs.PrependReactor("create", "pods", func(a ktesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() != "eviction" {
			return false, nil, nil
		}
		ca := a.(ktesting.CreateAction)
		ev := ca.GetObject().(*policyv1.Eviction)
		evicted = append(evicted, ev.Namespace+"/"+ev.Name)
		return true, ev, nil
	})
	return &evicted
}

func TestNodeOverloadedTransientDoesNotCordonOrEvict(t *testing.T) {
	dep, rs, pod := makeDeployChain("apps", "web", 3, "w-ov", "web-1")
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w-ov", nodecond.NodeOverloaded, 10*time.Minute, false),
		probetest.ReadyWorkerNode("w-ok", "", 0, false),
		dep, rs, pod,
	)
	evicted := captureEvictions(cs)
	p := testProberDyn(cs, probetest.OpDyn())

	res := probetest.MustCheck[*nodeHangCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
	if !res.Pass {
		t.Fatalf("transient NodeOverloaded (<15m) must pass: %+v", res)
	}
	n, _ := cs.CoreV1().Nodes().Get(ctx, "w-ov", metav1.GetOptions{})
	if n.Spec.Unschedulable {
		t.Fatal("transient NodeOverloaded cordoned too early")
	}
	if len(*evicted) != 0 {
		t.Fatalf("transient NodeOverloaded evicted pods: %v", *evicted)
	}
}

func TestNodeOverloadedSustainedCordonsEvictsOneAndRespectsExclusionsAndCooldown(t *testing.T) {
	testutil.CleanupMetric(t, nodeHangCordonsTotal, "w-ov")
	testutil.CleanupMetric(t, nodeHangUncordonsTotal, "w-ov")

	// Eligible Deployment pods (2 eligible -> only 1 evicted per sweep).
	depA, rsA, podA := makeDeployChain("apps", "api", 3, "w-ov", "api-1")
	depB, rsB, podB := makeDeployChain("apps", "worker", 2, "w-ov", "worker-1")

	// Ineligible pods on the same overloaded node:
	// 1. Single-replica Deployment (readyReplicas=1).
	depSingle, rsSingle, podSingle := makeDeployChain("apps", "singleton", 1, "w-ov", "singleton-1")
	// 2. Critical namespaces (kube-system, cilium-secrets, linkerd-viz, etc.).
	depSys, rsSys, podSys := makeDeployChain("kube-system", "coredns", 3, "w-ov", "coredns-1")
	depCilium, rsCilium, podCilium := makeDeployChain("cilium-secrets", "helper", 2, "w-ov", "helper-1")
	// 3. Deployment pod with PVC volume.
	depPVC, rsPVC, podPVC := makeDeployChain("apps", "with-pvc", 2, "w-ov", "with-pvc-1")
	podPVC.Spec.Volumes = []corev1.Volume{{
		Name:         "data",
		VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "pvc-1"}},
	}}
	// 4. System priority class.
	depPrio, rsPrio, podPrio := makeDeployChain("apps", "crit-prio", 2, "w-ov", "crit-prio-1")
	podPrio.Spec.PriorityClassName = "system-cluster-critical"
	// 5. Opt-out annotations.
	depNoCA, rsNoCA, podNoCA := makeDeployChain("apps", "no-ca", 2, "w-ov", "no-ca-1")
	podNoCA.Annotations = map[string]string{annoSafeToEvict: "false"}
	depOptOut, rsOptOut, podOptOut := makeDeployChain("apps", "no-ov", 2, "w-ov", "no-ov-1")
	podOptOut.Annotations = map[string]string{annoNoOverloadEvict: "true"}
	// 6. StatefulSet, DaemonSet, standalone pods.
	stsPod := probetest.PodWithPhase("apps", "db-0", corev1.PodRunning, true, 30*time.Minute)
	stsPod.Spec.NodeName = "w-ov"
	stsPod.OwnerReferences = []metav1.OwnerReference{{Kind: "StatefulSet", Name: "db", UID: "sts-1", Controller: ptr.To(true)}}
	dsPod := probetest.PodWithPhase("apps", "agent-x", corev1.PodRunning, true, 30*time.Minute)
	dsPod.Spec.NodeName = "w-ov"
	dsPod.OwnerReferences = []metav1.OwnerReference{{Kind: "DaemonSet", Name: "agent", UID: "ds-1", Controller: ptr.To(true)}}
	barePod := probetest.PodWithPhase("apps", "bare-1", corev1.PodRunning, true, 30*time.Minute)
	barePod.Spec.NodeName = "w-ov"

	now := time.Now()
	wOv := probetest.ReadyWorkerNode("w-ov", nodecond.NodeOverloaded, 20*time.Minute, false)
	wOk := probetest.ReadyWorkerNode("w-ok", "", 0, false)

	cs := fake.NewSimpleClientset(
		wOv, wOk,
		depA, rsA, podA,
		depB, rsB, podB,
		depSingle, rsSingle, podSingle,
		depSys, rsSys, podSys,
		depCilium, rsCilium, podCilium,
		depPVC, rsPVC, podPVC,
		depPrio, rsPrio, podPrio,
		depNoCA, rsNoCA, podNoCA,
		depOptOut, rsOptOut, podOptOut,
		stsPod, dsPod, barePod,
	)
	evicted := captureEvictions(cs)
	p := testProberDyn(cs, probetest.OpDyn())
	probetest.FreezeNow(p.Deps, now)

	chk := probetest.MustCheck[*nodeHangCheck](t, p)
	res := chk.Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass {
		t.Fatal("sustained NodeOverloaded (>=15m) must FAIL the check")
	}

	// Node must be cordoned & stamped.
	gotNode, _ := cs.CoreV1().Nodes().Get(ctx, "w-ov", metav1.GetOptions{})
	if !gotNode.Spec.Unschedulable || gotNode.Annotations[nodeHangPreCordonAnno] != nodeHangPreCordonValue {
		t.Fatalf("w-ov not cordoned+stamped: unsched=%v annos=%v", gotNode.Spec.Unschedulable, gotNode.Annotations)
	}

	// Exactly 1 eligible pod evicted (alphabetically first: apps/api-1).
	if len(*evicted) != 1 || (*evicted)[0] != "apps/api-1" {
		t.Fatalf("evicted = %v, want [apps/api-1]", *evicted)
	}

	// Inside 10m cooldown (5m later): no second eviction.
	probetest.FreezeNow(p.Deps, now.Add(5*time.Minute))
	// Refresh heartbeat so condition stays live at now+5m.
	for i := range gotNode.Status.Conditions {
		if gotNode.Status.Conditions[i].Type == nodecond.NodeOverloaded {
			gotNode.Status.Conditions[i].LastHeartbeatTime = metav1.NewTime(now.Add(5 * time.Minute))
		}
	}
	_, _ = cs.CoreV1().Nodes().UpdateStatus(ctx, gotNode, metav1.UpdateOptions{})
	_ = chk.Run(probetest.SweepCtx(ctx, p.Deps))
	if len(*evicted) != 1 {
		t.Fatalf("evicted inside 10m cooldown: %v", *evicted)
	}

	// Clearing NodeOverloaded to False auto-uncordons w-ov cleanly.
	for i := range gotNode.Status.Conditions {
		if gotNode.Status.Conditions[i].Type == nodecond.NodeOverloaded {
			gotNode.Status.Conditions[i].Status = corev1.ConditionFalse
			gotNode.Status.Conditions[i].LastTransitionTime = metav1.NewTime(now.Add(12 * time.Minute))
			gotNode.Status.Conditions[i].LastHeartbeatTime = metav1.NewTime(now.Add(12 * time.Minute))
		}
	}
	_, _ = cs.CoreV1().Nodes().UpdateStatus(ctx, gotNode, metav1.UpdateOptions{})
	probetest.FreezeNow(p.Deps, now.Add(12*time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("cleared NodeOverloaded must pass: %+v", res)
	}
	cleared, _ := cs.CoreV1().Nodes().Get(ctx, "w-ov", metav1.GetOptions{})
	if cleared.Spec.Unschedulable {
		t.Fatal("w-ov stayed cordoned after NodeOverloaded cleared")
	}
	if _, ok := cleared.Annotations[nodeHangPreCordonAnno]; ok {
		t.Fatal("pre-cordon stamp not removed on auto-uncordon")
	}
}

func TestNodeOverloadedShedRespectsClusterHeadroomAndPDB(t *testing.T) {
	t.Run("no healthy receiver worker skips shedding", func(t *testing.T) {
		testutil.CleanupMetric(t, nodeHangCordonsTotal, "w-ov")
		dep, rs, pod := makeDeployChain("apps", "web", 2, "w-ov", "web-1")
		// Only other worker is already cordoned -> zero healthy receiver headroom.
		cs := fake.NewSimpleClientset(
			probetest.ReadyWorkerNode("w-ov", nodecond.NodeOverloaded, 20*time.Minute, false),
			probetest.ReadyWorkerNode("w-cordoned", "", 0, true),
			dep, rs, pod,
		)
		evicted := captureEvictions(cs)
		p := testProberDyn(cs, probetest.OpDyn())
		_ = probetest.MustCheck[*nodeHangCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
		if len(*evicted) != 0 {
			t.Fatalf("evicted despite zero healthy receiver workers: %v", *evicted)
		}
	})

	t.Run("skips PDB-blocked pod and evicts next eligible pod", func(t *testing.T) {
		testutil.CleanupMetric(t, nodeHangCordonsTotal, "w-ov")
		depA, rsA, podA := makeDeployChain("apps", "aaa-blocked", 2, "w-ov", "aaa-1")
		depB, rsB, podB := makeDeployChain("apps", "bbb-free", 2, "w-ov", "bbb-1")
		pdb := &policyv1.PodDisruptionBudget{
			ObjectMeta: metav1.ObjectMeta{Name: "aaa-pdb", Namespace: "apps"},
			Spec: policyv1.PodDisruptionBudgetSpec{
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "aaa-blocked"}},
			},
			Status: policyv1.PodDisruptionBudgetStatus{DisruptionsAllowed: 0},
		}
		cs := fake.NewSimpleClientset(
			probetest.ReadyWorkerNode("w-ov", nodecond.NodeOverloaded, 20*time.Minute, false),
			probetest.ReadyWorkerNode("w-ok", "", 0, false),
			depA, rsA, podA,
			depB, rsB, podB,
			pdb,
		)
		evicted := captureEvictions(cs)
		p := testProberDyn(cs, probetest.OpDyn())
		_ = probetest.MustCheck[*nodeHangCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
		if len(*evicted) != 1 || (*evicted)[0] != "apps/bbb-1" {
			t.Fatalf("evicted = %v, want [apps/bbb-1] (skipping PDB-blocked aaa-1)", *evicted)
		}
	})

	t.Run("NODE_OVERLOADED_EVICT_ENABLED=false cordons but does not evict", func(t *testing.T) {
		t.Setenv("NODE_OVERLOADED_EVICT_ENABLED", "false")
		testutil.CleanupMetric(t, nodeHangCordonsTotal, "w-ov")
		dep, rs, pod := makeDeployChain("apps", "web", 2, "w-ov", "web-1")
		cs := fake.NewSimpleClientset(
			probetest.ReadyWorkerNode("w-ov", nodecond.NodeOverloaded, 20*time.Minute, false),
			probetest.ReadyWorkerNode("w-ok", "", 0, false),
			dep, rs, pod,
		)
		evicted := captureEvictions(cs)
		p := testProberDyn(cs, probetest.OpDyn())
		_ = probetest.MustCheck[*nodeHangCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
		n, _ := cs.CoreV1().Nodes().Get(ctx, "w-ov", metav1.GetOptions{})
		if !n.Spec.Unschedulable {
			t.Fatal("w-ov must still be cordoned when NODE_OVERLOADED_EVICT_ENABLED=false")
		}
		if len(*evicted) != 0 {
			t.Fatalf("evicted while NODE_OVERLOADED_EVICT_ENABLED=false: %v", *evicted)
		}
	})

	t.Run("uncordoned overloaded worker (e.g. skipped by 35% cordon cap) does not evict", func(t *testing.T) {
		testutil.CleanupMetric(t, nodeHangCordonsTotal, "w-ov")
		dep, rs, pod := makeDeployChain("apps", "web", 2, "w-ov", "web-1")
		// 3 workers total with 1 already cordoned -> cordoning w-ov would reach 2/3 (>35% cap),
		// so cordonLatched leaves w-ov schedulable while w-ok remains a healthy receiver.
		cs := fake.NewSimpleClientset(
			probetest.ReadyWorkerNode("w-cordoned", "", 0, true),
			probetest.ReadyWorkerNode("w-ov", nodecond.NodeOverloaded, 20*time.Minute, false),
			probetest.ReadyWorkerNode("w-ok", "", 0, false),
			dep, rs, pod,
		)
		evicted := captureEvictions(cs)
		p := testProberDyn(cs, probetest.OpDyn())
		_ = probetest.MustCheck[*nodeHangCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
		n, _ := cs.CoreV1().Nodes().Get(ctx, "w-ov", metav1.GetOptions{})
		if n.Spec.Unschedulable {
			t.Fatal("w-ov must remain uncordoned under 35% fleet cap")
		}
		if len(*evicted) != 0 {
			t.Fatalf("evicted from uncordoned overloaded worker: %v", *evicted)
		}
	})
}

func TestNodeOverloadedShedPrioritizesColocatedHADeployment(t *testing.T) {
	testutil.CleanupMetric(t, nodeHangCordonsTotal, "w-ov")

	// Alphabetically earlier Deployment is well-spread (1 pod on w-ov, 1 pod on w-ok).
	depAlpha, rsAlpha, podAlphaOv := makeDeployChain("apps", "alpha", 2, "w-ov", "alpha-1")
	_, _, podAlphaOk := makeDeployChain("apps", "alpha", 2, "w-ok", "alpha-2")

	// Alphabetically later HA Deployment is 100% co-located on w-ov (2/2 Ready pods on w-ov).
	depZeta, rsZeta, podZeta1 := makeDeployChain("zeta", "argocd-server", 2, "w-ov", "argocd-server-1")
	_, _, podZeta2 := makeDeployChain("zeta", "argocd-server", 2, "w-ov", "argocd-server-2")

	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w-ov", nodecond.NodeOverloaded, 20*time.Minute, false),
		probetest.ReadyWorkerNode("w-ok", "", 0, false),
		depAlpha, rsAlpha, podAlphaOv, podAlphaOk,
		depZeta, rsZeta, podZeta1, podZeta2,
	)
	evicted := captureEvictions(cs)
	p := testProberDyn(cs, probetest.OpDyn())
	_ = probetest.MustCheck[*nodeHangCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))

	if len(*evicted) != 1 || (*evicted)[0] != "zeta/argocd-server-1" {
		t.Fatalf("evicted = %v, want [zeta/argocd-server-1] (100%% co-located HA Deployment prioritized)", *evicted)
	}
}
