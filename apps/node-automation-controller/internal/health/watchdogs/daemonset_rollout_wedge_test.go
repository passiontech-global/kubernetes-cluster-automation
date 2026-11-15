package watchdogs

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

// dsWedgeFixture builds a DaemonSet mid-wedged-rollout plus the pod
// and node shapes the test needs.
func dsWedgeFixture(t *testing.T, now time.Time,
	ds *appsv1.DaemonSet, objs ...runtime.Object) (*fake.Clientset, *dsRolloutWedgeCheck) {

	t.Helper()
	all := []runtime.Object{ds}
	all = append(all, objs...)
	cs := fake.NewSimpleClientset(all...)
	d := probetest.NewDeps(cs, probetest.OpDyn())
	probetest.FreezeNow(d, now)
	return cs, &dsRolloutWedgeCheck{Deps: d, healEnabled: true}
}

// wedgedDS builds a RollingUpdate DaemonSet pinned short of desired
// with the unavailable count at the maxUnavailable budget.
func wedgedDS(ns, name string) *appsv1.DaemonSet {
	mu := intstr.FromInt(1)
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}},
			UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
				Type: appsv1.RollingUpdateDaemonSetStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDaemonSet{
					MaxUnavailable: &mu,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
			},
		},
		Status: appsv1.DaemonSetStatus{
			DesiredNumberScheduled: 3,
			UpdatedNumberScheduled: 1,
			NumberUnavailable:      1,
			NumberReady:            2,
		},
	}
}

// dsPod builds a DaemonSet-owned pod on nodeName with the given
// state: terminating, unready+waitReason, or ready.
func dsPod(ns, dsName, name, node string, terminating bool,
	waitReason string, ready bool) *corev1.Pod {

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name,
			Labels: map[string]string{"app": dsName},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "DaemonSet",
				Name: dsName, Controller: ptr.To(true),
			}},
		},
		Spec:   corev1.PodSpec{NodeName: node},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	if terminating {
		now := metav1.Now()
		pod.DeletionTimestamp = &now
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

// dsNode builds a node census row. A cordoned node WITHOUT the
// unschedulable taint reads as an ACTIVE cordon (age unverifiable —
// fail closed) which holds the maintenance mutex and defers every
// heal; dsStaticCordonedNode stamps the taint 2h old so the cordon
// reads as deliberate static state and the heal gate opens.
func dsNode(name string, ready, cordoned bool) *corev1.Node {
	return dsNodeAt(name, ready, cordoned, time.Time{})
}

func dsStaticCordonedNode(name string) *corev1.Node {
	return dsNodeAt(name, true, true, time.Now().Add(-2*time.Hour))
}

func dsNodeAt(name string, ready, cordoned bool, taintAge time.Time) *corev1.Node {
	st := corev1.ConditionFalse
	if ready {
		st = corev1.ConditionTrue
	}
	n := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.NodeSpec{Unschedulable: cordoned},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{
			Type: corev1.NodeReady, Status: st,
		}}},
	}
	if cordoned && !taintAge.IsZero() {
		ta := metav1.NewTime(taintAge)
		n.Spec.Taints = []corev1.Taint{{
			Key:       "node.kubernetes.io/unschedulable",
			Effect:    corev1.TaintEffectNoSchedule,
			TimeAdded: &ta,
		}}
	}
	return n
}

// A Terminating pod on a NotReady node pins the budget: first sweep
// arms the 30m window, the aged signature flags and deletes the pod.
func TestDaemonSetRolloutWedgeHealsTerminatingPod(t *testing.T) {
	now := time.Now()
	ds := wedgedDS("kube-system", "log-agent")
	stuck := dsPod("kube-system", "log-agent", "log-agent-x1", "node-dead", true, "", false)
	cs, chk := dsWedgeFixture(t, now, ds,
		stuck, dsNode("node-dead", false, false), dsNode("node-1", true, false))

	chk.Run(probetest.SweepCtx(ctx))
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, "log-agent-x1", metav1.GetOptions{}); err == nil {
		// still inside window — pod must exist
	} else {
		t.Fatalf("pod deleted inside window: %v", err)
	}

	probetest.FreezeNow(chk.Deps, now.Add(31*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatalf("aged wedge must flag: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, "log-agent-x1", metav1.GetOptions{}); err == nil {
		t.Fatal("terminating pod on dead node was not deleted")
	}
	if got := testutil.ToFloat64(dsRolloutWedgedGauge.WithLabelValues("kube-system", "log-agent")); got != 1 {
		t.Fatalf("wedge gauge = %v, want 1", got)
	}
}

// An unready error-state pod on a cordoned node is the second wedge
// shape: no replacement can schedule, the budget stays pinned.
func TestDaemonSetRolloutWedgeHealsCordonedPod(t *testing.T) {
	now := time.Now()
	ds := wedgedDS("kube-system", "log-agent")
	stuck := dsPod("kube-system", "log-agent", "log-agent-x2", "node-cordoned",
		false, "ImagePullBackOff", false)
	cs, chk := dsWedgeFixture(t, now, ds,
		stuck, dsStaticCordonedNode("node-cordoned"), dsNode("node-1", true, false))

	chk.Run(probetest.SweepCtx(ctx))
	probetest.FreezeNow(chk.Deps, now.Add(31*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatalf("cordoned-node wedge must flag: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, "log-agent-x2", metav1.GetOptions{}); err == nil {
		t.Fatal("unready pod on cordoned node was not deleted")
	}
}

// Negative shapes: a settled roll never flags; a wedge whose only
// unready pod sits on a HEALTHY schedulable node still flags the
// gauge (the budget pin is real) but deletes nothing — there is no
// dead-node or cordoned-node blocker to act on.
func TestDaemonSetRolloutWedgeLeavesHealthy(t *testing.T) {
	now := time.Now()

	// Settled DS — updated == desired.
	settled := wedgedDS("kube-system", "settled-ds")
	settled.Status.UpdatedNumberScheduled = 3
	settled.Status.NumberUnavailable = 0
	// Wedge-shaped DS but the only bad pod sits on a healthy node.
	blocked := wedgedDS("kube-system", "blocked-ds")
	pod := dsPod("kube-system", "blocked-ds", "blocked-ds-a", "node-1",
		false, "CrashLoopBackOff", false)
	cs, chk := dsWedgeFixture(t, now, settled, blocked, pod,
		dsNode("node-1", true, false))

	chk.Run(probetest.SweepCtx(ctx)) // arm the 30m window
	probetest.FreezeNow(chk.Deps, now.Add(time.Hour))
	res := chk.Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatalf("budget-pinned DS must flag even without an actionable pod: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, "blocked-ds-a", metav1.GetOptions{}); err != nil {
		t.Fatalf("pod on healthy node was deleted: %v", err)
	}
	if got := testutil.ToFloat64(dsRolloutWedgedGauge.WithLabelValues("kube-system", "settled-ds")); got != 0 {
		t.Fatalf("settled DS flagged: gauge=%v", got)
	}
}

// A Terminating pod on a dead node that CLAIMS a PVC must never be
// force-deleted: grace=0 drops the API object while the old kubelet
// may still hold the RWO volume — the replacement would double-mount.
// The wedge still flags; the pod survives for a human.
func TestDaemonSetRolloutWedgeRefusesPVCForceDelete(t *testing.T) {
	now := time.Now()
	ds := wedgedDS("kube-system", "log-agent")
	stuck := dsPod("kube-system", "log-agent", "log-agent-pvc", "node-dead",
		true, "", false)
	stuck.Spec.Volumes = []corev1.Volume{{
		Name: "data",
		VolumeSource: corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: "log-agent-data",
			},
		},
	}}
	stuck.Spec.Containers = []corev1.Container{{
		Name:  "c",
		Image: "img",
		VolumeMounts: []corev1.VolumeMount{{
			Name:      "data",
			MountPath: "/data",
		}},
	}}
	cs, chk := dsWedgeFixture(t, now, ds,
		stuck, dsNode("node-dead", false, false), dsNode("node-1", true, false))

	chk.Run(probetest.SweepCtx(ctx))
	probetest.FreezeNow(chk.Deps, now.Add(31*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatalf("PVC-pinned wedge must still flag: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, "log-agent-pvc", metav1.GetOptions{}); err != nil {
		t.Fatalf("PVC-claiming pod was force-deleted: %v", err)
	}
}

// healEnabled=false detects without deleting.
func TestDaemonSetRolloutWedgeReportOnly(t *testing.T) {
	now := time.Now()
	ds := wedgedDS("kube-system", "log-agent")
	stuck := dsPod("kube-system", "log-agent", "log-agent-x1", "node-dead", true, "", false)
	cs := fake.NewSimpleClientset(ds, stuck, dsNode("node-dead", false, false))
	d := probetest.NewDeps(cs, probetest.OpDyn())
	probetest.FreezeNow(d, now)
	chk := &dsRolloutWedgeCheck{Deps: d, healEnabled: false}

	chk.Run(probetest.SweepCtx(ctx))
	probetest.FreezeNow(d, now.Add(31*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx))
	if res.Pass {
		t.Fatalf("report-only wedge must flag: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, "log-agent-x1", metav1.GetOptions{}); err != nil {
		t.Fatalf("report-only mode deleted the pod: %v", err)
	}
}
