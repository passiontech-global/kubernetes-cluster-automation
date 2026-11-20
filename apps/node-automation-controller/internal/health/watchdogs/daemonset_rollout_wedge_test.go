package watchdogs

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// dsWedgeFixture builds a DaemonSet mid-wedged-rollout plus the pod
// and node shapes the test needs.
func dsWedgeFixture(t *testing.T, now time.Time,
	ds *appsv1.DaemonSet, objs ...runtime.Object) (*fake.Clientset, *dsRolloutWedgeCheck) {

	t.Helper()
	all := []runtime.Object{ds}
	all = append(all, objs...)
	// A real DaemonSet always has a ControllerRevision for its target
	// template. Fixtures that exercise another CR source pass their own;
	// otherwise seed one so the target revision is RESOLVABLE — an
	// unresolvable target must fail closed (no heal), not silently
	// classify every pod as old.
	hasCR := false
	for _, o := range objs {
		if _, ok := o.(*appsv1.ControllerRevision); ok {
			hasCR = true
			break
		}
	}
	if !hasCR {
		all = append(all, dsControllerRevision(ds, "rev-new", 1))
	}
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
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name,
			Generation: 1},
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
			ObservedGeneration:     1,
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
			Labels: map[string]string{
				"app":                      dsName,
				"controller-revision-hash": "rev-old",
				"pod-template-generation":  "0",
			},
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

// dsFencedNode builds a NotReady node carrying the explicit
// out-of-service fence — the ONLY NotReady shape a blocking pod may
// be force-deleted on. A plain NotReady node is deliberately not
// enough (its kubelet may come back).
func dsFencedNode(name string) *corev1.Node {
	n := dsNode(name, false, false)
	n.Spec.Taints = []corev1.Taint{{
		Key:    kube.TaintNodeOutOfService,
		Effect: corev1.TaintEffectNoSchedule,
	}}
	return n
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

// dsOnTargetRevision stamps a pod with the metadata the DaemonSet
// controller puts on a pod created from the DS's current template:
// pod-template-generation == ds.Generation plus the target's
// controller-revision-hash. This is the ONLY way a test may mark a pod
// "new" — PodReadyCond is deliberately never consulted by the check.
func dsOnTargetRevision(ds *appsv1.DaemonSet, pod *corev1.Pod,
	revision string) {
	pod.Labels["pod-template-generation"] = strconv.FormatInt(ds.Generation, 10)
	pod.Labels["controller-revision-hash"] = revision
}

// dsControllerRevision builds a ControllerRevision owned by ds; its
// controller-revision-hash label (or Name minus "<ds.Name>-") is what
// the DS controller stamps into pods' controller-revision-hash.
func dsControllerRevision(ds *appsv1.DaemonSet, name string,
	revision int64) *appsv1.ControllerRevision {
	return &appsv1.ControllerRevision{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ds.Namespace, Name: name,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "DaemonSet",
				Name: ds.Name, Controller: ptr.To(true),
			}},
		},
		Revision: revision,
	}
}

// A Terminating pod on a NotReady node pins the budget: first sweep
// arms the 30m window, the aged signature flags and deletes the pod.
func TestDaemonSetRolloutWedgeHealsTerminatingPod(t *testing.T) {
	now := time.Now()
	ds := wedgedDS("kube-system", "log-agent")
	stuck := dsPod("kube-system", "log-agent", "log-agent-x1", "node-dead", true, "", false)
	cs, chk := dsWedgeFixture(t, now, ds,
		stuck, dsFencedNode("node-dead"), dsNode("node-1", true, false))

	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, "log-agent-x1", metav1.GetOptions{}); err == nil {
		// still inside window — pod must exist
	} else {
		t.Fatalf("pod deleted inside window: %v", err)
	}

	probetest.FreezeNow(chk.Deps, now.Add(31*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
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

// A plain NotReady node is NOT a fence: its kubelet may return and
// still hold a RWO volume. Force-delete is forbidden; the wedge
// still flags and the pod survives for a human.
func TestDaemonSetRolloutWedgeRefusesForceDeleteOnPlainNotReady(t *testing.T) {
	now := time.Now()
	ds := wedgedDS("kube-system", "log-agent")
	stuck := dsPod("kube-system", "log-agent", "log-agent-x1", "node-unready", true, "", false)
	cs, chk := dsWedgeFixture(t, now, ds,
		stuck, dsNode("node-unready", false, false), dsNode("node-1", true, false))

	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	probetest.FreezeNow(chk.Deps, now.Add(31*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatalf("wedge must still flag: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, "log-agent-x1", metav1.GetOptions{}); err != nil {
		t.Fatalf("pod on plain NotReady node was force-deleted: %v", err)
	}
}

// A terminating pod already on the NEW revision cannot advance the
// roll when recreated — deleting it is pure churn. The target revision
// comes from pod-template-generation metadata (NOT from which pod is
// Ready); only a blocker on a DIFFERENT (old) revision is actionable.
func TestDaemonSetRolloutWedgeSkipsPodOnNewRevision(t *testing.T) {
	now := time.Now()
	ds := wedgedDS("kube-system", "log-agent")
	stuck := dsPod("kube-system", "log-agent", "log-agent-x1", "node-dead", true, "", false)
	stuck.Labels["controller-revision-hash"] = "rev-new"
	ready := dsPod("kube-system", "log-agent", "log-agent-y1", "node-1", false, "", true)
	dsOnTargetRevision(ds, ready, "rev-new")
	cs, chk := dsWedgeFixture(t, now, ds,
		stuck, ready, dsFencedNode("node-dead"), dsNode("node-1", true, false))

	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	probetest.FreezeNow(chk.Deps, now.Add(31*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatalf("wedge must still flag: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, "log-agent-x1", metav1.GetOptions{}); err != nil {
		t.Fatalf("pod on new revision was force-deleted: %v", err)
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

	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	probetest.FreezeNow(chk.Deps, now.Add(31*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
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

	chk.Run(probetest.SweepCtx(ctx, chk.Deps)) // arm the 30m window
	probetest.FreezeNow(chk.Deps, now.Add(time.Hour))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
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
		stuck, dsFencedNode("node-dead"), dsNode("node-1", true, false))

	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	probetest.FreezeNow(chk.Deps, now.Add(31*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
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

	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	probetest.FreezeNow(d, now.Add(31*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatalf("report-only wedge must flag: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, "log-agent-x1", metav1.GetOptions{}); err != nil {
		t.Fatalf("report-only mode deleted the pod: %v", err)
	}
}

// The target revision must come from DS/pod metadata, never from
// PodReadyCond — a Ready old pod must not disable healing, and an
// unready new pod must not be read as old.
func TestDaemonSetRolloutWedgeRevisionFromMetadata(t *testing.T) {
	now := time.Now()

	t.Run("roll-not-started-makes-every-pod-old", func(t *testing.T) {
		ds := wedgedDS("kube-system", "log-agent")
		ds.Status.UpdatedNumberScheduled = 0
		ready := dsPod("kube-system", "log-agent", "log-agent-old", "node-1",
			false, "", true)
		dsOnTargetRevision(ds, ready, "rev-new") // deliberately misleading
		_, chk := dsWedgeFixture(t, now, ds, ready)
		got, known := chk.newRevisionHashes(ctx, ds, []*corev1.Pod{ready})
		if !known || len(got) != 0 {
			t.Fatalf("UpdatedNumberScheduled==0 must yield a known empty target, got (%v,%v)", got, known)
		}
	})

	t.Run("pod-template-generation-defines-target", func(t *testing.T) {
		ds := wedgedDS("kube-system", "log-agent")
		newPod := dsPod("kube-system", "log-agent", "log-agent-new", "node-2",
			false, "ImagePullBackOff", false) // not Ready — must not matter
		dsOnTargetRevision(ds, newPod, "rev-new")
		oldPod := dsPod("kube-system", "log-agent", "log-agent-old", "node-1",
			false, "", true) // Ready — must not matter either
		oldPod.Labels["pod-template-generation"] = "0"
		oldPod.Labels["controller-revision-hash"] = "rev-old"
		_, chk := dsWedgeFixture(t, now, ds)
		got, known := chk.newRevisionHashes(ctx, ds, []*corev1.Pod{newPod, oldPod})
		if !known || !got["rev-new"] || len(got) != 1 {
			t.Fatalf("target = %v, want exactly {rev-new}", got)
		}
	})

	t.Run("unobserved-generation-uses-max-controllerrevision", func(t *testing.T) {
		ds := wedgedDS("kube-system", "log-agent")
		ds.Status.ObservedGeneration = 0 // generation 1 not observed yet
		ready := dsPod("kube-system", "log-agent", "log-agent-new", "node-2",
			false, "", true)
		dsOnTargetRevision(ds, ready, "rev-new") // must be ignored
		other := wedgedDS("kube-system", "other-ds")
		_, chk := dsWedgeFixture(t, now, ds, ready,
			dsControllerRevision(ds, "log-agent-r1", 1),
			dsControllerRevision(ds, "log-agent-r7", 7),
			dsControllerRevision(other, "other-r99", 99)) // not ours
		got, known := chk.newRevisionHashes(ctx, ds, []*corev1.Pod{ready})
		if !known || !got["r7"] || len(got) != 1 {
			t.Fatalf("target = %v, want the largest owned .Revision hash (r7)", got)
		}
	})

	t.Run("controller-revision-hash-label-defines-target", func(t *testing.T) {
		ds := wedgedDS("kube-system", "log-agent")
		ds.Status.ObservedGeneration = 0
		cr := dsControllerRevision(ds, "log-agent-7d9f8c", 7)
		cr.Labels = map[string]string{"controller-revision-hash": "7d9f8c"}
		_, chk := dsWedgeFixture(t, now, ds, cr)
		got, known := chk.newRevisionHashes(ctx, ds, nil)
		if !known || !got["7d9f8c"] || len(got) != 1 {
			t.Fatalf("target = %v, want {7d9f8c}", got)
		}
	})
}

// Mixed-revision multi-node wedge: a Ready rev-old pod, a CrashLoop
// rev-old pod on a cordoned node and an ImagePullBackOff rev-new pod on
// another cordoned node. The rev-old CrashLoop pod is the blocker; the
// rev-new pod must never be deleted even though it is equally unready
// on a cordoned node. Inferring the target from Ready pods used to
// treat rev-old as "new" (paralysing the heal) or rev-new as "old"
// (deleting it).
func TestDaemonSetRolloutWedgeMultiNodeMixedRevisions(t *testing.T) {
	now := time.Now()
	ds := wedgedDS("kube-system", "log-agent")

	readyOld := dsPod("kube-system", "log-agent", "log-agent-a", "node-1",
		false, "", true)
	readyOld.Labels["controller-revision-hash"] = "rev-old"
	readyOld.Labels["pod-template-generation"] = "0"

	crashOld := dsPod("kube-system", "log-agent", "log-agent-b",
		"node-cordoned-old", false, "CrashLoopBackOff", false)
	crashOld.Labels["controller-revision-hash"] = "rev-old"
	crashOld.Labels["pod-template-generation"] = "0"

	imagePullNew := dsPod("kube-system", "log-agent", "log-agent-c",
		"node-cordoned-new", false, "ImagePullBackOff", false)
	dsOnTargetRevision(ds, imagePullNew, "rev-new")

	cs, chk := dsWedgeFixture(t, now, ds, readyOld, crashOld, imagePullNew,
		dsNode("node-1", true, false),
		dsStaticCordonedNode("node-cordoned-old"),
		dsStaticCordonedNode("node-cordoned-new"),
		dsControllerRevision(ds, "log-agent-r2", 2))

	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	probetest.FreezeNow(chk.Deps, now.Add(31*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatalf("mixed-revision wedge must flag: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx,
		"log-agent-b", metav1.GetOptions{}); err == nil {
		t.Fatal("old-revision CrashLoop blocker on cordoned node was not deleted")
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx,
		"log-agent-c", metav1.GetOptions{}); err != nil {
		t.Fatalf("new-revision ImagePullBackOff pod was wrongly deleted: %v", err)
	}
}

// If neither pod-template-generation nor ControllerRevision can name
// the target revision, "no hashes" is NOT "all pods are old" — the
// heal must fail closed instead of force-deleting a new-revision pod.
func TestDaemonSetRolloutWedgeUnknownRevisionFailsClosed(t *testing.T) {
	now := time.Now()
	ds := wedgedDS("kube-system", "log-agent")
	blocker := dsPod("kube-system", "log-agent", "log-agent-new", "node-cordoned",
		false, "ImagePullBackOff", false)
	blocker.Labels["controller-revision-hash"] = "rev-new"
	blocker.Labels["pod-template-generation"] = "0" // not the current generation

	cs, chk := dsWedgeFixture(t, now, ds, blocker,
		dsStaticCordonedNode("node-cordoned"))
	cs.PrependReactor("list", "controllerrevisions", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(
			schema.GroupResource{Group: "apps", Resource: "controllerrevisions"}, "",
			errors.New("forbidden"))
	})
	_, known := chk.newRevisionHashes(ctx, ds, []*corev1.Pod{blocker})
	if known {
		t.Fatal("revision must be UNKNOWN when both metadata sources fail")
	}

	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	probetest.FreezeNow(chk.Deps, now.Add(31*time.Minute))
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx,
		"log-agent-new", metav1.GetOptions{}); err != nil {
		t.Fatalf("pod must survive when target revision is unresolvable: %v", err)
	}
}

// An unscheduled (NodeName=="") pod that is Terminating has no node to
// be vanished/fenced on. Looking up nodes[""] must never read as
// "node missing" and authorize a grace=0 force-delete.
func TestDaemonSetRolloutWedgeSkipsUnscheduledTerminatingPod(t *testing.T) {
	now := time.Now()
	ds := wedgedDS("kube-system", "log-agent")
	stuck := dsPod("kube-system", "log-agent", "log-agent-pending", "",
		true, "", false)
	cs, chk := dsWedgeFixture(t, now, ds, stuck, dsNode("node-1", true, false))

	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	probetest.FreezeNow(chk.Deps, now.Add(31*time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatalf("wedge must still flag: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx,
		"log-agent-pending", metav1.GetOptions{}); err != nil {
		t.Fatalf("unscheduled terminating pod was force-deleted: %v", err)
	}
}

// The circuit key must be stable across a DaemonSet pod recreate and
// free of '/' so the circuit-open Event name stays DNS-1123-valid.
func TestDaemonSetWedgeTargetKeyStableAcrossPodRecreate(t *testing.T) {
	ds := wedgedDS("kube-system", "log-agent")
	pod1 := dsPod("kube-system", "log-agent", "log-agent-aaaa", "node-1",
		false, "", false)
	pod2 := dsPod("kube-system", "log-agent", "log-agent-bbbb", "node-1",
		false, "", false)
	key1, key2 := dsWedgeTargetKey(ds, pod1), dsWedgeTargetKey(ds, pod2)
	if key1 != key2 {
		t.Fatalf("key changed across recreate: %q != %q", key1, key2)
	}
	if key1 != "kube-system.log-agent.node-1" {
		t.Fatalf("unexpected key %q", key1)
	}
	if strings.Contains(key1, "/") {
		t.Fatalf("key must be a DNS-1123 Event-name prefix, got %q", key1)
	}
}

// P0-7 end-to-end: when ObservedGeneration < Generation forces the
// ControllerRevision fallback, a new-revision unready pod on a cordoned
// node must survive while an old-revision blocker is deleted.
func TestDaemonSetRolloutWedgeP07ControllerRevisionFallbackEndToEnd(t *testing.T) {
	now := time.Now()
	ds := wedgedDS("kube-system", "log-agent")
	ds.Status.ObservedGeneration = 0
	cr := dsControllerRevision(ds, "log-agent-new", 7)
	cr.Labels = map[string]string{"controller-revision-hash": "new"}

	newPod := dsPod("kube-system", "log-agent", "log-agent-new-pod", "node-c1",
		false, "ImagePullBackOff", false)
	newPod.UID = "uid-new-pod"
	newPod.Labels["controller-revision-hash"] = "new"
	oldPod := dsPod("kube-system", "log-agent", "log-agent-old-pod", "node-c2",
		false, "CrashLoopBackOff", false)
	oldPod.UID = "uid-old-pod"
	oldPod.Labels["controller-revision-hash"] = "old"

	cs, chk := dsWedgeFixture(t, now, ds, cr, newPod, oldPod,
		dsStaticCordonedNode("node-c1"), dsStaticCordonedNode("node-c2"))
	var podLists int
	cs.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		podLists++
		return false, nil, nil
	})

	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	probetest.FreezeNow(chk.Deps, now.Add(31*time.Minute))

	podLists = 0
	sctx := probetest.SweepCtx(ctx, chk.Deps)
	res := chk.Run(sctx)
	if res.Pass {
		t.Fatalf("aged wedge must flag: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, newPod.Name, metav1.GetOptions{}); err != nil {
		t.Fatalf("new-revision pod was deleted via P0-7 fallback: %v", err)
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, oldPod.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("old-revision blocker pod was not deleted")
	}

	// SelfHealKey prefixing: Deps.Heals must stamp under SelfHealKey.
	expectedKey := "selfheal/" + CheckNameDaemonSetRolloutWedge + "/kube-system/log-agent"
	if !chk.Heals.CooledDown(expectedKey, time.Hour, now.Add(31*time.Minute)) {
		t.Fatalf("Deps.Heals missing key %q", expectedKey)
	}
	if chk.Heals.CooledDown("kube-system/log-agent", time.Hour, now.Add(31*time.Minute)) {
		t.Fatal("Deps.Heals must not stamp bare ns/name key")
	}

	// Wave 4: MarkPodDeleted tombstones the pod without calling InvalidatePods.
	podsInSweep, err := chk.Deps.AllPods(sctx)
	if err != nil {
		t.Fatalf("AllPods in same sweep: %v", err)
	}
	if podLists != 1 {
		t.Fatalf("pod list count in sweep = %d, want 1 (no InvalidatePods re-list)", podLists)
	}
	for i := range podsInSweep {
		if podsInSweep[i].Name == oldPod.Name {
			t.Fatalf("deleted pod %s still visible in same sweep after MarkPodDeleted", oldPod.Name)
		}
	}
}
