package controller

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var ciliumStaleTaint = corev1.Taint{
	Key:    ciliumNotReadyTaint,
	Effect: corev1.TaintEffectNoSchedule,
}

// emulatePodNodeNameSelector teaches the fake clientset to honor the
// spec.nodeName field selector the reaper relies on — the fake applies
// label selectors but silently ignores field selectors, so without this
// a cilium pod on another node would leak into the per-node pod list.
func emulatePodNodeNameSelector(cs *fake.Clientset) {
	gvr := schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	gvk := schema.GroupVersionKind{Version: "v1", Kind: "Pod"}
	cs.PrependReactor("list", "pods",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			la, ok := action.(ktesting.ListAction)
			if !ok {
				return false, nil, nil
			}
			restr := la.GetListRestrictions()
			nodeName, found := "", false
			if restr.Fields != nil {
				nodeName, found = restr.Fields.RequiresExactMatch("spec.nodeName")
			}
			if !found {
				return false, nil, nil // no nodeName filter -> fake default
			}
			obj, err := cs.Tracker().List(gvr, gvk, la.GetNamespace())
			if err != nil {
				return true, nil, err
			}
			all := obj.(*corev1.PodList)
			out := &corev1.PodList{ListMeta: all.ListMeta}
			for i := range all.Items {
				p := &all.Items[i]
				if p.Spec.NodeName != nodeName {
					continue
				}
				if restr.Labels != nil &&
					!restr.Labels.Matches(labels.Set(p.Labels)) {
					continue
				}
				out.Items = append(out.Items, *p)
			}
			return true, out, nil
		})
}

// reaperClientset returns an enabled reaper backed by a fake clientset
// with apiserver-faithful field-selector behavior.
func reaperClientset(objs ...runtime.Object) (*fake.Clientset, *ciliumTaintReaper) {
	cs := fake.NewSimpleClientset(objs...)
	emulatePodNodeNameSelector(cs)
	return cs, &ciliumTaintReaper{cs: cs, enabled: true}
}

func TestCiliumTaintReaperNoPodKeepsTaint(t *testing.T) {
	// Tainted but the daemon has no pod on the node at all (removed
	// from the DaemonSet, node draining, ...) — never reap blind.
	cs, r := reaperClientset(
		node("n1", corev1.ConditionTrue, nil, ciliumStaleTaint))
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if !hasTaint(getNode(t, cs, "n1").Spec.Taints, ciliumNotReadyTaint) {
		t.Fatal("taint removed with no cilium pod on the node")
	}
}

func TestCiliumTaintReaperUnreadyPodKeepsTaint(t *testing.T) {
	// Pod is Running but Ready=False — the taint is doing its job.
	pod := ciliumPod("n1", corev1.PodRunning, true)
	pod.Status.Conditions[0].Status = corev1.ConditionFalse
	cs, r := reaperClientset(
		node("n1", corev1.ConditionTrue, nil, ciliumStaleTaint), pod)
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if !hasTaint(getNode(t, cs, "n1").Spec.Taints, ciliumNotReadyTaint) {
		t.Fatal("taint removed while agent Ready=False")
	}
}

func TestCiliumTaintReaperTerminatingPodKeepsTaint(t *testing.T) {
	// Running+Ready but marked for deletion — a terminating agent is
	// not a healthy one.
	pod := ciliumPod("n1", corev1.PodRunning, true)
	now := metav1.Now()
	pod.DeletionTimestamp = &now
	cs, r := reaperClientset(
		node("n1", corev1.ConditionTrue, nil, ciliumStaleTaint), pod)
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if !hasTaint(getNode(t, cs, "n1").Spec.Taints, ciliumNotReadyTaint) {
		t.Fatal("taint removed while agent is terminating")
	}
}

func TestCiliumTaintReaperSweepsWholeCluster(t *testing.T) {
	// n1: tainted + healthy agent -> reaped.
	// n2: tainted + unready agent -> kept.
	// n3: no taint -> untouched (no pod lookup needed for the verdict,
	//     but its presence proves the sweep tolerates untainted nodes).
	healthy := ciliumPod("n1", corev1.PodRunning, true)
	healthy.Name = "cilium-n1"
	unready := ciliumPod("n2", corev1.PodRunning, true)
	unready.Name = "cilium-n2"
	unready.Status.Conditions[0].Status = corev1.ConditionFalse

	cs, r := reaperClientset(
		node("n1", corev1.ConditionTrue, nil, ciliumStaleTaint),
		node("n2", corev1.ConditionTrue, nil, ciliumStaleTaint),
		node("n3", corev1.ConditionTrue, nil),
		healthy, unready)
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if hasTaint(getNode(t, cs, "n1").Spec.Taints, ciliumNotReadyTaint) {
		t.Fatal("n1: stale taint not reaped despite healthy agent")
	}
	if !hasTaint(getNode(t, cs, "n2").Spec.Taints, ciliumNotReadyTaint) {
		t.Fatal("n2: taint removed while its agent is unready")
	}
	if got := getNode(t, cs, "n3").Spec.Taints; len(got) != 0 {
		t.Fatalf("n3: unexpected taints %+v", got)
	}
}

func TestCiliumTaintReaperPodOnOtherNodeDoesNotCount(t *testing.T) {
	// The verdict must read the cilium pod scheduled ON the tainted
	// node (spec.nodeName field selector + k8s-app label). A healthy
	// agent sitting on a different node must not reap n1's taint.
	cs, r := reaperClientset(
		node("n1", corev1.ConditionTrue, nil, ciliumStaleTaint),
		node("n2", corev1.ConditionTrue, nil),
		ciliumPod("n2", corev1.PodRunning, true))
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if !hasTaint(getNode(t, cs, "n1").Spec.Taints, ciliumNotReadyTaint) {
		t.Fatal("taint reaped by a cilium pod on a different node")
	}
}
