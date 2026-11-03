package node

import (
	"errors"
	"testing"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/controller/shared"
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
	if !shared.HasTaint(getNode(t, cs, "n1").Spec.Taints, ciliumNotReadyTaint) {
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
	if !shared.HasTaint(getNode(t, cs, "n1").Spec.Taints, ciliumNotReadyTaint) {
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
	if !shared.HasTaint(getNode(t, cs, "n1").Spec.Taints, ciliumNotReadyTaint) {
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
	if shared.HasTaint(getNode(t, cs, "n1").Spec.Taints, ciliumNotReadyTaint) {
		t.Fatal("n1: stale taint not reaped despite healthy agent")
	}
	if !shared.HasTaint(getNode(t, cs, "n2").Spec.Taints, ciliumNotReadyTaint) {
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
	if !shared.HasTaint(getNode(t, cs, "n1").Spec.Taints, ciliumNotReadyTaint) {
		t.Fatal("taint reaped by a cilium pod on a different node")
	}
}

// A pod list failure aborts the sweep — reaping on unreadable agent
// state could drop a taint that is doing its job.
func TestCiliumTaintReaperPodListError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		node("n1", corev1.ConditionTrue, nil, ciliumStaleTaint))
	cs.PrependReactor("list", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	r := &ciliumTaintReaper{cs: cs, enabled: true}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the cilium pod list fails")
	}
	if !shared.HasTaint(getNode(t, cs, "n1").Spec.Taints, ciliumNotReadyTaint) {
		t.Fatal("taint removed despite the failed pod list")
	}
}

// ciliumStaleTaints is the jqFilter projection — only agent-not-ready
// entries, in order, duplicates included.
func TestCiliumStaleTaints(t *testing.T) {
	other := corev1.Taint{Key: "dedicated", Value: "db", Effect: corev1.TaintEffectNoSchedule}
	dup := corev1.Taint{Key: ciliumNotReadyTaint, Effect: corev1.TaintEffectNoExecute}

	// No cilium taint -> empty projection (unrelated taints don't count).
	plain := node("n1", corev1.ConditionTrue, nil, other)
	if got := ciliumStaleTaints(plain); len(got) != 0 {
		t.Fatalf("unrelated taints leaked into projection: %+v", got)
	}

	// One cilium taint + an unrelated one -> exactly the cilium entry.
	mixed := node("n2", corev1.ConditionTrue, nil, ciliumStaleTaint, other)
	got := ciliumStaleTaints(mixed)
	if len(got) != 1 || got[0].Key != ciliumNotReadyTaint {
		t.Fatalf("expected only the cilium taint, got %+v", got)
	}

	// Two entries with the same key (different effects) are ALL kept —
	// kubectl taint removes per-key but the projection reports entries.
	both := node("n3", corev1.ConditionTrue, nil, ciliumStaleTaint, dup)
	got = ciliumStaleTaints(both)
	if len(got) != 2 {
		t.Fatalf("expected both cilium taint entries, got %+v", got)
	}
}

// A node list failure aborts the whole reconcile — reaping on an
// empty snapshot would look like "no stale taints" success.
func TestCiliumTaintReaperNodeListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	r := &ciliumTaintReaper{cs: cs, enabled: true}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the node list fails")
	}
}

// A healthy agent + stale taint, but the untaint patch is rejected —
// the error must propagate (reconcile retries next event).
func TestCiliumTaintReaperUntaintError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		node("n1", corev1.ConditionTrue, nil, ciliumStaleTaint),
		ciliumPod("n1", corev1.PodRunning, true))
	emulatePodNodeNameSelector(cs)
	cs.PrependReactor("patch", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	r := &ciliumTaintReaper{cs: cs, enabled: true}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the untaint patch fails")
	}
	if !shared.HasTaint(getNode(t, cs, "n1").Spec.Taints, ciliumNotReadyTaint) {
		t.Fatal("taint removed despite the rejected patch")
	}
}
