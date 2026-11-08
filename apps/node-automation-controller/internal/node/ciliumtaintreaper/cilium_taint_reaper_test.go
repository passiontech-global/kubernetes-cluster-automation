package ciliumtaintreaper

import (
	"context"
	"errors"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

var ciliumStaleTaint = corev1.Taint{
	Key:    ciliumNotReadyTaint,
	Effect: corev1.TaintEffectNoSchedule,
}

// reaperClientset returns a reaper backed by a fake clientset. The
// disabled path is not exercised here: gate-off means Setup registers
// nothing at all (covered by TestSetupDisabled).
func reaperClientset(objs ...runtime.Object) (*fake.Clientset, *ciliumTaintReaper) {
	cs := fake.NewSimpleClientset(objs...)
	return cs, &ciliumTaintReaper{cs: cs}
}

func TestCiliumTaintReaperNoPodKeepsTaint(t *testing.T) {
	// Tainted but the daemon has no pod on the node at all (removed
	// from the DaemonSet, node draining, ...) — never reap blind.
	cs, r := reaperClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil, ciliumStaleTaint))
	if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "n1").Spec.Taints, ciliumNotReadyTaint) {
		t.Fatal("taint removed with no cilium pod on the node")
	}
}

func TestCiliumTaintReaperUnreadyPodKeepsTaint(t *testing.T) {
	// Pod is Running but Ready=False — the taint is doing its job.
	pod := ciliumPod("n1", corev1.PodRunning, true)
	pod.Status.Conditions[0].Status = corev1.ConditionFalse
	cs, r := reaperClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil, ciliumStaleTaint), pod)
	if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "n1").Spec.Taints, ciliumNotReadyTaint) {
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
		testutil.Node("n1", corev1.ConditionTrue, nil, ciliumStaleTaint), pod)
	if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "n1").Spec.Taints, ciliumNotReadyTaint) {
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
		testutil.Node("n1", corev1.ConditionTrue, nil, ciliumStaleTaint),
		testutil.Node("n2", corev1.ConditionTrue, nil, ciliumStaleTaint),
		testutil.Node("n3", corev1.ConditionTrue, nil),
		healthy, unready)
	if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "n1").Spec.Taints, ciliumNotReadyTaint) {
		t.Fatal("n1: stale taint not reaped despite healthy agent")
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "n2").Spec.Taints, ciliumNotReadyTaint) {
		t.Fatal("n2: taint removed while its agent is unready")
	}
	if got := testutil.GetNode(t, cs, "n3").Spec.Taints; len(got) != 0 {
		t.Fatalf("n3: unexpected taints %+v", got)
	}
}

// A healthy agent must reap the taint even while an unhealthy sibling
// cilium pod (old agent mid-rollout, terminating replica) sits on the
// same node — the verdict reads every pod, not Items[0], so list
// order cannot keep a stale taint.
func TestCiliumTaintReaperAnyHealthyPodReaps(t *testing.T) {
	t.Run("unhealthy first, healthy second -> reaped", func(t *testing.T) {
		unready := ciliumPod("n1", corev1.PodRunning, true)
		unready.Name = "cilium-old"
		unready.Status.Conditions[0].Status = corev1.ConditionFalse
		healthy := ciliumPod("n1", corev1.PodRunning, true)
		healthy.Name = "cilium-new"
		cs, r := reaperClientset(
			testutil.Node("n1", corev1.ConditionTrue, nil, ciliumStaleTaint),
			unready, healthy)
		if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err != nil {
			t.Fatal(err)
		}
		if kube.HasTaint(testutil.GetNode(t, cs, "n1").Spec.Taints, ciliumNotReadyTaint) {
			t.Fatal("taint kept though a healthy agent runs on the node")
		}
	})

	t.Run("terminating + healthy -> reaped", func(t *testing.T) {
		terminating := ciliumPod("n1", corev1.PodRunning, true)
		terminating.Name = "cilium-dying"
		now := metav1.Now()
		terminating.DeletionTimestamp = &now
		healthy := ciliumPod("n1", corev1.PodRunning, true)
		healthy.Name = "cilium-live"
		cs, r := reaperClientset(
			testutil.Node("n1", corev1.ConditionTrue, nil, ciliumStaleTaint),
			terminating, healthy)
		if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err != nil {
			t.Fatal(err)
		}
		if kube.HasTaint(testutil.GetNode(t, cs, "n1").Spec.Taints, ciliumNotReadyTaint) {
			t.Fatal("taint kept though a healthy agent runs on the node")
		}
	})

	t.Run("all unhealthy -> kept", func(t *testing.T) {
		a := ciliumPod("n1", corev1.PodPending, false)
		a.Name = "cilium-a"
		b := ciliumPod("n1", corev1.PodRunning, true)
		b.Name = "cilium-b"
		b.Status.Conditions[0].Status = corev1.ConditionFalse
		cs, r := reaperClientset(
			testutil.Node("n1", corev1.ConditionTrue, nil, ciliumStaleTaint),
			a, b)
		if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err != nil {
			t.Fatal(err)
		}
		if !kube.HasTaint(testutil.GetNode(t, cs, "n1").Spec.Taints, ciliumNotReadyTaint) {
			t.Fatal("taint removed with no healthy agent on the node")
		}
	})
}

func TestCiliumTaintReaperPodOnOtherNodeDoesNotCount(t *testing.T) {
	// The verdict must read the cilium pod scheduled ON the tainted
	// node (spec.nodeName field selector + k8s-app label). A healthy
	// agent sitting on a different node must not reap n1's taint.
	cs, r := reaperClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil, ciliumStaleTaint),
		testutil.Node("n2", corev1.ConditionTrue, nil),
		ciliumPod("n2", corev1.PodRunning, true))
	if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "n1").Spec.Taints, ciliumNotReadyTaint) {
		t.Fatal("taint reaped by a cilium pod on a different node")
	}
}

// A pod list failure aborts the sweep — reaping on unreadable agent
// state could drop a taint that is doing its job.
func TestCiliumTaintReaperPodListError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil, ciliumStaleTaint))
	cs.PrependReactor("list", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	r := &ciliumTaintReaper{cs: cs}
	if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err == nil {
		t.Fatal("expected error when the cilium pod list fails")
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "n1").Spec.Taints, ciliumNotReadyTaint) {
		t.Fatal("taint removed despite the failed pod list")
	}
}

// ciliumStaleTaints is the jqFilter projection — only agent-not-ready
// entries, in order, duplicates included.
func TestCiliumStaleTaints(t *testing.T) {
	other := corev1.Taint{Key: "dedicated", Value: "db", Effect: corev1.TaintEffectNoSchedule}
	dup := corev1.Taint{Key: ciliumNotReadyTaint, Effect: corev1.TaintEffectNoExecute}

	// No cilium taint -> empty projection (unrelated taints don't count).
	plain := testutil.Node("n1", corev1.ConditionTrue, nil, other)
	if got := ciliumStaleTaints(plain); len(got) != 0 {
		t.Fatalf("unrelated taints leaked into projection: %+v", got)
	}

	// One cilium taint + an unrelated one -> exactly the cilium entry.
	mixed := testutil.Node("n2", corev1.ConditionTrue, nil, ciliumStaleTaint, other)
	got := ciliumStaleTaints(mixed)
	if len(got) != 1 || got[0].Key != ciliumNotReadyTaint {
		t.Fatalf("expected only the cilium taint, got %+v", got)
	}

	// Two entries with the same key (different effects) are ALL kept —
	// kubectl taint removes per-key but the projection reports entries.
	both := testutil.Node("n3", corev1.ConditionTrue, nil, ciliumStaleTaint, dup)
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
	r := &ciliumTaintReaper{cs: cs}
	if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err == nil {
		t.Fatal("expected error when the node list fails")
	}
}

// A healthy agent + stale taint, but the untaint patch is rejected —
// the error must propagate (reconcile retries next event).
func TestCiliumTaintReaperUntaintError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil, ciliumStaleTaint),
		ciliumPod("n1", corev1.PodRunning, true))
	cs.PrependReactor("patch", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	r := &ciliumTaintReaper{cs: cs}
	if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err == nil {
		t.Fatal("expected error when the untaint patch fails")
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "n1").Spec.Taints, ciliumNotReadyTaint) {
		t.Fatal("taint removed despite the rejected patch")
	}
}

// stubPodReader is the informer-cache seam stand-in: serves pods from
// a fixed slice and records the List options so tests can pin the
// cache-scope contract (kube-system + k8s-app=cilium — the manager
// cache's ByObject shape; a read outside it would silently miss).
type stubPodReader struct {
	pods    []corev1.Pod
	err     error
	lists   int
	lastNS  string
	lastSel string
}

func (s *stubPodReader) List(_ context.Context, list client.ObjectList, opts ...client.ListOption) error {
	s.lists++
	lo := &client.ListOptions{}
	for _, opt := range opts {
		opt.ApplyToList(lo)
	}
	s.lastNS = lo.Namespace
	if lo.LabelSelector != nil {
		s.lastSel = lo.LabelSelector.String()
	}
	if s.err != nil {
		return s.err
	}
	pl, ok := list.(*corev1.PodList)
	if !ok {
		return fmt.Errorf("stubPodReader: unsupported list type %T", list)
	}
	pl.Items = append(pl.Items, s.pods...)
	return nil
}

// The verdict reads cilium pods through the informer cache when the
// manager client is wired — the Pod watch this reconciler registers
// keeps it fresh — never a per-sweep apiserver LIST. The untaint
// WRITE still lands on the direct clientset.
func TestCiliumTaintReaperPodReadViaInformerCache(t *testing.T) {
	healthy := *ciliumPod("n1", corev1.PodRunning, true)
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil, ciliumStaleTaint))
	// The direct path must never be consulted while the cache seam is
	// wired: any pod list against the clientset is a bug.
	cs.PrependReactor("list", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("direct pod list must not run when the cache seam is wired")
		})
	pr := &stubPodReader{pods: []corev1.Pod{healthy}}
	r := &ciliumTaintReaper{cs: cs, podReader: pr}

	if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if pr.lists != 1 {
		t.Fatalf("cache read issued %d times, want 1", pr.lists)
	}
	if pr.lastNS != "kube-system" || pr.lastSel != "k8s-app=cilium" {
		t.Fatalf("cache List scope = %s/%s, want kube-system + k8s-app=cilium (the informer's ByObject shape)",
			pr.lastNS, pr.lastSel)
	}
	// The destructive write went through the direct clientset: the
	// stale taint is gone from the fake's node.
	if kube.HasTaint(testutil.GetNode(t, cs, "n1").Spec.Taints, ciliumNotReadyTaint) {
		t.Fatal("stale taint not reaped through the direct clientset")
	}
}

// A cache read failure is a real error — an empty snapshot must not
// read as "no cilium pod on the node" and keep (or drop) a taint on
// unreadable state.
func TestCiliumTaintReaperCachePodError(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("n1", corev1.ConditionTrue, nil, ciliumStaleTaint))
	r := &ciliumTaintReaper{cs: cs,
		podReader: &stubPodReader{err: errors.New("cache boom")}}
	if _, err := r.Reconcile(context.Background(), reconcile.Request{}); err == nil {
		t.Fatal("expected error when the informer-cache pod read fails")
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "n1").Spec.Taints, ciliumNotReadyTaint) {
		t.Fatal("taint must survive a failed pod read")
	}
}
