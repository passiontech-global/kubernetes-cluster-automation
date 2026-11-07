// snapshot_ctx_test.go — regression for the snapshot-poisoning bug:
// memoized LISTs must run under the captured sweep ctx (or the
// caller's ctx outside a sweep), never under the calling check's
// per-check ctx — an expired PerCheck deadline used to cache
// context.DeadlineExceeded and fail every later check in the sweep.
// Also covers InvalidatePods keeping the non-pod censuses memoized.
package probefw

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	ktesting "k8s.io/client-go/testing"
)

// ctxCaptureCS wraps a fake clientset so tests can see WHICH context
// a pod/node List ran under — the observable difference between the
// per-check ctx and the snapshot's captured sweep ctx. The Err() is
// recorded AT LIST TIME: the caller's deferred cancel fires after
// List returns, so inspecting the ctx later would misread it.
type ctxCaptureCS struct {
	kubernetes.Interface
	podListCtxErr      error
	nodeListCtxErr     error
	podListHadCtx      bool
	nodeListHadCtx     bool
	podListHadDeadline bool
}

func (c *ctxCaptureCS) CoreV1() corev1client.CoreV1Interface {
	return &ctxCaptureCore{CoreV1Interface: c.Interface.CoreV1(), cs: c}
}

type ctxCaptureCore struct {
	corev1client.CoreV1Interface
	cs *ctxCaptureCS
}

func (c *ctxCaptureCore) Pods(ns string) corev1client.PodInterface {
	return &ctxCapturePods{PodInterface: c.CoreV1Interface.Pods(ns), cs: c.cs}
}

func (c *ctxCaptureCore) Nodes() corev1client.NodeInterface {
	return &ctxCaptureNodes{NodeInterface: c.CoreV1Interface.Nodes(), cs: c.cs}
}

type ctxCapturePods struct {
	corev1client.PodInterface
	cs *ctxCaptureCS
}

func (c *ctxCapturePods) List(ctx context.Context, o metav1.ListOptions) (*corev1.PodList, error) {
	c.cs.podListHadCtx = true
	c.cs.podListCtxErr = ctx.Err()
	_, c.cs.podListHadDeadline = ctx.Deadline()
	return c.PodInterface.List(ctx, o)
}

type ctxCaptureNodes struct {
	corev1client.NodeInterface
	cs *ctxCaptureCS
}

func (c *ctxCaptureNodes) List(ctx context.Context, o metav1.ListOptions) (*corev1.NodeList, error) {
	c.cs.nodeListHadCtx = true
	c.cs.nodeListCtxErr = ctx.Err()
	return c.NodeInterface.List(ctx, o)
}

// A check running under an already-DEAD per-check ctx must still get
// a live LIST: the snapshot captured the sweep ctx at install, so
// the census populates under it instead of inheriting the caller's
// expired deadline.
func TestSweepSnapshotListsUnderSweepCtx(t *testing.T) {
	cs := &ctxCaptureCS{Interface: fake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "web-1"}})}
	d := &Deps{CS: cs}

	sweepCtx := WithSweepSnapshot(context.Background())
	deadCheckCtx, cancel := context.WithCancel(sweepCtx)
	cancel() // the check's PerCheck ctx already expired

	pods, err := d.AllPods(deadCheckCtx)
	if err != nil {
		t.Fatalf("AllPods under a dead per-check ctx = %v — "+
			"the snapshot must list under the sweep ctx", err)
	}
	if len(pods) != 1 {
		t.Fatalf("AllPods = %d pods, want 1", len(pods))
	}
	if !cs.podListHadCtx || cs.podListCtxErr != nil {
		t.Fatalf("pod LIST ran under ctx err=%v — the per-check "+
			"deadline must not poison the shared census",
			cs.podListCtxErr)
	}
	// The memoized read then serves every later check without a new
	// LIST — same dead ctx, same live data.
	cs.podListHadCtx = false
	if _, err := d.AllPods(deadCheckCtx); err != nil {
		t.Fatalf("memoized AllPods = %v", err)
	}
	if cs.podListHadCtx {
		t.Fatal("memoized census issued a second LIST")
	}
}

// Outside a sweep there is no captured ctx: the caller's own ctx is
// the LIST deadline, preserving the legacy list-fresh-per-call
// semantics for direct check.Run invocations.
func TestDirectRunSnapshotUsesCallerCtx(t *testing.T) {
	cs := &ctxCaptureCS{Interface: fake.NewSimpleClientset()}
	d := &Deps{CS: cs}
	if _, err := d.AllPods(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !cs.podListHadCtx {
		t.Fatal("no LIST ctx captured")
	}
	if !cs.podListHadDeadline {
		t.Fatal("direct-Run LIST lost its dedicated bound")
	}
}

// A pod delete only stales the pod census: InvalidatePods must force
// a pods re-list while nodes keep their memoized read.
func TestInvalidatePodsKeepsOtherCensuses(t *testing.T) {
	cs := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-1"}})
	var podLists, nodeLists int
	cs.PrependReactor("list", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			podLists++
			return false, nil, nil
		})
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			nodeLists++
			return false, nil, nil
		})
	d := &Deps{CS: cs}
	sweepCtx := WithSweepSnapshot(context.Background())

	if _, err := d.AllPods(sweepCtx); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AllNodes(sweepCtx); err != nil {
		t.Fatal(err)
	}
	d.InvalidatePods(sweepCtx)
	if _, err := d.AllPods(sweepCtx); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AllNodes(sweepCtx); err != nil {
		t.Fatal(err)
	}
	if podLists != 2 || nodeLists != 1 {
		t.Fatalf("lists pods=%d nodes=%d, want pods=2 nodes=1 "+
			"(pod-only invalidate must not drop the node census)",
			podLists, nodeLists)
	}
	// InvalidateSweep still drops everything.
	d.InvalidateSweep(sweepCtx)
	if _, err := d.AllNodes(sweepCtx); err != nil {
		t.Fatal(err)
	}
	if nodeLists != 2 {
		t.Fatalf("lists nodes=%d after InvalidateSweep, want 2", nodeLists)
	}
}
