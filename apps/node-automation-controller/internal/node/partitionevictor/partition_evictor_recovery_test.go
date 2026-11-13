// partition_evictor_recovery_test.go — recovery and live-confirmation
// disciplines: recovery untaints, the stale-informer live confirms,
// fence re-confirmation, open-circuit deferrals and the zombie latch.
package partitionevictor

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// Untaint runs before the flagged path: a recovered node loses the
// partition taint while a still-flagged node keeps it (and is not
// tainted twice).
func TestPartitionEvictorUntaintsRecoveredKeepsFlaggedTaint(t *testing.T) {
	partitionTaint := corev1.Taint{
		Key:    partitionTaintKey,
		Value:  "true",
		Effect: corev1.TaintEffectNoSchedule,
	}
	recovered := testutil.Node("r1", corev1.ConditionTrue, nil, partitionTaint) // tainted, no condition
	flagged := pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute, partitionTaint)
	objs := append([]runtime.Object{recovered, flagged}, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "r1").Spec.Taints, partitionTaintKey) {
		t.Fatal("recovered node kept its partition taint")
	}
	taints := testutil.GetNode(t, cs, "p1").Spec.Taints
	if !kube.HasTaint(taints, partitionTaintKey) {
		t.Fatal("still-flagged node lost its partition taint")
	}
	if n := peCountTaintsWithKey(taints, partitionTaintKey); n != 1 {
		t.Fatalf("partition taint duplicated on flagged node: %d entries", n)
	}
}

// A failed recovery-untaint is logged and the sweep continues —
// per-node errors are never fatal (same as bash).
func TestPartitionEvictorUntaintErrorTolerated(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("h1", corev1.ConditionTrue, nil,
			corev1.Taint{Key: partitionTaintKey, Value: "true",
				Effect: corev1.TaintEffectNoSchedule}))
	cs.PrependReactor("patch", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatalf("untaint failure must not fail the run: %v", err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "h1").Spec.Taints, partitionTaintKey) {
		t.Fatal("taint removed despite the rejected patch")
	}
}

// peStaleCacheReader stands in for a lagging informer cache: it
// answers List with the snapshot it was built with, never consulting
// the live clientset — the exact shape a watch backlog produces.
type peStaleCacheReader struct{ snapshot []runtime.Object }

func (r peStaleCacheReader) List(_ context.Context, l client.ObjectList,
	_ ...client.ListOption) error {
	nl, ok := l.(*corev1.NodeList)
	if !ok {
		return fmt.Errorf("peStaleCacheReader: unexpected list type %T", l)
	}
	nl.Items = nil
	for _, o := range r.snapshot {
		nl.Items = append(nl.Items, *o.(*corev1.Node).DeepCopy())
	}
	return nil
}

// Live re-confirmation (the census rides the informer cache, which
// can lag the apiserver by minutes): a node the cache still shows
// partitioned but the LIVE API shows healthy must keep its pods and
// must not be tainted — the lag window must not cost a live pod.
func TestPartitionEvictorStaleCacheHealedNodeNotEvicted(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	stale := pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute)
	live := testutil.Node("p1", corev1.ConditionTrue, nil) // healed: ready, no partition condition
	objs := append([]runtime.Object{live, pePod("flux-system", "p1", "victim")},
		peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{
		cs:         cs,
		nodeReader: peStaleCacheReader{snapshot: append([]runtime.Object{stale}, peHealthyNodes("h", 2)...)},
	}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !testutil.PodExistsStrict(t, cs, "flux-system", "victim") {
		t.Fatal("pod evicted off a node whose partition healed inside the cache lag window")
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "p1").Spec.Taints, partitionTaintKey) {
		t.Fatal("stale-flagged node tainted without live confirmation")
	}
}

// A live-healed node that still carries the previous run's partition
// taint loses it through the existing recovery path: the live Get
// removes it from the flagged set, so the pre-exit untaint sweep
// treats it as recovered.
func TestPartitionEvictorStaleCacheHealedNodeUntainted(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	partitionTaint := corev1.Taint{
		Key:    partitionTaintKey,
		Value:  "true",
		Effect: corev1.TaintEffectNoSchedule,
	}
	stale := pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute, partitionTaint)
	live := testutil.Node("p1", corev1.ConditionTrue, nil, partitionTaint) // healed, taint left by the previous run
	objs := append([]runtime.Object{live, pePod("flux-system", "p1", "victim")},
		peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	e := &partitionEvictor{
		cs:         cs,
		nodeReader: peStaleCacheReader{snapshot: append([]runtime.Object{stale}, peHealthyNodes("h", 2)...)},
	}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "p1").Spec.Taints, partitionTaintKey) {
		t.Fatal("live-healed node kept its stale partition taint")
	}
	if !testutil.PodExistsStrict(t, cs, "flux-system", "victim") {
		t.Fatal("pod evicted off a node whose partition healed")
	}
}

// A failed LIVE Get is fail-closed: the node is skipped for this
// sweep — no taint patch, no eviction — even though the cached census
// flags it, and the run itself succeeds (the next sweep retries).
func TestPartitionEvictorLiveGetFailClosedSkipsNode(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	stale := pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute)
	live := pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute) // really partitioned, but unverifiable here
	objs := append([]runtime.Object{live, pePod("flux-system", "p1", "victim")},
		peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	cs.PrependReactor("get", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("live get boom")
		})
	e := &partitionEvictor{
		cs:         cs,
		nodeReader: peStaleCacheReader{snapshot: append([]runtime.Object{stale}, peHealthyNodes("h", 2)...)},
	}
	if err := e.run(ctx); err != nil {
		t.Fatalf("one unconfirmable node must not fail the sweep: %v", err)
	}
	for _, a := range cs.Actions() {
		if a.GetResource().Resource == "nodes" && a.GetVerb() == "patch" {
			t.Fatal("node patched (taint/untaint) without live confirmation")
		}
		if ca, ok := a.(ktesting.CreateAction); ok &&
			a.GetResource().Resource == "pods" && ca.GetSubresource() == "eviction" {
			t.Fatal("pod evicted without live confirmation of the partition")
		}
	}
	if !testutil.PodExistsStrict(t, cs, "flux-system", "victim") {
		t.Fatal("pod evicted though the live Get failed")
	}
}

// THE REGRESSION for the eviction gate's fence check: the cached
// census still showed the previous run's fence, but the LIVE node has
// lost it (removed by another operator while the cache lagged). The
// fence must be live-confirmed and re-applied before any eviction —
// evicting on the cache's word would reschedule pods straight back
// onto the unfenced blackholed host.
func TestPartitionEvictorRefencesWhenLiveFenceMissing(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	partitionTaint := corev1.Taint{
		Key:    partitionTaintKey,
		Value:  "true",
		Effect: corev1.TaintEffectNoSchedule,
	}
	// Census snapshot: partitioned AND fenced.
	stale := pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute, partitionTaint)
	// Live truth: still partitioned, fence gone.
	live := pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute)
	objs := append([]runtime.Object{live, pePod("flux-system", "p1", "victim")},
		peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	peEmulateEviction(cs)
	e := &partitionEvictor{
		cs:         cs,
		nodeReader: peStaleCacheReader{snapshot: append([]runtime.Object{stale}, peHealthyNodes("h", 2)...)},
	}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "p1").Spec.Taints, partitionTaintKey) {
		t.Fatal("live-unfenced partitioned node evicted without a re-applied fence")
	}
	if testutil.PodExistsStrict(t, cs, "flux-system", "victim") {
		t.Fatal("pod not evicted although the fence landed first")
	}
}

// A failed live Get inside the fence confirmation is fail-closed:
// without proof the fence is up, the node's evictions are skipped for
// this sweep (error metered, run still nil) — never fired on trust.
func TestPartitionEvictorFenceConfirmGetErrorSkipsEviction(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	flagged := pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute)
	objs := append([]runtime.Object{flagged, pePod("flux-system", "p1", "victim")},
		peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	// Get #1 (confirmLive) must succeed so the node reaches the taint
	// pass; Get #2 (the fence confirmation there) fails.
	gets := 0
	cs.PrependReactor("get", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			gets++
			if gets == 2 {
				return true, nil, errors.New("live get boom")
			}
			return false, nil, nil
		})
	e := &partitionEvictor{cs: cs}
	if err := e.run(ctx); err != nil {
		t.Fatalf("one unverifiable fence must not fail the sweep: %v", err)
	}
	for _, a := range cs.Actions() {
		if a.GetResource().Resource == "nodes" && a.GetVerb() == "patch" {
			t.Fatal("node patched though the fence was never live-confirmed")
		}
		if ca, ok := a.(ktesting.CreateAction); ok &&
			a.GetResource().Resource == "pods" && ca.GetSubresource() == "eviction" {
			t.Fatal("pod evicted on an unconfirmed fence")
		}
	}
	if !testutil.PodExistsStrict(t, cs, "flux-system", "victim") {
		t.Fatal("pod evicted while the fence confirmation had failed")
	}
}

// A node whose breaker already opened defers BOTH of this module's
// actions: the fencing taint is skipped and the pods survive the
// sweep — the run absorbs the defer without an error. (A fresh
// circuit tainting and evicting is covered by the earlier tests.)
func TestPartitionEvictorDefersUnderOpenCircuit(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	flagged := pePartitionedNode("p1", "HostNetworkProblems", 15*time.Minute)
	objs := append([]runtime.Object{flagged, pePod("flux-system", "p1", "victim")},
		peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	now := time.Now()
	heal.ConfigureTargetBreaker(3, time.Hour)
	t.Cleanup(func() { heal.ConfigureTargetBreaker(0, 0) })
	for range 3 {
		heal.TryAcquireTarget("partition-pod-evictor", "p1", now)
	}
	e := &partitionEvictor{cs: cs, queue: "partition-pod-evictor"}
	if err := e.run(ctx); err != nil {
		t.Fatalf("open circuit must defer, not error: %v", err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "p1").Spec.Taints, partitionTaintKey) {
		t.Fatal("taint applied while the target circuit is open")
	}
	if !testutil.PodExistsStrict(t, cs, "flux-system", "victim") {
		t.Fatal("pod evicted while the target circuit is open")
	}
}

// Recovery is never breaker-gated: a recovered node untaints even
// while its circuit sits open, and the untaint clears its history so
// the next partition episode starts from zero.
func TestPartitionEvictorRecoveryUntaintUnderOpenCircuit(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	recovered := testutil.Node("p1", corev1.ConditionTrue, nil, corev1.Taint{
		Key: partitionTaintKey, Value: "true", Effect: corev1.TaintEffectNoSchedule,
	})
	objs := append([]runtime.Object{recovered}, peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	now := time.Now()
	heal.ConfigureTargetBreaker(3, time.Hour)
	t.Cleanup(func() { heal.ConfigureTargetBreaker(0, 0) })
	for range 3 {
		heal.TryAcquireTarget("partition-pod-evictor", "p1", now)
	}
	e := &partitionEvictor{cs: cs, queue: "partition-pod-evictor"}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "p1").Spec.Taints, partitionTaintKey) {
		t.Fatal("recovered node kept its partition taint under an open circuit")
	}
	if ok, _ := heal.TryAcquireTarget("partition-pod-evictor", "p1",
		now.Add(time.Minute)); !ok {
		t.Fatal("recovery untaint did not clear the node's breaker history")
	}
}

// ---------------------------------------------------------------------------
// confirmLive / untaintRecovered — the live-confirmation disciplines.
// ---------------------------------------------------------------------------

// A node deleted between census and confirm drops out of `flagged`
// and is left alone: no taint patch, no eviction, no error metering —
// a vanished node has nothing to evict or untaint and must not
// inflate the mesh-wide guard either.
func TestPartitionEvictorConfirmGetNotFoundDropsFlagged(t *testing.T) {
	t.Setenv(partitionNSsEnv, "flux-system")
	stale := pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute)
	objs := append([]runtime.Object{pePod("flux-system", "p1", "victim")},
		peHealthyNodes("h", 2)...)
	cs := fake.NewSimpleClientset(objs...)
	peEmulateEviction(cs)
	// The live Get of p1 404s; everything else answers normally.
	cs.PrependReactor("get", "nodes",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			if ga, ok := a.(ktesting.GetAction); ok && ga.GetName() == "p1" {
				return true, nil, apierrors.NewNotFound(
					corev1.Resource("nodes"), "p1")
			}
			return false, nil, nil
		})
	before := testutil.QueueErrorCount(t, "partition-pod-evictor")
	e := &partitionEvictor{
		cs:         cs,
		nodeReader: peStaleCacheReader{snapshot: append([]runtime.Object{stale}, peHealthyNodes("h", 2)...)},
	}
	if err := e.run(ctx); err != nil {
		t.Fatalf("a node gone since census must not error the sweep: %v", err)
	}
	if got := testutil.QueueErrorCount(t, "partition-pod-evictor") - before; got != 0 {
		t.Fatalf("a node gone since census metered %v errors", got)
	}
	if !testutil.PodExistsStrict(t, cs, "flux-system", "victim") {
		t.Fatal("pod evicted off a node deleted since the census")
	}
	for _, a := range cs.Actions() {
		if a.GetResource().Resource == "nodes" && a.GetVerb() == "patch" {
			t.Fatal("node gone since census still patched (taint/untaint)")
		}
		if ca, ok := a.(ktesting.CreateAction); ok &&
			a.GetResource().Resource == "pods" && ca.GetSubresource() == "eviction" {
			t.Fatal("eviction attempted against a node gone since census")
		}
	}
}

// The recovery untaint is live-confirmed: a node the cache aged out
// of `flagged` but whose LIVE API still reports the partition
// condition True keeps its fence this sweep.
func TestPartitionEvictorUntaintSkippedWhenStillPartitionedLive(t *testing.T) {
	partitionTaint := corev1.Taint{
		Key: partitionTaintKey, Value: "true", Effect: corev1.TaintEffectNoSchedule,
	}
	// Cache says healed (condition cleared) but the live API still
	// reports HostNetworkProblems True — a stale-cache flip must not
	// un-fence a live partition.
	stale := testutil.Node("p1", corev1.ConditionTrue, nil, partitionTaint)
	live := pePartitionedNode("p1", "HostNetworkProblems", 20*time.Minute, partitionTaint)
	cs := fake.NewSimpleClientset(live)
	e := &partitionEvictor{
		cs:         cs,
		nodeReader: peStaleCacheReader{snapshot: []runtime.Object{stale}},
	}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "p1").Spec.Taints, partitionTaintKey) {
		t.Fatal("untaint landed although the live node still reports the partition")
	}
}

// A zombie agent latch (True condition, frozen heartbeat) blocks the
// untaint too: the wedged reporter cannot vouch for the healing
// either way, so the fence stays up this sweep — the mirror image of
// not evicting on a zombie partition.
func TestPartitionEvictorUntaintSkippedOnZombieLatch(t *testing.T) {
	partitionTaint := corev1.Taint{
		Key: partitionTaintKey, Value: "true", Effect: corev1.TaintEffectNoSchedule,
	}
	zombie := pePartitionedNode("p1", "NebulaIsolated", 20*time.Minute, partitionTaint)
	for i := range zombie.Status.Conditions {
		if zombie.Status.Conditions[i].Type == "NebulaIsolated" {
			zombie.Status.Conditions[i].LastHeartbeatTime =
				metav1.NewTime(time.Now().Add(-2 * partitionCondHeartbeatMaxAge))
		}
	}
	// Cache snapshot predates the latch: it shows the node untainted
	// and healthy, so the untaint path is reached.
	stale := testutil.Node("p1", corev1.ConditionTrue, nil)
	cs := fake.NewSimpleClientset(zombie)
	e := &partitionEvictor{
		cs:         cs,
		nodeReader: peStaleCacheReader{snapshot: []runtime.Object{stale}},
	}
	if err := e.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "p1").Spec.Taints, partitionTaintKey) {
		t.Fatal("untaint landed on a zombie partition latch nobody can vouch for")
	}
}

// A node deleted since the census skips the untaint quietly: the live
// Get 404s, no patch is attempted, no error is metered — the taint
// died with the node.
func TestPartitionEvictorUntaintSkippedForGoneNode(t *testing.T) {
	partitionTaint := corev1.Taint{
		Key: partitionTaintKey, Value: "true", Effect: corev1.TaintEffectNoSchedule,
	}
	stale := testutil.Node("p1", corev1.ConditionTrue, nil, partitionTaint)
	cs := fake.NewSimpleClientset() // live API has no p1 at all
	cs.PrependReactor("get", "nodes",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			if ga, ok := a.(ktesting.GetAction); ok && ga.GetName() == "p1" {
				return true, nil, apierrors.NewNotFound(
					corev1.Resource("nodes"), "p1")
			}
			return false, nil, nil
		})
	before := testutil.QueueErrorCount(t, "partition-pod-evictor")
	e := &partitionEvictor{
		cs:         cs,
		nodeReader: peStaleCacheReader{snapshot: []runtime.Object{stale}},
	}
	if err := e.run(ctx); err != nil {
		t.Fatalf("a gone node must not error the sweep: %v", err)
	}
	if got := testutil.QueueErrorCount(t, "partition-pod-evictor") - before; got != 0 {
		t.Fatalf("a gone node metered %v errors", got)
	}
	for _, a := range cs.Actions() {
		if a.GetResource().Resource == "nodes" && a.GetVerb() == "patch" {
			t.Fatal("untaint attempted against a node gone since census")
		}
	}
}
