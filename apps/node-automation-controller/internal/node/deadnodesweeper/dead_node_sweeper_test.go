package deadnodesweeper

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// outOfServiceTaint is the taint the sweeper applies to confirmed-dead
// nodes; node controller then force-deletes pods + detaches volumes.
var outOfServiceTaint = corev1.Taint{
	Key:    outOfServiceTaintKey,
	Value:  outOfServiceTaintValue,
	Effect: corev1.TaintEffectNoExecute,
}

// stuckTerminatingPod is a pod that has been in Terminating for `age`.
func stuckTerminatingPod(ns, name, nodeName string, age time.Duration) *corev1.Pod {
	ts := metav1.NewTime(time.Now().Add(-age))
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			DeletionTimestamp: &ts,
			Finalizers:        []string{"test/stuck"},
		},
		Spec: corev1.PodSpec{NodeName: nodeName},
	}
}

// unknownNode is a node whose Ready=Unknown transition is `age` old.
func unknownNode(name string, age time.Duration) *corev1.Node {
	n := testutil.Node(name, corev1.ConditionUnknown, nil)
	n.Status.Conditions[0].LastTransitionTime = metav1.NewTime(time.Now().Add(-age))
	return n
}

// remediationObj builds a medik8s remediation CR (unstructured).
func remediationObj(gvr schema.GroupVersionResource, kind, ns, name string) *unstructured.Unstructured {
	// remediation CRs are named after the node.
	return testutil.Unstructured(gvr.GroupVersion().WithKind(kind), ns, name, nil)
}

func selfNodeRemediation(ns, name string) *unstructured.Unstructured {
	return remediationObj(selfNodeRemediationGVR, "SelfNodeRemediation", ns, name)
}

func fenceAgentsRemediation(ns, name string) *unstructured.Unstructured {
	return remediationObj(fenceAgentsRemediationGVR, "FenceAgentsRemediation", ns, name)
}

// deadNodeDynFake returns a dynamic fake that knows the list kinds for
// both medik8s GVRs (and every other CRD the sweep may touch).
func deadNodeDynFake(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return testutil.NewDynamicClient(objs...)
}

// healthyProbe is the default stub — kubelet answers /healthz "ok",
// so path (b) can never confirm death.
func healthyProbe(context.Context, string) (bool, error) { return true, nil }

func deadNodeSweeperFor(cs *fake.Clientset, dyn *dynamicfake.FakeDynamicClient,
	probe func(context.Context, string) (bool, error)) *deadNodeSweeper {
	if probe == nil {
		probe = healthyProbe
	}
	return &deadNodeSweeper{cs: cs, dyn: dyn, probeFn: probe}
}

func TestDeadNodeSweeperTaintsFencedNode(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("w1", corev1.ConditionFalse, nil),
		stuckTerminatingPod("db", "pg-0", "w1", 20*time.Minute))
	dyn := deadNodeDynFake(selfNodeRemediation("medik8s", "w1"))
	s := deadNodeSweeperFor(cs, dyn, nil)

	if err := s.run(ctx); err != nil {
		t.Fatal(err)
	}
	got := testutil.GetNode(t, cs, "w1")
	if !kube.HasTaint(got.Spec.Taints, outOfServiceTaintKey) {
		t.Fatal("fenced node with stuck Terminating pods not tainted")
	}
	for _, tn := range got.Spec.Taints {
		if tn.Key == outOfServiceTaintKey &&
			(tn.Value != outOfServiceTaintValue || tn.Effect != corev1.TaintEffectNoExecute) {
			t.Fatalf("wrong taint shape: %+v", tn)
		}
	}
}

func TestDeadNodeSweeperSkipsReadyNode(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("w1", corev1.ConditionTrue, nil),
		// w2 keeps hasNotReady true so the pod list still runs and
		// w1's skip comes from the in-loop Ready check, not the
		// all-Ready early return (w2 has no stuck pods of its own).
		testutil.Node("w2", corev1.ConditionFalse, nil),
		stuckTerminatingPod("db", "pg-0", "w1", 20*time.Minute))
	// Even with a remediation CR present — a Ready node is the host
	// watchdog's problem, never ours.
	dyn := deadNodeDynFake(selfNodeRemediation("medik8s", "w1"))
	s := deadNodeSweeperFor(cs, dyn, nil)

	if err := s.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"w1", "w2"} {
		if kube.HasTaint(testutil.GetNode(t, cs, name).Spec.Taints, outOfServiceTaintKey) {
			t.Fatalf("node %s tainted — should have been skipped", name)
		}
	}
}

func TestDeadNodeSweeperFailClosedNoEvidence(t *testing.T) {
	t.Run("NotReady without remediation CR", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			testutil.Node("w1", corev1.ConditionFalse, nil),
			stuckTerminatingPod("db", "pg-0", "w1", 20*time.Minute))
		// A CR for a DIFFERENT node must not count as evidence.
		dyn := deadNodeDynFake(selfNodeRemediation("medik8s", "other-node"))
		s := deadNodeSweeperFor(cs, dyn, nil)

		if err := s.run(ctx); err != nil {
			t.Fatal(err)
		}
		if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
			t.Fatal("node tainted with zero fencing evidence")
		}
	})

	t.Run("Unknown under the 30m window", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			unknownNode("w1", 10*time.Minute),
			stuckTerminatingPod("db", "pg-0", "w1", 20*time.Minute))
		dyn := deadNodeDynFake()
		probeCalled := false
		s := deadNodeSweeperFor(cs, dyn, func(context.Context, string) (bool, error) {
			probeCalled = true
			return false, nil // even a dead probe must not help inside the window
		})

		if err := s.run(ctx); err != nil {
			t.Fatal(err)
		}
		if probeCalled {
			t.Fatal("probe invoked before the 30m Unknown window elapsed")
		}
		if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
			t.Fatal("node tainted inside the 30m Unknown window")
		}
	})

	t.Run("fresh Terminating pods are ignored", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			testutil.Node("w1", corev1.ConditionFalse, nil),
			stuckTerminatingPod("db", "pg-0", "w1", 5*time.Minute)) // < 15m
		dyn := deadNodeDynFake(selfNodeRemediation("medik8s", "w1"))
		s := deadNodeSweeperFor(cs, dyn, nil)

		if err := s.run(ctx); err != nil {
			t.Fatal(err)
		}
		if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
			t.Fatal("node tainted for a pod still inside its grace window")
		}
	})
}

func TestDeadNodeSweeperProbePath(t *testing.T) {
	t.Run("Unknown>30m + probe fails -> tainted", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			unknownNode("w1", 45*time.Minute),
			stuckTerminatingPod("db", "pg-0", "w1", 20*time.Minute))
		dyn := deadNodeDynFake()
		s := deadNodeSweeperFor(cs, dyn,
			func(context.Context, string) (bool, error) { return false, nil })

		if err := s.run(ctx); err != nil {
			t.Fatal(err)
		}
		if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
			t.Fatal("Unknown>30m + dead kubelet not tainted")
		}
	})

	t.Run("Unknown>30m + probe error counts as failed -> tainted", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			unknownNode("w1", 45*time.Minute),
			stuckTerminatingPod("db", "pg-0", "w1", 20*time.Minute))
		dyn := deadNodeDynFake()
		s := deadNodeSweeperFor(cs, dyn,
			func(context.Context, string) (bool, error) {
				return false, errors.New("error trying to reach service")
			})

		if err := s.run(ctx); err != nil {
			t.Fatal(err)
		}
		if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
			t.Fatal("probe error (kubelet unreachable) not treated as dead")
		}
	})

	t.Run("Unknown>30m + probe ok -> skipped", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			unknownNode("w1", 45*time.Minute),
			stuckTerminatingPod("db", "pg-0", "w1", 20*time.Minute))
		dyn := deadNodeDynFake()
		s := deadNodeSweeperFor(cs, dyn, healthyProbe)

		if err := s.run(ctx); err != nil {
			t.Fatal(err)
		}
		if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
			t.Fatal("node tainted though its kubelet answers healthz")
		}
	})
}

func TestDeadNodeSweeperFenceAgentsCR(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("w1", corev1.ConditionFalse, nil),
		stuckTerminatingPod("db", "pg-0", "w1", 20*time.Minute))
	dyn := deadNodeDynFake(fenceAgentsRemediation("medik8s", "w1"))
	s := deadNodeSweeperFor(cs, dyn, nil)

	if err := s.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
		t.Fatal("fenceagentsremediation CR not accepted as fencing evidence")
	}
}

func TestDeadNodeSweeperUntaintsRecoveredNode(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("w1", corev1.ConditionTrue, nil, outOfServiceTaint))
	dyn := deadNodeDynFake()
	s := deadNodeSweeperFor(cs, dyn, nil)

	if err := s.run(ctx); err != nil {
		t.Fatal(err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
		t.Fatal("recovered node still carries out-of-service taint")
	}
}

func TestDeadNodeSweeperCapOnePerCycle(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("w1", corev1.ConditionFalse, nil),
		testutil.Node("w2", corev1.ConditionFalse, nil),
		stuckTerminatingPod("db", "pg-0", "w1", 20*time.Minute),
		stuckTerminatingPod("db", "pg-1", "w2", 20*time.Minute))
	dyn := deadNodeDynFake(
		selfNodeRemediation("medik8s", "w1"),
		selfNodeRemediation("medik8s", "w2"))
	s := deadNodeSweeperFor(cs, dyn, nil)

	if err := s.run(ctx); err != nil {
		t.Fatal(err)
	}
	tainted := 0
	for _, name := range []string{"w1", "w2"} {
		if kube.HasTaint(testutil.GetNode(t, cs, name).Spec.Taints, outOfServiceTaintKey) {
			tainted++
		}
	}
	if tainted != deadNodeCap {
		t.Fatalf("expected exactly %d node tainted per cycle, got %d", deadNodeCap, tainted)
	}
	// Deterministic order: w1 sorts first, so it is the one tainted.
	if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
		t.Fatal("expected w1 (first sorted) to be the capped-out node")
	}
}

func TestDeadNodeSweeperVolumeAttachments(t *testing.T) {
	t.Run("listing is signal-only — node still tainted", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			testutil.Node("w1", corev1.ConditionFalse, nil),
			stuckTerminatingPod("db", "pg-0", "w1", 20*time.Minute),
			&storagev1.VolumeAttachment{
				ObjectMeta: metav1.ObjectMeta{Name: "va-w1"},
				Spec: storagev1.VolumeAttachmentSpec{
					NodeName: "w1",
					Attacher: "csi.test",
					Source:   storagev1.VolumeAttachmentSource{},
				},
			})
		dyn := deadNodeDynFake(selfNodeRemediation("medik8s", "w1"))
		s := deadNodeSweeperFor(cs, dyn, nil)

		if err := s.run(ctx); err != nil {
			t.Fatal(err)
		}
		if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
			t.Fatal("node not tainted")
		}
	})

	t.Run("list failure is non-fatal", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			testutil.Node("w1", corev1.ConditionFalse, nil),
			stuckTerminatingPod("db", "pg-0", "w1", 20*time.Minute))
		cs.PrependReactor("list", "volumeattachments",
			func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("va list boom")
			})
		dyn := deadNodeDynFake(selfNodeRemediation("medik8s", "w1"))
		s := deadNodeSweeperFor(cs, dyn, nil)

		if err := s.run(ctx); err != nil {
			t.Fatalf("volumeattachment list failure must not fail the run: %v", err)
		}
		if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
			t.Fatal("taint vetoed by a volumeattachment list failure")
		}
	})
}

func TestDeadNodeSweeperMissingNode(t *testing.T) {
	// Stuck pod references a node object the apiserver no longer has.
	// w1 is NotReady so the pod list still runs — an all-Ready cluster
	// exits before ever reading pods, leaving the gone-node skip
	// branch uncovered.
	cs := fake.NewSimpleClientset(
		testutil.Node("w1", corev1.ConditionFalse, nil),
		stuckTerminatingPod("db", "pg-0", "ghost", 20*time.Minute))
	dyn := deadNodeDynFake()
	s := deadNodeSweeperFor(cs, dyn, nil)

	if err := s.run(ctx); err != nil {
		t.Fatalf("missing node must be a skip, not a run failure: %v", err)
	}
}

// The cluster-wide pod list is the sweep's most expensive read — it
// is skipped entirely when every listed node is Ready (nothing could
// be fenced anyway), and happens exactly once a NotReady node exists.
func TestDeadNodeSweeperSkipsPodListWhenAllReady(t *testing.T) {
	podListCount := func(cs *fake.Clientset) func() int {
		var n int32
		cs.PrependReactor("list", "pods",
			func(ktesting.Action) (bool, runtime.Object, error) {
				atomic.AddInt32(&n, 1)
				return false, nil, nil // fall through to the tracker
			})
		return func() int { return int(atomic.LoadInt32(&n)) }
	}

	t.Run("all Ready -> pod list never runs", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			testutil.Node("w1", corev1.ConditionTrue, nil),
			testutil.Node("w2", corev1.ConditionTrue, nil),
			// Even a stuck pod changes nothing — the all-Ready gate
			// fires before it can be counted.
			stuckTerminatingPod("db", "pg-0", "w1", 20*time.Minute))
		lists := podListCount(cs)
		s := deadNodeSweeperFor(cs, deadNodeDynFake(), nil)
		if err := s.run(ctx); err != nil {
			t.Fatal(err)
		}
		if lists() != 0 {
			t.Fatalf("pod list ran %d times on an all-Ready cluster", lists())
		}
	})

	t.Run("a NotReady node -> pod list runs once", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			testutil.Node("w1", corev1.ConditionTrue, nil),
			testutil.Node("w2", corev1.ConditionFalse, nil))
		lists := podListCount(cs)
		s := deadNodeSweeperFor(cs, deadNodeDynFake(), nil)
		if err := s.run(ctx); err != nil {
			t.Fatal(err)
		}
		if lists() != 1 {
			t.Fatalf("pod list ran %d times, want exactly 1", lists())
		}
	})
}

// ---------------------------------------------------------------------------
// run() failure tolerances — per-node errors are logged/metered, the
// sweep continues and still returns nil.
// ---------------------------------------------------------------------------

func TestDeadNodeSweeperNodeListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	s := deadNodeSweeperFor(cs, deadNodeDynFake(), nil)
	if err := s.run(ctx); err == nil {
		t.Fatal("expected error when the node list fails")
	}
}

func TestDeadNodeSweeperPodListError(t *testing.T) {
	// The pod list is skipped when every node is Ready — a NotReady
	// node is required for the sweep to reach it at all.
	cs := fake.NewSimpleClientset(testutil.Node("w1", corev1.ConditionFalse, nil))
	cs.PrependReactor("list", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	s := deadNodeSweeperFor(cs, deadNodeDynFake(), nil)
	if err := s.run(ctx); err == nil {
		t.Fatal("expected error when the pod list fails")
	}
}

// A Ready node carrying the taint gets untainted; a patch failure on
// that untaint is metered and the sweep moves on (returns nil).
func TestDeadNodeSweeperRecoveryUntaintErrorTolerated(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("w1", corev1.ConditionTrue, nil, outOfServiceTaint))
	cs.PrependReactor("patch", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	s := deadNodeSweeperFor(cs, deadNodeDynFake(), nil)
	if err := s.run(ctx); err != nil {
		t.Fatalf("untaint failure must not fail the run: %v", err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
		t.Fatal("taint removed despite the failed patch")
	}
}

// Pods that are not stuck (not Terminating, or Terminating with no
// node assignment) never enter the per-node suspect map.
func TestDeadNodeSweeperIgnoresNonStuckPods(t *testing.T) {
	running := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "db", Name: "pg-1"},
		Spec: corev1.PodSpec{NodeName: "w1"}}
	ts := metav1.NewTime(time.Now().Add(-20 * time.Minute))
	nodeless := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "db", Name: "pg-2",
		DeletionTimestamp: &ts, Finalizers: []string{"test/stuck"}},
	}
	cs := fake.NewSimpleClientset(
		testutil.Node("w1", corev1.ConditionFalse, nil), running, nodeless)
	dyn := deadNodeDynFake(selfNodeRemediation("medik8s", "w1"))
	s := deadNodeSweeperFor(cs, dyn, nil)
	if err := s.run(ctx); err != nil {
		t.Fatal(err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
		t.Fatal("node tainted without any stuck pod")
	}
}

// A NotReady node already carrying the out-of-service taint is the
// node controller's in-flight fencing — kept, and it does not consume
// the per-cycle cap.
func TestDeadNodeSweeperKeepsAlreadyFencedNode(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("w1", corev1.ConditionFalse, nil, outOfServiceTaint),
		stuckTerminatingPod("db", "pg-0", "w1", 20*time.Minute))
	s := deadNodeSweeperFor(cs, deadNodeDynFake(), nil)
	if err := s.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
		t.Fatal("already-fenced node's taint was dropped")
	}
}

// A confirmed-dead node whose taint patch fails is metered+skipped —
// the cap is not consumed, the run still returns nil.
func TestDeadNodeSweeperTaintPatchErrorTolerated(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("w1", corev1.ConditionFalse, nil),
		stuckTerminatingPod("db", "pg-0", "w1", 20*time.Minute))
	cs.PrependReactor("patch", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	dyn := deadNodeDynFake(selfNodeRemediation("medik8s", "w1"))
	s := deadNodeSweeperFor(cs, dyn, nil)
	if err := s.run(ctx); err != nil {
		t.Fatalf("taint failure must not fail the run: %v", err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
		t.Fatal("taint applied despite the rejected patch")
	}
}

// A missing medik8s CRD (NotFound/NoMatch on list) is "no evidence"
// and the scan continues to the next GVR — other errors are real.
func TestDeadNodeSweeperRemediationCRDMissing(t *testing.T) {
	dyn := deadNodeDynFake()
	dyn.PrependReactor("list", "selfnoderemediations",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(
				schema.GroupResource{
					Group:    selfNodeRemediationGVR.Group,
					Resource: selfNodeRemediationGVR.Resource,
				}, "")
		})
	s := deadNodeSweeperFor(fake.NewSimpleClientset(), dyn, nil)
	fenced, err := s.hasRemediationCR(ctx, "w1")
	if err != nil || fenced {
		t.Fatalf("missing CRD must read as no-evidence, got fenced=%v err=%v", fenced, err)
	}
}

func TestDeadNodeSweeperDynamicListError(t *testing.T) {
	// A real failure reading remediation CRs -> fail closed, node
	// skipped, run itself still succeeds (per-node error).
	cs := fake.NewSimpleClientset(
		testutil.Node("w1", corev1.ConditionFalse, nil),
		stuckTerminatingPod("db", "pg-0", "w1", 20*time.Minute))
	dyn := deadNodeDynFake()
	dyn.PrependReactor("list", "selfnoderemediations",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("snr list boom")
		})
	s := deadNodeSweeperFor(cs, dyn,
		func(context.Context, string) (bool, error) { return false, nil })

	if err := s.run(ctx); err != nil {
		t.Fatalf("per-node fencing check failure must not fail the run: %v", err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
		t.Fatal("node tainted though the fencing check itself errored")
	}
}
