package deadnodesweeper

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
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
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ctx is the sweep context every test in the package shares.
var ctx = context.Background()

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

// W12 P0-7 — medik8s NHC v0.6+ names remediation CRs
// "<nodeName>-<templateName>" under escalatingRemediations /
// multi-template setups, and may carry the target in
// remediation.medik8s.io/node-name. Both shapes are fencing
// evidence — a name-equality-only match misses the fencing proof.
func TestDeadNodeSweeperRemediationCRNameVariants(t *testing.T) {
	t.Run("template-suffixed CR name", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			testutil.Node("w1", corev1.ConditionFalse, nil),
			stuckTerminatingPod("db", "pg-0", "w1", 20*time.Minute))
		dyn := deadNodeDynFake(
			selfNodeRemediation("medik8s", "w1-snr-template"))
		s := deadNodeSweeperFor(cs, dyn, nil)

		if err := s.run(ctx); err != nil {
			t.Fatal(err)
		}
		if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
			t.Fatal("template-suffixed SelfNodeRemediation not accepted as fencing evidence")
		}
	})

	t.Run("node-name annotation on an unrelated name", func(t *testing.T) {
		cr := selfNodeRemediation("medik8s", "snr-7f9b2d")
		cr.SetAnnotations(map[string]string{
			"remediation.medik8s.io/node-name": "w1"})
		cs := fake.NewSimpleClientset(
			testutil.Node("w1", corev1.ConditionFalse, nil),
			stuckTerminatingPod("db", "pg-0", "w1", 20*time.Minute))
		dyn := deadNodeDynFake(cr)
		s := deadNodeSweeperFor(cs, dyn, nil)

		if err := s.run(ctx); err != nil {
			t.Fatal(err)
		}
		if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
			t.Fatal("node-name annotation not accepted as fencing evidence")
		}
	})

	t.Run("annotation naming a different node is not evidence", func(t *testing.T) {
		cr := selfNodeRemediation("medik8s", "snr-7f9b2d")
		cr.SetAnnotations(map[string]string{
			"remediation.medik8s.io/node-name": "w2"})
		cs := fake.NewSimpleClientset(
			testutil.Node("w1", corev1.ConditionFalse, nil),
			stuckTerminatingPod("db", "pg-0", "w1", 20*time.Minute))
		dyn := deadNodeDynFake(cr)
		s := deadNodeSweeperFor(cs, dyn, nil)

		if err := s.run(ctx); err != nil {
			t.Fatal(err)
		}
		if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
			t.Fatal("node tainted by an annotation naming a different node")
		}
	})
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
	fenced, err := s.hasRemediationCR(ctx, "w1", &remediationCache{}, nil)
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

// ---------------------------------------------------------------------------
// The branch-(b) stateful split-brain gate.
// ---------------------------------------------------------------------------

// stsOwnedTerminatingPod is a stuck pod owned by a StatefulSet.
func stsOwnedTerminatingPod(ns, name, nodeName string, age time.Duration) *corev1.Pod {
	p := stuckTerminatingPod(ns, name, nodeName, age)
	p.OwnerReferences = []metav1.OwnerReference{{
		Kind: "StatefulSet", Name: "pg", Controller: ptr.To(true)}}
	return p
}

// rwoVolumeAttachment is a PV-referenced attachment; pair it with
// rwoPV so the access modes resolve off the PV census.
func rwoVolumeAttachment(name, nodeName, pvName string) *storagev1.VolumeAttachment {
	return &storagev1.VolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: storagev1.VolumeAttachmentSpec{
			NodeName: nodeName,
			Attacher: "csi.test",
			Source: storagev1.VolumeAttachmentSource{
				PersistentVolumeName: ptr.To(pvName),
			},
		},
	}
}

func pvWithModes(name string, modes ...corev1.PersistentVolumeAccessMode) *corev1.PersistentVolume {
	return &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.PersistentVolumeSpec{AccessModes: modes},
	}
}

// deadProbe is the kubelet /healthz stub for branch (b): kubelet does
// not answer.
func deadProbe(context.Context, string) (bool, error) { return false, nil }

// A confirmed-dead branch-(b) node (no SNR CR) holding a StatefulSet
// pod is refused: no taint, the skip gauge fires, the fence counter
// stays silent.
func TestDeadNodeSweeperUnfencedStatefulSkipsSTS(t *testing.T) {
	testutil.CleanupMetric(t, metrics.DeadNodeUnfencedStatefulSkipped, "w1")
	testutil.CleanupMetric(t, metrics.DeadNodeFencedWithoutSNRTotal, "w1", "true")
	testutil.CleanupMetric(t, metrics.DeadNodeFencedWithoutSNRTotal, "w1", "false")

	cs := fake.NewSimpleClientset(
		unknownNode("w1", 45*time.Minute),
		stsOwnedTerminatingPod("db", "pg-0", "w1", 20*time.Minute))
	s := deadNodeSweeperFor(cs, deadNodeDynFake(), deadProbe)

	if err := s.run(ctx); err != nil {
		t.Fatal(err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
		t.Fatal("stateful-holding node fenced without a SNR CR or the override")
	}
	if got := ptestutil.ToFloat64(metrics.DeadNodeUnfencedStatefulSkipped.WithLabelValues("w1")); got != 1 {
		t.Fatalf("skip gauge = %v, want 1", got)
	}
	if got := ptestutil.ToFloat64(metrics.DeadNodeFencedWithoutSNRTotal.WithLabelValues("w1", "true")); got != 0 {
		t.Fatalf("fence counter(has_volumes=true) incremented on a skipped node: %v", got)
	}
	if got := ptestutil.ToFloat64(metrics.DeadNodeFencedWithoutSNRTotal.WithLabelValues("w1", "false")); got != 0 {
		t.Fatalf("fence counter(has_volumes=false) incremented on a skipped node: %v", got)
	}
}

// An RWO PV-backed VolumeAttachment alone holds the gate even with a
// plain (ReplicaSet-shaped) pod population.
func TestDeadNodeSweeperUnfencedStatefulSkipsRWOAttachment(t *testing.T) {
	testutil.CleanupMetric(t, metrics.DeadNodeUnfencedStatefulSkipped, "w1")

	cs := fake.NewSimpleClientset(
		unknownNode("w1", 45*time.Minute),
		stuckTerminatingPod("web", "web-abc", "w1", 20*time.Minute),
		pvWithModes("pv-rwo", corev1.ReadWriteOnce),
		rwoVolumeAttachment("va-rwo", "w1", "pv-rwo"))
	s := deadNodeSweeperFor(cs, deadNodeDynFake(), deadProbe)

	if err := s.run(ctx); err != nil {
		t.Fatal(err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
		t.Fatal("RWO-attachment node fenced without a SNR CR or the override")
	}
	if got := ptestutil.ToFloat64(metrics.DeadNodeUnfencedStatefulSkipped.WithLabelValues("w1")); got != 1 {
		t.Fatalf("skip gauge = %v, want 1", got)
	}
}

// A branch-(b) node with only stateless holders (plain pod, ROX
// volume) fences as before and the without-SNR counter fires with
// has_volumes=false.
func TestDeadNodeSweeperStatelessBranchBFences(t *testing.T) {
	testutil.CleanupMetric(t, metrics.DeadNodeUnfencedStatefulSkipped, "w1")
	testutil.CleanupMetric(t, metrics.DeadNodeFencedWithoutSNRTotal, "w1", "false")

	cs := fake.NewSimpleClientset(
		unknownNode("w1", 45*time.Minute),
		stuckTerminatingPod("web", "web-abc", "w1", 20*time.Minute),
		// ReadWriteMany does not hold the gate — multi-writer safe.
		pvWithModes("pv-rox", corev1.ReadWriteMany),
		rwoVolumeAttachment("va-rox", "w1", "pv-rox"))
	s := deadNodeSweeperFor(cs, deadNodeDynFake(), deadProbe)

	if err := s.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
		t.Fatal("stateless dead node not fenced")
	}
	if got := ptestutil.ToFloat64(metrics.DeadNodeFencedWithoutSNRTotal.WithLabelValues("w1", "false")); got != 1 {
		t.Fatalf("fence counter(has_volumes=false) = %v, want 1", got)
	}
	if got := ptestutil.ToFloat64(metrics.DeadNodeUnfencedStatefulSkipped.WithLabelValues("w1")); got != 0 {
		t.Fatalf("skip gauge set on a fenced node: %v", got)
	}
}

// The DEAD_NODE_SWEEPER_FENCE_UNFENCED_STATEFUL=true override fences
// through the gate — counted with has_volumes=true — and clears any
// stale skip flag from earlier cycles.
func TestDeadNodeSweeperOverrideForcesStatefulFence(t *testing.T) {
	t.Setenv("DEAD_NODE_SWEEPER_FENCE_UNFENCED_STATEFUL", "true")
	testutil.CleanupMetric(t, metrics.DeadNodeUnfencedStatefulSkipped, "w1")
	testutil.CleanupMetric(t, metrics.DeadNodeFencedWithoutSNRTotal, "w1", "true")
	// A stale skip flag from a previous gate-off cycle.
	metrics.DeadNodeUnfencedStatefulSkipped.WithLabelValues("w1").Set(1)

	cs := fake.NewSimpleClientset(
		unknownNode("w1", 45*time.Minute),
		stsOwnedTerminatingPod("db", "pg-0", "w1", 20*time.Minute),
		pvWithModes("pv-rwo", corev1.ReadWriteOnce),
		rwoVolumeAttachment("va-rwo", "w1", "pv-rwo"))
	s := deadNodeSweeperFor(cs, deadNodeDynFake(), deadProbe)

	if err := s.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
		t.Fatal("override did not force the fence")
	}
	if got := ptestutil.ToFloat64(metrics.DeadNodeFencedWithoutSNRTotal.WithLabelValues("w1", "true")); got != 1 {
		t.Fatalf("fence counter(has_volumes=true) = %v, want 1", got)
	}
	if got := ptestutil.ToFloat64(metrics.DeadNodeUnfencedStatefulSkipped.WithLabelValues("w1")); got != 0 {
		t.Fatalf("stale skip gauge survived the fence: %v", got)
	}
}

// Branch (a) is untouched: a node with a medik8s SNR CR fences even
// while holding StatefulSet pods and RWO volumes — the fencer certified
// the death, so no split-brain window remains — and no without-SNR
// counter fires.
func TestDeadNodeSweeperViaSNRIgnoresStatefulGate(t *testing.T) {
	testutil.CleanupMetric(t, metrics.DeadNodeUnfencedStatefulSkipped, "w1")
	testutil.CleanupMetric(t, metrics.DeadNodeFencedWithoutSNRTotal, "w1", "true")
	testutil.CleanupMetric(t, metrics.DeadNodeFencedWithoutSNRTotal, "w1", "false")

	cs := fake.NewSimpleClientset(
		testutil.Node("w1", corev1.ConditionFalse, nil),
		stsOwnedTerminatingPod("db", "pg-0", "w1", 20*time.Minute),
		pvWithModes("pv-rwo", corev1.ReadWriteOnce),
		rwoVolumeAttachment("va-rwo", "w1", "pv-rwo"))
	dyn := deadNodeDynFake(selfNodeRemediation("medik8s", "w1"))
	probeCalled := false
	s := deadNodeSweeperFor(cs, dyn, func(context.Context, string) (bool, error) {
		probeCalled = true
		return false, nil
	})

	if err := s.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
		t.Fatal("SNR-backed node refused fencing by the stateful gate")
	}
	if probeCalled {
		t.Fatal("kubelet probe ran for an SNR-certified node")
	}
	if got := ptestutil.ToFloat64(metrics.DeadNodeFencedWithoutSNRTotal.WithLabelValues("w1", "true")); got != 0 {
		t.Fatalf("without-SNR counter incremented on an SNR-backed fence: %v", got)
	}
	if got := ptestutil.ToFloat64(metrics.DeadNodeFencedWithoutSNRTotal.WithLabelValues("w1", "false")); got != 0 {
		t.Fatalf("without-SNR counter incremented on an SNR-backed fence: %v", got)
	}
}

// A stateful-holder list failure fails closed: no taint, the run still
// succeeds (per-node error, same tolerance as the remediation list).
func TestDeadNodeSweeperHolderListErrorFailsClosed(t *testing.T) {
	cs := fake.NewSimpleClientset(
		unknownNode("w1", 45*time.Minute),
		stuckTerminatingPod("web", "web-abc", "w1", 20*time.Minute))
	cs.PrependReactor("list", "persistentvolumes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("pv list boom")
		})
	s := deadNodeSweeperFor(cs, deadNodeDynFake(), deadProbe)

	if err := s.run(ctx); err != nil {
		t.Fatalf("holder list failure must not fail the run: %v", err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
		t.Fatal("node fenced while the holder check was unverifiable")
	}
}

// The skip gauge is ledger-managed: a node Set(1)'d by the split-brain
// gate keeps its series while it stays skipped, and the recovery
// untaint (same path that removes the taint) deletes the stale series
// instead of leaving a resolved node flagged unfenced-dead forever.
func TestDeadNodeSweeperSkipGaugeClearedOnRecovery(t *testing.T) {
	testutil.CleanupMetric(t, metrics.DeadNodeUnfencedStatefulSkipped, "w1")

	cs := fake.NewSimpleClientset(
		unknownNode("w1", 45*time.Minute),
		stsOwnedTerminatingPod("db", "pg-0", "w1", 20*time.Minute),
		pvWithModes("pv-rwo", corev1.ReadWriteOnce),
		rwoVolumeAttachment("va-rwo", "w1", "pv-rwo"))
	s := deadNodeSweeperFor(cs, deadNodeDynFake(), deadProbe)

	// Sweep 1: the node is branch-(b) dead holding a StatefulSet pod
	// + RWO volume — skipped, gauge armed.
	if err := s.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := ptestutil.ToFloat64(metrics.DeadNodeUnfencedStatefulSkipped.WithLabelValues("w1")); got != 1 {
		t.Fatalf("skip gauge = %v, want 1", got)
	}

	// Sweep 2: the node came back Ready while still carrying the
	// out-of-service taint.
	n := testutil.GetNode(t, cs, "w1")
	for i := range n.Status.Conditions {
		if n.Status.Conditions[i].Type == corev1.NodeReady {
			n.Status.Conditions[i].Status = corev1.ConditionTrue
		}
	}
	if _, err := cs.CoreV1().Nodes().Update(ctx, n, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := s.run(ctx); err != nil {
		t.Fatal(err)
	}
	if kube.HasTaint(testutil.GetNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
		t.Fatal("recovered node still carries out-of-service taint")
	}
	if got := ptestutil.CollectAndCount(metrics.DeadNodeUnfencedStatefulSkipped); got != 0 {
		t.Fatalf("skip gauge still exposes %d series after recovery, want 0", got)
	}
	if got := ptestutil.ToFloat64(metrics.DeadNodeUnfencedStatefulSkipped.WithLabelValues("w1")); got != 0 {
		t.Fatalf("skip gauge = %v after recovery, want 0 (series deleted)", got)
	}
}

// The without-SNR fence counter must not leak {node,has_volumes}
// series on node churn: the fence books its tuple into the
// carry-forward ledger, later sweeps keep the series while the node
// is still listed, and the sweep that first sees the node gone
// deletes it (same lifecycle as the DeadNodeUnfencedStatefulSkipped
// gauge sibling).
func TestDeadNodeSweeperFencedWithoutSNRSeriesPrunedOnNodeGone(t *testing.T) {
	testutil.CleanupMetric(t, metrics.DeadNodeFencedWithoutSNRTotal, "w1", "false")

	cs := fake.NewSimpleClientset(
		unknownNode("w1", 45*time.Minute),
		stuckTerminatingPod("web", "web-abc", "w1", 20*time.Minute))
	s := deadNodeSweeperFor(cs, deadNodeDynFake(), deadProbe)

	// Sweep 1 — the branch-(b) fence Inc's the counter.
	if err := s.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := ptestutil.ToFloat64(metrics.DeadNodeFencedWithoutSNRTotal.WithLabelValues("w1", "false")); got != 1 {
		t.Fatalf("fence counter(has_volumes=false) = %v, want 1", got)
	}

	// Sweep 2 — w1 still listed, nothing stuck anymore: the
	// early-exit prune must carry the series forward, not retire it.
	if err := cs.CoreV1().Pods("web").Delete(ctx, "web-abc", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := s.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := ptestutil.ToFloat64(metrics.DeadNodeFencedWithoutSNRTotal.WithLabelValues("w1", "false")); got != 1 {
		t.Fatalf("fence counter series pruned while its node is still listed: %v", got)
	}

	// Sweep 3 — w1 left the cluster: the prune must delete the
	// series. CollectAndCount is the proof (WithLabelValues would
	// silently re-create the series at 0).
	if err := cs.CoreV1().Nodes().Delete(ctx, "w1", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := s.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := ptestutil.CollectAndCount(metrics.DeadNodeFencedWithoutSNRTotal); got != 0 {
		t.Fatalf("fence counter series survived its node: %d series left", got)
	}
}
