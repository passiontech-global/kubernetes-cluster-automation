package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
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
	n := node(name, corev1.ConditionUnknown, nil)
	n.Status.Conditions[0].LastTransitionTime = metav1.NewTime(time.Now().Add(-age))
	return n
}

// remediationObj builds a medik8s remediation CR (unstructured).
func remediationObj(gvr schema.GroupVersionResource, kind, ns, name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": gvr.GroupVersion().String(),
		"kind":       kind,
		"metadata": map[string]any{
			"namespace": ns,
			"name":      name, // remediation CRs are named after the node
		},
	}}
}

func selfNodeRemediation(ns, name string) *unstructured.Unstructured {
	return remediationObj(selfNodeRemediationGVR, "SelfNodeRemediation", ns, name)
}

func fenceAgentsRemediation(ns, name string) *unstructured.Unstructured {
	return remediationObj(fenceAgentsRemediationGVR, "FenceAgentsRemediation", ns, name)
}

// deadNodeDynFake returns a dynamic fake that knows the list kinds for
// both medik8s GVRs.
func deadNodeDynFake(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			selfNodeRemediationGVR:    "SelfNodeRemediationList",
			fenceAgentsRemediationGVR: "FenceAgentsRemediationList",
		},
		objs...)
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
		node("w1", corev1.ConditionFalse, nil),
		stuckTerminatingPod("db", "pg-0", "w1", 20*time.Minute))
	dyn := deadNodeDynFake(selfNodeRemediation("medik8s", "w1"))
	s := deadNodeSweeperFor(cs, dyn, nil)

	if err := s.run(ctx); err != nil {
		t.Fatal(err)
	}
	got := getNode(t, cs, "w1")
	if !hasTaint(got.Spec.Taints, outOfServiceTaintKey) {
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
		node("w1", corev1.ConditionTrue, nil),
		stuckTerminatingPod("db", "pg-0", "w1", 20*time.Minute))
	// Even with a remediation CR present — a Ready node is the host
	// watchdog's problem, never ours.
	dyn := deadNodeDynFake(selfNodeRemediation("medik8s", "w1"))
	s := deadNodeSweeperFor(cs, dyn, nil)

	if err := s.run(ctx); err != nil {
		t.Fatal(err)
	}
	if hasTaint(getNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
		t.Fatal("Ready node tainted — should have been skipped")
	}
}

func TestDeadNodeSweeperFailClosedNoEvidence(t *testing.T) {
	t.Run("NotReady without remediation CR", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			node("w1", corev1.ConditionFalse, nil),
			stuckTerminatingPod("db", "pg-0", "w1", 20*time.Minute))
		// A CR for a DIFFERENT node must not count as evidence.
		dyn := deadNodeDynFake(selfNodeRemediation("medik8s", "other-node"))
		s := deadNodeSweeperFor(cs, dyn, nil)

		if err := s.run(ctx); err != nil {
			t.Fatal(err)
		}
		if hasTaint(getNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
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
		if hasTaint(getNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
			t.Fatal("node tainted inside the 30m Unknown window")
		}
	})

	t.Run("fresh Terminating pods are ignored", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			node("w1", corev1.ConditionFalse, nil),
			stuckTerminatingPod("db", "pg-0", "w1", 5*time.Minute)) // < 15m
		dyn := deadNodeDynFake(selfNodeRemediation("medik8s", "w1"))
		s := deadNodeSweeperFor(cs, dyn, nil)

		if err := s.run(ctx); err != nil {
			t.Fatal(err)
		}
		if hasTaint(getNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
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
		if !hasTaint(getNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
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
		if !hasTaint(getNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
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
		if hasTaint(getNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
			t.Fatal("node tainted though its kubelet answers healthz")
		}
	})
}

func TestDeadNodeSweeperFenceAgentsCR(t *testing.T) {
	cs := fake.NewSimpleClientset(
		node("w1", corev1.ConditionFalse, nil),
		stuckTerminatingPod("db", "pg-0", "w1", 20*time.Minute))
	dyn := deadNodeDynFake(fenceAgentsRemediation("medik8s", "w1"))
	s := deadNodeSweeperFor(cs, dyn, nil)

	if err := s.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !hasTaint(getNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
		t.Fatal("fenceagentsremediation CR not accepted as fencing evidence")
	}
}

func TestDeadNodeSweeperUntaintsRecoveredNode(t *testing.T) {
	cs := fake.NewSimpleClientset(
		node("w1", corev1.ConditionTrue, nil, outOfServiceTaint))
	dyn := deadNodeDynFake()
	s := deadNodeSweeperFor(cs, dyn, nil)

	if err := s.run(ctx); err != nil {
		t.Fatal(err)
	}
	if hasTaint(getNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
		t.Fatal("recovered node still carries out-of-service taint")
	}
}

func TestDeadNodeSweeperCapOnePerCycle(t *testing.T) {
	cs := fake.NewSimpleClientset(
		node("w1", corev1.ConditionFalse, nil),
		node("w2", corev1.ConditionFalse, nil),
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
		if hasTaint(getNode(t, cs, name).Spec.Taints, outOfServiceTaintKey) {
			tainted++
		}
	}
	if tainted != deadNodeCap {
		t.Fatalf("expected exactly %d node tainted per cycle, got %d", deadNodeCap, tainted)
	}
	// Deterministic order: w1 sorts first, so it is the one tainted.
	if !hasTaint(getNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
		t.Fatal("expected w1 (first sorted) to be the capped-out node")
	}
}

func TestDeadNodeSweeperVolumeAttachments(t *testing.T) {
	t.Run("listing is signal-only — node still tainted", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			node("w1", corev1.ConditionFalse, nil),
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
		if !hasTaint(getNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
			t.Fatal("node not tainted")
		}
	})

	t.Run("list failure is non-fatal", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			node("w1", corev1.ConditionFalse, nil),
			stuckTerminatingPod("db", "pg-0", "w1", 20*time.Minute))
		cs.Fake.PrependReactor("list", "volumeattachments",
			func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("va list boom")
			})
		dyn := deadNodeDynFake(selfNodeRemediation("medik8s", "w1"))
		s := deadNodeSweeperFor(cs, dyn, nil)

		if err := s.run(ctx); err != nil {
			t.Fatalf("volumeattachment list failure must not fail the run: %v", err)
		}
		if !hasTaint(getNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
			t.Fatal("taint vetoed by a volumeattachment list failure")
		}
	})
}

func TestDeadNodeSweeperMissingNode(t *testing.T) {
	// Stuck pod references a node object the apiserver no longer has.
	cs := fake.NewSimpleClientset(
		node("w1", corev1.ConditionTrue, nil),
		stuckTerminatingPod("db", "pg-0", "ghost", 20*time.Minute))
	dyn := deadNodeDynFake()
	s := deadNodeSweeperFor(cs, dyn, nil)

	if err := s.run(ctx); err != nil {
		t.Fatalf("missing node must be a skip, not a run failure: %v", err)
	}
}

func TestDeadNodeSweeperDynamicListError(t *testing.T) {
	// A real failure reading remediation CRs -> fail closed, node
	// skipped, run itself still succeeds (per-node error).
	cs := fake.NewSimpleClientset(
		node("w1", corev1.ConditionFalse, nil),
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
	if hasTaint(getNode(t, cs, "w1").Spec.Taints, outOfServiceTaintKey) {
		t.Fatal("node tainted though the fencing check itself errored")
	}
}
