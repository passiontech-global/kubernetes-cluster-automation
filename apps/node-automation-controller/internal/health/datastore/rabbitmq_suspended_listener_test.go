// rabbitmq_suspended_listener_test.go — coverage for the quorum
// gates and heal guards self_healing_test.go's W6.4 section does
// not reach: the BUG-C2 count check (fewer live pods than
// spec.replicas can never prove a delete leaves quorum), the
// "not every other replica Ready" sibling check reached only once
// the count passes, the maintenance-mutex defer and the pod-list
// Infra path, plus the terminating-pod signature exemption.
package datastore

import (
	"errors"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// rabbitSTS builds the owning StatefulSet with an explicit replica
// count — the BUG-C2 quorum math is anchored on spec.replicas, so
// every quorum test fixture must carry it.
func rabbitSTS(ns string, replicas int32) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "rabbitmq"},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app.kubernetes.io/component": "rabbitmq"}},
		},
	}
}

// BUG-C2: a mid-churn set where fewer pods than spec.replicas even
// EXIST cannot prove the delete leaves quorum — the suspended pod
// plus one Ready peer against a desired 3 means the third vote is
// unaccounted for. The pod is kept and the FAIL series keeps
// alerting.
func TestCheckRabbitMQSuspendedUnderCountUnsafe(t *testing.T) {
	base := time.Now()
	sts := rabbitSTS("mq", 3)
	stuck := shRabbitPod("mq", "rabbitmq-0", "u0", true, false)
	peer := shRabbitPod("mq", "rabbitmq-1", "u1", true, true)
	cs := fake.NewSimpleClientset(sts, stuck, peer)
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*rabbitMQSuspendedCheck](t, p).rbSuspendedSince.
		Observe("mq/rabbitmq-0/u0", base.Add(-time.Hour))

	if res := probetest.MustCheck[*rabbitMQSuspendedCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("suspended pod must still FAIL — the quorum gate only blocks the heal")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "rabbitmq-0", metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted while live pods < spec.replicas — quorum unproven")
	}
}

// The count passes but a sibling is not Ready: replicas=3 with the
// suspended pod, one Ready peer and a still-STARTING peer (Started
// unset — itself not yet suspended, but not a quorum vote either).
// ReadySiblings < replicas-1 → the heal stands down.
func TestCheckRabbitMQSuspendedUnreadySiblingUnsafe(t *testing.T) {
	base := time.Now()
	sts := rabbitSTS("mq", 3)
	stuck := shRabbitPod("mq", "rabbitmq-0", "u0", true, false)
	peer := shRabbitPod("mq", "rabbitmq-1", "u1", true, true)
	starting := shRabbitPod("mq", "rabbitmq-2", "u2", true, false)
	starting.Status.ContainerStatuses[0].Started = nil // still launching
	cs := fake.NewSimpleClientset(sts, stuck, peer, starting)
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*rabbitMQSuspendedCheck](t, p).rbSuspendedSince.
		Observe("mq/rabbitmq-0/u0", base.Add(-time.Hour))

	if res := probetest.MustCheck[*rabbitMQSuspendedCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("suspended pod must FAIL — only the heal is gated")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "rabbitmq-0", metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted with an unready sibling — quorum unsafe")
	}
}

// Deliberate maintenance (a cordoned node) gates the delete like
// every pod kill in this sweep — the signature still FAILs, the pod
// survives.
func TestCheckRabbitMQSuspendedMaintenanceDefers(t *testing.T) {
	base := time.Now()
	cordoned := testutil.Node("w1", corev1.ConditionTrue, nil)
	cordoned.Spec.Unschedulable = true
	sts := rabbitSTS("mq", 3)
	stuck := shRabbitPod("mq", "rabbitmq-0", "u0", true, false)
	peer1 := shRabbitPod("mq", "rabbitmq-1", "u1", true, true)
	peer2 := shRabbitPod("mq", "rabbitmq-2", "u2", true, true)
	cs := fake.NewSimpleClientset(cordoned, sts, stuck, peer1, peer2)
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*rabbitMQSuspendedCheck](t, p).rbSuspendedSince.
		Observe("mq/rabbitmq-0/u0", base.Add(-time.Hour))

	if res := probetest.MustCheck[*rabbitMQSuspendedCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("maintenance must defer the heal, not the detection")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "rabbitmq-0", metav1.GetOptions{}); err != nil {
		t.Fatal("suspended pod deleted during maintenance")
	}
}

// The rabbitmq-labeled pod list is the check's only input — a
// failure marks the check infra-failed rather than reading as
// "no suspended pods".
func TestCheckRabbitMQSuspendedPodListInfra(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	p := testProberDyn(cs, probetest.OpDyn())
	res := probetest.MustCheck[*rabbitMQSuspendedCheck](t, p).Run(ctx)
	if res.Infra == nil {
		t.Fatal("a pod list failure must mark the check infra-failed")
	}
}

// A pod already terminating carries the suspended shape (containers
// started, never Ready) but is no signature — the delete is in
// flight and a second one is never ours to issue.
func TestRabbitSuspendedTerminatingIgnored(t *testing.T) {
	pod := shRabbitPod("mq", "rabbitmq-0", "u0", true, false)
	now := metav1.Now()
	pod.DeletionTimestamp = &now
	if rabbitSuspended(pod) {
		t.Fatal("a terminating pod must not flag the suspended signature")
	}
	// And end-to-end: a terminating pod is not even tracked.
	cs := fake.NewSimpleClientset(pod)
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*rabbitMQSuspendedCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("terminating pod must keep the check quiet: %+v", res)
	}
}
