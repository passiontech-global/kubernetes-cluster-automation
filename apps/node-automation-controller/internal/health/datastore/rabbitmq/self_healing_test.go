// self_healing_test.go — the rabbitmq-suspended-listener healer's
// fake-clientset coverage (the suspended-pod wedge signature, the
// quorum-gated heal and its cooldown/resume paths). Moved with the
// check into the rabbitmq subpackage — see rabbitmq_suspended_listener.go
// for the check and its complementary coverage file.
package rabbitmq

import (
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// shRabbitPod builds a rabbitmq-labeled pod in the suspended-listener
// wedge (Running, started-but-never-Ready) unless overridden.
func shRabbitPod(ns, name string, uid types.UID, started, ready bool) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name, UID: uid,
			Labels: map[string]string{"app.kubernetes.io/component": "rabbitmq"},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "StatefulSet",
				Name: "rabbitmq", Controller: ptr.To(true),
			}},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{{
				Type:   corev1.PodReady,
				Status: map[bool]corev1.ConditionStatus{true: corev1.ConditionTrue, false: corev1.ConditionFalse}[ready],
			}},
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "rabbitmq", Started: ptr.To(started), Ready: ready,
			}},
		},
	}
}

// The signature itself: Running + every container started + none
// Ready — a still-starting container (Started=nil) or a terminal
// pod is never flagged.
func TestRabbitSuspendedSignature(t *testing.T) {
	if !rabbitSuspended(shRabbitPod("mq", "rabbitmq-0", "u1", true, false)) {
		t.Fatal("started-but-unready running pod must flag")
	}
	if rabbitSuspended(shRabbitPod("mq", "rabbitmq-0", "u1", true, true)) {
		t.Fatal("a ready pod must not flag")
	}
	unstarted := shRabbitPod("mq", "rabbitmq-0", "u1", true, false)
	unstarted.Status.ContainerStatuses[0].Started = nil
	if rabbitSuspended(unstarted) {
		t.Fatal("a container still starting must not flag")
	}
	pending := shRabbitPod("mq", "rabbitmq-0", "u1", true, false)
	pending.Status.Phase = corev1.PodPending
	if rabbitSuspended(pending) {
		t.Fatal("a pending pod must not flag")
	}
}

// Stuck >=10m with all peers Ready → the suspended pod is deleted and
// the heals counter moves; the check FAILs either way.
func TestCheckRabbitMQSuspendedHeals(t *testing.T) {
	base := time.Now()
	replicas := int32(3)
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "mq", Name: "rabbitmq"},
		Spec: appsv1.StatefulSetSpec{
			// BUG-C2: quorum is verified against spec.replicas — a
			// fixture without it is refused outright.
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app.kubernetes.io/component": "rabbitmq"}},
		},
	}
	stuck := shRabbitPod("mq", "rabbitmq-0", "u0", true, false)
	peer1 := shRabbitPod("mq", "rabbitmq-1", "u1", true, true)
	peer2 := shRabbitPod("mq", "rabbitmq-2", "u2", true, true)
	cs := fake.NewSimpleClientset(sts, stuck, peer1, peer2)
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	before := func() float64 {
		m := probetest.FindMetric(t, "node_automation_rabbitmq_suspended_heals_total",
			map[string]string{"namespace": "mq", "pod": "rabbitmq-0"})
		if m == nil {
			return 0
		}
		return m.GetCounter().GetValue()
	}()
	t.Cleanup(func() {
		rabbitMQSuspendedHealsTotal.DeleteLabelValues("mq", "rabbitmq-0")
	})

	// First sighting — tracked, quiet, pod kept.
	if res := probetest.MustCheck[*rabbitMQSuspendedCheck](t, p).Run(probetest.SweepCtx(ctx)); !res.Pass {
		t.Fatalf("first-seen suspended pod must pass: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "rabbitmq-0", metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted before the 10m window")
	}

	at := base.Add(11 * time.Minute)
	p.Now = func() time.Time { return at }
	if res := probetest.MustCheck[*rabbitMQSuspendedCheck](t, p).Run(probetest.SweepCtx(ctx)); res.Pass {
		t.Fatal("suspended >=10m with quorum safe must FAIL")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "rabbitmq-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("suspended pod must be deleted, err=%v", err)
	}
	m := probetest.FindMetric(t, "node_automation_rabbitmq_suspended_heals_total",
		map[string]string{"namespace": "mq", "pod": "rabbitmq-0"})
	var got float64
	if m != nil {
		got = m.GetCounter().GetValue()
	}
	if got != before+1 {
		t.Fatalf("heals total = %v, want %v", got, before+1)
	}
}

// Restart resume: a suspended pod still carrying the persisted
// first-seen stamp past the 10m window heals on the FIRST
// post-restart sweep — the in-RAM ledger is empty but the annotation
// proves the suspended-listener wedge held.
func TestCheckRabbitMQSuspendedRestartResume(t *testing.T) {
	base := time.Now()
	replicas := int32(3)
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "mq", Name: "rabbitmq"},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app.kubernetes.io/component": "rabbitmq"}},
		},
	}
	stuck := shRabbitPod("mq", "rabbitmq-0", "u0", true, false)
	stuck.Annotations = map[string]string{
		kube.AnnoFirstSeenRabbitSuspended: `{"mq/rabbitmq-0/u0":"` +
			base.Add(-11*time.Minute).UTC().Format(time.RFC3339) + `"}`}
	peer1 := shRabbitPod("mq", "rabbitmq-1", "u1", true, true)
	peer2 := shRabbitPod("mq", "rabbitmq-2", "u2", true, true)
	cs := fake.NewSimpleClientset(sts, stuck, peer1, peer2)
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	t.Cleanup(func() {
		rabbitMQSuspendedHealsTotal.DeleteLabelValues("mq", "rabbitmq-0")
	})

	if res := probetest.MustCheck[*rabbitMQSuspendedCheck](t, p).Run(probetest.SweepCtx(ctx)); res.Pass {
		t.Fatal("persisted suspended window past 10m must FAIL on the first sweep")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "rabbitmq-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("resumed window must heal on the first sweep, err=%v", err)
	}
}

// A suspended pod whose peers are NOT all Ready is kept — the delete
// could take the cluster below quorum; the FAIL series keeps alerting.
func TestCheckRabbitMQSuspendedQuorumUnsafe(t *testing.T) {
	base := time.Now()
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "mq", Name: "rabbitmq"},
		Spec: appsv1.StatefulSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app.kubernetes.io/component": "rabbitmq"}},
		},
	}
	stuck := shRabbitPod("mq", "rabbitmq-0", "u0", true, false)
	peerDown := shRabbitPod("mq", "rabbitmq-1", "u1", true, false) // also unready
	cs := fake.NewSimpleClientset(sts, stuck, peerDown)
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*rabbitMQSuspendedCheck](t, p).rbSuspendedSince.
		Observe("mq/rabbitmq-0/u0", base.Add(-time.Hour))

	if res := probetest.MustCheck[*rabbitMQSuspendedCheck](t, p).Run(probetest.SweepCtx(ctx)); res.Pass {
		t.Fatal("suspended pod must still FAIL — quorum gate only blocks the heal")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "rabbitmq-0", metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted with a peer down — quorum unsafe")
	}
}

// A pod not owned by a StatefulSet cannot have its quorum verified —
// the heal stands down.
func TestCheckRabbitMQSuspendedNoSTSOwner(t *testing.T) {
	base := time.Now()
	stuck := shRabbitPod("mq", "rabbitmq-0", "u0", true, false)
	stuck.OwnerReferences = nil // bare pod — no quorum chain
	cs := fake.NewSimpleClientset(stuck)
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*rabbitMQSuspendedCheck](t, p).rbSuspendedSince.
		Observe("mq/rabbitmq-0/u0", base.Add(-time.Hour))

	if res := probetest.MustCheck[*rabbitMQSuspendedCheck](t, p).Run(probetest.SweepCtx(ctx)); res.Pass {
		t.Fatal("suspended pod must FAIL")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "rabbitmq-0", metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted with no StatefulSet owner — quorum unverifiable")
	}
}

// Inside the 30m heal cooldown a same-named suspended pod is kept.
func TestCheckRabbitMQSuspendedCooldown(t *testing.T) {
	base := time.Now()
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "mq", Name: "rabbitmq"},
		Spec: appsv1.StatefulSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app.kubernetes.io/component": "rabbitmq"}},
		},
	}
	stuck := shRabbitPod("mq", "rabbitmq-0", "u0", true, false)
	peer := shRabbitPod("mq", "rabbitmq-1", "u1", true, true)
	cs := fake.NewSimpleClientset(sts, stuck, peer)
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*rabbitMQSuspendedCheck](t, p).rbSuspendedSince.
		Observe("mq/rabbitmq-0/u0", base.Add(-time.Hour))
	probetest.MustCheck[*rabbitMQSuspendedCheck](t, p).rbHealed.
		Stamp("mq/rabbitmq-0", base.Add(-10*time.Minute))

	if res := probetest.MustCheck[*rabbitMQSuspendedCheck](t, p).Run(probetest.SweepCtx(ctx)); res.Pass {
		t.Fatal("suspended pod must FAIL even inside the heal cooldown")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "rabbitmq-0", metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted inside the 30m heal cooldown")
	}
}
