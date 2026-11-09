// self_healing_test.go — the datastore self-healing checks
// (stateful-masterless-services stateful-masterless guard, rabbitmq-suspended-listener rabbitmq suspended-listener
// healer, percona-cluster-quorum percona quorum) driven through the fake
// clientset + fake dynamic client.
package datastore

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// ---------------------------------------------------------------------------
// stateful-masterless-services — stateful-masterless-services
// ---------------------------------------------------------------------------

// shSTS builds a ready StatefulSet with pod-template labels.
func shSTS(ns, name string, ready int32, labels map[string]string) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name, Labels: labels,
		},
		Spec: appsv1.StatefulSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
			},
		},
		Status: appsv1.StatefulSetStatus{ReadyReplicas: ready},
	}
}

// shMasterSvc builds a ClusterIP Service whose selector routes to the
// STS pods under a master role key.
func shMasterSvc(ns, name string, selector map[string]string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.96.0.10",
			Selector:  selector,
		},
	}
}

func shStatefulZeroGauge(t *testing.T, ns, svc, sts string) (float64, bool) {
	t.Helper()
	m := probetest.FindMetric(t, "node_automation_stateful_service_zero_endpoints",
		map[string]string{"namespace": ns, "service": svc, "statefulset": sts})
	if m == nil {
		return 0, false
	}
	return m.GetGauge().GetValue(), true
}

// shOperatorPod builds the dragonfly-operator leader pod the stateful-masterless-services
// step-1 bounce targets — Running and ReplicaSet-owned, the live
// shape healDragonflyOperator's candidate filter requires (a
// terminating/not-Running/controller-less pod is never a leader to
// bounce).
func shOperatorPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: kube.DragonflyOperatorNS,
			Name:      dragonflyOperatorPodPrefix + "-6f8bc-xy",
			UID:       types.UID("dr-op-1"),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "ReplicaSet",
				Name: dragonflyOperatorPodPrefix + "-6f8bc",
				UID:  types.UID("dr-op-rs-1"), Controller: ptr.To(true),
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

// A master-role Service on a ready STS with 0 Ready endpoints: tracked
// first, gauge at 3m — and because the STS is Dragonfly-owned the
// operator leader gets bounced at 5m to force re-election.
func TestCheckStatefulMasterlessZeroEndpoints(t *testing.T) {
	testutil.CleanupMetric(t, statefulServiceZeroEndpointsGauge, "db", "dragonfly-master", "dragonfly")
	base := time.Now()
	sts := shSTS("db", "dragonfly", 3,
		map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"})
	svc := shMasterSvc("db", "dragonfly-master",
		map[string]string{"app": "dragonfly", "role": "master"})
	opPod := shOperatorPod()
	cs := fake.NewSimpleClientset(sts, svc, opPod)
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	// First sighting — tracked, quiet.
	if res := probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("first-seen zero endpoints must pass: %+v", res)
	}
	key := "db/dragonfly-master/dragonfly"
	if _, ok := probetest.MustCheck[*statefulMasterlessCheck](t, p).stsZeroSince.Seen(key, base); !ok {
		t.Fatal("zero-endpoint tuple not tracked")
	}

	// 4m in — gauge fires, but under the 5m heal window.
	at := base.Add(4 * time.Minute)
	p.Now = func() time.Time { return at }
	if res := probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("zero endpoints >=3m must FAIL")
	}
	if v, _ := shStatefulZeroGauge(t, "db", "dragonfly-master", "dragonfly"); v != 1 {
		t.Fatalf("zero-endpoints gauge = %v, want 1", v)
	}
	if _, err := cs.CoreV1().Pods(kube.DragonflyOperatorNS).
		Get(ctx, opPod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("operator pod deleted before the 5m heal window")
	}

	// 6m in — the dragonfly operator leader is bounced.
	at = base.Add(6 * time.Minute)
	p.Now = func() time.Time { return at }
	if res := probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("still masterless — must keep FAILING")
	}
	if _, err := cs.CoreV1().Pods(kube.DragonflyOperatorNS).
		Get(ctx, opPod.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("dragonfly operator pod must be deleted past 5m, err=%v", err)
	}
}

// Deliberate maintenance (a cordoned node) defers the STEP-1
// dragonfly-operator bounce too — AllowedVPersisted's mutex half
// fails closed even though the zero-endpoint streak and the cooldown
// both cleared (mirrors certdriftauditor's
// TestLinkerdIssuerRolloutDeferredByMaintenanceMutex).
func TestDragonflyOperatorHealMaintenanceDefers(t *testing.T) {
	testutil.CleanupMetric(t, statefulServiceZeroEndpointsGauge, "db", "dragonfly-master", "dragonfly")
	base := time.Now()
	cordoned := testutil.Node("w1", corev1.ConditionTrue, nil)
	cordoned.Spec.Unschedulable = true
	sts := shSTS("db", "dragonfly", 3,
		map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"})
	svc := shMasterSvc("db", "dragonfly-master",
		map[string]string{"app": "dragonfly", "role": "master"})
	opPod := shOperatorPod()
	cs := fake.NewSimpleClientset(cordoned, sts, svc, opPod)
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	// Seed the streak, then sweep past the 5m heal window.
	_ = probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx)
	p.Now = func() time.Time { return base.Add(6 * time.Minute) }
	if res := probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("masterless under maintenance must still FAIL")
	}
	if _, err := cs.CoreV1().Pods(kube.DragonflyOperatorNS).
		Get(ctx, opPod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("operator pod deleted during maintenance")
	}
}

// Restart resume: an STS still carrying the persisted first-seen
// stamp past the 5m heal window bounces the dragonfly operator on
// the FIRST post-restart sweep — the in-RAM ledger is empty but the
// annotation proves the zero-endpoint streak held.
func TestCheckStatefulMasterlessRestartResume(t *testing.T) {
	testutil.CleanupMetric(t, statefulServiceZeroEndpointsGauge, "db", "dragonfly-master", "dragonfly")
	base := time.Now()
	sts := shSTS("db", "dragonfly", 3,
		map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"})
	sts.Annotations = map[string]string{
		kube.AnnoFirstSeenStatefulMasterless: `{"db/dragonfly-master/dragonfly":"` +
			base.Add(-6*time.Minute).UTC().Format(time.RFC3339) + `"}`}
	svc := shMasterSvc("db", "dragonfly-master",
		map[string]string{"app": "dragonfly", "role": "master"})
	opPod := shOperatorPod()
	cs := fake.NewSimpleClientset(sts, svc, opPod)
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("persisted masterless window must FAIL on the first sweep")
	}
	if _, err := cs.CoreV1().Pods(kube.DragonflyOperatorNS).
		Get(ctx, opPod.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("resumed window past 5m must bounce the operator, err=%v", err)
	}
}

// The step-1 candidate filter: a Pending (or otherwise not-Running,
// terminating or controller-less) operator pod is never a leader to
// bounce — deleting such a remnant would lock the shared 30m cooldown
// while the actually-Running leader survives untouched. Only the
// Running, owned pod is deleted.
func TestDragonflyOperatorHealSkipsUnreadyPods(t *testing.T) {
	testutil.CleanupMetric(t, statefulServiceZeroEndpointsGauge, "db", "dragonfly-master", "dragonfly")
	base := time.Now()
	sts := shSTS("db", "dragonfly", 3,
		map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"})
	svc := shMasterSvc("db", "dragonfly-master",
		map[string]string{"app": "dragonfly", "role": "master"})
	pending := shOperatorPod()
	pending.Name = dragonflyOperatorPodPrefix + "-9d2fa-old"
	pending.UID = types.UID("dr-op-2")
	pending.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "apps/v1", Kind: "ReplicaSet",
		Name: dragonflyOperatorPodPrefix + "-9d2fa",
		UID:  types.UID("dr-op-rs-2"), Controller: ptr.To(true),
	}}
	pending.Status.Phase = corev1.PodPending
	good := shOperatorPod()
	cs := fake.NewSimpleClientset(sts, svc, pending, good)
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	// Seed the zero-endpoint streak past the 5m heal window.
	probetest.MustCheck[*statefulMasterlessCheck](t, p).stsZeroSince.
		Observe("db/dragonfly-master/dragonfly", base.Add(-6*time.Minute))
	if res := probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("masterless streak must still FAIL")
	}
	if _, err := cs.CoreV1().Pods(kube.DragonflyOperatorNS).
		Get(ctx, good.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("running operator leader must be bounced, err=%v", err)
	}
	if _, err := cs.CoreV1().Pods(kube.DragonflyOperatorNS).
		Get(ctx, pending.Name, metav1.GetOptions{}); err != nil {
		t.Fatalf("pending operator pod must not consume the heal: %v", err)
	}
}

// The 1-per-cycle cap: mid-rollout the operator runs two ReplicaSet
// generations side by side and the per-controller cooldown only dedups
// pods of the SAME RS, so a sweep that deleted every prefix match
// would reap the whole operator at once. Exactly ONE pod — the
// deterministic OLDEST — is deleted per sweep, and the persisted STS
// stamp keeps the remaining replicas untouched inside the cooldown
// window (the cap is not a rolling deletion that eats replica after
// replica sweep after sweep).
func TestDragonflyOperatorHealDeletesOnePodPerSweep(t *testing.T) {
	testutil.CleanupMetric(t, statefulServiceZeroEndpointsGauge, "db", "dragonfly-master", "dragonfly")
	base := time.Now()
	sts := shSTS("db", "dragonfly", 3,
		map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"})
	svc := shMasterSvc("db", "dragonfly-master",
		map[string]string{"app": "dragonfly", "role": "master"})
	// Two pods of the outgoing ReplicaSet generation and one of the
	// incoming one — the mid-rollout shape — all valid bounce
	// candidates (Running, RS-owned, same prefix).
	opPod := func(name, rs string, created time.Time) *corev1.Pod {
		pod := shOperatorPod()
		pod.Name = dragonflyOperatorPodPrefix + "-" + name
		pod.UID = types.UID("uid-" + name)
		pod.CreationTimestamp = metav1.NewTime(created)
		pod.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: "apps/v1", Kind: "ReplicaSet",
			Name: dragonflyOperatorPodPrefix + "-" + rs,
			UID:  types.UID("dr-op-rs-" + rs), Controller: ptr.To(true),
		}}
		return pod
	}
	old1 := opPod("aaaaa-old1", "oldrs", base.Add(-2*time.Hour))
	old2 := opPod("bbbbb-old2", "oldrs", base.Add(-1*time.Hour))
	new1 := opPod("ccccc-new1", "newrs", base.Add(-30*time.Minute))
	cs := fake.NewSimpleClientset(sts, svc, old1, old2, new1)
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	// Seed the zero-endpoint streak past the 5m heal window.
	probetest.MustCheck[*statefulMasterlessCheck](t, p).stsZeroSince.
		Observe("db/dragonfly-master/dragonfly", base.Add(-6*time.Minute))
	if res := probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("masterless streak must still FAIL")
	}
	if _, err := cs.CoreV1().Pods(kube.DragonflyOperatorNS).
		Get(ctx, old1.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("the oldest operator pod must be the one deleted, err=%v", err)
	}
	for _, survivor := range []*corev1.Pod{old2, new1} {
		if _, err := cs.CoreV1().Pods(kube.DragonflyOperatorNS).
			Get(ctx, survivor.Name, metav1.GetOptions{}); err != nil {
			t.Fatalf("sweep must delete exactly one operator pod, %s gone: %v",
				survivor.Name, err)
		}
	}

	// A follow-up sweep inside the cooldown window deletes nothing
	// further — one pod per cycle, never a rolling wipe.
	p.Now = func() time.Time { return base.Add(time.Minute) }
	_ = probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx)
	for _, survivor := range []*corev1.Pod{old2, new1} {
		if _, err := cs.CoreV1().Pods(kube.DragonflyOperatorNS).
			Get(ctx, survivor.Name, metav1.GetOptions{}); err != nil {
			t.Fatalf("cooldown must hold the sweep to one pod, %s deleted: %v",
				survivor.Name, err)
		}
	}
}

// A masterless non-Dragonfly service fires the gauge but never
// touches any operator pod.
func TestCheckStatefulMasterlessNonDragonflyNoHeal(t *testing.T) {
	testutil.CleanupMetric(t, statefulServiceZeroEndpointsGauge, "cache", "redis-master", "redis")
	base := time.Now()
	sts := shSTS("cache", "redis", 2, map[string]string{"app": "redis"})
	// Role key on the Service LABELS this time — selector stays the
	// plain app set.
	svc := shMasterSvc("cache", "redis-master", map[string]string{"app": "redis"})
	svc.Labels = map[string]string{"app.kubernetes.io/role": "master"}
	opPod := shOperatorPod()
	cs := fake.NewSimpleClientset(sts, svc, opPod)
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*statefulMasterlessCheck](t, p).stsZeroSince.
		Observe("cache/redis-master/redis", base.Add(-time.Hour))

	if res := probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("masterless redis must FAIL")
	}
	if v, _ := shStatefulZeroGauge(t, "cache", "redis-master", "redis"); v != 1 {
		t.Fatalf("zero-endpoints gauge = %v, want 1", v)
	}
	if _, err := cs.CoreV1().Pods(kube.DragonflyOperatorNS).
		Get(ctx, opPod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("non-dragonfly STS must not bounce the dragonfly operator")
	}
}

// Recovery: once the Service has a Ready endpoint again the tuple
// leaves the ledger and its gauge series is deleted, not parked at 1.
func TestCheckStatefulMasterlessRecovers(t *testing.T) {
	statefulServiceZeroEndpointsGauge.DeleteLabelValues("db", "dragonfly-master", "dragonfly")
	base := time.Now()
	sts := shSTS("db", "dragonfly", 3,
		map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"})
	svc := shMasterSvc("db", "dragonfly-master",
		map[string]string{"app": "dragonfly", "role": "master"})
	cs := fake.NewSimpleClientset(sts, svc)
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*statefulMasterlessCheck](t, p).stsZeroSince.
		Observe("db/dragonfly-master/dragonfly", base.Add(-time.Hour))

	if res := probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("precondition: masterless service must FAIL")
	}
	// Endpoint comes back.
	up := true
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "db", Name: "dragonfly-master-abc",
			Labels: map[string]string{discoveryv1.LabelServiceName: "dragonfly-master"},
		},
		Endpoints: []discoveryv1.Endpoint{{
			Addresses:  []string{"10.0.0.9"},
			Conditions: discoveryv1.EndpointConditions{Ready: &up},
		}},
	}
	if _, err := cs.DiscoveryV1().EndpointSlices("db").
		Create(ctx, slice, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	at := base.Add(time.Minute)
	p.Now = func() time.Time { return at }
	if res := probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("recovered master must pass: %+v", res)
	}
	if _, ok := probetest.MustCheck[*statefulMasterlessCheck](t, p).stsZeroSince.
		Seen("db/dragonfly-master/dragonfly", at); ok {
		t.Fatal("recovered tuple must leave the first-seen ledger")
	}
	if statefulServiceZeroEndpointsGauge.DeleteLabelValues("db", "dragonfly-master", "dragonfly") {
		t.Fatal("zero-endpoints series must be pruned on recovery")
	}
}

// Non-matching Services never classify: headless, no role key, wrong
// selector, or the STS itself not ready.
func TestCheckStatefulMasterlessNonCandidates(t *testing.T) {
	base := time.Now()
	sts := shSTS("db", "dragonfly", 3, map[string]string{"app": "dragonfly"})
	notReadySTS := shSTS("db", "other", 0, map[string]string{"app": "other"})
	headless := shMasterSvc("db", "hs",
		map[string]string{"app": "dragonfly", "role": "master"})
	headless.Spec.ClusterIP = corev1.ClusterIPNone
	noRole := shMasterSvc("db", "plain", map[string]string{"app": "dragonfly"})
	wrongSel := shMasterSvc("db", "other-master",
		map[string]string{"app": "other", "role": "master"})
	roleOnly := shMasterSvc("db", "roleonly", map[string]string{"role": "master"})
	p := testProberDyn(fake.NewSimpleClientset(
		sts, notReadySTS, headless, noRole, wrongSel, roleOnly), probetest.OpDyn())
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*statefulMasterlessCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("non-candidates must pass, got %+v", res)
	}
	if keys := probetest.LedgerKeys(&probetest.MustCheck[*statefulMasterlessCheck](t, p).stsZeroSince); len(keys) != 0 {
		t.Fatalf("non-candidates must not be tracked: %v", keys)
	}
}

// ---------------------------------------------------------------------------
// rabbitmq-suspended-listener — rabbitmq-suspended-listener
// ---------------------------------------------------------------------------

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
	if res := probetest.MustCheck[*rabbitMQSuspendedCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("first-seen suspended pod must pass: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "rabbitmq-0", metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted before the 10m window")
	}

	at := base.Add(11 * time.Minute)
	p.Now = func() time.Time { return at }
	if res := probetest.MustCheck[*rabbitMQSuspendedCheck](t, p).Run(ctx); res.Pass {
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

	if res := probetest.MustCheck[*rabbitMQSuspendedCheck](t, p).Run(ctx); res.Pass {
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

	if res := probetest.MustCheck[*rabbitMQSuspendedCheck](t, p).Run(ctx); res.Pass {
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

	if res := probetest.MustCheck[*rabbitMQSuspendedCheck](t, p).Run(ctx); res.Pass {
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

	if res := probetest.MustCheck[*rabbitMQSuspendedCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("suspended pod must FAIL even inside the heal cooldown")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "rabbitmq-0", metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted inside the 30m heal cooldown")
	}
}

// ---------------------------------------------------------------------------
// percona-cluster-quorum — percona-cluster-quorum
// ---------------------------------------------------------------------------

func TestCheckPerconaClusterQuorum(t *testing.T) {
	base := time.Now()
	errCluster := probetest.UnstructuredObj("pxc.percona.com/v1",
		"PerconaXtraDBCluster", "db", "pxc", 3, 3)
	_ = unstructured.SetNestedField(errCluster.Object, "error",
		"status", "state")
	paused := probetest.UnstructuredObj("psmdb.percona.com/v1",
		"PerconaServerMongoDB", "db", "mongo", 3, 3)
	_ = unstructured.SetNestedField(paused.Object, true, "spec", "pause")
	_ = unstructured.SetNestedField(paused.Object, "error",
		"status", "state")
	ready := probetest.UnstructuredObj("pgv2.percona.com/v2",
		"PerconaPGCluster", "db", "pg", 3, 3)
	_ = unstructured.SetNestedField(ready.Object, "ready",
		"status", "state")
	_ = unstructured.SetNestedField(ready.Object, int64(2),
		"status", "postgres", "ready")
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(
		errCluster, paused, ready))
	p.Now = func() time.Time { return base }

	res := probetest.MustCheck[*perconaQuorumCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("error-state cluster must FAIL")
	}
	if !strings.Contains(res.Why, "pxc") {
		t.Fatalf("offender must name the cluster: %q", res.Why)
	}
	if strings.Contains(res.Why, "mongo") {
		t.Fatalf("paused cluster must not be flagged: %q", res.Why)
	}
}

// ready<1 (top-level AND the nested status.postgres.ready PG shape)
// flags an unpaused cluster.
func TestCheckPerconaClusterQuorumReadyZero(t *testing.T) {
	base := time.Now()
	pxc := probetest.UnstructuredObj("pxc.percona.com/v1",
		"PerconaXtraDBCluster", "db", "pxc", 3, 3)
	_ = unstructured.SetNestedField(pxc.Object, "ready", "status", "state")
	_ = unstructured.SetNestedField(pxc.Object, int64(0), "status", "ready")
	pg := probetest.UnstructuredObj("pgv2.percona.com/v2",
		"PerconaPGCluster", "db", "pg", 3, 3)
	_ = unstructured.SetNestedField(pg.Object, "ready", "status", "state")
	_ = unstructured.SetNestedField(pg.Object, int64(0),
		"status", "postgres", "ready")
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(pxc, pg))
	p.Now = func() time.Time { return base }

	res := probetest.MustCheck[*perconaQuorumCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("ready<1 clusters must FAIL")
	}
	if !strings.Contains(res.Why, "pxc") || !strings.Contains(res.Why, "pg") {
		t.Fatalf("both clusters must be flagged: %q", res.Why)
	}
}

// "initializing" gets the 30m grace window: first sighting passes,
// past the window it FAILs; resolving clears the timer.
func TestCheckPerconaClusterQuorumInitializing(t *testing.T) {
	base := time.Now()
	init := probetest.UnstructuredObj("pxc.percona.com/v1",
		"PerconaXtraDBCluster", "db", "pxc", 3, 3)
	_ = unstructured.SetNestedField(init.Object, "initializing",
		"status", "state")
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(init))
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*perconaQuorumCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("fresh initializing must pass: %+v", res)
	}
	// 31m later — still initializing → FAIL.
	p.Now = func() time.Time { return base.Add(31 * time.Minute) }
	if res := probetest.MustCheck[*perconaQuorumCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("initializing >30m must FAIL")
	}
}
