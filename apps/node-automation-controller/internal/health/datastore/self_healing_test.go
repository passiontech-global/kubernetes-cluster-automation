// self_healing_test.go — the datastore self-healing checks
// (W6.2 stateful-masterless guard, W6.4 rabbitmq suspended-listener
// healer, W10-ST5 percona quorum) driven through the fake
// clientset + fake dynamic client.
package datastore

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
)

// ---------------------------------------------------------------------------
// W6.2 — stateful-masterless-services
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

// A master-role Service on a ready STS with 0 Ready endpoints: tracked
// first, gauge at 3m — and because the STS is Dragonfly-owned the
// operator leader gets bounced at 5m to force re-election.
func TestCheckStatefulMasterlessZeroEndpoints(t *testing.T) {
	metrics.StatefulServiceZeroEndpoints.DeleteLabelValues("db", "dragonfly-master", "dragonfly")
	t.Cleanup(func() {
		metrics.StatefulServiceZeroEndpoints.DeleteLabelValues("db", "dragonfly-master", "dragonfly")
	})
	base := time.Now()
	sts := shSTS("db", "dragonfly", 3,
		map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"})
	svc := shMasterSvc("db", "dragonfly-master",
		map[string]string{"app": "dragonfly", "role": "master"})
	opPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: probefw.DragonflyOperatorNS,
		Name:      dragonflyOperatorPodPrefix + "-6f8bc-xy",
		UID:       types.UID("dr-op-1"),
	}}
	cs := fake.NewSimpleClientset(sts, svc, opPod)
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }

	// First sighting — tracked, quiet.
	if res := mustCheck[*statefulMasterlessCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("first-seen zero endpoints must pass: %+v", res)
	}
	key := "db/dragonfly-master/dragonfly"
	if _, ok := mustCheck[*statefulMasterlessCheck](t, p).stsZeroSince.Seen(key, base); !ok {
		t.Fatal("zero-endpoint tuple not tracked")
	}

	// 4m in — gauge fires, but under the 5m heal window.
	at := base.Add(4 * time.Minute)
	p.Now = func() time.Time { return at }
	if res := mustCheck[*statefulMasterlessCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("zero endpoints >=3m must FAIL")
	}
	if v, _ := shStatefulZeroGauge(t, "db", "dragonfly-master", "dragonfly"); v != 1 {
		t.Fatalf("zero-endpoints gauge = %v, want 1", v)
	}
	if _, err := cs.CoreV1().Pods(probefw.DragonflyOperatorNS).
		Get(ctx, opPod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("operator pod deleted before the 5m heal window")
	}

	// 6m in — the dragonfly operator leader is bounced.
	at = base.Add(6 * time.Minute)
	p.Now = func() time.Time { return at }
	if res := mustCheck[*statefulMasterlessCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("still masterless — must keep FAILING")
	}
	if _, err := cs.CoreV1().Pods(probefw.DragonflyOperatorNS).
		Get(ctx, opPod.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("dragonfly operator pod must be deleted past 5m, err=%v", err)
	}
}

// A masterless non-Dragonfly service fires the gauge but never
// touches any operator pod.
func TestCheckStatefulMasterlessNonDragonflyNoHeal(t *testing.T) {
	metrics.StatefulServiceZeroEndpoints.DeleteLabelValues("cache", "redis-master", "redis")
	t.Cleanup(func() {
		metrics.StatefulServiceZeroEndpoints.DeleteLabelValues("cache", "redis-master", "redis")
	})
	base := time.Now()
	sts := shSTS("cache", "redis", 2, map[string]string{"app": "redis"})
	// Role key on the Service LABELS this time — selector stays the
	// plain app set.
	svc := shMasterSvc("cache", "redis-master", map[string]string{"app": "redis"})
	svc.Labels = map[string]string{"app.kubernetes.io/role": "master"}
	opPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: probefw.DragonflyOperatorNS,
		Name:      dragonflyOperatorPodPrefix + "-6f8bc-xy",
	}}
	cs := fake.NewSimpleClientset(sts, svc, opPod)
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	mustCheck[*statefulMasterlessCheck](t, p).stsZeroSince.
		Observe("cache/redis-master/redis", base.Add(-time.Hour))

	if res := mustCheck[*statefulMasterlessCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("masterless redis must FAIL")
	}
	if v, _ := shStatefulZeroGauge(t, "cache", "redis-master", "redis"); v != 1 {
		t.Fatalf("zero-endpoints gauge = %v, want 1", v)
	}
	if _, err := cs.CoreV1().Pods(probefw.DragonflyOperatorNS).
		Get(ctx, opPod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("non-dragonfly STS must not bounce the dragonfly operator")
	}
}

// Recovery: once the Service has a Ready endpoint again the tuple
// leaves the ledger and its gauge series is deleted, not parked at 1.
func TestCheckStatefulMasterlessRecovers(t *testing.T) {
	metrics.StatefulServiceZeroEndpoints.DeleteLabelValues("db", "dragonfly-master", "dragonfly")
	base := time.Now()
	sts := shSTS("db", "dragonfly", 3,
		map[string]string{"app": "dragonfly", "app.kubernetes.io/part-of": "dragonfly"})
	svc := shMasterSvc("db", "dragonfly-master",
		map[string]string{"app": "dragonfly", "role": "master"})
	cs := fake.NewSimpleClientset(sts, svc)
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	mustCheck[*statefulMasterlessCheck](t, p).stsZeroSince.
		Observe("db/dragonfly-master/dragonfly", base.Add(-time.Hour))

	if res := mustCheck[*statefulMasterlessCheck](t, p).Run(ctx); res.Pass {
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
	if res := mustCheck[*statefulMasterlessCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("recovered master must pass: %+v", res)
	}
	if _, ok := mustCheck[*statefulMasterlessCheck](t, p).stsZeroSince.
		Seen("db/dragonfly-master/dragonfly", at); ok {
		t.Fatal("recovered tuple must leave the first-seen ledger")
	}
	if metrics.StatefulServiceZeroEndpoints.DeleteLabelValues("db", "dragonfly-master", "dragonfly") {
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

	if res := mustCheck[*statefulMasterlessCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("non-candidates must pass, got %+v", res)
	}
	if keys := dsTrackedKeys(&mustCheck[*statefulMasterlessCheck](t, p).stsZeroSince); len(keys) != 0 {
		t.Fatalf("non-candidates must not be tracked: %v", keys)
	}
}

// ---------------------------------------------------------------------------
// W6.4 — rabbitmq-suspended-listener
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
		metrics.RabbitMQSuspendedHealsTotal.DeleteLabelValues("mq", "rabbitmq-0")
	})

	// First sighting — tracked, quiet, pod kept.
	if res := mustCheck[*rabbitMQSuspendedCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("first-seen suspended pod must pass: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "rabbitmq-0", metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted before the 10m window")
	}

	at := base.Add(11 * time.Minute)
	p.Now = func() time.Time { return at }
	if res := mustCheck[*rabbitMQSuspendedCheck](t, p).Run(ctx); res.Pass {
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
	mustCheck[*rabbitMQSuspendedCheck](t, p).rbSuspendedSince.
		Observe("mq/rabbitmq-0/u0", base.Add(-time.Hour))

	if res := mustCheck[*rabbitMQSuspendedCheck](t, p).Run(ctx); res.Pass {
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
	mustCheck[*rabbitMQSuspendedCheck](t, p).rbSuspendedSince.
		Observe("mq/rabbitmq-0/u0", base.Add(-time.Hour))

	if res := mustCheck[*rabbitMQSuspendedCheck](t, p).Run(ctx); res.Pass {
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
	mustCheck[*rabbitMQSuspendedCheck](t, p).rbSuspendedSince.
		Observe("mq/rabbitmq-0/u0", base.Add(-time.Hour))
	mustCheck[*rabbitMQSuspendedCheck](t, p).rbHealed.
		Stamp("mq/rabbitmq-0", base.Add(-10*time.Minute))

	if res := mustCheck[*rabbitMQSuspendedCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("suspended pod must FAIL even inside the heal cooldown")
	}
	if _, err := cs.CoreV1().Pods("mq").
		Get(ctx, "rabbitmq-0", metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted inside the 30m heal cooldown")
	}
}

// ---------------------------------------------------------------------------
// W10-ST5 — percona-cluster-quorum
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

	res := mustCheck[*perconaQuorumCheck](t, p).Run(ctx)
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

	res := mustCheck[*perconaQuorumCheck](t, p).Run(ctx)
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

	if res := mustCheck[*perconaQuorumCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("fresh initializing must pass: %+v", res)
	}
	// 31m later — still initializing → FAIL.
	p.Now = func() time.Time { return base.Add(31 * time.Minute) }
	if res := mustCheck[*perconaQuorumCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("initializing >30m must FAIL")
	}
}
