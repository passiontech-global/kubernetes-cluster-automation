// cluster_health_wave9_test.go — coverage for the Wave-9 checks in
// cluster_health_wave8.go (linkerd-endpoint-sync, scylla-cluster-health)
// plus the W8-ST2/W9-CP3 extensions to node-hang-precordon and the
// healNamedPod maintenance gate.
package clusterhealthprobes

import (
	"testing"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// Builders (w9-prefixed)
// ---------------------------------------------------------------------------

// w9StampNode builds a worker node carrying our pre-cordon stamp —
// unschedulable with node.ops/precordoned-by=node-hang-precordon and
// no active latch (the auto-uncordon shape).
func w9StampNode(name string, unschedulable bool) *corev1.Node {
	n := w8Worker(name, "", 0, unschedulable)
	n.Annotations = map[string]string{
		nodeHangPreCordonAnno: nodeHangPreCordonValue,
	}
	return n
}

// w9LinkerdNS builds a namespace opted into linkerd injection.
func w9LinkerdNS(name string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:   name,
		Labels: map[string]string{linkerdInjectLabel: "enabled"},
	}}
}

// w9HeadlessSvc builds a headless Service with a pod selector — the
// shape linkerd-destination derives endpoints from.
func w9HeadlessSvc(ns, name string, selector map[string]string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: corev1.ServiceSpec{
			ClusterIP: corev1.ClusterIPNone,
			Selector:  selector,
		},
	}
}

// w9ReadyPodIP builds a Running+Ready pod carrying podIP and labels.
func w9ReadyPodIP(ns, name, ip string, lbls map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			Labels:            lbls,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
			UID:               types.UID("uid-" + name),
		},
		Spec: corev1.PodSpec{NodeName: "w1"},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			PodIP: ip,
			Conditions: []corev1.PodCondition{{
				Type:   corev1.PodReady,
				Status: corev1.ConditionTrue,
			}},
		},
	}
}

// w9EndpointSlice builds an EndpointSlice bound to svc carrying the
// given addresses, all Ready.
func w9EndpointSlice(ns, svc string, addrs ...string) *discoveryv1.EndpointSlice {
	s := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      svc + "-abc",
			Labels:    map[string]string{discoveryv1.LabelServiceName: svc},
		},
	}
	for _, a := range addrs {
		s.Endpoints = append(s.Endpoints, discoveryv1.Endpoint{
			Addresses:  []string{a},
			Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
		})
	}
	return s
}

// w9ScyllaPod builds a ScyllaDB member pod — Running+Ready by default;
// callers flip Ready/phase for the troubled shapes.
func w9ScyllaPod(ns, name, cluster, ip string, ready bool) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			Labels:            map[string]string{scyllaClusterLabel: cluster},
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
			UID:               types.UID("uid-" + name),
		},
		Spec: corev1.PodSpec{NodeName: "w1"},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			PodIP: ip,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:         scyllaContainerName,
				RestartCount: 3,
			}},
		},
	}
	if ready {
		p.Status.Conditions = []corev1.PodCondition{{
			Type:   corev1.PodReady,
			Status: corev1.ConditionTrue,
		}}
	}
	return p
}

// w9ScyllaMemberSvc builds the per-member Service the scylla-operator
// creates for internode traffic — labeled with the pod it fronts.
func w9ScyllaMemberSvc(ns, name, podName string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
			Labels:    map[string]string{scyllaPodNameLabel: podName},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.96.0.10",
			Ports:     []corev1.ServicePort{{Port: 9042}},
		},
	}
}

// w9ScyllaCR builds a ScyllaCluster CR carrying one status condition
// whose lastTransitionTime is `age` old.
func w9ScyllaCR(ns, name, condType, condStatus string, age time.Duration) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "scylla.scylladb.com/v1",
		"kind":       "ScyllaCluster",
		"metadata":   map[string]any{"namespace": ns, "name": name},
		"status": map[string]any{
			"conditions": []any{map[string]any{
				"type":               condType,
				"status":             condStatus,
				"lastTransitionTime": time.Now().Add(-age).UTC().Format(time.RFC3339),
			}},
		},
	}}
}

// ---------------------------------------------------------------------------
// W8-ST2 — pre-cordon annotation + auto-uncordon (W9 additions)
// ---------------------------------------------------------------------------

// A sustained hang latch cordons AND stamps the node so the
// auto-uncordon path can tell our cordon from a deliberate one.
func TestCheckNodeHangPreCordonStampsAnnotation(t *testing.T) {
	cs := fake.NewSimpleClientset(
		w8Worker("w-hang", "KernelHungTasks", 5*time.Minute, false),
		w8Worker("w-ok", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := p.checkNodeHangPreCordon(ctx); res.pass {
		t.Fatal("hung node did not fail the check")
	}
	n, err := cs.CoreV1().Nodes().Get(ctx, "w-hang", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !n.Spec.Unschedulable {
		t.Fatal("hung node not cordoned")
	}
	if got := n.Annotations[nodeHangPreCordonAnno]; got != nodeHangPreCordonValue {
		t.Fatalf("pre-cordon stamp = %q, want %q", got, nodeHangPreCordonValue)
	}
}

// A stamped cordon lifts itself once every latch cleared — the
// transient-recovery / post-SNR-reboot shape.
func TestCheckNodeHangAutoUncordon(t *testing.T) {
	cs := fake.NewSimpleClientset(
		w9StampNode("w-recover", true),
		w8Worker("w-ok", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := p.checkNodeHangPreCordon(ctx); !res.pass {
		t.Fatalf("cleared node must pass: %+v", res)
	}
	n, err := cs.CoreV1().Nodes().Get(ctx, "w-recover", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if n.Spec.Unschedulable {
		t.Fatal("cleared node still cordoned")
	}
	if _, ok := n.Annotations[nodeHangPreCordonAnno]; ok {
		t.Fatal("pre-cordon stamp not removed on uncordon")
	}
	m := findMetric(t, "node_automation_node_hang_uncordons_total",
		map[string]string{"node": "w-recover"})
	if m == nil || m.GetCounter().GetValue() != 1 {
		t.Fatalf("uncordons_total=%v, want 1", m)
	}
}

// An unstamped cordon is never ours — kubectl cordon / NHC fencing
// must survive the sweep untouched.
func TestCheckNodeHangLeavesForeignCordon(t *testing.T) {
	foreign := w8Worker("w-manual", "", 0, true) // unschedulable, no stamp
	cs := fake.NewSimpleClientset(foreign, w8Worker("w-ok", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := p.checkNodeHangPreCordon(ctx); !res.pass {
		t.Fatalf("no latch must pass: %+v", res)
	}
	n, _ := cs.CoreV1().Nodes().Get(ctx, "w-manual", metav1.GetOptions{})
	if !n.Spec.Unschedulable {
		t.Fatal("foreign cordon lifted by the auto-uncordon")
	}
}

// A latch that is True but still inside its cordon fuse keeps the
// pre-cordon — "active" for the uncordon guard is status, not age.
func TestCheckNodeHangUncordonBlockedByFreshLatch(t *testing.T) {
	n := w8Worker("w-fresh", "FilesystemReadOnly", 30*time.Second, true)
	n.Annotations = map[string]string{
		nodeHangPreCordonAnno: nodeHangPreCordonValue,
	}
	cs := fake.NewSimpleClientset(n, w8Worker("w-ok", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := p.checkNodeHangPreCordon(ctx); !res.pass {
		t.Fatalf("fresh latch must not fail the check: %+v", res)
	}
	got, _ := cs.CoreV1().Nodes().Get(ctx, "w-fresh", metav1.GetOptions{})
	if !got.Spec.Unschedulable {
		t.Fatal("node uncordoned while a latch is still True")
	}
	if _, ok := got.Annotations[nodeHangPreCordonAnno]; !ok {
		t.Fatal("pre-cordon stamp removed while latch active")
	}
}

// A stamp left on a schedulable node (manual `kubectl uncordon`) is
// cleaned so a later deliberate cordon cannot inherit the
// auto-uncordon.
func TestCheckNodeHangStaleStampCleanup(t *testing.T) {
	n := w9StampNode("w-stale", false) // schedulable but still stamped
	cs := fake.NewSimpleClientset(n, w8Worker("w-ok", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := p.checkNodeHangPreCordon(ctx); !res.pass {
		t.Fatalf("stale stamp must pass: %+v", res)
	}
	got, _ := cs.CoreV1().Nodes().Get(ctx, "w-stale", metav1.GetOptions{})
	if got.Spec.Unschedulable {
		t.Fatal("schedulable node cordoned by stamp cleanup")
	}
	if _, ok := got.Annotations[nodeHangPreCordonAnno]; ok {
		t.Fatal("stale pre-cordon stamp not removed")
	}
}

// ---------------------------------------------------------------------------
// W9-CP3 — ClockUnsynchronized pre-cordon
// ---------------------------------------------------------------------------

// ClockUnsynchronized past the 10m fuse cordons with the same stamp;
// inside the fuse the NTP daemon gets its resync window.
func TestCheckNodeHangClockSkewCordon(t *testing.T) {
	cs := fake.NewSimpleClientset(
		w8Worker("w-skew", nodeClockSkewCond, 15*time.Minute, false),
		w8Worker("w-skew-fresh", nodeClockSkewCond, 5*time.Minute, false),
		w8Worker("w-ok", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := p.checkNodeHangPreCordon(ctx); res.pass {
		t.Fatal("sustained clock skew did not fail the check")
	}
	old, _ := cs.CoreV1().Nodes().Get(ctx, "w-skew", metav1.GetOptions{})
	if !old.Spec.Unschedulable ||
		old.Annotations[nodeHangPreCordonAnno] != nodeHangPreCordonValue {
		t.Fatal("sustained ClockUnsynchronized not cordoned+stamped")
	}
	fresh, _ := cs.CoreV1().Nodes().Get(ctx, "w-skew-fresh", metav1.GetOptions{})
	if fresh.Spec.Unschedulable {
		t.Fatal("fresh ClockUnsynchronized cordoned inside the NTP resync window")
	}
}

// ---------------------------------------------------------------------------
// healNamedPod — maintenance gate (W8-ST2)
// ---------------------------------------------------------------------------

// A wedged control-plane pod is NOT deleted while maintenance is in
// flight — the direct healNamedPod path (linkerd re-roll) respects
// the same mutex as healComponentPod.
func TestHealNamedPodDefersDuringMaintenance(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         linkerdNS,
			Name:              linkerdDestinationName + "-aaa-111",
			UID:               types.UID("u-dest"),
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
		},
	}
	// kured holding its node-lock = a reboot drain in flight.
	kured := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{
		Namespace:   "kube-system",
		Name:        "kured",
		Annotations: map[string]string{shared.KuredLockAnno: "w1"},
	}}
	cs := fake.NewSimpleClientset(w8Worker("w1", "", 0, false), kured, pod)
	p := testProberDyn(cs, shOpDyn())
	p.healNamedPod(ctx, logr.Discard(), linkerdDestinationName,
		pod.Namespace+"/"+pod.Name, pod, linkerdHealCooldown, time.Now())
	if _, err := cs.CoreV1().Pods(linkerdNS).
		Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("pod deleted during maintenance — heal must defer")
	}
}

// Without a maintenance signal the same call deletes the pod.
func TestHealNamedPodDeletesWithoutMaintenance(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         linkerdNS,
			Name:              linkerdDestinationName + "-bbb-222",
			UID:               types.UID("u-dest2"),
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
		},
	}
	cs := fake.NewSimpleClientset(w8Worker("w1", "", 0, false), pod)
	p := testProberDyn(cs, shOpDyn())
	p.healNamedPod(ctx, logr.Discard(), linkerdDestinationName,
		pod.Namespace+"/"+pod.Name, pod, linkerdHealCooldown, time.Now())
	if _, err := cs.CoreV1().Pods(linkerdNS).
		Get(ctx, pod.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("pod not deleted outside maintenance")
	}
}

// ---------------------------------------------------------------------------
// W9-NM2 — linkerd-endpoint-sync
// ---------------------------------------------------------------------------

// Synced headless service: Ready pod IP == Ready EndpointSlice
// address — the check passes and no gauge series appears.
func TestCheckLinkerdEndpointSyncHealthy(t *testing.T) {
	cs := fake.NewSimpleClientset(
		w9LinkerdNS("app"),
		w9HeadlessSvc("app", "headless-svc", map[string]string{"app": "x"}),
		w9ReadyPodIP("app", "pod-0", "10.244.0.5",
			map[string]string{"app": "x"}),
		w9EndpointSlice("app", "headless-svc", "10.244.0.5"),
		w8Worker("w1", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := p.checkLinkerdEndpointSync(ctx); !res.pass {
		t.Fatalf("synced endpoints must pass: %+v", res)
	}
	if m := findMetric(t, "node_automation_linkerd_endpoint_desync",
		map[string]string{"namespace": "app", "service": "headless-svc"}); m != nil {
		t.Fatal("desync gauge emitted on a synced service")
	}
}

// Namespaces without linkerd.io/inject=enabled are never audited.
func TestCheckLinkerdEndpointSyncSkipsUninjected(t *testing.T) {
	plain := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "plain"}}
	cs := fake.NewSimpleClientset(
		plain,
		w9HeadlessSvc("plain", "headless-svc", map[string]string{"app": "x"}),
		w9ReadyPodIP("plain", "pod-0", "10.244.0.5",
			map[string]string{"app": "x"}),
		// No EndpointSlice at all — would desync if audited.
		w8Worker("w1", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	if res := p.checkLinkerdEndpointSync(ctx); !res.pass {
		t.Fatalf("uninjected namespace must pass: %+v", res)
	}
}

// A desynced headless service fails only after the 10m persistence
// window; past it the gauge fires and the OLDEST linkerd-destination
// pod is bounced.
func TestCheckLinkerdEndpointSyncDesyncHeal(t *testing.T) {
	base := time.Now()
	older := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         linkerdNS,
			Name:              linkerdDestinationName + "-old-111",
			UID:               types.UID("u-old"),
			CreationTimestamp: metav1.NewTime(base.Add(-2 * time.Hour)),
		},
	}
	newer := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         linkerdNS,
			Name:              linkerdDestinationName + "-new-222",
			UID:               types.UID("u-new"),
			CreationTimestamp: metav1.NewTime(base.Add(-time.Hour)),
		},
	}
	cs := fake.NewSimpleClientset(
		w9LinkerdNS("app"),
		w9HeadlessSvc("app", "headless-svc", map[string]string{"app": "x"}),
		w9ReadyPodIP("app", "pod-0", "10.244.0.5",
			map[string]string{"app": "x"}),
		// EndpointSlice holds a stale IP — the Ready pod IP is missing.
		w9EndpointSlice("app", "headless-svc", "10.244.0.9"),
		older, newer,
		w8Worker("w1", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }

	// First sighting: tracked, still passing.
	if res := p.checkLinkerdEndpointSync(ctx); !res.pass {
		t.Fatalf("first-seen desync must pass: %+v", res)
	}
	// Inside the window: still quiet.
	p.now = func() time.Time { return base.Add(5 * time.Minute) }
	if res := p.checkLinkerdEndpointSync(ctx); !res.pass {
		t.Fatalf("desync inside window must pass: %+v", res)
	}
	// Past the window: FAIL + gauge + oldest destination pod gone.
	at := base.Add(linkerdEndpointDesyncMinAge + time.Minute)
	p.now = func() time.Time { return at }
	if res := p.checkLinkerdEndpointSync(ctx); res.pass {
		t.Fatal("persisted desync did not fail the check")
	}
	m := findMetric(t, "node_automation_linkerd_endpoint_desync",
		map[string]string{"namespace": "app", "service": "headless-svc"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("desync gauge = %v, want 1", m)
	}
	if _, err := cs.CoreV1().Pods(linkerdNS).
		Get(ctx, older.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("oldest linkerd-destination pod not bounced")
	}
	if _, err := cs.CoreV1().Pods(linkerdNS).
		Get(ctx, newer.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("newer linkerd-destination pod bounced — not oldest-first")
	}

	// Inside the 1h per-service cooldown the newer pod survives even
	// though the desync persists.
	p.now = func() time.Time { return at.Add(30 * time.Minute) }
	if res := p.checkLinkerdEndpointSync(ctx); res.pass {
		t.Fatal("persisted desync stopped failing inside cooldown")
	}
	if _, err := cs.CoreV1().Pods(linkerdNS).
		Get(ctx, newer.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("linkerd-destination bounced inside the 1h cooldown")
	}
}

// A resolved desync clears the gauge series instead of leaking a
// stale 1.
func TestCheckLinkerdEndpointSyncResyncClears(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset(
		w9LinkerdNS("app"),
		w9HeadlessSvc("app", "headless-svc", map[string]string{"app": "x"}),
		w9ReadyPodIP("app", "pod-0", "10.244.0.5",
			map[string]string{"app": "x"}),
		w9EndpointSlice("app", "headless-svc", "10.244.0.9"), // stale
		w8Worker("w1", "", 0, false))
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }
	p.checkLinkerdEndpointSync(ctx)
	p.now = func() time.Time { return base.Add(linkerdEndpointDesyncMinAge + time.Minute) }
	if res := p.checkLinkerdEndpointSync(ctx); res.pass {
		t.Fatal("persisted desync did not fail")
	}
	// EndpointSlice resyncs — the tuple must drop off /metrics.
	if err := cs.DiscoveryV1().EndpointSlices("app").Delete(ctx,
		"headless-svc-abc", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	cs.DiscoveryV1().EndpointSlices("app").Create(ctx,
		w9EndpointSlice("app", "headless-svc", "10.244.0.5"), metav1.CreateOptions{})
	p.now = func() time.Time { return base.Add(2*linkerdEndpointDesyncMinAge + time.Minute) }
	if res := p.checkLinkerdEndpointSync(ctx); !res.pass {
		t.Fatalf("resynced service must pass: %+v", res)
	}
	if m := findMetric(t, "node_automation_linkerd_endpoint_desync",
		map[string]string{"namespace": "app", "service": "headless-svc"}); m != nil {
		t.Fatal("desync gauge not cleared after resync")
	}
}

// ---------------------------------------------------------------------------
// W9-ST1 — scylla-cluster-health
// ---------------------------------------------------------------------------

// degraded_condition: Degraded=True past 15m on the CR fails the
// check and raises the gauge under its own reason.
func TestCheckScyllaHealthDegradedCondition(t *testing.T) {
	cs := fake.NewSimpleClientset(w8Worker("w1", "", 0, false))
	dyn := shOpDyn(w9ScyllaCR("bino-scylla", "bino-scylla",
		"Degraded", "True", 20*time.Minute))
	p := testProberDyn(cs, dyn)
	if res := p.checkScyllaHealth(ctx); res.pass {
		t.Fatal("degraded ScyllaCluster passed")
	}
	m := findMetric(t, "node_automation_scylla_unhealthy", map[string]string{
		"namespace": "bino-scylla", "cluster": "bino-scylla",
		"reason": scyllaReasonDegraded})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("scylla_unhealthy=%v, want 1", m)
	}
}

// A fresh Degraded condition is inside its window — tracked by the
// condition's own clock, so even the first sweep already knows the
// age; under 15m it must not fire.
func TestCheckScyllaHealthDegradedTooFresh(t *testing.T) {
	cs := fake.NewSimpleClientset(w8Worker("w1", "", 0, false))
	dyn := shOpDyn(w9ScyllaCR("bino-scylla", "bino-scylla",
		"Degraded", "True", 5*time.Minute))
	p := testProberDyn(cs, dyn)
	if res := p.checkScyllaHealth(ctx); !res.pass {
		t.Fatalf("fresh Degraded must pass: %+v", res)
	}
}

// member_service_desync: the per-member Service's EndpointSlice lost
// the live pod IP — fails only after the 10m window.
func TestCheckScyllaHealthMemberDesync(t *testing.T) {
	base := time.Now()
	pod := w9ScyllaPod("bino-scylla", "bino-scylla-bino-dc-rack-1-0",
		"bino-scylla", "10.244.1.5", true)
	svc := w9ScyllaMemberSvc("bino-scylla",
		"bino-scylla-bino-dc-rack-1-0", pod.Name)
	cs := fake.NewSimpleClientset(w8Worker("w1", "", 0, false), pod, svc)
	// EndpointSlice exists but carries a stale address.
	cs.DiscoveryV1().EndpointSlices("bino-scylla").Create(ctx,
		w9EndpointSlice("bino-scylla", svc.Name, "10.244.1.9"),
		metav1.CreateOptions{})
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }
	if res := p.checkScyllaHealth(ctx); !res.pass {
		t.Fatalf("first-seen member desync must pass: %+v", res)
	}
	p.now = func() time.Time {
		return base.Add(scyllaSignatureMinAge + time.Minute)
	}
	if res := p.checkScyllaHealth(ctx); res.pass {
		t.Fatal("persisted member desync did not fail")
	}
	m := findMetric(t, "node_automation_scylla_unhealthy", map[string]string{
		"namespace": "bino-scylla", "cluster": "bino-scylla",
		"reason": scyllaReasonMemberDesync})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("scylla_unhealthy=%v, want 1", m)
	}
}

// A member service whose EndpointSlice carries the live pod IP is
// synced — pass, no gauge.
func TestCheckScyllaHealthMemberSynced(t *testing.T) {
	pod := w9ScyllaPod("bino-scylla", "bino-scylla-bino-dc-rack-1-0",
		"bino-scylla", "10.244.1.5", true)
	svc := w9ScyllaMemberSvc("bino-scylla",
		"bino-scylla-bino-dc-rack-1-0", pod.Name)
	cs := fake.NewSimpleClientset(
		w8Worker("w1", "", 0, false), pod, svc,
		w9EndpointSlice("bino-scylla", svc.Name, "10.244.1.5"))
	p := testProberDyn(cs, shOpDyn())
	if res := p.checkScyllaHealth(ctx); !res.pass {
		t.Fatalf("synced member service must pass: %+v", res)
	}
}

// gossip_or_raft_stall: an unready member pod whose scylla log tail
// carries the ghost-gossip signature fails after the window.
func TestCheckScyllaHealthGossipStall(t *testing.T) {
	base := time.Now()
	pod := w9ScyllaPod("bino-scylla", "bino-scylla-bino-dc-rack-1-0",
		"bino-scylla", "10.244.1.5", false) // never Ready
	pod.Status.ContainerStatuses[0].State = corev1.ContainerState{
		Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"},
	}
	cs := fake.NewSimpleClientset(w8Worker("w1", "", 0, false), pod)
	cs.Fake.PrependReactor("get", "pods",
		testutil.ProbeLogReactor(
			"INFO gossip - InetAddress /10.244.1.5 is already present in gossip, cancelling join\n",
			nil))
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }
	if res := p.checkScyllaHealth(ctx); !res.pass {
		t.Fatalf("first-seen gossip stall must pass: %+v", res)
	}
	p.now = func() time.Time {
		return base.Add(scyllaSignatureMinAge + time.Minute)
	}
	if res := p.checkScyllaHealth(ctx); res.pass {
		t.Fatal("persisted gossip stall did not fail")
	}
	m := findMetric(t, "node_automation_scylla_unhealthy", map[string]string{
		"namespace": "bino-scylla", "cluster": "bino-scylla",
		"reason": scyllaReasonGossipStall})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("scylla_unhealthy=%v, want 1", m)
	}
}

// Clean logs on a troubled pod are not a stall — the signature must
// match, not just the pod shape.
func TestCheckScyllaHealthCleanLogsPass(t *testing.T) {
	pod := w9ScyllaPod("bino-scylla", "bino-scylla-bino-dc-rack-1-0",
		"bino-scylla", "10.244.1.5", false)
	cs := fake.NewSimpleClientset(w8Worker("w1", "", 0, false), pod)
	cs.Fake.PrependReactor("get", "pods",
		testutil.ProbeLogReactor("INFO scylla - starting up normally\n", nil))
	p := testProberDyn(cs, shOpDyn())
	base := time.Now()
	p.now = func() time.Time { return base }
	p.checkScyllaHealth(ctx)
	p.now = func() time.Time {
		return base.Add(scyllaSignatureMinAge + time.Minute)
	}
	if res := p.checkScyllaHealth(ctx); !res.pass {
		t.Fatalf("clean logs must pass: %+v", res)
	}
}

// A healthy cluster — synced member service, ready pods, no CR
// conditions — passes with no gauge series.
func TestCheckScyllaHealthHealthy(t *testing.T) {
	pod := w9ScyllaPod("bino-scylla", "bino-scylla-bino-dc-rack-1-0",
		"bino-scylla", "10.244.1.5", true)
	svc := w9ScyllaMemberSvc("bino-scylla",
		"bino-scylla-bino-dc-rack-1-0", pod.Name)
	cs := fake.NewSimpleClientset(
		w8Worker("w1", "", 0, false), pod, svc,
		w9EndpointSlice("bino-scylla", svc.Name, "10.244.1.5"))
	dyn := shOpDyn(w9ScyllaCR("bino-scylla", "bino-scylla",
		"Available", "True", time.Hour))
	p := testProberDyn(cs, dyn)
	if res := p.checkScyllaHealth(ctx); !res.pass {
		t.Fatalf("healthy scylla stack must pass: %+v", res)
	}
}
