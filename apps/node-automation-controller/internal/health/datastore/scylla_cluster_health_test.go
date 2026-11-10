// scylla_cluster_health_test.go — coverage for the
// scylla-cluster-health check (scylla-cluster-health): degraded CR condition,
// member-service desync, gossip/raft stall log signatures.
package datastore

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// scylla-cluster-health — scylla-cluster-health
// ---------------------------------------------------------------------------

// degraded_condition: Degraded=True past 15m on the CR fails the
// check and raises the gauge under its own reason.
func TestCheckScyllaHealthDegradedCondition(t *testing.T) {
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false))
	dyn := probetest.OpDyn(scyllaClusterCR("bino-scylla", "bino-scylla",
		"Degraded", "True", 20*time.Minute))
	p := testProberDyn(cs, dyn)
	if res := probetest.MustCheck[*scyllaHealthCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("degraded ScyllaCluster passed")
	}
	m := probetest.FindMetric(t, "node_automation_scylla_unhealthy", map[string]string{
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
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false))
	dyn := probetest.OpDyn(scyllaClusterCR("bino-scylla", "bino-scylla",
		"Degraded", "True", 5*time.Minute))
	p := testProberDyn(cs, dyn)
	if res := probetest.MustCheck[*scyllaHealthCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("fresh Degraded must pass: %+v", res)
	}
}

// member_service_desync: the per-member Service's EndpointSlice lost
// the live pod IP — fails only after the 10m window.
func TestCheckScyllaHealthMemberDesync(t *testing.T) {
	base := time.Now()
	pod := scyllaMemberPod("bino-scylla", "bino-scylla-bino-dc-rack-1-0",
		"bino-scylla", "10.244.1.5", true)
	svc := scyllaMemberService("bino-scylla",
		"bino-scylla-bino-dc-rack-1-0", pod.Name)
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false), pod, svc)
	// EndpointSlice exists but carries a stale address.
	if _, err := cs.DiscoveryV1().EndpointSlices("bino-scylla").Create(ctx,
		probetest.EndpointSliceForService("bino-scylla", svc.Name, "10.244.1.9"),
		metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	if res := probetest.MustCheck[*scyllaHealthCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("first-seen member desync must pass: %+v", res)
	}
	p.Now = func() time.Time {
		return base.Add(scyllaSignatureMinAge + time.Minute)
	}
	if res := probetest.MustCheck[*scyllaHealthCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("persisted member desync did not fail")
	}
	m := probetest.FindMetric(t, "node_automation_scylla_unhealthy", map[string]string{
		"namespace": "bino-scylla", "cluster": "bino-scylla",
		"reason": scyllaReasonMemberDesync})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("scylla_unhealthy=%v, want 1", m)
	}
}

// A member service whose EndpointSlice carries the live pod IP is
// synced — pass, no gauge.
func TestCheckScyllaHealthMemberSynced(t *testing.T) {
	pod := scyllaMemberPod("bino-scylla", "bino-scylla-bino-dc-rack-1-0",
		"bino-scylla", "10.244.1.5", true)
	svc := scyllaMemberService("bino-scylla",
		"bino-scylla-bino-dc-rack-1-0", pod.Name)
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w1", "", 0, false), pod, svc,
		probetest.EndpointSliceForService("bino-scylla", svc.Name, "10.244.1.5"))
	p := testProberDyn(cs, probetest.OpDyn())
	if res := probetest.MustCheck[*scyllaHealthCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("synced member service must pass: %+v", res)
	}
}

// gossip_or_raft_stall: an unready member pod whose scylla log tail
// carries the ghost-gossip signature fails after the window.
func TestCheckScyllaHealthGossipStall(t *testing.T) {
	base := time.Now()
	pod := scyllaMemberPod("bino-scylla", "bino-scylla-bino-dc-rack-1-0",
		"bino-scylla", "10.244.1.5", false) // never Ready
	pod.Status.ContainerStatuses[0].State = corev1.ContainerState{
		Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"},
	}
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false), pod)
	cs.PrependReactor("get", "pods",
		testutil.ProbeLogReactor(
			"INFO gossip - InetAddress /10.244.1.5 is already present in gossip, cancelling join\n",
			nil))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	if res := probetest.MustCheck[*scyllaHealthCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("first-seen gossip stall must pass: %+v", res)
	}
	p.Now = func() time.Time {
		return base.Add(scyllaSignatureMinAge + time.Minute)
	}
	if res := probetest.MustCheck[*scyllaHealthCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("persisted gossip stall did not fail")
	}
	m := probetest.FindMetric(t, "node_automation_scylla_unhealthy", map[string]string{
		"namespace": "bino-scylla", "cluster": "bino-scylla",
		"reason": scyllaReasonGossipStall})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("scylla_unhealthy=%v, want 1", m)
	}
}

// scylla-shard-imbalance — a troubled member whose log tail carries the tombstone-
// avalanche signature reports under tombstone_overload_stall after
// the same persistence window.
func TestCheckScyllaHealthTombstoneStall(t *testing.T) {
	t.Cleanup(func() {
		scyllaClusterUnhealthyGauge.DeleteLabelValues("bino-scylla",
			"bino-scylla", scyllaReasonTombstoneStall)
	})
	base := time.Now()
	pod := scyllaMemberPod("bino-scylla", "bino-scylla-bino-dc-rack-1-0",
		"bino-scylla", "10.244.1.5", false)
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false), pod)
	cs.PrependReactor("get", "pods",
		testutil.ProbeLogReactor(
			"WARN storage_proxy - Read 3 live cells and 91204 tombstones for query\n", nil))
	p := testProberDyn(cs, probetest.OpDyn())
	p.Now = func() time.Time { return base }
	if res := probetest.MustCheck[*scyllaHealthCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("first-seen tombstone stall must pass: %+v", res)
	}
	p.Now = func() time.Time {
		return base.Add(scyllaSignatureMinAge + time.Minute)
	}
	res := probetest.MustCheck[*scyllaHealthCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("persisted tombstone stall did not fail")
	}
	m := probetest.FindMetric(t, "node_automation_scylla_unhealthy", map[string]string{
		"namespace": "bino-scylla", "cluster": "bino-scylla",
		"reason": scyllaReasonTombstoneStall})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("scylla_unhealthy tombstone=%v, want 1", m)
	}
}

// Clean logs on a troubled pod are not a stall — the signature must
// match, not just the pod shape.
func TestCheckScyllaHealthCleanLogsPass(t *testing.T) {
	pod := scyllaMemberPod("bino-scylla", "bino-scylla-bino-dc-rack-1-0",
		"bino-scylla", "10.244.1.5", false)
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false), pod)
	cs.PrependReactor("get", "pods",
		testutil.ProbeLogReactor("INFO scylla - starting up normally\n", nil))
	p := testProberDyn(cs, probetest.OpDyn())
	base := time.Now()
	p.Now = func() time.Time { return base }
	probetest.MustCheck[*scyllaHealthCheck](t, p).Run(ctx)
	p.Now = func() time.Time {
		return base.Add(scyllaSignatureMinAge + time.Minute)
	}
	if res := probetest.MustCheck[*scyllaHealthCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("clean logs must pass: %+v", res)
	}
}

// A healthy cluster — synced member service, ready pods, no CR
// conditions — passes with no gauge series.
func TestCheckScyllaHealthHealthy(t *testing.T) {
	pod := scyllaMemberPod("bino-scylla", "bino-scylla-bino-dc-rack-1-0",
		"bino-scylla", "10.244.1.5", true)
	svc := scyllaMemberService("bino-scylla",
		"bino-scylla-bino-dc-rack-1-0", pod.Name)
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w1", "", 0, false), pod, svc,
		probetest.EndpointSliceForService("bino-scylla", svc.Name, "10.244.1.5"))
	dyn := probetest.OpDyn(scyllaClusterCR("bino-scylla", "bino-scylla",
		"Available", "True", time.Hour))
	p := testProberDyn(cs, dyn)
	if res := probetest.MustCheck[*scyllaHealthCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("healthy scylla stack must pass: %+v", res)
	}
}

// scyllaMemberPod builds a ScyllaDB member pod — Running+Ready by default;
// callers flip Ready/phase for the troubled shapes.
func scyllaMemberPod(ns, name, cluster, ip string, ready bool) *corev1.Pod {
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

// scyllaMemberService builds the per-member Service the scylla-operator
// creates for internode traffic — labeled with the pod it fronts.
func scyllaMemberService(ns, name, podName string) *corev1.Service {
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

// scyllaClusterCR builds a ScyllaCluster CR carrying one status condition
// whose lastTransitionTime is `age` old.
func scyllaClusterCR(ns, name, condType, condStatus string, age time.Duration) *unstructured.Unstructured {
	return testutil.Unstructured(
		scyllaClusterGVR.GroupVersion().WithKind("ScyllaCluster"), ns, name,
		map[string]any{"status": map[string]any{
			"conditions": []any{map[string]any{
				"type":               condType,
				"status":             condStatus,
				"lastTransitionTime": time.Now().Add(-age).UTC().Format(time.RFC3339),
			}},
		}})
}

// unstructuredCondStatus pure pins: a present condition yields its
// status + transition time, a missing condition yields zero values,
// and a malformed lastTransitionTime keeps the status but zeroes the
// time (the caller's min-age gate then skips it).
func TestUnstructuredCondStatusPredicate(t *testing.T) {
	mk := func(conds any) *unstructured.Unstructured {
		obj := testutil.Unstructured(
			scyllaClusterGVR.GroupVersion().WithKind("ScyllaCluster"),
			"scylla", "cluster", nil)
		_ = unstructured.SetNestedField(obj.Object, conds, "status", "conditions")
		return obj
	}
	good := mk([]any{map[string]any{
		"type": "Degraded", "status": "True",
		"lastTransitionTime": "2026-01-02T03:04:05Z",
	}})
	status, since := unstructuredCondStatus(good, "Degraded")
	if status != "True" || since.IsZero() ||
		!since.Equal(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Fatalf("got (%q, %v), want (True, 2026-01-02T03:04:05Z)", status, since)
	}

	if status, since := unstructuredCondStatus(mk([]any{}), "Degraded"); status != "" || !since.IsZero() {
		t.Fatalf("missing condition = (%q, %v), want zero values", status, since)
	}

	malformed := mk([]any{map[string]any{
		"type": "Degraded", "status": "True",
		"lastTransitionTime": "not-a-timestamp",
	}})
	status, since = unstructuredCondStatus(malformed, "Degraded")
	if status != "True" || !since.IsZero() {
		t.Fatalf("malformed timestamp = (%q, %v), want (True, zero)", status, since)
	}
}

// scyllaPodTroubled pure pins: terminating and Succeeded pods are
// NOT troubled (never logged / already gone); Pending, never-Ready
// Running and CrashLoopBackOff pods ARE; a Running+Ready pod with no
// crash loop is healthy.
func TestScyllaPodTroubledPredicate(t *testing.T) {
	now := metav1.NewTime(time.Now())
	ready := []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	unready := []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionFalse}}
	mk := func(mutate func(*corev1.Pod)) *corev1.Pod {
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "scylla", Name: "pod-0"},
			Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: ready}}
		mutate(pod)
		return pod
	}
	for _, tc := range []struct {
		name string
		pod  *corev1.Pod
		want bool
	}{
		{"terminating", mk(func(p *corev1.Pod) { p.DeletionTimestamp = &now }), false},
		{"succeeded", mk(func(p *corev1.Pod) { p.Status.Phase = corev1.PodSucceeded }), false},
		{"pending", mk(func(p *corev1.Pod) { p.Status.Phase = corev1.PodPending }), true},
		{"running never ready", mk(func(p *corev1.Pod) { p.Status.Conditions = unready }), true},
		{"crashloopbackoff", mk(func(p *corev1.Pod) {
			p.Status.ContainerStatuses = []corev1.ContainerStatus{{
				State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
					Reason: "CrashLoopBackOff"}},
			}}
		}), true},
		{"running ready", mk(func(*corev1.Pod) {}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := scyllaPodTroubled(tc.pod); got != tc.want {
				t.Fatalf("scyllaPodTroubled = %v, want %v", got, tc.want)
			}
		})
	}
}
