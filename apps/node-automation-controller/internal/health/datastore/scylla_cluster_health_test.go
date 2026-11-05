// scylla_cluster_health_test.go — coverage for the
// scylla-cluster-health check (W9-ST1): degraded CR condition,
// member-service desync, gossip/raft stall log signatures.
package datastore

import (
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/health/probetest"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// W9-ST1 — scylla-cluster-health
// ---------------------------------------------------------------------------

// degraded_condition: Degraded=True past 15m on the CR fails the
// check and raises the gauge under its own reason.
func TestCheckScyllaHealthDegradedCondition(t *testing.T) {
	cs := fake.NewSimpleClientset(probetest.ReadyWorkerNode("w1", "", 0, false))
	dyn := probetest.OpDyn(scyllaClusterCR("bino-scylla", "bino-scylla",
		"Degraded", "True", 20*time.Minute))
	p := testProberDyn(cs, dyn)
	if res := mustCheck[*scyllaHealthCheck](t, p).Run(ctx); res.Pass {
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
	if res := mustCheck[*scyllaHealthCheck](t, p).Run(ctx); !res.Pass {
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
	if res := mustCheck[*scyllaHealthCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("first-seen member desync must pass: %+v", res)
	}
	p.Now = func() time.Time {
		return base.Add(scyllaSignatureMinAge + time.Minute)
	}
	if res := mustCheck[*scyllaHealthCheck](t, p).Run(ctx); res.Pass {
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
	if res := mustCheck[*scyllaHealthCheck](t, p).Run(ctx); !res.Pass {
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
	if res := mustCheck[*scyllaHealthCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("first-seen gossip stall must pass: %+v", res)
	}
	p.Now = func() time.Time {
		return base.Add(scyllaSignatureMinAge + time.Minute)
	}
	if res := mustCheck[*scyllaHealthCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("persisted gossip stall did not fail")
	}
	m := probetest.FindMetric(t, "node_automation_scylla_unhealthy", map[string]string{
		"namespace": "bino-scylla", "cluster": "bino-scylla",
		"reason": scyllaReasonGossipStall})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("scylla_unhealthy=%v, want 1", m)
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
	mustCheck[*scyllaHealthCheck](t, p).Run(ctx)
	p.Now = func() time.Time {
		return base.Add(scyllaSignatureMinAge + time.Minute)
	}
	if res := mustCheck[*scyllaHealthCheck](t, p).Run(ctx); !res.Pass {
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
	if res := mustCheck[*scyllaHealthCheck](t, p).Run(ctx); !res.Pass {
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
