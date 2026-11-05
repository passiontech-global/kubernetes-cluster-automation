// scylla_cluster_health_test.go — coverage for the
// scylla-cluster-health check (W9-ST1): degraded CR condition,
// member-service desync, gossip/raft stall log signatures.
package clusterhealthprobes

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// W9-ST1 — scylla-cluster-health
// ---------------------------------------------------------------------------

// degraded_condition: Degraded=True past 15m on the CR fails the
// check and raises the gauge under its own reason.
func TestCheckScyllaHealthDegradedCondition(t *testing.T) {
	cs := fake.NewSimpleClientset(readyWorkerNode("w1", "", 0, false))
	dyn := shOpDyn(scyllaClusterCR("bino-scylla", "bino-scylla",
		"Degraded", "True", 20*time.Minute))
	p := testProberDyn(cs, dyn)
	if res := mustCheck[*scyllaHealthCheck](t, p).run(ctx); res.pass {
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
	cs := fake.NewSimpleClientset(readyWorkerNode("w1", "", 0, false))
	dyn := shOpDyn(scyllaClusterCR("bino-scylla", "bino-scylla",
		"Degraded", "True", 5*time.Minute))
	p := testProberDyn(cs, dyn)
	if res := mustCheck[*scyllaHealthCheck](t, p).run(ctx); !res.pass {
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
	cs := fake.NewSimpleClientset(readyWorkerNode("w1", "", 0, false), pod, svc)
	// EndpointSlice exists but carries a stale address.
	cs.DiscoveryV1().EndpointSlices("bino-scylla").Create(ctx,
		endpointSliceForService("bino-scylla", svc.Name, "10.244.1.9"),
		metav1.CreateOptions{})
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }
	if res := mustCheck[*scyllaHealthCheck](t, p).run(ctx); !res.pass {
		t.Fatalf("first-seen member desync must pass: %+v", res)
	}
	p.now = func() time.Time {
		return base.Add(scyllaSignatureMinAge + time.Minute)
	}
	if res := mustCheck[*scyllaHealthCheck](t, p).run(ctx); res.pass {
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
	pod := scyllaMemberPod("bino-scylla", "bino-scylla-bino-dc-rack-1-0",
		"bino-scylla", "10.244.1.5", true)
	svc := scyllaMemberService("bino-scylla",
		"bino-scylla-bino-dc-rack-1-0", pod.Name)
	cs := fake.NewSimpleClientset(
		readyWorkerNode("w1", "", 0, false), pod, svc,
		endpointSliceForService("bino-scylla", svc.Name, "10.244.1.5"))
	p := testProberDyn(cs, shOpDyn())
	if res := mustCheck[*scyllaHealthCheck](t, p).run(ctx); !res.pass {
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
	cs := fake.NewSimpleClientset(readyWorkerNode("w1", "", 0, false), pod)
	cs.Fake.PrependReactor("get", "pods",
		testutil.ProbeLogReactor(
			"INFO gossip - InetAddress /10.244.1.5 is already present in gossip, cancelling join\n",
			nil))
	p := testProberDyn(cs, shOpDyn())
	p.now = func() time.Time { return base }
	if res := mustCheck[*scyllaHealthCheck](t, p).run(ctx); !res.pass {
		t.Fatalf("first-seen gossip stall must pass: %+v", res)
	}
	p.now = func() time.Time {
		return base.Add(scyllaSignatureMinAge + time.Minute)
	}
	if res := mustCheck[*scyllaHealthCheck](t, p).run(ctx); res.pass {
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
	pod := scyllaMemberPod("bino-scylla", "bino-scylla-bino-dc-rack-1-0",
		"bino-scylla", "10.244.1.5", false)
	cs := fake.NewSimpleClientset(readyWorkerNode("w1", "", 0, false), pod)
	cs.Fake.PrependReactor("get", "pods",
		testutil.ProbeLogReactor("INFO scylla - starting up normally\n", nil))
	p := testProberDyn(cs, shOpDyn())
	base := time.Now()
	p.now = func() time.Time { return base }
	mustCheck[*scyllaHealthCheck](t, p).run(ctx)
	p.now = func() time.Time {
		return base.Add(scyllaSignatureMinAge + time.Minute)
	}
	if res := mustCheck[*scyllaHealthCheck](t, p).run(ctx); !res.pass {
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
		readyWorkerNode("w1", "", 0, false), pod, svc,
		endpointSliceForService("bino-scylla", svc.Name, "10.244.1.5"))
	dyn := shOpDyn(scyllaClusterCR("bino-scylla", "bino-scylla",
		"Available", "True", time.Hour))
	p := testProberDyn(cs, dyn)
	if res := mustCheck[*scyllaHealthCheck](t, p).run(ctx); !res.pass {
		t.Fatalf("healthy scylla stack must pass: %+v", res)
	}
}
