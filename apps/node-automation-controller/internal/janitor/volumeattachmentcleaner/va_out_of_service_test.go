// va_out_of_service_test.go — the out-of-service gate: the 15m
// not-Ready window on fenced nodes, pod/claim blockers, DaemonSet
// discounting, window re-arming and the taint requirement.
package volumeattachmentcleaner

import (
	"testing"
	"time"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
)

// ---------------------------------------------------------------------------
// out_of_service_node
// ---------------------------------------------------------------------------

// A fenced node (out-of-service taint) that stays not-Ready past the
// window and hosts no non-terminal pods gets its VAs reaped. A
// terminal pod on the node does not block.
func TestVACleanerOutOfService(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacNode("dead", corev1.ConditionFalse, outOfService),
		vacPod("data", "old-job", "dead", corev1.PodSucceeded),
		vacAttachment("va-fenced", "dead", now.Add(-time.Hour)),
	)
	c := newVACleaner(cs, func() time.Time { return now })
	before := promtest.ToFloat64(
		metrics.VolumeAttachmentsCleanedTotal.WithLabelValues("out_of_service_node"))

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !vaExists(t, cs, "va-fenced") {
		t.Fatal("VA deleted before the 15m not-Ready window elapsed")
	}
	now = now.Add(16 * time.Minute)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if vaExists(t, cs, "va-fenced") {
		t.Fatal("VA kept on fenced node past the window with 0 live pods")
	}
	if got := promtest.ToFloat64(metrics.VolumeAttachmentsCleanedTotal.
		WithLabelValues("out_of_service_node")) - before; got != 1 {
		t.Fatalf("out_of_service_node counter delta = %v, want 1", got)
	}
}

// A single non-terminal pod on the fenced node keeps the VA — the
// mount may still be real.
func TestVACleanerOutOfServicePodsBlock(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacNode("dead", corev1.ConditionFalse, outOfService),
		vacPod("data", "still-running", "dead", corev1.PodRunning),
		vacAttachment("va-fenced", "dead", now.Add(-time.Hour)),
	)
	c := newVACleaner(cs, func() time.Time { return now })

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(20 * time.Minute)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !vaExists(t, cs, "va-fenced") {
		t.Fatal("VA deleted while a non-terminal pod still sits on the node")
	}
}

// A DaemonSet pod mounting a claim on the fenced node keeps the VA:
// DS agents can hold PVC/generic-ephemeral mounts just like workload
// pods (the fast-reboot branch's podsUsingVolume already inspects
// them), so discounting DS pods wholesale would fabricate a live==0
// and strip a mount that is still in use.
func TestVACleanerOutOfServiceDaemonSetClaimPodBlocks(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacNode("dead", corev1.ConditionFalse, outOfService),
		vacDSPod("kube-system", "agent-a", "dead", "data-a", false), // PVC claim
		vacDSPod("kube-system", "agent-b", "dead", "data-b", true),  // generic ephemeral
		vacAttachment("va-fenced", "dead", now.Add(-time.Hour)),
	)
	c := newVACleaner(cs, func() time.Time { return now })

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(20 * time.Minute)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !vaExists(t, cs, "va-fenced") {
		t.Fatal("VA deleted while a DaemonSet pod holds a claim mount on the fenced node")
	}
}

// A DaemonSet pod WITHOUT any claim-backed volume stays discounted —
// the plain infra-agent shape must not keep the gate shut forever.
func TestVACleanerOutOfServiceDaemonSetPodWithoutClaimKeepsGateOpen(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacNode("dead", corev1.ConditionFalse, outOfService),
		vacDSPod("kube-system", "agent-plain", "dead", "", false),
		vacAttachment("va-fenced", "dead", now.Add(-time.Hour)),
	)
	c := newVACleaner(cs, func() time.Time { return now })

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !vaExists(t, cs, "va-fenced") {
		t.Fatal("VA deleted before the 15m not-Ready window elapsed")
	}
	now = now.Add(16 * time.Minute)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if vaExists(t, cs, "va-fenced") {
		t.Fatal("VA kept past the window — a claimless DaemonSet pod must not block the gate")
	}
}

// The 15m not-Ready window re-arms when the node flips Ready — a
// flap cannot smuggle a detach in under the wire.
func TestVACleanerNotReadyWindowRearms(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacNode("flap", corev1.ConditionFalse, outOfService),
		vacAttachment("va-flap", "flap", now.Add(-time.Hour)),
	)
	c := newVACleaner(cs, func() time.Time { return now })

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(10 * time.Minute)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !vaExists(t, cs, "va-flap") {
		t.Fatal("VA deleted inside the not-Ready window")
	}
	// Node recovers → the death clock must reset.
	if _, err := cs.CoreV1().Nodes().Update(ctx,
		vacNode("flap", corev1.ConditionTrue, outOfService), metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.nodeNotReadySince.Seen("flap", time.Now()); ok {
		t.Fatal("not-Ready ledger not pruned on recovery")
	}
	// Node dies again — a fresh window starts now, so even after the
	// original 15m mark the VA must survive the first new cycle.
	if _, err := cs.CoreV1().Nodes().Update(ctx,
		vacNode("flap", corev1.ConditionFalse, outOfService), metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !vaExists(t, cs, "va-flap") {
		t.Fatal("VA deleted on a re-armed not-Ready window")
	}
}

// NotReady without the fencing taint is never enough — the taint is
// the declaration that a fencer already judged the node dead.
func TestVACleanerKeepsUntaintedNotReadyNode(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		vacNode("sick", corev1.ConditionFalse), // no taint
		vacAttachment("va-sick", "sick", now.Add(-time.Hour)),
		vacNode("alive", corev1.ConditionTrue),
		vacAttachment("va-healthy", "alive", now.Add(-time.Hour)),
	)
	c := newVACleaner(cs, func() time.Time { return now })

	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(20 * time.Minute)
	if err := c.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"va-sick", "va-healthy"} {
		if !vaExists(t, cs, name) {
			t.Fatalf("VA %s deleted without fencing evidence", name)
		}
	}
}
