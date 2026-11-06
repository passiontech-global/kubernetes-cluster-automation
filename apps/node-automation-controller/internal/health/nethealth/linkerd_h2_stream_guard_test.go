// linkerd_h2_stream_guard_test.go — coverage for the
// linkerd-h2-stream-guard check: storm-signature delete with a
// Ready sibling, and the no-sibling skip.
package nethealth

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// meshedPod builds a Running+Ready pod with a linkerd-proxy
// container, owned by controller `owner`.
func meshedPod(ns, name string, ready bool, owner types.UID) *corev1.Pod {
	pod := probetest.PodWithPhase(ns, name, corev1.PodRunning, ready, time.Hour)
	pod.Spec.Containers = []corev1.Container{
		{Name: "app"}, {Name: linkerdProxyContainer},
	}
	pod.OwnerReferences = []metav1.OwnerReference{{
		Kind: "ReplicaSet", Name: "rs-" + name,
		UID: owner, Controller: ptr.To(true)}}
	return pod
}

func TestLinkerdH2StormDeletesPodWithReadySibling(t *testing.T) {
	owner := types.UID("rs-shared")
	bad := meshedPod("apps", "web-1", true, owner)
	// The sibling is an UNMESHED pod under the same owner — the fake
	// log reactor returns the same body for every pod, so a meshed
	// sibling would read as storming too and be deleted alongside.
	good := probetest.PodWithPhase("apps", "web-2", corev1.PodRunning, true, time.Hour)
	good.OwnerReferences = bad.OwnerReferences
	cs := fake.NewSimpleClientset(bad, good)
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"linkerd-proxy ERR Http2 stream error: ENHANCE_YOUR_CALM\n", nil))
	p := testProber(cs)
	res := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("h2 storm signature must fail: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-1", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("storming pod should be deleted, err=%v", err)
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-2", metav1.GetOptions{}); err != nil {
		t.Fatalf("Ready sibling must survive: %v", err)
	}
}

func TestLinkerdH2StormSkipsPodWithoutSibling(t *testing.T) {
	// The storming pod is the ONLY Ready replica of its owner —
	// deleting it blackholes the workload.
	owner := types.UID("rs-solo")
	bad := meshedPod("apps", "web-1", true, owner)
	cs := fake.NewSimpleClientset(bad)
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"linkerd-proxy ERR too_many_pings\n", nil))
	p := testProber(cs)
	res := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("h2 storm signature must still fail: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-1", metav1.GetOptions{}); err != nil {
		t.Fatalf("lone-replica pod must not be deleted: %v", err)
	}
}

func TestLinkerdH2CleanLogsPass(t *testing.T) {
	pod := meshedPod("apps", "web-1", true, types.UID("rs-1"))
	cs := fake.NewSimpleClientset(pod)
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"linkerd-proxy INFO connection established\n", nil))
	p := testProber(cs)
	if res := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("clean proxy log must pass: %+v", res)
	}
}

// ---------------------------------------------------------------------------
// mTLS identity stall — leaf-certificate expiry / issuance loop
// ---------------------------------------------------------------------------

// Every documented identity-stall spelling is recognized — the proxy
// log reactor returns the same body for every pod, so a single Ready
// pod per case keeps the assertion unambiguous.
func TestLinkerdIdentityStallMarkers(t *testing.T) {
	for _, line := range []string{
		"linkerd-proxy WARN rustls certificate error: CertificateExpired",
		"linkerd-proxy ERR identity: certificate_expired for default.web",
		"linkerd-proxy ERR tonic: InvalidCertificate(Expired)",
		"linkerd-proxy ERR Failed to certify identity: status: Unauthenticated",
	} {
		t.Run(line, func(t *testing.T) {
			owner := types.UID("rs-id")
			bad := meshedPod("apps", "web-1", true, owner)
			good := probetest.PodWithPhase("apps", "web-2", corev1.PodRunning, true, time.Hour)
			good.OwnerReferences = bad.OwnerReferences
			cs := fake.NewSimpleClientset(bad, good)
			cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(line+"\n", nil))
			p := testProber(cs)
			res := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p).Run(ctx)
			if res.Pass {
				t.Fatalf("identity-stall signature must fail: %q", line)
			}
			if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-1", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
				t.Fatalf("identity-stalled pod should be evicted for a fresh leaf cert, err=%v", err)
			}
			m := probetest.FindMetric(t, "node_automation_linkerd_proxy_identity_stalled",
				map[string]string{"namespace": "apps", "pod": "web-1"})
			if m == nil || m.GetGauge().GetValue() != 1 {
				t.Fatalf("identity-stalled gauge = %v, want 1", m)
			}
		})
	}
}

// A Ready identity-stalled pod evicts only while ANOTHER Ready pod
// sits under the same controller — readyByOwner[ref.UID] >= 2 counts
// the stalled pod itself, so a lone replica is never evicted.
func TestLinkerdIdentityStallSkipsLoneReplica(t *testing.T) {
	bad := meshedPod("apps", "web-1", true, types.UID("rs-solo"))
	cs := fake.NewSimpleClientset(bad)
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"linkerd-proxy ERR CertificateExpired\n", nil))
	p := testProber(cs)
	res := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("identity-stall signature must still fail: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-1", metav1.GetOptions{}); err != nil {
		t.Fatalf("lone-replica pod must not be evicted: %v", err)
	}
}

// A stalled pod that is NOT itself Ready still evicts when two
// genuine Ready siblings exist under its owner — the >=2 census is
// about surviving replicas, not about the stalled pod's readiness.
func TestLinkerdIdentityStallEvictsUnreadyPodWithTwoSiblings(t *testing.T) {
	owner := types.UID("rs-trio")
	bad := meshedPod("apps", "web-1", false, owner)
	sib1 := probetest.PodWithPhase("apps", "web-2", corev1.PodRunning, true, time.Hour)
	sib1.OwnerReferences = bad.OwnerReferences
	sib2 := probetest.PodWithPhase("apps", "web-3", corev1.PodRunning, true, time.Hour)
	sib2.OwnerReferences = bad.OwnerReferences
	cs := fake.NewSimpleClientset(bad, sib1, sib2)
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"linkerd-proxy ERR failed to certify identity\n", nil))
	p := testProber(cs)
	res := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("identity-stall signature must fail: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-1", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("unready identity-stalled pod should be evicted, err=%v", err)
	}
	for _, sib := range []string{"web-2", "web-3"} {
		if _, err := cs.CoreV1().Pods("apps").Get(ctx, sib, metav1.GetOptions{}); err != nil {
			t.Fatalf("Ready sibling %s must survive: %v", sib, err)
		}
	}
}

// The identity gauge tuple clears once the signature is gone — no
// stale 1 leaks past the resolve.
func TestLinkerdIdentityStallGaugeClears(t *testing.T) {
	owner := types.UID("rs-id")
	bad := meshedPod("apps", "web-1", true, owner)
	good := probetest.PodWithPhase("apps", "web-2", corev1.PodRunning, true, time.Hour)
	good.OwnerReferences = bad.OwnerReferences
	cs := fake.NewSimpleClientset(bad, good)
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"linkerd-proxy ERR certificate_expired\n", nil))
	p := testProber(cs)
	chk := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p)
	if res := chk.Run(ctx); res.Pass {
		t.Fatal("identity-stall signature must fail")
	}
	if m := probetest.FindMetric(t, "node_automation_linkerd_proxy_identity_stalled",
		map[string]string{"namespace": "apps", "pod": "web-1"}); m == nil {
		t.Fatal("identity-stalled gauge missing")
	}
	// The heal already evicted the stalled pod — its series must
	// reconcile away on the next sweep.
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-1", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("identity-stalled pod should already be evicted, err=%v", err)
	}
	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("resolved identity stall must pass: %+v", res)
	}
	if m := probetest.FindMetric(t, "node_automation_linkerd_proxy_identity_stalled",
		map[string]string{"namespace": "apps", "pod": "web-1"}); m != nil {
		t.Fatal("identity-stalled gauge not cleared after pod eviction")
	}
}
