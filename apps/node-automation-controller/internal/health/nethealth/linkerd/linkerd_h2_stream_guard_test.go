// linkerd_h2_stream_guard_test.go — coverage for the
// linkerd-h2-stream-guard check: storm-signature delete with a
// Ready sibling, the no-sibling skip, the linkerd-h2-stream-guard outbound balancer
// lockout and proxy OOM detection.
package linkerd

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// meshedPod builds a Running+Ready pod with a linkerd-proxy
// container, owned by controller `owner`.
func meshedPod(ns, name string, ready bool, owner types.UID) *corev1.Pod {
	pod := probetest.PodWithPhase(ns, name, corev1.PodRunning, ready, time.Hour)
	pod.Spec.Containers = []corev1.Container{
		{Name: "app"}, {Name: kube.LinkerdProxyContainer},
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
		// linkerd-h2-stream-guard — issued-at skew (NotValidYet) and trust-root skew
		// (UnknownIssuer) stall the identity the same way.
		"linkerd-proxy ERR tonic: InvalidCertificate(NotValidYet)",
		"linkerd-proxy ERR identity: UnknownIssuer for default.web",
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

// ---------------------------------------------------------------------------
// linkerd-h2-stream-guard — linkerd-proxy OOMKilled detection
// ---------------------------------------------------------------------------

// oomKilledPod builds a meshed pod whose linkerd-proxy container last
// terminated on OOMKilled.
func oomKilledPod(ns, name string, owner types.UID) *corev1.Pod {
	pod := meshedPod(ns, name, true, owner)
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name: kube.LinkerdProxyContainer,
		LastTerminationState: corev1.ContainerState{
			Terminated: &corev1.ContainerStateTerminated{
				Reason:     "OOMKilled",
				ExitCode:   137,
				FinishedAt: metav1.NewTime(time.Now().Add(-time.Minute)),
			},
		},
	}}
	return pod
}

// A linkerd-proxy that OOM'd reports on
// node_automation_linkerd_proxy_oomkilled — detection only, the pod
// already restarted its proxy and must NOT be deleted.
func TestLinkerdProxyOOMKilledFlagged(t *testing.T) {
	pod := oomKilledPod("apps", "web-1", types.UID("rs-1"))
	cs := fake.NewSimpleClientset(pod)
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"linkerd-proxy INFO connection established\n", nil))
	p := testProber(cs)
	res := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("OOMKilled linkerd-proxy must fail: %+v", res)
	}
	m := probetest.FindMetric(t, "node_automation_linkerd_proxy_oomkilled",
		map[string]string{"namespace": "apps", "pod": "web-1"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("oomkilled gauge = %v, want 1", m)
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-1", metav1.GetOptions{}); err != nil {
		t.Fatalf("OOMKilled pod must NOT be deleted (proxy already restarted): %v", err)
	}
	t.Cleanup(func() {
		linkerdProxyOOMKilledGauge.DeleteLabelValues("apps", "web-1")
	})
}

// An OOMKilled termination OLDER than the 30m window is not the wedge
// seed — the proxy already restarted clean and re-learned its
// balancer view; the gauge must stay silent.
func TestLinkerdProxyOOMKilledStaleWindowNotFlagged(t *testing.T) {
	pod := meshedPod("apps", "web-1", true, types.UID("rs-1"))
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name: kube.LinkerdProxyContainer,
		LastTerminationState: corev1.ContainerState{
			Terminated: &corev1.ContainerStateTerminated{
				Reason:     "OOMKilled",
				ExitCode:   137,
				FinishedAt: metav1.NewTime(time.Now().Add(-45 * time.Minute)),
			},
		},
	}}
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	res := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p).Run(ctx)
	if !res.Pass {
		t.Fatalf("a 45m-old OOM kill is not a wedge seed: %+v", res)
	}
	if m := probetest.FindMetric(t, "node_automation_linkerd_proxy_oomkilled",
		map[string]string{"namespace": "apps", "pod": "web-1"}); m != nil {
		t.Fatal("stale OOM kill must not raise the oomkilled gauge")
	}
	t.Cleanup(func() {
		linkerdProxyOOMKilledGauge.DeleteLabelValues("apps", "web-1")
	})
}

// An OOMKilled linkerd-proxy INIT container (mesh-before-app shapes)
// reads the same wedge seed — the init statuses are inspected too.
func TestLinkerdProxyInitOOMKilledFlagged(t *testing.T) {
	pod := meshedPod("apps", "web-1", true, types.UID("rs-1"))
	pod.Status.InitContainerStatuses = []corev1.ContainerStatus{{
		Name: kube.LinkerdProxyContainer,
		LastTerminationState: corev1.ContainerState{
			Terminated: &corev1.ContainerStateTerminated{
				Reason:     "OOMKilled",
				ExitCode:   137,
				FinishedAt: metav1.NewTime(time.Now().Add(-2 * time.Minute)),
			},
		},
	}}
	cs := fake.NewSimpleClientset(pod)
	p := testProber(cs)
	probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p).Run(ctx)
	if m := probetest.FindMetric(t, "node_automation_linkerd_proxy_oomkilled",
		map[string]string{"namespace": "apps", "pod": "web-1"}); m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("init-container OOM kill must raise the oomkilled gauge")
	}
	t.Cleanup(func() {
		linkerdProxyOOMKilledGauge.DeleteLabelValues("apps", "web-1")
	})
}

// ---------------------------------------------------------------------------
// linkerd-h2-stream-guard — outbound balancer lockout
// ---------------------------------------------------------------------------

// linkerdTargetService parses the service identity back out of a
// target_addr label on both supported shapes and refuses
// non-service targets.
func TestLinkerdTargetService(t *testing.T) {
	for _, tc := range []struct {
		addr         string
		wantNS, want string
		ok           bool
	}{
		{"db-svc.backend.svc.cluster.local:5432", "backend", "db-svc", true},
		{"db-svc.backend.svc.cluster.local", "backend", "db-svc", true},
		{"db-svc.backend.svc:5432", "backend", "db-svc", true},
		{"10.244.0.9:8080", "", "", false},
		{"example.com:443", "", "", false},
	} {
		ns, name, ok := linkerdTargetService(tc.addr)
		if ok != tc.ok || ns != tc.wantNS || name != tc.want {
			t.Fatalf("linkerdTargetService(%q) = (%q,%q,%v), want (%q,%q,%v)",
				tc.addr, ns, name, ok, tc.wantNS, tc.want, tc.ok)
		}
	}
}

// A wedged outbound balancer (total > 0, ready == 0) whose target
// Service still has Ready endpoints is the lockout: past the 10m
// window the gauge fires and the client pod is bounced — a Ready
// sibling absorbs the traffic.
func TestLinkerdBalancerWedgedHeals(t *testing.T) {
	base := time.Now()
	owner := types.UID("rs-shared")
	bad := meshedPod("apps", "web-1", true, owner)
	// The unmeshed sibling proves "someone can absorb the traffic"
	// without being re-flagged by the shared log reactor.
	good := probetest.PodWithPhase("apps", "web-2", corev1.PodRunning, true, time.Hour)
	good.OwnerReferences = bad.OwnerReferences
	cs := fake.NewSimpleClientset(
		bad, good,
		// The destination Service still has a Ready endpoint — the
		// wedge is client-side, not a real outage.
		probetest.EndpointSliceForService("backend", "db-svc", "10.244.0.9"))
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"linkerd-proxy INFO connection established\n", nil))
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, `state="ready"`) {
			return nil // no ready endpoints on the wedged target
		}
		return []probetest.PromTestSample{{
			Labels: map[string]string{
				"namespace":   "apps",
				"pod":         "web-1",
				"target_addr": "db-svc.backend.svc.cluster.local:5432",
			},
			Value: 3,
		}}
	})
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()

	chk := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p)
	probetest.FreezeNow(p.Deps, base)
	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("first-seen wedge must pass (inside window): %+v", res)
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-1", metav1.GetOptions{}); err != nil {
		t.Fatalf("pod deleted inside the persistence window: %v", err)
	}
	probetest.FreezeNow(p.Deps, base.Add(linkerdBalancerWedgeMinAge+time.Minute))
	res := chk.Run(ctx)
	if res.Pass {
		t.Fatal("persisted balancer wedge must fail")
	}
	m := probetest.FindMetric(t, "node_automation_linkerd_outbound_balancer_wedged",
		map[string]string{"namespace": "apps", "pod": "web-1"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("balancer-wedged gauge = %v, want 1", m)
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-1", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("wedged client pod should be bounced, err=%v", err)
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-2", metav1.GetOptions{}); err != nil {
		t.Fatalf("Ready sibling must survive: %v", err)
	}
	t.Cleanup(func() {
		linkerdOutboundBalancerWedgedGauge.DeleteLabelValues("apps", "web-1")
	})
}

// A "wedged" tuple whose target Service genuinely has zero ready
// endpoints cluster-wide is a real outage the proxy reports
// honestly — never flagged, never bounced.
func TestLinkerdBalancerRealOutageSkipped(t *testing.T) {
	base := time.Now()
	owner := types.UID("rs-shared")
	bad := meshedPod("apps", "web-1", true, owner)
	cs := fake.NewSimpleClientset(bad) // NO ready endpoints for db-svc at all
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"linkerd-proxy INFO connection established\n", nil))
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, `state="ready"`) {
			return nil
		}
		return []probetest.PromTestSample{{
			Labels: map[string]string{
				"namespace":   "apps",
				"pod":         "web-1",
				"target_addr": "db-svc.backend.svc.cluster.local:5432",
			},
			Value: 3,
		}}
	})
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	chk := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p)
	probetest.FreezeNow(p.Deps, base)
	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("real outage must pass: %+v", res)
	}
	probetest.FreezeNow(p.Deps, base.Add(linkerdBalancerWedgeMinAge+time.Minute))
	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("real outage still must pass past the window: %+v", res)
	}
	if m := probetest.FindMetric(t, "node_automation_linkerd_outbound_balancer_wedged",
		map[string]string{"namespace": "apps", "pod": "web-1"}); m != nil {
		t.Fatal("balancer-wedged gauge emitted for a genuine outage")
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-1", metav1.GetOptions{}); err != nil {
		t.Fatalf("outage-reporting pod must not be bounced: %v", err)
	}
}
