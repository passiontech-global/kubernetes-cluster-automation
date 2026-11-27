// linkerd_h2_stream_guard_test.go — coverage for the
// linkerd-h2-stream-guard check: storm-signature delete with a
// Ready sibling, the no-sibling skip, the linkerd-h2-stream-guard outbound balancer
// lockout and proxy OOM detection.
package linkerd

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
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

// runPastSigWindow runs the check twice — the first sweep only arms
// the linkerdH2SigMinAge signature-persistence window, the second
// (clock advanced past it) is the sweep whose verdict the test
// asserts on.
func runPastSigWindow(t *testing.T, p *probetest.Prober) probefw.Result {
	t.Helper()
	chk := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p)
	base := time.Now()
	probetest.FreezeNow(p.Deps, base)
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	probetest.FreezeNow(p.Deps, base.Add(linkerdH2SigMinAge+time.Minute))
	return chk.Run(probetest.SweepCtx(ctx, chk.Deps))
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
	res := runPastSigWindow(t, p)
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
	res := runPastSigWindow(t, p)
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
	if res := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
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
			res := runPastSigWindow(t, p)
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
	res := runPastSigWindow(t, p)
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
	res := runPastSigWindow(t, p)
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
	base := time.Now()
	probetest.FreezeNow(p.Deps, base)
	chk.Run(probetest.SweepCtx(ctx, chk.Deps)) // arms the signature window
	probetest.FreezeNow(p.Deps, base.Add(linkerdH2SigMinAge+time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); res.Pass {
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
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
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
	res := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
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
	res := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
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
	probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
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

// A wedged outbound balancer (pending > 0, ready == 0) whose target
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
		if !strings.Contains(query, `endpoint_state="pending"`) {
			return nil // no ready endpoints or failfast on the wedged target
		}
		return []probetest.PromTestSample{{
			Labels: map[string]string{
				"namespace":         "apps",
				"pod":               "web-1",
				"backend_kind":      "Service",
				"backend_namespace": "backend",
				"backend_name":      "db-svc",
				"backend_port":      "5432",
			},
			Value: 3,
		}}
	})
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()

	chk := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p)
	probetest.FreezeNow(p.Deps, base)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("first-seen wedge must pass (inside window): %+v", res)
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-1", metav1.GetOptions{}); err != nil {
		t.Fatalf("pod deleted inside the persistence window: %v", err)
	}
	probetest.FreezeNow(p.Deps, base.Add(linkerdBalancerWedgeMinAge+time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
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
		if !strings.Contains(query, `endpoint_state="pending"`) {
			return nil
		}
		return []probetest.PromTestSample{{
			Labels: map[string]string{
				"namespace":         "apps",
				"pod":               "web-1",
				"backend_kind":      "Service",
				"backend_namespace": "backend",
				"backend_name":      "db-svc",
				"backend_port":      "5432",
			},
			Value: 3,
		}}
	})
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	chk := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p)
	probetest.FreezeNow(p.Deps, base)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("real outage must pass: %+v", res)
	}
	probetest.FreezeNow(p.Deps, base.Add(linkerdBalancerWedgeMinAge+time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
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

func TestLinkerdBalancerTarget(t *testing.T) {
	for _, tc := range []struct {
		name     string
		labels   map[string]string
		wantID   string
		wantNS   string
		wantSvc  string
		wantOkay bool
	}{
		{
			name: "edge-26 backend Service with port",
			labels: map[string]string{
				"backend_kind":      "Service",
				"backend_namespace": "backend",
				"backend_name":      "db-svc",
				"backend_port":      "5432",
				"parent_kind":       "HTTPRoute",
				"parent_namespace":  "gateway",
				"parent_name":       "api-route",
			},
			wantID: "backend/db-svc:5432", wantNS: "backend", wantSvc: "db-svc", wantOkay: true,
		},
		{
			name: "edge-26 backend Service without port",
			labels: map[string]string{
				"backend_kind":      "Service",
				"backend_namespace": "backend",
				"backend_name":      "db-svc",
			},
			wantID: "backend/db-svc", wantNS: "backend", wantSvc: "db-svc", wantOkay: true,
		},
		{
			name: "edge-26 parent Service fallback",
			labels: map[string]string{
				"parent_kind":      "Service",
				"parent_namespace": "backend",
				"parent_name":      "api-svc",
				"parent_port":      "8080",
			},
			wantID: "backend/api-svc:8080", wantNS: "backend", wantSvc: "api-svc", wantOkay: true,
		},
		{
			name: "legacy target_addr fallback",
			labels: map[string]string{
				"target_addr": "db-svc.backend.svc.cluster.local:5432",
			},
			wantID: "db-svc.backend.svc.cluster.local:5432", wantNS: "backend", wantSvc: "db-svc", wantOkay: true,
		},
		{
			name: "non-Service backend_kind rejected",
			labels: map[string]string{
				"backend_kind":      "EgressNetwork",
				"backend_namespace": "egress",
				"backend_name":      "external-api",
			},
			wantOkay: false,
		},
		{
			name: "non-Service parent_kind rejected when backend absent",
			labels: map[string]string{
				"parent_kind":      "HTTPRoute",
				"parent_namespace": "apps",
				"parent_name":      "web-route",
			},
			wantOkay: false,
		},
		{
			name: "IP target_addr rejected",
			labels: map[string]string{
				"target_addr": "10.244.0.9:8080",
			},
			wantOkay: false,
		},
		{
			name: "external target_addr rejected",
			labels: map[string]string{
				"target_addr": "example.com:443",
			},
			wantOkay: false,
		},
		{
			name:     "empty target labels rejected",
			labels:   map[string]string{"namespace": "apps", "pod": "web-1"},
			wantOkay: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, ns, svc, ok := linkerdBalancerTarget(promq.Sample{Metric: tc.labels})
			if ok != tc.wantOkay || id != tc.wantID || ns != tc.wantNS || svc != tc.wantSvc {
				t.Fatalf("linkerdBalancerTarget(%v) = (%q,%q,%q,%v), want (%q,%q,%q,%v)",
					tc.labels, id, ns, svc, ok, tc.wantID, tc.wantNS, tc.wantSvc, tc.wantOkay)
			}
		})
	}
}

// Legacy Linkerd (<edge-26) exports state="pending"/"ready" + target_addr.
func TestLinkerdBalancerLegacyStateAndTargetAddrHeals(t *testing.T) {
	base := time.Now()
	owner := types.UID("rs-legacy")
	bad := meshedPod("apps", "web-1", true, owner)
	good := probetest.PodWithPhase("apps", "web-2", corev1.PodRunning, true, time.Hour)
	good.OwnerReferences = bad.OwnerReferences
	cs := fake.NewSimpleClientset(bad, good,
		probetest.EndpointSliceForService("backend", "db-svc", "10.244.0.9"))
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"linkerd-proxy INFO connection established\n", nil))
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if !strings.Contains(query, `state="pending"`) {
			return nil
		}
		return []probetest.PromTestSample{{
			Labels: map[string]string{
				"namespace":   "apps",
				"pod":         "web-1",
				"target_addr": "db-svc.backend.svc.cluster.local:5432",
			},
			Value: 2,
		}}
	})
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	chk := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p)
	t.Cleanup(func() {
		linkerdOutboundBalancerWedgedGauge.DeleteLabelValues("apps", "web-1")
	})

	probetest.FreezeNow(p.Deps, base)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("first-seen legacy wedge must pass inside window: %+v", res)
	}
	probetest.FreezeNow(p.Deps, base.Add(linkerdBalancerWedgeMinAge+time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); res.Pass {
		t.Fatal("persisted legacy wedge must fail")
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-1", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("legacy wedged client pod should be bounced, err=%v", err)
	}
}

// Regression for R2.1/R2.2: idle/boot-only targets (ready == 0 && pending == 0
// with no active fail-fast queue-gate shutups) account for ~89% of live Linkerd
// edge-26.x series and MUST NOT be flagged as wedged or arm balancerSeen.
func TestLinkerdBalancerIdleZeroPendingNotFlagged(t *testing.T) {
	base := time.Now()
	owner := types.UID("rs-idle")
	bad := meshedPod("apps", "web-1", true, owner)
	good := probetest.PodWithPhase("apps", "web-2", corev1.PodRunning, true, time.Hour)
	good.OwnerReferences = bad.OwnerReferences
	cs := fake.NewSimpleClientset(bad, good,
		probetest.EndpointSliceForService("backend", "db-svc", "10.244.0.9"))
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"linkerd-proxy INFO connection established\n", nil))

	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "outbound_http_balancer_queue_gate_shut_total") {
			return nil
		}
		// Both pending and ready report 0 (idle/boot-only balancer).
		return []probetest.PromTestSample{{
			Labels: map[string]string{
				"namespace":         "apps",
				"pod":               "web-1",
				"backend_kind":      "Service",
				"backend_namespace": "backend",
				"backend_name":      "db-svc",
				"backend_port":      "5432",
			},
			Value: 0,
		}}
	})
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	chk := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, base)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("idle balancer must pass: %+v", res)
	}
	if keys := probetest.LedgerKeys(&chk.balancerSeen); len(keys) != 0 {
		t.Fatalf("idle balancer must not arm balancerSeen, got %v", keys)
	}
	probetest.FreezeNow(p.Deps, base.Add(linkerdBalancerWedgeMinAge+time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("idle balancer past window must still pass: %+v", res)
	}
	if m := probetest.FindMetric(t, "node_automation_linkerd_outbound_balancer_wedged",
		map[string]string{"namespace": "apps", "pod": "web-1"}); m != nil {
		t.Fatal("idle balancer must not emit wedged gauge")
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-1", metav1.GetOptions{}); err != nil {
		t.Fatalf("idle pod must survive: %v", err)
	}
}

// ready == 0 && pending == 0 WITH active fail-fast (queue_gate_shut_total
// increase > 0) IS a wedged target and heals after >= 10m.
func TestLinkerdBalancerZeroPendingWithFailfastFlagged(t *testing.T) {
	base := time.Now()
	owner := types.UID("rs-failfast")
	bad := meshedPod("apps", "web-1", true, owner)
	good := probetest.PodWithPhase("apps", "web-2", corev1.PodRunning, true, time.Hour)
	good.OwnerReferences = bad.OwnerReferences
	cs := fake.NewSimpleClientset(bad, good,
		probetest.EndpointSliceForService("backend", "db-svc", "10.244.0.9"))
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"linkerd-proxy INFO connection established\n", nil))

	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		labels := map[string]string{
			"namespace":         "apps",
			"pod":               "web-1",
			"backend_kind":      "Service",
			"backend_namespace": "backend",
			"backend_name":      "db-svc",
			"backend_port":      "5432",
		}
		if strings.Contains(query, "outbound_http_balancer_queue_gate_shut_total") {
			return []probetest.PromTestSample{{Labels: labels, Value: 4}}
		}
		return []probetest.PromTestSample{{Labels: labels, Value: 0}}
	})
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	chk := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p)
	t.Cleanup(func() {
		linkerdOutboundBalancerWedgedGauge.DeleteLabelValues("apps", "web-1")
	})

	probetest.FreezeNow(p.Deps, base)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("first-seen failfast must pass inside window: %+v", res)
	}
	if keys := probetest.LedgerKeys(&chk.balancerSeen); len(keys) != 1 {
		t.Fatalf("failfast must arm balancerSeen, got %v", keys)
	}
	probetest.FreezeNow(p.Deps, base.Add(linkerdBalancerWedgeMinAge+time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatal("persisted failfast wedge must fail")
	}
	m := probetest.FindMetric(t, "node_automation_linkerd_outbound_balancer_wedged",
		map[string]string{"namespace": "apps", "pod": "web-1"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("balancer-wedged gauge = %v, want 1", m)
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-1", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("failfast wedged pod should be bounced, err=%v", err)
	}
}

// parent_* fallback resolves targets when backend_* is absent, and targets with
// ready > 0 && pending > 0 stay healthy (not flagged).
func TestLinkerdBalancerParentLabelsAndHealthyReadySkipped(t *testing.T) {
	base := time.Now()
	owner := types.UID("rs-parent")
	wedged := meshedPod("apps", "web-1", true, owner)
	healthy := meshedPod("apps", "web-2", true, types.UID("rs-healthy"))
	sib := probetest.PodWithPhase("apps", "web-sib", corev1.PodRunning, true, time.Hour)
	sib.OwnerReferences = wedged.OwnerReferences
	cs := fake.NewSimpleClientset(wedged, healthy, sib,
		probetest.EndpointSliceForService("backend", "api-svc", "10.244.0.10"),
		probetest.EndpointSliceForService("backend", "ok-svc", "10.244.0.11"))
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"linkerd-proxy INFO connection established\n", nil))

	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, `endpoint_state="pending"`) {
			return []probetest.PromTestSample{
				{
					Labels: map[string]string{
						"namespace":        "apps",
						"pod":              "web-1",
						"parent_kind":      "Service",
						"parent_namespace": "backend",
						"parent_name":      "api-svc",
						"parent_port":      "443",
					},
					Value: 2,
				},
				{
					Labels: map[string]string{
						"namespace":         "apps",
						"pod":               "web-2",
						"backend_kind":      "Service",
						"backend_namespace": "backend",
						"backend_name":      "ok-svc",
						"backend_port":      "8080",
					},
					Value: 1, // pending > 0 but ready > 0 below -> healthy
				},
			}
		}
		if strings.Contains(query, `endpoint_state="ready"`) {
			return []probetest.PromTestSample{{
				Labels: map[string]string{
					"namespace":         "apps",
					"pod":               "web-2",
					"backend_kind":      "Service",
					"backend_namespace": "backend",
					"backend_name":      "ok-svc",
					"backend_port":      "8080",
				},
				Value: 2,
			}}
		}
		return nil
	})
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	chk := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p)
	t.Cleanup(func() {
		linkerdOutboundBalancerWedgedGauge.DeleteLabelValues("apps", "web-1")
		linkerdOutboundBalancerWedgedGauge.DeleteLabelValues("apps", "web-2")
	})

	probetest.FreezeNow(p.Deps, base)
	_ = chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	probetest.FreezeNow(p.Deps, base.Add(linkerdBalancerWedgeMinAge+time.Minute))
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatal("parent_* wedged pod must fail")
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-1", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("parent_* wedged pod should be deleted, err=%v", err)
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-2", metav1.GetOptions{}); err != nil {
		t.Fatalf("pod with ready > 0 && pending > 0 must survive: %v", err)
	}
	if m := probetest.FindMetric(t, "node_automation_linkerd_outbound_balancer_wedged",
		map[string]string{"namespace": "apps", "pod": "web-2"}); m != nil {
		t.Fatal("pod with ready > 0 && pending > 0 must not emit wedged gauge")
	}
}

// Fail closed when readySeries PromQL query errors: do not flag or delete on
// fresh sweeps, and preserve held gauge/balancerSeen without deleting on
// established wedges.
func TestLinkerdBalancerReadyQueryErrorFailsClosed(t *testing.T) {
	base := time.Now()
	owner := types.UID("rs-err")
	bad := meshedPod("apps", "web-1", true, owner)
	good := probetest.PodWithPhase("apps", "web-2", corev1.PodRunning, true, time.Hour)
	good.OwnerReferences = bad.OwnerReferences
	cs := fake.NewSimpleClientset(bad, good,
		probetest.EndpointSliceForService("backend", "db-svc", "10.244.0.9"))
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"linkerd-proxy INFO connection established\n", nil))

	var failReady atomic.Bool
	failReady.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = r.ParseForm()
		q := r.FormValue("query")
		if failReady.Load() && strings.Contains(q, `endpoint_state="ready"`) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(q, `endpoint_state="pending"`) {
			_, _ = fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"namespace":"apps","pod":"web-1","backend_kind":"Service","backend_namespace":"backend","backend_name":"db-svc","backend_port":"5432"},"value":[1,"3"]}]}}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
	}))
	t.Cleanup(srv.Close)

	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	chk := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, base)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("ready query failure must fail closed and pass: %+v", res)
	}
	if keys := probetest.LedgerKeys(&chk.balancerSeen); len(keys) != 0 {
		t.Fatalf("ready query failure must not arm balancerSeen, got %v", keys)
	}
	probetest.FreezeNow(p.Deps, base.Add(linkerdBalancerWedgeMinAge+time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("repeated ready query failure must still fail closed: %+v", res)
	}
	if m := probetest.FindMetric(t, "node_automation_linkerd_outbound_balancer_wedged",
		map[string]string{"namespace": "apps", "pod": "web-1"}); m != nil {
		t.Fatal("ready query failure must not emit wedged gauge")
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-1", metav1.GetOptions{}); err != nil {
		t.Fatalf("pod must survive ready query error: %v", err)
	}

	// Now allow ready query to succeed for a sibling-less pod so gauge emits,
	// then fail ready query on the next sweep and confirm carry preserves it.
	cs2 := fake.NewSimpleClientset(meshedPod("apps", "web-solo", true, types.UID("rs-solo")),
		probetest.EndpointSliceForService("backend", "db-svc", "10.244.0.9"))
	cs2.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"linkerd-proxy INFO connection established\n", nil))
	failReady.Store(false)
	srv2, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if !strings.Contains(query, `endpoint_state="pending"`) {
			return nil
		}
		return []probetest.PromTestSample{{
			Labels: map[string]string{
				"namespace":         "apps",
				"pod":               "web-solo",
				"backend_kind":      "Service",
				"backend_namespace": "backend",
				"backend_name":      "db-svc",
				"backend_port":      "5432",
			},
			Value: 3,
		}}
	})
	p2 := testProber(cs2)
	p2.Cfg.HTTPContent.URL = srv2.URL
	p2.HTTPClient = srv2.Client()
	chk2 := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p2)
	t.Cleanup(func() {
		linkerdOutboundBalancerWedgedGauge.DeleteLabelValues("apps", "web-solo")
	})

	probetest.FreezeNow(p2.Deps, base)
	_ = chk2.Run(probetest.SweepCtx(ctx, chk2.Deps))
	probetest.FreezeNow(p2.Deps, base.Add(linkerdBalancerWedgeMinAge+time.Minute))
	if res := chk2.Run(probetest.SweepCtx(ctx, chk2.Deps)); res.Pass {
		t.Fatal("persisted wedge must emit before query error")
	}
	// Point chk2 at failing server: carried gauge stays live, balancerSeen preserved.
	failReady.Store(true)
	p2.Cfg.HTTPContent.URL = srv.URL
	p2.HTTPClient = srv.Client()
	if res := chk2.Run(probetest.SweepCtx(ctx, chk2.Deps)); res.Pass {
		t.Fatal("carried gauge on query error must stay failed")
	}
	if keys := probetest.LedgerKeys(&chk2.balancerSeen); len(keys) != 1 {
		t.Fatalf("ready query error must preserve balancerSeen, got %v", keys)
	}
	if m := probetest.FindMetric(t, "node_automation_linkerd_outbound_balancer_wedged",
		map[string]string{"namespace": "apps", "pod": "web-solo"}); m == nil {
		t.Fatal("carried balancer-wedged gauge missing on query error")
	}
}

// Fail closed on unresolvable targets (IP literal, external domain, non-Service
// kind, or missing target labels): never skip EndpointSlice cross-check.
func TestLinkerdBalancerUnresolvableTargetFailsClosed(t *testing.T) {
	base := time.Now()
	owner := types.UID("rs-unres")
	bad := meshedPod("apps", "web-1", true, owner)
	good := probetest.PodWithPhase("apps", "web-2", corev1.PodRunning, true, time.Hour)
	good.OwnerReferences = bad.OwnerReferences
	cs := fake.NewSimpleClientset(bad, good,
		probetest.EndpointSliceForService("backend", "db-svc", "10.244.0.9"))
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"linkerd-proxy INFO connection established\n", nil))

	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if !strings.Contains(query, `endpoint_state="pending"`) {
			return nil
		}
		return []probetest.PromTestSample{
			{
				Labels: map[string]string{"namespace": "apps", "pod": "web-1", "target_addr": "10.244.0.9:8080"},
				Value:  3,
			},
			{
				Labels: map[string]string{"namespace": "apps", "pod": "web-1", "target_addr": "example.com:443"},
				Value:  2,
			},
			{
				Labels: map[string]string{"namespace": "apps", "pod": "web-1", "backend_kind": "HTTPRoute", "backend_namespace": "apps", "backend_name": "route-1"},
				Value:  1,
			},
			{
				Labels: map[string]string{"namespace": "apps", "pod": "web-1"},
				Value:  1,
			},
		}
	})
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	chk := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, base)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("unresolvable targets must fail closed and pass: %+v", res)
	}
	probetest.FreezeNow(p.Deps, base.Add(linkerdBalancerWedgeMinAge+time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("unresolvable targets past window must pass: %+v", res)
	}
	if keys := probetest.LedgerKeys(&chk.balancerSeen); len(keys) != 0 {
		t.Fatalf("unresolvable targets must not arm balancerSeen, got %v", keys)
	}
	if m := probetest.FindMetric(t, "node_automation_linkerd_outbound_balancer_wedged",
		map[string]string{"namespace": "apps", "pod": "web-1"}); m != nil {
		t.Fatal("unresolvable targets must not emit wedged gauge")
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-1", metav1.GetOptions{}); err != nil {
		t.Fatalf("pod with unresolvable targets must survive: %v", err)
	}
}

// Fail closed when AllEndpointSlices returns an error: never delete pods or
// prune balancerSeen.
func TestLinkerdBalancerEndpointSliceErrorFailsClosed(t *testing.T) {
	base := time.Now()
	owner := types.UID("rs-ep-err")
	bad := meshedPod("apps", "web-1", true, owner)
	good := probetest.PodWithPhase("apps", "web-2", corev1.PodRunning, true, time.Hour)
	good.OwnerReferences = bad.OwnerReferences
	cs := fake.NewSimpleClientset(bad, good,
		probetest.EndpointSliceForService("backend", "db-svc", "10.244.0.9"))
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"linkerd-proxy INFO connection established\n", nil))

	var failSlices atomic.Bool
	failSlices.Store(true)
	cs.PrependReactor("list", "endpointslices", func(ktesting.Action) (bool, runtime.Object, error) {
		if failSlices.Load() {
			return true, nil, errors.New("apiserver endpointslices timeout")
		}
		return false, nil, nil
	})

	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if !strings.Contains(query, `endpoint_state="pending"`) {
			return nil
		}
		return []probetest.PromTestSample{{
			Labels: map[string]string{
				"namespace":         "apps",
				"pod":               "web-1",
				"backend_kind":      "Service",
				"backend_namespace": "backend",
				"backend_name":      "db-svc",
				"backend_port":      "5432",
			},
			Value: 3,
		}}
	})
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	chk := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, base)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("EndpointSlice list failure must fail closed and pass: %+v", res)
	}
	probetest.FreezeNow(p.Deps, base.Add(linkerdBalancerWedgeMinAge+time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("EndpointSlice list failure past window must still fail closed: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-1", metav1.GetOptions{}); err != nil {
		t.Fatalf("pod must survive EndpointSlice list error: %v", err)
	}
	if m := probetest.FindMetric(t, "node_automation_linkerd_outbound_balancer_wedged",
		map[string]string{"namespace": "apps", "pod": "web-1"}); m != nil {
		t.Fatal("EndpointSlice list error must not emit wedged gauge")
	}

	// Mid-wedge EndpointSlice error preserves held gauge and balancerSeen
	// without deleting the pod.
	failSlices.Store(false)
	t.Cleanup(func() {
		linkerdOutboundBalancerWedgedGauge.DeleteLabelValues("apps", "web-1")
	})
	csNoSib := fake.NewSimpleClientset(meshedPod("apps", "web-1", true, types.UID("rs-solo-ep")),
		probetest.EndpointSliceForService("backend", "db-svc", "10.244.0.9"))
	csNoSib.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"linkerd-proxy INFO connection established\n", nil))
	csNoSib.PrependReactor("list", "endpointslices", func(ktesting.Action) (bool, runtime.Object, error) {
		if failSlices.Load() {
			return true, nil, errors.New("apiserver endpointslices timeout")
		}
		return false, nil, nil
	})
	p2 := testProber(csNoSib)
	p2.Cfg.HTTPContent.URL = srv.URL
	p2.HTTPClient = srv.Client()
	chk2 := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p2)
	probetest.FreezeNow(p2.Deps, base)
	_ = chk2.Run(probetest.SweepCtx(ctx, chk2.Deps))
	probetest.FreezeNow(p2.Deps, base.Add(linkerdBalancerWedgeMinAge+time.Minute))
	if res := chk2.Run(probetest.SweepCtx(ctx, chk2.Deps)); res.Pass {
		t.Fatal("persisted wedge must emit before EndpointSlice failure")
	}
	failSlices.Store(true)
	if res := chk2.Run(probetest.SweepCtx(ctx, chk2.Deps)); res.Pass {
		t.Fatal("carried gauge on EndpointSlice failure must stay failed")
	}
	if keys := probetest.LedgerKeys(&chk2.balancerSeen); len(keys) != 1 {
		t.Fatalf("EndpointSlice error must preserve balancerSeen, got %v", keys)
	}
}

// Terminating pods (DeletionTimestamp != nil) must be skipped before arming or
// emitting balancer wedge findings.
func TestLinkerdBalancerTerminatingPodSkipped(t *testing.T) {
	base := time.Now()
	bad := meshedPod("apps", "web-1", true, types.UID("rs-term"))
	nowMeta := metav1.NewTime(base)
	bad.DeletionTimestamp = &nowMeta
	bad.Finalizers = []string{"kubernetes"}
	cs := fake.NewSimpleClientset(bad,
		probetest.EndpointSliceForService("backend", "db-svc", "10.244.0.9"))
	cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
		"linkerd-proxy INFO connection established\n", nil))

	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if !strings.Contains(query, `endpoint_state="pending"`) {
			return nil
		}
		return []probetest.PromTestSample{{
			Labels: map[string]string{
				"namespace":         "apps",
				"pod":               "web-1",
				"backend_kind":      "Service",
				"backend_namespace": "backend",
				"backend_name":      "db-svc",
				"backend_port":      "5432",
			},
			Value: 3,
		}}
	})
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	chk := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p)

	probetest.FreezeNow(p.Deps, base)
	_ = chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	probetest.FreezeNow(p.Deps, base.Add(linkerdBalancerWedgeMinAge+time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("terminating pod must be skipped and pass: %+v", res)
	}
	if keys := probetest.LedgerKeys(&chk.balancerSeen); len(keys) != 0 {
		t.Fatalf("terminating pod must not arm balancerSeen, got %v", keys)
	}
}

func TestLinkerdH2StreamGuardEvictEnabledEnvGate(t *testing.T) {
	for _, tc := range []struct {
		name     string
		val      *string
		want     bool
		wantWarn bool
	}{
		{name: "unset defaults true", val: nil, want: true},
		{name: "explicit true", val: ptr.To("true"), want: true},
		{name: "explicit false", val: ptr.To("false"), want: false},
		// envx.Gate warns at most once per key across the process.
		{name: "invalid bool-like False falls back to true with warning", val: ptr.To("False"), want: true, wantWarn: true},
		{name: "invalid bool-like 0 falls back to true", val: ptr.To("0"), want: true, wantWarn: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var warned atomic.Bool
			envx.SetWarnf(func(string, ...any) { warned.Store(true) })
			t.Cleanup(func() { envx.SetWarnf(nil) })

			if tc.val == nil {
				t.Setenv("LINKERD_H2_STREAM_GUARD_EVICT_ENABLED", "")
			} else {
				t.Setenv("LINKERD_H2_STREAM_GUARD_EVICT_ENABLED", *tc.val)
			}
			chk := NewLinkerdH2StreamGuardCheck(probetest.NewDeps(fake.NewSimpleClientset(), probetest.OpDyn())).(*linkerdH2StreamGuardCheck)
			if chk.evictEnabled != tc.want {
				t.Fatalf("evictEnabled = %v, want %v", chk.evictEnabled, tc.want)
			}
			if warned.Load() != tc.wantWarn {
				t.Fatalf("warned = %v, want %v", warned.Load(), tc.wantWarn)
			}
		})
	}
}

// When LINKERD_H2_STREAM_GUARD_EVICT_ENABLED=false, all 3 SafePodDelete paths
// (H2 storm, mTLS identity stall, and outbound balancer) keep detection,
// gauges, and findings active while deleting zero pods.
func TestLinkerdH2StreamGuardAuditOnlyMode(t *testing.T) {
	t.Run("h2 storm audit-only keeps pod alive", func(t *testing.T) {
		t.Setenv("LINKERD_H2_STREAM_GUARD_EVICT_ENABLED", "false")
		owner := types.UID("rs-storm-audit")
		bad := meshedPod("apps", "web-1", true, owner)
		good := probetest.PodWithPhase("apps", "web-2", corev1.PodRunning, true, time.Hour)
		good.OwnerReferences = bad.OwnerReferences
		cs := fake.NewSimpleClientset(bad, good)
		cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
			"linkerd-proxy ERR Http2 stream error: ENHANCE_YOUR_CALM\n", nil))
		p := testProber(cs)
		t.Cleanup(func() {
			linkerdH2StreamStalledGauge.DeleteLabelValues("apps", "web-1")
		})
		res := runPastSigWindow(t, p)
		if res.Pass {
			t.Fatalf("audit-only h2 storm must still fail check: %+v", res)
		}
		if m := probetest.FindMetric(t, "node_automation_linkerd_h2_stream_stalled",
			map[string]string{"namespace": "apps", "pod": "web-1"}); m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatalf("h2 stream stalled gauge = %v, want 1", m)
		}
		if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-1", metav1.GetOptions{}); err != nil {
			t.Fatalf("audit-only must not delete storming pod: %v", err)
		}
	})

	t.Run("identity stall audit-only keeps pod alive", func(t *testing.T) {
		t.Setenv("LINKERD_H2_STREAM_GUARD_EVICT_ENABLED", "false")
		owner := types.UID("rs-id-audit")
		bad := meshedPod("apps", "web-1", true, owner)
		good := probetest.PodWithPhase("apps", "web-2", corev1.PodRunning, true, time.Hour)
		good.OwnerReferences = bad.OwnerReferences
		cs := fake.NewSimpleClientset(bad, good)
		cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
			"linkerd-proxy ERR CertificateExpired\n", nil))
		p := testProber(cs)
		t.Cleanup(func() {
			linkerdProxyIdentityStalledGauge.DeleteLabelValues("apps", "web-1")
		})
		res := runPastSigWindow(t, p)
		if res.Pass {
			t.Fatalf("audit-only identity stall must still fail check: %+v", res)
		}
		if m := probetest.FindMetric(t, "node_automation_linkerd_proxy_identity_stalled",
			map[string]string{"namespace": "apps", "pod": "web-1"}); m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatalf("identity stalled gauge = %v, want 1", m)
		}
		if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-1", metav1.GetOptions{}); err != nil {
			t.Fatalf("audit-only must not delete identity-stalled pod: %v", err)
		}
	})

	t.Run("outbound balancer audit-only keeps pod alive and skips partition check", func(t *testing.T) {
		t.Setenv("LINKERD_H2_STREAM_GUARD_EVICT_ENABLED", "false")
		base := time.Now()
		owner := types.UID("rs-bal-audit")
		bad := meshedPod("apps", "web-1", true, owner)
		good := probetest.PodWithPhase("apps", "web-2", corev1.PodRunning, true, time.Hour)
		good.OwnerReferences = bad.OwnerReferences
		cs := fake.NewSimpleClientset(bad, good,
			probetest.EndpointSliceForService("backend", "db-svc", "10.244.0.9"))
		cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
			"linkerd-proxy INFO connection established\n", nil))
		var nodesListed atomic.Bool
		cs.PrependReactor("list", "nodes", func(ktesting.Action) (bool, runtime.Object, error) {
			nodesListed.Store(true)
			return false, nil, nil
		})
		srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
			if !strings.Contains(query, `endpoint_state="pending"`) {
				return nil
			}
			return []probetest.PromTestSample{{
				Labels: map[string]string{
					"namespace":         "apps",
					"pod":               "web-1",
					"backend_kind":      "Service",
					"backend_namespace": "backend",
					"backend_name":      "db-svc",
					"backend_port":      "5432",
				},
				Value: 3,
			}}
		})
		p := testProber(cs)
		p.Cfg.HTTPContent.URL = srv.URL
		p.HTTPClient = srv.Client()
		chk := probetest.MustCheck[*linkerdH2StreamGuardCheck](t, p)
		t.Cleanup(func() {
			linkerdOutboundBalancerWedgedGauge.DeleteLabelValues("apps", "web-1")
		})

		probetest.FreezeNow(p.Deps, base)
		_ = chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		probetest.FreezeNow(p.Deps, base.Add(linkerdBalancerWedgeMinAge+time.Minute))
		res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if res.Pass {
			t.Fatal("audit-only outbound balancer wedge must still fail check")
		}
		if m := probetest.FindMetric(t, "node_automation_linkerd_outbound_balancer_wedged",
			map[string]string{"namespace": "apps", "pod": "web-1"}); m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatalf("balancer-wedged gauge = %v, want 1", m)
		}
		if _, err := cs.CoreV1().Pods("apps").Get(ctx, "web-1", metav1.GetOptions{}); err != nil {
			t.Fatalf("audit-only must not delete wedged pod: %v", err)
		}
		if nodesListed.Load() {
			t.Fatal("audit-only must skip checkPartition() / AllNodes()")
		}
	})
}
