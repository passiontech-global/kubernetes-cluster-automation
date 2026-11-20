// coredns_upstream_test.go — coverage for the coredns-upstream
// check (coredns-upstream): isolated-failure pod delete, fleet-wide
// detection-only, readiness fallback.
package nethealth

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

func TestCoreDNSUpstreamDeletesIsolatedFailingPod(t *testing.T) {
	srv := coreDNSUpstreamPromServer(t)
	// Both pods must share one controller — the healthy-sibling
	// check keys on PodControllerKey, and two standalone pods share
	// no controller.
	owner := []metav1.OwnerReference{{
		APIVersion: "apps/v1", Kind: "ReplicaSet",
		Name: "coredns-7c65d6f9b4", Controller: ptr.To(true),
	}}
	bad := probetest.PodWithPhase("kube-system", "coredns-bad", corev1.PodRunning, false, time.Hour)
	bad.OwnerReferences = owner
	good := probetest.PodWithPhase("kube-system", "coredns-good", corev1.PodRunning, true, time.Hour)
	good.OwnerReferences = owner
	cs := fake.NewSimpleClientset(bad, good)
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()

	check := probetest.MustCheck[*coreDNSUpstreamCheck](t, p)
	base := time.Now()
	// First sight tracks the signature inside the 10m persistence
	// window — detection fails but no delete yet.
	probetest.FreezeNow(p.Deps, base)
	if res := check.Run(probetest.SweepCtx(ctx, check.Deps)); res.Pass {
		t.Fatalf("isolated upstream failure must fail: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, "coredns-bad", metav1.GetOptions{}); err != nil {
		t.Fatalf("first sweep must not delete before persistence: %v", err)
	}

	// Past the window the persisted signature heals the isolated pod.
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	res := check.Run(probetest.SweepCtx(ctx, check.Deps))
	if res.Pass {
		t.Fatalf("isolated upstream failure must fail: %+v", res)
	}
	if !strings.Contains(res.Why, "coredns-bad") {
		t.Fatalf("why missing pod: %q", res.Why)
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, "coredns-bad", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("isolated failing pod should be deleted, err=%v", err)
	}
	if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, "coredns-good", metav1.GetOptions{}); err != nil {
		t.Fatalf("healthy sibling must survive: %v", err)
	}
}

// Every flagged pod advances its persistence window even when the
// one-delete-per-cycle cap suppresses its heal. The old `&&` order
// short-circuited Persisted for the 2nd pod, so its 10m timer never
// started while the first pod was being healed.
func TestCoreDNSUpstreamTracksAllFlaggedPodsPastHealCap(t *testing.T) {
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "healthcheck_failures_total") {
			return []probetest.PromTestSample{
				{Labels: map[string]string{"pod": "coredns-bad", "namespace": "kube-system"}, Value: 1},
				{Labels: map[string]string{"pod": "coredns-bad2", "namespace": "kube-system"}, Value: 1},
			}
		}
		return nil
	})
	owner := []metav1.OwnerReference{{
		APIVersion: "apps/v1", Kind: "ReplicaSet",
		Name: "coredns-7c65d6f9b4", Controller: ptr.To(true),
	}}
	bad := probetest.PodWithPhase("kube-system", "coredns-bad", corev1.PodRunning, false, time.Hour)
	bad.OwnerReferences = owner
	bad2 := probetest.PodWithPhase("kube-system", "coredns-bad2", corev1.PodRunning, false, time.Hour)
	bad2.OwnerReferences = owner
	good := probetest.PodWithPhase("kube-system", "coredns-good", corev1.PodRunning, true, time.Hour)
	good.OwnerReferences = owner
	cs := fake.NewSimpleClientset(bad, bad2, good)
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	base := time.Now()
	probetest.FreezeNow(p.Deps, base)

	check := probetest.MustCheck[*coreDNSUpstreamCheck](t, p)
	if res := check.Run(probetest.SweepCtx(ctx, check.Deps)); res.Pass {
		t.Fatalf("upstream failures must fail: %+v", res)
	}
	// Past the window the first pod heals; the second is held back
	// by the one-per-cycle cap but MUST still have advanced its
	// first-seen stamp on BOTH sweeps.
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	if res := check.Run(probetest.SweepCtx(ctx, check.Deps)); res.Pass {
		t.Fatalf("upstream failures must fail past the window: %+v", res)
	}
	keys := map[string]bool{}
	for _, k := range probetest.LedgerKeys(&check.seen) {
		keys[k] = true
	}
	for _, want := range []string{"kube-system/coredns-bad", "kube-system/coredns-bad2"} {
		if !keys[want] {
			t.Fatalf("flagged pod %s never advanced its first-seen window: %v", want, keys)
		}
	}
	// Still only one pod deleted this cycle.
	deleted := 0
	for _, name := range []string{"coredns-bad", "coredns-bad2"} {
		if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, name, metav1.GetOptions{}); err != nil {
			deleted++
		}
	}
	if deleted != 1 {
		t.Fatalf("one-delete-per-cycle cap broken: %d pods deleted", deleted)
	}
}

func TestCoreDNSUpstreamFleetWideDoesNotDelete(t *testing.T) {
	// Both dns pods flagged -> no healthy sibling -> detection only.
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "healthcheck_failures_total") {
			return []probetest.PromTestSample{
				{Labels: map[string]string{"pod": "coredns-a", "namespace": "kube-system"}, Value: 1},
				{Labels: map[string]string{"pod": "coredns-b", "namespace": "kube-system"}, Value: 1},
			}
		}
		return nil
	})
	a := probetest.PodWithPhase("kube-system", "coredns-a", corev1.PodRunning, true, time.Hour)
	b := probetest.PodWithPhase("kube-system", "coredns-b", corev1.PodRunning, true, time.Hour)
	cs := fake.NewSimpleClientset(a, b)
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()

	res := probetest.MustCheck[*coreDNSUpstreamCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass {
		t.Fatalf("fleet-wide failure must fail: %+v", res)
	}
	for _, name := range []string{"coredns-a", "coredns-b"} {
		if _, err := cs.CoreV1().Pods("kube-system").Get(ctx, name, metav1.GetOptions{}); err != nil {
			t.Fatalf("fleet-wide failure must not delete %s: %v", name, err)
		}
	}
}

func TestCoreDNSFallbackUnreadyPod(t *testing.T) {
	// Prometheus dead -> readiness fallback: unready >10m + sibling.
	bad := probetest.PodWithPhase("kube-system", "node-local-dns-x1", corev1.PodPending, false, 15*time.Minute)
	good := probetest.PodWithPhase("kube-system", "node-local-dns-x2", corev1.PodRunning, true, time.Hour)
	// A real DaemonSet pod is always scheduled; the check deliberately
	// skips unscheduled pods (no failure domain to key a cooldown on).
	bad.Spec.NodeName = "node-1"
	good.Spec.NodeName = "node-2"
	cs := fake.NewSimpleClientset(bad, good)
	p := testProber(cs) // dead httpURL -> both prom queries fail

	res := probetest.MustCheck[*coreDNSUpstreamCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass {
		t.Fatalf("fallback must detect the unready dns pod: %+v", res)
	}
	if !strings.Contains(res.Why, "node-local-dns-x1") {
		t.Fatalf("why missing pod: %q", res.Why)
	}
}

// An unready but UNSCHEDULED DaemonSet pod has no node to key the
// per-node cooldown on — it must not produce a "/" target or a finding.
func TestCoreDNSFallbackSkipsUnscheduledPod(t *testing.T) {
	bad := probetest.PodWithPhase("kube-system", "node-local-dns-pending", corev1.PodPending, false, 15*time.Minute)
	good := probetest.PodWithPhase("kube-system", "node-local-dns-x2", corev1.PodRunning, true, time.Hour)
	good.Spec.NodeName = "node-2"
	cs := fake.NewSimpleClientset(bad, good)
	p := testProber(cs)
	res := probetest.MustCheck[*coreDNSUpstreamCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
	if !res.Pass {
		t.Fatalf("unscheduled DNS pod must be ignored: %+v", res)
	}
}

// node-local-dns is a DaemonSet: the readiness fallback must scope its
// heal cooldown by NODE, not just the shared controller key, or one
// agent's bounce parks every other node's agent for 30m.
func TestCoreDNSFallbackDaemonSetCooldownPerNode(t *testing.T) {
	ctrl := true
	dsOwner := []metav1.OwnerReference{{
		APIVersion: "apps/v1", Kind: "DaemonSet",
		Name: "node-local-dns", UID: "ds-localdns", Controller: &ctrl,
	}}
	pod := func(name, node string, ready bool, age time.Duration) *corev1.Pod {
		p := probetest.PodWithPhase("kube-system", name, corev1.PodRunning, ready, age)
		p.OwnerReferences = dsOwner
		p.Spec.NodeName = node
		return p
	}
	base := time.Now()
	bad1 := pod("node-local-dns-w1", "w1", false, 15*time.Minute)
	bad2 := pod("node-local-dns-w2", "w2", false, 15*time.Minute)
	good := pod("node-local-dns-w3", "w3", true, time.Hour)
	cs := fake.NewSimpleClientset(bad1, bad2, good,
		probetest.ReadyWorkerNode("w1", "", 0, false),
		probetest.ReadyWorkerNode("w2", "", 0, false),
		probetest.ReadyWorkerNode("w3", "", 0, false))
	p := testProber(cs) // dead prom URL -> readiness fallback
	chk := probetest.MustCheck[*coreDNSUpstreamCheck](t, p)
	probetest.FreezeNow(p.Deps, base)
	chk.Run(probetest.SweepCtx(ctx, p.Deps))

	get := func(name string) bool {
		_, err := cs.CoreV1().Pods("kube-system").Get(ctx, name, metav1.GetOptions{})
		return err == nil
	}
	if !get(bad2.Name) || !get(good.Name) {
		t.Fatal("one-delete-per-sweep cap broken on the first fallback sweep")
	}
	if get(bad1.Name) {
		t.Fatal("first unready node-local-dns agent was not bounced")
	}
	// Next sweep: w2 is a different failure domain. A controller-only
	// cooldown key would suppress it; the node-scoped key permits it.
	probetest.FreezeNow(p.Deps, base.Add(time.Minute))
	chk.Run(probetest.SweepCtx(ctx, p.Deps))
	if get(bad2.Name) {
		t.Fatal("second node's agent suppressed by the first node's cooldown")
	}
}

// coreDNSUpstreamPromServer answers the two coredns queries: the healthcheck
// query reports pod "bad" failing; the SERVFAIL query reports none.
func coreDNSUpstreamPromServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "healthcheck_failures_total") {
			return []probetest.PromTestSample{{
				Labels: map[string]string{"pod": "coredns-bad", "namespace": "kube-system"},
				Value:  1.4,
			}}
		}
		return nil
	})
	return srv
}

// Two dns pods sharing a bare name across namespaces must each be
// attributed to their own namespace — a bare-name census key would
// collapse them and silently drop one namespace's flag.
func TestCoreDNSUpstreamDuplicateNamesAcrossNamespaces(t *testing.T) {
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		if strings.Contains(query, "healthcheck_failures_total") {
			return []probetest.PromTestSample{
				{Labels: map[string]string{"pod": "coredns-dup", "namespace": "kube-system"}, Value: 1},
				{Labels: map[string]string{"pod": "coredns-dup", "namespace": "dns-secondary"}, Value: 1},
			}
		}
		return nil
	})
	kube1 := probetest.PodWithPhase("kube-system", "coredns-dup", corev1.PodRunning, true, time.Hour)
	kube2 := probetest.PodWithPhase("dns-secondary", "coredns-dup", corev1.PodRunning, true, time.Hour)
	cs := fake.NewSimpleClientset(kube1, kube2)
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()

	res := probetest.MustCheck[*coreDNSUpstreamCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass {
		t.Fatalf("both flagged pods must fail the check: %+v", res)
	}
	for _, key := range []string{"kube-system/coredns-dup", "dns-secondary/coredns-dup"} {
		if !strings.Contains(res.Why, key) {
			t.Fatalf("why missing %s (cross-ns name collision misattributed): %q", key, res.Why)
		}
	}
}

// isDNSPod is the census predicate deciding which pods the
// upstream-failure and readiness-fallback paths consider — by name
// prefix first, then the label spellings the upstream charts stamp.
// A pod matching none of them is invisible to the check.
func TestIsDNSPod(t *testing.T) {
	pod := func(name string, labels map[string]string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: name, Labels: labels}}
	}
	cases := []struct {
		name string
		pod  *corev1.Pod
		want bool
	}{
		{"coredns name prefix", pod("coredns-abc12", nil), true},
		{"node-local-dns name prefix", pod("node-local-dns-x1", nil), true},
		{"k8s-app kube-dns", pod("dns-1", map[string]string{"k8s-app": "kube-dns"}), true},
		{"k8s-app node-local-dns", pod("dns-2", map[string]string{"k8s-app": "node-local-dns"}), true},
		{"app name coredns", pod("dns-3", map[string]string{"app.kubernetes.io/name": "coredns"}), true},
		{"app name node-local-dns", pod("dns-4", map[string]string{"app.kubernetes.io/name": "node-local-dns"}), true},
		{"bare coredns name is not a prefix match", pod("coredns", nil), false},
		{"unrelated pod", pod("web-1", map[string]string{"app": "web"}), false},
		{"nil labels", pod("web-2", nil), false},
	}
	for _, tc := range cases {
		if got := isDNSPod(tc.pod); got != tc.want {
			t.Errorf("%s: isDNSPod=%v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestCoreDNSUpstreamDualMetricQueryAndLegacySupport(t *testing.T) {
	var seenQueries []string
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		seenQueries = append(seenQueries, query)
		if strings.Contains(query, `coredns_proxy_healthcheck_failures_total{proxy_name="forward"}`) &&
			strings.Contains(query, "coredns_forward_healthcheck_failures_total") {
			return []probetest.PromTestSample{{
				Labels: map[string]string{"pod": "coredns-bad", "namespace": "kube-system"},
				Value:  1.2,
			}}
		}
		return nil
	})
	bad := probetest.PodWithPhase("kube-system", "coredns-bad", corev1.PodRunning, true, time.Hour)
	good := probetest.PodWithPhase("kube-system", "coredns-good", corev1.PodRunning, true, time.Hour)
	cs := fake.NewSimpleClientset(bad, good)
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()

	res := probetest.MustCheck[*coreDNSUpstreamCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass {
		t.Fatalf("expected dual-metric query to flag failing pod: %+v", res)
	}
	foundHealthQuery := false
	for _, q := range seenQueries {
		if strings.Contains(q, "ForwardHealthcheckFailureCount") {
			t.Fatalf("issued obsolete non-existent CoreDNS metric query: %q", q)
		}
		if strings.Contains(q, `coredns_proxy_healthcheck_failures_total{proxy_name="forward"}`) &&
			strings.Contains(q, "coredns_forward_healthcheck_failures_total") {
			foundHealthQuery = true
		}
	}
	if !foundHealthQuery {
		t.Fatalf("missing modern+legacy CoreDNS healthcheck failure query in %v", seenQueries)
	}
}
