// cilium_node_ipam_exhaustion_test.go — coverage for the
// cilium-node-ipam-exhaustion check (cilium-node-ipam-exhaustion): exhaustion FAIL +
// terminal-pod reap, healthy node, podCIDR capacity math.
package nethealth

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// cilium-node-ipam-exhaustion — cilium-node-ipam-exhaustion
// ---------------------------------------------------------------------------

func TestCiliumIPAMExhaustionFailsAndReapsTerminalPods(t *testing.T) {
	// /30 podCIDR -> 2 usable IPs; 2 running pods exhaust it.
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "w-exhaust"},
		Spec: corev1.NodeSpec{PodCIDR: "10.240.0.0/30"}}
	p1 := probetest.PodWithPhase("apps", "app-1", corev1.PodRunning, true, time.Hour)
	p1.Spec.NodeName = "w-exhaust"
	p2 := probetest.PodWithPhase("apps", "app-2", corev1.PodRunning, true, time.Hour)
	p2.Spec.NodeName = "w-exhaust"
	dead := probetest.PodWithPhase("apps", "app-dead", corev1.PodSucceeded, false, time.Hour)
	dead.Spec.NodeName = "w-exhaust"
	cs := fake.NewSimpleClientset(node, p1, p2, dead)
	// The fake ignores field selectors — teach it spec.nodeName so
	// the per-node reap list stays scoped like the real apiserver.
	testutil.EmulatePodNodeNameSelector(cs)
	p := testProber(cs) // dead prom -> pod-count fallback

	res := probetest.MustCheck[*ciliumNodeIPAMExhaustionCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("exhausted node must fail: %+v", res)
	}
	if !strings.Contains(res.Why, "w-exhaust") {
		t.Fatalf("why missing node: %q", res.Why)
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "app-dead", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("terminal pod should be reaped, err=%v", err)
	}
	for _, name := range []string{"app-1", "app-2"} {
		if _, err := cs.CoreV1().Pods("apps").Get(ctx, name, metav1.GetOptions{}); err != nil {
			t.Fatalf("live pod %s must survive: %v", name, err)
		}
	}
}

func TestCiliumIPAMHealthyNodePasses(t *testing.T) {
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "w-ok"},
		Spec: corev1.NodeSpec{PodCIDR: "10.240.1.0/24"}}
	cs := fake.NewSimpleClientset(node)
	p := testProber(cs)
	if res := probetest.MustCheck[*ciliumNodeIPAMExhaustionCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("empty /24 must pass: %+v", res)
	}
}

func TestPodCIDRCapacity(t *testing.T) {
	if got, ok := podCIDRCapacity("10.0.0.0/24"); !ok || got != 254 {
		t.Fatalf("/24 capacity = %d,%v want 254,true", got, ok)
	}
	if _, ok := podCIDRCapacity("fd00::/64"); ok {
		t.Fatal("IPv6 podCIDR must be skipped")
	}
	if _, ok := podCIDRCapacity(""); ok {
		t.Fatal("empty podCIDR must be skipped")
	}
	if got, ok := podCIDRCapacity("10.0.0.1/32"); !ok || got != 1 {
		t.Fatalf("/32 capacity = %d,%v want 1,true (usable floor)", got, ok)
	}
	if _, ok := podCIDRCapacity("0.0.0.0/0"); ok {
		t.Fatal("/0 podCIDR must be skipped (no host bits)")
	}
}

// ipamNode builds a bare node carrying the given podCIDR ("" / IPv6 /
// garbage all exercise the podCIDRCapacity skip).
func ipamNode(name, podCIDR string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.NodeSpec{PodCIDR: podCIDR}}
}

// ipamPodOnNode builds a Running pod pinned to node — the pod-count
// fallback's census input.
func ipamPodOnNode(ns, name, node string, phase corev1.PodPhase) *corev1.Pod {
	p := probetest.PodWithPhase(ns, name, phase, true, time.Hour)
	p.Spec.NodeName = node
	return p
}

// promIPAMServer wires a PromTestServer that answers the two
// cilium_operator_ipam_* queries from the given sample maps (nil map
// = empty vector for that metric).
func promIPAMServer(t *testing.T, used, avail map[string]float64) *httptest.Server {
	t.Helper()
	srv, _ := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
		var out []probetest.PromTestSample
		src := used
		if strings.Contains(query, "available_ips") {
			src = avail
		}
		for node, v := range src {
			out = append(out, probetest.PromTestSample{
				Labels: map[string]string{"target_node": node}, Value: v})
		}
		return out
	})
	return srv
}

// Operator IPAM accounting is authoritative when present: used=200
// avail=10 on an otherwise EMPTY /24 reads 4.8% free — FAIL — where
// the pod census alone would report 100% free.
func TestCiliumIPAMPrometheusAccountingWins(t *testing.T) {
	node := ipamNode("w-prom", "10.240.2.0/24")
	cs := fake.NewSimpleClientset(node)
	srv := promIPAMServer(t,
		map[string]float64{"w-prom": 200},
		map[string]float64{"w-prom": 10})
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()

	res := probetest.MustCheck[*ciliumNodeIPAMExhaustionCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("operator-reported 4.8%% free must fail despite an empty pod census: %+v", res)
	}
	if !strings.Contains(res.Why, "w-prom") {
		t.Fatalf("why missing the exhausted node: %q", res.Why)
	}
	if m := probetest.FindMetric(t, "node_automation_cilium_ipam_free_ratio",
		map[string]string{"node": "w-prom"}); m == nil {
		t.Fatal("free-ratio gauge missing for the prom-covered node")
	}
}

// used_ips present but available_ips empty for the node: the ratio
// falls back to capacity math with the operator's used count — and a
// node absent from used_ips entirely keeps the pod-count path.
func TestCiliumIPAMPrometheusPartialCoverage(t *testing.T) {
	nodes := []*corev1.Node{
		ipamNode("w-mix", "10.240.3.0/30"),  // used=2 of 2 -> 0% free
		ipamNode("w-pc", "10.240.4.0/30"),   // not in prom -> pod count
		ipamNode("w-zero", "10.240.5.0/24"), // used=0 avail=0 -> capacity math
		ipamNode("w-ok", "10.240.6.0/24"),   // healthy either way
	}
	pods := []runtime.Object{
		ipamPodOnNode("apps", "pc-1", "w-pc", corev1.PodRunning),
		ipamPodOnNode("apps", "pc-2", "w-pc", corev1.PodRunning),
	}
	objs := make([]runtime.Object, 0, len(nodes)+len(pods))
	for _, n := range nodes {
		objs = append(objs, n)
	}
	objs = append(objs, pods...)
	cs := fake.NewSimpleClientset(objs...)
	testutil.EmulatePodNodeNameSelector(cs)
	srv := promIPAMServer(t,
		map[string]float64{"w-mix": 2, "w-zero": 0},
		map[string]float64{"w-zero": 0})
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()

	res := probetest.MustCheck[*ciliumNodeIPAMExhaustionCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("exhausted nodes must fail")
	}
	for _, want := range []string{"w-mix", "w-pc"} {
		if !strings.Contains(res.Why, want) {
			t.Fatalf("why missing %s: %q", want, res.Why)
		}
	}
	for _, notWant := range []string{"w-zero", "w-ok"} {
		if strings.Contains(res.Why, notWant) {
			t.Fatalf("healthy node %s reported as finding: %q", notWant, res.Why)
		}
	}
}

// A failed available_ips query poisons the whole prom path (promOK
// stays false): every node reads pod-count even though used_ips
// answered — fail back to the census, never to a half-answer.
func TestCiliumIPAMAvailableQueryErrorFallsBack(t *testing.T) {
	node := ipamNode("w1", "10.240.7.0/24")
	cs := fake.NewSimpleClientset(node)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Query().Get("query"), "available_ips") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[`+
			`{"metric":{"target_node":"w1"},"value":[1,"250"]}]}}`)
	}))
	defer srv.Close()
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()

	// Pod census says 100% free — only the (broken) prom path could
	// have failed this node.
	if res := probetest.MustCheck[*ciliumNodeIPAMExhaustionCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("avail-query failure must degrade to pod-count, got %+v", res)
	}
}

// The pod-count census skips the shapes that hold no pod IP:
// hostNetwork pods, unscheduled pods, and terminal pods — a node
// carrying only those stays at 100% free.
func TestCiliumIPAMPodCountSkipsNonIPShapes(t *testing.T) {
	node := ipamNode("w-filters", "10.240.8.0/30")
	hostNet := ipamPodOnNode("apps", "host-net", "w-filters", corev1.PodRunning)
	hostNet.Spec.HostNetwork = true
	unscheduled := probetest.PodWithPhase("apps", "pending", corev1.PodPending, true, time.Hour)
	unscheduled.Spec.NodeName = ""
	terminal := ipamPodOnNode("apps", "done", "w-filters", corev1.PodSucceeded)
	live := ipamPodOnNode("apps", "live", "w-filters", corev1.PodRunning)
	cs := fake.NewSimpleClientset(node, hostNet, unscheduled, terminal, live)
	p := testProber(cs) // dead prom -> pod-count fallback

	if res := probetest.MustCheck[*ciliumNodeIPAMExhaustionCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("only 1 IP-holding pod on a /30 must pass: %+v", res)
	}
}

// used > capacity clamps free at 0 rather than going negative —
// over-subscribed podCIDRs still read as fully exhausted.
func TestCiliumIPAMFreeClampsAtZero(t *testing.T) {
	node := ipamNode("w-over", "10.240.9.0/30") // 2 usable IPs
	pods := []runtime.Object{node}
	for i := 0; i < 3; i++ {
		pods = append(pods, ipamPodOnNode("apps",
			fmt.Sprintf("over-%d", i), "w-over", corev1.PodRunning))
	}
	cs := fake.NewSimpleClientset(pods...)
	testutil.EmulatePodNodeNameSelector(cs)
	p := testProber(cs)

	res := probetest.MustCheck[*ciliumNodeIPAMExhaustionCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("3 pods on a 2-IP podCIDR must fail")
	}
	if !strings.Contains(res.Why, "free=0/2") {
		t.Fatalf("why missing the clamped free=0 finding: %q", res.Why)
	}
}

// Nodes without a usable podCIDR (absent, IPv6, garbage) are skipped
// entirely — no gauge, no finding, no reap.
func TestCiliumIPAMSkipsBadPodCIDRNodes(t *testing.T) {
	nodes := []*corev1.Node{
		ipamNode("w-none", ""),
		ipamNode("w-v6", "fd00:10::/64"),
		ipamNode("w-garbage", "not-a-cidr"),
	}
	objs := make([]runtime.Object, 0, len(nodes))
	for _, n := range nodes {
		objs = append(objs, n)
	}
	cs := fake.NewSimpleClientset(objs...)
	p := testProber(cs)

	if res := probetest.MustCheck[*ciliumNodeIPAMExhaustionCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("unusable podCIDRs must be skipped, not failed: %+v", res)
	}
}

// A terminal pod already being deleted (DeletionTimestamp set) is not
// a reap target — the delete is already in flight.
func TestCiliumIPAMReapSkipsDeletingPod(t *testing.T) {
	node := ipamNode("w-del", "10.240.10.0/30")
	p1 := ipamPodOnNode("apps", "app-1", "w-del", corev1.PodRunning)
	p2 := ipamPodOnNode("apps", "app-2", "w-del", corev1.PodRunning)
	dying := ipamPodOnNode("apps", "app-dying", "w-del", corev1.PodSucceeded)
	dying.DeletionTimestamp = &metav1.Time{Time: time.Now()}
	cs := fake.NewSimpleClientset(node, p1, p2, dying)
	testutil.EmulatePodNodeNameSelector(cs)
	p := testProber(cs)

	res := probetest.MustCheck[*ciliumNodeIPAMExhaustionCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("exhausted node must fail")
	}
	if _, err := cs.CoreV1().Pods("apps").Get(ctx, "app-dying", metav1.GetOptions{}); err != nil {
		t.Fatalf("already-deleting pod must not be re-deleted: %v", err)
	}
}

// The per-node reap is capped at ciliumIPAMMaxReaps — a node carrying
// more terminal pods than the cap keeps the overflow for the next
// cooldown window.
func TestCiliumIPAMReapCap(t *testing.T) {
	node := ipamNode("w-cap", "10.240.11.0/30")
	pods := []runtime.Object{node,
		ipamPodOnNode("apps", "live-1", "w-cap", corev1.PodRunning),
		ipamPodOnNode("apps", "live-2", "w-cap", corev1.PodRunning)}
	for i := 0; i < ciliumIPAMMaxReaps+5; i++ {
		pods = append(pods, ipamPodOnNode("apps",
			fmt.Sprintf("dead-%02d", i), "w-cap", corev1.PodSucceeded))
	}
	cs := fake.NewSimpleClientset(pods...)
	testutil.EmulatePodNodeNameSelector(cs)
	p := testProber(cs)

	res := probetest.MustCheck[*ciliumNodeIPAMExhaustionCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("exhausted node must fail")
	}
	remaining := 0
	for i := 0; i < ciliumIPAMMaxReaps+5; i++ {
		if _, err := cs.CoreV1().Pods("apps").Get(ctx,
			fmt.Sprintf("dead-%02d", i), metav1.GetOptions{}); err == nil {
			remaining++
		}
	}
	if remaining != 5 {
		t.Fatalf("terminal pods remaining = %d, want exactly the 5 over cap", remaining)
	}
}

// Census failures are Infra results, not silent passes: the node list
// and the pod list each fail the check closed.
func TestCiliumIPAMInfraErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		verb string
		res  string
		objs []runtime.Object
	}{
		{"nodes", "list", "nodes", nil},
		{"pods", "list", "pods", []runtime.Object{ipamNode("w1", "10.240.12.0/24")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset(tc.objs...)
			cs.PrependReactor(tc.verb, tc.res,
				func(ktesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("api down")
				})
			p := testProber(cs)
			res := probetest.MustCheck[*ciliumNodeIPAMExhaustionCheck](t, p).Run(ctx)
			if res.Infra == nil {
				t.Fatalf("%s list failure must surface as Infra, got %+v", tc.name, res)
			}
		})
	}
}
