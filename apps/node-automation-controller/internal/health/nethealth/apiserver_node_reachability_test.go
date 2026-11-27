// apiserver_node_reachability_test.go — coverage for the
// apiserver-node-reachability check: the fresh-lease + probe-fail
// signature persisting past darkMinAge fences the node and deletes
// its Fail-policy webhook backends; dead-kubelet and mesh-wide
// shapes never act; recovery untaints.
package nethealth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// anrNodeLease builds the kube-node-lease/<node> heartbeat Lease —
// renewTime must sit within leaseFreshMaxAge of the check's FROZEN
// clock at run time, so callers pass the sweep's `now`.
func anrNodeLease(node string, renew time.Time) *coordinationv1.Lease {
	return &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-node-lease", Name: node},
		Spec: coordinationv1.LeaseSpec{
			RenewTime: &metav1.MicroTime{Time: renew}},
	}
}

// anrRefreshLeases re-stamps every kube-node-lease/<node> RenewTime
// to t — a live kubelet renews ~10s, so each sweep phase of a
// frozen-clock test re-arms freshness the way heartbeats do.
func anrRefreshLeases(t *testing.T, cs *fake.Clientset,
	nodes []string, renew time.Time) {
	t.Helper()
	for _, n := range nodes {
		l, err := cs.CoordinationV1().Leases("kube-node-lease").
			Get(ctx, n, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get lease %s: %v", n, err)
		}
		l.Spec.RenewTime = &metav1.MicroTime{Time: renew}
		if _, err := cs.CoordinationV1().Leases("kube-node-lease").
			Update(ctx, l, metav1.UpdateOptions{}); err != nil {
			t.Fatalf("update lease %s: %v", n, err)
		}
	}
}

// anrWebhookConfig builds a ValidatingWebhookConfiguration whose
// single sub-webhook calls svcRef with the given failure policy.
func anrWebhookConfig(name, svcNS, svcName string,
	policy admissionv1.FailurePolicyType) *admissionv1.ValidatingWebhookConfiguration {
	return &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Webhooks: []admissionv1.ValidatingWebhook{{
			Name:          "wh-" + name,
			FailurePolicy: ptr.To(policy),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: &admissionv1.ServiceReference{
					Namespace: svcNS, Name: svcName, Port: ptr.To(int32(443))},
			},
		}},
	}
}

// anrSlice builds the EndpointSlice binding svcName to one ready Pod
// endpoint on the given pod.
func anrSlice(ns, svcName, podNS, podName string) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: svcName + "-abc",
			Labels: map[string]string{
				discoveryv1.LabelServiceName: svcName}},
		Endpoints: []discoveryv1.Endpoint{{
			Addresses:  []string{"10.0.0.1"},
			Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
			TargetRef: &corev1.ObjectReference{
				Kind: "Pod", Namespace: podNS, Name: podName},
		}},
	}
}

// anrBackendPod builds a controller-owned Running pod on node —
// the webhook-backend heal candidate shape.
func anrBackendPod(ns, name, node string) *corev1.Pod {
	p := probetest.PodWithPhase(ns, name, corev1.PodRunning, true, time.Hour)
	p.Spec.NodeName = node
	ctrl := true
	p.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "apps/v1", Kind: "ReplicaSet",
		Name: "rs-" + name, Controller: &ctrl}}
	return p
}

// anrCheck builds the check with a probeFn stubbed per node — the
// kubeletreaper seam (fake clientset cannot serve the REST proxy).
func anrCheck(t *testing.T, p *probetest.Prober,
	darkNodes map[string]bool) *apiserverNodeReachabilityCheck {
	t.Helper()
	c := probetest.MustCheck[*apiserverNodeReachabilityCheck](t, p)
	c.probeFn = func(_ context.Context, node string) bool {
		return !darkNodes[node]
	}
	return c
}

// A probe-failing node with a fresh kubelet lease persists past
// darkMinAge: the check fences it and deletes the Fail-policy
// webhook backend pod scheduled there.
func TestApiserverDarkFencesAndEvacuates(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset([]runtime.Object{
		probetest.ReadyWorkerNode("w1", "", 0, false),
		probetest.ReadyWorkerNode("w2", "", 0, false),
		probetest.ReadyWorkerNode("w3", "", 0, false),
		probetest.ReadyWorkerNode("w4", "", 0, false),
		probetest.ReadyWorkerNode("w5", "", 0, false),
		probetest.ReadyWorkerNode("w6", "", 0, false),
		anrNodeLease("w1", base), anrNodeLease("w2", base),
		anrNodeLease("w3", base), anrNodeLease("w4", base),
		anrNodeLease("w5", base), anrNodeLease("w6", base),
		anrWebhookConfig("linkerd-policy-validator", "linkerd",
			"linkerd-policy-validator", admissionv1.Fail),
		anrSlice("linkerd", "linkerd-policy-validator", "linkerd",
			"linkerd-destination-aaa"),
		anrBackendPod("linkerd", "linkerd-destination-aaa", "w1"),
		anrBackendPod("linkerd", "linkerd-destination-bbb", "w2"),
	}...)
	p := testProber(cs)
	probetest.FreezeNow(p.Deps, base)
	check := anrCheck(t, p, map[string]bool{"w1": true})

	// First sight: inside darkMinAge — pass, no taint yet.
	if res := check.Run(probetest.SweepCtx(ctx, check.Deps)); !res.Pass {
		t.Fatalf("first sight inside window must pass: %+v", res)
	}
	if kube.HasTaint(mustNode(t, cs, "w1").Spec.Taints,
		kube.TaintApiserverUnreachable) {
		t.Fatal("taint before persistence window")
	}

	// Past the window: w1 fenced + its webhook backend deleted.
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	anrRefreshLeases(t, cs,
		[]string{"w1", "w2", "w3", "w4", "w5", "w6"}, base.Add(11*time.Minute))
	res := check.Run(probetest.SweepCtx(ctx, check.Deps))
	if res.Pass {
		t.Fatal("persisted apiserver-dark node must FAIL the sweep")
	}
	if !kube.HasTaint(mustNode(t, cs, "w1").Spec.Taints,
		kube.TaintApiserverUnreachable) {
		t.Fatal("apiserver-dark node not fenced")
	}
	if _, err := cs.CoreV1().Pods("linkerd").Get(ctx,
		"linkerd-destination-aaa", metav1.GetOptions{}); err == nil {
		t.Fatal("webhook backend on dark node not deleted")
	}
	if _, err := cs.CoreV1().Pods("linkerd").Get(ctx,
		"linkerd-destination-bbb", metav1.GetOptions{}); err != nil {
		t.Fatal("webhook backend on healthy node must survive")
	}
}

// A probe-failing node whose kubelet Lease is STALE is the
// dead-kubelet case — kubelet-liveness-reaper's domain, never
// fenced here.
func TestApiserverDarkStaleLeaseSkips(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset([]runtime.Object{
		probetest.ReadyWorkerNode("w1", "", 0, false),
		probetest.ReadyWorkerNode("w2", "", 0, false),
		probetest.ReadyWorkerNode("w3", "", 0, false),
		probetest.ReadyWorkerNode("w4", "", 0, false),
		probetest.ReadyWorkerNode("w5", "", 0, false),
		probetest.ReadyWorkerNode("w6", "", 0, false),
		anrNodeLease("w1", base), anrNodeLease("w2", base),
		anrNodeLease("w3", base), anrNodeLease("w4", base),
		anrNodeLease("w5", base),
		// w6 lease stale — renewTime far outside leaseFreshMaxAge.
		anrNodeLease("w6", base.Add(-10*time.Minute)),
	}...)
	p := testProber(cs)
	probetest.FreezeNow(p.Deps, base)
	// w1..w5 probe OK; only w6 fails — but its lease is stale.
	check := anrCheck(t, p, map[string]bool{"w6": true})

	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	anrRefreshLeases(t, cs,
		[]string{"w1", "w2", "w3", "w4", "w5"}, base.Add(11*time.Minute))
	// w6 stays stale — the dead-kubelet case.
	res := check.Run(probetest.SweepCtx(ctx, check.Deps))
	if !res.Pass {
		t.Fatalf("dead-kubelet probe failure is not this check's evidence: %+v", res)
	}
	if kube.HasTaint(mustNode(t, cs, "w6").Spec.Taints,
		kube.TaintApiserverUnreachable) {
		t.Fatal("stale-lease node must not be fenced by this check")
	}
}

// >= half the workers dark is a mesh-wide/apiserver-side fault —
// the sweep reports but fences nothing.
func TestApiserverDarkMeshWideAborts(t *testing.T) {
	base := time.Now()
	var objs []runtime.Object
	for _, n := range []string{"w1", "w2", "w3", "w4"} {
		objs = append(objs, probetest.ReadyWorkerNode(n, "", 0, false),
			anrNodeLease(n, base))
	}
	cs := fake.NewSimpleClientset(objs...)
	p := testProber(cs)
	probetest.FreezeNow(p.Deps, base)
	// 3 of 4 workers dark — majority.
	check := anrCheck(t, p, map[string]bool{"w1": true, "w2": true, "w3": true})

	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	anrRefreshLeases(t, cs, []string{"w1", "w2", "w3", "w4"}, base.Add(11*time.Minute))
	res := check.Run(probetest.SweepCtx(ctx, check.Deps))
	// Mesh-wide dark is a real outage — the sweep FAILs with the
	// finding but must fence nothing.
	if res.Pass {
		t.Fatal("mesh-wide probe failure must FAIL the sweep")
	}
	for _, n := range []string{"w1", "w2", "w3", "w4"} {
		if kube.HasTaint(mustNode(t, cs, n).Spec.Taints,
			kube.TaintApiserverUnreachable) {
			t.Fatalf("mesh-wide abort must not fence %s", n)
		}
	}
}

// A mass dead-kubelet event (probe fails + STALE leases) must not
// trip the mesh-wide guard and suppress fencing of a genuinely
// apiserver-dark node sharing the sweep — the guard counts only
// fresh-lease candidates.
func TestApiserverDarkDeadKubeletFleetDoesNotAbort(t *testing.T) {
	base := time.Now()
	var objs []runtime.Object
	for _, n := range []string{"w1", "w2", "w3", "w4", "w5"} {
		// Dead kubelets: probe fails AND lease stale.
		objs = append(objs, probetest.ReadyWorkerNode(n, "", 0, false),
			anrNodeLease(n, base.Add(-10*time.Minute)))
	}
	objs = append(objs,
		probetest.ReadyWorkerNode("w6", "", 0, false),
		anrNodeLease("w6", base))
	cs := fake.NewSimpleClientset(objs...)
	p := testProber(cs)
	probetest.FreezeNow(p.Deps, base)
	// w1..w5 dead-kubelet + w6 apiserver-dark — 6/6 probe failures
	// but only 1 fresh-lease candidate.
	check := anrCheck(t, p, map[string]bool{
		"w1": true, "w2": true, "w3": true,
		"w4": true, "w5": true, "w6": true})
	check.Run(probetest.SweepCtx(ctx, check.Deps))

	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	// Live kubelets keep renewing — w6 stays fresh, dead ones stay
	// stale (nobody renews a dead kubelet's lease).
	anrRefreshLeases(t, cs, []string{"w6"}, base.Add(11*time.Minute))
	check.Run(probetest.SweepCtx(ctx, check.Deps))
	if !kube.HasTaint(mustNode(t, cs, "w6").Spec.Taints,
		kube.TaintApiserverUnreachable) {
		t.Fatal("dead-kubelet fleet must not suppress the real dark node's fence")
	}
}

// Recovery: a fenced node whose probe answers again is unfenced on
// the next sweep — the taint lifecycle is self-contained.
func TestApiserverDarkRecoveryUntaints(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset([]runtime.Object{
		probetest.ReadyWorkerNode("w1", "", 0, false),
		probetest.ReadyWorkerNode("w2", "", 0, false),
		probetest.ReadyWorkerNode("w3", "", 0, false),
		probetest.ReadyWorkerNode("w4", "", 0, false),
		probetest.ReadyWorkerNode("w5", "", 0, false),
		probetest.ReadyWorkerNode("w6", "", 0, false),
		anrNodeLease("w1", base), anrNodeLease("w2", base),
		anrNodeLease("w3", base), anrNodeLease("w4", base),
		anrNodeLease("w5", base), anrNodeLease("w6", base),
	}...)
	p := testProber(cs)
	probetest.FreezeNow(p.Deps, base)
	check := anrCheck(t, p, map[string]bool{"w1": true})
	// First sight at base — inside darkMinAge, no taint yet.
	check.Run(probetest.SweepCtx(ctx, check.Deps))
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	anrRefreshLeases(t, cs,
		[]string{"w1", "w2", "w3", "w4", "w5", "w6"}, base.Add(11*time.Minute))
	check.Run(probetest.SweepCtx(ctx, check.Deps))
	if !kube.HasTaint(mustNode(t, cs, "w1").Spec.Taints,
		kube.TaintApiserverUnreachable) {
		t.Fatal("setup: node not fenced")
	}

	// Probe recovers — w1 answers again.
	check.probeFn = func(_ context.Context, _node string) bool { return true }
	probetest.FreezeNow(p.Deps, base.Add(16*time.Minute))
	anrRefreshLeases(t, cs,
		[]string{"w1", "w2", "w3", "w4", "w5", "w6"}, base.Add(16*time.Minute))
	check.Run(probetest.SweepCtx(ctx, check.Deps))
	if kube.HasTaint(mustNode(t, cs, "w1").Spec.Taints,
		kube.TaintApiserverUnreachable) {
		t.Fatal("recovered node still fenced")
	}
}

// mustNode fetches a node from the fake clientset for taint asserts.
func mustNode(t *testing.T, cs *fake.Clientset, name string) *corev1.Node {
	t.Helper()
	n, err := cs.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get node %s: %v", name, err)
	}
	return n
}

func TestApiserverNodeReachabilityProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "ok-node") {
			_, _ = w.Write([]byte("ok\n"))
			return
		}
		http.Error(w, "unreachable", http.StatusBadGateway)
	}))
	defer srv.Close()

	cs, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatalf("NewForConfig: %v", err)
	}
	chk := &apiserverNodeReachabilityCheck{
		Deps:     probetest.NewDeps(cs, nil),
		probeGap: time.Millisecond,
	}
	if !chk.probe(ctx, "ok-node") {
		t.Fatal("expected ok-node probe (\"ok\\n\") to return true")
	}
	if chk.probe(ctx, "bad-node") {
		t.Fatal("expected bad-node probe to return false")
	}
}

// Transient 1-shot / 2-shot proxy blips must be absorbed by the 3-attempt
// retry loop before marking a node dark; 3 consecutive failures return false.
func TestApiserverNodeReachabilityProbeRetriesBlip(t *testing.T) {
	attempts := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "flaky-node"):
			attempts["flaky-node"]++
			if attempts["flaky-node"] < 3 {
				http.Error(w, "blip", http.StatusBadGateway)
				return
			}
			_, _ = w.Write([]byte(" ok \n"))
		case strings.Contains(r.URL.Path, "dead-node"):
			attempts["dead-node"]++
			http.Error(w, "timeout", http.StatusGatewayTimeout)
		}
	}))
	defer srv.Close()

	cs, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatalf("NewForConfig: %v", err)
	}
	chk := &apiserverNodeReachabilityCheck{
		Deps:     probetest.NewDeps(cs, nil),
		probeGap: time.Millisecond,
	}
	if !chk.probe(ctx, "flaky-node") {
		t.Fatal("expected flaky-node to succeed on 3rd attempt")
	}
	if attempts["flaky-node"] != 3 {
		t.Fatalf("flaky-node attempts = %d, want 3", attempts["flaky-node"])
	}
	if chk.probe(ctx, "dead-node") {
		t.Fatal("expected dead-node to fail after 3 attempts")
	}
	if attempts["dead-node"] != 3 {
		t.Fatalf("dead-node attempts = %d, want 3", attempts["dead-node"])
	}
}

// Production regression: a worker node whose Ready condition is False
// while still carrying passiontech.dev/apiserver-unreachable must still be
// probed and untainted as soon as kubelet /proxy/healthz answers "ok\n".
// Control-plane nodes remain skipped.
func TestApiserverDarkUntaintsNotReadyNodeOnHealthzOK(t *testing.T) {
	base := time.Now()
	notReadyWorker := probetest.ReadyWorkerNode("w1", "", 0, false)
	notReadyWorker.Status.Conditions = []corev1.NodeCondition{{
		Type:   corev1.NodeReady,
		Status: corev1.ConditionFalse,
	}}
	notReadyWorker.Spec.Taints = []corev1.Taint{{
		Key:    kube.TaintApiserverUnreachable,
		Value:  "true",
		Effect: corev1.TaintEffectNoSchedule,
	}}
	notReadyCP := probetest.ReadyWorkerNode("cp1", "", 0, false)
	notReadyCP.Labels = map[string]string{"node-role.kubernetes.io/control-plane": ""}
	notReadyCP.Status.Conditions = []corev1.NodeCondition{{
		Type:   corev1.NodeReady,
		Status: corev1.ConditionFalse,
	}}
	notReadyCP.Spec.Taints = []corev1.Taint{{
		Key:    kube.TaintApiserverUnreachable,
		Value:  "true",
		Effect: corev1.TaintEffectNoSchedule,
	}}

	cs := fake.NewSimpleClientset(
		notReadyWorker,
		notReadyCP,
		probetest.ReadyWorkerNode("w2", "", 0, false),
		anrNodeLease("w1", base),
		anrNodeLease("w2", base),
	)
	p := testProber(cs)
	probetest.FreezeNow(p.Deps, base)

	// Wire a real HTTP healthz server returning "ok\n" to exercise the
	// TrimSpace("ok\n") path end-to-end inside probeFn.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	}))
	defer srv.Close()
	probeCS, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatalf("NewForConfig: %v", err)
	}
	probeHelper := &apiserverNodeReachabilityCheck{
		Deps:     probetest.NewDeps(probeCS, nil),
		probeGap: time.Millisecond,
	}

	var probedMu sync.Mutex
	probed := map[string]bool{}
	check := probetest.MustCheck[*apiserverNodeReachabilityCheck](t, p)
	check.probeFn = func(ctx context.Context, node string) bool {
		probedMu.Lock()
		probed[node] = true
		probedMu.Unlock()
		return probeHelper.probe(ctx, node)
	}

	res := check.Run(probetest.SweepCtx(ctx, check.Deps))
	if !res.Pass {
		t.Fatalf("sweep with recovered NotReady worker must pass: %+v", res)
	}
	if !probed["w1"] {
		t.Fatal("NotReady worker carrying apiserver-unreachable taint was not probed")
	}
	if probed["cp1"] {
		t.Fatal("control-plane node must remain skipped")
	}
	if kube.HasTaint(mustNode(t, cs, "w1").Spec.Taints, kube.TaintApiserverUnreachable) {
		t.Fatal("apiserver-unreachable taint was not removed from NotReady worker after healthz returned ok\\n")
	}
	if !kube.HasTaint(mustNode(t, cs, "cp1").Spec.Taints, kube.TaintApiserverUnreachable) {
		t.Fatal("control-plane node must not be untainted by worker check")
	}
}

func TestApiserverDarkSingleWorkerNeverFences(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w1", "", 0, false),
		anrNodeLease("w1", base),
		anrWebhookConfig("wh-test", "ns", "svc", admissionv1.Fail),
		anrSlice("ns", "svc", "ns", "backend-1"),
		anrBackendPod("ns", "backend-1", "w1"),
	)
	p := testProber(cs)
	probetest.FreezeNow(p.Deps, base)
	check := anrCheck(t, p, map[string]bool{"w1": true})

	check.Run(probetest.SweepCtx(ctx, check.Deps))
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	anrRefreshLeases(t, cs, []string{"w1"}, base.Add(11*time.Minute))
	res := check.Run(probetest.SweepCtx(ctx, check.Deps))
	if res.Pass {
		t.Fatal("single dark worker must still fail the sweep (the finding is the alert)")
	}
	if kube.HasTaint(mustNode(t, cs, "w1").Spec.Taints, kube.TaintApiserverUnreachable) {
		t.Fatal("single-worker cluster must NOT fence its only worker — no peer to compare, nowhere to reschedule")
	}
	if _, err := cs.CoreV1().Pods("ns").Get(ctx, "backend-1", metav1.GetOptions{}); err != nil {
		t.Fatalf("no fence means no webhook-backend evacuation: %v", err)
	}
}

// A single HEALTHY worker (zero dark candidates) must PASS cleanly —
// no finding, no FAIL, no taint. The mesh-wide/single-worker guard
// exists to SUPPRESS fencing, so it may only fire when at least one
// worker is actually dark. An unconditional `len(candidates) <= 1`
// branch emitted a bogus "apiserver-dark on 0/1 workers" finding and
// pinned every healthy one-worker cluster at FAIL=1 forever.
func TestApiserverDarkSingleHealthyWorkerPasses(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w1", "", 0, false),
		anrNodeLease("w1", base),
	)
	p := testProber(cs)
	probetest.FreezeNow(p.Deps, base)
	check := anrCheck(t, p, nil) // w1 probes OK — no dark candidate

	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	anrRefreshLeases(t, cs, []string{"w1"}, base.Add(11*time.Minute))
	res := check.Run(probetest.SweepCtx(ctx, check.Deps))
	if !res.Pass {
		t.Fatalf("single healthy worker must PASS: %+v", res)
	}
	if res.Why != "" {
		t.Fatalf("healthy fleet must emit no finding, got %q", res.Why)
	}
	if kube.HasTaint(mustNode(t, cs, "w1").Spec.Taints, kube.TaintApiserverUnreachable) {
		t.Fatal("healthy worker must not be fenced")
	}
}

// Recovery untaints BEFORE the mesh-wide guard: a previously fenced
// node whose probe answers again must be unfenced even when a
// majority of the other workers are dark in the same sweep. The old
// order returned early on the mesh-wide verdict and stranded the
// recovered node with its NoSchedule taint until the blip cleared.
func TestApiserverDarkUntaintsBeforeMeshWideGuard(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w1", "", 0, false),
		probetest.ReadyWorkerNode("w2", "", 0, false),
		probetest.ReadyWorkerNode("w3", "", 0, false),
		probetest.ReadyWorkerNode("w4", "", 0, false),
		anrNodeLease("w1", base), anrNodeLease("w2", base),
		anrNodeLease("w3", base), anrNodeLease("w4", base),
	)
	if err := kube.TaintNode(ctx, cs, "w1", kube.TaintApiserverUnreachable,
		"true", corev1.TaintEffectNoSchedule); err != nil {
		t.Fatalf("seed fence taint: %v", err)
	}
	p := testProber(cs)
	probetest.FreezeNow(p.Deps, base)
	// w1 recovered (probe OK); w2+w3 dark -> 2/4 triggers mesh-wide.
	check := anrCheck(t, p, map[string]bool{"w2": true, "w3": true})
	res := check.Run(probetest.SweepCtx(ctx, check.Deps))
	if res.Pass {
		t.Fatal("mesh-wide dark must still fail the sweep")
	}
	if kube.HasTaint(mustNode(t, cs, "w1").Spec.Taints, kube.TaintApiserverUnreachable) {
		t.Fatal("recovered node must be unfenced even when the mesh-wide guard aborts fencing")
	}
	for _, n := range []string{"w2", "w3"} {
		if kube.HasTaint(mustNode(t, cs, n).Spec.Taints, kube.TaintApiserverUnreachable) {
			t.Fatalf("mesh-wide guard must not fence %s", n)
		}
	}
}

// A controller restart empties the in-RAM seen ledger: a node still
// carrying the fence taint whose probe keeps failing must stay in
// fencedDark so its Fail-policy webhook backends keep being
// evacuated (instead of waiting a fresh darkMinAge after every
// operator rollout).
func TestApiserverDarkFenceSurvivesRestart(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w1", "", 0, false),
		probetest.ReadyWorkerNode("w2", "", 0, false),
		probetest.ReadyWorkerNode("w3", "", 0, false),
		probetest.ReadyWorkerNode("w4", "", 0, false),
		anrNodeLease("w1", base), anrNodeLease("w2", base),
		anrNodeLease("w3", base), anrNodeLease("w4", base),
		anrWebhookConfig("wh-test", "ns", "svc", admissionv1.Fail),
		anrSlice("ns", "svc", "ns", "backend-1"),
		anrBackendPod("ns", "backend-1", "w1"),
	)
	if err := kube.TaintNode(ctx, cs, "w1", kube.TaintApiserverUnreachable,
		"true", corev1.TaintEffectNoSchedule); err != nil {
		t.Fatalf("seed fence taint: %v", err)
	}
	p := testProber(cs)
	probetest.FreezeNow(p.Deps, base)
	// Fresh check instance (empty seen ledger) = controller restart.
	check := anrCheck(t, p, map[string]bool{"w1": true})
	if res := check.Run(probetest.SweepCtx(ctx, check.Deps)); res.Pass {
		t.Fatal("persisted dark node must fail the sweep")
	}
	if _, err := cs.CoreV1().Pods("ns").Get(ctx, "backend-1", metav1.GetOptions{}); err == nil {
		t.Fatal("fenced-dark node's webhook backend must be evacuated on the first post-restart sweep")
	}
}

func TestApiserverDarkSkipsPodEvictionWhenFenceDeferred(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset(
		probetest.ReadyWorkerNode("w1", "", 0, false),
		probetest.ReadyWorkerNode("w2", "", 0, false),
		probetest.ReadyWorkerNode("w3", "", 0, false),
		probetest.ReadyWorkerNode("w4", "", 0, false),
		anrNodeLease("w1", base), anrNodeLease("w2", base),
		anrNodeLease("w3", base), anrNodeLease("w4", base),
		anrWebhookConfig("wh-test", "ns", "svc", admissionv1.Fail),
		anrSlice("ns", "svc", "ns", "backend-1"),
		anrBackendPod("ns", "backend-1", "w1"),
	)
	cs.PrependReactor("patch", "nodes", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("taint rejected")
	})
	p := testProber(cs)
	probetest.FreezeNow(p.Deps, base)
	check := anrCheck(t, p, map[string]bool{"w1": true})

	check.Run(probetest.SweepCtx(ctx, check.Deps))
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	anrRefreshLeases(t, cs, []string{"w1", "w2", "w3", "w4"}, base.Add(11*time.Minute))
	check.Run(probetest.SweepCtx(ctx, check.Deps))

	if kube.HasTaint(mustNode(t, cs, "w1").Spec.Taints, kube.TaintApiserverUnreachable) {
		t.Fatal("unexpected fence taint on w1")
	}
	if _, err := cs.CoreV1().Pods("ns").Get(ctx, "backend-1", metav1.GetOptions{}); err != nil {
		t.Fatalf("webhook backend pod on unfenced node must not be deleted: %v", err)
	}
}
