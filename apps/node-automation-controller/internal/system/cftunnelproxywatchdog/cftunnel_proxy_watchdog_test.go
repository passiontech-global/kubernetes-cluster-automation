package cftunnelproxywatchdog

import (
	"context"
	"errors"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

const cfWatchdogTestNS = "cf-test"

// proxyPod builds a gateway proxy pod carrying the watchdog's
// label selector; ready=false leaves the Ready condition False.
func proxyPod(name string, ready bool) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: cfWatchdogTestNS,
			Labels: map[string]string{
				"app.kubernetes.io/component": "proxy",
				"app.kubernetes.io/instance":  "cloudflare-tunnel-gateway-controller",
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	if ready {
		p.Status.Conditions = []corev1.PodCondition{
			{Type: corev1.PodReady, Status: corev1.ConditionTrue},
		}
	} else {
		p.Status.Conditions = []corev1.PodCondition{
			{Type: corev1.PodReady, Status: corev1.ConditionFalse},
		}
	}
	return p
}

// proxySlice is the headless-Service EndpointSlice the watchdog
// annotates to force a config push.
func proxySlice(name string) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: cfWatchdogTestNS,
			Labels: map[string]string{
				discoveryv1.LabelServiceName: cfTunnelProxySliceService,
			},
		},
	}
}

// proxyDeploy builds the proxy Deployment with the given status
// conditions (nil for a healthy one).
func proxyDeploy(conds []appsv1.DeploymentCondition) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: cfTunnelProxyDeployName, Namespace: cfWatchdogTestNS,
		},
		Status: appsv1.DeploymentStatus{Conditions: conds},
	}
}

func getSlice(t *testing.T, cs *fake.Clientset, name string) *discoveryv1.EndpointSlice {
	t.Helper()
	s, err := cs.DiscoveryV1().EndpointSlices(cfWatchdogTestNS).
		Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get endpointslice %s: %v", name, err)
	}
	return s
}

// A Running-but-not-Ready proxy pod forces a resync annotation on
// every headless-Service slice.
func TestWatchdogForcesResyncOnUnreadyPod(t *testing.T) {
	cs := fake.NewSimpleClientset(
		proxyPod("proxy-1", true),
		proxyPod("proxy-2", false), // stuck "no config loaded"
		proxySlice("proxy-headless-abc"),
		proxySlice("proxy-headless-def"),
		proxyDeploy(nil))
	w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS}
	if err := w.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, name := range []string{"proxy-headless-abc", "proxy-headless-def"} {
		got := getSlice(t, cs, name).Annotations[cfTunnelResyncAnno]
		if got == "" {
			t.Fatalf("slice %s not annotated for resync", name)
		}
	}
}

// All pods ready -> the slices must not be touched.
func TestWatchdogAllReadyNoSlicePatch(t *testing.T) {
	cs := fake.NewSimpleClientset(
		proxyPod("proxy-1", true),
		proxySlice("proxy-headless-abc"),
		proxyDeploy(nil))
	var patched bool
	cs.PrependReactor("patch", "endpointslices",
		func(ktesting.Action) (bool, runtime.Object, error) {
			patched = true
			return true, nil, nil
		})
	w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS}
	if err := w.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if patched {
		t.Fatal("annotated slices although every proxy pod is ready")
	}
}

// Pending (not yet Running) pods must not trigger a resync — the
// shell greps for "Running|False" exactly.
func TestWatchdogPendingPodNoResync(t *testing.T) {
	cs := fake.NewSimpleClientset(
		func() *corev1.Pod {
			p := proxyPod("proxy-1", false)
			p.Status.Phase = corev1.PodPending
			return p
		}(),
		proxySlice("proxy-headless-abc"),
		proxyDeploy(nil))
	var patched bool
	cs.PrependReactor("patch", "endpointslices",
		func(ktesting.Action) (bool, runtime.Object, error) {
			patched = true
			return true, nil, nil
		})
	w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS}
	if err := w.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if patched {
		t.Fatal("resynced for a Pending pod — only Running+notReady counts")
	}
}

// The forced resync is PACED: one annotated sweep per cooldown
// window, the sweeps in between only count the unready pods — and
// the stamp VALUE churns again once the window clears (each real
// resync stamps >= the cooldown apart, so the EndpointSlice always
// sees a new value and emits its event).
func TestWatchdogResyncCooldownPacesSweeps(t *testing.T) {
	now := time.Now()
	clock := now
	cs := fake.NewSimpleClientset(
		proxyPod("proxy-1", true),
		proxyPod("proxy-2", false), // stuck "no config loaded"
		proxySlice("proxy-headless-abc"),
		proxyDeploy(nil))
	var patches int
	cs.PrependReactor("patch", "endpointslices",
		func(ktesting.Action) (bool, runtime.Object, error) {
			patches++
			return false, nil, nil // fall through — the tracker applies it
		})
	w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS,
		now: func() time.Time { return clock }}
	if err := w.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	first := getSlice(t, cs, "proxy-headless-abc").Annotations[cfTunnelResyncAnno]
	if first == "" {
		t.Fatal("first sweep must annotate the slice")
	}
	if patches != 1 {
		t.Fatalf("first sweep patched %d times, want 1", patches)
	}

	// +5m: still inside the 10m window — count-only, no patch.
	clock = now.Add(5 * time.Minute)
	if err := w.run(context.Background()); err != nil {
		t.Fatalf("gated run: %v", err)
	}
	if patches != 1 {
		t.Fatalf("gated sweep patched %d times, want 0", patches-1)
	}
	if got := getSlice(t, cs, "proxy-headless-abc").Annotations[cfTunnelResyncAnno]; got != first {
		t.Fatal("gated sweep re-annotated the slice")
	}

	// +10m+1s: the window cleared — the resync fires again and the
	// value churns (a repeated value would emit no event).
	clock = now.Add(cfTunnelResyncCooldown + time.Second)
	if err := w.run(context.Background()); err != nil {
		t.Fatalf("post-cooldown run: %v", err)
	}
	if patches != 2 {
		t.Fatalf("post-cooldown sweep patched %d times total, want 2", patches)
	}
	second := getSlice(t, cs, "proxy-headless-abc").Annotations[cfTunnelResyncAnno]
	if second == first {
		t.Fatal("resync stamp value did not churn — no event would fire")
	}
}

// A failed slice patch must not arm the pacing cooldown — the next
// sweep retries ungated (delivered-only stamping).
func TestWatchdogResyncCooldownNotStampedOnPatchFailure(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		proxyPod("proxy-1", true),
		proxyPod("proxy-2", false),
		proxySlice("proxy-headless-abc"),
		proxyDeploy(nil))
	cs.PrependReactor("patch", "endpointslices",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS,
		now: func() time.Time { return now }}
	if err := w.run(context.Background()); err == nil {
		t.Fatal("expected the patch failure to surface")
	}
	if _, ok := w.lastResync.Last(cfTunnelProxySliceService); ok {
		t.Fatal("cooldown stamped although no slice patch was delivered")
	}
}

// A stale Progressing/ProgressDeadlineExceeded condition is removed
// via a status-subresource JSONPatch — same call the shell made with
// `kubectl patch --subresource=status --type=json`, plus a "test" op
// precondition so the remove only fires while the index still points
// at the stale condition (TOCTOU guard).
func TestWatchdogClearsStaleStall(t *testing.T) {
	cs := fake.NewSimpleClientset(
		proxyPod("proxy-1", true),
		proxyDeploy([]appsv1.DeploymentCondition{
			{Type: appsv1.DeploymentAvailable, Reason: "MinimumReplicasAvailable"},
			{Type: appsv1.DeploymentProgressing, Reason: "ProgressDeadlineExceeded"},
			{Type: appsv1.DeploymentReplicaFailure, Reason: "FailedCreate"},
		}))
	var gotType types.PatchType
	var gotPatch []byte
	var gotSubresource string
	cs.PrependReactor("patch", "deployments",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			pa := a.(ktesting.PatchAction)
			gotType = pa.GetPatchType()
			gotPatch = pa.GetPatch()
			gotSubresource = pa.GetSubresource()
			return true, nil, nil // don't apply; capture only
		})
	w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS}
	if err := w.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if gotType != types.JSONPatchType {
		t.Fatalf("patch type = %v, want JSONPatchType", gotType)
	}
	want := `[{"op":"test","path":"/status/conditions/1/reason","value":"ProgressDeadlineExceeded"},` +
		`{"op":"remove","path":"/status/conditions/1"}]`
	if string(gotPatch) != want {
		t.Fatalf("patch body = %s, want %s", gotPatch, want)
	}
	if gotSubresource != "status" {
		t.Fatalf("subresource = %q, want %q", gotSubresource, "status")
	}
}

// A raced test-op rejection (Invalid, the API server's answer when
// the precondition misses) must NOT abort the sweep: run() proceeds
// to healCloudflaredWedges (the wedged pod is deleted) and the
// periodic loop doesn't IncError. Non-conflict patch failures still
// propagate.
func TestWatchdogStallClearRaceDoesNotAbortSweep(t *testing.T) {
	now := time.Now()
	newCS := func() *fake.Clientset {
		return fake.NewSimpleClientset(
			proxyPod("proxy-ok", true),
			staleUnreadyProxyPod("proxy-wedged",
				now.Add(-time.Hour), now.Add(-10*time.Minute)),
			proxyDeploy([]appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentProgressing, Reason: "ProgressDeadlineExceeded"},
			}))
	}

	t.Run("Invalid test-op rejection — sweep continues", func(t *testing.T) {
		const queue = "cf-tunnel-proxy-watchdog-race-test"
		before := testutil.QueueErrorCount(t, queue)
		cs := newCS()
		cs.PrependReactor("patch", "deployments",
			func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, apierrors.NewInvalid(
					appsv1.SchemeGroupVersion.WithKind("Deployment").
						GroupKind(), "cloudflare-tunnel-proxy",
					field.ErrorList{field.Invalid(
						field.NewPath("status", "conditions").Index(0),
						"ProgressDeadlineExceeded", "test failed")})
			})
		cs.PrependReactor("get", "pods", cfLogReactor(
			"2026-11-20T00:00:00Z ERR Couldn't start tunnel: config file error\n"))
		w := &cfTunnelProxyWatchdog{cs: cs, dyn: testutil.NewDynamicClient(),
			queue: queue, namespace: cfWatchdogTestNS,
			now: func() time.Time { return now }}
		if err := w.run(context.Background()); err != nil {
			t.Fatalf("raced stall clear must not abort the sweep: %v", err)
		}
		if d := testutil.QueueErrorCount(t, queue) - before; d != 0 {
			t.Fatalf("raced stall clear counted %v sweep errors", d)
		}
		if cfPodExists(t, cs, cfWatchdogTestNS, "proxy-wedged") {
			t.Fatal("wedge heal skipped after raced stall clear")
		}
	})

	t.Run("non-conflict patch failure still surfaces", func(t *testing.T) {
		cs := newCS()
		cs.PrependReactor("patch", "deployments",
			func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("conn refused")
			})
		w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS,
			now: func() time.Time { return now }}
		if err := w.run(context.Background()); err == nil {
			t.Fatal("real patch failure must surface")
		}
	})
}

// No stale condition -> no status patch.
func TestWatchdogHealthyDeployNoPatch(t *testing.T) {
	cs := fake.NewSimpleClientset(
		proxyDeploy([]appsv1.DeploymentCondition{
			{Type: appsv1.DeploymentProgressing, Reason: "NewReplicaSetAvailable"},
		}))
	var patched bool
	cs.PrependReactor("patch", "deployments",
		func(ktesting.Action) (bool, runtime.Object, error) {
			patched = true
			return true, nil, nil
		})
	w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS}
	if err := w.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if patched {
		t.Fatal("patched a Deployment with no stale condition")
	}
}

// Missing Deployment = cluster without the release: quiet nil, not
// an error (the shell's `2>/dev/null || true`).
func TestWatchdogDeploymentNotFound(t *testing.T) {
	cs := fake.NewSimpleClientset(proxyPod("proxy-1", true))
	w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS}
	if err := w.run(context.Background()); err != nil {
		t.Fatalf("run must be a no-op when the Deployment is absent: %v", err)
	}
}

// A list failure aborts the cycle with an error — the periodic loop
// logs + IncError it.
func TestWatchdogPodListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS}
	if err := w.run(context.Background()); err == nil {
		t.Fatal("expected error when the pod list fails")
	}
}

// ---------------------------------------------------------------------------
// cloudflared-wedge-heal — wedged cloudflared connector healer.
// ---------------------------------------------------------------------------

// staleUnreadyProxyPod is proxyPod plus a Ready=False condition whose
// LastTransitionTime is `age` in the past — old enough for the
// wedge healer to consider it.
func staleUnreadyProxyPod(name string, created, unreadyFor time.Time) *corev1.Pod {
	p := proxyPod(name, false)
	p.CreationTimestamp = metav1.NewTime(created)
	lt := metav1.NewTime(unreadyFor)
	p.Status.Conditions[0].LastTransitionTime = lt
	return p
}

// connectorPod builds a pod in the ingress-controller namespace with
// the controlled-cloudflared-connector label.
func connectorPod(name string, created, unreadyFor time.Time) *corev1.Pod {
	p := staleUnreadyProxyPod(name, created, unreadyFor)
	p.Namespace = cfTunnelConnectorNS
	p.Labels = map[string]string{"app": "controlled-cloudflared-connector"}
	return p
}

// rsOwnedPod is staleUnreadyProxyPod carrying a controller
// OwnerReference to the ReplicaSet named rs — the object the heal
// cooldown persists on (healCooledDown/stampHealPersisted).
func rsOwnedPod(name, rs string, created, unreadyFor time.Time) *corev1.Pod {
	p := staleUnreadyProxyPod(name, created, unreadyFor)
	p.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "apps/v1",
		Kind:       "ReplicaSet",
		Name:       rs,
		UID:        types.UID("rs-uid-" + rs),
		Controller: ptr.To(true),
	}}
	return p
}

// healRs builds the ReplicaSet object rsOwnedPod points at, with the
// given heal annotation (nil = none).
func healRs(name string, annos map[string]string) *appsv1.ReplicaSet {
	return &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
		Name:        name,
		Namespace:   cfWatchdogTestNS,
		Annotations: annos,
	}}
}

// cfLogReactor answers pod log reads in cfWatchdogTestNS (the fake
// GetLogs action carries no pod name, so the body is shared across
// pods in a namespace).
func cfLogReactor(body string) ktesting.ReactionFunc {
	return func(a ktesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() != "log" {
			return false, nil, nil
		}
		return true, &runtime.Unknown{Raw: []byte(body)}, nil
	}
}

func cfPodExists(t *testing.T, cs *fake.Clientset, ns, name string) bool {
	t.Helper()
	_, err := cs.CoreV1().Pods(ns).Get(context.Background(), name, metav1.GetOptions{})
	return err == nil
}

// A stale-unready pod whose logs carry a fatal cloudflared signature
// is deleted even while siblings stay Ready — config resync cannot
// revive "Couldn't start tunnel".
func TestWatchdogDeletesPodWithFatalLogs(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		proxyPod("proxy-ok", true),
		staleUnreadyProxyPod("proxy-wedged",
			now.Add(-time.Hour), now.Add(-10*time.Minute)),
		proxyDeploy(nil))
	cs.PrependReactor("get", "pods", cfLogReactor(
		"2026-11-20T00:00:00Z ERR Couldn't start tunnel: config file error\n"))
	w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS, now: func() time.Time { return now }}
	if err := w.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if cfPodExists(t, cs, cfWatchdogTestNS, "proxy-wedged") {
		t.Fatal("fatal-log pod not deleted")
	}
	if !cfPodExists(t, cs, cfWatchdogTestNS, "proxy-ok") {
		t.Fatal("ready pod deleted")
	}
}

// heal.Gate is only consulted AFTER the detection pass proves at
// least one pod actually needs the delete: the mutex evaluation
// costs API reads and the heal budget is a shared global allowance.
// A node-list reactor that ERRORS makes the gate "unverifiable" (its
// IncError + its node read are the observable trace) — with nothing
// to heal the gate must never run (no node read, no IncError); with
// a wedged pod it must (IncError fires, no delete lands).
func TestWatchdogHealGateOnlyWithCandidates(t *testing.T) {
	now := time.Now()
	const queue = "cf-tunnel-proxy-watchdog-gate-test"

	nodeLists := 0
	nodeErr := func(a ktesting.Action) (bool, runtime.Object, error) {
		if a.GetResource().Resource != "nodes" {
			return false, nil, nil
		}
		nodeLists++
		return true, nil, errors.New("gate probe")
	}

	t.Run("nothing to heal — gate never consulted", func(t *testing.T) {
		before := testutil.QueueErrorCount(t, queue)
		cs := fake.NewSimpleClientset(
			proxyPod("proxy-ok", true),
			proxyDeploy(nil))
		cs.PrependReactor("*", "*", nodeErr)
		w := &cfTunnelProxyWatchdog{cs: cs, dyn: testutil.NewDynamicClient(),
			queue: queue, namespace: cfWatchdogTestNS,
			now: func() time.Time { return now }}
		if err := w.run(context.Background()); err != nil {
			t.Fatalf("run: %v", err)
		}
		if nodeLists != 0 {
			t.Fatalf("maintenance mutex evaluated with nothing to heal (%d node reads)", nodeLists)
		}
		if d := testutil.QueueErrorCount(t, queue) - before; d != 0 {
			t.Fatalf("empty sweep counted %v gate errors", d)
		}
	})

	t.Run("wedged pod — gate consulted, heal deferred unverifiable", func(t *testing.T) {
		before := testutil.QueueErrorCount(t, queue)
		cs := fake.NewSimpleClientset(
			proxyPod("proxy-ok", true),
			staleUnreadyProxyPod("proxy-wedged",
				now.Add(-time.Hour), now.Add(-10*time.Minute)),
			proxyDeploy(nil))
		cs.PrependReactor("*", "*", nodeErr)
		cs.PrependReactor("get", "pods", cfLogReactor(
			"2026-11-20T00:00:00Z ERR Couldn't start tunnel: config file error\n"))
		w := &cfTunnelProxyWatchdog{cs: cs, dyn: testutil.NewDynamicClient(),
			queue: queue, namespace: cfWatchdogTestNS,
			now: func() time.Time { return now }}
		if err := w.run(context.Background()); err != nil {
			t.Fatalf("run: %v", err)
		}
		if nodeLists == 0 {
			t.Fatal("gate never evaluated although a pod needed the delete")
		}
		if d := testutil.QueueErrorCount(t, queue) - before; d == 0 {
			t.Fatal("unverifiable mutex did not IncError the queue")
		}
		if !cfPodExists(t, cs, cfWatchdogTestNS, "proxy-wedged") {
			t.Fatal("pod deleted while the maintenance check was unverifiable — must defer fail-closed")
		}
	})
}

// The "increase receive buffer" line is the benign startup warning
// cloudflared logs on every Linux node — a stale-unready pod whose
// tail holds ONLY that warning must stay untouched (the false
// positive this guard exists for), and the ready sibling stays
// untouched with it.
func TestWatchdogBufferWarningPodUntouched(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		proxyPod("proxy-ok", true),
		staleUnreadyProxyPod("proxy-buffer-warn",
			now.Add(-time.Hour), now.Add(-10*time.Minute)),
		proxyDeploy(nil))
	cs.PrependReactor("get", "pods", cfLogReactor(
		"2026-11-20T00:00:00Z ERR Failed to sufficiently increase receive buffer size\n"+
			"INF Registered tunnel connection\n"))
	w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS, now: func() time.Time { return now }}
	if err := w.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !cfPodExists(t, cs, cfWatchdogTestNS, "proxy-buffer-warn") {
		t.Fatal("pod deleted on the benign receive-buffer startup warning")
	}
	if !cfPodExists(t, cs, cfWatchdogTestNS, "proxy-ok") {
		t.Fatal("ready pod deleted")
	}
}

// Three buffer warnings (or the warning mixed into a real edge-error
// loop) clear the >=3 weighted-line bar — the warning is weight-1
// noise, fatal only by accumulation.
func TestWatchdogBufferWarningLoopDeleted(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		proxyPod("proxy-ok", true),
		staleUnreadyProxyPod("proxy-wedged",
			now.Add(-time.Hour), now.Add(-10*time.Minute)),
		proxyDeploy(nil))
	cs.PrependReactor("get", "pods", cfLogReactor(
		"ERR Failed to sufficiently increase receive buffer size\n"+
			"ERR Failed to sufficiently increase receive buffer size\n"+
			"ERR Failed to sufficiently increase receive buffer size\n"))
	w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS, now: func() time.Time { return now }}
	if err := w.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if cfPodExists(t, cs, cfWatchdogTestNS, "proxy-wedged") {
		t.Fatal("sustained buffer-warning loop pod not deleted")
	}
}

// readyCount==0 deadlock: every running replica unready >=5m with
// clean logs — the resync loop can never converge, so the OLDEST
// pod is deleted once per cooldown instead of skipping forever.
func TestWatchdogAllUnreadyDeletesOldest(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		staleUnreadyProxyPod("proxy-new",
			now.Add(-30*time.Minute), now.Add(-6*time.Minute)),
		staleUnreadyProxyPod("proxy-old",
			now.Add(-time.Hour), now.Add(-20*time.Minute)),
		proxyDeploy(nil))
	cs.PrependReactor("get", "pods", cfLogReactor("INF tunnel running normally\n"))
	w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS, now: func() time.Time { return now }}
	if err := w.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if cfPodExists(t, cs, cfWatchdogTestNS, "proxy-old") {
		t.Fatal("oldest all-unready pod not deleted")
	}
	if !cfPodExists(t, cs, cfWatchdogTestNS, "proxy-new") {
		t.Fatal("younger pod deleted — only ONE pod per sweep")
	}
	// Within the 10m cooldown a recreated same-name pod must not be
	// deleted again.
	cs2 := fake.NewSimpleClientset(
		staleUnreadyProxyPod("proxy-old",
			now.Add(-5*time.Minute), now.Add(-time.Minute)),
		proxyDeploy(nil))
	cs2.PrependReactor("get", "pods", cfLogReactor("INF ok\n"))
	w2 := &cfTunnelProxyWatchdog{cs: cs2, namespace: cfWatchdogTestNS}
	w2.lastHeal.Stamp(cfWatchdogTestNS+"/proxy-old", now.Add(-5*time.Minute))
	w2.now = func() time.Time { return now }
	if err := w2.run(context.Background()); err != nil {
		t.Fatalf("run2: %v", err)
	}
	if !cfPodExists(t, cs2, cfWatchdogTestNS, "proxy-old") {
		t.Fatal("pod deleted inside the 10m cooldown")
	}
}

// Pods unready for less than 5m are startup churn — never deleted,
// logs never even read.
func TestWatchdogYoungUnreadyPodUntouched(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		staleUnreadyProxyPod("proxy-fresh",
			now.Add(-2*time.Minute), now.Add(-30*time.Second)),
		proxyDeploy(nil))
	var logReads int
	cs.PrependReactor("get", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			if a.GetSubresource() == "log" {
				logReads++
			}
			return false, nil, nil
		})
	w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS, now: func() time.Time { return now }}
	if err := w.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !cfPodExists(t, cs, cfWatchdogTestNS, "proxy-fresh") {
		t.Fatal("young unready pod deleted")
	}
	if logReads != 0 {
		t.Fatalf("logs read %d times for a pod inside the 5m grace window", logReads)
	}
}

// The ingress-controller namespace is scanned too: a wedged
// controlled-cloudflared-connector pod is deleted under its own
// label scheme.
func TestWatchdogHealsIngressControllerNamespace(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		connectorPod("ingress-wedged",
			now.Add(-time.Hour), now.Add(-15*time.Minute)),
		proxyDeploy(nil))
	cs.PrependReactor("get", "pods", cfLogReactor(
		"2026-11-20T00:00:00Z ERR Serve tunnel error error=\"connection refused\"\n"))
	w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS, now: func() time.Time { return now }}
	if err := w.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if cfPodExists(t, cs, cfTunnelConnectorNS, "ingress-wedged") {
		t.Fatal("wedged ingress-controller connector not deleted")
	}
}

// A delivered heal stamps the RFC3339 cooldown annotation on the
// pod's owning ReplicaSet AND the in-RAM ledger — the durable half
// that survives an operator restart.
func TestWatchdogHealStampsReplicaSetAnnotation(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		proxyPod("proxy-ok", true),
		rsOwnedPod("proxy-wedged", "proxy-rs",
			now.Add(-time.Hour), now.Add(-10*time.Minute)),
		healRs("proxy-rs", nil),
		proxyDeploy(nil))
	cs.PrependReactor("get", "pods", cfLogReactor(
		"ERR Couldn't start tunnel: config file error\n"))
	w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS, now: func() time.Time { return now }}
	if err := w.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if cfPodExists(t, cs, cfWatchdogTestNS, "proxy-wedged") {
		t.Fatal("wedged pod not deleted")
	}
	got, err := cs.AppsV1().ReplicaSets(cfWatchdogTestNS).
		Get(context.Background(), "proxy-rs", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get replicaset: %v", err)
	}
	stamp, err := time.Parse(time.RFC3339, got.Annotations[cfTunnelHealAnno])
	if err != nil {
		t.Fatalf("heal annotation %q is not RFC3339: %v",
			got.Annotations[cfTunnelHealAnno], err)
	}
	if d := stamp.Sub(now); d < -2*time.Second || d > 2*time.Second {
		t.Fatalf("heal stamp = %v, want ~%v", stamp, now)
	}
	if _, ok := w.lastHeal.Last(cfWatchdogTestNS + "/proxy-rs"); !ok {
		t.Fatal("in-RAM ledger not stamped on the delivered heal")
	}
}

// The persisted annotation cools the heal across an operator restart:
// a FRESH watchdog (empty lastHeal) must still skip a controller
// whose ReplicaSet carries a stamp inside the cooldown window.
func TestWatchdogHealCooledDownByPersistedStamp(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		proxyPod("proxy-ok", true),
		rsOwnedPod("proxy-wedged", "proxy-rs",
			now.Add(-time.Hour), now.Add(-10*time.Minute)),
		healRs("proxy-rs", map[string]string{
			cfTunnelHealAnno: now.Add(-2 * time.Minute).UTC().Format(time.RFC3339),
		}),
		proxyDeploy(nil))
	cs.PrependReactor("get", "pods", cfLogReactor(
		"ERR Couldn't start tunnel: config file error\n"))
	// Empty lastHeal — the operator just restarted and forgot.
	w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS, now: func() time.Time { return now }}
	if err := w.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !cfPodExists(t, cs, cfWatchdogTestNS, "proxy-wedged") {
		t.Fatal("pod deleted inside the persisted-annotation cooldown")
	}
	if _, ok := w.lastHeal.Last(cfWatchdogTestNS + "/proxy-rs"); ok {
		t.Fatal("ledger stamped while the heal was skipped")
	}
}

// A failed ReplicaSet annotation patch must not undo the delivered
// delete — the in-RAM ledger stamp holds (the same
// annotation-fails-but-heal-stands shape dragonfly_heals uses).
func TestWatchdogHealSurvivesStampPatchFailure(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		proxyPod("proxy-ok", true),
		rsOwnedPod("proxy-wedged", "proxy-rs",
			now.Add(-time.Hour), now.Add(-10*time.Minute)),
		healRs("proxy-rs", nil),
		proxyDeploy(nil))
	cs.PrependReactor("get", "pods", cfLogReactor(
		"ERR Couldn't start tunnel: config file error\n"))
	cs.PrependReactor("patch", "replicasets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS, now: func() time.Time { return now }}
	if err := w.run(context.Background()); err != nil {
		t.Fatalf("run must not fail over the stamp patch: %v", err)
	}
	if cfPodExists(t, cs, cfWatchdogTestNS, "proxy-wedged") {
		t.Fatal("wedged pod not deleted although only the stamp patch failed")
	}
	if _, ok := w.lastHeal.Last(cfWatchdogTestNS + "/proxy-rs"); !ok {
		t.Fatal("in-RAM ledger not stamped on the delivered delete")
	}
}

// cloudflaredLogsWedged signature table — the fatal strings match
// case-insensitively; the edge-error loop needs >=3 error lines.
func TestCloudflaredLogsWedged(t *testing.T) {
	for _, tc := range []struct {
		name string
		logs string
		want bool
	}{
		{"clean", "INF Registered tunnel connection\nINF metrics server started\n", false},
		{"couldnt start", "ERR Couldn't start tunnel\n", true},
		{"recv buffer", "ERR Failed to sufficiently increase receive buffer size\n", false},
		{"recv buffer loop",
			"ERR Failed to sufficiently increase receive buffer size\n" +
				"ERR Failed to sufficiently increase receive buffer size\n" +
				"ERR Failed to sufficiently increase receive buffer size\n", true},
		{"recv buffer mixed into an edge loop",
			"ERR Failed to sufficiently increase receive buffer size\n" +
				"ERR connection with edge closed\n" +
				"ERR connection with edge reset\n", true},
		{"serve tunnel", "ERR Serve tunnel error error=\"dial tcp: timeout\"\n", true},
		{"edge loop", "ERR connection with edge closed\n" +
			"ERR connection with edge closed\n" +
			"ERR connection with edge reset\n", true},
		{"edge single blip", "ERR connection with edge closed\nINF retrying\n", false},
		{"edge info lines only",
			"INF connection with edge established\n" +
				"INF connection with edge registered\n" +
				"INF connection with edge ready\n", false},
		{"quic dial loop",
			"ERR failed to dial to edge with quic\n" +
				"ERR failed to dial to edge with quic\n" +
				"ERR failed to dial to edge with quic\n", true},
		{"quic dial single blip",
			"ERR failed to dial to edge with quic\nINF retrying\n", false},
		{"quic no recent network activity loop",
			"ERR timeout: no recent network activity\n" +
				"ERR timeout: no recent network activity\n" +
				"ERR timeout: no recent network activity\n", true},
		{"quic prefix loop",
			"ERR quic: connection closed before handshake\n" +
				"ERR quic: connection closed before handshake\n" +
				"ERR quic: connection closed before handshake\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cloudflaredLogsWedged(tc.logs); got != tc.want {
				t.Fatalf("cloudflaredLogsWedged = %v, want %v", got, tc.want)
			}
		})
	}
}

// Disabled must be a clean no-op — nothing registered, no error.
// Deps.Disabled is what setupModules stamps for
// CF_TUNNEL_WATCHDOG_ENABLED=false.
func TestSetupCFTunnelProxyWatchdogDisabled(t *testing.T) {
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Name: "cf-tunnel-proxy-watchdog", Mgr: m, CS: fake.NewSimpleClientset(),
		Dyn: testutil.StubDyn(), Disabled: true}); err != nil {
		t.Fatalf("disabled setup must return nil, got %v", err)
	}
	if len(m.Added) != 0 {
		t.Fatalf("disabled module registered %d runnables, want 0", len(m.Added))
	}
}

// Enabled registration goes through shared.AddPeriodic with the legacy queue
// name and the configured interval.
func TestSetupCFTunnelProxyWatchdogPeriodic(t *testing.T) {
	// Zero-value Deps.Disabled = gate-on — CF_TUNNEL_WATCHDOG_ENABLED
	// is resolved by setupModules, not re-read here.
	t.Setenv("CF_TUNNEL_WATCHDOG_NAMESPACE", cfWatchdogTestNS)
	t.Setenv("CF_TUNNEL_WATCHDOG_INTERVAL", "5m")
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Name: "cf-tunnel-proxy-watchdog", Mgr: m, CS: fake.NewSimpleClientset(),
		Dyn: testutil.StubDyn()}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	testutil.ExpectPeriodic(t, m, "cf-tunnel-proxy-watchdog", 5*time.Minute)
}

// ---------------------------------------------------------------------------
// cf-gateway-sync-error — gateway controller sync-error audit
// ---------------------------------------------------------------------------

// gatewayCtrlPod builds a cloudflare-tunnel-gateway-controller pod
// carrying the audit's label selector.
func gatewayCtrlPod(name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: cfWatchdogTestNS,
			Labels: map[string]string{
				"app.kubernetes.io/name": "cloudflare-tunnel-gateway-controller",
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func syncErrGaugeVal(t *testing.T) float64 {
	t.Helper()
	return ptestutil.ToFloat64(cftunnelGatewaySyncErrorGauge.
		WithLabelValues(cfWatchdogTestNS))
}

// The classifier matches the three observed Cloudflare API sync
// failure signatures and stays clean on unrelated controller noise.
func TestControllerSyncErrorsClassifier(t *testing.T) {
	for _, tc := range []struct {
		logs string
		want bool
	}{
		{"", false},
		{"level=info msg=\"updating tunnel configuration\" ok\n", false},
		{"level=error msg=\"failed to update tunnel configuration: 400\"\n", true},
		{"request failed with 429 Too Many Requests\n", true},
		{"ERROR authentication error: invalid token\n", true},
		{"some unrelated reconciliation error\n", false},
	} {
		if got := controllerSyncErrors(tc.logs); got != tc.want {
			t.Errorf("controllerSyncErrors(%q) = %v, want %v", tc.logs, got, tc.want)
		}
	}
}

// The gauge lifecycle: error tail sets 1; a clean tail inside the
// clear window keeps 1; a clean tail past the window resets 0; a
// failed log read inside the window keeps 1.
func TestWatchdogSyncErrorGaugeSetsAndClears(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(gatewayCtrlPod("cf-gw-ctrl-0"))
	w := &cfTunnelProxyWatchdog{cs: cs, queue: "cf-tunnel-proxy-watchdog",
		namespace: cfWatchdogTestNS,
		now:       shared.Clock(func() time.Time { return now })}
	cs.PrependReactor("get", "pods", cfLogReactor(
		"2026-11-20T00:00:00Z ERR failed to update tunnel configuration\n"))

	if err := w.run(context.Background()); err != nil {
		t.Fatalf("run (error tail): %v", err)
	}
	if got := syncErrGaugeVal(t); got != 1 {
		t.Fatalf("gauge = %v after error tail, want 1", got)
	}

	// Clean tail but only 2 minutes later — inside the clear window.
	cs.PrependReactor("get", "pods", cfLogReactor("all quiet\n"))
	w.syncErrLast[cfWatchdogTestNS] = now.Add(-2 * time.Minute)
	if err := w.run(context.Background()); err != nil {
		t.Fatalf("run (clean tail, inside window): %v", err)
	}
	if got := syncErrGaugeVal(t); got != 1 {
		t.Fatalf("gauge = %v inside the clear window, want 1", got)
	}

	// Log read now fails (pod restarting) — still must not clear.
	cs.PrependReactor("get", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			if a.GetSubresource() != "log" {
				return false, nil, nil
			}
			return true, nil, errors.New("log stream dead")
		})
	w.syncErrLast[cfWatchdogTestNS] = now.Add(-6 * time.Minute)
	if err := w.run(context.Background()); err != nil {
		t.Fatalf("run (log read failure): %v", err)
	}
	if got := syncErrGaugeVal(t); got != 1 {
		t.Fatalf("gauge = %v after failed log read, want 1", got)
	}

	// Clean tail past the window — the reset lands.
	cs.PrependReactor("get", "pods", cfLogReactor("all quiet\n"))
	if err := w.run(context.Background()); err != nil {
		t.Fatalf("run (clean tail, past window): %v", err)
	}
	if got := syncErrGaugeVal(t); got != 0 {
		t.Fatalf("gauge = %v after clean tail past the window, want 0", got)
	}
}

// A healthy controller tail from the start never raises the gauge.
func TestWatchdogSyncErrorGaugeHealthyNoRaise(t *testing.T) {
	cs := fake.NewSimpleClientset(gatewayCtrlPod("cf-gw-ctrl-0"))
	cs.PrependReactor("get", "pods", cfLogReactor(
		"level=info msg=\"reconciled routes\" ok\n"))
	w := &cfTunnelProxyWatchdog{cs: cs, queue: "cf-tunnel-proxy-watchdog",
		namespace: cfWatchdogTestNS}
	if err := w.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := syncErrGaugeVal(t); got != 0 {
		t.Fatalf("gauge = %v with a healthy tail, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// deleteConnectorPod — UID-preconditioned delete outcomes
// ---------------------------------------------------------------------------

// wedgeDeletedCount reads the delivered-deletes counter for the test
// namespace and reason.
func wedgeDeletedCount(t *testing.T, reason string) float64 {
	t.Helper()
	return ptestutil.ToFloat64(metrics.CFTunnelWedgePodsDeletedTotal.
		WithLabelValues(cfWatchdogTestNS, reason))
}

// deleteConnectorPod verifies before it deletes — the listed pod
// could already have been replaced by a same-named fresh pod, and
// killing the replacement would undo the heal. The fake API server
// ignores delete preconditions, so the conflict branch is simulated
// by a reactor that replays exactly what the real API answers when
// the precondition UID no longer matches: a Conflict error.
func TestWatchdogDeleteConnectorPodOutcomes(t *testing.T) {
	now := time.Now()
	pod := staleUnreadyProxyPod("proxy-wedged",
		now.Add(-time.Hour), now.Add(-10*time.Minute))

	t.Run("uid conflict — error, no counter", func(t *testing.T) {
		testutil.CleanupMetric(t, metrics.CFTunnelWedgePodsDeletedTotal,
			cfWatchdogTestNS, "fatal_logs")
		repl := pod.DeepCopy()
		repl.UID = pod.UID + "-fresh"
		cs := fake.NewSimpleClientset(repl)
		cs.PrependReactor("delete", "pods",
			func(a ktesting.Action) (bool, runtime.Object, error) {
				da := a.(ktesting.DeleteAction)
				uid := da.GetDeleteOptions().Preconditions.UID
				if uid != nil && string(*uid) != string(repl.UID) {
					return true, nil, apierrors.NewConflict(
						corev1.Resource("pods"), repl.Name,
						errors.New("the object has been modified"))
				}
				return false, nil, nil
			})
		w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS,
			now: shared.Clock(func() time.Time { return now })}
		if err := w.deleteConnectorPod(context.Background(), pod, "fatal_logs"); err == nil {
			t.Fatal("precondition miss must propagate the Conflict error")
		}
		if got := wedgeDeletedCount(t, "fatal_logs"); got != 0 {
			t.Fatalf("failed delete counted %v heals", got)
		}
	})

	t.Run("notfound — nil, no counter", func(t *testing.T) {
		testutil.CleanupMetric(t, metrics.CFTunnelWedgePodsDeletedTotal,
			cfWatchdogTestNS, "fatal_logs")
		cs := fake.NewSimpleClientset()
		w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS,
			now: shared.Clock(func() time.Time { return now })}
		if err := w.deleteConnectorPod(context.Background(), pod, "fatal_logs"); err != nil {
			t.Fatalf("already-gone pod must be nil: %v", err)
		}
		if got := wedgeDeletedCount(t, "fatal_logs"); got != 0 {
			t.Fatalf("a delete we did not deliver counted %v heals", got)
		}
	})

	t.Run("api error — error propagates, no counter", func(t *testing.T) {
		testutil.CleanupMetric(t, metrics.CFTunnelWedgePodsDeletedTotal,
			cfWatchdogTestNS, "fatal_logs")
		cs := fake.NewSimpleClientset(pod)
		cs.PrependReactor("delete", "pods",
			func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("etcd unavailable")
			})
		w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS,
			now: shared.Clock(func() time.Time { return now })}
		if err := w.deleteConnectorPod(context.Background(), pod, "fatal_logs"); err == nil {
			t.Fatal("api failure must propagate")
		}
		if got := wedgeDeletedCount(t, "fatal_logs"); got != 0 {
			t.Fatalf("failed API delete counted %v heals", got)
		}
	})

	t.Run("delivered delete counts", func(t *testing.T) {
		testutil.CleanupMetric(t, metrics.CFTunnelWedgePodsDeletedTotal,
			cfWatchdogTestNS, "fatal_logs")
		cs := fake.NewSimpleClientset(pod)
		w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS,
			now: shared.Clock(func() time.Time { return now })}
		if err := w.deleteConnectorPod(context.Background(), pod, "fatal_logs"); err != nil {
			t.Fatalf("clean delete failed: %v", err)
		}
		if got := wedgeDeletedCount(t, "fatal_logs"); got != 1 {
			t.Fatalf("delivered delete counter = %v, want 1", got)
		}
	})
}

// The per-target cfTunnelMaxHealsPerTarget bound: a mass wedge
// deletes at most cap pods per sweep, and once the fatal-log path
// fills the cap the all-unready slot stays suppressed — one sweep can
// never exceed cfTunnelMaxHealsPerTarget deletes.
func TestWatchdogHealCapPerTarget(t *testing.T) {
	now := time.Now()
	testutil.CleanupMetric(t, metrics.CFTunnelWedgePodsDeletedTotal,
		cfWatchdogTestNS, "fatal_logs")
	testutil.CleanupMetric(t, metrics.CFTunnelWedgePodsDeletedTotal,
		cfWatchdogTestNS, "all_unready_oldest")
	cs := fake.NewSimpleClientset(
		staleUnreadyProxyPod("proxy-w1", now.Add(-time.Hour), now.Add(-10*time.Minute)),
		staleUnreadyProxyPod("proxy-w2", now.Add(-time.Hour), now.Add(-9*time.Minute)),
		staleUnreadyProxyPod("proxy-w3", now.Add(-time.Hour), now.Add(-8*time.Minute)),
		proxyDeploy(nil))
	cs.PrependReactor("get", "pods", cfLogReactor(
		"2026-11-20T00:00:00Z ERR Couldn't start tunnel: config file error\n"))
	w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS,
		now: shared.Clock(func() time.Time { return now })}
	deleted, err := w.healCloudflaredWedges(context.Background())
	if err != nil {
		t.Fatalf("heal sweep: %v", err)
	}
	if deleted != cfTunnelMaxHealsPerTarget {
		t.Fatalf("deleted %d pods, want the cap %d", deleted, cfTunnelMaxHealsPerTarget)
	}
	if cfPodExists(t, cs, cfWatchdogTestNS, "proxy-w3") == cfPodExists(t, cs, cfWatchdogTestNS, "proxy-w1") {
		t.Fatal("expected exactly the cap-front pods deleted and the rest kept")
	}
	if got := wedgeDeletedCount(t, "fatal_logs"); got != float64(cfTunnelMaxHealsPerTarget) {
		t.Fatalf("fatal_logs counter = %v, want %d", got, cfTunnelMaxHealsPerTarget)
	}
	if got := wedgeDeletedCount(t, "all_unready_oldest"); got != 0 {
		t.Fatalf("cap-full sweep issued %v all-unready deletes — slot must be suppressed", got)
	}
}

// ---------------------------------------------------------------------------
// cf-gateway-sync-error — inconclusive-tail branches
// ---------------------------------------------------------------------------

// An EMPTY log tail (fresh controller pod, quiet window) is
// inconclusive: with the errored stamp already past the clear window
// the gauge must stay 1 and the stamp must hold — no clean evidence,
// no clear.
func TestWatchdogSyncErrorEmptyTailNeverClears(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(gatewayCtrlPod("cf-gw-ctrl-0"))
	cs.PrependReactor("get", "pods", cfLogReactor(""))
	testutil.CleanupMetric(t, cftunnelGatewaySyncErrorGauge, cfWatchdogTestNS)
	cftunnelGatewaySyncErrorGauge.WithLabelValues(cfWatchdogTestNS).Set(1)
	w := &cfTunnelProxyWatchdog{cs: cs, queue: "cf-tunnel-proxy-watchdog",
		namespace: cfWatchdogTestNS,
		now:       shared.Clock(func() time.Time { return now })}
	w.syncErrLast = map[string]time.Time{cfWatchdogTestNS: now.Add(-6 * time.Minute)}
	w.auditControllerSyncErrors(context.Background())
	if got := syncErrGaugeVal(t); got != 1 {
		t.Fatalf("gauge = %v after an empty tail, want 1", got)
	}
	if _, ok := w.syncErrLast[cfWatchdogTestNS]; !ok {
		t.Fatal("inconclusive sweep cleared the errored stamp")
	}
}

// With 2 replicas, one unreadable tail + one clean tail is still
// inconclusive (the crash-loop shape is exactly when one tail is
// unreadable) — the gauge must stay 1.
func TestWatchdogSyncErrorPartialReplicaReadKeepsGauge(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(
		gatewayCtrlPod("cf-gw-ctrl-0"), gatewayCtrlPod("cf-gw-ctrl-1"))
	calls := 0
	cs.PrependReactor("get", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			if a.GetSubresource() != "log" {
				return false, nil, nil
			}
			calls++
			if calls == 1 {
				return true, nil, errors.New("log stream dead")
			}
			return true, &runtime.Unknown{Raw: []byte("all quiet\n")}, nil
		})
	testutil.CleanupMetric(t, cftunnelGatewaySyncErrorGauge, cfWatchdogTestNS)
	cftunnelGatewaySyncErrorGauge.WithLabelValues(cfWatchdogTestNS).Set(1)
	w := &cfTunnelProxyWatchdog{cs: cs, queue: "cf-tunnel-proxy-watchdog",
		namespace: cfWatchdogTestNS,
		now:       shared.Clock(func() time.Time { return now })}
	w.syncErrLast = map[string]time.Time{cfWatchdogTestNS: now.Add(-6 * time.Minute)}
	w.auditControllerSyncErrors(context.Background())
	if calls != 2 {
		t.Fatalf("read %d log tails, want both replicas", calls)
	}
	if got := syncErrGaugeVal(t); got != 1 {
		t.Fatalf("gauge = %v after a partial read, want 1", got)
	}
	if _, ok := w.syncErrLast[cfWatchdogTestNS]; !ok {
		t.Fatal("partial-read sweep cleared the errored stamp")
	}
}
