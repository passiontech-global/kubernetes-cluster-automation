package cftunnelproxywatchdog

import (
	"errors"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
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
		Get(ctx, name, metav1.GetOptions{})
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
	if err := w.run(ctx); err != nil {
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
	if err := w.run(ctx); err != nil {
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
	if err := w.run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
	if patched {
		t.Fatal("resynced for a Pending pod — only Running+notReady counts")
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
	if err := w.run(ctx); err != nil {
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
	if err := w.run(ctx); err != nil {
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
	if err := w.run(ctx); err != nil {
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
	if err := w.run(ctx); err == nil {
		t.Fatal("expected error when the pod list fails")
	}
}

// ---------------------------------------------------------------------------
// W10-NM2 — wedged cloudflared connector healer.
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
	_, err := cs.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
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
		"2026-11-20T00:00:00Z ERR Failed to sufficiently increase receive buffer size\n"))
	w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS, nowFn: func() time.Time { return now }}
	if err := w.run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
	if cfPodExists(t, cs, cfWatchdogTestNS, "proxy-wedged") {
		t.Fatal("fatal-log pod not deleted")
	}
	if !cfPodExists(t, cs, cfWatchdogTestNS, "proxy-ok") {
		t.Fatal("ready pod deleted")
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
	w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS, nowFn: func() time.Time { return now }}
	if err := w.run(ctx); err != nil {
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
	w2.lastHeal = map[string]time.Time{
		cfWatchdogTestNS + "/proxy-old": now.Add(-5 * time.Minute),
	}
	w2.nowFn = func() time.Time { return now }
	if err := w2.run(ctx); err != nil {
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
	w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS, nowFn: func() time.Time { return now }}
	if err := w.run(ctx); err != nil {
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
	w := &cfTunnelProxyWatchdog{cs: cs, namespace: cfWatchdogTestNS, nowFn: func() time.Time { return now }}
	if err := w.run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
	if cfPodExists(t, cs, cfTunnelConnectorNS, "ingress-wedged") {
		t.Fatal("wedged ingress-controller connector not deleted")
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
		{"recv buffer", "ERR Failed to sufficiently increase receive buffer size\n", true},
		{"serve tunnel", "ERR Serve tunnel error error=\"dial tcp: timeout\"\n", true},
		{"edge loop", "ERR connection with edge closed\n" +
			"ERR connection with edge closed\n" +
			"ERR connection with edge reset\n", true},
		{"edge single blip", "ERR connection with edge closed\nINF retrying\n", false},
		{"edge info lines only",
			"INF connection with edge established\n" +
				"INF connection with edge registered\n" +
				"INF connection with edge ready\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cloudflaredLogsWedged(tc.logs); got != tc.want {
				t.Fatalf("cloudflaredLogsWedged = %v, want %v", got, tc.want)
			}
		})
	}
}

// Disabled must be a clean no-op — nothing registered, no error.
func TestSetupCFTunnelProxyWatchdogDisabled(t *testing.T) {
	m := testutil.NewStubManager()
	if err := Setup(m, fake.NewSimpleClientset(),
		false, cfWatchdogTestNS, 5*time.Minute); err != nil {
		t.Fatalf("disabled setup must return nil, got %v", err)
	}
	if len(m.Added) != 0 {
		t.Fatalf("disabled module registered %d runnables, want 0", len(m.Added))
	}
}

// Enabled registration goes through shared.AddPeriodic with the legacy queue
// name and the configured interval.
func TestSetupCFTunnelProxyWatchdogPeriodic(t *testing.T) {
	m := testutil.NewStubManager()
	if err := Setup(m, fake.NewSimpleClientset(),
		true, cfWatchdogTestNS, 5*time.Minute); err != nil {
		t.Fatalf("setup: %v", err)
	}
	testutil.ExpectPeriodic(t, m, cfTunnelWatchdogQueue, 5*time.Minute)
}
