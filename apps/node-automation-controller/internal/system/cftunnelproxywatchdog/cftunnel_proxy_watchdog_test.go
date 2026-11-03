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
// `kubectl patch --subresource=status --type=json`.
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
	want := `[{"op":"remove","path":"/status/conditions/1"}]`
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
