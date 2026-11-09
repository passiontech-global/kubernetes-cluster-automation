package corednswatchdog

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

// cdnsPod builds a kube-dns labelled coredns pod with a podIP (layer 2
// and 3 are skipped for pods without one).
func cdnsPod(name, ip string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: corednsNS,
			Labels:    map[string]string{"k8s-app": "kube-dns"},
		},
		Status: corev1.PodStatus{PodIP: ip},
	}
}

// cdnsDeployment builds deploy/coredns with the given status — recover()
// gates on ReadyReplicas < Replicas.
func cdnsDeployment(replicas, ready int32, annos map[string]string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "coredns",
			Namespace:   corednsNS,
			Annotations: annos,
		},
		Spec:   appsv1.DeploymentSpec{Replicas: &replicas},
		Status: appsv1.DeploymentStatus{Replicas: replicas, ReadyReplicas: ready},
	}
}

// cdnsProbeService builds the <10m-old Service + EndpointSlice pair that
// layer 2 uses as its freshness oracle. ready may be nil (bash: nil does
// NOT count as ready).
func cdnsProbeService(name, ns string, age time.Duration, ready *bool) (*corev1.Service, *discoveryv1.EndpointSlice) {
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{
		Name:              name,
		Namespace:         ns,
		CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
	}}
	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name + "-eps",
			Namespace: ns,
			Labels:    map[string]string{"kubernetes.io/service-name": name},
		},
		Endpoints: []discoveryv1.Endpoint{{
			Conditions: discoveryv1.EndpointConditions{Ready: ready},
		}},
	}
	return svc, es
}

// newCDNSWatchdog returns a watchdog with every external probe stubbed
// to the "all clean" result — each test overrides the layer it exercises.
func newCDNSWatchdog(cs *fake.Clientset) *coreDNSWatchdog {
	return &coreDNSWatchdog{
		cs: cs,
		// NewDynamicClient (not StubDyn): recover()'s maintenance
		// mutex autopilot-Plan signal must be verifiable or every
		// recovery defers fail-closed.
		dyn:      testutil.NewDynamicClient(),
		logHitFn: func(context.Context, string) string { return "" },
		dnsFn:    func(context.Context, string, string) ([]string, error) { return []string{"10.1.2.3"}, nil },
		panicsFn: func(context.Context, string) (float64, bool) { return 0, true },
	}
}

func getCDNSDeployment(t *testing.T, cs *fake.Clientset) *appsv1.Deployment {
	t.Helper()
	d, err := cs.AppsV1().Deployments(corednsNS).Get(ctx, "coredns", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get deploy/coredns: %v", err)
	}
	return d
}

func cdnsPodExists(t *testing.T, cs *fake.Clientset, name string) bool {
	t.Helper()
	_, err := cs.CoreV1().Pods(corednsNS).Get(ctx, name, metav1.GetOptions{})
	return err == nil
}

// ---------------------------------------------------------------------------
// Layer 1 — log fast-path
// ---------------------------------------------------------------------------

func TestCoreDNSWatchdogLayer1LogHit(t *testing.T) {
	cs := fake.NewSimpleClientset(
		cdnsPod("cdns-a", "10.0.0.1"),
		cdnsPod("cdns-b", "10.0.0.2"),
		cdnsDeployment(2, 2, nil))
	w := newCDNSWatchdog(cs)
	w.logHitFn = func(_ context.Context, pod string) string {
		if pod == "cdns-a" {
			return `Failed to watch *v1.Endpoints: failed to list *v1.Endpoints: Unauthorized`
		}
		return ""
	}
	// First hit: suspect only — streak 1, no recovery action.
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := w.logStreak.Count("cdns-a"); got != 1 {
		t.Fatalf("first run streak=%d, want 1", got)
	}
	if got := w.logStreak.Count("cdns-b"); got != 0 {
		t.Fatal("clean pod got a streak")
	}
	if !cdnsPodExists(t, cs, "cdns-a") {
		t.Fatal("pod deleted on the FIRST log hit — one blip must not restart")
	}
	if a := getCDNSDeployment(t, cs).Annotations[corednsTSAnno]; a != "" {
		t.Fatal("cooldown annotation set before any recovery")
	}
	// Second consecutive hit: stale -> subset recovery deletes it.
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := w.logStreak.Count("cdns-a"); got != corednsStreakMax {
		t.Fatalf("second run streak=%d, want %d", got, corednsStreakMax)
	}
	// 1 of 2 stale -> subset recovery deletes only that pod.
	if cdnsPodExists(t, cs, "cdns-a") {
		t.Fatal("stale pod not deleted")
	}
	if !cdnsPodExists(t, cs, "cdns-b") {
		t.Fatal("healthy pod deleted — recovery must be surgical")
	}
	if a := getCDNSDeployment(t, cs).Annotations[corednsTSAnno]; a == "" {
		t.Fatal("cooldown annotation not stamped")
	}
}

// A layer-1 blip (hit on one run, gone the next) resets the log
// streak — only hits on two CONSECUTIVE runs make a pod stale.
func TestCoreDNSWatchdogLayer1BlipResets(t *testing.T) {
	cs := fake.NewSimpleClientset(
		cdnsPod("cdns-a", "10.0.0.1"),
		cdnsPod("cdns-b", "10.0.0.2"),
		cdnsDeployment(2, 2, nil))
	w := newCDNSWatchdog(cs)
	hit := false
	w.logHitFn = func(_ context.Context, pod string) string {
		if pod == "cdns-a" && hit {
			return "Failed to watch *v1.Endpoints: Unauthorized"
		}
		return ""
	}
	// Run 1: hit -> streak 1, no action.
	hit = true
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := w.logStreak.Count("cdns-a"); got != 1 {
		t.Fatalf("after first hit streak=%d, want 1", got)
	}
	if !cdnsPodExists(t, cs, "cdns-a") {
		t.Fatal("pod deleted on a single log hit")
	}
	// Run 2: no signature in the window -> the streak resets.
	hit = false
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := w.logStreak.Count("cdns-a"); got != 0 {
		t.Fatalf("clean run left streak=%d, want 0 (reset)", got)
	}
	// Run 3: a fresh single hit rides a RESET streak -> still only 1.
	hit = true
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := w.logStreak.Count("cdns-a"); got != 1 {
		t.Fatalf("fresh hit after reset streak=%d, want 1", got)
	}
	if !cdnsPodExists(t, cs, "cdns-a") {
		t.Fatal("pod deleted on non-consecutive hits")
	}
	// Run 4: second consecutive hit -> stale -> deleted.
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if cdnsPodExists(t, cs, "cdns-a") {
		t.Fatal("pod not deleted after two consecutive log hits")
	}
	if !cdnsPodExists(t, cs, "cdns-b") {
		t.Fatal("healthy pod deleted")
	}
}

// ---------------------------------------------------------------------------
// Layer 2 — active freshness query
// ---------------------------------------------------------------------------

func TestCoreDNSProbeFQDN(t *testing.T) {
	readyTrue, readyFalse := true, false
	for _, tc := range []struct {
		name  string
		age   time.Duration
		ready *bool
		noES  bool
		want  string
	}{
		{"ready endpoint", 0, &readyTrue, false, "fresh-svc.app-ns.svc.cluster.local"},
		{"service older than 10m", 11 * time.Minute, &readyTrue, false, ""},
		{"endpoint not ready", 0, &readyFalse, false, ""},
		{"endpoint ready nil", 0, nil, false, ""},
		{"no endpointslice", 0, &readyTrue, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, es := cdnsProbeService("fresh-svc", "app-ns", tc.age, tc.ready)
			cs := fake.NewSimpleClientset(svc)
			if !tc.noES {
				cs = fake.NewSimpleClientset(svc, es)
			}
			w := newCDNSWatchdog(cs)
			if got, _ := w.probeFQDN(ctx); got != tc.want {
				t.Fatalf("probeFQDN=%q, want %q", got, tc.want)
			}
		})
	}

	t.Run("old service skipped for a fresh one", func(t *testing.T) {
		oldSvc, oldES := cdnsProbeService("old-svc", "app-ns", 20*time.Minute, &readyTrue)
		newSvc, newES := cdnsProbeService("fresh-svc", "app-ns", 0, &readyTrue)
		w := newCDNSWatchdog(fake.NewSimpleClientset(oldSvc, oldES, newSvc, newES))
		if got, _ := w.probeFQDN(ctx); got != "fresh-svc.app-ns.svc.cluster.local" {
			t.Fatalf("probeFQDN=%q", got)
		}
	})

	t.Run("empty cluster is inconclusive", func(t *testing.T) {
		w := newCDNSWatchdog(fake.NewSimpleClientset())
		if got, _ := w.probeFQDN(ctx); got != "" {
			t.Fatalf("probeFQDN=%q, want empty", got)
		}
	})

	// The <10m age filter reads the watchdog's clock seam, not
	// time.Since — a pinned clock decides the window.
	t.Run("age filter follows the clock seam", func(t *testing.T) {
		pinned := time.Unix(1700000000, 0)
		mk := func(name string, created time.Time) (*corev1.Service, *discoveryv1.EndpointSlice) {
			svc, es := cdnsProbeService(name, "app-ns", 0, &readyTrue)
			svc.CreationTimestamp = metav1.NewTime(created)
			return svc, es
		}
		freshSvc, freshES := mk("seam-fresh", pinned.Add(-5*time.Minute))
		w := newCDNSWatchdog(fake.NewSimpleClientset(freshSvc, freshES))
		w.now = func() time.Time { return pinned }
		if got, _ := w.probeFQDN(ctx); got != "seam-fresh.app-ns.svc.cluster.local" {
			t.Fatalf("5m-old service skipped under the pinned clock: %q", got)
		}
		oldSvc, oldES := mk("seam-old", pinned.Add(-11*time.Minute))
		w = newCDNSWatchdog(fake.NewSimpleClientset(oldSvc, oldES))
		w.now = func() time.Time { return pinned }
		if got, _ := w.probeFQDN(ctx); got != "" {
			t.Fatalf("11m-old service accepted under the pinned clock: %q", got)
		}
	})
}

func TestCoreDNSWatchdogLayer2StreakThenRecover(t *testing.T) {
	ready := true
	svc, es := cdnsProbeService("fresh-svc", "app-ns", 0, &ready)
	cs := fake.NewSimpleClientset(
		cdnsPod("cdns-a", "10.0.0.1"),
		cdnsPod("cdns-b", "10.0.0.2"),
		cdnsDeployment(2, 2, nil),
		svc, es)
	w := newCDNSWatchdog(cs)
	w.dnsFn = func(_ context.Context, podIP, _ string) ([]string, error) {
		if podIP == "10.0.0.1" {
			return nil, nil // only cdns-a fails to resolve
		}
		return []string{"10.1.2.3"}, nil
	}

	// First failure: suspect only — streak 1, no recovery action.
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	// The layer-2 cache now holds the picked target — the fqdn every
	// probe saw (the dnsFn stub must stay race-free, so the capture
	// moved here).
	if got := w.cachedFQDN; got != "fresh-svc.app-ns.svc.cluster.local" {
		t.Fatalf("probe fqdn=%q", got)
	}
	if got := w.streak.Count("cdns-a"); got != 1 {
		t.Fatalf("first run streak=%d, want 1", got)
	}
	if !cdnsPodExists(t, cs, "cdns-a") {
		t.Fatal("pod deleted on streak 1 — recovery fired too early")
	}
	if a := getCDNSDeployment(t, cs).Annotations[corednsTSAnno]; a != "" {
		t.Fatal("cooldown annotation set before any recovery")
	}

	// Second consecutive failure: stale -> subset recovery deletes it.
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := w.streak.Count("cdns-a"); got != corednsStreakMax {
		t.Fatalf("second run streak=%d, want %d", got, corednsStreakMax)
	}
	if cdnsPodExists(t, cs, "cdns-a") {
		t.Fatal("stale pod not deleted after streak max")
	}
	if !cdnsPodExists(t, cs, "cdns-b") {
		t.Fatal("healthy pod deleted")
	}
	if a := getCDNSDeployment(t, cs).Annotations[corednsTSAnno]; a == "" {
		t.Fatal("cooldown annotation not stamped after recovery")
	}
}

func TestCoreDNSWatchdogLayer2AbortAllFail(t *testing.T) {
	ready := true
	svc, es := cdnsProbeService("fresh-svc", "app-ns", 0, &ready)
	cs := fake.NewSimpleClientset(
		cdnsPod("cdns-a", "10.0.0.1"),
		cdnsPod("cdns-b", "10.0.0.2"),
		cdnsDeployment(2, 2, nil),
		svc, es)
	w := newCDNSWatchdog(cs)
	w.streak.Set("cdns-a", 1)
	// Every pod fails to resolve -> the probe path is broken, NOT the
	// fleet. The layer must abort without bumping any streak.
	w.dnsFn = func(context.Context, string, string) ([]string, error) { return nil, nil }

	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := w.streak.Count("cdns-a"); got != 1 {
		t.Fatalf("abort bumped streak: got %d, want 1", got)
	}
	if got := w.streak.Count("cdns-b"); got != 0 {
		t.Fatal("abort seeded a streak for cdns-b")
	}
	for _, p := range []string{"cdns-a", "cdns-b"} {
		if !cdnsPodExists(t, cs, p) {
			t.Fatalf("pod %s deleted during abort", p)
		}
	}
	if a := getCDNSDeployment(t, cs).Annotations[corednsTSAnno]; a != "" {
		t.Fatal("cooldown annotation set during abort")
	}
}

// ---------------------------------------------------------------------------
// Layer 3 — coredns_panics_total on :9153
// ---------------------------------------------------------------------------

func TestCoreDNSWatchdogLayer3Panics(t *testing.T) {
	cs := fake.NewSimpleClientset(
		cdnsPod("cdns-a", "10.0.0.1"),
		cdnsPod("cdns-b", "10.0.0.2"),
		cdnsDeployment(2, 2, nil))
	w := newCDNSWatchdog(cs)
	w.panicsFn = func(_ context.Context, podIP string) (float64, bool) {
		if podIP == "10.0.0.1" {
			return 5, true
		}
		return 0, true
	}
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := w.streak.Count("cdns-a"); got != corednsStreakMax {
		t.Fatalf("streak=%d, want %d", got, corednsStreakMax)
	}
	if cdnsPodExists(t, cs, "cdns-a") {
		t.Fatal("panicking pod not deleted")
	}
	if !cdnsPodExists(t, cs, "cdns-b") {
		t.Fatal("healthy pod deleted")
	}
}

func TestCoreDNSWatchdogLayer3UnknownIsNotStale(t *testing.T) {
	cs := fake.NewSimpleClientset(
		cdnsPod("cdns-a", "10.0.0.1"),
		cdnsDeployment(1, 1, nil))
	w := newCDNSWatchdog(cs)
	// ok=false — metrics endpoint unreachable: UNKNOWN, never stale.
	w.panicsFn = func(context.Context, string) (float64, bool) { return 7, false }
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := w.streak.Count("cdns-a"); got != 0 {
		t.Fatal("UNKNOWN metrics produced a streak")
	}
	if !cdnsPodExists(t, cs, "cdns-a") {
		t.Fatal("pod deleted on UNKNOWN metrics")
	}
}

// ---------------------------------------------------------------------------
// recover() — cooldown / storm-gate / rollout gates, restart vs delete
// ---------------------------------------------------------------------------

func TestCoreDNSRecover(t *testing.T) {
	t.Run("inside cooldown does nothing", func(t *testing.T) {
		cooldown := map[string]string{
			corednsTSAnno: strconv.FormatInt(time.Now().Unix(), 10),
		}
		cs := fake.NewSimpleClientset(
			cdnsPod("cdns-a", "10.0.0.1"), cdnsPod("cdns-b", "10.0.0.2"),
			cdnsDeployment(2, 2, cooldown))
		w := newCDNSWatchdog(cs)
		if err := w.recover(ctx, []string{"cdns-a", "cdns-b"}, nil, 2); err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{"cdns-a", "cdns-b"} {
			if !cdnsPodExists(t, cs, p) {
				t.Fatalf("pod %s deleted inside cooldown", p)
			}
		}
		if a := getCDNSDeployment(t, cs).Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"]; a != "" {
			t.Fatal("rollout restarted inside cooldown")
		}
	})

	t.Run("NotReady node gates recovery", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			testutil.Node("n1", corev1.ConditionFalse, nil),
			cdnsPod("cdns-a", "10.0.0.1"),
			cdnsDeployment(1, 1, nil))
		w := newCDNSWatchdog(cs)
		if err := w.recover(ctx, []string{"cdns-a"}, nil, 1); err != nil {
			t.Fatal(err)
		}
		if !cdnsPodExists(t, cs, "cdns-a") {
			t.Fatal("pod deleted during a node storm")
		}
		d := getCDNSDeployment(t, cs)
		if a := d.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"]; a != "" {
			t.Fatal("rollout restarted during a node storm")
		}
		if d.Annotations[corednsTSAnno] != "" {
			t.Fatal("cooldown stamped while gated — next run must still act")
		}
	})

	t.Run("rollout in progress gates recovery", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			cdnsPod("cdns-a", "10.0.0.1"),
			cdnsDeployment(2, 1, nil)) // 2 desired, only 1 ready
		w := newCDNSWatchdog(cs)
		if err := w.recover(ctx, []string{"cdns-a"}, nil, 1); err != nil {
			t.Fatal(err)
		}
		if !cdnsPodExists(t, cs, "cdns-a") {
			t.Fatal("pod deleted during an in-flight rollout")
		}
	})

	t.Run("entire fleet stale -> rollout restart", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			cdnsPod("cdns-a", "10.0.0.1"), cdnsPod("cdns-b", "10.0.0.2"),
			cdnsDeployment(2, 2, nil))
		w := newCDNSWatchdog(cs)
		if err := w.recover(ctx, []string{"cdns-a", "cdns-b"}, nil, 2); err != nil {
			t.Fatal(err)
		}
		d := getCDNSDeployment(t, cs)
		if a := d.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"]; a == "" {
			t.Fatal("restartedAt annotation missing on pod template")
		}
		if d.Annotations[corednsTSAnno] == "" {
			t.Fatal("cooldown annotation not stamped")
		}
		// The restart path does not delete pods directly.
		for _, p := range []string{"cdns-a", "cdns-b"} {
			if !cdnsPodExists(t, cs, p) {
				t.Fatalf("pod %s deleted by the full-fleet path", p)
			}
		}
	})

	t.Run("subset stale -> deletes only the suspects", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			cdnsPod("cdns-a", "10.0.0.1"), cdnsPod("cdns-b", "10.0.0.2"),
			cdnsDeployment(2, 2, nil))
		w := newCDNSWatchdog(cs)
		if err := w.recover(ctx, []string{"cdns-a"}, nil, 2); err != nil {
			t.Fatal(err)
		}
		if cdnsPodExists(t, cs, "cdns-a") {
			t.Fatal("suspect pod not deleted")
		}
		if !cdnsPodExists(t, cs, "cdns-b") {
			t.Fatal("healthy pod deleted")
		}
		d := getCDNSDeployment(t, cs)
		if d.Annotations[corednsTSAnno] == "" {
			t.Fatal("cooldown annotation not stamped")
		}
		if a := d.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"]; a != "" {
			t.Fatal("subset path must not restart the deployment")
		}
	})

	t.Run("missing deployment is a hard error", func(t *testing.T) {
		w := newCDNSWatchdog(fake.NewSimpleClientset())
		if err := w.recover(ctx, []string{"cdns-a"}, nil, 1); err == nil {
			t.Fatal("expected error when deploy/coredns is absent")
		}
	})
}

// A pod list failure is an inconclusive run, NOT an error — the next
// minute's tick re-evaluates, so run returns nil (no retry hot loop).
func TestCoreDNSWatchdogPodListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	w := newCDNSWatchdog(cs)
	if err := w.run(ctx); err != nil {
		t.Fatalf("pod list failure must be inconclusive, got %v", err)
	}
}

// Layer 2 skips a pod already proven stale by layer 1 AND a pod with
// no podIP — the DNS fn must never be invoked for either.
func TestCoreDNSWatchdogLayer2Skips(t *testing.T) {
	ready := true
	svc, es := cdnsProbeService("fresh-svc", "app-ns", 0, &ready)
	cs := fake.NewSimpleClientset(
		cdnsPod("cdns-a", "10.0.0.1"),
		cdnsPod("cdns-b", ""), // pending — no podIP yet
		cdnsDeployment(2, 2, nil),
		svc, es)
	w := newCDNSWatchdog(cs)
	// One prior log hit: this run's hit is the second CONSECUTIVE
	// one, so cdns-a is layer-1-stale without another full run.
	w.logStreak.Set("cdns-a", 1)
	w.logHitFn = func(_ context.Context, pod string) string {
		if pod == "cdns-a" {
			return "Failed to watch *v1.Endpoints: Unauthorized"
		}
		return ""
	}
	dnsCalled := false
	w.dnsFn = func(context.Context, string, string) ([]string, error) {
		dnsCalled = true
		return []string{"10.1.2.3"}, nil
	}
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if dnsCalled {
		t.Fatal("dns probe ran for a stale or IP-less pod")
	}
	if cdnsPodExists(t, cs, "cdns-a") {
		t.Fatal("layer-1-stale pod not deleted")
	}
	if !cdnsPodExists(t, cs, "cdns-b") {
		t.Fatal("IP-less pod touched")
	}
}

// recover() hard-failure paths — the errors are returned so the
// periodic wrapper meters them.
func TestCoreDNSRecoverErrorPaths(t *testing.T) {
	t.Run("node list failure aborts recovery", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			cdnsPod("cdns-a", "10.0.0.1"),
			cdnsDeployment(1, 1, nil))
		cs.PrependReactor("list", "nodes",
			func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("api down")
			})
		w := newCDNSWatchdog(cs)
		if err := w.recover(ctx, []string{"cdns-a"}, nil, 1); err == nil {
			t.Fatal("expected error when the node list fails")
		}
	})

	t.Run("rollout restart patch failure errors", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			cdnsPod("cdns-a", "10.0.0.1"),
			cdnsDeployment(1, 1, nil))
		cs.PrependReactor("patch", "deployments",
			func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("patch rejected")
			})
		w := newCDNSWatchdog(cs)
		if err := w.recover(ctx, []string{"cdns-a"}, nil, 1); err == nil {
			t.Fatal("expected error when the restart patch fails")
		}
	})

	t.Run("stale pod delete failure errors", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			cdnsPod("cdns-a", "10.0.0.1"), cdnsPod("cdns-b", "10.0.0.2"),
			cdnsDeployment(2, 2, nil))
		cs.PrependReactor("delete", "pods",
			func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("delete rejected")
			})
		w := newCDNSWatchdog(cs)
		if err := w.recover(ctx, []string{"cdns-a"}, nil, 2); err == nil {
			t.Fatal("expected error when the pod delete fails")
		}
	})
}

// bash: top-8 newest BEFORE the age filter — a fresh probe service
// sitting 9th-by-age is never even queried.
func TestCoreDNSProbeFQDNTop8Cap(t *testing.T) {
	ready := true
	var objs []runtime.Object
	for i := 0; i < 8; i++ {
		svc, _ := cdnsProbeService(
			fmt.Sprintf("svc-%d", i), "app-ns",
			time.Duration(i+1)*time.Minute, &ready) // no EndpointSlice -> skip
		objs = append(objs, svc)
	}
	// 9th newest: the only one with a ready endpoint — unreachable
	// behind the top-8 cap.
	oldSvc, oldES := cdnsProbeService("svc-9th", "app-ns", 9*time.Minute, &ready)
	objs = append(objs, oldSvc, oldES)
	w := newCDNSWatchdog(fake.NewSimpleClientset(objs...))
	if got, _ := w.probeFQDN(ctx); got != "" {
		t.Fatalf("probeFQDN=%q, want empty (9th-newest service must be capped)", got)
	}
}

// An EndpointSlice list failure skips that service — other candidates
// are still considered.
func TestCoreDNSProbeFQDNSliceListError(t *testing.T) {
	ready := true
	svc, _ := cdnsProbeService("fresh-svc", "app-ns", 0, &ready)
	cs := fake.NewSimpleClientset(svc)
	cs.PrependReactor("list", "endpointslices",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	w := newCDNSWatchdog(cs)
	if got, _ := w.probeFQDN(ctx); got != "" {
		t.Fatalf("probeFQDN=%q, want empty on slice list failure", got)
	}
}

// ---------------------------------------------------------------------------
// Streak bookkeeping — prune vanished pods, reset on fresh answer
// ---------------------------------------------------------------------------

func TestCoreDNSWatchdogStreakBookkeeping(t *testing.T) {
	ready := true
	svc, es := cdnsProbeService("fresh-svc", "app-ns", 0, &ready)
	cs := fake.NewSimpleClientset(
		cdnsPod("cdns-a", "10.0.0.1"),
		cdnsDeployment(1, 1, nil),
		svc, es)
	w := newCDNSWatchdog(cs)
	w.streak.Set("ghost-pod", 2) // pod vanished between runs
	w.streak.Set("cdns-a", 1)    // still alive and answering -> reset

	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := w.streak.Count("ghost-pod"); got != 0 {
		t.Fatal("streak for vanished pod not pruned")
	}
	if got := w.streak.Count("cdns-a"); got != 0 {
		t.Fatal("streak for freshly-answering pod not reset")
	}
}

// ---------------------------------------------------------------------------
// Layer-2 probe-target cache — TTL hit/miss, conclusive-only
// ---------------------------------------------------------------------------

// svcListCounter counts Service list API calls through a reactor —
// the observable cost the FQDN cache exists to save.
func svcListCounter(cs *fake.Clientset) *int {
	n := 0
	cs.PrependReactor("list", "services",
		func(ktesting.Action) (bool, runtime.Object, error) {
			n++
			return false, nil, nil
		})
	return &n
}

func TestCoreDNSProbeFQDNCacheTTL(t *testing.T) {
	ready := true
	pinned := time.Unix(1700000000, 0)
	// The freshness oracle decays with the clock (both windows are
	// 10m), so the probe Service is stamped close to the LATEST
	// pinned time — it stays "<10m old" across the whole timeline and
	// every conclusive pick lands on the same fqdn.
	svc, es := cdnsProbeService("fresh-svc", "app-ns", 0, &ready)
	svc.CreationTimestamp = metav1.NewTime(pinned.Add(10 * time.Minute))
	clock := pinned
	w := newCDNSWatchdog(fake.NewSimpleClientset(svc, es))
	w.now = func() time.Time { return clock }
	lists := svcListCounter(w.cs.(*fake.Clientset))

	fqdn, _ := w.probeFQDN(ctx)
	if fqdn != "fresh-svc.app-ns.svc.cluster.local" {
		t.Fatalf("first pick fqdn=%q", fqdn)
	}
	if got := *lists; got != 1 {
		t.Fatalf("first pick made %d service lists, want 1", got)
	}

	// Inside the TTL: a cache HIT — the Service/EndpointSlice lists
	// are never re-issued, which was the whole point (a 60s sweep
	// must not LIST the cluster's Services every run).
	clock = pinned.Add(5 * time.Minute)
	if fqdn2, _ := w.probeFQDN(ctx); fqdn2 != fqdn {
		t.Fatalf("cached pick changed: %q != %q", fqdn2, fqdn)
	}
	if got := *lists; got != 1 {
		t.Fatalf("TTL hit re-listed services (%d lists, want 1)", got)
	}

	// Past the TTL: a MISS — exactly one re-list, and the refreshed
	// answer re-arms the cache.
	clock = pinned.Add(corednsFQDNCacheTTL + time.Minute)
	if fqdn3, _ := w.probeFQDN(ctx); fqdn3 != fqdn {
		t.Fatalf("post-TTL pick changed: %q != %q", fqdn3, fqdn)
	}
	if got := *lists; got != 2 {
		t.Fatalf("TTL expiry did not re-list (%d lists, want 2)", got)
	}
	clock = clock.Add(time.Minute)
	if _, _ = w.probeFQDN(ctx); *lists != 2 {
		t.Fatal("refreshed answer not re-cached")
	}
}

// An INCONCLUSIVE pick ("", nil) is never cached — otherwise one
// empty cluster read would latch "no target" for the full TTL and
// layer 2 would go blind instead of re-listing on the next sweep.
func TestCoreDNSProbeFQDNCacheSkipsInconclusive(t *testing.T) {
	w := newCDNSWatchdog(fake.NewSimpleClientset()) // nothing qualifies
	lists := svcListCounter(w.cs.(*fake.Clientset))
	for i := 0; i < 2; i++ {
		if fqdn, _ := w.probeFQDN(ctx); fqdn != "" {
			t.Fatalf("empty cluster returned %q", fqdn)
		}
	}
	if got := *lists; got != 2 {
		t.Fatalf("inconclusive pick cached — %d lists across 2 runs, want 2", got)
	}
}

// ---------------------------------------------------------------------------
// Layer-2 stale cached want-set — re-probe once before concluding
// ---------------------------------------------------------------------------

// headlessProbeTarget builds the headless Service + EndpointSlice the
// W8-NM5 fallback picks: zero creationTimestamp keeps the <10m
// Service path — whose want-set is nil — from claiming it, and the
// fallback's want-set IS the ready endpoint pod IPs, exactly the set
// a CoreDNS pod roll invalidates.
func headlessProbeTarget(rv, a1, a2 string) (*corev1.Service, *discoveryv1.EndpointSlice) {
	ready := true
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "headless-svc", Namespace: "app-ns"},
		Spec:       corev1.ServiceSpec{ClusterIP: corev1.ClusterIPNone},
	}
	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "headless-svc-eps",
			Namespace:       "app-ns",
			ResourceVersion: rv,
			Labels:          map[string]string{discoveryv1.LabelServiceName: "headless-svc"},
		},
		Endpoints: []discoveryv1.Endpoint{{
			Conditions: discoveryv1.EndpointConditions{Ready: &ready},
			Addresses:  []string{a1, a2},
		}},
	}
	return svc, es
}

// A cached want-set that predates a CoreDNS roll must not fail the
// fleet: the rolled replicas answer from NEW IPs the stale set
// rejects, and two such cycles deleted healthy pods. The failed
// cached run must drop the cache, re-pick a target (fresh
// EndpointSlice read → fresh want-set) and re-probe ONCE — the fresh
// run's answers reset the streaks, nothing is deleted, and the
// re-cached target carries the NEW endpoint set.
func TestCoreDNSWatchdogStaleCachedWantReprobes(t *testing.T) {
	svc, es := headlessProbeTarget("100", "10.0.0.1", "10.0.0.2")
	cs := fake.NewSimpleClientset(
		cdnsPod("cdns-a", "10.0.0.1"),
		cdnsPod("cdns-b", "10.0.0.2"),
		cdnsDeployment(2, 2, nil),
		svc, es)
	w := newCDNSWatchdog(cs)
	var probes atomic.Int32
	rolled := false
	w.dnsFn = func(_ context.Context, _, _ string) ([]string, error) {
		probes.Add(1)
		if rolled {
			// The rolled fleet answers from its NEW IP set.
			return []string{"10.0.1.1", "10.0.1.2"}, nil
		}
		return []string{"10.0.0.1", "10.0.0.2"}, nil
	}

	// Run 1 — fresh pick, want matches the answers: all fresh, one
	// probe per pod.
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := w.cachedFQDN; got != "headless-svc.app-ns.svc.cluster.local" {
		t.Fatalf("probe fqdn=%q", got)
	}
	if len(w.cachedWant) != 2 || !w.cachedWant["10.0.0.1"] || !w.cachedWant["10.0.0.2"] {
		t.Fatalf("cached want-set = %v, want the pre-roll endpoints", w.cachedWant)
	}
	if got := probes.Load(); got != 2 {
		t.Fatalf("run 1 probes=%d, want 2", got)
	}
	for _, p := range []string{"cdns-a", "cdns-b"} {
		if got := w.streak.Count(p); got != 0 {
			t.Fatalf("%s streak=%d after a fresh pick, want 0", p, got)
		}
	}

	// Roll: the slice carries the new ready set; the replicas answer
	// from it. The cache still holds the pre-roll want-set.
	rolled = true
	newES := es.DeepCopy()
	newES.ResourceVersion = "200"
	newES.Endpoints[0].Addresses = []string{"10.0.1.1", "10.0.1.2"}
	if _, err := cs.DiscoveryV1().EndpointSlices("app-ns").Update(ctx, newES, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	// Run 2 — the cached want fails the rolled fleet, so the cycle
	// must drop the cache and re-probe ONCE with a fresh pick: 2
	// (discarded cached run) + 2 (fresh re-probe) this run.
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := probes.Load(); got != 6 {
		t.Fatalf("run 2 probes=%d total, want 6 (cached run + one re-probe)", got)
	}
	if w.cachedFQDN == "" || len(w.cachedWant) != 2 ||
		!w.cachedWant["10.0.1.1"] || !w.cachedWant["10.0.1.2"] ||
		w.cachedWant["10.0.0.1"] {
		t.Fatalf("cache not refreshed to the rolled endpoint set: fqdn=%q want=%v",
			w.cachedFQDN, w.cachedWant)
	}
	for _, p := range []string{"cdns-a", "cdns-b"} {
		if got := w.streak.Count(p); got != 0 {
			t.Fatalf("%s streak=%d — the stale cached want leaked a verdict", p, got)
		}
		if !cdnsPodExists(t, cs, p) {
			t.Fatalf("healthy rolled pod %s deleted", p)
		}
	}
	if a := getCDNSDeployment(t, cs).Annotations[corednsTSAnno]; a != "" {
		t.Fatal("recovery stamped on a healthy rolled fleet")
	}
}

// A FRESH pick that still fails pods is a real failure — the re-probe
// path is reserved for cached targets: exactly one probe run per
// cycle, streak evidence lands as before.
func TestCoreDNSWatchdogFreshPickFailsOnce(t *testing.T) {
	ready := true
	svc, es := cdnsProbeService("fresh-svc", "app-ns", 0, &ready)
	cs := fake.NewSimpleClientset(
		cdnsPod("cdns-a", "10.0.0.1"),
		cdnsPod("cdns-b", "10.0.0.2"),
		cdnsDeployment(2, 2, nil),
		svc, es)
	w := newCDNSWatchdog(cs)
	var probes atomic.Int32
	w.dnsFn = func(_ context.Context, podIP, _ string) ([]string, error) {
		probes.Add(1)
		if podIP == "10.0.0.1" {
			return nil, nil // cdns-a genuinely serves NODATA
		}
		return []string{"10.1.2.3"}, nil
	}
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := probes.Load(); got != 2 {
		t.Fatalf("fresh-pick run re-probed: %d probes, want 2", got)
	}
	if got := w.streak.Count("cdns-a"); got != 1 {
		t.Fatalf("fresh-pick failure streak=%d, want 1", got)
	}
	if !cdnsPodExists(t, cs, "cdns-a") {
		t.Fatal("pod deleted on streak 1 — recovery fired too early")
	}
}

// ---------------------------------------------------------------------------
// Worker pool — the layer-2 fan-out bound
// ---------------------------------------------------------------------------

// boundedForEach must never exceed probePoolSize goroutines in
// flight, must run every index exactly once, and must block until
// all of them finish.
func TestBoundedForEachBound(t *testing.T) {
	const items = 32 // 8x the bound — a serial loop would still pass, an unbounded fan-out would not
	var mu sync.Mutex
	inFlight, maxInFlight := 0, 0
	seen := make([]bool, items)
	done := make(chan struct{})
	go func() {
		boundedForEach(make([]string, items), func(i int) {
			mu.Lock()
			inFlight++
			if inFlight > maxInFlight {
				maxInFlight = inFlight
			}
			if seen[i] {
				t.Errorf("index %d visited twice", i)
			}
			seen[i] = true
			mu.Unlock()
			time.Sleep(time.Millisecond) // widen the race window
			mu.Lock()
			inFlight--
			mu.Unlock()
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("boundedForEach did not return — pool deadlocked")
	}
	if maxInFlight == 0 || maxInFlight > probePoolSize {
		t.Fatalf("max in-flight probes = %d, want 1..%d", maxInFlight, probePoolSize)
	}
	for i, ok := range seen {
		if !ok {
			t.Fatalf("index %d never visited", i)
		}
	}
}

// ---------------------------------------------------------------------------
// recover() — legitimate skips never count as run errors
// ---------------------------------------------------------------------------

// queueErrDelta reads the IncError counter for the watchdog's queue
// around fn — the observable for "a legitimate skip must not count
// as a run error".
func queueErrDelta(t *testing.T, queue string, fn func()) float64 {
	t.Helper()
	before := testutil.QueueErrorCount(t, queue)
	fn()
	return testutil.QueueErrorCount(t, queue) - before
}

func TestCoreDNSRecoverLegitSkipsNotCounted(t *testing.T) {
	const queue = "coredns-stale-watchdog-test"

	t.Run("cooldown skip", func(t *testing.T) {
		cooldown := map[string]string{corednsTSAnno: strconv.FormatInt(time.Now().Unix(), 10)}
		cs := fake.NewSimpleClientset(
			cdnsPod("cdns-a", "10.0.0.1"), cdnsPod("cdns-b", "10.0.0.2"),
			cdnsDeployment(2, 2, cooldown))
		w := newCDNSWatchdog(cs)
		w.queue = queue
		if d := queueErrDelta(t, queue, func() {
			if err := w.recover(ctx, []string{"cdns-a", "cdns-b"}, nil, 2); err != nil {
				t.Fatal(err)
			}
		}); d != 0 {
			t.Fatalf("cooldown skip counted %v run errors", d)
		}
	})

	t.Run("NotReady-node storm skip", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			testutil.Node("n1", corev1.ConditionFalse, nil),
			cdnsPod("cdns-a", "10.0.0.1"),
			cdnsDeployment(1, 1, nil))
		w := newCDNSWatchdog(cs)
		w.queue = queue
		if d := queueErrDelta(t, queue, func() {
			if err := w.recover(ctx, []string{"cdns-a"}, nil, 1); err != nil {
				t.Fatal(err)
			}
		}); d != 0 {
			t.Fatalf("storm skip counted %v run errors", d)
		}
	})

	t.Run("rollout-in-progress skip", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			cdnsPod("cdns-a", "10.0.0.1"),
			cdnsDeployment(2, 1, nil)) // 2 desired, only 1 ready
		w := newCDNSWatchdog(cs)
		w.queue = queue
		if d := queueErrDelta(t, queue, func() {
			if err := w.recover(ctx, []string{"cdns-a"}, nil, 1); err != nil {
				t.Fatal(err)
			}
		}); d != 0 {
			t.Fatalf("rollout skip counted %v run errors", d)
		}
	})
}

// ---------------------------------------------------------------------------
// recover() — delete NotFound tolerance + delivered-only cooldown stamp
// ---------------------------------------------------------------------------

// A suspect already gone (NotFound on delete) is tolerated — the
// fleet is exactly where recovery wanted it — and the cooldown is
// stamped only when at least one delete was DELIVERED.
func TestCoreDNSRecoverNotFoundDelete(t *testing.T) {
	t.Run("mixed: live suspect deleted, ghost tolerated, cooldown stamped", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			cdnsPod("cdns-a", "10.0.0.1"), cdnsPod("cdns-b", "10.0.0.2"),
			cdnsDeployment(2, 2, nil))
		w := newCDNSWatchdog(cs)
		// "ghost" has no pod in the fake — its delete answers NotFound.
		// nPods=3 keeps len(suspects)=2 on the surgical-delete path.
		if err := w.recover(ctx, []string{"cdns-a", "ghost"}, nil, 3); err != nil {
			t.Fatalf("NotFound delete must not error: %v", err)
		}
		if cdnsPodExists(t, cs, "cdns-a") {
			t.Fatal("live suspect not deleted")
		}
		if a := getCDNSDeployment(t, cs).Annotations[corednsTSAnno]; a == "" {
			t.Fatal("cooldown not stamped although one delete was delivered")
		}
	})

	t.Run("all gone: no error, cooldown NOT stamped", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			cdnsPod("cdns-a", "10.0.0.1"), cdnsPod("cdns-b", "10.0.0.2"),
			cdnsDeployment(2, 2, nil))
		w := newCDNSWatchdog(cs)
		if err := w.recover(ctx, []string{"ghost-a", "ghost-b"}, nil, 3); err != nil {
			t.Fatalf("all-NotFound recovery must not error: %v", err)
		}
		if a := getCDNSDeployment(t, cs).Annotations[corednsTSAnno]; a != "" {
			t.Fatal("cooldown stamped for a recovery that deleted nothing")
		}
	})
}

// ---------------------------------------------------------------------------
// Setup — Disabled gate
// ---------------------------------------------------------------------------

// Setup must register nothing when Deps.Disabled is set — routed
// through shared.SetupNoConfig so the gate is structural, not
// comment-enforced (the module has no GateEnv row today; the test
// pins the gate the helper enforces for the day one lands).
func TestSetupCoreDNSWatchdogDisabled(t *testing.T) {
	m := testutil.NewStubManager()
	if err := Setup(shared.Deps{Name: "coredns-stale-watchdog", Mgr: m,
		CS: fake.NewSimpleClientset(), Dyn: testutil.StubDyn(),
		Disabled: true}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if got := len(m.Added); got != 0 {
		t.Fatalf("disabled module registered %d runnables, want 0", got)
	}
}
