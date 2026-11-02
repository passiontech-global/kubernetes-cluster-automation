package controller

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
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
		cs:       cs,
		streak:   map[string]int{},
		logHitFn: func(context.Context, string) string { return "" },
		dnsFn:    func(context.Context, string, string) bool { return true },
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
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	// Instant catch: streak is forced straight to max, no 2-run wait.
	if got := w.streak["cdns-a"]; got != corednsStreakMax {
		t.Fatalf("streak=%d, want %d", got, corednsStreakMax)
	}
	if _, ok := w.streak["cdns-b"]; ok {
		t.Fatal("clean pod got a streak")
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
			if got := w.probeFQDN(ctx); got != tc.want {
				t.Fatalf("probeFQDN=%q, want %q", got, tc.want)
			}
		})
	}

	t.Run("old service skipped for a fresh one", func(t *testing.T) {
		oldSvc, oldES := cdnsProbeService("old-svc", "app-ns", 20*time.Minute, &readyTrue)
		newSvc, newES := cdnsProbeService("fresh-svc", "app-ns", 0, &readyTrue)
		w := newCDNSWatchdog(fake.NewSimpleClientset(oldSvc, oldES, newSvc, newES))
		if got := w.probeFQDN(ctx); got != "fresh-svc.app-ns.svc.cluster.local" {
			t.Fatalf("probeFQDN=%q", got)
		}
	})

	t.Run("empty cluster is inconclusive", func(t *testing.T) {
		w := newCDNSWatchdog(fake.NewSimpleClientset())
		if got := w.probeFQDN(ctx); got != "" {
			t.Fatalf("probeFQDN=%q, want empty", got)
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
	var gotFQDN string
	w.dnsFn = func(_ context.Context, podIP, fqdn string) bool {
		gotFQDN = fqdn
		return podIP != "10.0.0.1" // only cdns-a fails to resolve
	}

	// First failure: suspect only — streak 1, no recovery action.
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if gotFQDN != "fresh-svc.app-ns.svc.cluster.local" {
		t.Fatalf("probe fqdn=%q", gotFQDN)
	}
	if got := w.streak["cdns-a"]; got != 1 {
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
	if got := w.streak["cdns-a"]; got != corednsStreakMax {
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
	w.streak["cdns-a"] = 1
	// Every pod fails to resolve -> the probe path is broken, NOT the
	// fleet. The layer must abort without bumping any streak.
	w.dnsFn = func(context.Context, string, string) bool { return false }

	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := w.streak["cdns-a"]; got != 1 {
		t.Fatalf("abort bumped streak: got %d, want 1", got)
	}
	if _, ok := w.streak["cdns-b"]; ok {
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
	if got := w.streak["cdns-a"]; got != corednsStreakMax {
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
	if _, ok := w.streak["cdns-a"]; ok {
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
		if err := w.recover(ctx, []string{"cdns-a", "cdns-b"}, 2); err != nil {
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
			node("n1", corev1.ConditionFalse, nil),
			cdnsPod("cdns-a", "10.0.0.1"),
			cdnsDeployment(1, 1, nil))
		w := newCDNSWatchdog(cs)
		if err := w.recover(ctx, []string{"cdns-a"}, 1); err != nil {
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
		if err := w.recover(ctx, []string{"cdns-a"}, 1); err != nil {
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
		if err := w.recover(ctx, []string{"cdns-a", "cdns-b"}, 2); err != nil {
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
		if err := w.recover(ctx, []string{"cdns-a"}, 2); err != nil {
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
		if err := w.recover(ctx, []string{"cdns-a"}, 1); err == nil {
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
	w.logHitFn = func(_ context.Context, pod string) string {
		if pod == "cdns-a" {
			return "Failed to watch *v1.Endpoints: Unauthorized"
		}
		return ""
	}
	dnsCalled := false
	w.dnsFn = func(context.Context, string, string) bool {
		dnsCalled = true
		return true
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
		if err := w.recover(ctx, []string{"cdns-a"}, 1); err == nil {
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
		if err := w.recover(ctx, []string{"cdns-a"}, 1); err == nil {
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
		if err := w.recover(ctx, []string{"cdns-a"}, 2); err == nil {
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
	if got := w.probeFQDN(ctx); got != "" {
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
	if got := w.probeFQDN(ctx); got != "" {
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
	w.streak["ghost-pod"] = 2 // pod vanished between runs
	w.streak["cdns-a"] = 1    // still alive and answering -> reset

	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.streak["ghost-pod"]; ok {
		t.Fatal("streak for vanished pod not pruned")
	}
	if _, ok := w.streak["cdns-a"]; ok {
		t.Fatal("streak for freshly-answering pod not reset")
	}
}
