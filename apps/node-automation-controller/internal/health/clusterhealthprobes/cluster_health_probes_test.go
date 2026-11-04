// cluster_health_probes_test.go — the five ported kuberhealthy checks
// driven through an injectable DNS seam, an httptest target and the
// fake clientset (apiserver reads only — no envtest needed).
package clusterhealthprobes

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

// testProber builds a prober with the env-equivalent defaults but
// deterministic seams: DNS always resolves, and the HTTP check points
// at a dead address (fast connection-refused FAIL) unless the test
// overrides cfg.httpURL/httpClient.
func testProber(cs *fake.Clientset) *clusterHealthProber {
	p := newClusterHealthProber(cs, healthProbeConfig{
		dnsHostnames:        []string{"svc-a.ns.svc", "svc-b.ns.svc"},
		checkTimeout:        5 * time.Second,
		httpURL:             "http://127.0.0.1:1/",
		httpExpectedContent: "Healthy",
		podCheckNamespace:   "kube-system",
		maxPodRestarts:      10,
		podSkipDuration:     10 * time.Minute,
		quotaThreshold:      0.9,
		kcmLeaseMaxAge:      30 * time.Second,
		kcmFreezeMinAge:     10 * time.Minute,
	})
	p.lookupHost = func(context.Context, string) ([]string, error) {
		return []string{"10.0.0.1"}, nil
	}
	return p
}

// findMetric locates one series by exact label set inside a gathered
// family — returns nil when absent.
func findMetric(t *testing.T, family string, want map[string]string) *dto.Metric {
	t.Helper()
	fams, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range fams {
		if f.GetName() != family {
			continue
		}
		for _, m := range f.GetMetric() {
			if len(m.GetLabel()) != len(want) {
				continue
			}
			match := true
			for _, l := range m.GetLabel() {
				v, ok := want[l.GetName()]
				if !ok || v != l.GetValue() {
					match = false
					break
				}
			}
			if match {
				return m
			}
		}
	}
	return nil
}

func healthGauge(t *testing.T, check, status string) (float64, bool) {
	t.Helper()
	m := findMetric(t, "kuberhealthy_check",
		map[string]string{"check": check, "namespace": "kuberhealthy", "status": status})
	if m == nil {
		return 0, false
	}
	return m.GetGauge().GetValue(), true
}

func chPod(ns, name string, phase corev1.PodPhase, age time.Duration) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
		},
		Status: corev1.PodStatus{Phase: phase},
	}
}

// ---------------------------------------------------------------------------
// dns-status-internal
// ---------------------------------------------------------------------------

func TestProbeDNS(t *testing.T) {
	p := testProber(fake.NewSimpleClientset())
	if res := p.probeDNS(ctx); !res.pass {
		t.Fatalf("expected pass, got %+v", res)
	}

	// Any single lookup failure fails the whole check.
	p.lookupHost = func(_ context.Context, host string) ([]string, error) {
		if host == "svc-b.ns.svc" {
			return nil, errors.New("NXDOMAIN")
		}
		return []string{"10.0.0.1"}, nil
	}
	res := p.probeDNS(ctx)
	if res.pass || res.infra != nil {
		t.Fatalf("expected clean FAIL, got %+v", res)
	}
	if res.why == "" {
		t.Fatal("FAIL without a reason")
	}
}

// ---------------------------------------------------------------------------
// http-content-check
// ---------------------------------------------------------------------------

func TestProbeHTTPContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "Prometheus Server is Healthy.")
	}))
	t.Cleanup(srv.Close)

	p := testProber(fake.NewSimpleClientset())
	p.cfg.httpURL = srv.URL
	p.httpClient = srv.Client()

	if res := p.probeHTTPContent(ctx); !res.pass {
		t.Fatalf("expected pass on 'Healthy' body, got %+v", res)
	}

	// Expected substring missing -> FAIL.
	p.cfg.httpExpectedContent = "Absolutely"
	if res := p.probeHTTPContent(ctx); res.pass {
		t.Fatal("expected FAIL when body lacks the expected content")
	}
}

func TestProbeHTTPContentNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)

	p := testProber(fake.NewSimpleClientset())
	p.cfg.httpURL = srv.URL
	p.httpClient = srv.Client()
	if res := p.probeHTTPContent(ctx); res.pass {
		t.Fatal("expected FAIL on non-200")
	}
}

// ---------------------------------------------------------------------------
// pod-restarts
// ---------------------------------------------------------------------------

func TestProbePodRestarts(t *testing.T) {
	over := chPod("kube-system", "restarty", corev1.PodRunning, time.Hour)
	over.Status.ContainerStatuses = []corev1.ContainerStatus{
		{Name: "c", RestartCount: 11}, // > max(10) -> FAIL
	}
	p := testProber(fake.NewSimpleClientset(over))
	if res := p.probePodRestarts(ctx); res.pass {
		t.Fatal("expected FAIL on RestartCount 11")
	}

	// Boundary: exactly at the limit is still a pass.
	over.Status.ContainerStatuses[0].RestartCount = 10
	cs := fake.NewSimpleClientset(over)
	if res := testProber(cs).probePodRestarts(ctx); !res.pass {
		t.Fatal("RestartCount == max must pass")
	}

	// Init containers count too (a crash-looping initContainer never
	// reaches the app statuses).
	init := chPod("kube-system", "initcrash", corev1.PodRunning, time.Hour)
	init.Status.InitContainerStatuses = []corev1.ContainerStatus{
		{Name: "init", RestartCount: 42},
	}
	if res := testProber(fake.NewSimpleClientset(init)).probePodRestarts(ctx); res.pass {
		t.Fatal("expected FAIL on init-container restarts")
	}
}

// ---------------------------------------------------------------------------
// pod-status-check
// ---------------------------------------------------------------------------

func TestProbePodStatus(t *testing.T) {
	p := testProber(fake.NewSimpleClientset(
		chPod("kube-system", "stuck", corev1.PodPending, 15*time.Minute)))
	if res := p.probePodStatus(ctx); res.pass {
		t.Fatal("expected FAIL on old Pending pod")
	}

	// Younger than SKIP_DURATION -> ignored (image still pulling).
	p = testProber(fake.NewSimpleClientset(
		chPod("kube-system", "fresh", corev1.PodPending, 5*time.Minute)))
	if res := p.probePodStatus(ctx); !res.pass {
		t.Fatal("young Pending pod must be skipped")
	}

	for _, phase := range []corev1.PodPhase{corev1.PodFailed, corev1.PodUnknown} {
		p = testProber(fake.NewSimpleClientset(
			chPod("kube-system", "dead", phase, time.Hour)))
		if res := p.probePodStatus(ctx); res.pass {
			t.Fatalf("expected FAIL on phase %s", phase)
		}
	}

	p = testProber(fake.NewSimpleClientset(
		chPod("kube-system", "ok", corev1.PodRunning, time.Hour),
		chPod("kube-system", "done", corev1.PodSucceeded, time.Hour)))
	if res := p.probePodStatus(ctx); !res.pass {
		t.Fatal("Running+Succeeded must pass")
	}
}

// ---------------------------------------------------------------------------
// resource-quota-check
// ---------------------------------------------------------------------------

func quota(ns, name, used, hard string) *corev1.ResourceQuota {
	q := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Status: corev1.ResourceQuotaStatus{
			Hard: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse(hard)},
		},
	}
	if used != "" {
		q.Status.Used = corev1.ResourceList{corev1.ResourceCPU: resource.MustParse(used)}
	}
	return q
}

func TestProbeResourceQuota(t *testing.T) {
	// 95% of hard -> FAIL.
	p := testProber(fake.NewSimpleClientset(quota("a", "q", "950m", "1")))
	if res := p.probeResourceQuota(ctx); res.pass {
		t.Fatal("expected FAIL at 0.95 used/hard")
	}

	// Boundary: exactly at threshold is a pass (only '>' fails).
	p = testProber(fake.NewSimpleClientset(quota("a", "q", "900m", "1")))
	if res := p.probeResourceQuota(ctx); !res.pass {
		t.Fatal("used/hard == threshold must pass")
	}

	// No usage recorded -> used=0 -> pass.
	p = testProber(fake.NewSimpleClientset(quota("a", "q", "", "1")))
	if res := p.probeResourceQuota(ctx); !res.pass {
		t.Fatal("absent Used entry must pass")
	}
}

// ---------------------------------------------------------------------------
// run() — metric emission + error accounting
// ---------------------------------------------------------------------------

// A passing cycle emits OK=1/FAIL=0 for every check under the original
// HealthCheck names and the literal "kuberhealthy" namespace label.
func TestRunEmitsAllChecksPassing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "Prometheus Server is Healthy.")
	}))
	t.Cleanup(srv.Close)

	p := testProber(fake.NewSimpleClientset())
	p.cfg.httpURL = srv.URL
	p.httpClient = srv.Client()

	if err := p.run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, check := range []string{
		checkNameDNS, checkNameHTTPContent, checkNamePodRestarts,
		checkNamePodStatus, checkNameResourceQuota, checkNameKCMWorkqueue,
	} {
		v, ok := healthGauge(t, check, "OK")
		if !ok || v != 1 {
			t.Fatalf("kuberhealthy_check{check=%s,status=OK} = %v,%v want 1", check, v, ok)
		}
		v, ok = healthGauge(t, check, "FAIL")
		if !ok || v != 0 {
			t.Fatalf("kuberhealthy_check{check=%s,status=FAIL} = %v,%v want 0", check, v, ok)
		}
		m := findMetric(t, "kuberhealthy_check_seconds_since_success",
			map[string]string{"check": check, "namespace": "kuberhealthy"})
		if m == nil {
			t.Fatalf("seconds_since_success series missing for %s", check)
		}
	}
}

// A check that keeps failing must report a growing
// seconds_since_success — the stale-alert contract.
func TestRunFailGrowsStaleness(t *testing.T) {
	p := testProber(fake.NewSimpleClientset())
	// Seed a past success so the fail path has something to measure.
	p.lastPass[checkNameDNS] = time.Now().Add(-time.Hour)
	p.lookupHost = func(context.Context, string) ([]string, error) {
		return nil, errors.New("SERVFAIL")
	}
	if err := p.run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
	if v, _ := healthGauge(t, checkNameDNS, "FAIL"); v != 1 {
		t.Fatalf("dns FAIL gauge = %v, want 1", v)
	}
	m := findMetric(t, "kuberhealthy_check_seconds_since_success",
		map[string]string{"check": checkNameDNS, "namespace": "kuberhealthy"})
	if m == nil || m.GetGauge().GetValue() < 3599 {
		t.Fatalf("seconds_since_success = %v, want ~3600", m.GetGauge().GetValue())
	}
}

// An apiserver List error marks the check FAIL AND counts a queue run
// error, but the cycle still returns nil while other checks probe
// fine — check failures are the metric, not the run result.
func TestRunInfraErrorMarksFail(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.Fake.PrependReactor("list", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("apiserver boom")
		})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "Prometheus Server is Healthy.")
	}))
	t.Cleanup(srv.Close)

	p := testProber(cs)
	p.cfg.httpURL = srv.URL
	p.httpClient = srv.Client()

	errCount := func() float64 {
		m := findMetric(t, "shell_operator_hook_run_errors_total",
			map[string]string{"queue": clusterHealthQueue})
		if m == nil {
			return 0
		}
		return m.GetCounter().GetValue()
	}
	before := errCount()

	if err := p.run(ctx); err != nil {
		t.Fatalf("partial infra failure must not fail the cycle: %v", err)
	}
	if v, _ := healthGauge(t, checkNamePodRestarts, "FAIL"); v != 1 {
		t.Fatalf("pod-restarts FAIL gauge = %v, want 1 on List error", v)
	}
	if v, _ := healthGauge(t, checkNamePodStatus, "FAIL"); v != 1 {
		t.Fatalf("pod-status FAIL gauge = %v, want 1 on List error", v)
	}
	// Both pod checks hit the same List error -> two run errors.
	if got := errCount() - before; got != 2 {
		t.Fatalf("run errors delta = %v, want 2", got)
	}
}

// A cancelled sweep context (SIGTERM during rollout/shutdown) aborts
// the run silently: no FAIL series — a dying pod emitting FAIL=1 would
// leave a fake health signal behind — and no run-error increment. The
// DNS probe cancels mid-sweep to simulate the shutdown landing inside
// the first check.
func TestRunAbortEmitsNothing(t *testing.T) {
	cctx, cancel := context.WithCancel(ctx)
	p := testProber(fake.NewSimpleClientset())
	p.lookupHost = func(context.Context, string) ([]string, error) {
		cancel() // SIGTERM lands mid-sweep
		return []string{"10.0.0.1"}, nil
	}

	snapshot := func() map[string]float64 {
		out := map[string]float64{}
		for _, check := range []string{checkNameDNS, checkNameHTTPContent,
			checkNamePodRestarts, checkNamePodStatus, checkNameResourceQuota} {
			for _, status := range []string{"OK", "FAIL"} {
				if v, ok := healthGauge(t, check, status); ok {
					out[check+"/"+status] = v
				}
			}
		}
		m := findMetric(t, "shell_operator_hook_run_errors_total",
			map[string]string{"queue": clusterHealthQueue})
		if m != nil {
			out["run-errors"] = m.GetCounter().GetValue()
		}
		return out
	}
	before := snapshot()

	if err := p.run(cctx); err != nil {
		t.Fatalf("aborted sweep must return nil, got %v", err)
	}
	after := snapshot()
	for k, v := range before {
		if after[k] != v {
			t.Fatalf("series %q changed by aborted run: %v -> %v",
				k, v, after[k])
		}
	}
	if len(after) != len(before) {
		t.Fatalf("aborted run emitted new series: %v -> %v", before, after)
	}
}

// ---------------------------------------------------------------------------
// kcm-workqueue-watchdog (C6)
// ---------------------------------------------------------------------------

func kcmReadyNode() *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "n1"},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{
			Type:   corev1.NodeReady,
			Status: corev1.ConditionTrue,
		}}},
	}
}

// kcmLease builds the kube-controller-manager leader Lease with
// renewTime `age` before `at`.
func kcmLease(age time.Duration, at time.Time) *coordinationv1.Lease {
	rt := metav1.NewMicroTime(at.Add(-age))
	return &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: metav1.NamespaceSystem,
			Name:      "kube-controller-manager",
		},
		Spec: coordinationv1.LeaseSpec{RenewTime: &rt},
	}
}

// renewKCMLease moves renewTime to just before `at` — the "still
// renewing" signal the watchdog requires as test time advances.
func renewKCMLease(t *testing.T, cs *fake.Clientset, at time.Time) {
	t.Helper()
	lease, err := cs.CoordinationV1().Leases(metav1.NamespaceSystem).
		Get(ctx, "kube-controller-manager", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get lease: %v", err)
	}
	rt := metav1.NewMicroTime(at.Add(-2 * time.Second))
	lease.Spec.RenewTime = &rt
	if _, err := cs.CoordinationV1().Leases(metav1.NamespaceSystem).
		Update(ctx, lease, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("renew lease: %v", err)
	}
}

// kcmDesiredZeroDS is the freeze signature: desired dropped to 0 while
// pods remain scheduled — the DS controller stopped recomputing.
func kcmDesiredZeroDS() *appsv1.DaemonSet {
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  metav1.NamespaceSystem,
			Name:       "cilium",
			Generation: 1,
		},
		Status: appsv1.DaemonSetStatus{
			ObservedGeneration:     1,
			DesiredNumberScheduled: 0,
			CurrentNumberScheduled: 5,
		},
	}
}

func kcmFrozenGauge(t *testing.T, reason string) (float64, bool) {
	t.Helper()
	m := findMetric(t, "node_automation_kcm_workqueue_frozen",
		map[string]string{"reason": reason})
	if m == nil {
		return 0, false
	}
	return m.GetGauge().GetValue(), true
}

// resetKCMFrozenSeries drops the gauge's reason series: the registry
// is process-global across the package, so a value held at 1 by an
// earlier test would leak into "want absent/0" assertions here.
func resetKCMFrozenSeries(t *testing.T, reasons ...string) {
	t.Helper()
	for _, r := range reasons {
		metrics.KCMWorkqueueFrozen.DeleteLabelValues(r)
	}
}

// The freeze gauge fires only after the signature persists the full
// min-age window — first sighting and a mid-window observation pass.
func TestCheckKCMWorkqueueFreezeAfterMinAge(t *testing.T) {
	resetKCMFrozenSeries(t, "daemonset_desired_zero")
	base := time.Now()
	cs := fake.NewSimpleClientset(
		kcmReadyNode(),
		kcmLease(2*time.Second, base),
		kcmDesiredZeroDS(),
	)
	p := testProber(cs)
	p.now = func() time.Time { return base }

	// First sighting stamps first-seen — quiet.
	if res := p.checkKCMWorkqueue(ctx); !res.pass {
		t.Fatalf("first-seen signature must pass: %+v", res)
	}
	if _, ok := p.kcmFirstSeen["daemonset_desired_zero/daemonset/cilium"]; !ok {
		t.Fatal("signature not tracked in kcmFirstSeen")
	}
	if v, ok := kcmFrozenGauge(t, "daemonset_desired_zero"); ok && v != 0 {
		t.Fatalf("frozen gauge = %v before minAge, want absent/0", v)
	}

	// Inside the window — still quiet.
	at := base.Add(9 * time.Minute)
	renewKCMLease(t, cs, at)
	p.now = func() time.Time { return at }
	if res := p.checkKCMWorkqueue(ctx); !res.pass {
		t.Fatalf("signature at 9m must still pass: %+v", res)
	}
	if v, _ := kcmFrozenGauge(t, "daemonset_desired_zero"); v != 0 {
		t.Fatalf("frozen gauge = %v inside window, want 0", v)
	}

	// Past the persistence window the freeze fires.
	at = base.Add(10 * time.Minute)
	renewKCMLease(t, cs, at)
	p.now = func() time.Time { return at }
	if res := p.checkKCMWorkqueue(ctx); res.pass {
		t.Fatal("signature persisted >=10m must FAIL")
	}
	if v, _ := kcmFrozenGauge(t, "daemonset_desired_zero"); v != 1 {
		t.Fatalf("frozen gauge = %v, want 1", v)
	}
}

// A kube-system Deployment or DaemonSet whose observedGeneration lags
// generation flags stale_observed_generation once past the window.
func TestCheckKCMWorkqueueStaleObservedGeneration(t *testing.T) {
	resetKCMFrozenSeries(t, "stale_observed_generation")
	base := time.Now()
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  metav1.NamespaceSystem,
			Name:       "coredns",
			Generation: 5,
		},
		Status: appsv1.DeploymentStatus{ObservedGeneration: 3},
	}
	// A DS caught up to its spec is not a signature alongside it.
	settled := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  metav1.NamespaceSystem,
			Name:       "kube-proxy",
			Generation: 2,
		},
		Status: appsv1.DaemonSetStatus{
			ObservedGeneration:     2,
			DesiredNumberScheduled: 4,
			CurrentNumberScheduled: 4,
			NumberReady:            4,
		},
	}
	cs := fake.NewSimpleClientset(
		kcmReadyNode(),
		kcmLease(2*time.Second, base),
		dep, settled,
	)
	p := testProber(cs)
	p.now = func() time.Time { return base }

	if res := p.checkKCMWorkqueue(ctx); !res.pass {
		t.Fatalf("first-seen signature must pass: %+v", res)
	}
	if _, ok := p.kcmFirstSeen["stale_observed_generation/deployment/coredns"]; !ok {
		t.Fatal("deployment signature not tracked")
	}
	if len(p.kcmFirstSeen) != 1 {
		t.Fatalf("settled DS must not be tracked: %v", p.kcmFirstSeen)
	}

	at := base.Add(11 * time.Minute)
	renewKCMLease(t, cs, at)
	p.now = func() time.Time { return at }
	res := p.checkKCMWorkqueue(ctx)
	if res.pass {
		t.Fatal("stale observedGeneration >=10m must FAIL")
	}
	if v, _ := kcmFrozenGauge(t, "stale_observed_generation"); v != 1 {
		t.Fatalf("frozen gauge = %v, want 1", v)
	}
	if !strings.Contains(res.why, "stale_observed_generation") {
		t.Fatalf("why = %q, want the reason label", res.why)
	}
}

// A stale renewTime means the KCM is DEAD — a different failure — so
// freeze-looking signatures must not fire, and any held state clears.
func TestCheckKCMWorkqueueQuietOnStaleLease(t *testing.T) {
	resetKCMFrozenSeries(t, "daemonset_desired_zero")
	base := time.Now()
	cs := fake.NewSimpleClientset(
		kcmReadyNode(),
		kcmLease(10*time.Minute, base), // renewTime far past maxAge
		kcmDesiredZeroDS(),
	)
	p := testProber(cs)
	p.now = func() time.Time { return base }

	if res := p.checkKCMWorkqueue(ctx); !res.pass {
		t.Fatalf("stale KCM lease must stay quiet: %+v", res)
	}
	if v, _ := kcmFrozenGauge(t, "daemonset_desired_zero"); v != 0 {
		t.Fatalf("frozen gauge = %v on stale lease, want absent/0", v)
	}
	if len(p.kcmFirstSeen) != 0 {
		t.Fatalf("stale lease left %d tracked signatures", len(p.kcmFirstSeen))
	}

	// A previously-frozen gauge also clears when the holder dies.
	p.kcmFrozenReasons["daemonset_desired_zero"] = true
	metrics.KCMWorkqueueFrozen.WithLabelValues("daemonset_desired_zero").Set(1)
	if res := p.checkKCMWorkqueue(ctx); !res.pass {
		t.Fatalf("stale KCM lease must stay quiet: %+v", res)
	}
	if v, ok := kcmFrozenGauge(t, "daemonset_desired_zero"); !ok || v != 0 {
		t.Fatalf("held gauge on dead KCM = %v,%v want 0", v, ok)
	}

	// No Lease object at all — same quiet path.
	p = testProber(fake.NewSimpleClientset(kcmReadyNode(), kcmDesiredZeroDS()))
	p.now = func() time.Time { return base }
	if res := p.checkKCMWorkqueue(ctx); !res.pass {
		t.Fatalf("missing KCM lease must stay quiet: %+v", res)
	}
}

// With no Ready node the desired==0 reading is ambiguous — quiet.
func TestCheckKCMWorkqueueQuietOnNoReadyNodes(t *testing.T) {
	resetKCMFrozenSeries(t, "daemonset_desired_zero")
	base := time.Now()

	// Zero nodes at all.
	cs := fake.NewSimpleClientset(kcmLease(2*time.Second, base), kcmDesiredZeroDS())
	p := testProber(cs)
	p.now = func() time.Time { return base }
	if res := p.checkKCMWorkqueue(ctx); !res.pass {
		t.Fatalf("no nodes must stay quiet: %+v", res)
	}

	// Every node NotReady — same.
	notReady := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "n1"},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{
			Type:   corev1.NodeReady,
			Status: corev1.ConditionFalse,
		}}},
	}
	cs = fake.NewSimpleClientset(notReady, kcmLease(2*time.Second, base), kcmDesiredZeroDS())
	p = testProber(cs)
	p.now = func() time.Time { return base }
	if res := p.checkKCMWorkqueue(ctx); !res.pass {
		t.Fatalf("all nodes NotReady must stay quiet: %+v", res)
	}
	if v, _ := kcmFrozenGauge(t, "daemonset_desired_zero"); v != 0 {
		t.Fatalf("frozen gauge = %v with no ready nodes, want absent/0", v)
	}
	if len(p.kcmFirstSeen) != 0 {
		t.Fatalf("no-ready-nodes left %d tracked signatures", len(p.kcmFirstSeen))
	}
}

// Once the DS reconciles again the signature drops, first-seen is
// pruned and the gauge flips back to 0.
func TestCheckKCMWorkqueueRecoveryClearsGauge(t *testing.T) {
	resetKCMFrozenSeries(t, "daemonset_desired_zero")
	base := time.Now()
	cs := fake.NewSimpleClientset(
		kcmReadyNode(),
		kcmLease(2*time.Second, base),
		kcmDesiredZeroDS(),
	)
	p := testProber(cs)
	p.now = func() time.Time { return base }

	// Drive past the window into frozen.
	if res := p.checkKCMWorkqueue(ctx); !res.pass {
		t.Fatalf("first-seen signature must pass: %+v", res)
	}
	at := base.Add(11 * time.Minute)
	renewKCMLease(t, cs, at)
	p.now = func() time.Time { return at }
	if res := p.checkKCMWorkqueue(ctx); res.pass {
		t.Fatal("expected frozen FAIL")
	}
	if v, _ := kcmFrozenGauge(t, "daemonset_desired_zero"); v != 1 {
		t.Fatalf("frozen gauge = %v, want 1", v)
	}

	// KCM catches up: desired recomputed to match the scheduled pods.
	at = base.Add(12 * time.Minute)
	renewKCMLease(t, cs, at)
	p.now = func() time.Time { return at }
	ds, err := cs.AppsV1().DaemonSets(metav1.NamespaceSystem).
		Get(ctx, "cilium", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get ds: %v", err)
	}
	ds.Status.DesiredNumberScheduled = 5
	if _, err := cs.AppsV1().DaemonSets(metav1.NamespaceSystem).
		Update(ctx, ds, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update ds: %v", err)
	}

	if res := p.checkKCMWorkqueue(ctx); !res.pass {
		t.Fatalf("recovered signature must pass: %+v", res)
	}
	if v, ok := kcmFrozenGauge(t, "daemonset_desired_zero"); !ok || v != 0 {
		t.Fatalf("frozen gauge after recovery = %v,%v want 0", v, ok)
	}
	if len(p.kcmFirstSeen) != 0 {
		t.Fatalf("resolved signature not pruned: %v", p.kcmFirstSeen)
	}
}

// HEALTH_* env knobs: garbage strings, zero and negative values must
// not silently produce dangerous config — HEALTH_CHECK_TIMEOUT=0
// would instant-fail every probe, HEALTH_MAX_POD_RESTARTS=-1 would
// flag every container, and a 0s interval would panic the ticker.
// Each falls back to the default (and logs a warning).
func TestHealthEnvHelpersClampBadValues(t *testing.T) {
	// Unset → defaults.
	for _, k := range []string{
		"HEALTH_CHECK_TIMEOUT", "HEALTH_POD_SKIP_DURATION",
		"HEALTH_KCM_LEASE_MAX_AGE", "HEALTH_KCM_FREEZE_MIN_AGE",
		"HEALTH_MAX_POD_RESTARTS", "HEALTH_RESOURCE_QUOTA_THRESHOLD",
		"CLUSTER_HEALTH_PROBES_INTERVAL",
	} {
		t.Setenv(k, "")
	}
	cfg := healthProbeConfigFromEnv()
	if cfg.checkTimeout != 30*time.Second || cfg.podSkipDuration != 10*time.Minute ||
		cfg.kcmLeaseMaxAge != 30*time.Second || cfg.kcmFreezeMinAge != 10*time.Minute {
		t.Fatalf("unset env produced non-default config: %+v", cfg)
	}
	if cfg.maxPodRestarts != 10 || cfg.quotaThreshold != 0.9 {
		t.Fatalf("unset env produced non-default config: %+v", cfg)
	}

	// Zero/negative durations → default, not instant-fail/panic.
	for _, v := range []string{"0", "0s", "-5s", "garbage"} {
		t.Setenv("HEALTH_CHECK_TIMEOUT", v)
		if got := healthProbeConfigFromEnv().checkTimeout; got != 30*time.Second {
			t.Fatalf("HEALTH_CHECK_TIMEOUT=%q → checkTimeout %v, want 30s default", v, got)
		}
	}
	// A parseable positive value wins.
	t.Setenv("HEALTH_CHECK_TIMEOUT", "15s")
	if got := healthProbeConfigFromEnv().checkTimeout; got != 15*time.Second {
		t.Fatalf("HEALTH_CHECK_TIMEOUT=15s → %v, want 15s", got)
	}

	// Negative int → default; 0 is a legitimate (strict) threshold.
	t.Setenv("HEALTH_MAX_POD_RESTARTS", "-1")
	if got := healthProbeConfigFromEnv().maxPodRestarts; got != 10 {
		t.Fatalf("HEALTH_MAX_POD_RESTARTS=-1 → %d, want 10 default", got)
	}
	t.Setenv("HEALTH_MAX_POD_RESTARTS", "not-an-int")
	if got := healthProbeConfigFromEnv().maxPodRestarts; got != 10 {
		t.Fatalf("HEALTH_MAX_POD_RESTARTS=not-an-int → %d, want 10 default", got)
	}
	t.Setenv("HEALTH_MAX_POD_RESTARTS", "0")
	if got := healthProbeConfigFromEnv().maxPodRestarts; got != 0 {
		t.Fatalf("HEALTH_MAX_POD_RESTARTS=0 → %d, want 0 (any restart flags)", got)
	}

	// Unparseable float → default.
	t.Setenv("HEALTH_RESOURCE_QUOTA_THRESHOLD", "banana")
	if got := healthProbeConfigFromEnv().quotaThreshold; got != 0.9 {
		t.Fatalf("HEALTH_RESOURCE_QUOTA_THRESHOLD=banana → %v, want 0.9", got)
	}
}

// desired==0 with zero pods anywhere is a legitimately-empty selector
// — not a freeze — and it must never even enter first-seen tracking.
func TestCheckKCMWorkqueueIgnoresEmptyDaemonSet(t *testing.T) {
	resetKCMFrozenSeries(t, "daemonset_desired_zero")
	base := time.Now()
	empty := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  metav1.NamespaceSystem,
			Name:       "hw-agent",
			Generation: 1,
		},
		Status: appsv1.DaemonSetStatus{
			ObservedGeneration:     1,
			DesiredNumberScheduled: 0,
			// nothing scheduled/ready/misscheduled anywhere
		},
	}
	cs := fake.NewSimpleClientset(
		kcmReadyNode(),
		kcmLease(2*time.Second, base),
		empty,
	)
	p := testProber(cs)
	p.now = func() time.Time { return base }

	if res := p.checkKCMWorkqueue(ctx); !res.pass {
		t.Fatalf("empty DaemonSet must pass: %+v", res)
	}
	at := base.Add(30 * time.Minute)
	renewKCMLease(t, cs, at)
	p.now = func() time.Time { return at }
	if res := p.checkKCMWorkqueue(ctx); !res.pass {
		t.Fatalf("empty DaemonSet must never freeze: %+v", res)
	}
	if v, _ := kcmFrozenGauge(t, "daemonset_desired_zero"); v != 0 {
		t.Fatalf("frozen gauge = %v, want absent/0", v)
	}
	if len(p.kcmFirstSeen) != 0 {
		t.Fatalf("non-signature must not be tracked: %v", p.kcmFirstSeen)
	}
}
