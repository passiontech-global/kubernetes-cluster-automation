// Package probetest holds the shared test builders every
// cluster-health check subpackage uses: the standard probefw.Deps
// wiring with deterministic seams, the fake dynamic client carrying
// every GVR the checks List, node/pod/EndpointSlice fixtures, the
// fake Prometheus query server, and the metric-registry lookup
// helpers. Functional names — no wave provenance.
package probetest

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func init() {
	// Snapshot immutability guardrail: every test binary that links
	// this scaffolding verifies each memoized sweep census was not
	// mutated in place between reads — the shared-map write bug
	// class the sweep overlay exists to eliminate gets a permanent
	// CI tripwire instead of a silent cross-check corruption.
	// Production binaries never import probetest, so the flag can
	// never arm outside tests.
	probefw.EnableSnapshotVerify()
}

// NewDeps builds a probefw.Deps with the env-equivalent defaults but
// deterministic seams: DNS always resolves, and the HTTP check points
// at a dead address (fast connection-refused FAIL) unless the test
// overrides Cfg.HTTPContent.URL/HTTPClient.
func NewDeps(cs kubernetes.Interface, dyn dynamic.Interface) *probefw.Deps {
	d := &probefw.Deps{
		Name: "cluster-health-probes",
		CS:   cs,
		Dyn:  dyn,
		Cfg: probefw.Config{
			Timeouts: probefw.TimeoutsConfig{
				Check:    5 * time.Second,
				PerCheck: time.Minute,
			},
			HTTPContent: probefw.HTTPContentConfig{
				URL:      "http://127.0.0.1:1/",
				Expected: "Healthy",
			},
		},
		LookupHost: func(context.Context, string) ([]string, error) {
			return []string{"10.0.0.1"}, nil
		},
		HTTPClient: &http.Client{},
		Now:        time.Now,
	}
	// Same wiring probefw.NewDeps applies in production: the
	// Prometheus client shares the HTTPClient seam tests swap
	// post-construction and bounds each query by the check timeout.
	d.Prom = promq.Client{HTTP: d.HTTPClient, Timeout: d.Cfg.Timeouts.Check}
	return d
}

// FreezeNow pins the Deps clock to base — the shared shape for the
// "p.Now = func() time.Time { return base }" every persistence-window
// test hand-rolls. Advance by calling again with a new base (the
// clock is the same plain func var production wires to time.Now).
func FreezeNow(d *probefw.Deps, base time.Time) {
	d.Now = func() time.Time { return base }
}

// SweepCtx returns ctx carrying a FRESH probefw sweep snapshot +
// write-overlay — the same wrapper the production sweep root
// installs once per run. Check tests must drive Run through it:
// on a bare ctx every census call spawns its own throwaway
// snapshot, so the memoized reads never share within a Run AND
// the EnableSnapshotVerify fingerprint guard can never observe a
// second read of the same census — the mutation tripwire this
// package exists to arm would be dead code. A fresh snapshot per
// call keeps each Run an isolated "sweep" exactly like production.
//
// Keep the returned ctx and pass it to VerifySweep AFTER the check
// Run returns: the per-read fingerprint guard only fires when a
// memo is read again, so a census object mutated in place AFTER
// its memo's last read is invisible until the post-sweep verify
// re-checks every loaded memo (probefw.VerifySweepSnapshotUnmutated
// — same panic contract).
func SweepCtx(ctx context.Context) context.Context {
	return probefw.WithSweepSnapshot(ctx)
}

// VerifySweep is the post-Run half of the snapshot mutation guard:
// it re-verifies every census memo the sweepCtx-carrying Run
// loaded against its load-time fingerprint, panicking on the first
// in-place write the per-read guard could not observe (a mutation
// after the memo's last read). Call it with the SAME ctx SweepCtx
// returned, after the check's Run completes:
//
//	sctx := probetest.SweepCtx(ctx)
//	res := check.Run(sctx)
//	probetest.VerifySweep(sctx)
//
// Outside a sweep snapshot (or in a binary that never armed
// EnableSnapshotVerify — production) it is a no-op.
func VerifySweep(sweepCtx context.Context) {
	probefw.VerifySweepSnapshotUnmutated(sweepCtx)
}

// OpDyn returns the shared CRD-aware dynamic fake — every GVR the
// sweep checks scan is already in testutil's dynCRDGVKs table (the
// fake PANICS on an unregistered GVR List, so the watched-operator
// roster, OLM/autopilot reads and report CRs all live there) plus
// the apiextensions kinds via NewDynamicClientWithCRDs:
// api-object-sprawl-report-gc's kine large-object census Lists CRDs
// every cycle, matching the always-served apiextensions API on a
// real cluster.
func OpDyn(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return testutil.NewDynamicClientWithCRDs(objs...)
}

// UnstructuredObj builds a CR object carrying a generation and an
// optional status.observedGeneration (og=0 leaves the field absent).
func UnstructuredObj(apiVersion, kind, ns, name string, gen, og int64) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]any{
			"namespace": ns, "name": name, "generation": gen,
		},
	}}
	if og > 0 {
		_ = unstructured.SetNestedField(obj.Object, og, "status", "observedGeneration")
	}
	return obj
}

// FindMetric locates one series by exact label set inside a gathered
// family — returns nil when absent.
func FindMetric(t *testing.T, family string, want map[string]string) *dto.Metric {
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

// HealthGauge reads the kuberhealthy_check{check,status} gauge under
// the literal "kuberhealthy" namespace label.
func HealthGauge(t *testing.T, check, status string) (float64, bool) {
	t.Helper()
	m := FindMetric(t, "kuberhealthy_check",
		map[string]string{"check": check, "namespace": "kuberhealthy", "status": status})
	if m == nil {
		return 0, false
	}
	return m.GetGauge().GetValue(), true
}

// ---------------------------------------------------------------------------
// Node / pod / EndpointSlice builders
// ---------------------------------------------------------------------------

// ReadyWorkerNode builds a Ready, schedulable worker node with optional
// extra conditions (FilesystemReadOnly/KernelHungTasks latched `age`
// ago for the hang check).
func ReadyWorkerNode(name string, cond corev1.NodeConditionType, condAge time.Duration, unschedulable bool) *corev1.Node {
	n := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.NodeSpec{Unschedulable: unschedulable},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{
			{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}},
	}
	if cond != "" {
		n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
			Type:               cond,
			Status:             corev1.ConditionTrue,
			LastTransitionTime: metav1.NewTime(time.Now().Add(-condAge)),
			// A live writer re-stamps the heartbeat — node-hang
			// precordon refuses fused latches whose heartbeat is
			// stale, so the default shape is a fresh stamp; tests
			// for the zombie-latch gate overwrite it with an old
			// (or zero) value.
			LastHeartbeatTime: metav1.NewTime(time.Now()),
		})
	}
	return n
}

// PendingUnscheduledPod builds a Pending pod that was never assigned —
// no nodeName, and when scheduled=false no PodScheduled condition at
// all (the scheduler-freeze signature).
func PendingUnscheduledPod(ns, name string, age time.Duration, scheduled bool) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
		},
		Status: corev1.PodStatus{Phase: corev1.PodPending},
	}
	if scheduled {
		p.Status.Conditions = []corev1.PodCondition{{
			Type:   corev1.PodScheduled,
			Status: corev1.ConditionFalse}}
	}
	return p
}

// HeadlessService builds a headless Service with a pod selector — the
// shape linkerd-destination derives endpoints from.
func HeadlessService(ns, name string, selector map[string]string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: corev1.ServiceSpec{
			ClusterIP: corev1.ClusterIPNone,
			Selector:  selector,
		},
	}
}

// ReadyPodWithIP builds a Running+Ready pod carrying podIP and labels.
func ReadyPodWithIP(ns, name, ip string, lbls map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			Labels:            lbls,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
			UID:               types.UID("uid-" + name),
		},
		Spec: corev1.PodSpec{NodeName: "w1"},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			PodIP: ip,
			Conditions: []corev1.PodCondition{{
				Type:   corev1.PodReady,
				Status: corev1.ConditionTrue,
			}},
		},
	}
}

// EndpointSliceForService builds an EndpointSlice bound to svc carrying
// the given addresses, all Ready.
func EndpointSliceForService(ns, svc string, addrs ...string) *discoveryv1.EndpointSlice {
	s := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      svc + "-abc",
			Labels:    map[string]string{discoveryv1.LabelServiceName: svc},
		},
	}
	for _, a := range addrs {
		s.Endpoints = append(s.Endpoints, discoveryv1.Endpoint{
			Addresses:  []string{a},
			Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
		})
	}
	return s
}

// PodWithPhase builds a pod with explicit phase, readiness and age.
func PodWithPhase(ns, name string, phase corev1.PodPhase, ready bool, age time.Duration) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
			UID:               types.UID("uid-" + ns + "-" + name),
		},
		Status: corev1.PodStatus{Phase: phase},
	}
	if ready {
		p.Status.Conditions = []corev1.PodCondition{{
			Type:   corev1.PodReady,
			Status: corev1.ConditionTrue,
		}}
	} else {
		p.Status.Conditions = []corev1.PodCondition{{
			Type:               corev1.PodReady,
			Status:             corev1.ConditionFalse,
			LastTransitionTime: metav1.NewTime(time.Now().Add(-age)),
		}}
	}
	return p
}

// ---------------------------------------------------------------------------
// Fake Prometheus query server
// ---------------------------------------------------------------------------

// PromTestSample is one Prometheus instant-vector sample for the fake
// query API.
type PromTestSample struct {
	Labels map[string]string
	Value  float64
}

// promTestBody renders a Prometheus /api/v1/query vector response.
func promTestBody(samples []PromTestSample) string {
	var b strings.Builder
	b.WriteString(`{"status":"success","data":{"resultType":"vector","result":[`)
	for i, s := range samples {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"metric":{`)
		first := true
		for k, v := range s.Labels {
			if !first {
				b.WriteString(",")
			}
			first = false
			fmt.Fprintf(&b, "%q:%q", k, v)
		}
		b.WriteString(`},"value":[1,"` +
			strconv.FormatFloat(s.Value, 'f', -1, 64) + `"]}`)
	}
	b.WriteString(`]}}`)
	return b.String()
}

// PromTestServer serves promTestBody(respond(query)) at /api/v1/query
// and returns the server plus the last query string seen (for
// assertion).
func PromTestServer(t *testing.T, respond func(query string) []PromTestSample) (*httptest.Server, *string) {
	t.Helper()
	var lastQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// promq issues POST + form body (query strings stay out of
		// URL access logs); ParseForm covers both that and any
		// legacy GET caller.
		_ = r.ParseForm()
		lastQuery = r.FormValue("query")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, promTestBody(respond(lastQuery)))
	}))
	t.Cleanup(srv.Close)
	return srv, &lastQuery
}

// ---------------------------------------------------------------------------
// Dynamic-client + counter assertions
// ---------------------------------------------------------------------------

// DynExists reports whether the dynamic fake still holds the
// ns/name object — the "was it deleted / did the write land"
// assertion for CR fixtures. A non-NotFound GET error fails the
// test: an unreadable fake is a broken fixture, not an absence.
func DynExists(ctx context.Context, t *testing.T, dyn dynamic.Interface,
	gvr schema.GroupVersionResource, ns, name string) bool {

	t.Helper()
	_, err := dyn.Resource(gvr).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		return true
	}
	if apierrors.IsNotFound(err) {
		return false
	}
	t.Fatalf("dyn get %s %s/%s: %v", gvr.Resource, ns, name, err)
	return false
}

// CounterSnapshot reads the queue's legacy hook-error counter —
// pair with AssertCounterDelta after the action under test.
func CounterSnapshot(t *testing.T, queue string) float64 {
	t.Helper()
	return testutil.QueueErrorCount(t, queue)
}

// AssertCounterDelta fails unless the queue error counter grew by
// exactly want since before — the one-liner form of the
// QueueErrorCount-before/after pairs every IncError assertion
// hand-rolls.
func AssertCounterDelta(t *testing.T, queue string, before, want float64) {
	t.Helper()
	if d := testutil.QueueErrorCount(t, queue) - before; d != want {
		t.Fatalf("queue %q error counter delta = %v, want %v", queue, d, want)
	}
}
