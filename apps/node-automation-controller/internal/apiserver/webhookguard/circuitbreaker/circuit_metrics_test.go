// circuit_metrics_test.go — coverage for the emitted-series bookkeeping:
// the carry-forward that re-asserts a failed patch's still-present
// tuples (forgetting webhooks deleted from the config), and the CRD
// conversion-backend sweep's verdicts.
package circuitbreaker

import (
	"context"
	"errors"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func TestCarryBrokenForward(t *testing.T) {
	b := &Breaker{}
	kind, cfg := guardstate.KindMutating, "mwc-carry"
	hookKey := kind + "/" + cfg + "/hook.example.com"
	deadKey := kind + "/" + cfg + "/gone.example.com"
	otherKey := guardstate.KindValidating + "/vwc-x/hook.example.com"

	// Last sweep emitted all three tuples; the gauge series exist.
	b.brokenEmitted.Emit(hookKey, kind, cfg, "hook.example.com")
	b.brokenEmitted.Emit(deadKey, kind, cfg, "gone.example.com")
	b.brokenEmitted.Emit(otherKey, guardstate.KindValidating, "vwc-x", "hook.example.com")
	metrics.WebhookCircuitBroken.WithLabelValues(kind, cfg, "hook.example.com").Set(1)
	metrics.WebhookCircuitBroken.WithLabelValues(kind, cfg, "gone.example.com").Set(1)
	metrics.WebhookCircuitBroken.WithLabelValues(guardstate.KindValidating, "vwc-x", "hook.example.com").Set(1)
	t.Cleanup(func() {
		metrics.WebhookCircuitBroken.DeleteLabelValues(kind, cfg, "hook.example.com")
		metrics.WebhookCircuitBroken.DeleteLabelValues(kind, cfg, "gone.example.com")
		metrics.WebhookCircuitBroken.DeleteLabelValues(guardstate.KindValidating, "vwc-x", "hook.example.com")
	})
	if n := b.brokenEmitted.Prune(metrics.WebhookCircuitBroken.DeleteLabelValues); n != 0 {
		t.Fatalf("first prune deleted %d live series, want 0", n)
	}

	// This sweep's patch failed and gone.example.com left the config —
	// carry only this config's tuples whose webhook is still in the
	// config's live views, then prune: the other kind's stale tuple
	// and the deleted webhook's tuple must be deleted, the carried
	// one must survive.
	b.brokenEmitted.Begin()
	b.carryBrokenForward(kind, cfg, []hookView{{name: "hook.example.com"}})
	if n := b.brokenEmitted.Prune(metrics.WebhookCircuitBroken.DeleteLabelValues); n != 2 {
		t.Fatalf("prune deleted %d series, want the foreign tuple and the deleted webhook's", n)
	}
	last := b.brokenEmitted.Last()
	if _, ok := last[hookKey]; !ok {
		t.Fatalf("carried tuple %q missing from ledger: %v", hookKey, last)
	}
	if _, ok := last[deadKey]; ok {
		t.Fatalf("deleted webhook's tuple survived the carry-forward prune: %v", last)
	}
	if _, ok := last[otherKey]; ok {
		t.Fatalf("foreign tuple %q survived the carry-forward prune: %v", otherKey, last)
	}
	if got := ptestutil.ToFloat64(metrics.WebhookCircuitBroken.WithLabelValues(kind, cfg, "hook.example.com")); got != 1 {
		t.Fatalf("carried series value = %v, want 1", got)
	}
	// The deleted webhook's series is forgotten, not re-emitted —
	// DeleteLabelValues doubles as the exists-probe.
	if metrics.WebhookCircuitBroken.DeleteLabelValues(kind, cfg, "gone.example.com") {
		t.Fatal("deleted webhook's series must be forgotten, not re-emitted")
	}
}

// cbConversionCRD builds the conversion-webhook CRD fixture targeting
// backend/conv-svc:9443.
func cbConversionCRD() *unstructured.Unstructured {
	crd := testutil.Unstructured(
		kube.GVRCustomResourceDefinition.GroupVersion().WithKind("CustomResourceDefinition"),
		"", "widgets.example.com", nil)
	_ = unstructured.SetNestedField(crd.Object, "Webhook",
		"spec", "conversion", "strategy")
	_ = unstructured.SetNestedMap(crd.Object,
		map[string]any{"namespace": "backend", "name": "conv-svc", "port": int64(9443)},
		"spec", "conversion", "webhook", "clientConfig", "service")
	return crd
}

// cbFixture builds the cluster a conversion-backend sweep reads: the
// CRD on the dynamic fake, the given typed objects on the clientset.
// The clientset emulates the pods/eviction contract because the
// conversion bounce evicts through policy/v1 (heal.EvictPod) — a
// bare fake records the eviction CREATE without deleting the pod.
func cbFixture(t *testing.T, extra ...runtime.Object) (*guardstate.Guard, *Breaker) {
	t.Helper()
	crd := cbConversionCRD()
	dyn := testutil.NewDynWithCRDs(crd)
	objs := append([]runtime.Object{}, extra...)
	cs := fake.NewSimpleClientset(objs...)
	emulateEviction(cs)
	g := &guardstate.Guard{
		CS:  cs,
		Dyn: dyn,
		Now: func() time.Time { return time.Unix(1_700_000_000, 0) },
	}
	return g, &Breaker{}
}

func TestSweepCRDConversionBackendsVerdicts(t *testing.T) {
	up, down := true, false
	const (
		svcNS, svcName = "backend", "conv-svc"
		crdName        = "widgets.example.com"
		svcKey         = svcNS + "/" + svcName
	)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: svcNS, Name: "conv-0",
			CreationTimestamp: metav1.NewTime(time.Unix(1_690_000_000, 0)),
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{{
				Type: corev1.PodReady, Status: corev1.ConditionTrue,
			}},
		},
	}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: svcNS, Name: svcName}}
	eps := func(ready bool) *discoveryv1.EndpointSlice {
		ep := discoveryv1.Endpoint{Addresses: []string{"10.10.0.1"}}
		if ready {
			ep.Conditions = discoveryv1.EndpointConditions{Ready: &up}
		} else {
			// Ready=false explicitly — a nil Ready counts as ready.
			ep.Conditions = discoveryv1.EndpointConditions{Ready: &down}
		}
		ep.TargetRef = &corev1.ObjectReference{Kind: "Pod", Namespace: svcNS, Name: "conv-0"}
		return &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: svcNS, Name: svcName + "-slice",
				Labels: map[string]string{discoveryv1.LabelServiceName: svcName},
			},
			Endpoints: []discoveryv1.Endpoint{ep},
		}
	}
	cleanup := func(t *testing.T) {
		t.Cleanup(func() {
			for _, reason := range []string{
				CRDReasonMissingService, CRDReasonZeroEndpoints, CRDReasonTLSProbeFailed} {
				CRDConversionWebhookUnhealthy.DeleteLabelValues(crdName, svcKey, reason)
			}
		})
	}
	seriesCount := func(t *testing.T) int {
		t.Helper()
		return ptestutil.CollectAndCount(CRDConversionWebhookUnhealthy)
	}
	seriesFor := func(t *testing.T, reason string) float64 {
		t.Helper()
		return ptestutil.ToFloat64(
			CRDConversionWebhookUnhealthy.WithLabelValues(crdName, svcKey, reason))
	}

	t.Run("missing service", func(t *testing.T) {
		cleanup(t)
		g, b := cbFixture(t)
		if err := b.SweepCRDConversionBackends(ctx, g.TakeSnapshot(ctx)); err != nil {
			t.Fatal(err)
		}
		if seriesCount(t) != 1 {
			t.Fatalf("want exactly one unhealthy series, got %d", seriesCount(t))
		}
		if got := seriesFor(t, CRDReasonMissingService); got != 1 {
			t.Fatalf("missing_service series = %v, want 1", got)
		}
	})

	t.Run("zero effective endpoints", func(t *testing.T) {
		cleanup(t)
		g, b := cbFixture(t, svc, eps(false))
		if err := b.SweepCRDConversionBackends(ctx, g.TakeSnapshot(ctx)); err != nil {
			t.Fatal(err)
		}
		if got := seriesFor(t, CRDReasonZeroEndpoints); got != 1 {
			t.Fatalf("zero_endpoints series = %v, want 1", got)
		}
	})

	t.Run("healthy backend carries no series", func(t *testing.T) {
		cleanup(t)
		g, b := cbFixture(t, svc, eps(true))
		g.EndpointProber = func(context.Context, string, int32) bool { return true }
		if err := b.SweepCRDConversionBackends(ctx, g.TakeSnapshot(ctx)); err != nil {
			t.Fatal(err)
		}
		if seriesCount(t) != 0 {
			t.Fatalf("healthy backend must emit no series, got %d", seriesCount(t))
		}
	})

	t.Run("tls probe failed bounces the wedged pod", func(t *testing.T) {
		cleanup(t)
		// A healthy conversion backend rides alongside so the probe
		// census is NOT monitor-blind (probeBlind): one responsive
		// backend proves the controller can reach webhook pods,
		// licensing the unresponsive verdict on the other.
		okCRD := testutil.Unstructured(
			kube.GVRCustomResourceDefinition.GroupVersion().WithKind("CustomResourceDefinition"),
			"", "gadgets.example.com", nil)
		_ = unstructured.SetNestedField(okCRD.Object, "Webhook",
			"spec", "conversion", "strategy")
		_ = unstructured.SetNestedMap(okCRD.Object,
			map[string]any{"namespace": "backend", "name": "ok-svc", "port": int64(9443)},
			"spec", "conversion", "webhook", "clientConfig", "service")
		up := true
		okSlice := &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: svcNS, Name: "ok-svc-slice",
				Labels: map[string]string{discoveryv1.LabelServiceName: "ok-svc"},
			},
			Endpoints: []discoveryv1.Endpoint{{
				Addresses:  []string{"10.10.0.2"},
				Conditions: discoveryv1.EndpointConditions{Ready: &up},
			}},
		}
		g, b := cbFixture(t, svc, eps(true), pod,
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: svcNS, Name: "ok-svc"}},
			okSlice)
		// cbFixture wires only widgets.example.com on the dyn fake —
		// add the healthy CRD so its backend is measured too.
		g.Dyn = testutil.NewDynWithCRDs(cbConversionCRD(), okCRD)
		g.EndpointProber = func(_ context.Context, ip string, _ int32) bool {
			return ip == "10.10.0.2" // ok-svc answers; conv-svc wedged
		}
		if err := b.SweepCRDConversionBackends(ctx, g.TakeSnapshot(ctx)); err != nil {
			t.Fatal(err)
		}
		if got := seriesFor(t, CRDReasonTLSProbeFailed); got != 1 {
			t.Fatalf("tls_probe_failed series = %v, want 1", got)
		}
		if _, err := g.CS.CoreV1().Pods(svcNS).Get(ctx, "conv-0", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatalf("wedged pod must be bounced, get err = %v", err)
		}
	})

	t.Run("crd list failure fails closed and carries forward", func(t *testing.T) {
		cleanup(t)
		g, b := cbFixture(t)
		// Last sweep's verdict for this CRD.
		k := crdConversionKey{crd: crdName, service: svcKey, reason: CRDReasonZeroEndpoints}
		b.crdUnhealthyEmitted.Set(CRDConversionWebhookUnhealthy, 1, k,
			k.crd, k.service, k.reason)
		b.crdUnhealthyEmitted.Prune(CRDConversionWebhookUnhealthy.DeleteLabelValues)
		snap := &guardstate.Snapshot{G: g, CRDErr: errors.New("crd boom"), UnhealthyNodes: map[string]bool{}}
		if err := b.SweepCRDConversionBackends(ctx, snap); err == nil {
			t.Fatal("CRD list failure must surface as an error")
		}
		if seriesCount(t) != 1 {
			t.Fatalf("unverifiable sweep must carry the series forward, got %d", seriesCount(t))
		}
	})

	t.Run("census failure carries only live crds", func(t *testing.T) {
		cleanup(t)
		g, b := cbFixture(t)
		// Last sweep's verdicts: one for the CRD still in the
		// cluster, one for a CRD since retired from it.
		liveK := crdConversionKey{crd: crdName, service: svcKey, reason: CRDReasonZeroEndpoints}
		deadK := crdConversionKey{crd: "retired.example.com", service: "backend/old-svc", reason: CRDReasonZeroEndpoints}
		for _, k := range []crdConversionKey{liveK, deadK} {
			b.crdUnhealthyEmitted.Set(CRDConversionWebhookUnhealthy, 1, k,
				k.crd, k.service, k.reason)
		}
		b.crdUnhealthyEmitted.Prune(CRDConversionWebhookUnhealthy.DeleteLabelValues)

		// The CRD list succeeded (snap.CRDs carries the live CRD) but
		// the node census failed: carry-forward keeps the live CRD's
		// series and forgets the retired CRD's instead of re-pinning
		// it while the census keeps failing.
		snap := &guardstate.Snapshot{
			G:              g,
			Ctx:            ctx,
			CRDs:           []unstructured.Unstructured{*cbConversionCRD()},
			NodesErr:       errors.New("nodes boom"),
			UnhealthyNodes: map[string]bool{},
		}
		t.Setenv("WEBHOOK_CIRCUIT_BREAKER_ENABLED", "true")
		if err := b.SweepCRDConversionBackends(ctx, snap); err != nil {
			t.Fatalf("enabled breaker absorbs the census failure: %v", err)
		}
		if n := seriesCount(t); n != 1 {
			t.Fatalf("want only the live CRD's series, got %d", n)
		}
		if got := seriesFor(t, CRDReasonZeroEndpoints); got != 1 {
			t.Fatalf("live CRD series must carry forward, got %v", got)
		}
		if CRDConversionWebhookUnhealthy.DeleteLabelValues("retired.example.com", "backend/old-svc", CRDReasonZeroEndpoints) {
			t.Fatal("retired CRD series must be forgotten, not carried")
		}
		if _, ok := b.crdUnhealthyEmitted.Last()[deadK]; ok {
			t.Fatal("retired CRD tuple must leave the ledger")
		}
	})

	t.Run("census failure behind the lever", func(t *testing.T) {
		cleanup(t)
		g, b := cbFixture(t)
		nodesErr := errors.New("nodes boom")
		mk := func() *guardstate.Snapshot {
			return &guardstate.Snapshot{G: g, NodesErr: nodesErr, UnhealthyNodes: map[string]bool{}}
		}
		// Lever on: the breaker reports the same census failure as its
		// own error — this sweep absorbs it and carries forward.
		t.Setenv("WEBHOOK_CIRCUIT_BREAKER_ENABLED", "true")
		if err := b.SweepCRDConversionBackends(ctx, mk()); err != nil {
			t.Fatalf("enabled breaker absorbs the census failure, got %v", err)
		}
		// Lever off: nobody else reports the census failure — must surface.
		t.Setenv("WEBHOOK_CIRCUIT_BREAKER_ENABLED", "false")
		if err := b.SweepCRDConversionBackends(ctx, mk()); err == nil {
			t.Fatal("disabled breaker must report the census failure")
		}
	})

	t.Run("service get flap carries the crd verdict", func(t *testing.T) {
		cleanup(t)
		g, b := cbFixture(t, svc, eps(true))
		g.EndpointProber = func(context.Context, string, int32) bool { return true }
		k := crdConversionKey{crd: crdName, service: svcKey, reason: CRDReasonTLSProbeFailed}
		b.crdUnhealthyEmitted.Set(CRDConversionWebhookUnhealthy, 1, k,
			k.crd, k.service, k.reason)
		b.crdUnhealthyEmitted.Prune(CRDConversionWebhookUnhealthy.DeleteLabelValues)
		cs := g.CS.(*fake.Clientset)
		cs.PrependReactor("get", "services",
			func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("apiserver flap")
			})
		if err := b.SweepCRDConversionBackends(ctx, g.TakeSnapshot(ctx)); err != nil {
			t.Fatalf("absorbed sub-failure must not abort the sweep: %v", err)
		}
		if seriesCount(t) != 1 {
			t.Fatalf("flapped sweep must carry the CRD's last verdict, got %d", seriesCount(t))
		}
	})
}
