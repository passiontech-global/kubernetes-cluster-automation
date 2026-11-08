// circuit_metrics_test.go — coverage for the emitted-series bookkeeping:
// the carry-forward that re-asserts a failed patch's still-broken
// tuples, and the CRD conversion-backend sweep's verdicts.
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
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func TestCarryBrokenForward(t *testing.T) {
	b := &Breaker{}
	kind, cfg := guardstate.KindMutating, "mwc-carry"
	hookKey := kind + "/" + cfg + "/hook.example.com"
	otherKey := guardstate.KindValidating + "/vwc-x/hook.example.com"

	// Last sweep emitted both tuples; the gauge series exist.
	b.brokenEmitted.Emit(hookKey, kind, cfg, "hook.example.com")
	b.brokenEmitted.Emit(otherKey, guardstate.KindValidating, "vwc-x", "hook.example.com")
	metrics.WebhookCircuitBroken.WithLabelValues(kind, cfg, "hook.example.com").Set(1)
	metrics.WebhookCircuitBroken.WithLabelValues(guardstate.KindValidating, "vwc-x", "hook.example.com").Set(1)
	t.Cleanup(func() {
		metrics.WebhookCircuitBroken.DeleteLabelValues(kind, cfg, "hook.example.com")
		metrics.WebhookCircuitBroken.DeleteLabelValues(guardstate.KindValidating, "vwc-x", "hook.example.com")
	})
	if n := b.brokenEmitted.Prune(metrics.WebhookCircuitBroken.DeleteLabelValues); n != 0 {
		t.Fatalf("first prune deleted %d live series, want 0", n)
	}

	// This sweep's patch failed — carry only this config's tuples
	// forward, then prune: the other kind's stale tuple must be
	// deleted, the carried one must survive.
	b.brokenEmitted.Begin()
	b.carryBrokenForward(kind, cfg)
	if n := b.brokenEmitted.Prune(metrics.WebhookCircuitBroken.DeleteLabelValues); n != 1 {
		t.Fatalf("prune deleted %d series, want exactly the non-matching stale one", n)
	}
	last := b.brokenEmitted.Last()
	if _, ok := last[hookKey]; !ok {
		t.Fatalf("carried tuple %q missing from ledger: %v", hookKey, last)
	}
	if _, ok := last[otherKey]; ok {
		t.Fatalf("foreign tuple %q survived the carry-forward prune: %v", otherKey, last)
	}
	if got := ptestutil.ToFloat64(metrics.WebhookCircuitBroken.WithLabelValues(kind, cfg, "hook.example.com")); got != 1 {
		t.Fatalf("carried series value = %v, want 1", got)
	}
}

// cbConversionCRD builds the conversion-webhook CRD fixture targeting
// backend/conv-svc:9443.
func cbConversionCRD() *unstructured.Unstructured {
	crd := testutil.Unstructured(
		guardstate.CustomResourceDefinitionGVR.GroupVersion().WithKind("CustomResourceDefinition"),
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
func cbFixture(t *testing.T, extra ...runtime.Object) (*guardstate.Guard, *Breaker) {
	t.Helper()
	crd := cbConversionCRD()
	dyn := testutil.NewDynWithCRDs(crd)
	objs := append([]runtime.Object{}, extra...)
	cs := fake.NewSimpleClientset(objs...)
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
		g, b := cbFixture(t, svc, eps(true), pod)
		g.EndpointProber = func(context.Context, string, int32) bool { return false }
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
