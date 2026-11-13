// sweep_series_test.go — the WebhookCircuitBroken series lifecycle:
// stale-annotation drops, prunes for deleted/recreated configs, the
// patch-failure carry-forward contract and the every-cycle streak
// prune on aborted sweeps.
package circuitbreaker

import (
	"errors"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
)

// Annotation names that no longer match a live sub-webhook drop out —
// e.g. after the orphan sweep removed the entry — while genuinely
// broken names are kept.
func TestWebhookCircuitBreakerDropsStaleAnnotationNames(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cb-stale",
			Annotations: map[string]string{
				guardstate.CircuitBrokenAnno: "gone.example.com,still-dead.example.com",
			},
		},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "still-dead.example.com",
			FailurePolicy: new(admissionv1.Ignore),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: wgSvcRef("backend", "dead-svc"),
			},
		}},
	}
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("backend"),
		wgService("backend", "dead-svc"),
		wgEndpointSlice("backend", "dead-svc", 0, 1),
		mwc)
	b := &Breaker{}
	g := &guardstate.Guard{CS: cs, Dyn: wgDyn()}
	t.Cleanup(func() {
		metrics.WebhookCircuitBroken.DeleteLabelValues(
			guardstate.KindMutating, "cb-stale", "still-dead.example.com")
	})
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	anno, ok := wgMutatingAnno(t, cs, "cb-stale")
	if !ok || anno != "still-dead.example.com" {
		t.Fatalf("annotation = %q (present=%v), want %q",
			anno, ok, "still-dead.example.com")
	}
}

// A webhook config DELETED while circuit-broken must not pin the alert
// forever — the sweep prunes every WebhookCircuitBroken series whose
// kind/config/webhook tuple it did not re-see.
// DeleteLabelValues doubles as the exists-probe: it reports whether a
// series was still registered (and removes it if so).
func TestWebhookCircuitBreakerPrunesSeriesForDeletedConfig(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cb-deleted"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "dead.example.com",
			FailurePolicy: new(admissionv1.Fail),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: wgSvcRef("backend", "dead-svc"),
			},
		}},
	}
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("backend"),
		wgService("backend", "dead-svc"),
		wgEndpointSlice("backend", "dead-svc", 0, 1),
		mwc)
	now := time.Unix(1_700_000_000, 0)
	g, b := wgBreakerGuard(cs, &now)
	t.Cleanup(func() {
		metrics.WebhookCircuitBroken.DeleteLabelValues(
			guardstate.KindMutating, "cb-deleted", "dead.example.com")
	})

	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	now = now.Add(DeadThreshold + time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if got := wgBrokenGauge(t, guardstate.KindMutating, "cb-deleted", "dead.example.com"); got != 1 {
		t.Fatalf("precondition: WebhookCircuitBroken = %v, want 1", got)
	}

	// The whole config vanishes — the next sweep never re-sees the
	// tuple, so its =1 series must be deleted, not left firing.
	if err := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().
		Delete(ctx, "cb-deleted", metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete config: %v", err)
	}
	now = now.Add(time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if metrics.WebhookCircuitBroken.DeleteLabelValues(
		guardstate.KindMutating, "cb-deleted", "dead.example.com") {
		t.Fatal("WebhookCircuitBroken series for a deleted config must be pruned")
	}
}

// A config recreated under the SAME name but without the
// circuit-broken annotation — the outage resolved before GitOps
// reapplied it — must not inherit the old object's =1 series: the
// sweep that no longer re-sees a broken tuple prunes it.
// (A recreated config whose backend is STILL dead legitimately
// re-trips the same sweep — deadSince deliberately survives a trip so
// a failed patch retries immediately — so the healthy-backend case is
// the one that proves the prune.)
func TestWebhookCircuitBreakerPrunesSeriesForRecreatedConfig(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cb-recreated"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "dead.example.com",
			FailurePolicy: new(admissionv1.Fail),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: wgSvcRef("backend", "dead-svc"),
			},
		}},
	}
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("backend"),
		wgService("backend", "dead-svc"),
		wgEndpointSlice("backend", "dead-svc", 0, 1),
		mwc)
	now := time.Unix(1_700_000_000, 0)
	g, b := wgBreakerGuard(cs, &now)
	t.Cleanup(func() {
		metrics.WebhookCircuitBroken.DeleteLabelValues(
			guardstate.KindMutating, "cb-recreated", "dead.example.com")
	})

	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	now = now.Add(DeadThreshold + time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if got := wgBrokenGauge(t, guardstate.KindMutating, "cb-recreated", "dead.example.com"); got != 1 {
		t.Fatalf("precondition: WebhookCircuitBroken = %v, want 1", got)
	}

	// Delete + recreate under the same name with failurePolicy=Fail
	// and no annotation — and the Service is healthy again by then
	// (the fix and the re-apply land together).
	if err := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().
		Delete(ctx, "cb-recreated", metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete config: %v", err)
	}
	fresh := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cb-recreated"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "dead.example.com",
			FailurePolicy: new(admissionv1.Fail),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: wgSvcRef("backend", "dead-svc"),
			},
		}},
	}
	if _, err := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().
		Create(ctx, fresh, metav1.CreateOptions{}); err != nil {
		t.Fatalf("recreate config: %v", err)
	}
	if _, err := cs.DiscoveryV1().EndpointSlices("backend").Update(ctx,
		wgEndpointSlice("backend", "dead-svc", 1, 0), metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update slice: %v", err)
	}
	now = now.Add(time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}

	if metrics.WebhookCircuitBroken.DeleteLabelValues(
		guardstate.KindMutating, "cb-recreated", "dead.example.com") {
		t.Fatal("WebhookCircuitBroken series for a recreated (un-annotated) config must be pruned")
	}
	if got := wgMutatingFP(t, cs, "cb-recreated", "dead.example.com"); got != admissionv1.Fail {
		t.Fatalf("recreated webhook keeps its declared policy, failurePolicy=%q", got)
	}
	if anno, ok := wgMutatingAnno(t, cs, "cb-recreated"); ok {
		t.Fatalf("recreated config must not carry the annotation, still %q", anno)
	}
}

// A webhook deleted from the config while its patch keeps failing must
// not pin its WebhookCircuitBroken series: the patch-failure
// carry-forward re-asserts only the sub-webhooks still in the
// config's snapshot views, so the sweep-end prune forgets the deleted
// webhook's series while a still-present one survives.
func TestWebhookCircuitBreakerCarryForwardSkipsDeletedWebhooks(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cb-carry"},
		Webhooks: []admissionv1.MutatingWebhook{
			{
				Name:          "keep.example.com",
				FailurePolicy: new(admissionv1.Fail),
				ClientConfig: admissionv1.WebhookClientConfig{
					Service: wgSvcRef("backend", "dead-svc"),
				},
			},
			{
				Name:          "gone.example.com",
				FailurePolicy: new(admissionv1.Fail),
				ClientConfig: admissionv1.WebhookClientConfig{
					Service: wgSvcRef("backend", "dead-svc"),
				},
			},
		},
	}
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("backend"),
		wgService("backend", "dead-svc"),
		wgEndpointSlice("backend", "dead-svc", 0, 1),
		mwc)
	keepLV := []string{guardstate.KindMutating, "cb-carry", "keep.example.com"}
	goneLV := []string{guardstate.KindMutating, "cb-carry", "gone.example.com"}
	t.Cleanup(func() {
		metrics.WebhookCircuitBroken.DeleteLabelValues(keepLV...)
		metrics.WebhookCircuitBroken.DeleteLabelValues(goneLV...)
	})
	now := time.Unix(1_700_000_000, 0)
	g, b := wgBreakerGuard(cs, &now)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	now = now.Add(DeadThreshold + time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if got := ptestutil.ToFloat64(metrics.WebhookCircuitBroken.WithLabelValues(keepLV...)); got != 1 {
		t.Fatalf("keep series = %v, want both webhooks tripped", got)
	}
	if got := ptestutil.ToFloat64(metrics.WebhookCircuitBroken.WithLabelValues(goneLV...)); got != 1 {
		t.Fatalf("gone series = %v, want both webhooks tripped", got)
	}

	// A concurrent writer deletes gone.example.com from the config,
	// then every patch starts failing — the trip state is now
	// unverifiable and the carry-forward decides what survives.
	live, err := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().
		Get(ctx, "cb-carry", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	live.Webhooks = live.Webhooks[:1] // drop gone.example.com
	if err := cs.Tracker().Update(
		admissionv1.SchemeGroupVersion.WithResource("mutatingwebhookconfigurations"),
		live, ""); err != nil {
		t.Fatal(err)
	}
	cs.PrependReactor("patch", "mutatingwebhookconfigurations",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("patch rejected")
		})
	for sweep := 3; sweep <= 4; sweep++ {
		now = now.Add(DeadThreshold + time.Minute)
		if err := runBreaker(ctx, g, b); err == nil {
			t.Fatal("expected the aggregated circuit breaker patch failure")
		}
		if got := ptestutil.ToFloat64(metrics.WebhookCircuitBroken.WithLabelValues(keepLV...)); got != 1 {
			t.Fatalf("sweep %d: webhook still in the census must survive the failed patch, got %v", sweep, got)
		}
		if metrics.WebhookCircuitBroken.DeleteLabelValues(goneLV...) {
			t.Fatalf("sweep %d: deleted webhook's series must be forgotten, not re-pinned", sweep)
		}
	}
}

// The streak ledgers prune on EVERY cycle: a sweep that loses its
// inputs (here: the node census fails before the jobs loop) still
// prunes deadSince and recoverStreak so streaks cannot stay pinned to
// entries nobody evaluates. brokenEmitted is exempt on purpose — its
// Begin/Prune pairing is the carry-forward contract, so the aborted
// sweep keeps the live series pinned.
func TestWebhookCircuitBreakerAbortedSweepStillPrunesStreaks(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "cb-abort"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "dead.example.com",
			FailurePolicy: new(admissionv1.Fail),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: wgSvcRef("backend", "dead-svc"),
			},
		}},
	}
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("backend"),
		wgService("backend", "dead-svc"),
		wgEndpointSlice("backend", "dead-svc", 0, 1),
		mwc)
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("nodes unreachable")
		})
	g, b := wgBreakerGuard(cs, &t0)
	key := guardstate.KindMutating + "/cb-abort/dead.example.com"
	b.deadSince.Seed(key, t0.Add(-DeadThreshold-time.Minute))
	b.recoverStreak.Hit(key)

	if err := runBreaker(ctx, g, b); err == nil {
		t.Fatal("expected the census failure to surface")
	}
	if _, seen := b.deadSince.Seen(key, t0); seen {
		t.Fatal("deadSince streak survived the aborted sweep — prune must run every cycle")
	}
	if b.recoverStreak.Count(key) != 0 {
		t.Fatal("recoverStreak survived the aborted sweep — prune must run every cycle")
	}
}

// The stale-annotation drop releases its metric series only once the
// patch LANDS — circuitPatch must not delete series for entries the
// write may still carry (the annotation is the SSOT while the patch
// fails).
func TestWebhookCircuitBreakerStaleDropSeriesReleasedOnPatchSuccess(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cb-stale-series",
			Annotations: map[string]string{
				guardstate.CircuitBrokenAnno: "gone.example.com",
			},
		},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "still-dead.example.com",
			FailurePolicy: new(admissionv1.Ignore),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: wgSvcRef("backend", "dead-svc"),
			},
		}},
	}
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("backend"),
		wgService("backend", "dead-svc"),
		wgEndpointSlice("backend", "dead-svc", 0, 1),
		mwc)
	b := &Breaker{}
	g := &guardstate.Guard{CS: cs, Dyn: wgDyn()}
	metrics.WebhookCircuitBroken.WithLabelValues(
		guardstate.KindMutating, "cb-stale-series", "gone.example.com").Set(1)
	t.Cleanup(func() {
		metrics.WebhookCircuitBroken.DeleteLabelValues(
			guardstate.KindMutating, "cb-stale-series", "gone.example.com")
	})
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	// DeleteLabelValues doubles as the exists-probe.
	if metrics.WebhookCircuitBroken.DeleteLabelValues(
		guardstate.KindMutating, "cb-stale-series", "gone.example.com") {
		t.Fatal("stale drop's series not released after the landed patch")
	}
}
