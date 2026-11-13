// sweep_bounce_test.go — the brownout probe and pod-bounce path:
// unresponsive backends, PDB refusals and budget refunds, the
// monitor-blind guard and the kill-switch RestoreOnly mode.
package circuitbreaker

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// circuit-breaker-bounce — brownout probe, pod bounce, unresponsive breaker
// ---------------------------------------------------------------------------

// wgPod builds a Running+Ready Pod fixture for the bounce path.
func wgPod(ns, name string, age time.Duration) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{{
				Type:   corev1.PodReady,
				Status: corev1.ConditionTrue,
			}},
		},
	}
}

// wgHungSlice builds a slice whose single Ready endpoint targets a
// Pod and carries no NodeName — effective-ready by benefit of the
// doubt, exactly the brownout shape circuit-breaker-bounce probes.
func wgHungSlice(ns, svc, pod string) *discoveryv1.EndpointSlice {
	es := wgEndpointSlice(ns, svc, 0, 0)
	up := true
	es.Endpoints = []discoveryv1.Endpoint{{
		Addresses:  []string{"10.10.7.7"},
		TargetRef:  &corev1.ObjectReference{Kind: "Pod", Name: pod},
		Conditions: discoveryv1.EndpointConditions{Ready: &up},
	}}
	return es
}

// A webhook backend whose Ready endpoints ALL fail the TCP+TLS
// handshake is "unresponsive": stage 1 bounces the oldest Ready
// backing pod immediately (15m per-service cooldown), and stage 2
// trips the breaker to Ignore after the 90s partition threshold —
// then restores Fail once a probe answers again.
func TestWebhookCircuitBreakerUnresponsiveTripsAndBounces(t *testing.T) {
	// ok-svc rides alongside the hung backend so the sweep's probe
	// census is NOT monitor-blind (probeBlind): one responsive
	// backend proves the controller's path to webhook pods works,
	// which is what licenses the unresponsive verdict on the other.
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "brownout"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "hung.example.com",
			FailurePolicy: new(admissionv1.Fail),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: wgSvcRef("backend", "hung-svc"),
			},
		}, {
			Name:          "ok.example.com",
			FailurePolicy: new(admissionv1.Fail),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: wgSvcRef("backend", "ok-svc"),
			},
		}},
	}
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("backend"),
		wgService("backend", "hung-svc"),
		wgHungSlice("backend", "hung-svc", "wh-old"),
		wgService("backend", "ok-svc"),
		wgEndpointSlice("backend", "ok-svc", 1, 0),
		wgPod("backend", "wh-old", 48*time.Hour),
		wgPod("backend", "wh-new", time.Hour),
		mwc)
	testutil.EmulateEviction(cs) // the bounce evicts through policy/v1
	now := time.Unix(1_700_000_000, 0)
	// endpointProber answers per IP: ok-svc's endpoint (10.10.0.1)
	// responds, hung-svc's (10.10.7.7) fails every handshake — the
	// pods are hung.
	b := &Breaker{}
	g := &guardstate.Guard{
		CS: cs, Dyn: wgDyn(),
		Now: func() time.Time { return now },
		EndpointProber: func(_ context.Context, ip string, _ int32) bool {
			return ip == "10.10.0.1"
		}}
	t.Cleanup(func() {
		metrics.WebhookCircuitBroken.DeleteLabelValues(
			guardstate.KindMutating, "brownout", "hung.example.com")
		metrics.WebhookCircuitBroken.DeleteLabelValues(
			guardstate.KindMutating, "brownout", "ok.example.com")
	})

	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	// Stage 1 fired on first sight: the OLDEST Ready pod is gone,
	// its younger sibling survives.
	if _, err := cs.CoreV1().Pods("backend").Get(ctx, "wh-old",
		metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("oldest hung pod must be bounced, get err=%v", err)
	}
	if _, err := cs.CoreV1().Pods("backend").Get(ctx, "wh-new",
		metav1.GetOptions{}); err != nil {
		t.Fatalf("younger pod must survive the single-pod bounce: %v", err)
	}
	// Too early for the breaker — inside the 90s partition window.
	if got := wgMutatingFP(t, cs, "brownout", "hung.example.com"); got != admissionv1.Fail {
		t.Fatalf("unresponsive backend must not trip inside threshold, failurePolicy=%q", got)
	}

	// Past the threshold the breaker trips to Ignore.
	now = now.Add(PartitionedThreshold + time.Second)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if got := wgMutatingFP(t, cs, "brownout", "hung.example.com"); got != admissionv1.Ignore {
		t.Fatalf("unresponsive backend past threshold must trip to Ignore, got %q", got)
	}
	if got := wgMutatingFP(t, cs, "brownout", "ok.example.com"); got != admissionv1.Fail {
		t.Fatalf("responsive sibling must never trip, got %q", got)
	}
	// Bounce cooldown: the surviving pod is NOT deleted again.
	if _, err := cs.CoreV1().Pods("backend").Get(ctx, "wh-new",
		metav1.GetOptions{}); err != nil {
		t.Fatalf("15m bounce cooldown must protect the surviving pod: %v", err)
	}

	// The pod came back healthy — the next probe answers. The FIRST
	// responsive sweep only DEFERS (the recover-confirm gate — one
	// healthy sweep is not a recovery); the SECOND confirms the
	// declared Fail policy.
	g.EndpointProber = func(context.Context, string, int32) bool { return true }
	now = now.Add(time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if got := wgMutatingFP(t, cs, "brownout", "hung.example.com"); got != admissionv1.Ignore {
		t.Fatalf("first responsive sweep must defer the recover, got %q", got)
	}
	now = now.Add(time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if got := wgMutatingFP(t, cs, "brownout", "hung.example.com"); got != admissionv1.Fail {
		t.Fatalf("responsive backend must recover to Fail, got %q", got)
	}
}

// A PDB with disruptionsAllowed==0 refuses the bounce eviction (HTTP
// 429) — a DEFERRAL, not a failure: the hung pod stays, nothing is
// metered (no IncError) and bounceAt is NOT stamped, so the next
// sweep retries once disruptions free up instead of sitting out the
// 15m cooldown for a bounce that never landed.
func TestWebhookCircuitBreakerBouncePDBRefusalDefers(t *testing.T) {
	// ok-svc rides alongside so the probe census is NOT monitor-blind
	// (probeBlind) — the unresponsive verdict is the thing under test.
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "pdb-brownout"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "hung.example.com",
			FailurePolicy: new(admissionv1.Fail),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: wgSvcRef("backend", "hung-svc"),
			},
		}, {
			Name:          "ok.example.com",
			FailurePolicy: new(admissionv1.Fail),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: wgSvcRef("backend", "ok-svc"),
			},
		}},
	}
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("backend"),
		wgService("backend", "hung-svc"),
		wgHungSlice("backend", "hung-svc", "wh-old"),
		wgService("backend", "ok-svc"),
		wgEndpointSlice("backend", "ok-svc", 1, 0),
		wgPod("backend", "wh-old", 48*time.Hour),
		mwc)
	cs.PrependReactor("create", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			ca, ok := a.(ktesting.CreateAction)
			if !ok || ca.GetSubresource() != "eviction" {
				return false, nil, nil
			}
			return true, nil, apierrors.NewTooManyRequests(
				"pdb allows no disruptions", 0)
		})
	now := time.Unix(1_700_000_000, 0)
	b := &Breaker{}
	g := &guardstate.Guard{
		CS: cs, Dyn: wgDyn(),
		Queue: "webhook-guard", // the IncError label the assertion reads
		Now:   func() time.Time { return now },
		EndpointProber: func(_ context.Context, ip string, _ int32) bool {
			return ip == "10.10.0.1" // ok-svc answers; hung-svc wedged
		}}

	before := testutil.QueueErrorCount(t, "webhook-guard")
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.CoreV1().Pods("backend").Get(ctx, "wh-old",
		metav1.GetOptions{}); err != nil {
		t.Fatalf("PDB-refused pod was evicted anyway: %v", err)
	}
	if _, stamped := b.bounceAt.Last("backend/hung-svc"); stamped {
		t.Fatal("PDB refusal stamped bounceAt — deferral must not open the cooldown")
	}
	if got := testutil.QueueErrorCount(t, "webhook-guard") - before; got != 0 {
		t.Fatalf("PDB refusal metered as an error: delta = %v, want 0", got)
	}
}

// The refused bounce's budget grant comes back: the preamble and the
// eviction are ONE heal.EvictPodV call now, so a backend wedged
// behind a drained disruptionsAllowed cannot burn the fleet budget
// (10/5min) one grant per sweep and starve every other heal-gated
// module. The refused sweeps therefore keep reaching the eviction API
// (attempts advance every sweep — the pre-fix split shape deferred at
// the exhausted budget gate after the first refusal), and the grant a
// DELIVERED bounce consumes stays spent.
func TestWebhookCircuitBreakerRefusedBounceRefundsBudget(t *testing.T) {
	heal.ConfigureBudget(1, time.Hour)
	t.Cleanup(func() { heal.ConfigureBudget(0, 0) })
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "pdb-brownout"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "hung.example.com",
			FailurePolicy: new(admissionv1.Fail),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: wgSvcRef("backend", "hung-svc"),
			},
		}, {
			Name:          "ok.example.com",
			FailurePolicy: new(admissionv1.Fail),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: wgSvcRef("backend", "ok-svc"),
			},
		}},
	}
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("backend"),
		wgService("backend", "hung-svc"),
		wgHungSlice("backend", "hung-svc", "wh-old"),
		wgService("backend", "ok-svc"),
		wgEndpointSlice("backend", "ok-svc", 1, 0),
		wgPod("backend", "wh-old", 48*time.Hour),
		mwc)
	// The PDB stand-in flips to delivered on demand — the refusal
	// phase proves the refund, the delivery phase proves the granted
	//-and-kept accounting on the same budget.
	attempts := 0
	refuse := true
	cs.PrependReactor("create", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			ca, ok := a.(ktesting.CreateAction)
			if !ok || ca.GetSubresource() != "eviction" {
				return false, nil, nil
			}
			attempts++
			if refuse {
				return true, nil, apierrors.NewTooManyRequests(
					"pdb allows no disruptions", 0)
			}
			ev := ca.GetObject().(*policyv1.Eviction)
			return true, ev, cs.Tracker().Delete(
				corev1.SchemeGroupVersion.WithResource("pods"),
				ca.GetNamespace(), ev.Name)
		})
	now := time.Unix(1_700_000_000, 0)
	b := &Breaker{}
	g := &guardstate.Guard{
		CS: cs, Dyn: wgDyn(),
		Now: func() time.Time { return now },
		EndpointProber: func(_ context.Context, ip string, _ int32) bool {
			return ip == "10.10.0.1" // ok-svc answers; hung-svc wedged
		}}

	// Sweep 1: the bounce reaches the eviction API and is refused.
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 {
		t.Fatalf("first sweep attempts = %d, want 1", attempts)
	}
	// Sweep 2: the refund let the budget admit a fresh grant — the
	// eviction is attempted again (pre-fix the spent grant made this
	// sweep defer at the budget gate and attempts stayed 1).
	now = now.Add(time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("refused sweep must reach the eviction API again: attempts = %d, want 2", attempts)
	}
	if _, stamped := b.bounceAt.Last("backend/hung-svc"); stamped {
		t.Fatal("PDB refusal stamped bounceAt")
	}
	// Sweep 3: disruptions freed up — the bounce DELIVERS, consumes a
	// grant of its own and stamps the cooldown (delivered contract
	// unchanged by the refund wiring).
	refuse = false
	now = now.Add(time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 {
		t.Fatalf("delivery sweep attempts = %d, want 3", attempts)
	}
	if _, stamped := b.bounceAt.Last("backend/hung-svc"); !stamped {
		t.Fatal("delivered bounce did not stamp bounceAt")
	}
	if _, err := cs.CoreV1().Pods("backend").Get(ctx, "wh-old",
		metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("delivered bounce left the pod behind: %v", err)
	}
	// The delivered grant stays spent: a 1-grant budget has no room
	// left for another key, and the exhaustion counter says so.
	denials := 0
	heal.SetBudgetExhaustedHook(func() { denials++ })
	t.Cleanup(func() { heal.SetBudgetExhaustedHook(nil) })
	heal.AllowedV(ctx, logr.Discard(), nil, cs, wgDyn(), nil, "other-key",
		0, now.Add(time.Minute))
	if denials != 1 {
		t.Fatalf("delivered bounce kept no grant: denials = %d, want 1", denials)
	}
}

// A responsive backend never bounces and never trips — the probe's
// ANY-success verdict keeps one healthy replica honest even when a
// sibling hangs.
func TestWebhookCircuitBreakerResponsiveSkipsBounce(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "healthy-brownout"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "ok.example.com",
			FailurePolicy: new(admissionv1.Fail),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: wgSvcRef("backend", "ok-svc"),
			},
		}},
	}
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("backend"),
		wgService("backend", "ok-svc"),
		wgHungSlice("backend", "ok-svc", "ok-pod"),
		wgPod("backend", "ok-pod", 48*time.Hour),
		mwc)
	now := time.Unix(1_700_000_000, 0)
	b := &Breaker{}
	g := &guardstate.Guard{
		CS: cs, Dyn: wgDyn(),
		Now: func() time.Time { return now },
		EndpointProber: func(context.Context, string, int32) bool {
			return true // at least one endpoint answers
		}}
	for range 3 {
		if err := runBreaker(ctx, g, b); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := cs.CoreV1().Pods("backend").Get(ctx, "ok-pod",
		metav1.GetOptions{}); err != nil {
		t.Fatalf("responsive backend must never bounce its pod: %v", err)
	}
	if got := wgMutatingFP(t, cs, "healthy-brownout", "ok.example.com"); got != admissionv1.Fail {
		t.Fatalf("responsive backend must never trip, got %q", got)
	}
}

// probeBlind: when EVERY probed backend fails the handshake from this
// pod, the monitor — not the fleet — is the likely culprit
// (NetworkPolicy/CNI). The unresponsive verdict must not fire: no
// bounce (a healthy Ready pod must survive) and no trip, even well
// past the threshold.
func TestWebhookCircuitBreakerBlindMonitorDefers(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "blind-brownout"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "hung.example.com",
			FailurePolicy: new(admissionv1.Fail),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: wgSvcRef("backend", "hung-svc"),
			},
		}},
	}
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("backend"),
		wgService("backend", "hung-svc"),
		wgHungSlice("backend", "hung-svc", "wh-old"),
		wgPod("backend", "wh-old", 48*time.Hour),
		mwc)
	now := time.Unix(1_700_000_000, 0)
	b := &Breaker{}
	g := &guardstate.Guard{
		CS: cs, Dyn: wgDyn(),
		Now: func() time.Time { return now },
		EndpointProber: func(context.Context, string, int32) bool {
			return false // every probed IP fails — monitor-blind
		}}
	t.Cleanup(func() {
		metrics.WebhookCircuitBroken.DeleteLabelValues(
			guardstate.KindMutating, "blind-brownout", "hung.example.com")
	})
	// Stage 1 must defer: the Ready pod survives.
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.CoreV1().Pods("backend").Get(ctx, "wh-old",
		metav1.GetOptions{}); err != nil {
		t.Fatalf("blind monitor must not bounce a Ready pod: %v", err)
	}
	// Past the threshold the breaker must still not trip.
	now = now.Add(PartitionedThreshold + time.Minute)
	if err := runBreaker(ctx, g, b); err != nil {
		t.Fatal(err)
	}
	if got := wgMutatingFP(t, cs, "blind-brownout", "hung.example.com"); got != admissionv1.Fail {
		t.Fatalf("blind monitor must not trip, failurePolicy=%q", got)
	}
	if _, ok := wgMutatingAnno(t, cs, "blind-brownout"); ok {
		t.Fatal("blind monitor must not write the circuit-broken annotation")
	}
}

// probeBlind freezes recovery: a circuit-broken entry whose backend
// looks healthy in the endpoint census must NOT confirm while the
// handshake probes come back all-fail ("can't tell" holds the
// annotation). The moment one backend answers, the recover-confirm
// streak resumes and the entry restores Fail.
func TestWebhookCircuitBreakerBlindMonitorFreezesRecovery(t *testing.T) {
	mwc := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "blind-freeze",
			Annotations: map[string]string{
				guardstate.CircuitBrokenAnno: "frozen.example.com",
			},
		},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "frozen.example.com",
			FailurePolicy: new(admissionv1.Ignore),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: wgSvcRef("backend", "frozen-svc"),
			},
		}},
	}
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("backend"),
		wgService("backend", "frozen-svc"),
		wgHungSlice("backend", "frozen-svc", "frozen-pod"),
		mwc)
	now := time.Unix(1_700_000_000, 0)
	b := &Breaker{}
	g := &guardstate.Guard{
		CS: cs, Dyn: wgDyn(),
		Now: func() time.Time { return now },
		EndpointProber: func(context.Context, string, int32) bool {
			return false // blind — cannot verify the recovery
		}}
	t.Cleanup(func() {
		metrics.WebhookCircuitBroken.DeleteLabelValues(
			guardstate.KindMutating, "blind-freeze", "frozen.example.com")
	})
	// More than RecoverConfirmSweeps blind sweeps — the entry must
	// stay broken (Ignore re-asserted, annotation held).
	for range RecoverConfirmSweeps + 1 {
		now = now.Add(time.Minute)
		if err := runBreaker(ctx, g, b); err != nil {
			t.Fatal(err)
		}
	}
	if got := wgMutatingFP(t, cs, "blind-freeze", "frozen.example.com"); got != admissionv1.Ignore {
		t.Fatalf("blind sweeps must not recover the entry, got %q", got)
	}
	if anno, ok := wgMutatingAnno(t, cs, "blind-freeze"); !ok || anno != "frozen.example.com" {
		t.Fatalf("blind sweeps must hold the annotation, got %q present=%v", anno, ok)
	}
	// The monitor regains contrast — recovery confirms as usual.
	g.EndpointProber = func(context.Context, string, int32) bool { return true }
	for range RecoverConfirmSweeps {
		now = now.Add(time.Minute)
		if err := runBreaker(ctx, g, b); err != nil {
			t.Fatal(err)
		}
	}
	if got := wgMutatingFP(t, cs, "blind-freeze", "frozen.example.com"); got != admissionv1.Fail {
		t.Fatalf("recovered monitor must confirm the recover, got %q", got)
	}
}

// The kill-switch's RestoreOnly recovers already-tripped entries once
// their backend serves again — and never trips a NEW dead one: a
// dead-backend Fail policy stays Fail, unannotated, patch-free while
// levered off.
func TestWebhookBreakerRestoreOnlyRecoversButNeverTrips(t *testing.T) {
	recoverable := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "restore-recover",
			Annotations: map[string]string{
				guardstate.CircuitBrokenAnno: "was-broken.example.com",
			},
		},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "was-broken.example.com",
			FailurePolicy: new(admissionv1.Ignore),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: wgSvcRef("backend", "back-svc"),
			},
		}},
	}
	dead := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "restore-dead"},
		Webhooks: []admissionv1.MutatingWebhook{{
			Name:          "still-dead.example.com",
			FailurePolicy: new(admissionv1.Fail),
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: wgSvcRef("backend", "dead-svc"),
			},
		}},
	}
	cs := fake.NewSimpleClientset(
		wgNamespace("kube-system"), wgNamespace("backend"),
		wgService("backend", "back-svc"),
		wgEndpointSlice("backend", "back-svc", 1, 0),
		wgService("backend", "dead-svc"),
		wgEndpointSlice("backend", "dead-svc", 0, 1),
		recoverable, dead)
	patches := wgPatchCounter(cs)
	b := &Breaker{}
	g := &guardstate.Guard{
		CS: cs, Dyn: wgDyn(),
		// The prober answers so back-svc's census is responsive —
		// the recover must confirm (a nil prober reads as an
		// all-fail, monitor-blind sweep and would freeze it).
		EndpointProber: func(context.Context, string, int32) bool { return true },
	}
	t.Cleanup(func() {
		metrics.WebhookCircuitBroken.DeleteLabelValues(
			guardstate.KindMutating, "restore-recover", "was-broken.example.com")
		metrics.WebhookCircuitBroken.DeleteLabelValues(
			guardstate.KindMutating, "restore-dead", "still-dead.example.com")
	})
	// First sweep defers the recover (the confirm gate needs two
	// consecutive healthy sweeps), second confirms it.
	if err := b.RestoreOnly(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatal(err)
	}
	if got := wgMutatingFP(t, cs, "restore-recover", "was-broken.example.com"); got != admissionv1.Ignore {
		t.Fatalf("first restore sweep must defer the recover, got %q", got)
	}
	if err := b.RestoreOnly(ctx, g.TakeSnapshot(ctx)); err != nil {
		t.Fatal(err)
	}
	if got := wgMutatingFP(t, cs, "restore-recover", "was-broken.example.com"); got != admissionv1.Fail {
		t.Fatalf("kill-switched breaker must restore the recovered entry, got %q", got)
	}
	if _, ok := wgMutatingAnno(t, cs, "restore-recover"); ok {
		t.Fatal("restored entry's annotation must be dropped")
	}
	// The still-dead Fail policy must stay untouched — restore mode
	// never trips, never annotates, never patches it.
	if got := wgMutatingFP(t, cs, "restore-dead", "still-dead.example.com"); got != admissionv1.Fail {
		t.Fatalf("restore mode must never trip a dead backend, got %q", got)
	}
	if _, ok := wgMutatingAnno(t, cs, "restore-dead"); ok {
		t.Fatal("restore mode must not annotate a dead backend")
	}
	// Exactly one patch lands — the recover flip. The first sweep
	// defers without writing: the policy is already Ignore, so the
	// defer branch re-asserts nothing (payload nil → no patch call).
	if got := atomic.LoadInt32(patches); got != 1 {
		t.Fatalf("restore mode patch calls = %d, want exactly the recover flip", got)
	}
}
