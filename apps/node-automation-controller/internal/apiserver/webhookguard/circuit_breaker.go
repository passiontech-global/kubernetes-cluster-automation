// circuit_breaker.go — the C1 admission-webhook self-deadlock
// circuit breaker plus the W9-CP1 brownout probe/pod-bounce: the
// second of the three independent duties behind webhookGuard.run.
// The sweep trips fail-closed sub-webhooks whose backend Service has
// reported 0 effective Ready endpoints past the dead threshold to
// failurePolicy=Ignore, restores them on recovery, and bounces the
// oldest Ready backing pod of a TCP+TLS-unresponsive backend. Its
// state (dead-backend streaks, the broken-series ledger, bounce
// cooldowns, test-seam thresholds) lives on circuitBreaker; shared
// deps are reached through snap.g.
package webhookguard

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	// webhookDeadThreshold is how long a fail-closed sub-webhook's
	// backend Service must report 0 Ready endpoints before the breaker
	// trips it to Ignore.
	webhookDeadThreshold = 5 * time.Minute
	// webhookPartitionedThreshold is the faster trip window used when
	// the Service still reports Ready endpoints but EVERY one sits on
	// a partitioned/unresponsive node (W5.5): those pods cannot serve
	// the apiserver's webhook calls, so the deadlock is real now — 90s
	// of that condition is already an outage, no need to wait out the
	// full dead-backend window.
	webhookPartitionedThreshold = 90 * time.Second

	// W9-CP1 — Admission Webhook gray-failure TCP/TLS brownout
	// probe: a webhook backend whose EndpointSlice still reports
	// Ready endpoints on healthy nodes but whose pods all fail the
	// TCP+TLS handshake is hung, not partitioned. The breaker treats
	// it as effective=0 (90s partition threshold), and stage 1 bounces
	// the oldest Ready backing pod — one bounce per service per
	// webhookBounceCooldown so a wedged pod cannot be restarted every
	// sweep.
	webhookBounceCooldown   = 15 * time.Minute
	webhookProbeMaxPerSvc   = 2  // endpoint IPs dialed per service
	webhookProbeMaxPodRefs  = 32 // backing-pod candidates kept per service
	webhookProbeDefaultPort = 443
)

// ---------------------------------------------------------------------------
// C1 — admission webhook self-deadlock circuit breaker.
// ---------------------------------------------------------------------------

// circuitBreakerEnabled reads the kill-switch every run — an env flip
// takes effect on the next sweep without a code change.
func circuitBreakerEnabled() bool {
	return envx.Gate("WEBHOOK_CIRCUIT_BREAKER_ENABLED", true)
}

// circuitBreaker owns the C1 sweep's per-sweep state — embedded in
// webhookGuard so the facade's method set (and every in-package test
// fixture built on it) is unchanged by the split. Shared deps
// (cs/dyn/now/endpointProber) are reached through snap.g; only the
// breaker-specific ledgers and cooldowns live here.
type circuitBreaker struct {
	// deadSince is the first-seen ledger of each
	// kind/config/sub-webhook sighted fail-closed against a Service
	// with 0 Ready endpoints. A sighting that disappears (endpoints
	// back, entry removed) resets the streak.
	deadSince state.FirstSeenLedger
	// brokenEmitted is the ledger of WebhookCircuitBroken label tuples
	// ("kind/config/webhook") currently held at =1. Each sweep
	// re-asserts the triples still broken; a tuple not re-seen —
	// config deleted, recreated without the annotation, entry pruned
	// by the orphan sweep — gets its series deleted via
	// DeleteLabelValues instead of pinning the alert forever (same
	// seen-set hygiene as the cert drift auditor).
	brokenEmitted state.GaugeLedger[string]
	// zeroThreshold / partitionZeroThreshold override the two trip
	// windows — tests shrink them; a zero value falls back to
	// webhookDeadThreshold / webhookPartitionedThreshold.
	zeroThreshold          time.Duration
	partitionZeroThreshold time.Duration
	// bounceAt: webhook backend service key ("ns/name") → last pod
	// bounce — the in-memory half of the 15m per-service cooldown.
	bounceAt state.CooldownSet
}

// sweepCircuitBreaker trips fail-closed sub-webhooks whose backend
// Service has reported 0 Ready endpoints continuously for
// webhookDeadThreshold, and restores previously tripped entries once
// the Service has endpoints again. It runs after the orphan sweep so
// it always evaluates post-prune state; a patch failure on one config
// is logged and the sweep continues with the rest.
func (b *circuitBreaker) sweepCircuitBreaker(ctx context.Context, snap *sweepSnapshot) error {
	g := snap.g
	log := logf.FromContext(ctx)
	now := g.now.Now()

	ready, err := snap.readyCounts()
	if err != nil {
		return err
	}
	if snap.mwcErr != nil {
		return fmt.Errorf("list mutatingwebhookconfigurations — circuit breaker skipped: %w", snap.mwcErr)
	}
	if snap.vwcErr != nil {
		return fmt.Errorf("list validatingwebhookconfigurations — circuit breaker skipped: %w", snap.vwcErr)
	}
	mwcs, vwcs := snap.mwc, snap.vwc

	// seen marks the deadSince keys still under evaluation — streaks
	// for entries gone since the last sweep are pruned below.
	seen := map[string]bool{}
	var failed []string
	for i := range mwcs.Items {
		cfg := &mwcs.Items[i]
		payload, trips, recovered := b.circuitPatch(log, g.queue, webhookKindMutating,
			cfg.Name, cfg.Annotations[webhookCircuitAnno],
			mutHookViews(cfg.Webhooks), ready, now, seen, &b.brokenEmitted)
		if payload == nil {
			continue
		}
		if _, err := g.cs.AdmissionregistrationV1().MutatingWebhookConfigurations().
			Patch(ctx, cfg.Name, types.StrategicMergePatchType, payload, metav1.PatchOptions{}); err != nil {
			log.Error(err, "circuit breaker patch failed",
				"kind", webhookKindMutating, "config", cfg.Name)
			failed = append(failed, cfg.Name)
			continue
		}
		circuitMetrics(&b.brokenEmitted, webhookKindMutating, cfg.Name, trips, recovered)
	}
	for i := range vwcs.Items {
		cfg := &vwcs.Items[i]
		payload, trips, recovered := b.circuitPatch(log, g.queue, webhookKindValidating,
			cfg.Name, cfg.Annotations[webhookCircuitAnno],
			valHookViews(cfg.Webhooks), ready, now, seen, &b.brokenEmitted)
		if payload == nil {
			continue
		}
		if _, err := g.cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().
			Patch(ctx, cfg.Name, types.StrategicMergePatchType, payload, metav1.PatchOptions{}); err != nil {
			log.Error(err, "circuit breaker patch failed",
				"kind", webhookKindValidating, "config", cfg.Name)
			failed = append(failed, cfg.Name)
			continue
		}
		circuitMetrics(&b.brokenEmitted, webhookKindValidating, cfg.Name, trips, recovered)
	}

	// W9-CP1 stage 1 — rolling pod bounce: a webhook backend whose
	// Ready endpoints ALL fail the TCP+TLS handshake has a hung pod,
	// not a partitioned one. Bounce the oldest Ready backing pod so
	// its controller recreates it fresh — this runs even while the
	// breaker holds the entry open, because a pod that never comes
	// back would keep the webhook circuit-broken forever.
	b.bounceHungWebhookPods(ctx, snap, ready)

	// Prune broken series whose label tuple was not re-seen — a config
	// deleted while broken, recreated without the annotation, or an
	// entry removed must not pin circuit_broken=1 forever.
	b.brokenEmitted.Prune(metrics.WebhookCircuitBroken.DeleteLabelValues)

	// Same prune for the dead-backend streaks: keys not re-evaluated
	// this sweep (Service recovered, entry flipped to Ignore) re-arm
	// their window.
	b.deadSince.Prune(func(k string) bool { return seen[k] })
	if len(failed) > 0 {
		return fmt.Errorf("circuit breaker patches failed for: %s",
			strings.Join(failed, ", "))
	}
	return nil
}

// hookView is the breaker's uniform projection over MutatingWebhook /
// ValidatingWebhook — identical relevant fields, distinct Go types.
type hookView struct {
	name string
	fp   *admissionv1.FailurePolicyType
	svc  *admissionv1.ServiceReference
}

func mutHookViews(ws []admissionv1.MutatingWebhook) []hookView {
	out := make([]hookView, len(ws))
	for i := range ws {
		out[i] = hookView{
			name: ws[i].Name, fp: ws[i].FailurePolicy,
			svc: ws[i].ClientConfig.Service,
		}
	}
	return out
}

func valHookViews(ws []admissionv1.ValidatingWebhook) []hookView {
	out := make([]hookView, len(ws))
	for i := range ws {
		out[i] = hookView{
			name: ws[i].Name, fp: ws[i].FailurePolicy,
			svc: ws[i].ClientConfig.Service,
		}
	}
	return out
}

// tripThreshold picks the dead-backend streak window for this webhook:
// when the Service still reports Ready endpoints but every one sits on
// a partitioned/unresponsive node (raw > 0, effective == 0) the
// deadlock is already real — the shorter partition threshold applies;
// a genuinely empty backend keeps the full dead threshold. The fields
// are test seams; zero values fall back to the package defaults.
func (b *circuitBreaker) tripThreshold(rawReady int) time.Duration {
	if rawReady > 0 {
		if b.partitionZeroThreshold > 0 {
			return b.partitionZeroThreshold
		}
		return webhookPartitionedThreshold
	}
	if b.zeroThreshold > 0 {
		return b.zeroThreshold
	}
	return webhookDeadThreshold
}

// circuitPatch evaluates one config's sub-webhooks against the ready
// census and builds the strategic-merge patch that flips long-dead
// entries to Ignore, restores recovered ones to Fail and rewrites the
// circuit-broken annotation (merge-patch null removes the key when the
// set empties). hooks views the config's live webhook list; each
// changed entry lands in the patch as {"name": X, "failurePolicy":
// ...} — the webhooks list is patchMergeKey=name + patchStrategy=merge
// (+listType=map), so only the touched element's failurePolicy is
// rewritten and a concurrent writer's sibling entries survive instead
// of being reverted by a whole-array reserialize. emitted is the
// sweep's WebhookCircuitBroken series ledger — tuples re-asserted at
// =1 are Emitted into it so the caller's Prune deletes whatever was
// not re-seen. Returns nil payload when nothing changed;
// trips/recovered are the names whose metric updates the caller must
// apply only after the patch lands.
func (b *circuitBreaker) circuitPatch(log logr.Logger, queue, kind, cfgName, annoVal string,
	hooks []hookView, ready endpointCensus, now time.Time,
	seen map[string]bool, emitted *state.GaugeLedger[string]) ([]byte, []string, []string) {

	broken := parseCircuitAnnotation(annoVal)
	// present holds every live sub-webhook name — the staleness check
	// below compares the annotation against it (a freshly tripped name
	// is present even though it was not in the annotation yet).
	present := map[string]bool{}
	// hookMerges collects the strategic-merge entries for every
	// failurePolicy flip — one {"name": X, "failurePolicy": ...} map
	// per touched sub-webhook (each hook is visited once, so a plain
	// append cannot duplicate a merge key).
	var hookMerges []map[string]any
	flip := func(h hookView, fp admissionv1.FailurePolicyType) {
		hookMerges = append(hookMerges, map[string]any{
			"name": h.name, "failurePolicy": string(fp)})
	}
	changed := false
	var trips, recovered []string

	for _, h := range hooks {
		present[h.name] = true
		key := kind + "/" + cfgName + "/" + h.name
		isBroken := broken[h.name]
		// svcEffective < 0 marks "not Service-backed" — URL webhooks
		// and malformed refs are unmeasurable, the breaker never
		// trips them. effective excludes Ready endpoints sitting on
		// partitioned/unresponsive nodes (W5.5); raw keeps them for
		// the threshold pick.
		svcEffective, svcRaw := -1, -1
		svc := ""
		// unresponsive is the W9-CP1 brownout verdict: the Service
		// reports Ready endpoints on healthy nodes but EVERY probed
		// endpoint IP failed the TCP+TLS handshake — the pods are
		// hung, which is as dead for admission as a partition. It is
		// only ever true when svcEffective > 0 (effective==0 is
		// already covered by the W5.5 path) and the service was
		// actually probed this run.
		unresponsive := false
		if h.svc != nil && h.svc.Namespace != "" && h.svc.Name != "" {
			svc = h.svc.Namespace + "/" + h.svc.Name
			svcEffective = ready.effective[svc]
			svcRaw = ready.raw[svc]
			unresponsive = svcEffective > 0 &&
				ready.probed[svc] && !ready.responsive[svc]
		}
		switch {
		case isBroken && svcEffective != 0 && !unresponsive:
			// RECOVER — the Service has >= 1 reachable Ready endpoint
			// again, or the entry was repointed off its Service
			// entirely (svcEffective < 0): the breaker cannot measure
			// a URL, so it hands back the declared Fail and steps
			// out. Endpoints on partitioned nodes do NOT count —
			// they still fail every apiserver call — and neither do
			// endpoints whose pods are still failing the handshake
			// (W9-CP1): "Ready" in the EndpointSlice is not "serving".
			flip(h, admissionv1.Fail)
			delete(broken, h.name)
			recovered = append(recovered, h.name)
			changed = true
			log.Info("CIRCUIT-RECOVER: restoring failurePolicy=Fail",
				"kind", kind, "config", cfgName, "webhook", h.name,
				"service", svcRefString(h.svc))
		case isBroken:
			// Still dead — the annotation is the SSOT, so re-assert
			// Ignore if the policy was flipped back externally.
			if h.fp == nil || *h.fp != admissionv1.Ignore {
				flip(h, admissionv1.Ignore)
				changed = true
			}
			metrics.WebhookCircuitBroken.WithLabelValues(kind, cfgName, h.name).Set(1)
			emitted.Emit(key, kind, cfgName, h.name)
		case (svcEffective == 0 || unresponsive) && failClosed(h.fp):
			seen[key] = true
			first, tracked := b.deadSince.Observe(key, now)
			if !tracked {
				log.Info("circuit breaker: fail-closed webhook on a dead Service — tracking",
					"kind", kind, "config", cfgName, "webhook", h.name,
					"service", svc, "rawReady", svcRaw)
				continue
			}
			threshold := b.tripThreshold(svcRaw)
			if now.Sub(first) < threshold {
				continue
			}
			// TRIP — dead backend past the threshold. deadSince is
			// deliberately NOT cleared here: if the patch fails the
			// annotation never lands, so keeping the streak lets the
			// next sweep retry immediately instead of re-opening a
			// fresh window. Once the entry is broken it no longer
			// marks seen[key], so the ledger prunes itself.
			flip(h, admissionv1.Ignore)
			broken[h.name] = true
			trips = append(trips, h.name)
			changed = true
			switch {
			case unresponsive:
				// W9-CP1 — every probed Ready endpoint failed the
				// TCP+TLS handshake: hung pods, not a partition.
				// svcRaw > 0 keeps the 90s partition threshold.
				log.Info("CIRCUIT-TRIP: unresponsive — all probed ready endpoints fail TCP+TLS handshake — patching failurePolicy=Ignore",
					"kind", kind, "config", cfgName, "webhook", h.name,
					"service", svc, "threshold", threshold)
			case svcRaw > 0:
				log.Info("CIRCUIT-TRIP: all ready endpoints on partitioned/unresponsive nodes — patching failurePolicy=Ignore",
					"kind", kind, "config", cfgName, "webhook", h.name,
					"service", svc, "rawReady", svcRaw, "threshold", threshold)
			default:
				log.Info("CIRCUIT-TRIP: 0 ready endpoints — patching failurePolicy=Ignore",
					"kind", kind, "config", cfgName, "webhook", h.name,
					"service", svc, "threshold", threshold)
			}
		}
	}

	// Stale annotation names (the sub-webhook itself is gone — e.g.
	// removed by the orphan sweep) drop out so the record stays exact.
	for name := range broken {
		if !present[name] {
			delete(broken, name)
			metrics.WebhookCircuitBroken.DeleteLabelValues(kind, cfgName, name)
			changed = true
			log.Info("CIRCUIT-CLEAN: annotation entry has no live webhook — dropping",
				"kind", kind, "config", cfgName, "webhook", name)
		}
	}
	if !changed {
		return nil, nil, nil
	}

	anno := map[string]any{webhookCircuitAnno: nil} // merge-patch null deletes the key
	if len(broken) > 0 {
		anno[webhookCircuitAnno] = strings.Join(slices.Sorted(maps.Keys(broken)), ",")
	}
	doc := map[string]any{
		"metadata": map[string]any{"annotations": anno},
	}
	if len(hookMerges) > 0 {
		doc["webhooks"] = hookMerges
	}
	payload, err := json.Marshal(doc)
	if err != nil {
		// Absorbed sub-failure: the sweep logs and continues —
		// metered so the dropped work is still counted.
		metrics.IncError(queue)
		log.Error(err, "marshal circuit breaker patch", "config", cfgName)
		return nil, nil, nil
	}
	return payload, trips, recovered
}

// failClosed reports whether the entry currently fails closed. A nil
// failurePolicy defaults to Fail server-side; anything not explicitly
// Ignore is treated as fail-closed.
func failClosed(fp *admissionv1.FailurePolicyType) bool {
	return fp == nil || *fp != admissionv1.Ignore
}

// svcRefString renders a webhook's Service reference for log lines.
func svcRefString(ref *admissionv1.ServiceReference) string {
	if ref == nil || ref.Namespace == "" || ref.Name == "" {
		return "<none>"
	}
	return ref.Namespace + "/" + ref.Name
}
