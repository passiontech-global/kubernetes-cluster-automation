// circuit_breaker.go — the C1 admission-webhook self-deadlock
// circuit breaker core: Breaker owns the sweep's persisted state
// (dead-backend streaks, the broken-series ledger, bounce
// cooldowns, test-seam thresholds) and Sweep is the per-sweep entry
// the facade calls — it runs every webhook config through
// circuitPatch (circuit_patch.go), lands the strategic-merge
// patches, invokes the W9-CP1 pod bounce (pod_bounce.go) and prunes
// the emitted series. The trip thresholds, the hot-reloaded
// Enabled() ops lever and the hookView projection shared with
// pod_bounce.go live here too; the CRD conversion-backend duty
// moved to crd_conversion.go.
package circuitbreaker

import (
	"context"
	"fmt"
	"strings"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	// DeadThreshold is how long a fail-closed sub-webhook's
	// backend Service must report 0 Ready endpoints before the breaker
	// trips it to Ignore.
	DeadThreshold = 5 * time.Minute
	// PartitionedThreshold is the faster trip window used when
	// the Service still reports Ready endpoints but EVERY one sits on
	// a partitioned/unresponsive node (W5.5): those pods cannot serve
	// the apiserver's webhook calls, so the deadlock is real now — 90s
	// of that condition is already an outage, no need to wait out the
	// full dead-backend window.
	PartitionedThreshold = 90 * time.Second

	// W9-CP1 — one pod bounce per service per BounceCooldown so a
	// wedged pod cannot be restarted every sweep; admission and
	// conversion backends share the ledger on purpose: one hung
	// Service is one bounce per cooldown regardless of which duty
	// noticed it.
	BounceCooldown = 15 * time.Minute
)

// ---------------------------------------------------------------------------
// C1 — admission webhook self-deadlock circuit breaker.
// ---------------------------------------------------------------------------

// Enabled reads the kill-switch EVERY run — the
// sanctioned exception to the resolve-at-Setup rule: the breaker is
// an ops lever that must stay flippable mid-incident, so an env flip
// takes effect on the next sweep without an operator restart (the
// same deliberate hot reload the unmeshed remediation lever carries).
func Enabled() bool {
	return envx.Gate("WEBHOOK_CIRCUIT_BREAKER_ENABLED", true)
}

// Breaker owns the circuit-breaker sweep's per-sweep state — the
// facade holds one across runs so the ledgers and cooldowns persist.
// Shared deps (CS/Dyn/Now/EndpointProber/Verdict) are reached through
// snap.G; only the breaker-specific ledgers and cooldowns live here.
type Breaker struct {
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
	// DeadThreshold / PartitionedThreshold.
	zeroThreshold          time.Duration
	partitionZeroThreshold time.Duration
	// bounceAt: webhook backend service key ("ns/name") → last pod
	// bounce — the in-memory half of the BounceCooldown per-service
	// cooldown. Admission and conversion backends share the ledger on
	// purpose: one hung Service is one bounce per cooldown regardless
	// of which duty noticed it.
	bounceAt state.CooldownSet
	// crdUnhealthyEmitted is the same GaugeLedger hygiene for
	// CRDConversionWebhookUnhealthy — tuples re-asserted each sweep,
	// stale ones (CRD gone, backend healthy, reason changed) pruned
	// via DeleteLabelValues.
	crdUnhealthyEmitted state.GaugeLedger[crdConversionKey]
}

// Sweep trips fail-closed sub-webhooks whose backend
// Service has reported 0 Ready endpoints continuously for
// DeadThreshold, and restores previously tripped entries once
// the Service has endpoints again. It runs after the orphan sweep so
// it always evaluates post-prune state; a patch failure on one config
// is logged and the sweep continues with the rest.
func (b *Breaker) Sweep(ctx context.Context, snap *guardstate.Snapshot) error {
	b.brokenEmitted.Begin() // drop any aborted sweep's leftover emissions
	g := snap.G
	log := logf.FromContext(ctx)
	now := g.Now.Now()
	// bounceAt keys on backend Service names that die with the
	// Service — bound the map so stale stamps cannot accumulate.
	b.bounceAt.PruneExpired(now, BounceCooldown)

	ready, err := snap.ReadyCounts()
	if err != nil {
		return err
	}
	if snap.MWCErr != nil {
		return fmt.Errorf("list mutatingwebhookconfigurations — circuit breaker skipped: %w", snap.MWCErr)
	}
	if snap.VWCErr != nil {
		return fmt.Errorf("list validatingwebhookconfigurations — circuit breaker skipped: %w", snap.VWCErr)
	}
	mwcs, vwcs := snap.MWC, snap.VWC

	// seen marks the deadSince keys still under evaluation — streaks
	// for entries gone since the last sweep are pruned below.
	seen := map[string]bool{}
	var failed []string
	for i := range mwcs.Items {
		cfg := &mwcs.Items[i]
		payload, trips, recovered, stillBroken := b.circuitPatch(log, g.Queue,
			guardstate.KindMutating, cfg.Name,
			cfg.Annotations[guardstate.CircuitBrokenAnno],
			mutHookViews(cfg.Webhooks), ready, now, seen)
		if payload == nil {
			// Nothing to write — the still-broken re-asserts read
			// verified live state (the annotation already lists
			// them, the policy is already Ignore), so the series
			// emits without a landed patch.
			circuitMetrics(&b.brokenEmitted, guardstate.KindMutating,
				cfg.Name, nil, nil, stillBroken)
			continue
		}
		patched, err := g.CS.AdmissionregistrationV1().MutatingWebhookConfigurations().
			Patch(ctx, cfg.Name, types.StrategicMergePatchType, payload, metav1.PatchOptions{})
		if err != nil {
			// The post-patch annotation state is unverifiable —
			// carry the config's last-emitted tuples forward so
			// the sweep-end prune does not flap a still-broken
			// series off (the annotation may well still list it).
			b.carryBrokenForward(guardstate.KindMutating, cfg.Name)
			log.Error(err, "circuit breaker patch failed",
				"kind", guardstate.KindMutating, "config", cfg.Name)
			failed = append(failed, cfg.Name)
			continue
		}
		// Write the landed object back into the shared snapshot —
		// the unmeshed audit's injector-health read must see the
		// new failurePolicy/annotation state, not the stale list.
		snap.SetMWC(patched)
		circuitMetrics(&b.brokenEmitted, guardstate.KindMutating,
			cfg.Name, trips, recovered, stillBroken)
	}
	for i := range vwcs.Items {
		cfg := &vwcs.Items[i]
		payload, trips, recovered, stillBroken := b.circuitPatch(log, g.Queue,
			guardstate.KindValidating, cfg.Name,
			cfg.Annotations[guardstate.CircuitBrokenAnno],
			valHookViews(cfg.Webhooks), ready, now, seen)
		if payload == nil {
			circuitMetrics(&b.brokenEmitted, guardstate.KindValidating,
				cfg.Name, nil, nil, stillBroken)
			continue
		}
		patched, err := g.CS.AdmissionregistrationV1().ValidatingWebhookConfigurations().
			Patch(ctx, cfg.Name, types.StrategicMergePatchType, payload, metav1.PatchOptions{})
		if err != nil {
			b.carryBrokenForward(guardstate.KindValidating, cfg.Name)
			log.Error(err, "circuit breaker patch failed",
				"kind", guardstate.KindValidating, "config", cfg.Name)
			failed = append(failed, cfg.Name)
			continue
		}
		snap.SetVWC(patched)
		circuitMetrics(&b.brokenEmitted, guardstate.KindValidating,
			cfg.Name, trips, recovered, stillBroken)
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
