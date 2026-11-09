// circuit_breaker.go — the C1 admission-webhook self-deadlock
// circuit breaker core: Breaker owns the sweep's persisted state
// (dead-backend streaks, the broken-series ledger, bounce
// cooldowns, test-seam thresholds) and Sweep is the per-sweep entry
// the facade calls — it runs every webhook config through
// circuitPatch (circuit_patch.go), lands the strategic-merge
// patches, invokes the circuit-breaker-bounce pod bounce (pod_bounce.go) and prunes
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
	// a partitioned/unresponsive node (endpoint-census): those pods cannot serve
	// the apiserver's webhook calls, so the deadlock is real now — 90s
	// of that condition is already an outage, no need to wait out the
	// full dead-backend window.
	PartitionedThreshold = 90 * time.Second

	// circuit-breaker-bounce — one pod bounce per service per BounceCooldown so a
	// wedged pod cannot be restarted every sweep; admission and
	// conversion backends share the ledger on purpose: one hung
	// Service is one bounce per cooldown regardless of which duty
	// noticed it.
	BounceCooldown = 15 * time.Minute

	// RecoverConfirmSweeps is how many CONSECUTIVE healthy sweeps an
	// annotation-broken entry needs before its recover patch fires.
	// ONE healthy sweep is not a recovery: a backend flapping
	// 0↔1 Ready endpoint would trip and recover in alternating
	// sweeps, patching the WebhookConfiguration twice a cycle. The
	// annotation stays the SSOT for "broken" — the gate only delays
	// the Fail restore.
	RecoverConfirmSweeps = 2
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
	// seen-set hygiene as the cert drift auditor). A failed patch's
	// carry-forward re-asserts only the sub-webhooks still in the
	// config's snapshot views, so a webhook deleted from the config
	// is forgotten too instead of being carried past its death.
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
	// recoverStreak counts, per kind/config/sub-webhook key, how
	// many consecutive healthy sweeps a broken entry has served —
	// the recover-confirm gate of RecoverConfirmSweeps. Hit in the
	// healthy branch (alongside its recoverSeen mark), Reset on
	// every disproving path (still-dead sweep, confirmed recover),
	// pruned at sweep end for keys no longer under evaluation so a
	// webhook removed from its config cannot inherit a stale streak
	// when it reappears. In-RAM only: an operator restart restarts
	// confirmation from one sweep — acceptable, the annotation
	// still holds the entry broken meanwhile.
	recoverStreak state.StreakLedger
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

	// seen marks the deadSince keys still under evaluation — streaks
	// for entries gone since the last sweep are pruned below.
	seen := map[string]bool{}
	// recoverSeen marks the recover-confirmation streaks Hit this
	// sweep — the prune's keep set (Hit and defer land together, so
	// every live streak key appears here each sweep).
	recoverSeen := map[string]bool{}
	// The two streak ledgers prune on EVERY cycle — declared up front
	// so the defers also fire on the census/config-list failures that
	// early-return below: a sweep that lost its inputs must not leave
	// streaks pinned to entries it can no longer evaluate. An empty
	// keep-set wipes the streaks, which only ever DELAYS a
	// trip/recover — the conservative direction. brokenEmitted's
	// prune is deliberately NOT deferred: its Begin/Prune pairing IS
	// the carry-forward contract — an aborted sweep re-asserts
	// nothing, so pruning it would flap live circuit_broken=1 series
	// off during an API outage.
	defer b.deadSince.Prune(func(k string) bool { return seen[k] })
	defer b.recoverStreak.Prune(func(k string) bool { return recoverSeen[k] })

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

	var failed []string

	// cfgJob is one webhook configuration's per-sweep work: the
	// kind-independent fields the breaker evaluates plus the
	// kind-specific patch-and-refresh closure (the only true MWC/VWC
	// difference — the evaluation loop below is shared by both kinds,
	// so a kind-specific edit lands in exactly one place).
	type cfgJob struct {
		kind  string
		name  string
		anno  string
		views []hookView
		patch func(context.Context, []byte) error
	}
	patchMutating := func(cfg *admissionv1.MutatingWebhookConfiguration) func(context.Context, []byte) error {
		return func(ctx context.Context, payload []byte) error {
			patched, err := g.CS.AdmissionregistrationV1().MutatingWebhookConfigurations().
				Patch(ctx, cfg.Name, types.StrategicMergePatchType, payload, metav1.PatchOptions{})
			if err != nil {
				return err
			}
			snap.SetMWC(patched)
			return nil
		}
	}
	patchValidating := func(cfg *admissionv1.ValidatingWebhookConfiguration) func(context.Context, []byte) error {
		return func(ctx context.Context, payload []byte) error {
			patched, err := g.CS.AdmissionregistrationV1().ValidatingWebhookConfigurations().
				Patch(ctx, cfg.Name, types.StrategicMergePatchType, payload, metav1.PatchOptions{})
			if err != nil {
				return err
			}
			snap.SetVWC(patched)
			return nil
		}
	}
	jobs := make([]cfgJob, 0, len(mwcs.Items)+len(vwcs.Items))
	for i := range mwcs.Items {
		cfg := &mwcs.Items[i]
		jobs = append(jobs, cfgJob{
			kind: guardstate.KindMutating, name: cfg.Name,
			anno:  cfg.Annotations[guardstate.CircuitBrokenAnno],
			views: mutHookViews(cfg.Webhooks), patch: patchMutating(cfg),
		})
	}
	for i := range vwcs.Items {
		cfg := &vwcs.Items[i]
		jobs = append(jobs, cfgJob{
			kind: guardstate.KindValidating, name: cfg.Name,
			anno:  cfg.Annotations[guardstate.CircuitBrokenAnno],
			views: valHookViews(cfg.Webhooks), patch: patchValidating(cfg),
		})
	}
	for _, job := range jobs {
		payload, trips, recovered, stillBroken, dropped := b.circuitPatch(log, g.Queue,
			job.kind, job.name, job.anno, job.views, ready, now, seen, recoverSeen)
		if payload == nil {
			// Nothing to write — the still-broken re-asserts read
			// verified live state (the annotation already lists
			// them, the policy is already Ignore), so the series
			// emits without a landed patch.
			circuitMetrics(&b.brokenEmitted, job.kind, job.name, nil, nil, stillBroken)
			continue
		}
		if err := job.patch(ctx, payload); err != nil {
			// The post-patch annotation state is unverifiable —
			// carry the config's last-emitted tuples forward so
			// the sweep-end prune does not flap a still-broken
			// series off (the annotation may well still list it).
			// Liveness-aware: a tuple whose sub-webhook is no
			// longer in the config's snapshot views is not
			// carried, so the sweep-end prune forgets its series
			// instead of re-pinning it while patches keep failing.
			b.carryBrokenForward(job.kind, job.name, job.views)
			log.Error(err, "circuit breaker patch failed",
				"kind", job.kind, "config", job.name)
			failed = append(failed, job.name)
			continue
		}
		// The patch landed — the stale-annotation drops are durable,
		// so their series are released only here (a failed patch
		// keeps the annotation, the SSOT, listing those names).
		for _, name := range dropped {
			metrics.WebhookCircuitBroken.DeleteLabelValues(job.kind, job.name, name)
		}
		circuitMetrics(&b.brokenEmitted, job.kind, job.name, trips, recovered, stillBroken)
	}

	// circuit-breaker-bounce stage 1 — rolling pod bounce: a webhook backend whose
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

	// The deadSince and recoverStreak prunes run via defer (declared
	// beside their keep-sets above) so they fire on every cycle,
	// including the early-return census failures.
	if len(failed) > 0 {
		return fmt.Errorf("circuit breaker patches failed for: %s",
			strings.Join(failed, ", "))
	}
	return nil
}

// markHealthyStreak advances key's consecutive-healthy-sweep count
// and returns it — the recover-confirm gate compares the return
// against RecoverConfirmSweeps.
func (b *Breaker) markHealthyStreak(key string) int {
	return b.recoverStreak.Hit(key)
}

// clearHealthyStreak drops key's healthy streak — the streak is
// CONSECUTIVE, so any disproving sweep (backend dead again, recover
// confirmed) re-arms the gate from zero.
func (b *Breaker) clearHealthyStreak(key string) {
	b.recoverStreak.Reset(key)
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

// allHookViews projects the snapshot's mutating then validating
// configs — one pass over both kinds for consumers that read the same
// fields off every webhook (the pod-bounce key collector). A nil
// webhook-config list (its list failed) contributes nothing.
func allHookViews(snap *guardstate.Snapshot) [][]hookView {
	var out [][]hookView
	if snap.MWC != nil {
		for i := range snap.MWC.Items {
			out = append(out, mutHookViews(snap.MWC.Items[i].Webhooks))
		}
	}
	if snap.VWC != nil {
		for i := range snap.VWC.Items {
			out = append(out, valHookViews(snap.VWC.Items[i].Webhooks))
		}
	}
	return out
}
