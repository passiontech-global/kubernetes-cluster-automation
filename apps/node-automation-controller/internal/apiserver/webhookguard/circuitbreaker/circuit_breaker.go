// circuit_breaker.go — the C1 admission-webhook self-deadlock
// circuit breaker plus the W9-CP1 brownout probe/pod-bounce and the
// CRD conversion-webhook backend health check: the sweep trips
// fail-closed sub-webhooks whose backend Service has reported 0
// effective Ready endpoints past the dead threshold to
// failurePolicy=Ignore, restores them on recovery, bounces the
// oldest Ready backing pod of a TCP+TLS-unresponsive backend, and
// exports node_automation_crd_conversion_webhook_unhealthy for CRDs
// whose conversion webhook backend is measurably broken. Its state
// (dead-backend streaks, the broken-series ledger, bounce cooldowns,
// test-seam thresholds) lives on Breaker; shared deps are reached
// through snap.G.
package circuitbreaker

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
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
// CRD conversion-webhook backend health — the same dead-backend
// failure modes the breaker covers for admission webhooks, but with
// no failurePolicy knob at all: a dead conversion backend errors
// every CR read for the whole API group.
// ---------------------------------------------------------------------------

// CRDReason* are the reason label values of
// CRDConversionWebhookUnhealthy — the three measurable dead-backend
// signatures.
const (
	// CRDReasonMissingService: the conversion clientConfig points at
	// a Service that does not exist.
	CRDReasonMissingService = "missing_service"
	// CRDReasonZeroEndpoints: the Service exists but the endpoint
	// census reports 0 effective-Ready endpoints (endpoints on
	// partitioned nodes count as dead, same as the breaker's math).
	CRDReasonZeroEndpoints = "zero_endpoints"
	// CRDReasonTLSProbeFailed: Ready endpoints exist but EVERY probed
	// IP failed the TCP+TLS handshake — wedged pods, which the sweep
	// bounces.
	CRDReasonTLSProbeFailed = "tls_probe_failed"
)

// CRDConversionWebhookUnhealthy marks (1) each CustomResourceDefinition
// whose spec.conversion webhook backend is measurably broken — a
// single-check series, so it lives here (colocated var + init)
// instead of internal/metrics. reason carries the verdict
// (missing_service|zero_endpoints|tls_probe_failed); the series
// disappears once the backend is healthy again.
var CRDConversionWebhookUnhealthy = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_crd_conversion_webhook_unhealthy",
	Help: "1 while the CRD's spec.conversion webhook backend is unhealthy (missing_service|zero_endpoints|tls_probe_failed).",
}, []string{"crd", "service", "reason"})

func init() {
	ctrlmetrics.Registry.MustRegister(CRDConversionWebhookUnhealthy)
}

// crdConversionKey is the exact label tuple of the
// CRDConversionWebhookUnhealthy gauge — the GaugeLedger key, same
// contract as the WebhookCircuitBroken ledger.
type crdConversionKey struct{ crd, service, reason string }

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
	g := snap.G
	log := logf.FromContext(ctx)
	now := g.Now.Now()

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
		payload, trips, recovered := b.circuitPatch(log, g.Queue, guardstate.KindMutating,
			cfg.Name, cfg.Annotations[guardstate.CircuitBrokenAnno],
			mutHookViews(cfg.Webhooks), ready, now, seen, &b.brokenEmitted)
		if payload == nil {
			continue
		}
		if _, err := g.CS.AdmissionregistrationV1().MutatingWebhookConfigurations().
			Patch(ctx, cfg.Name, types.StrategicMergePatchType, payload, metav1.PatchOptions{}); err != nil {
			log.Error(err, "circuit breaker patch failed",
				"kind", guardstate.KindMutating, "config", cfg.Name)
			failed = append(failed, cfg.Name)
			continue
		}
		circuitMetrics(&b.brokenEmitted, guardstate.KindMutating, cfg.Name, trips, recovered)
	}
	for i := range vwcs.Items {
		cfg := &vwcs.Items[i]
		payload, trips, recovered := b.circuitPatch(log, g.Queue, guardstate.KindValidating,
			cfg.Name, cfg.Annotations[guardstate.CircuitBrokenAnno],
			valHookViews(cfg.Webhooks), ready, now, seen, &b.brokenEmitted)
		if payload == nil {
			continue
		}
		if _, err := g.CS.AdmissionregistrationV1().ValidatingWebhookConfigurations().
			Patch(ctx, cfg.Name, types.StrategicMergePatchType, payload, metav1.PatchOptions{}); err != nil {
			log.Error(err, "circuit breaker patch failed",
				"kind", guardstate.KindValidating, "config", cfg.Name)
			failed = append(failed, cfg.Name)
			continue
		}
		circuitMetrics(&b.brokenEmitted, guardstate.KindValidating, cfg.Name, trips, recovered)
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
func (b *Breaker) tripThreshold(rawReady int) time.Duration {
	if rawReady > 0 {
		if b.partitionZeroThreshold > 0 {
			return b.partitionZeroThreshold
		}
		return PartitionedThreshold
	}
	if b.zeroThreshold > 0 {
		return b.zeroThreshold
	}
	return DeadThreshold
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
func (b *Breaker) circuitPatch(log logr.Logger, queue, kind, cfgName, annoVal string,
	hooks []hookView, ready guardstate.EndpointCensus, now time.Time,
	seen map[string]bool, emitted *state.GaugeLedger[string]) ([]byte, []string, []string) {

	broken := guardstate.ParseCircuitAnnotation(annoVal)
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
		// trips them. Effective excludes Ready endpoints sitting on
		// partitioned/unresponsive nodes (W5.5); Raw keeps them for
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
			svcEffective = ready.Effective[svc]
			svcRaw = ready.Raw[svc]
			unresponsive = svcEffective > 0 &&
				ready.Probed[svc] && !ready.Responsive[svc]
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
			emitted.Set(metrics.WebhookCircuitBroken, 1, key, kind, cfgName, h.name)
		case (svcEffective == 0 || unresponsive) && guardstate.FailClosed(h.fp):
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

	anno := map[string]any{guardstate.CircuitBrokenAnno: nil} // merge-patch null deletes the key
	if len(broken) > 0 {
		anno[guardstate.CircuitBrokenAnno] = strings.Join(slices.Sorted(maps.Keys(broken)), ",")
	}
	// MergePatchAnnos builds the annotations half; the webhooks
	// merge entries are grafted onto the same doc so the policy
	// flips and the trip record land in ONE strategic-merge patch
	// (the webhooks list is patchMergeKey=name — a concurrent
	// writer's sibling entries survive).
	payload, err := kube.MergePatchAnnos(anno)
	if err == nil && len(hookMerges) > 0 {
		var doc map[string]any
		if err = json.Unmarshal(payload, &doc); err == nil {
			doc["webhooks"] = hookMerges
			payload, err = json.Marshal(doc)
		}
	}
	if err != nil {
		// Absorbed sub-failure: the sweep logs and continues —
		// metered so the dropped work is still counted.
		metrics.IncError(queue)
		log.Error(err, "marshal circuit breaker patch", "config", cfgName)
		return nil, nil, nil
	}
	return payload, trips, recovered
}

// svcRefString renders a webhook's Service reference for log lines.
func svcRefString(ref *admissionv1.ServiceReference) string {
	if ref == nil || ref.Namespace == "" || ref.Name == "" {
		return "<none>"
	}
	return ref.Namespace + "/" + ref.Name
}

// SweepCRDConversionBackends health-checks every CRD whose
// spec.conversion.strategy is Webhook and whose clientConfig targets
// an in-cluster Service — one of the four independent duties behind
// the admission-webhook-guard sweep. The failure modes are the breaker's three
// dead-backend signatures, but a dead CONVERSION backend is worse
// than a dead admission one: there is no failurePolicy to trip, so
// every CR read for the whole API group errors while it lasts. The
// sweep therefore only exports
// node_automation_crd_conversion_webhook_unhealthy per CRD — never
// touches the CRD object — and bounces the oldest wedged backend pod
// so the controller recreates it serving (the same stage-1 heal as
// the admission path: BounceCooldown, the shared maintenance
// mutex via heal.AllowedV, UID-preconditioned delete).
//
// Series hygiene: a complete sweep emits the current tuple per
// unhealthy CRD and prunes whatever was not re-seen — a stale
// reason tuple (missing_service → zero_endpoints when the Service
// comes back empty) or a recovered backend must not pin the alert.
// An unverifiable sweep carries the last verdict forward — a
// transient CRD list failure or a blind census is "can't tell", not
// "clean".
func (b *Breaker) SweepCRDConversionBackends(ctx context.Context,
	snap *guardstate.Snapshot) error {
	g := snap.G
	log := logf.FromContext(ctx)
	now := g.Now.Now()

	carryForward := func() {
		for k, lv := range b.crdUnhealthyEmitted.Last() {
			b.crdUnhealthyEmitted.Emit(k, lv...)
		}
		b.crdUnhealthyEmitted.Prune(CRDConversionWebhookUnhealthy.DeleteLabelValues)
	}

	if snap.CRDErr != nil {
		// API flap — "can't read the surface" fails closed: carry
		// the series forward and surface the error.
		carryForward()
		return fmt.Errorf("list customresourcedefinitions — conversion webhook health skipped: %w", snap.CRDErr)
	}
	ready, err := snap.ReadyCounts()
	if err != nil {
		// The breaker reports the same census failure as ITS error —
		// re-reporting it here would double-count. Defer quietly and
		// keep the last verdict alive — UNLESS the breaker is
		// levered off this cycle, in which case nobody else reports
		// it and the failure would be invisible.
		carryForward()
		if !Enabled() {
			return fmt.Errorf("endpoint/node census — conversion webhook health skipped: %w", err)
		}
		return nil
	}

	var hung []string
	bounceSeen := map[string]bool{}
	for i := range snap.CRDs {
		crd := &snap.CRDs[i]
		svcKey, svcNS, svcName, ok := guardstate.CRDConversionServiceKey(crd)
		if !ok {
			continue // no webhook conversion or a URL backend — unmeasurable
		}
		reason := ""
		_, err := g.CS.CoreV1().Services(svcNS).
			Get(ctx, svcName, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			reason = CRDReasonMissingService
			log.Info("UNHEALTHY: CRD conversion webhook backend Service missing",
				"crd", crd.GetName(), "service", svcKey)
		case err != nil:
			// Can't verify — carry this CRD's last verdict forward
			// rather than flap; absorbed sub-failure, sweep
			// continues.
			metrics.IncError(g.Queue)
			log.Error(err, "conversion webhook backend Service get failed",
				"crd", crd.GetName(), "service", svcKey)
			for k, lv := range b.crdUnhealthyEmitted.Last() {
				if k.crd == crd.GetName() {
					b.crdUnhealthyEmitted.Emit(k, lv...)
				}
			}
			continue
		case ready.Effective[svcKey] == 0:
			reason = CRDReasonZeroEndpoints
			log.Info("UNHEALTHY: CRD conversion webhook backend has 0 effective-ready endpoints",
				"crd", crd.GetName(), "service", svcKey)
		case ready.Probed[svcKey] && !ready.Responsive[svcKey]:
			reason = CRDReasonTLSProbeFailed
			log.Info("UNHEALTHY: CRD conversion webhook backend fails TCP+TLS probe on every endpoint — pods wedged",
				"crd", crd.GetName(), "service", svcKey)
			if !bounceSeen[svcKey] {
				bounceSeen[svcKey] = true
				hung = append(hung, svcKey)
			}
		}
		if reason == "" {
			continue
		}
		k := crdConversionKey{crd: crd.GetName(), service: svcKey, reason: reason}
		b.crdUnhealthyEmitted.Set(CRDConversionWebhookUnhealthy, 1,
			k, k.crd, k.service, k.reason)
	}
	b.crdUnhealthyEmitted.Prune(CRDConversionWebhookUnhealthy.DeleteLabelValues)

	if !Enabled() {
		// The shared ops lever silences pod kills module-wide —
		// the gauge above stays live (detect-only, like the
		// unmeshed audit).
		return nil
	}
	for _, svcKey := range hung {
		// heal.AllowedV folds the BounceCooldown per-service cooldown AND the
		// maintenance mutex into one fail-closed preamble; &g.Verdict
		// memoizes the mutex across services (and shares it with the
		// admission bounce + unmeshed paths) instead of paying three
		// API reads per service.
		proceed, unverifiable := heal.AllowedV(ctx, log, &g.Verdict,
			g.CS, g.Dyn, &b.bounceAt, svcKey, BounceCooldown, now)
		if unverifiable {
			metrics.IncError(g.Queue)
			continue
		}
		if !proceed {
			continue
		}
		b.bounceOldestPod(ctx, snap, svcKey, ready.BackingPods[svcKey], now)
	}
	return nil
}
