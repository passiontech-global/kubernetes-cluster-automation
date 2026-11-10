// circuit_patch.go — the per-config half of the C1 circuit
// breaker, split out of circuit_breaker.go so the sweep
// orchestration and the per-entry verdict math each read on their
// own: circuitPatch walks one config's sub-webhooks against the
// endpoint census (trip / recover / still-broken / stale-annotation
// drop) and builds the single strategic-merge patch carrying every
// failurePolicy flip plus the rewritten circuit-broken annotation.
// tripThreshold (the dead vs. partitioned window pick) and
// svcRefString (Service-ref log rendering) are its private helpers.
package circuitbreaker

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admissionregistration/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

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

// circuitEval carries one circuitPatch call's per-config state —
// the annotation set being rebuilt, the failurePolicy-flip merge
// entries, the outcome lists the caller applies only after the
// patch lands, and the keep-sets the sweep's deferred prunes read.
type circuitEval struct {
	b           *Breaker
	log         logr.Logger
	kind        string
	cfgName     string
	hooks       []hookView
	ready       guardstate.EndpointCensus
	now         time.Time
	seen        map[string]bool
	recoverSeen map[string]bool
	allowTrips  bool

	broken      map[string]bool // annotation set being rebuilt
	present     map[string]bool // every live sub-webhook name
	blind       bool            // probe source itself suspect — see probeBlind
	hookMerges  []map[string]any
	changed     bool
	trips       []string
	recovered   []string
	stillBroken []string
	dropped     []string
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
// of being reverted by a whole-array reserialize. A recover only
// fires after RecoverConfirmSweeps CONSECUTIVE healthy sweeps
// (recoverHealthy counters + recoverSeen mark the live streaks);
// before that the entry stays broken (Ignore re-asserted, stillBroken
// returned). Returns nil
// payload when nothing changed; trips, recovered and stillBroken are
// the names whose metric/ledger updates the caller must apply only
// after the patch lands (stillBroken is also returned on the
// nil-payload path — nothing needs writing, but the
// annotation-verified series still re-asserts). dropped carries the
// stale-annotation names this evaluation removed — the caller owns
// their WebhookCircuitBroken series deletion too, and equally only
// AFTER the patch lands: deleting inside circuitPatch would release
// the series even when the write fails and the annotation (the SSOT)
// still lists the name. Emitting any of
// them earlier would let a failed patch pin or drop a series the
// annotation no longer justifies.
func (b *Breaker) circuitPatch(log logr.Logger, queue, kind, cfgName, annoVal string,
	hooks []hookView, ready guardstate.EndpointCensus, now time.Time,
	seen, recoverSeen map[string]bool, allowTrips bool) (payload []byte, trips, recovered, stillBroken, dropped []string) {

	e := &circuitEval{
		b: b, log: log,
		kind: kind, cfgName: cfgName, hooks: hooks,
		ready: ready, now: now,
		seen: seen, recoverSeen: recoverSeen, allowTrips: allowTrips,
		broken:  guardstate.ParseCircuitAnnotation(annoVal),
		present: map[string]bool{},
		// One probe source is the culprit when every probed backend
		// failed the handshake (probeBlind): the monitor — not the fleet
		// — is then the likely cause, so the unresponsive verdict is
		// silenced (no unresponsive trip, no bounce elsewhere) and broken
		// entries FREEZE: a blind sweep cannot verify recovery either, so
		// the healthy streak must not advance ("can't tell" holds the
		// annotation, the SSOT). Apiserver-truth verdicts (0 effective
		// endpoints) are unaffected.
		blind: probeBlind(ready),
	}
	for _, h := range e.hooks {
		e.evalHook(h)
	}
	e.dropStale()
	payload, err := e.marshalPayload()
	if err != nil {
		// Absorbed sub-failure: the sweep logs and continues —
		// metered so the dropped work is still counted.
		metrics.IncError(queue)
		log.Error(err, "marshal circuit breaker patch", "config", cfgName)
		return nil, nil, nil, e.stillBroken, nil
	}
	if payload == nil {
		return nil, nil, nil, e.stillBroken, nil
	}
	return payload, e.trips, e.recovered, e.stillBroken, e.dropped
}

// evalHook runs one sub-webhook through the four verdict branches —
// recover-defer / recover-confirmed, still-broken re-assert, and the
// dead-backend trip candidate. Anything else (healthy entry, blind
// probe source) needs no write. An unmeasurable ref (svcEffective ==
// svcRaw == -1: a URL webhook, or a Service ref with an empty
// namespace/name) can neither trip nor recover — a broken entry with
// one NEVER advances the recover streak; it freezes in evalStillBroken
// until the ref points at a measurable Service again, because
// flipping the policy back to Fail on zero evidence a backend was
// ever probed would un-fail-close a live outage.
func (e *circuitEval) evalHook(h hookView) {
	e.present[h.name] = true
	key := e.kind + "/" + e.cfgName + "/" + h.name
	isBroken := e.broken[h.name]
	// svcEffective < 0 marks "not Service-backed" — URL webhooks
	// and malformed refs are unmeasurable, the breaker never
	// trips them and never recovers them (the -1 freeze keeps the
	// entry in evalStillBroken). Effective excludes Ready endpoints sitting on
	// partitioned/unresponsive nodes (endpoint-census); Raw keeps them for
	// the threshold pick.
	svcEffective, svcRaw := -1, -1
	svc := ""
	// unresponsive is the circuit-breaker-bounce brownout verdict: the Service
	// reports Ready endpoints on healthy nodes but EVERY probed
	// endpoint IP failed the TCP+TLS handshake — the pods are
	// hung, which is as dead for admission as a partition. It is
	// only ever true when svcEffective > 0 (effective==0 is
	// already covered by the endpoint-census path) and the service was
	// actually probed this run.
	unresponsive := false
	if h.svc != nil && h.svc.Namespace != "" && h.svc.Name != "" {
		svc = h.svc.Namespace + "/" + h.svc.Name
		svcEffective = e.ready.Effective[svc]
		svcRaw = e.ready.Raw[svc]
		unresponsive = svcEffective > 0 &&
			e.ready.Probed[svc] && !e.ready.Responsive[svc] && !e.blind
	}
	switch {
	// Recover only on MEASURABLE, non-zero census evidence — both
	// counters must have left the -1 sentinel (a URL webhook or
	// malformed Service ref is unmeasurable and must NEVER advance
	// the streak) and effective must be positive (0 endpoints is a
	// backend that is still dead, not a recovered one; effective > 0
	// implies raw > 0, spelled out for symmetry with the freeze).
	case isBroken && svcEffective > 0 && svcRaw > 0 && !unresponsive && !e.blind:
		e.evalRecover(h, key, svc)
	case isBroken:
		e.evalStillBroken(h, key)
	case (svcEffective == 0 || unresponsive) && guardstate.FailClosed(h.fp) && e.allowTrips:
		e.evalTrip(h, key, svc, svcRaw, unresponsive)
	}
}

// evalRecover handles an annotation-broken entry whose backend is
// reachable again — but ONE healthy sweep is not a recovery: a
// Service flapping 0↔1 endpoint would trip and recover in
// alternating sweeps, patching the WebhookConfiguration twice a
// cycle. The annotation stays the SSOT for "broken"; the counter
// only gates WHEN the recover patch fires.
func (e *circuitEval) evalRecover(h hookView, key, svc string) {
	streak := e.b.markHealthyStreak(key)
	if streak < RecoverConfirmSweeps {
		e.recoverSeen[key] = true
		// Not confirmed yet — the entry stays broken:
		// re-assert Ignore if the policy was flipped back
		// externally, and re-assert the series.
		if h.fp == nil || *h.fp != admissionv1.Ignore {
			e.flip(h, admissionv1.Ignore)
		}
		e.stillBroken = append(e.stillBroken, h.name)
		e.log.Info("CIRCUIT-RECOVER-DEFER: healthy again — confirming next sweep",
			"kind", e.kind, "config", e.cfgName, "webhook", h.name,
			"service", svcRefString(h.svc),
			"healthySweeps", streak, "required", RecoverConfirmSweeps)
		return
	}
	// RECOVER confirmed — Endpoints on partitioned nodes did
	// NOT count toward the streak (they still fail every
	// apiserver call), and neither did endpoints whose pods
	// are still failing the handshake (circuit-breaker-bounce): "Ready" in
	// the EndpointSlice is not "serving".
	e.b.clearHealthyStreak(key)
	e.flip(h, admissionv1.Fail)
	delete(e.broken, h.name)
	e.recovered = append(e.recovered, h.name)
	e.log.Info("CIRCUIT-RECOVER: restoring failurePolicy=Fail",
		"kind", e.kind, "config", e.cfgName, "webhook", h.name,
		"service", svcRefString(h.svc))
}

// evalStillBroken re-asserts Ignore on an annotation-broken entry
// whose backend is still dead — the annotation is the SSOT, so a
// policy flipped back externally is corrected. This is also the
// unmeasurable ref's freeze: a URL-rewritten (or malformed-ref)
// entry lands here every sweep, and the streak clear below is what
// keeps a half-advanced healthy streak from surviving the rewrite.
// The series re-asserts post-patch via stillBroken: a failed patch
// leaves the annotation unverifiable, so marking it emitted here
// would let the prune keep (or drop) the wrong set.
func (e *circuitEval) evalStillBroken(h hookView, key string) {
	e.b.clearHealthyStreak(key) // the healthy streak must be CONSECUTIVE
	if h.fp == nil || *h.fp != admissionv1.Ignore {
		e.flip(h, admissionv1.Ignore)
	}
	e.stillBroken = append(e.stillBroken, h.name)
}

// evalTrip runs the dead-backend streak for a fail-closed entry on
// a dead Service — past the threshold (dead vs partitioned window)
// it flips the entry to Ignore and records it broken. deadSince is
// deliberately NOT cleared on trip: if the patch fails the
// annotation never lands, so keeping the streak lets the next
// sweep retry immediately instead of re-opening a fresh window.
// Once the entry is broken it no longer marks seen[key], so the
// ledger prunes itself.
func (e *circuitEval) evalTrip(h hookView, key, svc string, svcRaw int, unresponsive bool) {
	e.seen[key] = true
	first, tracked := e.b.deadSince.Observe(key, e.now)
	if !tracked {
		e.log.Info("circuit breaker: fail-closed webhook on a dead Service — tracking",
			"kind", e.kind, "config", e.cfgName, "webhook", h.name,
			"service", svc, "rawReady", svcRaw)
		return
	}
	threshold := e.b.tripThreshold(svcRaw)
	if e.now.Sub(first) < threshold {
		return
	}
	// TRIP — dead backend past the threshold.
	e.flip(h, admissionv1.Ignore)
	e.broken[h.name] = true
	e.trips = append(e.trips, h.name)
	switch {
	case unresponsive:
		// circuit-breaker-bounce — every probed Ready endpoint failed the
		// TCP+TLS handshake: hung pods, not a partition.
		// svcRaw > 0 keeps the 90s partition threshold.
		e.log.Info("CIRCUIT-TRIP: unresponsive — all probed ready endpoints fail TCP+TLS handshake — patching failurePolicy=Ignore",
			"kind", e.kind, "config", e.cfgName, "webhook", h.name,
			"service", svc, "threshold", threshold)
	case svcRaw > 0:
		e.log.Info("CIRCUIT-TRIP: all ready endpoints on partitioned/unresponsive nodes — patching failurePolicy=Ignore",
			"kind", e.kind, "config", e.cfgName, "webhook", h.name,
			"service", svc, "rawReady", svcRaw, "threshold", threshold)
	default:
		e.log.Info("CIRCUIT-TRIP: 0 ready endpoints — patching failurePolicy=Ignore",
			"kind", e.kind, "config", e.cfgName, "webhook", h.name,
			"service", svc, "threshold", threshold)
	}
}

// flip queues one failurePolicy merge entry — each hook is visited
// once, so a plain append cannot duplicate a merge key.
func (e *circuitEval) flip(h hookView, fp admissionv1.FailurePolicyType) {
	e.hookMerges = append(e.hookMerges, map[string]any{
		"name": h.name, "failurePolicy": string(fp)})
	e.changed = true
}

// dropStale removes annotation names whose sub-webhook itself is
// gone (e.g. removed by the orphan sweep) so the record stays exact.
// Their metric series are NOT deleted here — the caller releases
// them only after the patch lands (see the dropped contract).
func (e *circuitEval) dropStale() {
	for name := range e.broken {
		if !e.present[name] {
			delete(e.broken, name)
			e.dropped = append(e.dropped, name)
			e.changed = true
			e.log.Info("CIRCUIT-CLEAN: annotation entry has no live webhook — dropping",
				"kind", e.kind, "config", e.cfgName, "webhook", name)
		}
	}
}

// marshalPayload builds the strategic-merge patch: the annotation
// merge-patch plus the webhooks merge entries grafted onto the same
// doc so the policy flips and the trip record land in ONE patch.
// Returns nil when nothing changed.
func (e *circuitEval) marshalPayload() ([]byte, error) {
	if !e.changed {
		return nil, nil
	}
	anno := map[string]any{guardstate.CircuitBrokenAnno: nil} // merge-patch null deletes the key
	if len(e.broken) > 0 {
		anno[guardstate.CircuitBrokenAnno] = strings.Join(slices.Sorted(maps.Keys(e.broken)), ",")
	}
	// MergePatchAnnos builds the annotations half; the webhooks
	// merge entries are grafted onto the same doc so the policy
	// flips and the trip record land in ONE strategic-merge patch
	// (the webhooks list is patchMergeKey=name — a concurrent
	// writer's sibling entries survive).
	payload, err := kube.MergePatchAnnos(anno)
	if err == nil && len(e.hookMerges) > 0 {
		var doc map[string]any
		if err = json.Unmarshal(payload, &doc); err == nil {
			doc["webhooks"] = e.hookMerges
			payload, err = json.Marshal(doc)
		}
	}
	return payload, err
}

// svcRefString renders a webhook's Service reference for log lines.
func svcRefString(ref *admissionv1.ServiceReference) string {
	if ref == nil || ref.Namespace == "" || ref.Name == "" {
		return "<none>"
	}
	return ref.Namespace + "/" + ref.Name
}
