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

// circuitPatch evaluates one config's sub-webhooks against the ready
// census and builds the strategic-merge patch that flips long-dead
// entries to Ignore, restores recovered ones to Fail and rewrites the
// circuit-broken annotation (merge-patch null removes the key when the
// set empties). hooks views the config's live webhook list; each
// changed entry lands in the patch as {"name": X, "failurePolicy":
// ...} — the webhooks list is patchMergeKey=name + patchStrategy=merge
// (+listType=map), so only the touched element's failurePolicy is
// rewritten and a concurrent writer's sibling entries survive instead
// of being reverted by a whole-array reserialize. Returns nil
// payload when nothing changed; trips, recovered and stillBroken are
// the names whose metric/ledger updates the caller must apply only
// after the patch lands (stillBroken is also returned on the
// nil-payload path — nothing needs writing, but the
// annotation-verified series still re-asserts). Emitting any of
// them earlier would let a failed patch pin or drop a series the
// annotation no longer justifies.
func (b *Breaker) circuitPatch(log logr.Logger, queue, kind, cfgName, annoVal string,
	hooks []hookView, ready guardstate.EndpointCensus, now time.Time,
	seen map[string]bool) (payload []byte, trips, recovered, stillBroken []string) {

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
			// Ignore if the policy was flipped back externally. The
			// series re-asserts post-patch via stillBroken: a failed
			// patch leaves the annotation unverifiable, so marking
			// it emitted here would let the prune keep (or drop)
			// the wrong set.
			if h.fp == nil || *h.fp != admissionv1.Ignore {
				flip(h, admissionv1.Ignore)
				changed = true
			}
			stillBroken = append(stillBroken, h.name)
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
		return nil, nil, nil, stillBroken
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
		return nil, nil, nil, stillBroken
	}
	return payload, trips, recovered, stillBroken
}

// svcRefString renders a webhook's Service reference for log lines.
func svcRefString(ref *admissionv1.ServiceReference) string {
	if ref == nil || ref.Namespace == "" || ref.Name == "" {
		return "<none>"
	}
	return ref.Namespace + "/" + ref.Name
}
