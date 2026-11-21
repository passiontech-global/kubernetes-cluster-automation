// cel_criticalns.go — critical self-healing namespace & heartbeat
// exposure audit and safe NotIn exclusion auto-patch for CEL policies.
package celpolicy

import (
	"context"
	json "encoding/json/v2"
	"slices"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// criticalPolicyAllowlist holds "<kind>/<policyName>" entries exempted
// from critical-NS auto-patching.
var criticalPolicyAllowlist = map[string]bool{}

func (s *Sweeper) sweepCriticalNS(ctx context.Context, snap *guardstate.Snapshot, censuses []*kindCensus) {
	matchedCritNS, ok := guardstate.MatchedCriticalNamespaces(snap)
	if !ok {
		// Namespace census unavailable — preserve existing critNSEmitted
		// gauges without pruning rather than dropping live series.
		return
	}

	s.critNSEmitted.Begin()
	log := logf.FromContext(ctx)
	g := snap.G
	now := g.Now.Now()
	enforce := CriticalNSEnforceEnabled()

	for _, c := range censuses {
		if c.absent {
			continue
		}
		if c.skipped {
			s.carryCritNSKind(c.kind)
			continue
		}
		for i := range c.policies {
			p := &c.policies[i]
			if !guardstate.FailClosed(p.FailurePolicy) || p.MatchConstraints == nil {
				continue
			}
			rules := toRuleWithOps(p.MatchConstraints.ResourceRules)
			hbHits := policyHeartbeatHits(rules)
			if len(hbHits) > 0 {
				log.V(1).Info("fail-closed CEL policy rules match heartbeat resource",
					"kind", p.Kind, "policy", p.Name, "resources", hbHits)
			}
			if guardstate.AllClusterScopedRules(rules) {
				continue
			}
			exposed := exposedCriticalNamespaces(p, c.bindings[p.Name], matchedCritNS)
			if len(exposed) == 0 {
				continue
			}

			emitExposed := func() {
				for _, ns := range exposed {
					s.critNSEmitted.Set(metrics.CELPolicyCriticalNSExposed, 1,
						p.Kind+"/"+p.Name+"/"+ns, p.Kind, p.Name, ns)
				}
			}

			if !enforce || criticalPolicyAllowlist[p.key()] {
				emitExposed()
				continue
			}

			gateKey := "cel_criticalns/" + p.key()
			proceed, unverifiable := heal.AllowedV(ctx, log, g.Verdict, g.CS, g.Dyn, &s.heals, gateKey, 0, now)
			if unverifiable {
				metrics.IncError(g.Queue)
			}
			if !proceed {
				emitExposed()
				continue
			}
			if !heal.FluxPatchGate(p.Kind, p.Object, gateKey, now) {
				heal.RefundGrant(now)
				log.Info("skip heal: Flux Heal-Revert Loop detected — CEL critical-NS exclusion patch deferred",
					"kind", p.Kind, "policy", p.Name)
				emitExposed()
				continue
			}

			payload, err := json.Marshal(map[string]any{
				"spec": map[string]any{
					"matchConstraints": map[string]any{
						"namespaceSelector": guardstate.MergeCriticalNSExclusion(p.MatchConstraints.NamespaceSelector),
					},
				},
			})
			if err != nil {
				heal.RefundGrant(now)
				metrics.IncError(g.Queue)
				log.Error(err, "marshal CEL critical-NS exclusion patch", "kind", p.Kind, "policy", p.Name)
				emitExposed()
				continue
			}

			log.Info("PATCH: injecting critical-ns NotIn exclusion into fail-closed CEL policy",
				"kind", p.Kind, "policy", p.Name, "namespaces", exposed)
			patched, err := p.patchFn(ctx, payload)
			if err != nil {
				switch {
				case apierrors.IsForbidden(err):
					heal.RefundGrant(now)
					log.V(1).Info("WARN: CEL critical-NS exclusion patch forbidden (403) — skipping",
						"kind", p.Kind, "policy", p.Name, "error", err)
					emitExposed()
				case kube.IsCRDAbsent(err):
					heal.RefundGrant(now)
					log.V(1).Info("WARN: CEL critical-NS exclusion patch target not found (404) — skipping",
						"kind", p.Kind, "policy", p.Name, "error", err)
					// Omit emitExposed so critNSEmitted prunes any stale series for the vanished policy.
				default:
					metrics.IncError(g.Queue)
					log.Error(err, "CEL critical-NS exclusion patch failed", "kind", p.Kind, "policy", p.Name)
					emitExposed()
				}
				continue
			}
			p.applyPatched(patched)
			metrics.CELPolicyActionsTotal.WithLabelValues(p.Kind, "criticalns_patch").Inc()
		}
	}

	s.critNSEmitted.Prune(metrics.CELPolicyCriticalNSExposed.DeleteLabelValues)
}

func (s *Sweeper) carryCritNSKind(kind string) {
	for k, lv := range s.critNSEmitted.Last() {
		if len(lv) >= 1 && lv[0] == kind {
			s.critNSEmitted.Emit(k, lv...)
		}
	}
}

func toRuleWithOps(in []admissionv1.NamedRuleWithOperations) []admissionv1.RuleWithOperations {
	if len(in) == 0 {
		return nil
	}
	out := make([]admissionv1.RuleWithOperations, len(in))
	for i := range in {
		out[i] = in[i].RuleWithOperations
	}
	return out
}

func policyHeartbeatHits(rules []admissionv1.RuleWithOperations) []string {
	var hits []string
	seen := map[string]bool{}
	for _, r := range rules {
		for _, res := range guardstate.HeartbeatRuleHits(r) {
			if !seen[res] {
				seen[res] = true
				hits = append(hits, res)
			}
		}
	}
	return hits
}

func exposedCriticalNamespaces(p *policyView, bindings []bindingView,
	matched func(*metav1.LabelSelector) []string) []string {

	polMatched := matched(p.MatchConstraints.NamespaceSelector)
	if len(polMatched) == 0 {
		return nil
	}
	if len(bindings) == 0 {
		return polMatched
	}
	polSet := make(map[string]bool, len(polMatched))
	for _, ns := range polMatched {
		polSet[ns] = true
	}
	union := map[string]bool{}
	for _, b := range bindings {
		var bMatched []string
		if b.MatchResources == nil || b.MatchResources.NamespaceSelector == nil {
			bMatched = guardstate.CriticalSelfHealingNamespaces
		} else {
			bMatched = matched(b.MatchResources.NamespaceSelector)
		}
		for _, ns := range bMatched {
			if polSet[ns] {
				union[ns] = true
			}
		}
	}
	var out []string
	for _, ns := range guardstate.CriticalSelfHealingNamespaces {
		if union[ns] && !slices.Contains(out, ns) {
			out = append(out, ns)
		}
	}
	return out
}
