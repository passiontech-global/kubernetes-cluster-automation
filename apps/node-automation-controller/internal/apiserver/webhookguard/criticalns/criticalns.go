// criticalns.go — the critical-namespace audit duties (critical-ns-audit):
// Sweeper owns the two emitted-series ledgers — the facade
// holds one Sweeper across runs so fixed or removed webhooks have
// their series pruned — and the audits share the namespaceSelector
// matcher built from the snapshot's namespace census.
package criticalns

import (
	json "encoding/json/v2"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

var (
	criticalSelfHealingNamespaces   = guardstate.CriticalSelfHealingNamespaces
	heartbeatClusterScopedResources = guardstate.HeartbeatClusterScopedResources
	heartbeatScopeAllows            = guardstate.HeartbeatScopeAllows
)

// CriticalNSEnforceEnabled reads the critical-ns auto-patch gate EVERY
// run — the sanctioned exception to the resolve-at-Setup rule (the
// same deliberate hot reload the unmeshed remediation lever carries):
// the lever flips mid-incident without an operator restart. Opt-in
// (exactly "true"), default off — the patch mutates webhook configs the
// controller does not own.
func CriticalNSEnforceEnabled() bool {
	return envx.Gate("WEBHOOK_CRITICAL_NS_ENFORCE_ENABLED", false)
}

// criticalNSPatchAllowlist is the auto-patcher's do-not-touch set,
// keyed "<configName>/<webhookName>" — the runtime twin of
// check-webhook-guard.sh's ALLOWLIST. Every entry needs a reason
// comment; empty today like the static gate (a webhook that must
// genuinely intercept a critical namespace declares itself here
// instead of being re-patched every sweep).
var criticalNSPatchAllowlist = map[string]bool{}

// Sweeper owns the critical-ns audits' per-sweep state — the facade
// holds one across runs so the emitted-series ledgers persist. Shared
// deps (CS) are reached through snap.G.
type Sweeper struct {
	// exclusionEmitted tracks live WebhookMissingCriticalNSExclusion
	// series ("kind/name/webhook") so fixed or removed webhooks have
	// their series pruned.
	exclusionEmitted state.GaugeLedger[string]
	// heartbeatEmitted tracks live WebhookHeartbeatResourceExposed
	// series ("kind/name/webhook/resource") so webhooks whose rules or
	// selector change have their series pruned.
	heartbeatEmitted state.GaugeLedger[string]
}

// Sweep runs both critical-ns audits against the shared snapshot —
// the facade invokes it after the circuit breaker so the audits read
// post-patch webhook state, exactly where they sat inside the unmeshed
// sweep before the duty moved to its own subpackage.
func (s *Sweeper) Sweep(snap *guardstate.Snapshot) {
	s.auditExclusions(snap)
	s.auditHeartbeat(snap)
}

func matcher(snap *guardstate.Snapshot) (matches func(*metav1.LabelSelector) bool, ok bool) {
	if snap == nil || snap.MWCErr != nil || snap.VWCErr != nil ||
		snap.MWC == nil || snap.VWC == nil {
		return nil, false
	}
	return guardstate.CriticalNSMatcher(snap)
}

func mergeExclusion(sel *metav1.LabelSelector) map[string]any {
	return guardstate.MergeCriticalNSExclusion(sel)
}

// auditExclusions (critical-ns-audit) audits live Mutating/Validating admission
// sub-webhooks with failurePolicy=Fail (or nil, which defaults to
// Fail) and emits
// node_automation_webhook_missing_critical_ns_exclusion=1 when the
// sub-webhook's namespaceSelector matches any of the critical
// self-healing namespaces (kube-system, kube-node-lease, node-ops,
// medik8s, operators).
//
// auditExclusions adds the optional auto-patch (WEBHOOK_CRITICAL_NS_ENFORCE_
// ENABLED=true): each flagged webhook outside the allowlist gets the
// NotIn exclusion merged into its namespaceSelector by strategic-merge
// patch — one patch per config carrying every missing entry, keyed by
// merge-key name so a concurrent writer's sibling entries survive.
// Under the auto-patch the series only reports webhooks the patch does
// NOT cover (lever off, allowlisted) or a FAILED patch — a landed
// patch means the exclusion exists, and the ledger re-verifies next
// sweep, so a failed patch only delays the exclusion instead of
// pinning a stale series.
func (s *Sweeper) auditExclusions(snap *guardstate.Snapshot) {
	s.exclusionEmitted.Begin() // drop any aborted sweep's leftover emissions
	matchesCriticalNS, ok := matcher(snap)
	if !ok {
		return
	}
	log := logf.FromContext(snap.Ctx)
	g := snap.G
	enforce := CriticalNSEnforceEnabled()

	// patchExclusion lands the queued merge entries for one config via
	// cfg.Patch (strategic-merge on the merge-key webhooks list,
	// keeping the snapshot current for later duties).
	patchExclusion := func(cfg guardstate.WebhookConfigView,
		merges []map[string]any, onFail func()) {
		if len(merges) == 0 {
			return
		}
		// SSA ping-pong defense: the exclusion write fights Flux when
		// the config is Git-owned (a HelmRelease-applied webhook with
		// driftDetection re-asserts the Git selector every reconcile).
		// Past the Heal-Revert-Loop threshold the patch SKIPS — the
		// missing-exclusion series stays live (onFail) and the
		// conflict counter fires, so the drift gets fixed in Git.
		if !heal.FluxPatchGate(cfg.Kind, cfg.Object, "criticalns/"+cfg.Kind+"/"+cfg.Name, g.Now.Now()) {
			log.Info("skip heal: Flux Heal-Revert Loop detected — exclusion patch deferred",
				"kind", cfg.Kind, "config", cfg.Name)
			onFail()
			return
		}
		payload, err := json.Marshal(map[string]any{"webhooks": merges})
		if err != nil {
			// Absorbed sub-failure: the audit logs and continues —
			// metered so the dropped work is still counted.
			metrics.IncError(g.Queue)
			log.Error(err, "marshal critical-ns exclusion patch", "config", cfg.Name)
			onFail()
			return
		}
		names := make([]string, 0, len(merges))
		for _, m := range merges {
			if name, _ := m["name"].(string); name != "" {
				names = append(names, name)
			}
		}
		log.Info("PATCH: injecting critical-ns NotIn exclusion into fail-closed webhook(s)",
			"kind", cfg.Kind, "config", cfg.Name, "webhooks", names,
			"namespaces", criticalSelfHealingNamespaces)
		if err := cfg.Patch(snap.Ctx, types.StrategicMergePatchType, payload); err != nil {
			metrics.IncError(g.Queue)
			log.Error(err, "critical-ns exclusion patch failed — webhook left fail-closed against critical namespaces",
				"kind", cfg.Kind, "config", cfg.Name)
			onFail()
		}
	}

	snap.ForEachWebhookConfig(func(cfg guardstate.WebhookConfigView) {
		var merges []map[string]any
		var queued []guardstate.WebhookView // webhooks whose exclusion the patch carries
		for _, w := range cfg.Hooks {
			// A webhook whose rules are ALL cluster-scoped never
			// consults its namespaceSelector — the missing
			// exclusion is not a finding and the patch would be a
			// no-op.
			if !guardstate.FailClosed(w.FailurePolicy) ||
				!matchesCriticalNS(w.NamespaceSelector) ||
				allClusterScopedRules(w.Rules) {
				continue
			}
			if !enforce || criticalNSPatchAllowlist[cfg.Name+"/"+w.Name] {
				// No patch will cover this webhook (lever off, or the
				// allowlist deliberately keeps it exposed) — the
				// missing-exclusion series stays live.
				s.exclusionEmitted.Set(metrics.WebhookMissingCriticalNSExclusion, 1,
					cfg.Kind+"/"+cfg.Name+"/"+w.Name, cfg.Kind, cfg.Name, w.Name)
				continue
			}
			merges = append(merges, map[string]any{
				"name": w.Name, "namespaceSelector": mergeExclusion(w.NamespaceSelector)})
			queued = append(queued, w)
		}
		// An auto-enforced webhook emits the series only when its
		// patch FAILED — a landed patch means the exclusion exists
		// and the ledger re-verifies (and re-emits) next sweep.
		patchExclusion(cfg, merges, func() {
			for _, w := range queued {
				s.exclusionEmitted.Set(metrics.WebhookMissingCriticalNSExclusion, 1,
					cfg.Kind+"/"+cfg.Name+"/"+w.Name, cfg.Kind, cfg.Name, w.Name)
			}
		})
	})
	s.exclusionEmitted.Prune(metrics.WebhookMissingCriticalNSExclusion.DeleteLabelValues)
}

func heartbeatRuleHits(rule admissionv1.RuleWithOperations) []string {
	return guardstate.HeartbeatRuleHits(rule)
}

func allClusterScopedRules(rules []admissionv1.RuleWithOperations) bool {
	return guardstate.AllClusterScopedRules(rules)
}

// auditHeartbeat audits live Mutating/Validating admission
// sub-webhooks with failurePolicy=Fail (or the nil default) whose
// rules[].resources intercept a heartbeat-path resource, emitting
// node_automation_webhook_heartbeat_resource_exposed
// {kind,name,webhook,resource}=1 per matched rule resource (the
// literal — wildcards stay wildcards, matching the static guard's
// grammar). The namespaceSelector split is resource-aware: hits on
// cluster-scoped or every-namespace paths (nodes/status — the API
// server never consults namespaceSelector for it — pods/eviction,
// and the wildcards) flag regardless of the selector, while the
// namespaced hits (pods/status, leases) only flag when the selector
// still matches a critical self-healing namespace. A selector that
// already excludes the critical namespaces silences the namespaced
// half: the webhook can still wedge itself, but it can no longer
// wedge the cluster's self-healing path.
func (s *Sweeper) auditHeartbeat(snap *guardstate.Snapshot) {
	s.heartbeatEmitted.Begin() // drop any aborted sweep's leftover emissions
	matchesCriticalNS, ok := matcher(snap)
	if !ok {
		return
	}
	// emitWebhook flags one webhook: each rule's resources are matched
	// against the heartbeat set GROUP-AWARE (see heartbeatRuleHits) and
	// each hit becomes a series keyed "kind/name/webhook/resource".
	// nsOK is the selector verdict for THIS webhook — consulted only
	// for the namespaced heartbeat resources.
	emitWebhook := func(kind, cfgName, hookName string,
		rules []admissionv1.RuleWithOperations, nsOK bool) {
		seen := map[string]bool{}
		for _, rule := range rules {
			for _, res := range heartbeatRuleHits(rule) {
				if seen[res] || (!nsOK && !heartbeatClusterScopedResources[res]) {
					continue
				}
				seen[res] = true
				s.heartbeatEmitted.Set(metrics.WebhookHeartbeatResourceExposed, 1,
					kind+"/"+cfgName+"/"+hookName+"/"+res,
					kind, cfgName, hookName, res)
			}
		}
	}
	snap.ForEachWebhookConfig(func(cfg guardstate.WebhookConfigView) {
		for _, w := range cfg.Hooks {
			if !guardstate.FailClosed(w.FailurePolicy) {
				continue
			}
			emitWebhook(cfg.Kind, cfg.Name, w.Name, w.Rules, matchesCriticalNS(w.NamespaceSelector))
		}
	})
	s.heartbeatEmitted.Prune(metrics.WebhookHeartbeatResourceExposed.DeleteLabelValues)
}
