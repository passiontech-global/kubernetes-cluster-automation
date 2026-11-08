// criticalns.go — the critical-namespace audit duties (W12-CP-B):
// Sweeper owns the two emitted-series ledgers — the facade
// holds one Sweeper across runs so fixed or removed webhooks have
// their series pruned — and the audits share the namespaceSelector
// matcher built from the snapshot's namespace census.
package criticalns

import (
	"encoding/json"
	"maps"
	"slices"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// criticalSelfHealingNamespaces are the four namespaces that run CNI,
// DNS, the kubelet heartbeat, and the node self-healing stack itself —
// a fail-closed admission webhook that matches any of them can
// deadlock recovery when its own backend dies (W12-CP-B, mirroring
// check-webhook-guard.sh at runtime). kube-node-lease joined
// later: its Lease objects ARE the kubelet node heartbeat, so a
// webhook that intercepts lease writes can flap every node NotReady
// on its own.
var criticalSelfHealingNamespaces = []string{"kube-system", "kube-node-lease", "node-ops", "medik8s"}

// webhookHeartbeatResources is the rule-resource set on the node/pod
// lifecycle heartbeat path — the runtime twin of check-webhook-guard.sh's
// blocked_resources grammar. A fail-closed webhook intercepting any of
// these turns its OWN outage into cluster-wide wedging: nodes/status and
// leases are the heartbeat writes (webhook dead = every node flaps
// NotReady / every leader expires), pods/status kills the status writer,
// pods/eviction blocks every drain, and the wildcards cover all four.
var webhookHeartbeatResources = map[string]bool{
	"nodes/status":  true,
	"pods/status":   true,
	"pods/eviction": true,
	"leases":        true,
	"*":             true,
	"*/*":           true,
}

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

// hookView is the critical-ns duties' uniform projection over
// MutatingWebhook / ValidatingWebhook — every field both audits read
// (name, failure policy, namespace selector, rules) exists on both
// kinds with identical types.
type hookView struct {
	name  string
	fp    *admissionv1.FailurePolicyType
	sel   *metav1.LabelSelector
	rules []admissionv1.RuleWithOperations
}

func mutHookViews(ws []admissionv1.MutatingWebhook) []hookView {
	out := make([]hookView, len(ws))
	for i := range ws {
		out[i] = hookView{name: ws[i].Name, fp: ws[i].FailurePolicy,
			sel: ws[i].NamespaceSelector, rules: ws[i].Rules}
	}
	return out
}

func valHookViews(ws []admissionv1.ValidatingWebhook) []hookView {
	out := make([]hookView, len(ws))
	for i := range ws {
		out[i] = hookView{name: ws[i].Name, fp: ws[i].FailurePolicy,
			sel: ws[i].NamespaceSelector, rules: ws[i].Rules}
	}
	return out
}

// forEachConfig walks the snapshot's mutating then validating configs
// in order, projecting each config's webhooks through hookView — one
// shared pass so a kind-specific edit cannot land on only one twin.
func forEachConfig(snap *guardstate.Snapshot, visit func(kind, cfgName string, hooks []hookView)) {
	if snap.MWC != nil {
		for i := range snap.MWC.Items {
			visit(guardstate.KindMutating, snap.MWC.Items[i].Name,
				mutHookViews(snap.MWC.Items[i].Webhooks))
		}
	}
	if snap.VWC != nil {
		for i := range snap.VWC.Items {
			visit(guardstate.KindValidating, snap.VWC.Items[i].Name,
				valHookViews(snap.VWC.Items[i].Webhooks))
		}
	}
}

// matcher builds the namespaceSelector predicate both audits share
// from the snapshot's namespace census: true when the selector still
// matches (fails to exclude) any of the critical self-healing
// namespaces — nil or malformed selectors match everything. ok=false
// when the shared inputs are missing (a census error or nil
// webhook-config lists); the callers skip their audits rather than act
// on partial state.
func matcher(snap *guardstate.Snapshot) (matches func(*metav1.LabelSelector) bool, ok bool) {
	if snap.NSErr != nil || snap.MWCErr != nil || snap.VWCErr != nil ||
		snap.MWC == nil || snap.VWC == nil {
		return nil, false
	}
	critLabels := make(map[string]labels.Set, len(criticalSelfHealingNamespaces))
	for _, ns := range criticalSelfHealingNamespaces {
		critLabels[ns] = labels.Set{"kubernetes.io/metadata.name": ns}
	}
	if snap.NS != nil {
		for i := range snap.NS.Items {
			ns := &snap.NS.Items[i]
			if _, ok := critLabels[ns.Name]; !ok {
				continue
			}
			merged := make(labels.Set, len(ns.Labels)+1)
			maps.Copy(merged, ns.Labels)
			merged["kubernetes.io/metadata.name"] = ns.Name
			critLabels[ns.Name] = merged
		}
	}
	return func(ls *metav1.LabelSelector) bool {
		if ls == nil {
			return true // nil selector matches all namespaces
		}
		sel, err := metav1.LabelSelectorAsSelector(ls)
		if err != nil {
			return true
		}
		for _, ns := range criticalSelfHealingNamespaces {
			if sel.Matches(critLabels[ns]) {
				return true
			}
		}
		return false
	}, true
}

// mergeExclusion is the matchExpressions block the critical-NS auto-patch
// injects into a webhook's namespaceSelector — the exact NotIn shape
// check-webhook-guard.sh demands statically. Strategic merge keeps the
// selector's matchLabels (opt-in selectors keep working: matchLabels
// AND the new expression) and replaces any partial NotIn with the full
// four-namespace list.
func mergeExclusion() map[string]any {
	return map[string]any{
		"matchExpressions": []map[string]any{{
			"key":      "kubernetes.io/metadata.name",
			"operator": string(metav1.LabelSelectorOpNotIn),
			"values":   slices.Clone(criticalSelfHealingNamespaces),
		}},
	}
}

// auditExclusions (W12-CP-B) audits live Mutating/Validating admission
// sub-webhooks with failurePolicy=Fail (or nil, which defaults to
// Fail) and emits
// node_automation_webhook_missing_critical_ns_exclusion=1 when the
// sub-webhook's namespaceSelector matches any of the critical
// self-healing namespaces (kube-system, kube-node-lease, node-ops,
// medik8s).
//
// auditExclusions adds the optional auto-patch (WEBHOOK_CRITICAL_NS_ENFORCE_
// ENABLED=true): each flagged webhook outside the allowlist gets the
// NotIn exclusion injected by strategic-merge patch — one patch per
// config carrying every missing entry, keyed by merge-key name so a
// concurrent writer's sibling entries survive. The ledger re-verifies
// next sweep, so a failed patch only delays the exclusion instead of
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

	// patchExclusion lands the queued merge entries for one config —
	// the orphansweep's mechanics (strategic-merge on the merge-key
	// webhooks list, snapshot kept current for the later duties). The
	// mutating flag only selects the typed clientset call — the only
	// true MWC/VWC difference.
	patchExclusion := func(kind string, mutating bool, cfgName string, merges []map[string]any) {
		if len(merges) == 0 {
			return
		}
		payload, err := json.Marshal(map[string]any{"webhooks": merges})
		if err != nil {
			// Absorbed sub-failure: the audit logs and continues —
			// metered so the dropped work is still counted.
			metrics.IncError(g.Queue)
			log.Error(err, "marshal critical-ns exclusion patch", "config", cfgName)
			return
		}
		names := make([]string, 0, len(merges))
		for _, m := range merges {
			if name, _ := m["name"].(string); name != "" {
				names = append(names, name)
			}
		}
		log.Info("PATCH: injecting critical-ns NotIn exclusion into fail-closed webhook(s)",
			"kind", kind, "config", cfgName, "webhooks", names,
			"namespaces", criticalSelfHealingNamespaces)
		var patchErr error
		if mutating {
			var patched *admissionv1.MutatingWebhookConfiguration
			patched, patchErr = g.CS.AdmissionregistrationV1().
				MutatingWebhookConfigurations().Patch(snap.Ctx, cfgName,
				types.StrategicMergePatchType, payload, metav1.PatchOptions{})
			if patchErr == nil {
				snap.SetMWC(patched)
			}
		} else {
			var patched *admissionv1.ValidatingWebhookConfiguration
			patched, patchErr = g.CS.AdmissionregistrationV1().
				ValidatingWebhookConfigurations().Patch(snap.Ctx, cfgName,
				types.StrategicMergePatchType, payload, metav1.PatchOptions{})
			if patchErr == nil {
				snap.SetVWC(patched)
			}
		}
		if patchErr != nil {
			metrics.IncError(g.Queue)
			log.Error(patchErr, "critical-ns exclusion patch failed — webhook left fail-closed against critical namespaces",
				"kind", kind, "config", cfgName)
		}
	}

	forEachConfig(snap, func(kind, cfgName string, hooks []hookView) {
		var merges []map[string]any
		for _, w := range hooks {
			if !guardstate.FailClosed(w.fp) || !matchesCriticalNS(w.sel) {
				continue
			}
			s.exclusionEmitted.Set(metrics.WebhookMissingCriticalNSExclusion, 1,
				kind+"/"+cfgName+"/"+w.name, kind, cfgName, w.name)
			if enforce && !criticalNSPatchAllowlist[cfgName+"/"+w.name] {
				merges = append(merges, map[string]any{
					"name": w.name, "namespaceSelector": mergeExclusion()})
			}
		}
		patchExclusion(kind, kind == guardstate.KindMutating, cfgName, merges)
	})
	s.exclusionEmitted.Prune(metrics.WebhookMissingCriticalNSExclusion.DeleteLabelValues)
}

// auditHeartbeat audits live Mutating/Validating admission
// sub-webhooks with failurePolicy=Fail (or the nil default) whose
// rules[].resources intercept a heartbeat-path resource while the
// namespaceSelector still matches a critical self-healing namespace,
// emitting node_automation_webhook_heartbeat_resource_exposed
// {kind,name,webhook,resource}=1 per matched rule resource (the
// literal — wildcards stay wildcards, matching the static guard's
// grammar). A selector that already excludes the critical namespaces
// emits nothing: the webhook can still wedge itself, but it can no
// longer wedge the cluster's self-healing path.
func (s *Sweeper) auditHeartbeat(snap *guardstate.Snapshot) {
	s.heartbeatEmitted.Begin() // drop any aborted sweep's leftover emissions
	matchesCriticalNS, ok := matcher(snap)
	if !ok {
		return
	}
	// emitWebhook flags one webhook: the webhook's deduped rule
	// resources are matched against the heartbeat set and each hit
	// becomes a series keyed "kind/name/webhook/resource".
	emitWebhook := func(kind, cfgName, hookName string, rules []admissionv1.RuleWithOperations) {
		seen := map[string]bool{}
		for _, rule := range rules {
			for _, res := range rule.Resources {
				if !webhookHeartbeatResources[res] || seen[res] {
					continue
				}
				seen[res] = true
				s.heartbeatEmitted.Set(metrics.WebhookHeartbeatResourceExposed, 1,
					kind+"/"+cfgName+"/"+hookName+"/"+res,
					kind, cfgName, hookName, res)
			}
		}
	}
	forEachConfig(snap, func(kind, cfgName string, hooks []hookView) {
		for _, w := range hooks {
			if !guardstate.FailClosed(w.fp) || !matchesCriticalNS(w.sel) {
				continue
			}
			emitWebhook(kind, cfgName, w.name, w.rules)
		}
	})
	s.heartbeatEmitted.Prune(metrics.WebhookHeartbeatResourceExposed.DeleteLabelValues)
}
