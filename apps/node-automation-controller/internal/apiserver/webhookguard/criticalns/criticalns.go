// criticalns.go — the critical-namespace audit duties (critical-ns-audit):
// Sweeper owns the two emitted-series ledgers — the facade
// holds one Sweeper across runs so fixed or removed webhooks have
// their series pruned — and the audits share the namespaceSelector
// matcher built from the snapshot's namespace census.
package criticalns

import (
	"encoding/json"
	"maps"
	"slices"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// criticalSelfHealingNamespaces are the namespaces that run CNI,
// DNS, the kubelet heartbeat, the OLM operator stack, and the node
// self-healing stack itself — a fail-closed admission webhook that
// matches any of them can deadlock recovery when its own backend
// dies (critical-ns-audit, mirroring check-webhook-guard.sh at
// runtime). kube-node-lease joined later: its Lease objects ARE the
// kubelet node heartbeat, so a webhook that intercepts lease writes
// can flap every node NotReady on its own. operators joined with it:
// every OLM Subscription/CSV/operator pod lives there, so a webhook
// that can wedge pod creation in operators wedges the entire
// operator-driven remediation fleet at once.
var criticalSelfHealingNamespaces = []string{"kube-system", "kube-node-lease", "node-ops", "medik8s", "operators"}

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

// heartbeatClusterScopedResources are the heartbeat hits a
// namespaceSelector can NEVER exclude: nodes/status is cluster-scoped
// (the API server does not consult namespaceSelector for it at all),
// pods/eviction wedges every drain in EVERY namespace, and the
// wildcards cover both by definition. auditHeartbeat flags these
// unconditionally; pods/status and leases stay namespaced and keep
// the critical-namespace match requirement.
var heartbeatClusterScopedResources = map[string]bool{
	"nodes/status":  true,
	"pods/eviction": true,
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
func forEachConfig(snap *guardstate.Snapshot,
	visit func(kind, cfgName string, cfgObj metav1.Object, hooks []hookView)) {
	if snap.MWC != nil {
		for i := range snap.MWC.Items {
			visit(guardstate.KindMutating, snap.MWC.Items[i].Name,
				&snap.MWC.Items[i], mutHookViews(snap.MWC.Items[i].Webhooks))
		}
	}
	if snap.VWC != nil {
		for i := range snap.VWC.Items {
			visit(guardstate.KindValidating, snap.VWC.Items[i].Name,
				&snap.VWC.Items[i], valHookViews(snap.VWC.Items[i].Webhooks))
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

// mergeExclusion is the namespaceSelector patch the critical-NS
// auto-patch injects into a webhook — the exact NotIn shape
// check-webhook-guard.sh demands statically, MERGED into the
// webhook's EXISTING selector. metav1.LabelSelector.MatchExpressions
// is a plain list with no patchStrategy:"merge" in the Kubernetes
// API, so a patch carrying only the exclusion rule would REPLACE
// every expression the webhook already had — silently widening, say,
// a tier=prod-restricted webhook to the whole cluster. The payload
// therefore sends the full union: the existing matchLabels (strategic
// merge keeps map entries anyway, but stating them keeps the patch
// self-describing), every existing matchExpressions element, with
// missing critical namespaces merged into an existing
// kubernetes.io/metadata.name NotIn rule's values — or that rule
// appended after the preserved expressions when no such rule exists.
func mergeExclusion(sel *metav1.LabelSelector) map[string]any {
	var cur metav1.LabelSelector // nil selector (match-all) contributes nothing
	if sel != nil {
		cur = *sel
	}
	const nameKey = "kubernetes.io/metadata.name"
	patch := map[string]any{}
	if len(cur.MatchLabels) > 0 {
		ml := make(map[string]string, len(cur.MatchLabels))
		maps.Copy(ml, cur.MatchLabels)
		patch["matchLabels"] = ml
	}
	exprs := make([]map[string]any, 0, len(cur.MatchExpressions)+1)
	merged := false
	for _, e := range cur.MatchExpressions {
		vals := slices.Clone(e.Values)
		if e.Key == nameKey && e.Operator == metav1.LabelSelectorOpNotIn {
			for _, ns := range criticalSelfHealingNamespaces {
				if !slices.Contains(vals, ns) {
					vals = append(vals, ns)
				}
			}
			merged = true
		}
		exprs = append(exprs, map[string]any{
			"key": e.Key, "operator": string(e.Operator), "values": vals,
		})
	}
	if !merged {
		exprs = append(exprs, map[string]any{
			"key":      nameKey,
			"operator": string(metav1.LabelSelectorOpNotIn),
			"values":   slices.Clone(criticalSelfHealingNamespaces),
		})
	}
	patch["matchExpressions"] = exprs
	return patch
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

	// patchExclusion lands the queued merge entries for one config —
	// the orphansweep's mechanics (strategic-merge on the merge-key
	// webhooks list, snapshot kept current for the later duties). The
	// mutating flag only selects the typed clientset call — the only
	// true MWC/VWC difference.
	patchExclusion := func(kind string, mutating bool, cfgName string,
		cfgObj metav1.Object, merges []map[string]any, onFail func()) {
		if len(merges) == 0 {
			return
		}
		// SSA ping-pong defense: the exclusion write fights Flux when
		// the config is Git-owned (a HelmRelease-applied webhook with
		// driftDetection re-asserts the Git selector every reconcile).
		// Past the Heal-Revert-Loop threshold the patch SKIPS — the
		// missing-exclusion series stays live (onFail) and the
		// conflict counter fires, so the drift gets fixed in Git.
		if !heal.FluxPatchGate(kind, cfgObj, kind+"/"+cfgName, time.Now()) {
			log.Info("skip heal: Flux Heal-Revert Loop detected — exclusion patch deferred",
				"kind", kind, "config", cfgName)
			onFail()
			return
		}
		payload, err := json.Marshal(map[string]any{"webhooks": merges})
		if err != nil {
			// Absorbed sub-failure: the audit logs and continues —
			// metered so the dropped work is still counted.
			metrics.IncError(g.Queue)
			log.Error(err, "marshal critical-ns exclusion patch", "config", cfgName)
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
			onFail()
		}
	}

	forEachConfig(snap, func(kind, cfgName string, cfgObj metav1.Object, hooks []hookView) {
		var merges []map[string]any
		var queued []hookView // webhooks whose exclusion the patch carries
		for _, w := range hooks {
			if !guardstate.FailClosed(w.fp) || !matchesCriticalNS(w.sel) {
				continue
			}
			if !enforce || criticalNSPatchAllowlist[cfgName+"/"+w.name] {
				// No patch will cover this webhook (lever off, or the
				// allowlist deliberately keeps it exposed) — the
				// missing-exclusion series stays live.
				s.exclusionEmitted.Set(metrics.WebhookMissingCriticalNSExclusion, 1,
					kind+"/"+cfgName+"/"+w.name, kind, cfgName, w.name)
				continue
			}
			merges = append(merges, map[string]any{
				"name": w.name, "namespaceSelector": mergeExclusion(w.sel)})
			queued = append(queued, w)
		}
		// An auto-enforced webhook emits the series only when its
		// patch FAILED — a landed patch means the exclusion exists
		// and the ledger re-verifies (and re-emits) next sweep.
		patchExclusion(kind, kind == guardstate.KindMutating, cfgName, cfgObj, merges, func() {
			for _, w := range queued {
				s.exclusionEmitted.Set(metrics.WebhookMissingCriticalNSExclusion, 1,
					kind+"/"+cfgName+"/"+w.name, kind, cfgName, w.name)
			}
		})
	})
	s.exclusionEmitted.Prune(metrics.WebhookMissingCriticalNSExclusion.DeleteLabelValues)
}

// heartbeatRuleHits returns the rule's resource literals that land on
// the heartbeat path, checked against the rule's APIGroups — the
// literal alone lies, because a CRD group can serve its own "leases"
// resource without ever touching the kubelet heartbeat. leases demands
// coordination.k8s.io; nodes/status, pods/status and pods/eviction are
// core-group subresources so a wildcard APIGroups ["*"] must not claim
// them (only the wildcard RESOURCES "*", "*/*" cover every group); a
// wildcard group behind a typed resource is exactly the false-positive
// shape this check exists to avoid.
func heartbeatRuleHits(rule admissionv1.RuleWithOperations) []string {
	var hits []string
	for _, res := range rule.Resources {
		if !webhookHeartbeatResources[res] {
			continue
		}
		switch {
		case res == "leases":
			if !slices.Contains(rule.APIGroups, "coordination.k8s.io") {
				continue
			}
		case res == "*" || res == "*/*":
			// Wildcard resources cover every group by definition.
		default:
			if !slices.Contains(rule.APIGroups, "") {
				continue
			}
		}
		hits = append(hits, res)
	}
	return hits
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
	forEachConfig(snap, func(kind, cfgName string, _ metav1.Object, hooks []hookView) {
		for _, w := range hooks {
			if !guardstate.FailClosed(w.fp) {
				continue
			}
			emitWebhook(kind, cfgName, w.name, w.rules, matchesCriticalNS(w.sel))
		}
	})
	s.heartbeatEmitted.Prune(metrics.WebhookHeartbeatResourceExposed.DeleteLabelValues)
}
