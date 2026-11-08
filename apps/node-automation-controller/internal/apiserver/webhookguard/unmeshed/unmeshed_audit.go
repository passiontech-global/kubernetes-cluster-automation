// unmeshed_audit.go — the unmeshed-pod auditor, one of the four
// independent duties behind the admission-webhook-guard run: it
// exports node_automation_unmeshed_pods{namespace,pod} for every
// Running pod that opted into linkerd injection but carries no
// linkerd-proxy sidecar (the signature of a pod admitted while the
// C1 breaker held the injector open), and — once the injector is
// provably healthy again — evicts a bounded number of them so their
// owner controller recreates them meshed. Its state (the
// emitted-series ledgers) lives on Auditor; shared deps are reached
// through snap.G.
package unmeshed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// The linkerd identifiers (inject annotation key, injected sidecar
// container name, injector sub-webhook name) live in platform/kube —
// the nethealth checks and the zombie-sidecar reaper match the same
// identity.
const (
	// unmeshedMinPodAge: a pod must be this old before deletion —
	// younger pods may simply be mid-admission/mid-start.
	unmeshedMinPodAge = 2 * time.Minute
	// unmeshedDeleteCap bounds successful remediation per cycle — the
	// owner controller recreates each pod, so slow rolling is safer
	// than a sweep-wide delete burst.
	unmeshedDeleteCap = 2
	// unmeshedDeleteAttempts bounds delete ATTEMPTS per cycle —
	// without it a persistently failing delete (RBAC drift, an
	// apiserver in partial outage) would be retried for every
	// candidate, turning the sweep itself into an API storm.
	unmeshedDeleteAttempts = 4
)

// ---------------------------------------------------------------------------
// 2.2 — unmeshed-pod-auditor + post-circuit-breaker pod healer.
// ---------------------------------------------------------------------------

// RemediationEnabled reads the kill-switch EVERY run — the
// sanctioned exception to the resolve-at-Setup rule: remediation is an
// ops lever that must stay flippable mid-incident, so an env flip
// takes effect on the next sweep without an operator restart (the
// same deliberate hot reload the circuit-breaker lever carries).
func RemediationEnabled() bool {
	return envx.Gate("UNMESHED_POD_REMEDIATION_ENABLED", true)
}

// criticalSelfHealingNamespaces are the four namespaces that run CNI,
// DNS, the kubelet heartbeat, and the node self-healing stack itself —
// a fail-closed admission webhook that matches any of them can
// deadlock recovery when its own backend dies (W12-CP-B, mirroring
// check-webhook-guard.sh at runtime). kube-node-lease joined in
// W15-CP0: its Lease objects ARE the kubelet node heartbeat, so a
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
// same deliberate hot reload RemediationEnabled carries): the lever
// flips mid-incident without an operator restart. Opt-in (exactly
// "true"), default off — the patch mutates webhook configs the
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

// Auditor owns the unmeshed-pod sweep's per-sweep state — the facade
// holds one across runs so the emitted-series ledgers persist. Shared
// deps (CS/Dyn/Now) are reached through snap.G; only the
// emitted-series ledgers live here.
type Auditor struct {
	// unmeshedEmitted is the ledger for UnmeshedPods
	// ("namespace/pod") — deleted pods and pods that gained the
	// sidecar get their series pruned each sweep.
	unmeshedEmitted state.GaugeLedger[string]
	// criticalNSExclusionEmitted tracks live WebhookMissingCriticalNSExclusion
	// series ("kind/name/webhook") so fixed or removed webhooks have their
	// series pruned.
	criticalNSExclusionEmitted state.GaugeLedger[string]
	// heartbeatResourceEmitted tracks live WebhookHeartbeatResourceExposed
	// series ("kind/name/webhook/resource") so webhooks whose rules or
	// selector change have their series pruned (W15-CP0).
	heartbeatResourceEmitted state.GaugeLedger[string]
}

// Sweep audits Running Pods that opted into linkerd
// injection (namespace OR pod linkerd.io/inject=enabled) but carry no
// linkerd-proxy container or initContainer — the signature of a pod
// admitted while the C1 breaker held the injector open. The gauge is
// exported unconditionally; deletion additionally requires the
// injector webhook provably healthy and the remediation flag on.
func (a *Auditor) Sweep(ctx context.Context, snap *guardstate.Snapshot) error {
	a.unmeshedEmitted.Begin() // drop any aborted sweep's leftover emissions
	a.auditCriticalNSExclusions(snap)
	a.auditHeartbeatResources(snap)
	g := snap.G
	log := logf.FromContext(ctx)

	// The namespace census carries the ns-level inject=enabled
	// opt-in. An empty list is an API flap — a pod whose namespace
	// cannot be checked must never be classified, so abort the
	// audit before anything is emitted or deleted.
	if snap.NSErr != nil {
		return fmt.Errorf("list namespaces — unmeshed audit skipped: %w", snap.NSErr)
	}
	if len(snap.NS.Items) == 0 {
		return errors.New("empty namespace list (API flap) — unmeshed audit skipped")
	}
	nsInject := make(map[string]string, len(snap.NS.Items))
	for _, ns := range snap.NS.Items {
		nsInject[ns.Name] = injectDirective(ns.Labels, ns.Annotations)
	}

	// Server-side phase filter (the informer cache is list/watch-
	// locked to kube-system cilium pods, so this goes through CS like
	// every other module); the in-code phase check stays because
	// fake clientsets ignore field selectors. The list is PAGED —
	// all Running pods cluster-wide is an unbounded read, and each
	// page is processed then dropped instead of pinning the whole
	// list for the sweep.
	now := g.Now.Now()
	unmeshed := 0 // UnmeshedPods tuples re-asserted this sweep
	var candidates []corev1.Pod
	listOpts := metav1.ListOptions{
		FieldSelector: "status.phase=Running",
		Limit:         guardstate.ListPageSize,
	}
	err := kube.ListEach(ctx, listOpts,
		kube.Pods(g.CS, metav1.NamespaceAll),
		func(items []corev1.Pod) error {
			for i := range items {
				p := &items[i]
				if p.Status.Phase != corev1.PodRunning {
					continue // mirrors the FieldSelector for fake clients
				}
				if !podWantsMesh(p, nsInject[p.Namespace]) {
					continue
				}
				if podHasSidecar(p) {
					continue
				}
				a.unmeshedEmitted.Set(metrics.UnmeshedPods, 1,
					p.Namespace+"/"+p.Name, p.Namespace, p.Name)
				unmeshed++
				log.Info("UNMESHED: pod running without linkerd-proxy sidecar",
					"pod", p.Namespace+"/"+p.Name)
				// Deletion requires a CONTROLLER owner (a bare
				// ownerReference proves nothing is recreating the pod)
				// that is not a Node — mirror pods only reflect a
				// static manifest, deleting one changes nothing — and
				// the pod must not already be terminating: its
				// replacement gets the sidecar at admission, so a
				// second delete buys nothing. The candidate is COPIED
				// out of the page — holding pointers would keep the
				// whole pods.Items backing array reachable until the
				// deletes finish.
				if owner := metav1.GetControllerOf(p); owner != nil &&
					owner.Kind != "Node" &&
					p.DeletionTimestamp.IsZero() &&
					now.Sub(p.CreationTimestamp.Time) >= unmeshedMinPodAge {
					candidates = append(candidates, *p)
				}
			}
			return nil
		})
	if err != nil {
		return fmt.Errorf("list pods — unmeshed audit skipped: %w", err)
	}

	// Prune series for pods that vanished or gained the sidecar —
	// same DeleteLabelValues hygiene as the circuit breaker's ledger.
	a.unmeshedEmitted.Prune(metrics.UnmeshedPods.DeleteLabelValues)

	if len(candidates) == 0 {
		return nil
	}
	if !RemediationEnabled() {
		log.Info("unmeshed remediation disabled (UNMESHED_POD_REMEDIATION_ENABLED=false)",
			"candidates", len(candidates))
		return nil
	}

	// Remediation only runs when the injector is provably back: the
	// webhook not circuit-broken, its declared Fail policy intact,
	// and >= 1 Ready endpoint behind its Service. An unverifiable
	// answer fails closed — a wrong "healthy" verdict deletes pods
	// that would only be recreated unmeshed again.
	healthy, err := a.linkerdInjectorHealthy(snap)
	if err != nil {
		metrics.IncError(g.Queue)
		log.Info("WARN: injector health unverifiable — remediation skipped (fail closed)",
			"error", err, "candidates", len(candidates))
		return nil
	}
	if !healthy {
		log.Info("injector webhook not healthy — remediation deferred",
			"candidates", len(candidates))
		return nil
	}

	// W7-C1 — the maintenance mutex gates the evictions: killing
	// pods mid-drain/upgrade is exactly what the mutex exists to
	// prevent, and "cannot verify" fails closed like every other
	// caller of the shared check.
	held, why, err := g.MaintenanceActive(ctx)
	if err != nil {
		metrics.IncError(g.Queue)
		log.Info("WARN: maintenance check unverifiable — "+
			"DEFER: unmeshed remediation skipped (fail closed)",
			"error", err, "candidates", len(candidates))
		return nil
	}
	if held {
		log.Info("DEFER: maintenance active — unmeshed remediation skipped",
			"why", why, "candidates", len(candidates))
		return nil
	}

	// Deterministic order so the cap picks the same pods.
	slices.SortFunc(candidates, func(a, b corev1.Pod) int {
		return strings.Compare(a.Namespace+"/"+a.Name, b.Namespace+"/"+b.Name)
	})
	deleted, attempts := 0, 0
	for i := range candidates {
		p := &candidates[i]
		if deleted >= unmeshedDeleteCap || attempts >= unmeshedDeleteAttempts {
			break
		}
		attempts++
		log.Info("EVICT: unmeshed pod — owner controller recreates it meshed",
			"pod", p.Namespace+"/"+p.Name,
			"age", now.Sub(p.CreationTimestamp.Time).Truncate(time.Second))
		// The kill goes through the policy/v1 Eviction API, NOT a raw
		// Delete (W7-C1): the apiserver enforces PodDisruptionBudgets
		// and consumes a disruption slot atomically, so an already
		// degraded workload cannot lose its last replica to a
		// cosmetic fix. The UID precondition closes the TOCTOU
		// window between the audit snapshot and the evict — a
		// same-named pod recreated in between was admitted after
		// the injector recovered and is not ours to reap.
		uid := p.UID
		deleteOpts := kube.UIDDeleteOptions(uid, "")
		eviction := &policyv1.Eviction{
			ObjectMeta: metav1.ObjectMeta{
				Name:      p.Name,
				Namespace: p.Namespace,
			},
			DeleteOptions: &deleteOpts,
		}
		if err := g.CS.CoreV1().Pods(p.Namespace).EvictV1(ctx, eviction); err != nil {
			if apierrors.IsTooManyRequests(err) {
				// HTTP 429 — a PDB with disruptionsAllowed==0
				// refused the eviction. That is a deferral, not a
				// failure: the workload is already at its replica
				// floor and killing this pod would finish the
				// outage. Keep it, count no error, move on.
				log.Info("DEFER: PDB refused eviction of unmeshed pod — keeping pod alive",
					"pod", p.Namespace+"/"+p.Name)
				continue
			}
			log.Error(err, "unmeshed pod eviction failed", "pod", p.Namespace+"/"+p.Name)
			metrics.IncError(g.Queue)
			continue
		}
		metrics.UnmeshedPodsRecreatedTotal.WithLabelValues(p.Namespace).Inc()
		deleted++
	}
	log.Info("unmeshed audit done", "unmeshed", unmeshed,
		"candidates", len(candidates), "deleted", deleted)
	return nil
}

// podWantsMesh reports whether the pod opted into linkerd injection:
// the pod's own linkerd.io/inject directive decides first (disabled
// opts out even inside an enabled namespace, enabled opts in even
// inside a disabled one); when the pod says nothing the namespace
// directive applies.
func podWantsMesh(p *corev1.Pod, nsDirective string) bool {
	if p.Spec.HostNetwork {
		return false // hostNetwork pods are never injected
	}
	for _, ref := range p.OwnerReferences {
		if ref.Kind == "Job" || ref.Kind == "CronJob" {
			return false // batch pods are never injected
		}
	}
	switch d := injectDirective(p.Labels, p.Annotations); d {
	case "disabled":
		return false
	case "enabled":
		return true
	default:
		return nsDirective == "enabled"
	}
}

// podHasSidecar reports whether the pod carries a linkerd-proxy
// container or initContainer — the injection signature.
func podHasSidecar(p *corev1.Pod) bool {
	for _, c := range p.Spec.Containers {
		if c.Name == kube.LinkerdProxyContainer {
			return true
		}
	}
	for _, c := range p.Spec.InitContainers {
		if c.Name == kube.LinkerdProxyContainer {
			return true
		}
	}
	return false
}

// injectDirective reads linkerd.io/inject from an object's labels and
// annotations — annotations are checked BEFORE labels and the first
// recognized directive wins (linkerd's own precedence); an absent or
// unrecognized annotation value falls through to the label check, and
// no directive anywhere returns "".
func injectDirective(labels, annotations map[string]string) string {
	for _, m := range []map[string]string{annotations, labels} {
		switch m[kube.LinkerdInjectKey] {
		case "disabled":
			return "disabled"
		case "enabled":
			return "enabled"
		}
	}
	return ""
}

// linkerdInjectorHealthy reports whether the linkerd-proxy-injector
// mutating webhook is fully back: not circuit-broken, failurePolicy
// still Fail (a tripped breaker leaves Ignore behind), and >= 1 Ready
// endpoint behind its backend Service. Any measurement failure is a
// real error — the caller treats "cannot verify" as "not healthy".
// Runs only when unmeshed candidates exist, so its census +
// config-list inputs are drawn from the shared run snapshot (the
// census is computed lazily on first use — see guardstate.Snapshot).
func (a *Auditor) linkerdInjectorHealthy(snap *guardstate.Snapshot) (bool, error) {
	ready, err := snap.ReadyCounts()
	if err != nil {
		return false, err
	}
	if snap.MWCErr != nil {
		return false, fmt.Errorf("list mutatingwebhookconfigurations — injector health unknown: %w", snap.MWCErr)
	}
	mwcs := snap.MWC
	found := false
	for i := range mwcs.Items {
		cfg := &mwcs.Items[i]
		broken := guardstate.ParseCircuitAnnotation(cfg.Annotations[guardstate.CircuitBrokenAnno])
		for _, w := range cfg.Webhooks {
			if w.Name != kube.LinkerdInjectorWebhook {
				continue // exact match — a lookalike name is not the injector
			}
			found = true
			if broken[w.Name] || !guardstate.FailClosed(w.FailurePolicy) {
				continue // circuit-broken (or manually set to Ignore)
			}
			if w.ClientConfig.Service == nil {
				continue
			}
			svc := w.ClientConfig.Service.Namespace + "/" + w.ClientConfig.Service.Name
			// W9-CP1 brownout guard: an effective-ready endpoint set
			// that was probed AND failed every TCP+TLS handshake is
			// hung, not healthy — evicting unmeshed pods now would
			// only recreate them unmeshed again. A service that was
			// never probed gets the benefit of the doubt.
			if ready.Effective[svc] > 0 && (!ready.Probed[svc] || ready.Responsive[svc]) {
				return true, nil
			}
		}
	}
	if !found {
		logf.FromContext(snap.Ctx).Info("injector health: no linkerd-proxy-injector webhook found")
	}
	return false, nil
}

// criticalNSMatcher builds the namespaceSelector predicate the
// critical-ns duties share from the snapshot's namespace census: true
// when the selector still matches (fails to exclude) any of the
// critical self-healing namespaces — nil or malformed selectors match
// everything. ok=false when the shared inputs are missing (a census
// error or nil webhook-config lists); the callers skip their audits
// rather than act on partial state.
func criticalNSMatcher(snap *guardstate.Snapshot) (matches func(*metav1.LabelSelector) bool, ok bool) {
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

// criticalNSMergeExclusion is the matchExpressions block the
// W15-CP0 auto-patch injects into a webhook's namespaceSelector —
// the exact NotIn shape check-webhook-guard.sh demands statically.
// Strategic merge keeps the selector's matchLabels (opt-in
// selectors keep working: matchLabels AND the new expression) and
// replaces any partial NotIn with the full four-namespace list.
func criticalNSMergeExclusion() map[string]any {
	return map[string]any{
		"matchExpressions": []map[string]any{{
			"key":      "kubernetes.io/metadata.name",
			"operator": string(metav1.LabelSelectorOpNotIn),
			"values":   slices.Clone(criticalSelfHealingNamespaces),
		}},
	}
}

// auditCriticalNSExclusions (W12-CP-B) audits live Mutating/Validating
// admission sub-webhooks with failurePolicy=Fail (or nil, which defaults
// to Fail) and emits node_automation_webhook_missing_critical_ns_exclusion=1
// when the sub-webhook's namespaceSelector matches any of the critical
// self-healing namespaces (kube-system, kube-node-lease, node-ops,
// medik8s).
//
// W15-CP0 adds the optional auto-patch (WEBHOOK_CRITICAL_NS_ENFORCE_
// ENABLED=true): each flagged webhook outside the allowlist gets the
// NotIn exclusion injected by strategic-merge patch — one patch per
// config carrying every missing entry, keyed by merge-key name so a
// concurrent writer's sibling entries survive. The ledger re-verifies
// next sweep, so a failed patch only delays the exclusion instead of
// pinning a stale series.
func (a *Auditor) auditCriticalNSExclusions(snap *guardstate.Snapshot) {
	a.criticalNSExclusionEmitted.Begin() // drop any aborted sweep's leftover emissions
	matchesCriticalNS, ok := criticalNSMatcher(snap)
	if !ok {
		return
	}
	log := logf.FromContext(snap.Ctx)
	g := snap.G
	enforce := CriticalNSEnforceEnabled()

	// patchCriticalNS lands the queued merge entries for one config —
	// the orphansweep's mechanics (strategic-merge on the merge-key
	// webhooks list, snapshot kept current for the later duties).
	patchCriticalNS := func(kind string, mutating bool, cfgName string, merges []map[string]any) {
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

	for i := range snap.MWC.Items {
		cfg := &snap.MWC.Items[i]
		var merges []map[string]any
		for j := range cfg.Webhooks {
			w := &cfg.Webhooks[j]
			if !guardstate.FailClosed(w.FailurePolicy) || !matchesCriticalNS(w.NamespaceSelector) {
				continue
			}
			a.criticalNSExclusionEmitted.Set(metrics.WebhookMissingCriticalNSExclusion, 1,
				guardstate.KindMutating+"/"+cfg.Name+"/"+w.Name,
				guardstate.KindMutating, cfg.Name, w.Name)
			if enforce && !criticalNSPatchAllowlist[cfg.Name+"/"+w.Name] {
				merges = append(merges, map[string]any{
					"name": w.Name, "namespaceSelector": criticalNSMergeExclusion()})
			}
		}
		patchCriticalNS(guardstate.KindMutating, true, cfg.Name, merges)
	}
	for i := range snap.VWC.Items {
		cfg := &snap.VWC.Items[i]
		var merges []map[string]any
		for j := range cfg.Webhooks {
			w := &cfg.Webhooks[j]
			if !guardstate.FailClosed(w.FailurePolicy) || !matchesCriticalNS(w.NamespaceSelector) {
				continue
			}
			a.criticalNSExclusionEmitted.Set(metrics.WebhookMissingCriticalNSExclusion, 1,
				guardstate.KindValidating+"/"+cfg.Name+"/"+w.Name,
				guardstate.KindValidating, cfg.Name, w.Name)
			if enforce && !criticalNSPatchAllowlist[cfg.Name+"/"+w.Name] {
				merges = append(merges, map[string]any{
					"name": w.Name, "namespaceSelector": criticalNSMergeExclusion()})
			}
		}
		patchCriticalNS(guardstate.KindValidating, false, cfg.Name, merges)
	}
	a.criticalNSExclusionEmitted.Prune(metrics.WebhookMissingCriticalNSExclusion.DeleteLabelValues)
}

// auditHeartbeatResources (W15-CP0) audits live Mutating/Validating
// admission sub-webhooks with failurePolicy=Fail (or the nil default)
// whose rules[].resources intercept a heartbeat-path resource while the
// namespaceSelector still matches a critical self-healing namespace,
// emitting node_automation_webhook_heartbeat_resource_exposed
// {kind,name,webhook,resource}=1 per matched rule resource (the literal
// — wildcards stay wildcards, matching the static guard's grammar).
// A selector that already excludes the critical namespaces emits
// nothing: the webhook can still wedge itself, but it can no longer
// wedge the cluster's self-healing path.
func (a *Auditor) auditHeartbeatResources(snap *guardstate.Snapshot) {
	a.heartbeatResourceEmitted.Begin() // drop any aborted sweep's leftover emissions
	matchesCriticalNS, ok := criticalNSMatcher(snap)
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
				a.heartbeatResourceEmitted.Set(metrics.WebhookHeartbeatResourceExposed, 1,
					kind+"/"+cfgName+"/"+hookName+"/"+res,
					kind, cfgName, hookName, res)
			}
		}
	}
	for i := range snap.MWC.Items {
		cfg := &snap.MWC.Items[i]
		for j := range cfg.Webhooks {
			w := &cfg.Webhooks[j]
			if !guardstate.FailClosed(w.FailurePolicy) || !matchesCriticalNS(w.NamespaceSelector) {
				continue
			}
			emitWebhook(guardstate.KindMutating, cfg.Name, w.Name, w.Rules)
		}
	}
	for i := range snap.VWC.Items {
		cfg := &snap.VWC.Items[i]
		for j := range cfg.Webhooks {
			w := &cfg.Webhooks[j]
			if !guardstate.FailClosed(w.FailurePolicy) || !matchesCriticalNS(w.NamespaceSelector) {
				continue
			}
			emitWebhook(guardstate.KindValidating, cfg.Name, w.Name, w.Rules)
		}
	}
	a.heartbeatResourceEmitted.Prune(metrics.WebhookHeartbeatResourceExposed.DeleteLabelValues)
}
