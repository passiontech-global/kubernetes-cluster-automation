// critical_daemonset_starvation.go — the critical-daemonset-
// starvation check (P0.2a): infrastructure DaemonSets that can
// never schedule — desiredNumberScheduled == 0 — or that still
// select nodes through DEPRECATED label keys (beta.kubernetes.io/*,
// failure-domain.beta.kubernetes.io/*, the bare "master" role
// label). Both signatures mean pods that must run on every node
// (CNI agents, CSI node plugins, kube-proxy, log/monitor agents)
// are silently absent on the whole fleet or a subset — the exact
// shape of the "DaemonSet desiredNumberScheduled=0" production
// incident and the deprecated-selector scheduling wedge.
//
// Evidence per DaemonSet (typed census, cluster-wide):
//   - desiredNumberScheduled == 0 (status field — the API's own
//     count of nodes the DS wants pods on; 0 means the selector
//     matched nothing or every node is excluded),
//   - nodeSelector keys or nodeAffinity matchExpressions carrying a
//     deprecated label key.
//
// The desired==0 signature must persist criticalDSMinAge (in-RAM
// first-seen) before it flags; deprecated selectors flag
// immediately (they are static config, not a transient).
//
// Heal: when a flagged DS's deprecated-selector wedge can be
// unblocked by compat labels, the check patches the missing
// one-way compat labels onto the nodes the DS should cover —
// master="" for control-plane nodes, beta.kubernetes.io/os|arch
// from kubernetes.io/os|arch, failure-domain.beta.kubernetes.io/
// zone|region from topology.kubernetes.io/* — the same sync
// nodelabeler's P0.2b pass maintains. Cooldown-gated per DS,
// maintenance-mutex gated, gauge + Event always.
package watchdogs

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// criticalDaemonSetStarvationCheck is the DS starvation detector +
// compat-label healer.
type criticalDaemonSetStarvationCheck struct {
	*probefw.Deps

	// seen tracks each zero-desired DS's first-seen sweep — the
	// persistence window; pruned on recovery so a later starvation
	// re-arms.
	seen state.FirstSeenLedger
	// emitted is the emitted-gauge ledger.
	emitted state.GaugeLedger[string]
	// eventHealed dedupes the cluster Event per window.
	eventHealed state.CooldownSet
}

// NewCriticalDaemonSetStarvationCheck builds the check.
func NewCriticalDaemonSetStarvationCheck(d *probefw.Deps) probefw.Check {
	return &criticalDaemonSetStarvationCheck{Deps: d}
}

const (
	CheckNameCriticalDSStarvation = "critical-daemonset-starvation"

	// A zero-desired signature must hold this long before it flags
	// — a node drain or a rolling cordon legitimately drops desired
	// counts transiently.
	criticalDSMinAge = 5 * time.Minute
	// One cluster Event per window.
	criticalDSEventCooldown = 30 * time.Minute
	// Compat-label heal cooldown per DaemonSet.
	criticalDSHealCooldown = 30 * time.Minute
)

var (
	// critical-daemonset-starvation — 1 per wedged DaemonSet,
	// labelled by reason (zero_desired / deprecated_selector).
	criticalDSStarvationGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_critical_daemonset_starvation",
		Help: "1 while an infrastructure DaemonSet reports desiredNumberScheduled=0 or selects nodes via deprecated label keys — critical-daemonset-starvation.",
	}, []string{"namespace", "name", "reason"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(criticalDSStarvationGauge)
}

// deprecatedLabelPrefixes are the label-key prefixes/k8s role keys
// that modern node labelling replaced — a DaemonSet selecting on
// them starves on nodes that only carry the GA keys.
var deprecatedLabelPrefixes = []string{
	"beta.kubernetes.io/",
	"failure-domain.beta.kubernetes.io/",
}

// deprecatedLabelKeys are the exact deprecated keys (no prefix
// match): the pre-GA control-plane role labels, in both spellings
// (node-role.kubernetes.io/master is canonical; the bare "master"
// survives in older manifests).
var deprecatedLabelKeys = map[string]bool{
	"master":                         true,
	"node-role.kubernetes.io/master": true,
}

// isDeprecatedLabelKey reports whether key is a deprecated node
// label a scheduler selector must not depend on.
func isDeprecatedLabelKey(key string) bool {
	if deprecatedLabelKeys[key] {
		return true
	}
	for _, p := range deprecatedLabelPrefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

// dsDeprecatedSelectorKeys returns the deprecated label keys the
// DaemonSet's nodeSelector + nodeAffinity still reference.
func dsDeprecatedSelectorKeys(ds *appsv1.DaemonSet) []string {
	var keys []string
	seen := map[string]bool{}
	add := func(k string) {
		if isDeprecatedLabelKey(k) && !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	for k := range ds.Spec.Template.Spec.NodeSelector {
		add(k)
	}
	if aff := ds.Spec.Template.Spec.Affinity; aff != nil &&
		aff.NodeAffinity != nil {
		na := aff.NodeAffinity
		var terms []corev1.NodeSelectorTerm
		if na.RequiredDuringSchedulingIgnoredDuringExecution != nil {
			terms = append(terms,
				na.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms...)
		}
		for _, p := range na.PreferredDuringSchedulingIgnoredDuringExecution {
			terms = append(terms, p.Preference)
		}
		for _, term := range terms {
			for _, expr := range term.MatchExpressions {
				add(expr.Key)
			}
		}
	}
	return keys
}

// compatLabelsForNode derives the one-way GA→deprecated compat
// label pairs a node should carry — the shared mapping in
// kube.CompatNodeLabels (the same sync nodelabeler's P0.2b pass
// maintains).
func compatLabelsForNode(n *corev1.Node) map[string]string {
	return kube.CompatNodeLabels(n.Labels)
}

// Run audits every DaemonSet for the starvation signatures and
// heals the compat-label half of the deprecated-selector wedge.
func (p *criticalDaemonSetStarvationCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	p.eventHealed.PruneExpired(now, criticalDSEventCooldown)
	var rep probefw.SweepReport

	dss, err := p.AllDaemonSets(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list daemonsets: %w", err)}
	}
	seenKeep := map[string]bool{}
	healCandidates := map[string][]string{} // dsKey → deprecated keys
	starved := false
	for i := range dss {
		ds := &dss[i]
		key := ds.Namespace + "/" + ds.Name
		var reasons []string
		if ds.Status.DesiredNumberScheduled == 0 && ds.Generation > 0 &&
			!dsHasNodeRestriction(ds) {
			// generation>0 guards a just-created DS whose status
			// has not been populated yet — desired=0 there is
			// "not yet counted", not starvation. A DS carrying its
			// own nodeSelector/required-affinity (GPU pools, zone
			// pins) legitimately desires 0 when no node matches —
			// flagging it is a false positive; only an
			// unrestricted DS wanting every node can starve.
			first, _ := p.seen.Observe("ds/"+key, now)
			seenKeep[key] = true
			if now.Sub(first) >= criticalDSMinAge {
				reasons = append(reasons, "zero_desired")
				starved = true
			}
		} else {
			p.seen.Forget("ds/" + key)
		}
		if dep := dsDeprecatedSelectorKeys(ds); len(dep) > 0 {
			reasons = append(reasons, "deprecated_selector")
			healCandidates[key] = dep
		}
		if len(reasons) == 0 {
			continue
		}
		for _, reason := range reasons {
			rep.Flag(criticalDSStarvationGauge, key+"/"+reason,
				[]string{ds.Namespace, ds.Name, reason})
		}
		rep.Find(key + "(" + strings.Join(reasons, ",") + ")")
	}
	p.seen.Prune(func(k string) bool {
		return seenKeep[strings.TrimPrefix(k, "ds/")]
	})

	if starved || len(healCandidates) > 0 {
		// The event fires on ANY persisted starvation finding —
		// gating it on healCandidates alone meant a pure
		// zero_desired wedge (no deprecated keys to heal) was
		// flagged in metrics but never paged.
		p.emitStarvationEvent(ctx, log, rep.Findings(), now)
	}
	if len(healCandidates) > 0 {
		p.healCompatLabels(ctx, log, healCandidates, now)
	}
	return rep.Result(&p.emitted, criticalDSStarvationGauge.DeleteLabelValues,
		"critical daemonsets starved: ", ", ")
}

// dsHasNodeRestriction reports whether the DS scopes itself to a
// subset of nodes — a non-empty nodeSelector or a required
// nodeAffinity term. Such a DS desiring zero pods is a scheduling
// answer, not starvation.
func dsHasNodeRestriction(ds *appsv1.DaemonSet) bool {
	if len(ds.Spec.Template.Spec.NodeSelector) > 0 {
		return true
	}
	na := ds.Spec.Template.Spec.Affinity
	if na == nil || na.NodeAffinity == nil {
		return false
	}
	// RequiredDuringScheduling is a *NodeSelector — a DS carrying
	// only preferredDuringScheduling terms (or an empty
	// nodeAffinity: {}) leaves it nil; dereferencing would panic
	// the whole sweep.
	req := na.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution
	return req != nil && len(req.NodeSelectorTerms) > 0
}

// healCompatLabels patches the missing compat labels onto every
// node for each flagged DaemonSet — bounded by the per-DS cooldown
// and the shared maintenance mutex. Nodes are patched through the
// typed merge patch (labels map merge), never a replace.
func (p *criticalDaemonSetStarvationCheck) healCompatLabels(ctx context.Context,
	log logr.Logger, candidates map[string][]string, now time.Time) {

	nodes, err := p.AllNodes(ctx)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: critical DS starvation node census failed", "error", err)
		return
	}
	overlay := map[string]map[string]string{}
	for key, depKeys := range candidates {
		// Pre-compute WHICH nodes actually miss a needed label —
		// spending the HealAllowed grant before this check burned
		// a budget token on DaemonSets whose deprecated keys every
		// node already satisfies (post-heal steady state).
		type nodePatch struct {
			name string
			need map[string]string
		}
		var queue []nodePatch
		for i := range nodes {
			n := &nodes[i]
			compat := compatLabelsForNode(n)
			// Only patch labels the DS actually needs — deriving
			// the full set on every node would stamp compat twins
			// the cluster does not use (noise, not healing). The
			// bare "master" key sits in the same compat map.
			needed := map[string]string{}
			for _, dk := range depKeys {
				v, ok := compat[dk]
				if !ok {
					continue
				}
				// Already labelled (on shared node snapshot or this sweep's overlay).
				if cur, has := n.Labels[dk]; has && cur == v {
					continue
				}
				if cur, has := overlay[n.Name][dk]; has && cur == v {
					continue
				}
				needed[dk] = v
			}
			if len(needed) == 0 {
				continue
			}
			queue = append(queue, nodePatch{name: n.Name, need: needed})
		}
		if len(queue) == 0 {
			continue // nothing to heal — no grant spent
		}
		ck := probefw.SelfHealKey(CheckNameCriticalDSStarvation, key)
		proceed, unverifiable := p.HealAllowed(ctx, log, &p.Heals,
			ck, criticalDSHealCooldown, now)
		switch {
		case unverifiable:
			metrics.IncError(p.Name)
			return
		case !proceed:
			continue
		}
		patched := 0
		for _, np := range queue {
			patch := []byte(fmt.Sprintf(
				`{"metadata":{"labels":%s}}`, mustJSONMap(np.need)))
			if _, err := p.CS.CoreV1().Nodes().Patch(ctx, np.name,
				types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
				metrics.IncError(p.Name)
				log.Error(err, "critical DS starvation compat-label patch failed",
					"node", np.name, "daemonset", key)
				continue
			}
			patched++
			if overlay[np.name] == nil {
				overlay[np.name] = map[string]string{}
			}
			for k, v := range np.need {
				overlay[np.name][k] = v
			}
		}
		if patched > 0 {
			p.Heals.Stamp(ck, now)
			p.InvalidateNodes(ctx)
			log.Info("ACTION: patched compat labels for starved daemonset",
				"daemonset", key, "deprecatedKeys", depKeys, "nodesPatched", patched)
		}
	}
}

// mustJSONMap renders a string map as a JSON object literal for
// merge-patch embedding — values are label strings (no escaping
// surprises beyond what encoding/json handles).
func mustJSONMap(m map[string]string) string {
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// emitStarvationEvent fires ONE deduped Warning event per window
// naming the wedged DaemonSets.
func (p *criticalDaemonSetStarvationCheck) emitStarvationEvent(ctx context.Context,
	log logr.Logger, findings []string, now time.Time) {

	if len(findings) == 0 {
		return
	}
	ck := probefw.SelfHealKey(CheckNameCriticalDSStarvation, "event")
	if p.eventHealed.CooledDown(ck, criticalDSEventCooldown, now) {
		return
	}
	msg := "critical daemonset starvation: " + findings[0]
	if len(findings) > 1 {
		msg = fmt.Sprintf("critical daemonset starvation: %d daemonsets (%s, +%d more)",
			len(findings), findings[0], len(findings)-1)
	}
	if err := kube.EmitWarningEvent(ctx, p.CS, kube.WarningEvent{
		Name:      "critical-ds-starvation-" + now.Format("20060102-150405"),
		Namespace: "kube-system",
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Namespace",
			Name:       "kube-system",
		},
		Reason:            "CriticalDaemonSetStarvation",
		Note:              msg,
		ReportingInstance: p.Name,
		Now:               now,
	}); err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: critical DS starvation event create failed (RBAC?)",
			"error", err)
		return
	}
	p.eventHealed.Stamp(ck, now)
	log.Info("EVENT: CriticalDaemonSetStarvation", "detail", msg)
}
