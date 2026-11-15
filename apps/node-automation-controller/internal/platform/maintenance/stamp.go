// stamp.go — the Cluster Maintenance Mutex WRITE half:
// StampMaintenanceTargets converges every node's
// cluster-maintenance-until annotation toward the active target set
// (the L1↔L3 coordination hint node-host-agents read). Deliberately
// separate from the read-only MaintenanceActive verdict so a "does
// maintenance hold?" query can never patch Nodes as a side effect.
package maintenance

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

// maintenanceStampCordonMaxAge is the cordon-freshness horizon the
// STAMP path applies — wider than the verdict's nodeCordonActiveMaxAge
// (45m) because the stamp is a hold-hint for node-host-agents, not
// the mutex itself: over-holding a static cordon costs agents a few
// deferred local actions, under-holding resumes them mid-drain.
const maintenanceStampCordonMaxAge = 2 * time.Hour

// maintenanceStampTTL is how far out the cluster-maintenance-until
// annotation reaches — refreshed on every held verdict (the Verdict
// memo bounds that to ~1/min), self-expiring if the controller
// dies mid-maintenance. 15m covers the agent's ~30s annotation
// cache with generous slack for a missed refresh.
const maintenanceStampTTL = 15 * time.Minute

// maintenanceStampRefreshFloor skips the node patch when the node's
// existing stamp already reaches past now+10m — the eval runs ~1/min
// while held, so without the floor every stamped node would take a
// merge patch every minute for the whole drain.
const maintenanceStampRefreshFloor = 10 * time.Minute

// remediationNodeNameAnno is the annotation medik8s NHC (>= v0.6)
// stamps on remediation CRs it names "<nodeName>-<templateName>" —
// the CR name no longer equals the node name, so the annotation
// carries the fencing target (same key deadnodesweeper reads; kept
// private here because platform cannot import the domain package).
const remediationNodeNameAnno = "remediation.medik8s.io/node-name"

// StampMaintenanceTargets is the L1↔L3 coordination WRITE half of
// the maintenance mutex — deliberately separate from the read-only
// MaintenanceActive verdict so a "does maintenance hold?" query can
// never patch Nodes as a side effect. Each pass converges every
// node's cluster-maintenance-until annotation toward the active
// target set:
//
//   - actively-cordoned nodes and nodes named by live medik8s
//     remediation CRs stamp INDIVIDUALLY — a single-node SNR must
//     not freeze every node's L1 self-heal;
//   - a live autopilot Plan or kured lock is cluster-wide by
//     nature (upgrade / reboot drain) — every node takes the stamp;
//   - a node OUTSIDE the target set has its stamp REMOVED when the
//     value is one this controller could have written — maintenance
//     ending must not leave agents paused on a stale window, and
//     waiting out the 15m TTL would extend every drain's tail by
//     that much. The unstamp keys off the STAMP target computation
//     (2h cordon horizon), never the 45m verdict window: a node
//     cordoned 90m is still mid-drain for stamping purposes.
//
// Best-effort by contract: per-node patch errors are swallowed (a
// failed stamp costs one agent cache window, never a wrong verdict)
// and target-collection read failures degrade to fewer STAMP
// targets — but a degraded read also disables the unstamp half:
// removing a hold on a signal we failed to observe is the one
// direction that must fail closed.
func StampMaintenanceTargets(ctx context.Context, cs kubernetes.Interface,
	dyn dynamic.Interface, nodeReader kube.CachedNodeReader, now time.Time) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	nodes, err := kube.ListNodesCached(ctx, nodeReader, cs)
	if err != nil {
		return
	}
	all, names, complete := maintenanceStampTargets(ctx, cs, dyn, nodes, now)
	if !all && len(names) == 0 && !complete {
		return // degraded read, nothing to stamp, unstamp unsafe
	}
	stamp := now.Add(maintenanceStampTTL).UTC().Format(time.RFC3339)
	floor := now.Add(maintenanceStampRefreshFloor)
	var stampPatch, unstampPatch []byte
	for i := range nodes {
		n := &nodes[i]
		if all || names[n.Name] {
			if t, ok := kube.ParseAnnoTime(n.Annotations[nodecond.AnnoClusterMaintenanceUntil]); ok &&
				t.After(floor) {
				continue // stamp fresh enough — skip the write
			}
			if stampPatch == nil {
				var perr error
				stampPatch, perr = kube.MergePatchAnnos(map[string]any{
					nodecond.AnnoClusterMaintenanceUntil: stamp,
				})
				if perr != nil {
					return
				}
			}
			_, _ = cs.CoreV1().Nodes().Patch(ctx, n.Name,
				types.MergePatchType, stampPatch, metav1.PatchOptions{})
			continue
		}
		if !complete {
			continue // a signal read failed — never drop a hold blind
		}
		v, ok := n.Annotations[nodecond.AnnoClusterMaintenanceUntil]
		if !ok || !controllerOwnedStamp(v, now) {
			continue // absent, or a value this controller did not write
		}
		if unstampPatch == nil {
			var perr error
			unstampPatch, perr = kube.MergePatchAnnos(map[string]any{
				nodecond.AnnoClusterMaintenanceUntil: nil,
			})
			if perr != nil {
				return
			}
		}
		_, _ = cs.CoreV1().Nodes().Patch(ctx, n.Name,
			types.MergePatchType, unstampPatch, metav1.PatchOptions{})
	}
}

// controllerOwnedStamp reports whether an annotation value has the
// shape THIS controller writes: an RFC3339 timestamp no further out
// than the stamp TTL plus a minute of slack. The stamp
// carries no owner field, so ownership is the value domain — a
// parseable timestamp inside the writable window is a stamp we (or
// a previous replica of us) could have written; anything else (a
// hand-set sentinel, another tool's format, a far-future "forever"
// mark) is left untouched. Past timestamps pass: an expired stamp
// is dead weight regardless of which replica wrote it, and removing
// it cannot extend a hold. The one-minute slack covers write/read
// clock skew between replicas — a live stamp's value is always
// <= its write time + TTL, so now+TTL+1m is the widest value this
// controller can legitimately have on a node.
func controllerOwnedStamp(value string, now time.Time) bool {
	t, ok := kube.ParseAnnoTime(value)
	if !ok {
		return false
	}
	return !t.After(now.Add(maintenanceStampTTL + time.Minute))
}

// maintenanceStampTargets resolves which nodes the active
// maintenance signals cover for the STAMP path — the 2h cordon
// horizon wrapper over the shared maintenanceTargets resolver
// Verdict.Scope also uses (at the narrower 45m verdict window).
func maintenanceStampTargets(ctx context.Context, cs kubernetes.Interface,
	dyn dynamic.Interface, nodes []corev1.Node, now time.Time) (all bool,
	names map[string]bool, complete bool) {
	all, names, complete, _ = maintenanceTargets(ctx, cs, dyn, nodes,
		now, maintenanceStampCordonMaxAge)
	return all, names, complete
}

// maintenanceTargets is the shared target resolver behind both the
// stamp writer (2h cordon horizon) and the Verdict.Scope read (45m
// verdict horizon): cordon-fresh nodes, kured-lock targets and live
// medik8s remediation targets land in `names`, cluster-wide signals
// (autopilot Plan, unscoped kured lock, an unresolvable medik8s CR)
// land in `all`. Read failures degrade to "no targets" per source —
// stamping is a hint — but they also clear `complete` so callers
// that unstamp or fail closed can tell a degraded read apart;
// Scope maps !complete to its unverifiable error. The fourth return
// is the first held signal's evidence string in the canonical
// a→b→c→d order — the stamp path ignores it.
func maintenanceTargets(ctx context.Context, cs kubernetes.Interface,
	dyn dynamic.Interface, nodes []corev1.Node, now time.Time,
	cordonMaxAge time.Duration) (all bool,
	names map[string]bool, complete bool, why string) {
	names = map[string]bool{}
	complete = true
	var whyCordon, whyKured, whyAutopilot, whyMedik8s string
	nodeNames := map[string]bool{}
	for i := range nodes {
		nodeNames[nodes[i].Name] = true
		// The stamp horizon is wider than the verdict's 45m:
		// a node cordoned for up to 2h is still inside its
		// drain window for stamping purposes — agents holding
		// local remediation longer than the verdict needs is
		// cheap, resuming it mid-drain is not.
		if kube.NodeCordonedFresh(&nodes[i], now, cordonMaxAge) {
			names[nodes[i].Name] = true
			if whyCordon == "" {
				whyCordon = "node " + nodes[i].Name + " actively cordoned"
			}
		}
	}
	if dyn == nil {
		// The Plan and medik8s signals are unverifiable without a
		// dynamic client — same fail-closed rule as the verdict.
		complete = false
	} else {
		for _, gvr := range kube.Medik8sRemediationGVRs {
			items, err := listLiveMedik8s(ctx, dyn, gvr, now)
			if err != nil {
				complete = false
				continue // list failure — no targets from it
			}
			for i := range items {
				n := medik8sTargetNode(&items[i], nodeNames)
				// Only a target that resolves to a LIVE node scopes
				// the hold — the annotation path returns its raw
				// value, so a remediation naming an already-deleted
				// (or garbage) node cannot be pinned to a census
				// entry and degrades to the cluster-wide hold.
				if n != "" && nodeNames[n] {
					names[n] = true
				} else {
					// A live remediation CR we cannot scope
					// to any node must hold EVERYTHING —
					// dropping it would read "no maintenance"
					// while fencing is in flight.
					all = true
				}
				if whyMedik8s == "" {
					obj := &items[i]
					kind := obj.GetKind()
					if kind == "" {
						kind = gvr.Resource
					}
					whyMedik8s = fmt.Sprintf("medik8s remediation %s %s in flight",
						kind, obj.GetNamespace()+"/"+obj.GetName())
				}
			}
		}
		if plans, err := activeAutopilotPlans(ctx, dyn); err != nil {
			complete = false
		} else {
			for i := range plans {
				all = true // cluster upgrade — every node holds
				if whyAutopilot == "" {
					state, _ := kube.NestedString(plans[i].Object, "status", "state")
					whyAutopilot = fmt.Sprintf("autopilot plan %s state=%s",
						plans[i].GetName(), state)
				}
			}
		}
	}
	if holder, err := kuredLockHolder(ctx, cs); err == nil {
		if holder != "" {
			// kured's lock names the node it is draining when the
			// value resolves to a live node — stamp only that
			// target instead of holding the whole cluster for one
			// node's reboot window. An unresolvable value
			// (timestamp/identity, or the node already deleted)
			// cannot be scoped, so it degrades to the conservative
			// cluster-wide hold the verdict already uses.
			if nodeNames[holder] {
				names[holder] = true
			} else {
				all = true
			}
			whyKured = "kured lock held by " + holder
		}
	} else {
		complete = false
	}
	// Canonical a→b→c→d evidence order — the same "first held
	// signal answers" contract the short-circuit verdict kept.
	for _, w := range []string{whyCordon, whyKured, whyAutopilot, whyMedik8s} {
		if w != "" {
			why = w
			break
		}
	}
	return all, names, complete, why
}

// medik8sTargetNode extracts the node a remediation CR works on:
// the remediation.medik8s.io/node-name annotation first (NHC >=
// v0.6 names CRs "<node>-<template>"), then the CR name itself —
// exact node-name match, or the LONGEST "<node>-<suffix>" prefix
// for older named-template setups ("worker-1-gpu-x" resolves to
// node "worker-1-gpu", not the shorter "worker-1").
func medik8sTargetNode(obj *unstructured.Unstructured,
	nodeNames map[string]bool) string {
	if n := obj.GetAnnotations()[remediationNodeNameAnno]; n != "" {
		return n
	}
	name := obj.GetName()
	if nodeNames[name] {
		return name
	}
	// Longest matching "<node>-<suffix>" prefix wins: map iteration
	// order is random, so returning the FIRST prefix hit could pick
	// "worker-1" for CR "worker-1-gpu-reboot" when node "worker-1-gpu"
	// also exists — stamping/holding the wrong node. The longest
	// prefix is the most specific node name the CR name can encode.
	best := ""
	for nn := range nodeNames {
		if strings.HasPrefix(name, nn+"-") && len(nn) > len(best) {
			best = nn
		}
	}
	return best
}
