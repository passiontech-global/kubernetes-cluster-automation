// stamp.go — the Cluster Maintenance Mutex WRITE half:
// StampMaintenanceTargets converges every node's
// cluster-maintenance-until annotation toward the active target set
// (the L1↔L3 coordination hint node-host-agents read). Deliberately
// separate from the read-only MaintenanceActive verdict so a "does
// maintenance hold?" query can never patch Nodes as a side effect.
package maintenance

import (
	"context"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
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
// maintenance signals cover, plus whether every consulted signal
// read succeeded. Read failures degrade to "no targets" per source —
// stamping is a hint, and the held verdict that triggered this call
// already proved maintenance is real — but they also clear `complete`
// so the caller skips the unstamp half: dropping a hold on a signal
// we could not observe is the unsafe direction.
func maintenanceStampTargets(ctx context.Context, cs kubernetes.Interface,
	dyn dynamic.Interface, nodes []corev1.Node, now time.Time) (all bool,
	names map[string]bool, complete bool) {
	names = map[string]bool{}
	complete = true
	nodeNames := map[string]bool{}
	for i := range nodes {
		nodeNames[nodes[i].Name] = true
		// The stamp horizon is wider than the verdict's 45m:
		// a node cordoned for up to 2h is still inside its
		// drain window for stamping purposes — agents holding
		// local remediation longer than the verdict needs is
		// cheap, resuming it mid-drain is not.
		if kube.NodeCordonedFresh(&nodes[i], now, maintenanceStampCordonMaxAge) {
			names[nodes[i].Name] = true
		}
	}
	if dyn == nil {
		// The Plan and medik8s signals are unverifiable without a
		// dynamic client — same fail-closed rule as the verdict.
		complete = false
	} else {
		for _, gvr := range kube.Medik8sRemediationGVRs {
			items, err := kube.ListAllUnstructured(ctx, dyn.Resource(gvr),
				metav1.ListOptions{Limit: kube.DefaultListPageSize})
			switch {
			case err == nil:
			case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
				continue // absent CRD — no targets, still complete
			default:
				complete = false
				continue // list failure — no targets from it
			}
			for i := range items.Items {
				obj := &items.Items[i]
				if gvr == kube.GVRNodeMaintenance {
					if phase, _ := kube.NestedString(
						obj.Object, "status", "phase"); phase == "Succeeded" {
						continue
					}
				}
				if n := medik8sTargetNode(obj, nodeNames); n != "" {
					names[n] = true
				}
			}
		}
		plans, err := kube.ListAllUnstructured(ctx,
			dyn.Resource(kube.AutopilotPlanGVR),
			metav1.ListOptions{Limit: kube.DefaultListPageSize})
		switch {
		case err == nil:
			for i := range plans.Items {
				state, _ := kube.NestedString(
					plans.Items[i].Object, "status", "state")
				if state != "Schedulable" && state != "Completed" {
					all = true // cluster upgrade — every node holds
					break
				}
			}
		case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
			// autopilot CRD absent — no targets, still complete
		default:
			complete = false
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
		}
	} else {
		complete = false
	}
	return all, names, complete
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
