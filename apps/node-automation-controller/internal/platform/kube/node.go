// node.go — Node helpers shared by several modules: condition/role
// reads, taint predicates and the JSON-merge taint/label patchers,
// plus the single place direct node listing happens (ListNodes; the
// storm-gate census rides the cached twin in nodes_cached.go).
package kube

import (
	"context"
	"encoding/json"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
)

// ---------------------------------------------------------------------------
// Node helpers — taints/conditions/labels shared by several modules.
// ---------------------------------------------------------------------------

// NodeCondition returns the node's condition of type t, or nil.
func NodeCondition(n *corev1.Node, t corev1.NodeConditionType) *corev1.NodeCondition {
	for i := range n.Status.Conditions {
		if n.Status.Conditions[i].Type == t {
			return &n.Status.Conditions[i]
		}
	}
	return nil
}

// NodeReady reports whether the node's Ready condition is True.
func NodeReady(n *corev1.Node) bool {
	c := NodeCondition(n, corev1.NodeReady)
	return c != nil && c.Status == corev1.ConditionTrue
}

// IsControlPlane reports whether the node carries a control-plane role
// label (k0s control planes run no kubelet workload).
func IsControlPlane(n *corev1.Node) bool {
	_, cp := n.Labels["node-role.kubernetes.io/control-plane"]
	_, m := n.Labels["node-role.kubernetes.io/master"]
	return cp || m
}

// HasTaint reports whether taints contains an entry with the given key
// (any effect — `kubectl taint node <n> <key>-` removes all effects).
func HasTaint(taints []corev1.Taint, key string) bool {
	for _, t := range taints {
		if t.Key == key {
			return true
		}
	}
	return false
}

// UnschedulableTaintKey is the taint the cordon path stamps alongside
// spec.unschedulable — its TimeAdded is the only clock for "how long
// has this cordon been live".
const UnschedulableTaintKey = "node.kubernetes.io/unschedulable"

// nodeCordonActiveMaxAge is how old a cordon may be before it reads as
// deliberate static state rather than a drain in flight.
const nodeCordonActiveMaxAge = 45 * time.Minute

// NodeActivelyCordoned reports whether the node is cordoned AND the
// cordon looks like a drain in flight — spec.unschedulable plus the
// node.kubernetes.io/unschedulable taint younger than
// nodeCordonActiveMaxAge (or timestamp-less: unverifiable fails
// closed). A statically-cordoned node — unschedulable held past the
// window — does NOT count: long-cordoned nodes are an operator
// decision (decommissioned capacity, quarantined hardware), not a
// drain, and treating them as "maintenance in flight" freezes every
// remediation that defers to it forever. Neither does a node
// carrying AnnoPreCordonedBy: the node-hang precordon is the
// controller's OWN defensive cordon of a degraded worker, and its
// fresh unschedulable taint would otherwise read as a 45m operator
// drain and lock every heal.AllowedV-gated remediation cluster-wide
// exactly while the cluster is sick (node-hang-precordon — self-inflicted
// maintenance lockout).
func NodeActivelyCordoned(n *corev1.Node, now time.Time) bool {
	if !n.Spec.Unschedulable {
		return false
	}
	// W19-T2: a node fenced by remediation (SNR reclaim, nodehealth
	// hang verdict, partition-evictor, cpu-steal) carries BOTH the
	// unschedulable spec flag and a remediation taint — that is NOT
	// an operator drain, and counting it as one freezes every
	// heal.AllowedV-gated remediation for 45m exactly while the node
	// needs recovery. Only remediation taints exempt; the plain
	// out-of-service unschedulable taint still counts as cordon.
	if HasRemediationTaint(n) {
		return false
	}
	if n.Annotations[AnnoPreCordonedBy] != "" {
		return false
	}
	for _, t := range n.Spec.Taints {
		if t.Key != UnschedulableTaintKey {
			continue
		}
		if t.TimeAdded == nil {
			return true // cordon timestamp unverifiable — fail closed
		}
		return now.Sub(t.TimeAdded.Time) < nodeCordonActiveMaxAge
	}
	// unschedulable without the companion taint — the age cannot be
	// verified, so it counts (fail closed, same as a nil TimeAdded).
	return true
}

// dropTaintsByKey returns taints with every entry matching key
// removed. It filters IN PLACE — the result aliases and shortens the
// caller's backing array, so the input must not be shared or
// informer-cache-owned. Callers must pass a slice they own (today
// every call site hands over .spec.taints of a fresh Get, which the
// apiserver decodes per call).
func dropTaintsByKey(taints []corev1.Taint, key string) []corev1.Taint {
	out := taints[:0]
	changed := false
	for _, t := range taints {
		if t.Key != key {
			out = append(out, t)
		} else {
			changed = true
		}
	}
	if changed {
		// Zero the tail — the filtered entries would otherwise stay
		// reachable (and their strings uncollectable) through the
		// shared backing array.
		clear(taints[len(out):])
	}
	return out
}

// patchNodeTaints replaces .spec.taints on a node via JSON Merge Patch
// — the merge semantics create the key when absent (a never-tainted
// node has no "taints" field, so a JSONPatch "replace" would be
// rejected) and arrays are replaced wholesale, which is exactly what
// callers pass (the full desired taint list). The patch pins
// metadata.resourceVersion: the whole-array replace makes a
// concurrent taint writer (kubelet, another controller) a conflict
// the caller retries instead of silently reverting.
func patchNodeTaints(ctx context.Context, cs kubernetes.Interface, node *corev1.Node, taints []corev1.Taint) error {
	if taints == nil {
		taints = []corev1.Taint{} // merge patch [] clears, nil would marshal "taints":null
	}
	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"resourceVersion": node.ResourceVersion},
		"spec":     map[string]any{"taints": taints},
	})
	if err != nil {
		return err
	}
	_, err = cs.CoreV1().Nodes().Patch(ctx, node.Name, types.MergePatchType, payload, metav1.PatchOptions{})
	return err
}

// TaintNode adds key=value:effect unless the key is already present.
// The node is re-fetched inside (kubectl taint's get-modify-patch
// pattern) and the whole get-modify-patch retries on conflict — a
// taint another writer added between our Get and Patch is merged
// around on the retry instead of being dropped by the stale
// whole-array replace.
func TaintNode(ctx context.Context, cs kubernetes.Interface, name, key, value string, effect corev1.TaintEffect) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		node, err := cs.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if HasTaint(node.Spec.Taints, key) {
			return nil
		}
		taints := append(append([]corev1.Taint{}, node.Spec.Taints...),
			corev1.Taint{Key: key, Value: value, Effect: effect})
		return patchNodeTaints(ctx, cs, node, taints)
	})
}

// UntaintNode removes every taint with the given key (all effects),
// under the same get-modify-patch conflict retry as TaintNode.
func UntaintNode(ctx context.Context, cs kubernetes.Interface, name, key string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		node, err := cs.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if !HasTaint(node.Spec.Taints, key) {
			return nil
		}
		return patchNodeTaints(ctx, cs, node, dropTaintsByKey(node.Spec.Taints, key))
	})
}

// PatchNodeLabels merges labels onto a node (kubectl label --overwrite).
func PatchNodeLabels(ctx context.Context, cs kubernetes.Interface, name string, labels map[string]string) error {
	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"labels": labels},
	})
	if err != nil {
		return err
	}
	_, err = cs.CoreV1().Nodes().Patch(ctx, name, types.StrategicMergePatchType, payload, metav1.PatchOptions{})
	return err
}

// ListNodes is the single place node listing happens (RBAC: cluster
// get/list/watch on nodes). Paged like every cluster-wide list —
// Node objects are the fattest typed payload any module pulls.
func ListNodes(ctx context.Context, cs kubernetes.Interface) ([]corev1.Node, error) {
	return ListAll(ctx, metav1.ListOptions{Limit: 500}, nodes(cs))
}
