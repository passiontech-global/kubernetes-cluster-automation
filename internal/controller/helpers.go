// Package controller implements the node-automation modules ported
// 1:1 from the shell-operator bash hooks in passiontech-fluxcd
// (infrastructure/base/node-ops/node-ops-operator/hooks/*.sh).
//
// Contract shared by every module:
//   - Reads go through the kubernetes.Interface clientset (cs) — the
//     operator's RBAC intentionally has NO watch verb on most types
//     (pods, services, jobs, webhookconfigs, ...), so a cached client
//     would deadlock the informer. Only types with an explicit
//     informer (Node, DaemonSet/konnectivity-agent, Secret/
//     passiontech-pipeline, ConfigMap in node-ops) may be watched.
//   - `name` everywhere is the legacy shell-operator queue name so
//     metrics.IncError(name) keeps the alert contract.
//   - Periodic modules register through addPeriodic; event-driven
//     modules register a reconciler and use Result.RequeueAfter as the
//     old crontab safety-net.
package controller

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/passiontech-global/node-automation-controller/internal/metrics"
)

// ---------------------------------------------------------------------------
// periodic — replaces a shell-operator `schedule:` binding.
// ---------------------------------------------------------------------------

type periodic struct {
	name     string
	interval time.Duration
	fn       func(ctx context.Context) error
	log      logr.Logger
}

func (p *periodic) Start(ctx context.Context) error {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := p.fn(ctx); err != nil {
				metrics.IncError(p.name)
				p.log.Error(err, "periodic run failed")
			}
		}
	}
}

// addPeriodic registers fn to run every interval (equivalent to the old
// crontab entry). name is the legacy queue name for metrics compat.
func addPeriodic(mgr manager.Manager, name string, interval time.Duration, fn func(ctx context.Context) error) error {
	return mgr.Add(&periodic{
		name:     name,
		interval: interval,
		fn:       fn,
		log:      mgr.GetLogger().WithName(name),
	})
}

// ---------------------------------------------------------------------------
// Node helpers — taints/conditions/labels shared by several modules.
// ---------------------------------------------------------------------------

// nodeCondition returns the node's condition of type t, or nil.
func nodeCondition(n *corev1.Node, t corev1.NodeConditionType) *corev1.NodeCondition {
	for i := range n.Status.Conditions {
		if n.Status.Conditions[i].Type == t {
			return &n.Status.Conditions[i]
		}
	}
	return nil
}

// nodeReady reports whether the node's Ready condition is True.
func nodeReady(n *corev1.Node) bool {
	c := nodeCondition(n, corev1.NodeReady)
	return c != nil && c.Status == corev1.ConditionTrue
}

// isControlPlane reports whether the node carries a control-plane role
// label (k0s control planes run no kubelet workload).
func isControlPlane(n *corev1.Node) bool {
	_, cp := n.Labels["node-role.kubernetes.io/control-plane"]
	_, m := n.Labels["node-role.kubernetes.io/master"]
	return cp || m
}

// hasTaint reports whether taints contains an entry with the given key
// (any effect — `kubectl taint node <n> <key>-` removes all effects).
func hasTaint(taints []corev1.Taint, key string) bool {
	for _, t := range taints {
		if t.Key == key {
			return true
		}
	}
	return false
}

// dropTaintsByKey returns taints with every entry matching key removed.
func dropTaintsByKey(taints []corev1.Taint, key string) []corev1.Taint {
	out := taints[:0]
	for _, t := range taints {
		if t.Key != key {
			out = append(out, t)
		}
	}
	return out
}

// patchNodeTaints replaces .spec.taints on a node via JSON Merge Patch
// — the merge semantics create the key when absent (a never-tainted
// node has no "taints" field, so a JSONPatch "replace" would be
// rejected) and arrays are replaced wholesale, which is exactly what
// callers pass (the full desired taint list).
func patchNodeTaints(ctx context.Context, cs kubernetes.Interface, name string, taints []corev1.Taint) error {
	if taints == nil {
		taints = []corev1.Taint{} // merge patch [] clears, nil would marshal "taints":null
	}
	payload, err := json.Marshal(map[string]any{
		"spec": map[string]any{"taints": taints},
	})
	if err != nil {
		return err
	}
	_, err = cs.CoreV1().Nodes().Patch(ctx, name, types.MergePatchType, payload, metav1.PatchOptions{})
	return err
}

// taintNode adds key=value:effect unless the key is already present.
// The node is re-fetched inside (kubectl taint's get-modify-patch
// pattern) so a taint added after the caller's snapshot is not lost.
func taintNode(ctx context.Context, cs kubernetes.Interface, name, key, value string, effect corev1.TaintEffect) error {
	node, err := cs.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if hasTaint(node.Spec.Taints, key) {
		return nil
	}
	taints := append(append([]corev1.Taint{}, node.Spec.Taints...),
		corev1.Taint{Key: key, Value: value, Effect: effect})
	return patchNodeTaints(ctx, cs, name, taints)
}

// untaintNode removes every taint with the given key (all effects).
func untaintNode(ctx context.Context, cs kubernetes.Interface, name, key string) error {
	node, err := cs.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if !hasTaint(node.Spec.Taints, key) {
		return nil
	}
	return patchNodeTaints(ctx, cs, name, dropTaintsByKey(node.Spec.Taints, key))
}

// patchNodeLabels merges labels onto a node (kubectl label --overwrite).
func patchNodeLabels(ctx context.Context, cs kubernetes.Interface, name string, labels map[string]string) error {
	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"labels": labels},
	})
	if err != nil {
		return err
	}
	_, err = cs.CoreV1().Nodes().Patch(ctx, name, types.StrategicMergePatchType, payload, metav1.PatchOptions{})
	return err
}

// listNodes is the single place node listing happens (RBAC: cluster
// get/list/watch on nodes).
func listNodes(ctx context.Context, cs kubernetes.Interface) ([]corev1.Node, error) {
	nl, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return nl.Items, nil
}

// countNotReadyNodes returns how many nodes are not Ready=True —
// the shared "storm-gate" check used by several modules.
func countNotReadyNodes(ctx context.Context, cs kubernetes.Interface) (int, error) {
	nodes, err := listNodes(ctx, cs)
	if err != nil {
		return 0, err
	}
	n := 0
	for i := range nodes {
		if !nodeReady(&nodes[i]) {
			n++
		}
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// DaemonSet helpers.
// ---------------------------------------------------------------------------

// daemonSetSettled mirrors the bash "rollout settled" check:
// observedGeneration == generation, updatedNumberScheduled ==
// desiredNumberScheduled and numberReady == desiredNumberScheduled.
func daemonSetSettled(ds *appsv1.DaemonSet) bool {
	return ds.Status.ObservedGeneration == ds.Generation &&
		ds.Status.UpdatedNumberScheduled == ds.Status.DesiredNumberScheduled &&
		ds.Status.NumberReady == ds.Status.DesiredNumberScheduled
}
