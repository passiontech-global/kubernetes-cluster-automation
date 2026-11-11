// snapshot_nodes.go — the node census reader of the per-sweep
// snapshot: AllNodes plus the node-derived NodeZones placement join
// (split out of snapshot.go — see its header for the memoizer
// contract).
package probefw

import (
	"context"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// AllNodes is the node twin of AllPods — the replacement for the
// per-check kube.ListNodes calls. After InvalidateNodes the FIRST
// re-read bypasses the informer cache and reads d.CS directly (a
// node patched milliseconds ago must not be served from a lagging
// cache); that read memoizes, and the rest of the sweep consumes it.
// The forceCS flag arrives consumed-inside-the-lock from memo.get —
// the armed/loaded decision can never split across racing readers.
func (d *Deps) AllNodes(ctx context.Context) ([]corev1.Node, error) {
	s := sweepSnap(ctx)
	return s.nodes.get(func(forceCS bool) ([]corev1.Node, error) {
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		if forceCS {
			return kube.ListNodes(lctx, d.CS)
		}
		return kube.ListNodesCached(lctx, d.NodeReader, d.CS)
	})
}

// NodeZones is the memoized node → topology-zone join the
// zone-aware checks used to each rebuild inline from AllNodes —
// the stateful site-skew signatures place endpoints and STS
// replicas through it, the zone-starvation check derives its
// worker-zone set on top. A zoneless node maps to "" — value-
// identical to a missing key for every consumer (they read the
// zone, never test presence). Built on the shared node census:
// the first caller pays that LIST, the error memoizes with the
// join exactly like the census errors do. The map is read-only —
// the serial sweep shares it across checks.
func (d *Deps) NodeZones(ctx context.Context) (map[string]string, error) {
	s := sweepSnap(ctx)
	return s.nodeZones.get(func(bool) (map[string]string, error) {
		nodes, err := d.AllNodes(ctx)
		if err != nil {
			return nil, err
		}
		m := make(map[string]string, len(nodes))
		for i := range nodes {
			m[nodes[i].Name] = nodes[i].Labels[corev1.LabelTopologyZone]
		}
		return m, nil
	})
}
