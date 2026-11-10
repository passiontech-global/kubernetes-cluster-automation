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
func (d *Deps) AllNodes(ctx context.Context) ([]corev1.Node, error) {
	s := sweepSnap(ctx)
	s.muNodes.Lock()
	defer s.muNodes.Unlock()
	if !s.nodesSet {
		s.nodesSet = true
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		if s.nodesForceCS {
			s.nodesForceCS = false
			s.nodes, s.nodesErr = kube.ListNodes(lctx, d.CS)
		} else {
			s.nodes, s.nodesErr = kube.ListNodesCached(lctx, d.NodeReader, d.CS)
		}
	}
	return s.nodes, s.nodesErr
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
	s.muNodeZones.Lock()
	defer s.muNodeZones.Unlock()
	if !s.nodeZonesSet {
		s.nodeZonesSet = true
		var nodes []corev1.Node
		nodes, s.nodeZonesErr = d.AllNodes(ctx)
		if s.nodeZonesErr == nil {
			s.nodeZones = make(map[string]string, len(nodes))
			for i := range nodes {
				s.nodeZones[nodes[i].Name] =
					nodes[i].Labels[corev1.LabelTopologyZone]
			}
		}
	}
	return s.nodeZones, s.nodeZonesErr
}
