// node_hang_writes.go — the node-hang-precordon check's three write
// passes: the auto-uncordon lift (frees capacity before the cordon
// pass re-evaluates the ratio), the stale-stamp cleanup (a
// precordon stamp on a schedulable node is ours to drop), and the
// ratio-capped pre-cordon patch. Run() in node_hang_precordon.go
// does the census and orchestrates; this file holds the patch
// loops. Every pass merge-patches spec.unschedulable together with
// the stamp in ONE payload and drops the informer-backed node
// census afterwards (InvalidateNodes) so the next cycle re-reads.
package nodehealth

import (
	"context"
	"sort"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// uncordonCleared lifts the cordon this check stamped on nodes
// whose latches all cleared (transient recovery, or a post-SNR
// reboot that came back healthy but kept spec.unschedulable). Runs
// BEFORE the cordon pass so freed capacity counts toward the 35%
// ratio. Returns the updated cordoned-worker count.
func (p *nodeHangCheck) uncordonCleared(ctx context.Context, log logr.Logger,
	uncordon []string, cordoned int) int {
	sort.Strings(uncordon)
	for _, name := range uncordon {
		payload, err := kube.MergePatchAnnos(map[string]any{
			nodeHangPreCordonAnno: nil, // merge-patch delete — lift our stamp
		})
		if err == nil {
			// The spec half rides ahead of the annotations doc so
			// the cordon lift and the stamp delete land in ONE merge
			// patch — bytes identical to the hand-marshalled shape.
			payload = append([]byte(`{"spec":{"unschedulable":false},`),
				payload[1:]...)
		}
		if err != nil {
			metrics.IncError(p.Name)
			log.Error(err, "hang precordon uncordon patch marshal failed", "node", name)
			continue
		}
		if _, err := p.CS.CoreV1().Nodes().Patch(ctx, name,
			types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
			metrics.IncError(p.Name)
			log.Error(err, "hang precordon uncordon patch failed", "node", name)
			continue
		}
		p.InvalidateNodes(ctx) // node spec changed — drop the node census, arm a CS re-read
		cordoned--
		nodeHangUncordonsTotal.WithLabelValues(name).Inc()
		p.hangCounters.mark(name)
		log.Info("UNCORDON: node hang condition cleared",
			"node", name)
	}
	return cordoned
}

// clearStaleStamps drops the precordon stamp from schedulable
// nodes — a stamp left behind by a manual `kubectl uncordon` is
// ours to clean, otherwise a later deliberate cordon would inherit
// the auto-uncordon.
func (p *nodeHangCheck) clearStaleStamps(ctx context.Context, log logr.Logger,
	staleStamp []string) {
	sort.Strings(staleStamp)
	for _, name := range staleStamp {
		payload, err := kube.MergePatchAnnos(map[string]any{
			nodeHangPreCordonAnno: nil,
		})
		if err != nil {
			metrics.IncError(p.Name)
			log.Error(err, "hang precordon stale-stamp patch marshal failed", "node", name)
			continue
		}
		if _, err := p.CS.CoreV1().Nodes().Patch(ctx, name,
			types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
			metrics.IncError(p.Name)
			log.Error(err, "hang precordon stale-stamp patch failed", "node", name)
			continue
		}
		p.InvalidateNodes(ctx) // node annotations changed — drop the node census, arm a CS re-read
		log.Info("CORDON STAMP CLEARED: schedulable node carried a stale pre-cordon annotation",
			"node", name)
	}
}

// cordonLatched patches spec.unschedulable=true + the precordon
// stamp onto every latch-positive, still-schedulable worker —
// bounded by the 35% cordoned-worker ratio so the guard cannot
// unnode the fleet during a correlated event (bad kernel rollout,
// storage backend outage). Returns the updated cordoned count.
func (p *nodeHangCheck) cordonLatched(ctx context.Context, log logr.Logger,
	rep *probefw.SweepReport, nodes []corev1.Node, workers, cordoned int) int {
	for _, entry := range rep.Sorted() {
		name, _, _ := strings.Cut(entry, ":")
		var target *corev1.Node
		for i := range nodes {
			if nodes[i].Name == name {
				target = &nodes[i]
				break
			}
		}
		if target == nil || target.Spec.Unschedulable {
			continue
		}
		// Cap invariant: after this cordon at most
		// max(1, floor(nodeHangMaxCordonedRatio*workers)) workers
		// are cordoned. The post-increment count (cordoned+1) is
		// what must stay inside the ratio — testing the
		// pre-increment count with >= let the fleet reach exactly
		// 35%+one, over-cap by one. The cordoned==0 exception lets
		// the FIRST cordon through regardless of ratio, so a
		// 2-worker cluster (floor(0.35*2)=0) keeps pre-cordon
		// ability: without it a 2-node fleet could never precordon.
		if workers > 0 && cordoned > 0 &&
			float64(cordoned+1)/float64(workers) > nodeHangMaxCordonedRatio {
			log.Info("skip precordon: cordoned-worker ratio at cap — refusing to unnode the fleet",
				"cordoned", cordoned, "workers", workers)
			continue
		}
		payload, err := kube.MergePatchAnnos(map[string]any{
			nodeHangPreCordonAnno: nodeHangPreCordonValue,
		})
		if err == nil {
			// Same one-patch shape as the uncordon half — the spec
			// write ahead of the annotations doc keeps the ported
			// byte order.
			payload = append([]byte(`{"spec":{"unschedulable":true},`),
				payload[1:]...)
		}
		if err != nil {
			metrics.IncError(p.Name)
			log.Error(err, "hang precordon patch marshal failed", "node", name)
			continue
		}
		if _, err := p.CS.CoreV1().Nodes().Patch(ctx, name,
			types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
			metrics.IncError(p.Name)
			log.Error(err, "hang precordon patch failed", "node", name)
			continue
		}
		p.InvalidateNodes(ctx) // node spec changed — drop the node census, arm a CS re-read
		cordoned++
		nodeHangCordonsTotal.WithLabelValues(name).Inc()
		p.hangCounters.mark(name)
		log.Info("CORDON: node carrying a sustained hang latch — unschedulable before NHC/SNR reboots it",
			"node", name, "condition", entry)
	}
	return cordoned
}
