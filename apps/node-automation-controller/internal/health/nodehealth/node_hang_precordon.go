// node_hang_precordon.go — the node-hang-precordon check
// (W8-ST2/W9-CP3/W10-KR6): patches spec.unschedulable onto worker
// nodes carrying a sustained hang latch before NHC/SNR reboots
// them, stamps the cordon, and auto-uncordons once every latch
// clears.
package nodehealth

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

// nodeHangCheck is the node-hang pre-cordon watchdog.
type nodeHangCheck struct {
	*probefw.Deps
	// hangCounters is the {node} counter-series bookkeeping for the
	// cordon/uncordon vecs — see hangCounterLedger.
	hangCounters hangCounterLedger
}

// newNodeHangCheck builds the W8-ST2 watchdog — it reads only Deps;
// hangCounters arms lazily on the first cordon/uncordon Inc (zero
// value ready, the platform/state convention).
func NewNodeHangCheck(d *probefw.Deps) probefw.Check {
	return &nodeHangCheck{Deps: d}
}

// hangCounterLedger tracks which {node} series the check has emitted
// into nodeHangCordonsTotal / nodeHangUncordonsTotal so node churn
// (pool rotation deleting the node object) cannot grow the two vecs
// monotonically — a counter Inc is never undone by the code path that
// created it, so only this sweep-side ledger can retire the series.
// The check lists every node each sweep, so the retire rule is
// census-based carry-forward: a node missing from one complete sweep
// is carried in missed rather than deleted (a list that just missed a
// node must not erase evidence), and a node missing from two
// consecutive sweeps has both its series deleted — the vecs share the
// single {node} label, so one delete call each retires the node
// entirely. Plain maps, deliberately not state.GaugeLedger/
// StreakLedger: counter series are never re-emitted per sweep, and
// the delete-on-second-miss rule needs the one-generation carry this
// shape gives.
type hangCounterLedger struct {
	live   map[string]struct{} // nodes carrying at least one series
	missed map[string]struct{} // live nodes absent from the previous complete sweep
}

// mark books node as carrying counter series — the Inc sites call it
// right after WithLabelValues(...).Inc(). Seeing the node again
// restarts its absence streak.
func (h *hangCounterLedger) mark(node string) {
	if h.live == nil {
		h.live = map[string]struct{}{}
	}
	h.live[node] = struct{}{}
	delete(h.missed, node)
}

// reconcile folds one complete sweep's node census into the ledger:
// seen nodes re-arm, a first absence is carried into missed, and a
// second consecutive absence deletes the node's series through del.
// Returns the number of nodes retired. Call exactly once per complete
// sweep, after the sweep's patch loops — a failed node list must skip
// it (the ledger cannot tell "node gone" from "sweep never ran"), the
// same incomplete-sweep contract as the platform ledgers' Prune.
func (h *hangCounterLedger) reconcile(present map[string]bool,
	del func(labelValues ...string) bool) int {
	retired := 0
	for node := range h.live {
		if present[node] {
			delete(h.missed, node)
			continue
		}
		if _, missedBefore := h.missed[node]; missedBefore {
			del(node)
			retired++
			delete(h.live, node)
			delete(h.missed, node)
			continue
		}
		if h.missed == nil {
			h.missed = map[string]struct{}{}
		}
		h.missed[node] = struct{}{}
	}
	return retired
}

const (
	// W8-ST2 — node-hang-precordon knobs.
	CheckNameNodeHang        = "node-hang-precordon"
	nodeHangCondMinAge       = 2 * time.Minute
	nodeHangMaxCordonedRatio = 0.35

	// W9-CP3 — clock-skew pre-cordon: the clock conditions get a
	// longer fuse than the hang latches — the NTP daemon needs
	// restart time to resync before the node counts as hanging.
	// ClockSkewDetected (W12-1.4) is the host-agent's >2s-offset
	// latch (chrony still reports a source, so ClockUnsynchronized
	// never trips) — skewed mTLS/Raft leases harm every pod that
	// lands on the node, same blast radius.
	nodeClockSkewCordonAge = 10 * time.Minute

	// nodeHangCondHeartbeatMaxAge is how old a condition's
	// lastHeartbeatTime may be before the value stops being cordon
	// evidence: the writer (nodereporter refreshes it every ~2m on
	// a live agent; kubelet refreshes its own conditions on every
	// status post) may be dead and the True a zombie — 2026-11-06
	// all six node-host-agents wedged mid-Cycle during an apiserver
	// flap and a frozen ~70m-old KubeletPLEGUnhealthy latch
	// precordoned half the fleet. 10m tolerates several missed
	// heartbeat refreshes (apiserver flap, agent restart) while
	// still catching a dead writer far inside the observed freeze.
	nodeHangCondHeartbeatMaxAge = 10 * time.Minute

	// nodeHangPreCordonAnno stamps every cordon this check applies so
	// the auto-uncordon path only ever lifts cordons IT created — a
	// kubectl cordon or an NHC fence carries no stamp and is never
	// touched.
	nodeHangPreCordonAnno  = kube.AnnoPreCordonedBy
	nodeHangPreCordonValue = "node-hang-precordon"
)

// nodeHangConds are the NPD/node-agent latches that precede a node
// reboot — patching unschedulable early keeps new pods off the dying
// node. The set lives in nodecond.HangPreCordonNames (libs/hostkit) —
// the single source of truth shared with the node-host-agent, so the
// controller can no longer drift from the names the agent actually
// emits. All members are custom NodeConditionTypes written by the
// node stack (FilesystemReadOnly/KernelHungTasks/KernelSlabLeak/
// KernelResourceExhaustion/CgroupDyingLeak by hostmetrics+workerhygiene,
// KubeletRuntimeStall/KubeletWatchWedge/PodTeardownWedged by
// nodereporter, MemoryPSIThrashing by the PSI monitor;
// InodePressure is the one kubelet-native member — nodefs/imagefs
// inode exhaustion, no agent latch involved; the Cilium*/CalicoFelixDown
// latches are the CNI death signals a pre-reboot node carries;
// NebulaIsolated is the overlay partition latch;
// KubeletPLEGUnhealthy — W12-1.4 — is the PLEG relist stall that
// precedes the kubelet dying outright).
// The clock conditions are deliberately NOT here: they carry their
// own longer fuse (nodeClockSkewCordonAge) and are checked
// separately.
var nodeHangConds = condTypes(nodecond.HangPreCordonNames)

// nodeClockSkewConds are the clock-health latches on the longer
// fuse (nodecond.ClockSkewPreCordonNames) — ClockUnsynchronized
// (no sync source) and ClockSkewDetected (synchronized but >2s
// offset, W12-1.4).
var nodeClockSkewConds = condTypes(nodecond.ClockSkewPreCordonNames)

// condTypes converts a nodecond name list into the
// corev1.NodeConditionType slices the check loops compare —
// nodecond keeps the names as untyped strings so libs/hostkit stays
// stdlib-only.
func condTypes(names []string) []corev1.NodeConditionType {
	out := make([]corev1.NodeConditionType, len(names))
	for i, name := range names {
		out[i] = corev1.NodeConditionType(name)
	}
	return out
}

var (
	// W8-ST2 — worker nodes patched spec.unschedulable after a
	// sustained hang condition (delivered cordons only).
	nodeHangCordonsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_automation_node_hang_cordons_total",
		Help: "Worker nodes patched spec.unschedulable after a sustained hang condition.",
	}, []string{"node"})

	// W8-ST2 — worker nodes patched schedulable after the
	// pre-cordon hang latch cleared (delivered uncordons only).
	nodeHangUncordonsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_automation_node_hang_uncordons_total",
		Help: "Worker nodes patched schedulable after the pre-cordon hang latch cleared.",
	}, []string{"node"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		nodeHangCordonsTotal,
		nodeHangUncordonsTotal)
}

// ---------------------------------------------------------------------------
// W8-ST2 — node-hang-precordon
// ---------------------------------------------------------------------------

// nodeHangLatch reports the first hang latch past its cordon fuse on
// the node whose lastHeartbeatTime is still fresh — "" when none
// qualifies. Every nodeHangConds entry fuses at nodeHangCondMinAge;
// the nodeClockSkewConds latches (W9-CP3) get
// nodeClockSkewCordonAge so an NTP daemon restart has time to
// resync before the node counts as hanging. stale returns the first
// fused latch the heartbeat-freshness gate rejected — a frozen or
// absent heartbeat means the writer may be dead and the True value
// a zombie, so it warns instead of cordoning.
func nodeHangLatch(n *corev1.Node, now time.Time) (latch, stale string) {
	fused := func(t corev1.NodeConditionType, fuse time.Duration) *corev1.NodeCondition {
		c := kube.NodeCondition(n, t)
		if c == nil || c.Status != corev1.ConditionTrue ||
			c.LastTransitionTime.IsZero() ||
			now.Sub(c.LastTransitionTime.Time) < fuse {
			return nil
		}
		return c
	}
	for _, t := range nodeHangConds {
		if c := fused(t, nodeHangCondMinAge); c != nil {
			if condHeartbeatLive(c, now) {
				return string(t), stale
			}
			if stale == "" {
				stale = string(t)
			}
		}
	}
	for _, t := range nodeClockSkewConds {
		if c := fused(t, nodeClockSkewCordonAge); c != nil {
			if condHeartbeatLive(c, now) {
				return string(t), stale
			}
			if stale == "" {
				stale = string(t)
			}
		}
	}
	return "", stale
}

// condHeartbeatLive reports whether a condition's
// lastHeartbeatTime is fresh enough to trust the value: the writer
// (nodereporter, kubelet) re-stamps it while alive, so a heartbeat
// older than nodeHangCondHeartbeatMaxAge — or never set — means the
// condition may be a zombie left by a dead reporter.
func condHeartbeatLive(c *corev1.NodeCondition, now time.Time) bool {
	return !c.LastHeartbeatTime.IsZero() &&
		now.Sub(c.LastHeartbeatTime.Time) < nodeHangCondHeartbeatMaxAge
}

// nodeHangLatchActive reports whether ANY hang latch is currently
// True on the node — the auto-uncordon guard. Status only, no age
// floor and NO heartbeat-freshness gate: a latch that just
// re-asserted still means the node is hanging, so the pre-cordon
// stays — and a frozen-True zombie latch holds it too, deliberately
// conservative (a dead reporter can't prove the node recovered;
// lifting the cordon on stale data would reschedule onto a node
// that may still be hung).
func nodeHangLatchActive(n *corev1.Node) bool {
	for _, t := range nodeHangConds {
		if c := kube.NodeCondition(n, t); c != nil &&
			c.Status == corev1.ConditionTrue {
			return true
		}
	}
	for _, t := range nodeClockSkewConds {
		if c := kube.NodeCondition(n, t); c != nil &&
			c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// checkNodeHangPreCordon patches spec.unschedulable=true onto worker
// nodes carrying a sustained hang latch (any nodeHangConds entry
// >=2m, a nodeClockSkewConds latch >=10m, and a lastHeartbeatTime
// fresh enough that the condition's writer is provably alive —
// a frozen heartbeat warns instead of cordoning) — NHC/SNR will
// reboot the node, but pods keep scheduling onto it until then. The
// cordon is stamped passiontech.dev/precordoned-by=node-hang-precordon and
// the same sweep AUTO-UNCORDONS a stamped node once every latch has
// cleared — transient recovery, or a post-SNR reboot that came back
// healthy but kept spec.unschedulable. A stale stamp on a schedulable
// node (manual uncordon) is dropped so a later deliberate cordon can
// never inherit the auto-uncordon. The 35% cap stops the guard from
// unnoding the fleet during a correlated event (bad kernel rollout,
// storage backend outage).
func (p *nodeHangCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	nodes, err := p.AllNodes(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list nodes: %w", err)}
	}
	workers, cordoned := 0, 0
	var rep probefw.SweepReport
	var uncordon, staleStamp []string
	// The full node census backs the counter-series carry-forward —
	// control-plane nodes are skipped by the check logic but still
	// count as "exists" for the retire rule.
	present := make(map[string]bool, len(nodes))
	for i := range nodes {
		n := &nodes[i]
		present[n.Name] = true
		if kube.IsControlPlane(n) {
			continue
		}
		workers++
		if n.Spec.Unschedulable {
			cordoned++
		}
		// Auto-uncordon / stale-stamp sweep — only nodes THIS check
		// cordoned carry the stamp; everything else is left alone.
		if n.Annotations[nodeHangPreCordonAnno] == nodeHangPreCordonValue {
			switch {
			case n.Spec.Unschedulable && !nodeHangLatchActive(n):
				uncordon = append(uncordon, n.Name)
			case !n.Spec.Unschedulable:
				staleStamp = append(staleStamp, n.Name)
			}
		}
		latch, stale := nodeHangLatch(n, now)
		if stale != "" {
			// Stale heartbeat = the condition's writer may be dead —
			// the True value is not cordon evidence, but a dead
			// reporter is itself worth surfacing (the 2026-11-06
			// wedge froze these heartbeats fleet-wide).
			log.Info("WARN: ignoring stale hang condition — "+
				"condition heartbeat frozen, not cordon evidence",
				"node", n.Name, "condition", stale,
				"maxHeartbeatAge", nodeHangCondHeartbeatMaxAge)
		}
		if latch != "" {
			rep.Find(n.Name + ":" + latch)
		}
	}

	// Lift our own cordons first — frees schedulable capacity before
	// the cordon pass re-evaluates the 35% ratio.
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
		p.InvalidateSweep(ctx) // node spec changed — drop the snapshot
		cordoned--
		nodeHangUncordonsTotal.WithLabelValues(name).Inc()
		p.hangCounters.mark(name)
		log.Info("UNCORDON: node hang condition cleared",
			"node", name)
	}
	// A stamp left on a schedulable node (manual `kubectl uncordon`)
	// is ours to clean — otherwise a later deliberate cordon would
	// inherit the auto-uncordon.
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
		p.InvalidateSweep(ctx) // node annotations changed — drop the snapshot
		log.Info("CORDON STAMP CLEARED: schedulable node carried a stale pre-cordon annotation",
			"node", name)
	}

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
		if workers > 0 && float64(cordoned)/float64(workers) >= nodeHangMaxCordonedRatio {
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
		p.InvalidateSweep(ctx) // node spec changed — drop the snapshot
		cordoned++
		nodeHangCordonsTotal.WithLabelValues(name).Inc()
		p.hangCounters.mark(name)
		log.Info("CORDON: node carrying a sustained hang latch — unschedulable before NHC/SNR reboots it",
			"node", name, "condition", entry)
	}
	// Complete sweep — retire cordon/uncordon series whose node has
	// now missed two consecutive censuses (the churn guard; see
	// hangCounterLedger).
	p.hangCounters.reconcile(present, func(lv ...string) bool {
		nodeHangCordonsTotal.DeleteLabelValues(lv[0])
		return nodeHangUncordonsTotal.DeleteLabelValues(lv[0])
	})
	return rep.Verdict("nodes hanging with a pre-reboot latch: ", ", ")
}
