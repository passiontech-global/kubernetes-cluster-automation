// node_hang_precordon.go — the node-hang-precordon check
// (W8-ST2/W9-CP3/W10-KR6): patches spec.unschedulable onto worker
// nodes carrying a sustained hang latch before NHC/SNR reboots
// them, stamps the cordon, and auto-uncordons once every latch
// clears.
package nodehealth

import (
	"context"
	"fmt"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// nodeHangCheck is the node-hang pre-cordon watchdog.
type nodeHangCheck struct{ *probefw.Deps }

// newNodeHangCheck builds the W8-ST2 watchdog — stateless, it reads
// only Deps.
func NewNodeHangCheck(d *probefw.Deps) probefw.Check {
	return &nodeHangCheck{Deps: d}
}

const (
	// W8-ST2 — node-hang-precordon knobs.
	CheckNameNodeHang        = "node-hang-precordon"
	nodeHangCondMinAge       = 2 * time.Minute
	nodeHangMaxCordonedRatio = 0.35

	// W9-CP3 — clock-skew pre-cordon: ClockUnsynchronized gets a
	// longer fuse than the hang latches — the NTP daemon needs
	// restart time to resync before the node counts as hanging.
	nodeClockSkewCond      corev1.NodeConditionType = "ClockUnsynchronized"
	nodeClockSkewCordonAge                          = 10 * time.Minute

	// nodeHangPreCordonAnno stamps every cordon this check applies so
	// the auto-uncordon path only ever lifts cordons IT created — a
	// kubectl cordon or an NHC fence carries no stamp and is never
	// touched.
	nodeHangPreCordonAnno  = kube.AnnoPreCordonedBy
	nodeHangPreCordonValue = "node-hang-precordon"
)

// nodeHangConds are the NPD/node-agent latches that precede a node
// reboot — patching unschedulable early keeps new pods off the dying
// node. All are custom NodeConditionTypes written by the node stack
// (FilesystemReadOnly/KernelHungTasks by hostmetrics+workerhygiene,
// KubeletRuntimeStall/KubeletWatchWedge/PodTeardownWedged by
// nodereporter; InodePressure is kubelet-native — nodefs/imagefs
// inode exhaustion, no agent latch involved). There is
// no corev1 constant for any of them — string literals are the
// convention here (same as nodeClockSkewCond below).
// ClockUnsynchronized is deliberately NOT here: it carries its own
// longer fuse (nodeClockSkewCordonAge) and is checked separately.
var nodeHangConds = []corev1.NodeConditionType{
	"KernelHungTasks", "FilesystemReadOnly", "KubeletRuntimeStall",
	"KubeletWatchWedge", "PodTeardownWedged", "InodePressure",
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
// the node — "" when none qualifies. Every nodeHangConds entry fuses
// at nodeHangCondMinAge; ClockUnsynchronized (W9-CP3) gets
// nodeClockSkewCordonAge so an NTP daemon restart has time to resync
// before the node counts as hanging.
func nodeHangLatch(n *corev1.Node, now time.Time) string {
	for _, t := range nodeHangConds {
		c := kube.NodeCondition(n, t)
		if c != nil && c.Status == corev1.ConditionTrue &&
			!c.LastTransitionTime.IsZero() &&
			now.Sub(c.LastTransitionTime.Time) >= nodeHangCondMinAge {
			return string(t)
		}
	}
	if c := kube.NodeCondition(n, nodeClockSkewCond); c != nil &&
		c.Status == corev1.ConditionTrue &&
		!c.LastTransitionTime.IsZero() &&
		now.Sub(c.LastTransitionTime.Time) >= nodeClockSkewCordonAge {
		return string(nodeClockSkewCond)
	}
	return ""
}

// nodeHangLatchActive reports whether ANY hang latch is currently
// True on the node — the auto-uncordon guard. Status only, no age
// floor: a latch that just re-asserted still means the node is
// hanging, so the pre-cordon stays.
func nodeHangLatchActive(n *corev1.Node) bool {
	for _, t := range nodeHangConds {
		if c := kube.NodeCondition(n, t); c != nil &&
			c.Status == corev1.ConditionTrue {
			return true
		}
	}
	if c := kube.NodeCondition(n, nodeClockSkewCond); c != nil &&
		c.Status == corev1.ConditionTrue {
		return true
	}
	return false
}

// checkNodeHangPreCordon patches spec.unschedulable=true onto worker
// nodes carrying a sustained hang latch (any nodeHangConds entry
// >=2m, ClockUnsynchronized >=10m) — NHC/SNR will
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
	nodes, err := kube.ListNodes(ctx, p.CS)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list nodes: %w", err)}
	}
	workers, cordoned := 0, 0
	var hang []string
	var uncordon, staleStamp []string
	for i := range nodes {
		n := &nodes[i]
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
		if latch := nodeHangLatch(n, now); latch != "" {
			hang = append(hang, n.Name+":"+latch)
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
		cordoned--
		nodeHangUncordonsTotal.WithLabelValues(name).Inc()
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
		log.Info("CORDON STAMP CLEARED: schedulable node carried a stale pre-cordon annotation",
			"node", name)
	}

	if len(hang) == 0 {
		return probefw.Result{Pass: true}
	}
	sort.Strings(hang)
	for _, entry := range hang {
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
		cordoned++
		nodeHangCordonsTotal.WithLabelValues(name).Inc()
		log.Info("CORDON: node carrying a sustained hang latch — unschedulable before NHC/SNR reboots it",
			"node", name, "condition", entry)
	}
	return probefw.Result{Why: "nodes hanging with a pre-reboot latch: " + strings.Join(hang, ", ")}
}
