// volumeattachment-cleaner — C4, the orphaned VolumeAttachment reaper.
//
// A VolumeAttachment (VA) is the cluster-scoped record that a CSI
// driver holds a volume attached to a node. It is also THE detach
// switch: deleting the VA object is what tells attach-detach the
// volume is detached and the PV may be mounted elsewhere — which is
// exactly why this module exists AND exactly why it must fail closed.
// Deleting a VA whose node is actually alive-and-mounted produces the
// classic split-brain: the PV becomes attachable on a second node
// while still attached to the first → two writers, filesystem
// corruption (the same foot-gun dead-node-sweeper documents for pod
// force-delete). Every gate below exists to prove the node cannot be
// a live writer before a delete is issued.
//
// Two leak shapes are reaped:
//
//	missing_node — spec.nodeName has no Node object (node removed
//	without drain: dead host replaced, `kubectl delete node` on a
//	lost worker). Nothing in-tree ever cleans that VA — the
//	external-attacher keeps "detaching" from a node that does not
//	exist, its finalizer never drains, the PV stays attached
//	forever and the rescheduled workload hits Multi-Attach on the
//	new node. Gates: VA age ≥ 5m (brand-new VAs legitimately race
//	ahead of a node create during provisioning) AND the orphan seen
//	in ≥2 consecutive cycles — a node missing from ONE List
//	(watch-cache gap, apiserver blip) must never detach a volume.
//
//	out_of_service_node — the node carries
//	node.kubernetes.io/out-of-service, the fencing signal CSI
//	respects (dead-node-sweeper and medik8s SNR set it once a node
//	is confirmed dead). On that taint attach-detach force-detaches
//	by deleting the VAs itself, so a VA still pointing at a fenced
//	node is a straggler — created after the taint, or its
//	force-delete wedged. Gates: node continuously not-Ready ≥ 15m
//	(first-seen ledger — a Ready node re-arms the window) AND a
//	live pod List confirms 0 non-terminal pods on it: a pod still
//	in Pending/Running on that node may still hold the mount, and
//	only the node controller — never us — force-deletes those.
//
// Hard bounds: the node list must be non-empty (an empty list means
// the apiserver or RBAC lied — every VA would look orphaned, so
// refuse to evaluate anything) and at most vaDeleteCap deletions per
// cycle bound the blast radius of a wrong verdict. Deletion is a
// plain Delete — the VA's own attacher finalizer still gates the
// real detach, but for the two shapes above removing the object is
// the unstick the PV needs.
package janitor

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/controller/shared"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

const (
	volumeAttachmentCleanerQueue = "volumeattachment-cleaner"
	vaCleanerInterval            = 5 * time.Minute

	// vaMissingNodeMinAge: a VA must exist at least this long before
	// "its node is gone" counts against it — a VA can legitimately
	// be created seconds before its Node object registers.
	vaMissingNodeMinAge = 5 * time.Minute
	// vaOutOfServiceDownFor: an out-of-service node must stay
	// not-Ready this long before its VAs are reaped — covers the
	// node controller's own force-detach grace so we only ever take
	// over a wedged cleanup, never a working one.
	vaOutOfServiceDownFor = 15 * time.Minute
	// vaDeleteCap bounds detach calls per cycle — a wrong verdict
	// must never detach more than a handful of volumes at once.
	vaDeleteCap = 10
	// vaOutOfServiceTaint is the Kubernetes-native "node is fenced"
	// signal — the same key dead-node-sweeper sets.
	vaOutOfServiceTaint = "node.kubernetes.io/out-of-service"
)

type volumeAttachmentCleaner struct {
	cs kubernetes.Interface
	// nowFn is the clock seam — tests pin and advance it freely.
	nowFn func() time.Time

	mu sync.Mutex
	// orphanFirstSeen: va name → first cycle the VA pointed at a
	// node that does not exist. Two consecutive sightings are
	// required to delete — an operator restart re-arms the window,
	// biasing conservative (same convention as helmrelease-unlocker).
	orphanFirstSeen map[string]time.Time
	// nodeNotReadySince: node name → first cycle the node was seen
	// not-Ready. Only consumed for out-of-service candidates, but
	// tracking every not-Ready node (not just tainted ones) means a
	// node that gets fenced after a long outage does not start a
	// fresh 15m window — its death clock was already running.
	nodeNotReadySince map[string]time.Time
}

// SetupVolumeAttachmentCleaner registers the 5-minute sweep. The
// enabled flag is wired by the caller (VOLUMEATTACHMENT_CLEANER_ENABLED,
// default on) — disabled skips registration entirely, matching the
// certmanager-reaper / cilium-taint-reaper contract.
func SetupVolumeAttachmentCleaner(mgr ctrl.Manager, cs kubernetes.Interface, enabled bool) error {
	if !enabled {
		logf.Log.WithName(volumeAttachmentCleanerQueue).Info("disabled — module not registered")
		return nil
	}
	c := &volumeAttachmentCleaner{
		cs:                cs,
		nowFn:             time.Now,
		orphanFirstSeen:   map[string]time.Time{},
		nodeNotReadySince: map[string]time.Time{},
	}
	return shared.AddPeriodic(mgr, volumeAttachmentCleanerQueue, vaCleanerInterval, c.run)
}

func (c *volumeAttachmentCleaner) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.nowFn()

	// Gate 1: the node list is the single source of truth for
	// "should this attachment exist". Abort on error — a partial or
	// blippy list would brand healthy attachments orphaned.
	nodes, err := shared.ListNodes(ctx, c.cs)
	if err != nil {
		return fmt.Errorf("list nodes: %w", err) // periodic wrapper IncErrors volumeattachment-cleaner
	}
	if len(nodes) == 0 {
		// An empty list is not "every VA is orphaned" — the operator
		// always runs against a cluster with nodes, so zero nodes
		// means the apiserver or RBAC broke. Refuse to evaluate.
		log.Info("SKIP: node list empty — refusing to evaluate attachments")
		return nil
	}
	nodeByName := make(map[string]*corev1.Node, len(nodes))
	for i := range nodes {
		n := &nodes[i]
		nodeByName[n.Name] = n
		// The not-Ready ledger feeds the out-of-service gate.
		// Recovery (or a vanished node, below) re-arms the window —
		// a node that flapped back to life must prove another full
		// 15m of death before its VAs are touched again.
		if !shared.NodeReady(n) {
			if _, ok := c.nodeNotReadySince[n.Name]; !ok {
				c.nodeNotReadySince[n.Name] = now
			}
		} else {
			delete(c.nodeNotReadySince, n.Name)
		}
	}
	for name := range c.nodeNotReadySince {
		if _, ok := nodeByName[name]; !ok {
			delete(c.nodeNotReadySince, name)
		}
	}
	nodes = nil

	vas, err := c.cs.StorageV1().VolumeAttachments().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list volumeattachments: %w", err)
	}
	// Deterministic order — the per-cycle cap must always pick the
	// same victims, not whichever ordering the apiserver returned.
	sort.Slice(vas.Items, func(i, j int) bool {
		return vas.Items[i].Name < vas.Items[j].Name
	})

	// orphanNow tracks which VAs still look missing-node orphaned
	// this cycle — a VA whose node reappeared, or that was deleted,
	// must re-arm the two-sighting rule.
	orphanNow := map[string]bool{}
	// livePods caches the per-node non-terminal pod verdict for the
	// cycle — several VAs typically share a node, and the List is
	// the expensive part of the out-of-service gate. Errors are
	// cached too (nil pods + err): without it every VA on one
	// fenced node would re-issue the same failing List and each
	// bump IncError.
	livePods := map[string]podProbe{}

	// seenPrior snapshots the ledger BEFORE this cycle's sightings —
	// "seen in >= 2 consecutive cycles" must compare against the
	// previous cycle, not the entry the pre-pass below just wrote.
	seenPrior := map[string]bool{}
	for name := range c.orphanFirstSeen {
		seenPrior[name] = true
	}

	// Pre-pass: record this cycle's missing-node sightings for EVERY
	// listed VA before any delete runs — a VA past the delete cap
	// keeps its firstSeen ledger instead of re-arming the
	// two-sighting window every capped cycle.
	for i := range vas.Items {
		va := &vas.Items[i]
		if va.DeletionTimestamp != nil {
			continue
		}
		if _, ok := nodeByName[va.Spec.NodeName]; !ok {
			orphanNow[va.Name] = true
			if _, seen := c.orphanFirstSeen[va.Name]; !seen {
				c.orphanFirstSeen[va.Name] = now
				log.Info("orphaned VA sighted — tracking for next cycle",
					"va", va.Name, "node", va.Spec.NodeName)
			}
		}
	}

	deleted, failed := 0, 0
	capped := false
	for i := range vas.Items {
		va := &vas.Items[i]
		if va.DeletionTimestamp != nil {
			// Already terminating — a second delete cannot unstick a
			// wedged attacher finalizer, and surfacing those is the
			// stuck-terminating audit's job (C3b).
			continue
		}

		reason := ""
		if node, ok := nodeByName[va.Spec.NodeName]; !ok {
			// missing_node: the node object is gone — the VA can
			// only be garbage. Still requires the VA to be old
			// enough AND a sighting in a PRIOR cycle (seenPrior),
			// so a one-off node List gap never detaches anything.
			if seenPrior[va.Name] &&
				now.Sub(va.CreationTimestamp.Time) >= vaMissingNodeMinAge {
				reason = "missing_node"
			}
		} else if c.nodeFencedDead(ctx, node, livePods, now) {
			reason = "out_of_service_node"
		}
		if reason == "" {
			continue
		}
		if deleted >= vaDeleteCap {
			capped = true
			break
		}

		log.Info(fmt.Sprintf("DELETE volumeattachment %s: reason=%s node=%s pv=%s",
			va.Name, reason, va.Spec.NodeName,
			ptr.Deref(va.Spec.Source.PersistentVolumeName, "?")))
		if err := c.cs.StorageV1().VolumeAttachments().Delete(ctx, va.Name,
			metav1.DeleteOptions{}); err != nil {
			metrics.IncError(volumeAttachmentCleanerQueue)
			log.Error(err, "volumeattachment delete failed",
				"va", va.Name, "node", va.Spec.NodeName,
				"pv", ptr.Deref(va.Spec.Source.PersistentVolumeName, "?"))
			failed++
			continue
		}
		metrics.VolumeAttachmentsCleanedTotal.WithLabelValues(reason).Inc()
		delete(c.orphanFirstSeen, va.Name)
		deleted++
	}
	// Re-arm the grace window for every VA that stopped looking
	// orphaned (node reappeared, or the VA vanished between cycles).
	for name := range c.orphanFirstSeen {
		if !orphanNow[name] {
			delete(c.orphanFirstSeen, name)
			log.Info("orphan sighting cleared — node reappeared or VA gone", "va", name)
		}
	}
	if capped {
		log.Info(fmt.Sprintf("SKIP rest: cap=%d reached", vaDeleteCap))
	}
	log.Info("sweep done", "deleted", deleted, "failed", failed)
	return nil
}

// nodeFencedDead is the out-of-service gate: true only when the node
// carries the fencing taint AND has been not-Ready past the window
// AND provably hosts zero non-terminal pods. Any failed check keeps
// the VA — the volume may still be mounted by something real.
// podProbe caches one node's live-pod verdict for the cycle: a
// successful count, or the list error (fail closed either way on
// retry within the same sweep).
type podProbe struct {
	count int
	err   error
}

func (c *volumeAttachmentCleaner) nodeFencedDead(ctx context.Context,
	node *corev1.Node, livePods map[string]podProbe, now time.Time) bool {
	log := logf.FromContext(ctx)
	if !shared.HasTaint(node.Spec.Taints, vaOutOfServiceTaint) {
		return false // not fenced — NotReady alone is never a verdict
	}
	if shared.NodeReady(node) {
		return false // fenced but alive — the taint is stale, VAs stay
	}
	since, ok := c.nodeNotReadySince[node.Name]
	if !ok {
		return false // node not in the not-Ready ledger — no verdict
	}
	if now.Sub(since) < vaOutOfServiceDownFor {
		log.Info("KEEP: fenced node still inside not-Ready window",
			"node", node.Name,
			"notReadyFor", now.Sub(since).Truncate(time.Minute),
			"required", vaOutOfServiceDownFor)
		return false // not-Ready window still running
	}
	live, err := c.livePodCount(ctx, livePods, node.Name)
	if err != nil {
		// Cannot prove the node is empty → cannot prove the mount
		// is dead. Fail closed: keep the VA, flag the API failure.
		metrics.IncError(volumeAttachmentCleanerQueue)
		log.Error(err, "pod list failed — keeping node VAs (fail closed)",
			"node", node.Name)
		return false
	}
	if live > 0 {
		log.Info("KEEP: fenced node still hosts non-terminal pods",
			"node", node.Name, "pods", live)
		return false
	}
	return true
}

// livePodCount lists pods bound to node and returns how many
// WORKLOAD pods are non-terminal (not Succeeded/Failed) — the "is
// anyone still potentially writing" check. DaemonSet and static
// mirror pods don't count: they run on every node, hold no PVC
// mounts, and on a fenced node are force-deleted + recreated as
// Pending by the controller — counting them would keep this gate
// permanently closed and the feature dead. Terminating workload
// pods count as live: a pod wedged in Terminating on a fenced node
// is the node controller's force-delete problem, and until it
// finishes the mount may still exist. Counts are cached per cycle.
func (c *volumeAttachmentCleaner) livePodCount(ctx context.Context,
	cache map[string]podProbe, node string) (int, error) {
	if pr, ok := cache[node]; ok {
		return pr.count, pr.err
	}
	pods, err := c.cs.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + node,
	})
	if err != nil {
		err = fmt.Errorf("list pods on %s: %w", node, err)
		cache[node] = podProbe{err: err}
		return 0, err
	}
	live := 0
	for i := range pods.Items {
		p := &pods.Items[i]
		// Fake clientsets ignore field selectors — the spec.nodeName
		// filter is applied in code too, same convention as the
		// phase filters elsewhere in this codebase.
		if p.Spec.NodeName != node {
			continue
		}
		if p.Status.Phase == corev1.PodSucceeded ||
			p.Status.Phase == corev1.PodFailed {
			continue // terminal — nobody is writing through it
		}
		if _, mirror := p.Annotations["kubernetes.io/config.mirror"]; mirror {
			continue // static pod mirror — the kubelet owns the real pod
		}
		ds := false
		for _, o := range p.OwnerReferences {
			if o.Kind == "DaemonSet" {
				ds = true
				break
			}
		}
		if ds {
			continue // infra agent — never holds a workload mount
		}
		live++
	}
	cache[node] = podProbe{count: live}
	return live, nil
}
