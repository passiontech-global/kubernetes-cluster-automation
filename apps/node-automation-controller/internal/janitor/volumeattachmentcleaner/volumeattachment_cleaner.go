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
// force-delete). Every gate exists to prove the node cannot be
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
// cycle bound the blast radius of a wrong verdict. The census rides
// the informer cache, so every destructive verdict is additionally
// confirmed by a live node Get on the direct clientset at the single
// Confirm point — the live answer wins (node present again keeps the
// VA; the apiserver answering NotFound stands), and a failed confirm
// keeps the VA fail-closed. Deletion is a
// plain Delete — the VA's own attacher finalizer still gates the
// real detach, but for the two shapes above removing the object is
// the unstick the PV needs.
//
// The gate proofs live in sibling files: va_missing_node_gate.go
// (gate 1 — the orphan sighting pre-pass and age proof),
// va_out_of_service_gate.go (gate 2 — the fenced-node proof) and
// va_stuck_terminating_gate.go (gate 3 — the va-stuck-terminating stuck-Terminating
// finalizer strip); this file keeps Setup and the sweep
// orchestration that consumes their verdicts.
package volumeattachmentcleaner

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

const (
	vaCleanerInterval = 5 * time.Minute

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
	// vaStuckTerminatingAge: a VA already carrying a DeletionTimestamp
	// this long whose node is gone or fenced-and-empty is a wedged
	// attach-detach cleanup — the external-attacher finalizer never
	// drains because the node it reports to no longer exists. Past
	// this age the cleaner strips the finalizers itself (va-stuck-terminating).
	vaStuckTerminatingAge = 15 * time.Minute
)

type volumeAttachmentCleaner struct {
	cs kubernetes.Interface
	// nodeReader backs ListNodesCached — the informer-backed node
	// census (read-only verdicts). Every destructive verdict still
	// confirms the node on the direct clientset at the sweep's
	// single Confirm point (confirmLiveNode) before any delete or
	// finalizer strip — a list can lag a Get. Nil (test fixtures)
	// falls back to ListNodes.
	nodeReader kube.CachedNodeReader
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name and every IncError label
	// come from one place.
	queue string
	// now is the clock seam — tests pin and advance it freely.
	now shared.Clock

	// orphanFirstSeen: va name → first cycle the VA pointed at a
	// node that does not exist. Two consecutive sightings are
	// required to delete — an operator restart re-arms the window,
	// biasing conservative (same convention as helmrelease-unlocker).
	orphanFirstSeen state.FirstSeenLedger
	// nodeNotReadySince: node name → first cycle the node was seen
	// not-Ready. Only consumed for out-of-service candidates, but
	// tracking every not-Ready node (not just tainted ones) means a
	// node that gets fenced after a long outage does not start a
	// fresh 15m window — its death clock was already running.
	nodeNotReadySince state.FirstSeenLedger
	// stuckReadyFirstSeen: va name → first cycle the VA sat stuck
	// Terminating on a Ready node with the volume provably unused
	// (the fast-reboot leak — the node came back before the fencing
	// taint ever landed). Two consecutive sightings are required to
	// strip — same conservative convention as orphanFirstSeen.
	stuckReadyFirstSeen state.FirstSeenLedger
	// finalizersRemovedEmitted is the carry-forward ledger for the
	// VolumeAttachmentFinalizersRemovedTotal counter (key node):
	// stripFinalizers Emits the tuple it Inc'd, each sweep re-emits
	// the tuples whose node this census still lists, and the
	// sweep's Prune retires the series once the node is gone — a
	// counter Inc is never undone by its own code path, so without
	// this the vec grows monotonically on node-pool rotation (the
	// same shape as deadnodesweeper's fencedWithoutSNREmitted).
	// Zero value ready.
	finalizersRemovedEmitted state.GaugeLedger[string]
}

// Setup registers the 5-minute sweep. The
// VOLUMEATTACHMENT_CLEANER_ENABLED gate (default on) is resolved by
// setupModules into Deps.Disabled — disabled skips registration
// entirely, matching the certmanager-reaper / cilium-taint-reaper
// contract.
func Setup(d shared.Deps) error {
	return shared.SetupNoConfig(d, func() error {
		c := &volumeAttachmentCleaner{
			cs:         d.CS,
			nodeReader: d.Mgr.GetClient(),
			queue:      d.Name,
			now:        shared.SystemClock,
		}
		return shared.AddPeriodic(d.Mgr, c.queue, vaCleanerInterval, c.run)
	})
}

func (c *volumeAttachmentCleaner) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	now := c.now.Now()

	// Drop any aborted sweep's leftover emissions so this sweep's
	// ledger state reflects only what THIS run measured.
	c.finalizersRemovedEmitted.Begin()

	// Gate 1: the node list is the single source of truth for
	// "should this attachment exist". Abort on error — a partial or
	// blippy list would brand healthy attachments orphaned.
	nodes, err := kube.ListNodesCached(ctx, c.nodeReader, c.cs)
	if err != nil {
		return fmt.Errorf("list nodes: %w", err) // periodic wrapper IncErrors volumeattachment-cleaner
	}
	if len(nodes) == 0 {
		// An empty list is not "every VA is orphaned" — the operator
		// always runs against a cluster with nodes, so zero nodes
		// means the apiserver or RBAC broke. Refuse to evaluate, but
		// meter it: a persistently-empty node list is invisible
		// otherwise (the run deliberately still returns nil).
		metrics.IncError(c.queue)
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
		c.trackNodeNotReady(n, now)
	}
	// A node that vanished between cycles re-arms too — its
	// not-Ready clock was measuring a node that no longer exists.
	c.pruneVanishedNodes(nodeByName)
	nodes = nil

	// Carry-forward: a finalizer-strip counter series stays alive
	// while its node still exists — re-emit every tracked tuple whose
	// node this census listed so the end-of-sweep Prune keeps it.
	// "Node absent" is the only resolve signal a strip counter has,
	// and only a sweep that actually listed the cluster may claim it
	// (the error and empty-list returns above leave the ledger
	// untouched). Fresh strips below re-emit their own tuples.
	for key, lv := range c.finalizersRemovedEmitted.Last() {
		if nodeByName[lv[0]] != nil {
			c.finalizersRemovedEmitted.Emit(key, lv...)
		}
	}

	vas, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.VolumeAttachments(c.cs))
	if err != nil {
		return fmt.Errorf("list volumeattachments: %w", err)
	}

	// Sweep phase (va_sweep.go): the cycle's probe caches + sighting
	// ledgers, the sighting pre-pass + target classification, and the
	// cap-bounded reap.Sweep whose Confirm re-proves every
	// destructive verdict on the live apiserver.
	cyc := newVaCycle()
	targets := c.buildTargets(ctx, vas, nodeByName, cyc, now, log)
	vas = nil // release the paged list before the sweep runs
	deleted, failed, capped := c.sweep(ctx, log, nodeByName, targets, cyc, now)

	// Re-arm the grace window for every VA that stopped looking
	// orphaned (node reappeared, or the VA vanished between cycles).
	c.forgetReattachedOrphans(cyc.orphanNow, log)
	// Same re-arm for the Ready-node window — the gate stopped
	// holding (pod rebound, volume re-attached, node unReady or the
	// VA resolved) resets the two-cycle count.
	c.forgetSettledStuckReady(cyc.stuckReadyNow)
	if capped {
		log.Info("SKIP rest: cap reached", "cap", vaDeleteCap)
	}
	// Retire strip-counter series whose node the census no longer
	// lists — node-pool rotation must not grow the vec for the
	// process lifetime (carry-forward above kept every tuple whose
	// node survived; only this complete-sweep path may claim a
	// resolve, mirroring the deadnodesweeper's end-of-sweep prunes).
	c.finalizersRemovedEmitted.Prune(metrics.VolumeAttachmentFinalizersRemovedTotal.DeleteLabelValues)
	log.Info("sweep done", "deleted", deleted, "failed", failed)
	return nil
}

// confirmLiveNode re-reads the VA's node on the DIRECT clientset —
// the destructive confirm the doc promises: the census verdict came
// off the informer-backed node list, and a list can lag a Get. The
// three-way verdict mirrors kube.ConfirmAbsent:
//
//	gone=true, node=nil — the apiserver itself answers NotFound: the
//	                     absence verdict stands (the strongest shape
//	                     of every destructive branch).
//	err!=nil            — the confirm itself failed: the caller
//	                     keeps the VA (fail closed) and meters once.
//	node!=nil, gone=false — the node still exists and the snapshot
//	                     was stale; the LIVE node wins over the
//	                     census and the destructive branch re-runs
//	                     against it.
func (c *volumeAttachmentCleaner) confirmLiveNode(ctx context.Context,
	name string) (node *corev1.Node, gone bool, err error) {
	n, getErr := c.cs.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
	gone, confirmErr := kube.ConfirmAbsent(getErr)
	if confirmErr != nil {
		return nil, false, confirmErr
	}
	if gone {
		return nil, true, nil
	}
	return n, false, nil
}
