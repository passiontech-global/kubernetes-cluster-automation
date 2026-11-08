// dead-node-sweeper — port of hooks/90-dead-node-sweeper.sh.
//
// Force-evicts pods stuck in Terminating on a dead node. A pod whose
// kubelet stopped answering stays "Terminating" forever (grace-period
// timers run on the kubelet, not the apiserver): PVCs stay attached,
// Deployments/StatefulSets can't reschedule, and `kubectl delete pod
// --force` is a foot-gun because it can produce two writers on one
// volume if the node is only partitioned (incident 2026-11-02: 40+
// Terminating pods on a power-failed worker, DBs pending for hours).
//
// The fix is NOT force-delete — it is the out-of-service taint
// (node.kubernetes.io/out-of-service=nodeshutdown:NoExecute). On that
// taint the node-controller itself force-deletes the node's pods and
// the attach-detach controller force-detaches its volumes — the same
// code path kubectl-node-shell / medik8s SNR use, so failover is
// atomic with no split-brain window.
//
// SAFETY — fail closed, always. The taint is applied only when there
// is independent evidence the node is fenced:
//
//	(a) a medik8s remediation CR exists for the node
//	    (selfnoderemediations.self-node-remediation.medik8s.io or
//	    fenceagentsremediations.fence-agents-remediation.medik8s.io, any namespace,
//	    named after the node) — a fencer already declared it dead; or
//	(b) Ready=Unknown for >30m AND the kubelet /healthz probe through
//	    the apiserver proxy fails — kubelet is unreachable AND the
//	    node-controller gave up on its lease long ago.
//
// W15-ST1 hardens branch (b) further: that evidence is one-sided
// (we cannot hear the node — the node may not hear US), so a node
// holding an RWO VolumeAttachment or a StatefulSet pod is NOT
// tainted. The out-of-service taint on a partitioned-but-alive node
// is a split-brain on its volumes. The skip is exported as
// node_automation_dead_node_unfenced_stateful_skipped; fencing such a
// node requires a medik8s CR or the explicit
// DEAD_NODE_SWEEPER_FENCE_UNFENCED_STATEFUL=true override, and every
// fence applied without a CR is counted by
// node_automation_dead_node_fenced_without_snr_total.
//
// A node that is merely NotReady (Ready=False) with no remediation CR
// and a fresh-enough heartbeat window is left alone — that is the
// host-watchdog / NHC layer's job. Pods on Ready nodes are skipped
// entirely. At most one node is tainted per cycle, so even a wrong
// verdict bounds the blast radius. Pods are never deleted directly.
//
// Recovery: a node that comes back Ready=True while still carrying
// the out-of-service taint gets untainted so it rejoins scheduling.
package deadnodesweeper

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	// deadNodeStuckPodAge: how long a pod may sit in Terminating
	// before its node is suspected. Longer than any legitimate
	// graceful shutdown (default grace 30s, worst-case preStop +
	// 5-10m drains) so normal deletes are never touched.
	deadNodeStuckPodAge = 15 * time.Minute
	// deadNodeUnknownAge: Ready=Unknown must persist this long
	// before path (b) is even considered — covers monitor-grace
	// (40s), lease retry storms and short network partitions.
	deadNodeUnknownAge = 30 * time.Minute
	// per-probe apiserver timeout (8s) lives in kube.KubeletHealthz —
	// this module used to define it as "same as the kubelet reaper's".
	// deadNodeCap: nodes tainted per cycle — wrong verdicts must
	// never take more than one node at a time.
	deadNodeCap = 1
	// outOfServiceTaint*: the Kubernetes-native "node is fenced"
	// signal — node lifecycle controller force-deletes the pods,
	// attach-detach controller force-detaches the volumes.
	outOfServiceTaintKey   = "node.kubernetes.io/out-of-service"
	outOfServiceTaintValue = "nodeshutdown"
)

// medik8s remediation CRs — a fencer naming a node is the strongest
// death certificate available in-cluster.
var (
	selfNodeRemediationGVR    = kube.GVRSelfNodeRemediation
	fenceAgentsRemediationGVR = kube.GVRFenceAgentsRemediation
)

type deadNodeSweeper struct {
	cs  kubernetes.Interface
	dyn dynamic.Interface
	// nodeReader backs ListNodesCached — the informer-backed node
	// census; the destructive confirm (UntaintNode/TaintNode re-Get)
	// stays on the direct clientset. Nil (test fixtures) falls back
	// to ListNodes.
	nodeReader kube.CachedNodeReader
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name and every IncError label
	// come from one place.
	queue string
	// now is the wall-clock seam so tests can pin the stuck-pod and
	// Unknown-window verdicts. nil reads as system time — the
	// standard unarmed-seam convention.
	now shared.Clock
	// Probe seam — same trick as kubeletReaper: the node/proxy REST
	// path cannot be served by the fake clientset, so tests stub the
	// healthz outcome per node.
	probeFn func(ctx context.Context, nodeName string) (bool, error)
}

// Setup registers the 5-minute sweep.
func Setup(d shared.Deps) error {
	s := &deadNodeSweeper{cs: d.CS, dyn: d.Dyn, queue: d.Name,
		nodeReader: d.Mgr.GetClient(), now: shared.SystemClock}
	s.probeFn = s.probe
	return shared.AddPeriodic(d.Mgr, s.queue, 5*time.Minute, s.run)
}

func (s *deadNodeSweeper) run(ctx context.Context) error {
	log := logf.FromContext(ctx)

	nodes, err := kube.ListNodesCached(ctx, s.nodeReader, s.cs)
	if err != nil {
		return fmt.Errorf("list nodes: %w", err)
	}
	nodeByName := make(map[string]*corev1.Node, len(nodes))
	nodeNames := make(map[string]bool, len(nodes))
	hasNotReady := false
	untainted := 0
	for i := range nodes {
		n := &nodes[i]
		nodeByName[n.Name] = n
		nodeNames[n.Name] = true
		if !kube.NodeReady(n) {
			hasNotReady = true
		}

		// Recovery first: a node back to Ready=True must not keep
		// the out-of-service taint or it stays unschedulable.
		if kube.HasTaint(n.Spec.Taints, outOfServiceTaintKey) && kube.NodeReady(n) {
			if err := kube.UntaintNode(ctx, s.cs, n.Name, outOfServiceTaintKey); err != nil {
				log.Error(err, "untaint failed", "node", n.Name)
				metrics.IncError(s.queue)
				continue
			}
			untainted++
			// W15-ST1 — a recovered node's stale skip flag reads as
			// an unfenced dead node forever; clear it with the taint.
			metrics.DeadNodeUnfencedStatefulSkipped.DeleteLabelValues(n.Name)
			log.Info("UNTAINT: node Ready again -> out-of-service removed", "node", n.Name)
		}
	}
	// nodeByName holds all the node data the rest of the sweep needs —
	// the slice copy stays reachable through it, so only the redundant
	// slice header is dropped here (keeps the diff honest about which
	// references are actually dead).
	nodes = nil

	// Every node Ready = nothing can be fenced this cycle, so skip
	// the cluster-wide pod list entirely: it is by far the biggest
	// read this module makes (every pod in the cluster, deserialized)
	// and the all-Ready happy path never consumes it. A stuck pod on
	// a since-deleted node could only produce a skip-log anyway.
	if !hasNotReady {
		log.Info("sweep done — all nodes Ready", "untainted", untainted)
		return nil
	}

	// Server-side phase filter: terminal pods can never be "stuck
	// Terminating" evidence, so they are dead weight in the biggest
	// read this module makes. The in-code phase check stays — fake
	// clientsets ignore field selectors and the belt costs nothing.
	// Paged: one unbounded List forces the apiserver to serialize
	// every pod in the cluster into a single response — a multi-MB
	// heap burst both server- and client-side; 500-per-page flattens
	// it while keeping only the per-node Terminating counts.
	// The stuck-pod count is folded INTO the pagination loop — each
	// page is tallied and dropped, so peak client heap is one page,
	// not every pod in the cluster (which is the same footprint the
	// unbounded List had).
	// One "now" pins the whole sweep — a stuck verdict measured
	// against a drifting wall clock inside a thousands-pod page loop
	// could straddle the threshold mid-pass.
	now := s.now.Now()
	stuck := map[string]int{}
	err = kube.ListEach(ctx, metav1.ListOptions{
		FieldSelector: "status.phase!=Succeeded,status.phase!=Failed",
		Limit:         kube.DefaultListPageSize,
	}, kube.Pods(s.cs, metav1.NamespaceAll),
		func(items []corev1.Pod) error {
			for i := range items {
				p := &items[i]
				if p.Status.Phase == corev1.PodSucceeded ||
					p.Status.Phase == corev1.PodFailed {
					continue // mirrors the FieldSelector for fake clients
				}
				if p.DeletionTimestamp == nil || p.Spec.NodeName == "" {
					continue
				}
				if now.Sub(p.DeletionTimestamp.Time) <= deadNodeStuckPodAge {
					continue // still inside a legitimate graceful shutdown
				}
				stuck[p.Spec.NodeName]++
			}
			return nil
		})
	if err != nil {
		return fmt.Errorf("list pods: %w", err)
	}
	if len(stuck) == 0 {
		log.Info("sweep done — no stuck Terminating pods", "untainted", untainted)
		return nil
	}

	// Deterministic order so the per-cycle cap picks the same node.
	names := make([]string, 0, len(stuck))
	for name := range stuck {
		names = append(names, name)
	}
	sort.Strings(names)

	// The two medik8s remediation CRD lists are fetched once per
	// sweep — lazily on the first death check — and shared by every
	// suspect node (previously one List pair PER node).
	remCache := &remediationCache{}
	tainted := 0
	for _, nodeName := range names {
		count := stuck[nodeName]

		n := nodeByName[nodeName]
		if n == nil {
			log.Info("SKIP: node object gone — apiserver already force-removed it?",
				"node", nodeName, "stuckPods", count)
			continue
		}
		if kube.NodeReady(n) {
			// Node is alive: Terminating pods there are a wedged
			// runtime/finalizer problem — the host watchdog's job,
			// not a fencing decision.
			log.Info("SKIP: node still Ready", "node", nodeName, "stuckPods", count)
			continue
		}
		if kube.HasTaint(n.Spec.Taints, outOfServiceTaintKey) {
			// Already fenced — the node controller is working on
			// the force-deletes; does not consume the cap.
			log.Info("KEEP-TAINT: already out-of-service", "node", nodeName, "stuckPods", count)
			continue
		}
		if tainted >= deadNodeCap {
			log.Info("SKIP rest: cap reached", "cap", deadNodeCap, "node", nodeName, "stuckPods", count)
			continue
		}

		dead, viaSNR, reason, err := s.confirmedDead(ctx, n, remCache, nodeNames)
		if err != nil {
			log.Error(err, "death check failed — node skipped (fail closed)",
				"node", nodeName, "stuckPods", count)
			metrics.IncError(s.queue)
			continue
		}
		if !dead {
			log.Info("SKIP: no fencing evidence — fail closed",
				"node", nodeName, "stuckPods", count)
			continue
		}

		// W15-ST1 — branch (b) (dead without a medik8s SNR CR): the
		// evidence is one-sided — we cannot hear the node, but the
		// node may simply not hear US. A node holding an RWO
		// VolumeAttachment or a StatefulSet pod could come back and
		// write over its re-bound volumes: exactly the split-brain a
		// fencer CR exists to rule out. Fail closed and leave the
		// decision to medik8s unless the operator's override says
		// otherwise.
		hasVolumes := false
		if !viaSNR {
			holds, holdsErr := s.nodeHasStatefulHolders(ctx, nodeName)
			if holdsErr != nil {
				log.Error(holdsErr, "stateful-holder check failed — node skipped (fail closed)",
					"node", nodeName, "stuckPods", count)
				metrics.IncError(s.queue)
				continue
			}
			hasVolumes = holds
			if holds && !fenceUnfencedStateful() {
				metrics.DeadNodeUnfencedStatefulSkipped.WithLabelValues(nodeName).Set(1)
				log.Info("SKIP: dead node holds stateful volumes/pods without medik8s SNR CR — fail closed against split-brain",
					"node", nodeName, "stuckPods", count)
				continue
			}
		}

		// Signal only: which volumes will the taint force-detach.
		// Failure here must not veto the taint decision.
		s.logVolumeAttachments(ctx, nodeName)

		if err := kube.TaintNode(ctx, s.cs, nodeName, outOfServiceTaintKey,
			outOfServiceTaintValue, corev1.TaintEffectNoExecute); err != nil {
			log.Error(err, "out-of-service taint failed", "node", nodeName,
				"stuckPods", count)
			metrics.IncError(s.queue)
			continue
		}
		tainted++
		// W15-ST1 — a fence without a SNR CR is a judgment call even
		// with the override: count it per node (and clear any stale
		// skip flag — the fence resolves the hold) so alerting sees
		// every fence the sweeper decided on its own evidence.
		if !viaSNR {
			metrics.DeadNodeFencedWithoutSNRTotal.WithLabelValues(
				nodeName, strconv.FormatBool(hasVolumes)).Inc()
			metrics.DeadNodeUnfencedStatefulSkipped.DeleteLabelValues(nodeName)
		}
		log.Info("TAINT: node confirmed dead -> out-of-service=nodeshutdown:NoExecute "+
			"(pods force-deleted, volumes detached by node controller)",
			"node", nodeName, "stuckPods", count,
			"evidence", reason, "viaSNR", viaSNR)
	}
	log.Info("sweep done", "tainted", tainted, "untainted", untainted,
		"stuckNodes", len(stuck))
	return nil
}

// confirmedDead is the safety gate — dead only with independent
// fencing evidence: (a) a medik8s remediation CR (viaSNR=true), or
// (b) Ready=Unknown>30m + a dead kubelet probe (viaSNR=false — no
// fencer has certified the death, so the caller owes the node the
// W15-ST1 stateful split-brain gate before tainting). reason carries
// the evidence for the caller's logs; a dead=false result leaves it
// empty.
func (s *deadNodeSweeper) confirmedDead(ctx context.Context, n *corev1.Node,
	rem *remediationCache, nodeNames map[string]bool) (dead, viaSNR bool, reason string, err error) {
	log := logf.FromContext(ctx)

	// Path (a): a fencer CR exists for the node.
	fenced, err := s.hasRemediationCR(ctx, n.Name, rem, nodeNames)
	if err != nil {
		return false, false, "", err
	}
	if fenced {
		log.Info("fencing evidence: medik8s remediation CR", "node", n.Name)
		return true, true, "medik8s remediation CR", nil
	}

	// Path (b): Ready=Unknown held for >30m (the node controller
	// stopped getting heartbeats long ago) AND the kubelet does not
	// answer /healthz through the apiserver proxy.
	c := kube.NodeCondition(n, corev1.NodeReady)
	if c == nil || c.Status != corev1.ConditionUnknown {
		return false, false, "", nil // NotReady/False alone is not a death certificate
	}
	if c.LastTransitionTime.IsZero() ||
		s.now.Now().Sub(c.LastTransitionTime.Time) <= deadNodeUnknownAge {
		return false, false, "", nil
	}
	ok, err := s.probeFn(ctx, n.Name)
	if err != nil {
		// A probe that errors out IS a failed probe — the kubelet
		// did not serve healthz (same meaning as kubelet reaper's
		// DoRaw error). Logged for forensics, not counted as a
		// module failure.
		log.Error(err, "kubelet healthz probe errored — counts as failed", "node", n.Name)
		return true, false, "Ready=Unknown>30m + kubelet probe failed", nil
	}
	if !ok {
		log.Info("fencing evidence: Ready=Unknown>30m + kubelet probe failed", "node", n.Name)
		return true, false, "Ready=Unknown>30m + kubelet probe failed", nil
	}
	return false, false, "", nil
}

// fenceUnfencedStateful reads the split-brain override EVERY cycle —
// the same hot-reload ops-lever convention as the webhookguard gates.
// Opt-in (exactly "true"), default off: it authorizes fencing a
// branch-(b) node that holds stateful volumes/pods without a medik8s
// SNR CR, an operator's explicit "I know the node is really dead".
func fenceUnfencedStateful() bool {
	return envx.Gate("DEAD_NODE_SWEEPER_FENCE_UNFENCED_STATEFUL", false)
}

// nodeHasStatefulHolders (W15-ST1) reports whether the node holds
// anything that makes force-detaching its volumes dangerous: a
// VolumeAttachment whose volume carries a ReadWriteOnce access mode
// (RWO is the single-writer contract a not-really-dead node breaks
// loudly), or a Pod owned by a StatefulSet (its identity is
// volume-bound even when the current spec lost the claim). A list
// failure is an error — the caller fails closed.
func (s *deadNodeSweeper) nodeHasStatefulHolders(ctx context.Context, nodeName string) (bool, error) {
	// One PV census for the whole check: PV-referenced attachments
	// carry only the volume NAME — the access modes live on the PV
	// object itself (inline CSI specs carry their own). PVs are
	// cluster-scoped and number in the dozens, so one paged list is
	// the cheap shape.
	pvModes := map[string][]corev1.PersistentVolumeAccessMode{}
	err := kube.ListEach(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.PersistentVolumes(s.cs),
		func(items []corev1.PersistentVolume) error {
			for i := range items {
				pvModes[items[i].Name] = items[i].Spec.AccessModes
			}
			return nil
		})
	if err != nil {
		return false, fmt.Errorf("list persistentvolumes: %w", err)
	}
	hasRWO := false
	err = kube.ListEach(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.VolumeAttachments(s.cs),
		func(items []storagev1.VolumeAttachment) error {
			for i := range items {
				if items[i].Spec.NodeName == nodeName && volumeAttachmentRWO(&items[i], pvModes) {
					hasRWO = true
				}
			}
			return nil
		})
	if err != nil {
		return false, fmt.Errorf("list volumeattachments: %w", err)
	}
	if hasRWO {
		return true, nil
	}

	// Server-side node filter with the in-code check kept — fake
	// clientsets ignore field selectors (the belt every paged pod
	// list in this codebase wears).
	stsPod := false
	err = kube.ListEach(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + nodeName,
		Limit:         kube.DefaultListPageSize,
	}, kube.Pods(s.cs, metav1.NamespaceAll),
		func(items []corev1.Pod) error {
			for i := range items {
				p := &items[i]
				if p.Spec.NodeName != nodeName {
					continue
				}
				for _, ref := range p.OwnerReferences {
					if ref.Kind == "StatefulSet" {
						stsPod = true
					}
				}
			}
			return nil
		})
	if err != nil {
		return false, fmt.Errorf("list pods: %w", err)
	}
	return stsPod, nil
}

// volumeAttachmentRWO reports whether the attachment's volume carries
// a ReadWriteOnce access mode: inline CSI specs resolve off their own
// spec, PV-referenced ones off the pvModes census. A volume with no
// modes anywhere (attachment still in flight, PV since deleted)
// cannot prove multi-writer safety either way and reads as NOT RWO —
// logVolumeAttachments still names it for forensics.
func volumeAttachmentRWO(va *storagev1.VolumeAttachment,
	pvModes map[string][]corev1.PersistentVolumeAccessMode) bool {
	if va.Spec.Source.InlineVolumeSpec != nil {
		for _, mode := range va.Spec.Source.InlineVolumeSpec.AccessModes {
			if mode == corev1.ReadWriteOnce {
				return true
			}
		}
	}
	if name := va.Spec.Source.PersistentVolumeName; name != nil {
		for _, mode := range pvModes[*name] {
			if mode == corev1.ReadWriteOnce {
				return true
			}
		}
	}
	return false
}

// remediationNodeNameAnno is the annotation medik8s NHC (>= v0.6)
// stamps on remediation CRs it names "<nodeName>-<templateName>"
// (escalatingRemediations / multi-template setups) — the CR name no
// longer equals the node name, so the annotation carries the
// fencing target (W12 P0-7).
const remediationNodeNameAnno = "remediation.medik8s.io/node-name"

// remediationCache memoizes the once-per-sweep remediation CR
// listing — the same API read serves every suspect node in the
// cycle, so N suspects cost two List calls total, not 2N. A list
// failure is cached too: the verdict stays consistent across the
// sweep instead of re-hammering a flapping API per node.
type remediationCache struct {
	fetched bool
	items   []unstructured.Unstructured
	err     error
}

// remediationItems returns both CRDs' objects, listing at most once
// per cache instance. A missing CRD is "no evidence" for that GVR —
// other list failures are real and sticky for the sweep.
func (s *deadNodeSweeper) remediationItems(ctx context.Context,
	rem *remediationCache) ([]unstructured.Unstructured, error) {
	// A missing dynamic client is a wiring bug, not "no fencing
	// evidence" — unverifiable fails closed like every other check
	// (same contract as descheduler-storm-gate's dyn guard).
	if s.dyn == nil {
		return nil, errors.New("no dynamic client — remediation CR check unverifiable")
	}
	if rem.fetched {
		return rem.items, rem.err
	}
	rem.fetched = true
	for _, gvr := range []schema.GroupVersionResource{
		selfNodeRemediationGVR, fenceAgentsRemediationGVR,
	} {
		items, err := kube.ListAll(ctx,
			metav1.ListOptions{Limit: kube.DefaultListPageSize},
			kube.DynamicPage(s.dyn.Resource(gvr).Namespace(metav1.NamespaceAll)))
		if err != nil {
			if apierrors.IsNotFound(err) || meta.IsNoMatchError(err) {
				continue // CRD not installed on this cluster
			}
			rem.err = fmt.Errorf("list %s: %w", gvr.Resource, err)
			return nil, rem.err
		}
		rem.items = append(rem.items, items...)
	}
	return rem.items, nil
}

// hasRemediationCR reports whether any medik8s remediation object
// targets the node: the remediation.medik8s.io/node-name annotation
// (AUTHORITATIVE when present — a CR stamped for another node is
// never evidence here), CR name == node name (the 1:1 shape both
// CRDs historically use), or a "<nodeName>-" name prefix (the
// template-suffixed shape NHC v0.6+ emits). The prefix fallback is
// guarded by the known node set: a CR like "worker-1-gpu" or
// "worker-1-gpu-<tpl>" belongs to the node worker-1-gpu, and a bare
// HasPrefix match would otherwise let it fence worker-1.
func (s *deadNodeSweeper) hasRemediationCR(ctx context.Context, nodeName string,
	rem *remediationCache, nodeNames map[string]bool) (bool, error) {
	items, err := s.remediationItems(ctx, rem)
	if err != nil {
		return false, err
	}
	for i := range items {
		crName := items[i].GetName()
		if anno := items[i].GetAnnotations()[remediationNodeNameAnno]; anno != "" {
			// The annotation is the fencing target — when it is
			// present it decides alone: no name or prefix match can
			// override it (a "worker-1-gpu-<tpl>" CR annotated for
			// worker-1-gpu must not fence worker-1).
			if anno == nodeName {
				return true, nil
			}
			continue
		}
		if crName == nodeName {
			return true, nil
		}
		if strings.HasPrefix(crName, nodeName+"-") &&
			!ownedByLongerNode(crName, nodeName, nodeNames) {
			return true, nil
		}
	}
	return false, nil
}

// ownedByLongerNode reports whether crName is actually named after a
// DIFFERENT known node with a longer name — the "worker-1-gpu" vs
// "worker-1" prefix-collision guard: a bare HasPrefix match would
// let a CR that belongs to worker-1-gpu fence worker-1.
func ownedByLongerNode(crName, nodeName string, nodeNames map[string]bool) bool {
	for other := range nodeNames {
		if len(other) <= len(nodeName) {
			continue // only a strictly-longer name can steal the prefix
		}
		if crName == other || strings.HasPrefix(crName, other+"-") {
			return true
		}
	}
	return false
}

// probe is a single kube.KubeletHealthz attempt — a body starting
// with "ok" is healthy. No retries: the 30m Unknown window already
// absorbed transient wobble.
func (s *deadNodeSweeper) probe(ctx context.Context, nodeName string) (bool, error) {
	body, err := kube.KubeletHealthz(ctx, s.cs, nodeName)
	if err != nil {
		return false, err
	}
	return strings.HasPrefix(strings.TrimSpace(string(body)), "ok"), nil
}

// logVolumeAttachments lists VolumeAttachments bound to the node as a
// forensics signal (these are what the taint will force-detach).
// Never fatal, never vetoes a decision.
func (s *deadNodeSweeper) logVolumeAttachments(ctx context.Context, nodeName string) {
	log := logf.FromContext(ctx)
	// Paged like the pod list above — VolumeAttachments are
	// cluster-scoped and unbounded, and this read is signal-only.
	var names []string
	err := kube.ListEach(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.VolumeAttachments(s.cs),
		func(items []storagev1.VolumeAttachment) error {
			for i := range items {
				if items[i].Spec.NodeName == nodeName {
					names = append(names, items[i].Name)
				}
			}
			return nil
		})
	if err != nil {
		log.Error(err, "volumeattachment list failed — signal only", "node", nodeName)
		metrics.IncError(s.queue)
		return
	}
	if len(names) > 0 {
		log.Info("node holds volumeattachments — taint will force-detach",
			"node", nodeName, "attachments", names)
	}
}
