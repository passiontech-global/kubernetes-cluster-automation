// partition_evictor.go — port of hooks/60-partition-pod-evictor.sh.
//
// Evicts non-HA infra pods off network-partitioned nodes: a node can stay
// Ready (kubelet posts status over a healthy path) while its pod IPs are
// unreachable from other sites — a single-replica source-controller
// stuck there blocked every Flux fetch for hours (incident 2026-09-28).
// NHC deliberately ignores pure partitions, so this sweep fills the gap.
//
// Flow (faithful to bash):
//   - flag a node when any NWPD network condition (plural or singular
//     spelling) is True continuously for >10m;
//   - re-confirm every flagged node against the LIVE API before acting
//     on it — the census rides the informer cache, and eviction must
//     never fire on a partition that healed inside the cache's lag
//     window (a failed live Get skips that node fail-closed for the
//     sweep);
//   - untaint recovered nodes first;
//   - abort when >= half (or all) nodes are flagged — that's a mesh-wide
//     partition where eviction only makes churn;
//   - taint flagged nodes passiontech.dev/network-partitioned=true:NoSchedule so
//     evicted pods don't get rescheduled onto the same broken node;
//   - delete pods in the configured namespaces (PARTITION_EVICT_NAMESPACES,
//     default flux-system) plus any pod carrying the
//     passiontech.dev/evict-on-partition=true opt-in annotation — in ANY
//     namespace — off flagged nodes, capped at 8/run.
//
// Three pod classes are never evicted no matter the namespace or the
// annotation: terminal pods (nothing left to move), DaemonSet pods
// (the daemon re-creates them in place — they are usually hostNetwork
// and unaffected by the pod-net partition anyway), and static mirror
// pods (the kubelet owns the real pod; the API object is a mirror).
package partitionevictor

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

const (
	partitionTaintKey = kube.TaintNetworkPartitioned
	partitionMinAge   = 600 * time.Second // condition True >10m before evicting
	partitionPodNS    = "flux-system"     // default for partitionNSsEnv
	partitionEvictCap = 8                 // bound churn per run
	// partitionNSsEnv is the comma-separated namespace allow-list the
	// sweep evicts from; unset/whitespace keeps the bash default
	// (partitionPodNS) so a misconfigured flag degrades to the
	// original behavior instead of silently evicting nothing.
	partitionNSsEnv = "PARTITION_EVICT_NAMESPACES"
	// partitionEvictAnno opts an individual pod into partition
	// eviction from ANY namespace — the escape hatch for
	// single-replica infra living outside the allow-list (a
	// cert-manager webhook or a database proxy wedged on a
	// blackholed node is just as stuck as source-controller was).
	// Pod-level only: partitionEvictable reads p.Annotations, never
	// the namespace object's — annotating the namespace opts
	// nothing in.
	partitionEvictAnno = kube.AnnoEvictOnPartition
	// mirrorPodAnno is the kubelet's static-pod marker — the API
	// object is only a mirror, the kubelet owns (and recreates) the
	// real pod, so deleting it buys nothing.
	mirrorPodAnno = "kubernetes.io/config.mirror"
)

// partitionNodePinnedStorageClasses are StorageClasses whose volumes
// are backed by the node's local disk — the provisioned PV carries
// node affinity, so a pod mounted to one can ONLY ever reschedule
// onto the node holding the data. Evicting such a pod off a
// partitioned node is pure churn: the replacement lands right back
// on the same broken host (or pends forever) — pinned-volume-guard adds
// openebs-hostpath alongside local-path, both hostPath-backed.
var partitionNodePinnedStorageClasses = map[string]bool{
	"local-path":       true,
	"openebs-hostpath": true,
}

// partitionCondTypes covers upstream NWPD K8sExporter plurals, the
// singular spellings some builds emit, NebulaIsolated — the
// node-host-agent's overlay-partition condition: a node cut off from
// the Nebula mesh is pod-unreachable from other sites in exactly the
// way this evictor exists for — and NebulaPMTUBlackhole, the
// node-host-agent's PMTU-blackhole latch (overlay path up but large
// packets dropped — same unreachable-from-peers shape). The names
// come from nodecond.PartitionNames, the source of truth shared with
// the node-host-agent so the two apps cannot drift.
var partitionCondTypes = kube.CondTypes(nodecond.PartitionNames)

// partitionCondHeartbeatMaxAge is how old an agent-emitted partition
// latch's lastHeartbeatTime may be before its True stops flagging the
// node — the reporter re-stamps it every ~2m while alive, so a frozen
// or absent stamp means the value is a zombie left by a dead agent
// (same 10m convention as nodehealth's precordon gate).
const partitionCondHeartbeatMaxAge = 10 * time.Minute

type partitionEvictor struct {
	cs kubernetes.Interface
	// dyn feeds the maintenance mutex's autopilot-Plan signal — the
	// pod evictions defer while a drain or k0s upgrade is in
	// flight. Nil (literal test fixtures) leaves the gate unarmed —
	// the same unarmed-seam convention as nodeReader/namespaces.
	dyn dynamic.Interface
	// nodeReader backs ListNodesCached — the informer-backed node
	// census; the taint/untaint writes still confirm on the direct
	// clientset. Nil (test fixtures) falls back to ListNodes.
	nodeReader kube.CachedNodeReader
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name and every IncError label
	// come from one place.
	queue string
	// verdict memoizes the maintenance-mutex evaluation so the
	// sweep pays one evaluation per TTL window.
	verdict kube.Verdict
	// now is the wall-clock seam so tests can age a partition
	// condition past partitionMinAge without sleeping. nil reads as
	// system time — the standard unarmed-seam convention.
	now shared.Clock
	// namespaces is the PARTITION_EVICT_NAMESPACES allow-list,
	// resolved once in Setup — env is fixed at process start, so the
	// sweep must not re-parse it per cycle. A nil field (a
	// literally-constructed test fixture) resolves lazily inside
	// run, the same unarmed-seam convention as Clock.
	namespaces map[string]struct{}
}

// Setup registers the 5-minute sweep (was crontab */5).
func Setup(d shared.Deps) error {
	return shared.SetupWithConfig(d, configFromEnv, func(cfg evictorConfig) error {
		e := &partitionEvictor{
			cs:         d.CS,
			dyn:        d.Dyn,
			nodeReader: d.Mgr.GetClient(),
			queue:      d.Name,
			now:        shared.SystemClock,
			namespaces: cfg.namespaces,
		}
		return shared.AddPeriodic(d.Mgr, e.queue, 5*time.Minute, e.run)
	})
}

// evictorConfig is the module's env-resolved knob set — carried
// through SetupWithConfig's parse step.
type evictorConfig struct {
	namespaces map[string]struct{}
}

// configFromEnv resolves the namespace allow-list ONCE at boot —
// the previous per-sweep parse implied env could change at runtime,
// which it cannot. SetupWithConfig runs it before the Deps.Disabled
// gate; partition-pod-evictor has no GateEnv today so the ordering
// is moot but keeps the parse->gate->register shape uniform with
// the gated modules.
func configFromEnv() evictorConfig {
	return evictorConfig{namespaces: partitionEvictNamespaces()}
}

// evictNamespaces returns the allow-list Setup stamped, resolving
// it lazily for fixtures that built the evictor literally — a nil
// field must not silently evict nothing.
func (e *partitionEvictor) evictNamespaces() map[string]struct{} {
	if e.namespaces == nil {
		return partitionEvictNamespaces()
	}
	return e.namespaces
}

// nodePartitioned reports whether any NWPD network condition has been
// True for longer than partitionMinAge measured against `now`. A
// missing/empty timestamp (bash's `[ -n "$ts" ]` guard) does NOT flag
// the node. The agent-emitted overlay latches (NebulaIsolated,
// NebulaPMTUBlackhole — nodecond.AgentHeartbeatManaged) additionally
// need a live lastHeartbeatTime: a frozen stamp means the wedged
// nodereporter can no longer vouch for the True, and evicting live
// pods on a zombie partition is exactly the churn this evictor exists
// to avoid. The NWPD monitor spellings are not agent-managed and keep
// the age-only gate.
func nodePartitioned(n *corev1.Node, now time.Time) bool {
	for _, t := range partitionCondTypes {
		c := kube.NodeCondition(n, t)
		if c == nil || c.Status != corev1.ConditionTrue ||
			c.LastTransitionTime.IsZero() ||
			now.Sub(c.LastTransitionTime.Time) <= partitionMinAge {
			continue
		}
		if nodecond.AgentHeartbeatManaged(string(t)) &&
			!kube.CondHeartbeatLive(c, partitionCondHeartbeatMaxAge, now) {
			continue // zombie latch — the reporter cannot vouch for it
		}
		return true
	}
	return false
}

// livePartitionTrue reports whether the LIVE node still reports any
// partition condition True — by status alone, deliberately without
// nodePartitioned's age and heartbeat gates. This is the untaint
// direction of the same signal: eviction needs PROOF a partition is
// real (aged past partitionMinAge, live-heartbeat vouch) before it
// acts, but an untaint needs PROOF the partition is gone before the
// fence comes down. So every True counts against recovery: a fresh
// latch still inside partitionMinAge, and a zombie one the wedged
// reporter can no longer vouch for, both keep the fence up this
// sweep even though nodePartitioned would flag neither.
func livePartitionTrue(n *corev1.Node) bool {
	for _, t := range partitionCondTypes {
		if c := kube.NodeCondition(n, t); c != nil && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// partitionEvictNamespaces parses PARTITION_EVICT_NAMESPACES into the
// namespace set the sweep evicts from: comma-separated, entries
// trimmed, blanks dropped (so "a, ,b" and trailing commas produce no
// phantom namespace). Unset or all-empty falls back to partitionPodNS.
func partitionEvictNamespaces() map[string]struct{} {
	raw := strings.TrimSpace(envx.Getenv(partitionNSsEnv, ""))
	if raw == "" {
		raw = partitionPodNS
	}
	out := make(map[string]struct{})
	for _, ns := range strings.Split(raw, ",") {
		if ns = strings.TrimSpace(ns); ns != "" {
			out[ns] = struct{}{}
		}
	}
	return out
}

// partitionEvictable reports whether pod p is a candidate for
// partition eviction. Membership is by the configured namespace set
// OR the passiontech.dev/evict-on-partition=true opt-in annotation, but
// three classes are always skipped no matter where they live:
//   - terminal pods (Succeeded/Failed): dead weight, nothing to move;
//   - DaemonSet pods: the daemon re-creates them in place — and DS
//     pods are usually hostNetwork, so the pod-net partition does not
//     strand them anyway;
//   - static mirror pods: the kubelet owns the real pod — deleting
//     the mirror only produces a new mirror.
func partitionEvictable(p *corev1.Pod, namespaces map[string]struct{}) bool {
	if p.Status.Phase == corev1.PodSucceeded ||
		p.Status.Phase == corev1.PodFailed {
		return false
	}
	if p.DeletionTimestamp != nil {
		// Already terminating — a re-delete changes nothing but the
		// attempt still counts against partitionEvictCap, so enough
		// wedged pods would starve the real victims.
		return false
	}
	if _, mirror := p.Annotations[mirrorPodAnno]; mirror {
		return false
	}
	for _, o := range p.OwnerReferences {
		if o.Kind == "DaemonSet" {
			return false
		}
	}
	if _, ok := namespaces[p.Namespace]; ok {
		return true
	}
	return p.Annotations[partitionEvictAnno] == "true"
}

// nodePinnedPVCs returns the set of "ns/name" PVCs whose
// spec.storageClassName is node-pinned (see
// partitionNodePinnedStorageClasses). A list failure is a real
// error — the caller fails the eviction pass closed rather than
// evicting pods it cannot prove are movable.
func (e *partitionEvictor) nodePinnedPVCs(ctx context.Context) (map[string]struct{}, error) {
	pvcs, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.PersistentVolumeClaims(e.cs, metav1.NamespaceAll))
	if err != nil {
		return nil, fmt.Errorf("list persistentvolumeclaims: %w", err)
	}
	out := map[string]struct{}{}
	for i := range pvcs {
		sc := pvcs[i].Spec.StorageClassName
		if sc != nil && partitionNodePinnedStorageClasses[*sc] {
			out[pvcs[i].Namespace+"/"+pvcs[i].Name] = struct{}{}
		}
	}
	return out, nil
}

// podOnNodePinnedPVC reports whether any of the pod's volumes pins it
// to its current node — a PVC whose storage class is node-pinned (see
// partitionNodePinnedStorageClasses; the volume's node affinity means
// the pod can only ever run on the node holding the data), a generic
// ephemeral volume (its PVC is provisioned on the node running the
// pod and dies with it), or a hostPath volume (the path only exists
// on this node). Such a pod is bound to its node and cannot be
// usefully evicted.
func podOnNodePinnedPVC(p *corev1.Pod, pinned map[string]struct{}) bool {
	for _, v := range p.Spec.Volumes {
		if v.Ephemeral != nil || v.HostPath != nil {
			return true
		}
		if pvc := v.PersistentVolumeClaim; pvc != nil {
			if _, ok := pinned[p.Namespace+"/"+pvc.ClaimName]; ok {
				return true
			}
		}
	}
	return false
}

// run sequences one sweep: census the cached nodes, re-confirm the
// flagged ones live, untaint recovered nodes, then — unless the
// mesh-wide guard aborts — fence the flagged nodes and evict their
// eligible pods. The phases live in partition_evictor_sweep.go.
func (e *partitionEvictor) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	s := &partitionSweep{e: e, log: log, now: e.now.Now()}
	if err := s.census(ctx); err != nil {
		return err
	}
	s.confirmLive(ctx)
	s.untaintRecovered(ctx)

	nFlagged := len(s.flagged)
	if nFlagged == 0 {
		log.Info("OK: no partitioned nodes")
		return nil
	}

	// Mesh-wide guard: >50% of EVICTABLE nodes flagged means the
	// partition is not node-local — evicting just churns pods
	// between broken nodes. Live-healed nodes left the set above;
	// unconfirmable ones (live Get failed) deliberately still count.
	if nFlagged*2 > s.total {
		log.Info("ABORT: nodes flagged — mesh-wide partition, no evict",
			"flagged", nFlagged, "total", s.total, "nodes", s.sortedFlagged())
		return nil
	}

	s.taintFlagged(ctx)
	s.evictPods(ctx)
	return nil
}
