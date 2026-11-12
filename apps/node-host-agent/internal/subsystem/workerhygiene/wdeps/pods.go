// pods.go — the pod-level helpers several domain checks share:
// the API-side verdicts (Ready, mirror, PVC consumer) and the
// verified force-delete the teardown check spends after its
// zero-live-task proof. ForceDeletePod lives here (not in pods/)
// because the log line is an NPD contract shared by every caller.
package wdeps

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
)

// PodHasPVC reports whether the pod mounts a persistentVolumeClaim —
// force-deleting a PVC consumer on a wrong "dead" verdict risks a
// dual-mount of an RWO volume.
func PodHasPVC(p *corev1.Pod) bool {
	for _, v := range p.Spec.Volumes {
		// PVC + generic ephemeral volumes share the same dual-mount
		// risk class on a wrong "dead" verdict.
		if v.PersistentVolumeClaim != nil || v.Ephemeral != nil {
			return true
		}
	}
	return false
}

// IsMirrorPod reports kubelet-static mirror pods — deleting the
// mirror object changes nothing on disk.
func IsMirrorPod(p *corev1.Pod) bool {
	_, ok := p.Annotations["kubernetes.io/config.mirror"]
	return ok
}

// PodReady reports whether the pod's Ready condition is True — the
// API-side verdict the datapath guards contrast against (a pod
// Ready=True whose service listener is dead is exactly the wedge
// these checks heal).
func PodReady(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// ForceDeletePod removes the pod object with grace 0 + Background
// propagation — reached only after zero-live-task verification, so it
// is pure object cleanup (no split-brain/dual-mount risk).
func (d *Deps) ForceDeletePod(ctx context.Context, p *corev1.Pod) error {
	// Log line is an NPD contract: ends in "force-delete pod ..." so
	// the StuckPodForceDeleted filelog pattern still fires.
	d.State.AppendLog(fmt.Sprintf(
		"POD-TEARDOWN-FORCE-DELETE: "+latchdefs.ReasonForceDeletePod+
			"%s/%s (uid %.8s) - Terminating %ds, zero live tasks",
		p.Namespace, p.Name, string(p.UID),
		int64(d.Cfg.Seams.Host.Clock.Now().Sub(p.DeletionTimestamp.Time).Seconds())))
	return d.Cfg.Client.CoreV1().Pods(p.Namespace).Delete(ctx, p.Name,
		metav1.DeleteOptions{
			GracePeriodSeconds: ptr.To[int64](0),
			PropagationPolicy:  ptr.To(metav1.DeletePropagationBackground),
			Preconditions:      &metav1.Preconditions{UID: &p.UID},
		})
}

// HoldLocalAction is the L1↔L3 maintenance gate every destructive
// path consults before a pod delete or policy eviction: true while
// the cluster verifiably holds the maintenance mutex (upgrade /
// kured drain) OR the verdict is unverifiable — nodecoord fails
// closed. Nil Coord (tests, unwired builds) never holds.
func (d *Deps) HoldLocalAction(ctx context.Context) bool {
	return d.Cfg.Coord != nil && d.Cfg.Coord.HoldLocalAction(ctx)
}

// HoldEmergencyHeal is the fail-open counterpart for self-heal
// paths that must never deadlock on an unreachable apiserver (CNI
// recovery in calico.go): holds only on positively-known
// maintenance. Nil Coord → false.
func (d *Deps) HoldEmergencyHeal(ctx context.Context) bool {
	return d.Cfg.Coord != nil && d.Cfg.Coord.HoldEmergencyHeal(ctx)
}

// StampLocalRemediation marks NodeCondition LocalRemediationInProgress
// on nodes/status — call BEFORE a node-local restart (k0sworker)
// so the cluster side yields remote remediation while L1 self-heals.
// Best-effort, rides nodecoord's own StampTimeout, errors only
// logged. Nil Coord is a no-op.
func (d *Deps) StampLocalRemediation(ctx context.Context) {
	if d.Cfg.Coord == nil {
		return
	}
	if err := d.Cfg.Coord.StampLocalRemediation(ctx); err != nil {
		d.State.AppendLog(fmt.Sprintf(
			"suspect: local-remediation stamp failed (attribution hint only): %v", err))
	}
}

// StampPodHealed records that L1 bounced infra pod ns/name — patches
// the pod's last-pod-healed-at annotation and refreshes the
// LocalRemediationInProgress node condition so the L3 side can
// attribute the churn — best-effort, rides nodecoord's own
// StampTimeout, errors only logged. Nil Coord is a no-op.
func (d *Deps) StampPodHealed(ctx context.Context, ns, name string) {
	if d.Cfg.Coord == nil {
		return
	}
	if err := d.Cfg.Coord.StampPodHealed(ctx, ns, name); err != nil {
		d.State.AppendLog(fmt.Sprintf(
			"suspect: pod-healed stamp failed (attribution hint only): %v", err))
	}
}

// --- eviction-protection registry -------------------------------------
//
// The psi-thrash victim picker (guards/psi_thrash.go) and the
// disk-bloat critical-band evictor (runtime/disk_bloat.go) used to
// carry near-identical copies of this protection surface — the
// disk-bloat copy had already drifted ahead with the "cnpg"/"percona"
// quorum tokens. One canonical set now: union semantics, so a pod the
// EITHER check would have protected stays protected under both.

// EvictProtectedNamespaces are namespaces no memory/disk-pressure
// evictor touches — system daemons, CNI/mesh control planes, storage
// operators, cert/secrets plumbing, the flux delivery layer and the
// database quorum namespaces. Evicting from these under pressure
// removes the very components needed to recover.
var EvictProtectedNamespaces = map[string]bool{
	"kube-system":      true,
	"node-ops":         true,
	"medik8s":          true,
	"cilium":           true,
	"linkerd":          true,
	"linkerd-cni":      true,
	"openebs":          true,
	"cert-manager":     true,
	"external-secrets": true,
	"operators":        true,
	"everest-system":   true,
	"scylla":           true,
	"scylla-manager":   true,
	"flux-system":      true,
}

// EvictCriticalPriorityClasses are the priority classes the
// scheduler marked untouchable — evicting them fights the cluster's
// own guarantees.
var EvictCriticalPriorityClasses = map[string]bool{
	"system-node-critical":    true,
	"system-cluster-critical": true,
}

// StatefulOwnerKinds are ownerReference kinds whose pods hold
// stateful/quorum workloads — a plain StatefulSet plus the database
// operators that raise pods under their own CRD kinds (CloudNativePG
// Cluster, Dragonfly, ScyllaCluster/ScyllaDBDatacenter, Percona
// PGv2/PSMDB/PXC). Losing one replica under pressure can cost
// quorum.
var StatefulOwnerKinds = map[string]bool{
	"StatefulSet":          true,
	"Cluster":              true, // CloudNativePG postgresql.cnpg.io
	"Dragonfly":            true,
	"ScyllaCluster":        true,
	"ScyllaDBDatacenter":   true,
	"PerconaServerMongoDB": true,
	"PerconaXtraDBCluster": true,
	"PerconaPGCluster":     true,
}

// OwnedByStatefulSet reports whether any ownerReference is a
// stateful/quorum workload owner (StatefulOwnerKinds).
func OwnedByStatefulSet(p *corev1.Pod) bool {
	for _, ref := range p.OwnerReferences {
		if StatefulOwnerKinds[ref.Kind] {
			return true
		}
	}
	return false
}

// DBQuorumTokens mark pods carrying database / quorum state —
// matched case-insensitively against label keys AND values. The
// union of both former copies: psi's base set plus disk-bloat's
// "cnpg"/"percona" (the drift the consolidation exists to fix).
var DBQuorumTokens = []string{
	"scylla", "dragonfly", "rabbitmq", "pxc", "psmdb", "postgresql",
	"cnpg", "percona",
}

// DBQuorumLabelKeys are label KEYS that mark database/quorum pods
// regardless of value — CNPG's instanceRole and the CrunchyData
// postgres-operator role selector carry no DBQuorumTokens substring.
// Keys are compared lowercased (label keys are case-sensitive but
// the convention is camelCase suffixes like instanceRole).
var DBQuorumLabelKeys = map[string]bool{
	"cnpg.io/instancerole":                   true,
	"postgres-operator.crunchydata.com/role": true,
}

// CarriesDBQuorumLabel reports whether the pod's labels name a
// database/quorum workload — DBQuorumLabelKeys exact key matches
// plus DBQuorumTokens (case-insensitive over keys and values). An
// INDEPENDENT gate: a CNPG/Percona/Scylla/Dragonfly pod is never an
// eviction victim no matter which CRD owns it, because quorum loss
// costs far more than the resources an eviction frees.
func CarriesDBQuorumLabel(p *corev1.Pod) bool {
	for k, v := range p.Labels {
		lk, lv := strings.ToLower(k), strings.ToLower(v)
		if DBQuorumLabelKeys[lk] {
			return true
		}
		for _, tok := range DBQuorumTokens {
			if strings.Contains(lk, tok) || strings.Contains(lv, tok) {
				return true
			}
		}
	}
	return false
}

// IsEvictProtectedPod is the pod-intrinsic half of the eviction
// rails both pressure evictors share: critical priority class,
// database/quorum labels, or a stateful/quorum owner. Namespace and
// DeletionTimestamp stay caller-side — the two checks' protected
// namespace sets coincide today but are separate policy surfaces.
func IsEvictProtectedPod(p *corev1.Pod) bool {
	return EvictCriticalPriorityClasses[p.Spec.PriorityClassName] ||
		CarriesDBQuorumLabel(p) ||
		OwnedByStatefulSet(p)
}
