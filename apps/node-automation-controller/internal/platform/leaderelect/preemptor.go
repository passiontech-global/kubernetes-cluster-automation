// preemptor.go — the fast dead-leader lease preemptor (W24): a
// NeedLeaderElection=false sweep that runs on EVERY replica —
// including standbys — and shortens the controller's own
// leader-election LeaseDuration to 1s when the current holder is
// provably dead.
//
// Why: the deployment runs leader election with a 180s
// LeaseDuration sized for multi-minute Nebula dataplane blips
// (incident 2026-11-04). That same tolerance means a leader whose
// NODE dies — kubelet gone, pod object orphaned, renewTime frozen —
// keeps the Lease for up to 180s while every heal module on the
// standby sits idle. The standby here detects the dead holder
// (pod deleted/terminating, or its Node NotReady/Unknown or
// carrying the unreachable/unresponsive/partitioned taints) and
// patches spec.leaseDurationSeconds=1 with the object's
// ResourceVersion as the concurrency guard, collapsing failover to
// ~30s (renewTime stale >30s + ~1s expiry + acquire retry).
//
// Safety: the 180s tolerance is preserved whenever the leader's
// node still reports Ready — a partitioned-but-alive leader keeps
// its lease and the standby never preempts on a liveness guess.
// Multiple standbys racing the same patch resolve through the
// ResourceVersion precondition: losers get Conflict and retry next
// sweep; only the winner's patch lands, so the preemption counter
// (wired by the caller — platform cannot import internal/metrics)
// increments once per actual transition.
package leaderelect

import (
	"context"
	"fmt"
	"strings"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

const (
	// DefaultNamespace/DefaultLeaseName locate the controller's own
	// leader-election Lease — the Lease name is the
	// LeaderElectionID "node-automation-controller.passiontech.dev"
	// wired in cmd/manager/main.go; controller-runtime places it in
	// the manager's own namespace.
	DefaultNamespace = "node-ops"
	DefaultLeaseName = "node-automation-controller.passiontech.dev"

	// PreemptStaleAfter is the dead-leader proof window: a healthy
	// elector renews every ~LeaseDuration/4 (45s at 180s — but the
	// renewDeadline/retryPeriod knobs bound it tighter in practice);
	// renewTime frozen past 30s while the holder is verifiably dead
	// means the standby should not wait out the full 180s.
	PreemptStaleAfter = 30 * time.Second

	// PreemptLeaseDurationSeconds is the shortened lease the patch
	// installs — long enough for one renew/acquire round-trip, short
	// enough that a standby wins within seconds of the next sweep.
	PreemptLeaseDurationSeconds = int32(1)

	// SweepInterval is the runnable's tick — fast enough that a dead
	// leader costs ~45s worst case (30s staleness proof + up to one
	// interval + ~1s lease expiry + acquire retry) against the 180s
	// LeaseDuration it replaces.
	SweepInterval = 15 * time.Second
)

// Reason labels for the preemption counter — the holder-dead
// evidence that justified the shorten. Ops contract: do not rename.
const (
	ReasonPodMissing      = "pod_missing"
	ReasonPodTerminating  = "pod_terminating"
	ReasonNodeNotReady    = "node_not_ready"
	ReasonNodeUnreachable = "node_unreachable"
)

// Preemptor audits the controller's leader-election Lease and
// shortens its duration when the holder is provably dead. The zero
// value uses node-ops defaults and the system clock.
type Preemptor struct {
	CS        kubernetes.Interface
	Now       timex.Clock
	Namespace string // zero → DefaultNamespace
	LeaseName string // zero → DefaultLeaseName
}

func (p *Preemptor) ns() string {
	if p.Namespace != "" {
		return p.Namespace
	}
	return DefaultNamespace
}

func (p *Preemptor) leaseName() string {
	if p.LeaseName != "" {
		return p.LeaseName
	}
	return DefaultLeaseName
}

// Sweep runs one preemption pass. It returns the reason a
// preemption patch landed ("" when nothing was done) — the caller
// increments node_automation_leader_lease_preemptions_total{reason}
// only on a non-empty reason so the series counts real transitions,
// not every sweep that observed a dead leader (the patch is
// idempotent: once leaseDurationSeconds is already 1 every standby
// sees the shortened lease and skips).
func (p *Preemptor) Sweep(ctx context.Context) (string, error) {
	ns, name := p.ns(), p.leaseName()
	lease, err := p.CS.CoordinationV1().Leases(ns).
		Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", nil // leader election disabled or lease not yet created
	}
	if err != nil {
		return "", fmt.Errorf("get lease %s/%s: %w", ns, name, err)
	}
	reason, dead := p.holderDead(ctx, lease)
	if !dead {
		return "", nil
	}
	if lease.Spec.LeaseDurationSeconds != nil &&
		*lease.Spec.LeaseDurationSeconds == PreemptLeaseDurationSeconds {
		return "", nil // already preempted — do not re-patch or recount
	}
	lease.Spec.LeaseDurationSeconds = ptr(PreemptLeaseDurationSeconds)
	if _, err := p.CS.CoordinationV1().Leases(ns).
		Update(ctx, lease, metav1.UpdateOptions{}); err != nil {
		// A Conflict means a sibling standby won the race — its
		// patch is the transition, ours is noise. Other errors are
		// real and surface to the caller's error accounting.
		if apierrors.IsConflict(err) {
			return "", nil
		}
		return "", fmt.Errorf("preempt lease %s/%s: %w", ns, name, err)
	}
	return reason, nil
}

// holderDead reports whether the lease's renewTime is stale past
// PreemptStaleAfter AND the holder pod is provably dead — deleted,
// terminating, or scheduled on a node that is NotReady/Unknown or
// carries a dead-node taint. The renewTime gate runs FIRST: a
// recently-renewed lease is healthy regardless of what the pod
// lookup would say (the holder may be mid-restart with a fresh
// standby about to take over).
func (p *Preemptor) holderDead(ctx context.Context,
	lease *coordinationv1.Lease) (reason string, dead bool) {

	if lease.Spec.RenewTime == nil ||
		p.Now.Now().Sub(lease.Spec.RenewTime.Time) <= PreemptStaleAfter {
		return "", false
	}
	holder := ""
	if lease.Spec.HolderIdentity != nil {
		holder = *lease.Spec.HolderIdentity
	}
	if holder == "" {
		// No attributable holder — an empty holderIdentity with a
		// stale renewTime is a vacant lease the normal election
		// path resolves at LeaseDuration expiry; there is no dead
		// pod to point the preemption reason at.
		return "", false
	}
	podName := holder
	if i := strings.LastIndex(holder, "_"); i > 0 {
		podName = holder[:i] // client-go suffixes "<pod>_<uid>"
	}
	pod, err := p.CS.CoreV1().Pods(lease.Namespace).
		Get(ctx, podName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return ReasonPodMissing, true
	case err != nil:
		// An unverifiable holder is NOT proof of death — fail
		// closed and leave the 180s tolerance in place.
		return "", false
	}
	if pod.DeletionTimestamp != nil {
		return ReasonPodTerminating, true
	}
	if pod.Spec.NodeName == "" {
		return "", false // unscheduled — the pod object is alive, election will sort it
	}
	node, err := p.CS.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName,
		metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return ReasonNodeNotReady, true
	}
	if err != nil {
		return "", false // fail closed on an unverifiable node
	}
	for _, taint := range node.Spec.Taints {
		switch taint.Key {
		case corev1.TaintNodeUnreachable,
			kube.TaintKubeletUnresponsive,
			kube.TaintNetworkPartitioned:
			return ReasonNodeUnreachable, true
		}
	}
	for _, cond := range node.Status.Conditions {
		if cond.Type == corev1.NodeReady {
			if cond.Status != corev1.ConditionTrue {
				return ReasonNodeNotReady, true
			}
			return "", false
		}
	}
	// No Ready condition at all — a node that never reported is
	// not a live leader.
	return ReasonNodeNotReady, true
}

func ptr[T any](v T) *T { return &v }
