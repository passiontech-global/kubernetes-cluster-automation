// local_remediation.go — the L1↔L3 yield for pod-kill heals: while
// node-host-agent is self-healing a node (or just bounced an infra
// pod on it), the cluster side must not race the same fix with a
// remote delete/eviction. Three signals mark the same episode,
// weakest-to-strongest:
//
//   - passiontech.dev/last-pod-healed-at ON THE POD — the agent
//     bounced this very pod seconds ago; a remote heal now would
//     double-kill it (free to read: the caller already holds the
//     pod object, no API call).
//   - passiontech.dev/local-remediation-until ON THE POD'S NODE —
//     the agent stamped "+3m" before restarting a node-local
//     service (kubeletreaper reads the same stamp for its taint
//     yield).
//   - NodeCondition LocalRemediationInProgress==True on the node
//     with LastHeartbeatTime fresher than the lease — the agent's
//     heartbeat-proven claim it is mid-remediation right now.
//
// The check runs inside DeletePod/EvictPod — the actuation half
// every pod-kill heal funnels through — BEFORE the workload
// disruption reservation so a deferred heal never burns the sweep's
// one-disruption slot. A hold is a deferral, not an error: the pod
// stays, no cooldown stamps, the next sweep retries.
package heal

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

// localRemediationLease bounds every L1 self-heal signal: the
// agent's stamps carry ~3m horizons and the condition's heartbeat
// freshness uses the same window — one constant so the three reads
// cannot drift apart.
const localRemediationLease = 3 * time.Minute

// localRemediationHold reports whether pod's node (or pod itself)
// is inside a node-host-agent L1 self-heal window — see the file
// header for the three signals. Pod-level signals cost zero API
// reads; the node-level pair costs one Nodes().Get, paid only when
// the pod is actually scheduled (NodeName set) and the cheap pod
// stamp did not already answer.
//
// A missing node (NotFound — the pod's node was already deleted)
// holds nothing: there is no agent left to wait for. Any other
// node-read error propagates — "cannot verify" fails closed like
// the maintenance mutex, so a heal never fires on a guess.
func localRemediationHold(ctx context.Context, cs kubernetes.Interface,
	pod *corev1.Pod, now time.Time) (bool, error) {

	if pod == nil {
		return false, nil
	}
	// Signal 1 — the pod itself was just bounced by the agent.
	if t, ok := kube.AnnoTime(pod, nodecond.AnnoLastPodHealedAt); ok &&
		now.Sub(t) < localRemediationLease {
		return true, nil
	}
	if pod.Spec.NodeName == "" {
		return false, nil // unscheduled — no node to ask
	}
	node, err := cs.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName,
		metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// Signal 2 — the agent's stamped remediation window on the node.
	if t, ok := kube.ParseAnnoTime(
		node.Annotations[nodecond.AnnoLocalRemediationUntil]); ok &&
		t.After(now) {
		return true, nil
	}
	// Signal 3 — the heartbeat-proven in-progress condition. A
	// frozen heartbeat means the reporter is dead (a zombie the
	// node-condition-sweeper clears), so it does not hold.
	if c := kube.NodeCondition(node, nodecond.CondLocalRemediation); c != nil &&
		c.Status == corev1.ConditionTrue &&
		kube.CondHeartbeatLive(c, localRemediationLease, now) {
		return true, nil
	}
	return false, nil
}
