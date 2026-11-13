// sweep.go — the kubelet-reaper per-node decision: the taint/untaint
// sweep (sweep) gated on the local-remediation yield, the heal
// circuit breaker and the kube-node-lease liveness check
// (kubeletAlive). Split out of kubelet_reaper.go so the file stays
// under the ~500-LOC bar.
package kubeletreaper

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

// sweep applies the taint decision for one node. listed is the object
// from this run's node list — already fresh enough to see our taint.
// The per-node Get (the bash's `kubectl get node`) now only happens
// when the probe FAILED: the liveness gate below needs a fresh read,
// while a healthy probe with no listed taint has literally nothing to
// decide — one fewer apiserver read per worker per cycle.
func (r *kubeletReaper) sweep(ctx context.Context, listed *corev1.Node, ok bool) error {
	log := logf.FromContext(ctx)

	if ok {
		// The kubelet serves :10250 — the node's own convergence
		// evidence: clear its breaker history AND any fresh-lease
		// persistence stamp now so the next real episode starts
		// from zero instead of inheriting a stale count.
		r.freshFail.Forget(listed.Name)
		heal.RecordTargetHealthy(r.queue, listed.Name)
		if kube.HasTaint(listed.Spec.Taints, kubeletReaperTaint) {
			// kube.UntaintNode re-Gets the node inside before patching,
			// so a stale listed snapshot cannot remove a taint that
			// is already gone — no separate Get needed here either.
			if err := kube.UntaintNode(ctx, r.cs, listed.Name, kubeletReaperTaint); err != nil {
				return fmt.Errorf("remove taint %s on node %s: %w",
					kubeletReaperTaint, listed.Name, err)
			}
			log.Info("UNTAINT: kubelet :10250 ok -> taint removed", "node", listed.Name)
		} else {
			log.Info("OK", "node", listed.Name)
		}
		return nil
	}

	// Probe failed — re-Get like the bash per-node kubectl get: the
	// heartbeat gate decides on freshness, so the listed snapshot
	// must not stand in for it.
	node, err := r.cs.CoreV1().Nodes().Get(ctx, listed.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get node %s: %w", listed.Name, err)
	}
	// L1<->L3 yield: node-host-agent stamps
	// passiontech.dev/local-remediation-until (+3m) before
	// restarting a node-local service — the cluster side defers
	// remote tainting while L1 self-heals first (this reaper is
	// the last resort, not a racer). The stamp is read off the
	// fresh Get, not the listed snapshot. An absent, unparseable
	// or expired stamp yields nothing; returning before
	// freshFail.Observe also keeps the persistence window from
	// burning while the agent owns the episode.
	if until, ok := kube.ParseAnnoTime(
		node.Annotations[nodecond.AnnoLocalRemediationUntil]); ok &&
		until.After(r.now.Now()) {
		log.Info("YIELD: node-host-agent local remediation in flight — taint deferred",
			"node", listed.Name, "until", until.Format(time.RFC3339))
		return nil
	}
	// The live L1 signal the annotation above was meant to be:
	// node-host-agent marks NodeCondition LocalRemediationInProgress
	// on nodes/status before restarting a node-local service —
	// trusted while its heartbeat stays inside the protocol's 3m
	// lease (a frozen heartbeat means the episode ended or the
	// reporter died). The agent's ClusterRole grants nodes/status
	// patch only, never nodes metadata patch, so nothing has
	// stamped local-remediation-until since the shell operator
	// retired — without this read the reaper races L1 self-heal.
	if c := kube.NodeCondition(node, nodecond.CondLocalRemediation); c != nil &&
		c.Status == corev1.ConditionTrue &&
		kube.CondHeartbeatLive(c, kubeletReaperLocalRemediationLease, r.now.Now()) {
		log.Info("YIELD: node-host-agent local remediation in flight — taint deferred",
			"node", listed.Name,
			"heartbeat", c.LastHeartbeatTime.Time.Format(time.RFC3339))
		return nil
	}
	has := kube.HasTaint(node.Spec.Taints, kubeletReaperTaint)
	name := listed.Name

	// Probe failed — liveness gate: a fresh Lease renewal = broken
	// proxy path, not a dead kubelet. The signal is the
	// kube-node-lease/<node> Lease's spec.renewTime, NOT the Ready
	// condition's lastHeartbeatTime: an upstream kubelet refreshes
	// that stamp only when it actually patches its Node status
	// (nodeStatusHasChanged deliberately ignores it) at
	// nodeStatusReportFrequency — 5m default plus up to 50% jitter —
	// so a HEALTHY kubelet routinely reads minutes stale on the old
	// 120s heartbeat gate and got tainted exactly during the
	// konnectivity/proxy outage this gate exists to ride out.
	alive, err := r.kubeletAlive(ctx, name)
	if err != nil {
		// Fail closed: an unreadable lease is not evidence of death
		// — tainting on our own read failure would punish live
		// kubelets during an apiserver flap. The per-node error
		// path meters it; the next 2m cycle retries.
		return fmt.Errorf("get lease %s/%s: %w", kubeletLeaseNamespace, name, err)
	}
	if alive {
		// Fresh Lease + failed probe is AMBIGUOUS: the fake-ready
		// wedge this module exists for (lease renews, :10250 hangs)
		// looks identical to a broken proxy path (konnectivity-agent
		// dead, mesh flap) where kubelet is healthy. The old code
		// read "fresh lease" as proof of health and skipped —
		// self-eliminating the only case it was built to catch.
		// Resolution: demand the probe-fail PERSIST across sweeps
		// for kubeletReaperLeaseFreshGrace before tainting; a
		// transient flap heals inside the window, a wedged kubelet
		// does not. Inconclusive evidence also never UNTAINTS —
		// only a succeeding probe clears the taint (the ok branch).
		first, seen := r.freshFail.Observe(name, r.now.Now())
		if !seen || r.now.Now().Sub(first) < kubeletReaperLeaseFreshGrace {
			if has {
				log.Info("KEEP-TAINT: probe fail persists but lease fresh — inside grace", "node", name)
			} else {
				log.Info("SKIP-TAINT: probe fail but kubelet alive (lease fresh) — persistence window", "node", name)
			}
			return nil
		}
		// Grace expired with the lease still fresh — before tainting,
		// the fleet guard gets a vote: when >=half the probed workers
		// show this same probe-fail+fresh-lease signature the suspect
		// is the shared apiserver->kubelet path (konnectivity/mesh),
		// not this kubelet — suppress the taint for the cycle (the
		// apiserver-node-reachability >=half-dark posture). The
		// freshFail entry is kept, not forgotten: observation
		// continues and a node still failing the sweep the guard
		// lifts fences immediately. Stale-lease fails below are
		// dead-kubelet evidence and taint regardless.
		if r.meshDark {
			log.Info("SUPPRESS: mesh-wide probe dark — fresh-lease taint deferred",
				"node", name)
			return nil
		}
		r.freshFail.Forget(name)
	} else {
		r.freshFail.Forget(name)
	}
	if !has {
		// Per-target non-convergent circuit breaker — the 4th
		// taint of the same node inside the breaker window
		// defers: a kubelet this module keeps tainting without
		// it ever coming back is not converging, and re-patching
		// every 2m cycle is exactly the churn the breaker stops.
		// Same semantics as the module's other no-action paths:
		// log, skip, return nil — never an error (IncError would
		// page on our own fail-safe). The history clears the
		// moment a probe succeeds (the ok branch above), so a
		// kubelet restart ends the episode instead of banking
		// against the next one.
		if allowed, reason := heal.TryAcquireTarget(r.queue, name, r.now.Now()); !allowed {
			log.Info("DEFER: heal target circuit open — taint skipped",
				"node", name, "reason", reason)
			return nil
		}
		if err := kube.TaintNode(ctx, r.cs, name, kubeletReaperTaint, "true",
			corev1.TaintEffectNoSchedule); err != nil {
			return fmt.Errorf("taint %s on node %s: %w",
				kubeletReaperTaint, name, err)
		}
		log.Info("TAINT: kubelet :10250 down -> NoSchedule",
			"node", name, "probes", kubeletReaperProbes)
	} else {
		log.Info("KEEP-TAINT: kubelet dead (lease stale/missing or fake-ready persisted)", "node", name)
	}
	return nil
}

// kubeletAlive reports whether the kube-node-lease/<node> Lease's
// renewal stamp proves the kubelet is alive. A live kubelet renews
// every ~10s, so anything past kubeletReaperLeaseStale reads as dead
// — well above the renewal cadence, and a dead kubelet's stamp
// crosses it within a minute. A MISSING Lease or a zero renewTime
// means the kubelet never posted a heartbeat — dead (the same
// missing-evidence-is-stale convention the Ready gate used). A
// renewal dated in the FUTURE (clock skew between the kubelet's host
// and this pod) is still proof of life — fresh; conflating skew with
// staleness would mass-taint on an NTP flap.
func (r *kubeletReaper) kubeletAlive(ctx context.Context, node string) (bool, error) {
	lease, err := r.cs.CoordinationV1().Leases(kubeletLeaseNamespace).
		Get(ctx, node, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// No heartbeat ever posted — dead.
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if lease.Spec.RenewTime.IsZero() {
		return false, nil
	}
	if age := r.now.Now().Sub(lease.Spec.RenewTime.Time); age < 0 {
		// A renewal 1-2s in the future is skew, not staleness.
		return true, nil
	} else {
		return age <= kubeletReaperLeaseStale, nil
	}
}
