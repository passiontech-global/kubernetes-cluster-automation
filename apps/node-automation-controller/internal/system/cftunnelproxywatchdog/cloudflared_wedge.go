// cloudflared_wedge.go — the cloudflared-wedge-heal check of the
// cf-tunnel proxy watchdog: detection (log-tail wedge signatures +
// the all-unready deadlock), maintenance-mutex + heal-budget gating,
// and the UID-preconditioned connector pod deletes (split out of
// cftunnel_proxy_watchdog.go — see its header for the module
// contract).
package cftunnelproxywatchdog

import (
	"context"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// ---------------------------------------------------------------------------
// cloudflared-wedge-heal — wedged cloudflared connector healer.
// ---------------------------------------------------------------------------

// cfTunnelConnectorTarget is one label-selected pod population that
// runs cloudflared and can wedge the same way.
type cfTunnelConnectorTarget struct {
	namespace string
	selector  string
}

// connectorTargets is the full population of cloudflared pods the
// healer watches: the gateway proxy Deployment AND the ingress
// controller release, which uses a different namespace + label
// scheme for the same binary.
func (w *cfTunnelProxyWatchdog) connectorTargets() []cfTunnelConnectorTarget {
	return []cfTunnelConnectorTarget{
		{namespace: w.namespace, selector: cfTunnelProxyPodSelector},
		{namespace: cfTunnelConnectorNS, selector: cfTunnelConnectorSelector},
	}
}

// healCloudflaredWedges is check 3: delete cloudflared pods that are
// provably wedged — fatal startup errors in the log tail, or an
// edge-connection error loop — plus the readyCount==0 deadlock fix:
// when EVERY running replica of a target is unready >= 5m, delete
// the single oldest one (10m cooldown) so the Deployment recreates
// it instead of skipping forever. Returns pods deleted.
//
// The maintenance mutex + global heal budget (heal.Gate) are only
// consulted AFTER at least one pod provably needs the delete: the
// mutex evaluation costs API reads and the budget is a shared global
// allowance, so spending either on a sweep that found nothing to
// heal burns 12-heals-per-hour windows for no effect.
func (w *cfTunnelProxyWatchdog) healCloudflaredWedges(ctx context.Context) (int, error) {
	log := logf.FromContext(ctx)
	now := w.now.Now()
	// The ledger keys carry controller names that outlive their pods
	// but die with their Deployments — bound the map so decommissioned
	// workloads' stamps cannot accumulate forever.
	w.lastHeal.PruneExpired(now, cfTunnelHealCooldown)

	// Detection pass (read-only): which pods across every target
	// provably need the delete this sweep? Log tails are read here —
	// a read failure skips that pod exactly like before.
	var candidates []cfTunnelWedge
	for _, tgt := range w.connectorTargets() {
		found, err := w.scanConnectorTarget(ctx, tgt, now, log)
		if err != nil {
			return 0, err
		}
		candidates = append(candidates, found...)
	}
	if len(candidates) == 0 {
		return 0, nil
	}

	// Maintenance mutex + global heal budget — the deletes below kill
	// LIVE pods, so they defer while a cordon/drain/kured reboot or a
	// k0s upgrade is in flight, and "cannot verify" fails closed.
	// heal.Gate runs the nil-heals-ledger preamble: this module's
	// pacing is the per-controller lastHeal cooldown already checked
	// per pod inside scanConnectorTarget — only the mutex and budget
	// gates apply here, shared via w.verdict so the sweep pays one
	// evaluation.
	if w.dyn != nil {
		proceed, unverifiable := heal.Gate(ctx, log, w.verdict,
			w.cs, w.dyn, "cloudflared-wedges", now)
		if unverifiable {
			metrics.IncError(w.queue)
			return 0, nil
		}
		if !proceed {
			return 0, nil
		}
	}
	healed := 0
	for _, c := range candidates {
		delivered, err := w.deleteConnectorPod(ctx, c.pod, c.reason, now)
		if err != nil {
			log.Error(err, "delete wedged connector pod failed",
				"pod", c.pod.Namespace+"/"+c.pod.Name)
			continue
		}
		if !delivered {
			// 404 (already gone — goal state), a local-remediation
			// hold or the sweep's one-disruption reservation: no
			// heal landed, so no cooldown stamp either — the next
			// sweep re-evaluates the pod.
			continue
		}
		w.lastHeal.Stamp(kube.PodControllerKey(c.pod), now)
		w.stampHealPersisted(ctx, c.pod, now)
		healed++
	}
	if healed > 0 {
		log.Info("ACTION: deleted wedged cloudflared pod(s)", "deleted", healed)
	} else {
		// The gate consumed one fleet grant but every candidate
		// delete was refused or already-gone — nothing was
		// delivered, so the grant goes back (refund-on-skip).
		heal.RefundGrant(now)
	}
	return healed, nil
}

// cfTunnelWedge is one pod the detection pass proved needs the
// delete — the only shape healCloudflaredWedges acts on.
type cfTunnelWedge struct {
	pod    *corev1.Pod
	reason string
}

// scanConnectorTarget is the detection half of the old
// healConnectorTarget: it scans one pod population and returns the
// pods this sweep would delete WITHOUT deleting them. Only Running
// pods are candidates; Ready=True pods are never touched. Unready
// pods younger than cfTunnelUnreadyMinAge are left alone — rollout
// startup churn must not trigger deletes. The per-target
// cfTunnelMaxHealsPerTarget bound applies here, so the gate only
// ever sees the same deletes the old code would have issued.
func (w *cfTunnelProxyWatchdog) scanConnectorTarget(ctx context.Context,
	tgt cfTunnelConnectorTarget, now time.Time, log logr.Logger,
) ([]cfTunnelWedge, error) {
	all, err := w.podsInNS(ctx, tgt.namespace)
	if err != nil {
		return nil, err
	}
	pods, err := matchPodSelector(all, tgt.selector)
	if err != nil {
		return nil, err
	}
	var running []*corev1.Pod
	var unreadyStale []*corev1.Pod
	ready := 0
	for i := range pods {
		p := &pods[i]
		if p.Status.Phase != corev1.PodRunning || p.DeletionTimestamp != nil {
			continue
		}
		running = append(running, p)
		if kube.PodReadyCond(p) {
			ready++
			continue
		}
		if age, ok := kube.PodUnreadyFor(p, now); ok && age >= cfTunnelUnreadyMinAge {
			unreadyStale = append(unreadyStale, p)
		}
	}
	if len(running) == 0 || len(unreadyStale) == 0 {
		return nil, nil
	}
	var wedges []cfTunnelWedge
	// seenController enforces the per-controller pacing INSIDE the
	// sweep: healCooledDown reads the lastHeal stamp, but that stamp is
	// only written after the deletes land (healCloudflaredWedges), so
	// two pods of the same ReplicaSet would both pass the cooldown
	// check here and be deleted together — killing every replica of a
	// 2-replica Deployment in one cycle. One wedge per controller per
	// sweep serializes the deletes exactly like the cooldown does
	// across sweeps (and skips the ReplicaSet GET healCooledDown would
	// spend on the sibling).
	seenController := map[string]bool{}
	// Fatal-signature pods: unready >= 5m AND wedged logs — doomed
	// pods a config resync cannot revive. Bounded per target per
	// sweep so a mass-wedge cannot delete the whole fleet at once.
	for _, p := range unreadyStale {
		if len(wedges) >= cfTunnelMaxHealsPerTarget {
			break
		}
		key := kube.PodControllerKey(p)
		if seenController[key] {
			continue
		}
		wedged, err := w.podLogWedged(ctx, p)
		if err != nil {
			// Log read failure is not proof of health — skip this
			// pod this cycle; the all-unready path below can still
			// cover it.
			log.Info("connector log read failed — skipping wedge check",
				"pod", p.Namespace+"/"+p.Name, "error", err.Error())
			continue
		}
		if !wedged || w.healCooledDown(ctx, p, now) {
			continue
		}
		wedges = append(wedges, cfTunnelWedge{pod: p, reason: "fatal_logs"})
		seenController[key] = true
	}
	// readyCount==0 deadlock: every running replica unready — the
	// resync loop can never converge. Delete the single OLDEST
	// stale-unready pod (10m cooldown) so its Deployment recreates
	// it; one per sweep bounds churn during a genuine outage. Runs
	// only when the fatal-signature pass queued NOTHING: a non-empty
	// wedges list means this sweep already has deletes in flight (and
	// `oldest` could be a pod already queued — deleting it twice would
	// double-count the metric — or the second replica of a Deployment
	// whose first replica is already being replaced).
	if ready == 0 && len(wedges) == 0 {
		oldest := unreadyStale[0]
		for _, p := range unreadyStale[1:] {
			if p.CreationTimestamp.Before(&oldest.CreationTimestamp) {
				oldest = p
			}
		}
		if !w.healCooledDown(ctx, oldest, now) {
			wedges = append(wedges, cfTunnelWedge{pod: oldest, reason: "all_unready_oldest"})
		}
	}
	return wedges, nil
}

// healCooledDown reports whether this pod's controller is inside
// cfTunnelHealCooldown on EITHER clock — the in-RAM lastHeal ledger
// OR the passiontech.dev/last-cloudflared-heal annotation persisted
// on the pod's owning ReplicaSet (the durable half that survives an
// operator restart). Both reads are the heal.PersistedCooledDown
// wider-of contract. Keyed on the owner (not the pod name) so a
// recreated pod that wedges again waits out the window instead of
// being killed every sweep under a fresh name. A failed (or absent)
// ReplicaSet read degrades the gate to the in-RAM ledger alone —
// never fail a heal over its cooldown's cheap half.
func (w *cfTunnelProxyWatchdog) healCooledDown(ctx context.Context,
	p *corev1.Pod, now time.Time) bool {
	var rs metav1.Object
	// Only a ReplicaSet controller ref resolves to a ReplicaSet —
	// a bare name match would GET/PATCH whatever kind actually
	// owns the pod (a Job, a bare pod's owner) under the RS GVR.
	if ref := metav1.GetControllerOf(p); ref != nil && ref.Name != "" &&
		ref.Kind == "ReplicaSet" {
		got, err := w.cs.AppsV1().ReplicaSets(p.Namespace).
			Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			logf.FromContext(ctx).Info(
				"replicaset read failed — heal cooldown degrades to the in-RAM ledger",
				"replicaset", p.Namespace+"/"+ref.Name, "error", err.Error())
		} else {
			rs = got
		}
	}
	return heal.PersistedCooledDown(ctx, &w.lastHeal, rs, cfTunnelHealAnno,
		kube.PodControllerKey(p), cfTunnelHealCooldown, now)
}

// stampHealPersisted is the durable half of the heal cooldown: the
// RFC3339 annotation on the pod's owning ReplicaSet, delivered via
// heal.StampPersisted AFTER the delete landed. A failed annotation
// patch leaves the in-RAM lastHeal stamp holding (it was stamped on
// the delivered delete) and only costs durability — the same
// annotation-fails-but-heal-stands shape dragonfly_heals uses.
func (w *cfTunnelProxyWatchdog) stampHealPersisted(ctx context.Context,
	p *corev1.Pod, now time.Time) {
	ref := metav1.GetControllerOf(p)
	if ref == nil || ref.Name == "" || ref.Kind != "ReplicaSet" {
		return // standalone pod or non-RS owner — no ReplicaSet to persist on
	}
	err := heal.StampPersisted(ctx,
		nil,
		func(ctx context.Context, data []byte) error {
			_, err := w.cs.AppsV1().ReplicaSets(p.Namespace).
				Patch(ctx, ref.Name, types.MergePatchType, data, metav1.PatchOptions{})
			return err
		},
		cfTunnelHealAnno, nil, "", now)
	if err != nil {
		logf.FromContext(ctx).Error(err, "persist cloudflared heal stamp failed",
			"replicaset", p.Namespace+"/"+ref.Name)
	}
}

// deleteConnectorPod deletes a connector pod through heal.DeletePod —
// the shared UID-preconditioned delete every pod heal uses: the
// listed pod could already have been replaced by a same-named fresh
// pod (killing the replacement would undo the heal), the sweep
// overlay's local-remediation hold and one-disruption-per-workload
// reservation apply, and the pod's UID is tombstoned for the rest of
// the sweep. heals is nil — this module's pacing is the lastHeal
// ledger the CALLER stamps on a delivered delete only. Returns
// (delivered, err): a 404 or a hold/reservation refusal is
// (false, nil) — the pod is gone or the delete deferred, and no
// cooldown may stamp on either.
func (w *cfTunnelProxyWatchdog) deleteConnectorPod(ctx context.Context,
	p *corev1.Pod, reason string, now time.Time) (bool, error) {
	deleted, err := heal.DeletePod(ctx, w.cs, nil,
		kube.PodControllerKey(p), p, now)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil // already gone — not a delete we delivered
		}
		return false, err
	}
	if !deleted {
		return false, nil
	}
	// Count only delivered deletes — incrementing before the call
	// recorded every API failure as a heal that never happened.
	metrics.CFTunnelWedgePodsDeletedTotal.WithLabelValues(
		p.Namespace, reason).Inc()
	return true, nil
}

// podLogWedged fetches the tail of the pod's log and matches the
// cloudflared wedge signatures.
func (w *cfTunnelProxyWatchdog) podLogWedged(ctx context.Context,
	p *corev1.Pod) (bool, error) {
	text, err := kube.ReadPodLogText(ctx, w.cs, p, kube.PodLogOpts{
		TailLines: cfTunnelLogTailLines,
		MaxBytes:  cfTunnelLogMaxBytes,
		Timeout:   cfTunnelLogTimeout,
	})
	if err != nil {
		return false, err
	}
	return cloudflaredLogsWedged(text), nil
}

// cloudflaredLogsWedged matches the observed cloudflared failure
// signatures: fatal startup/config errors, and a sustained
// error loop (>=3 weighted error lines in the tail — a single blip
// during an edge rollout is normal). The QUIC patterns cover the
// UDP-blackhole wedge where the connector still reports Ready but
// every dial to the edge times out: "failed to dial to edge with
// quic", "timeout: no recent network activity" and the "quic: "
// error prefix.
//
// "failed to sufficiently increase receive buffer size" is NOT
// fatal: it is the benign startup warning cloudflared logs on every
// Linux node whose default rmem is below its request, so it only
// counts as weight-1 loop noise — three of them (or mixed with real
// edge errors) still mean wedged, one alone never does.
func cloudflaredLogsWedged(logs string) bool {
	edgeErrs := 0
	for line := range strings.SplitSeq(logs, "\n") {
		l := strings.ToLower(line)
		if strings.Contains(l, "couldn't start tunnel") ||
			strings.Contains(l, "serve tunnel error") {
			return true
		}
		if strings.Contains(l, "failed to sufficiently increase receive buffer") {
			// Benign startup warning — weight-1 noise, never an
			// instant kill (it appears on EVERY Linux node at boot).
			edgeErrs++
			continue
		}
		if strings.Contains(l, "connection with edge") &&
			(strings.Contains(l, "err") ||
				strings.Contains(l, "failed") ||
				strings.Contains(l, "timeout") ||
				strings.Contains(l, "reset") ||
				strings.Contains(l, "closed")) {
			edgeErrs++
			continue
		}
		if strings.Contains(l, "failed to dial to edge with quic") ||
			strings.Contains(l, "timeout: no recent network activity") ||
			strings.Contains(l, "quic: ") {
			edgeErrs++
		}
	}
	return edgeErrs >= 3
}
