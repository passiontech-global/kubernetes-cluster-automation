// heal_ops.go — the two heal shapes the sweep checks still hand-roll
// on top of DeletePodHeal/HealAllowed:
//
//   - SafePodDelete: the owner + Ready-sibling fail-closed guard that
//     must pass before a degraded pod is bounced (cloudflared tunnel,
//     linkerd-h2 storm/balancer/identity), ending in DeletePodHeal.
//     The linkerd outlier evict (PDB-pre-checked Eviction) and the
//     coredns upstream heal (extra sweep-scoped predicate) keep their
//     own hand-rolled gates — their shapes do not fit this primitive.
//   - BounceOperatorPod: the operator-bounce skeleton — gate once
//     (cooldown + maintenance mutex, fail closed), list the pod pool,
//     let the call site pick its targets (the per-ns pod-prefix pick
//     stays at call sites: olm-operator, localpv provisioner, db
//     operator aliases, the dragonfly operator, the IPAM terminal
//     reap), UID-delete each with IncError-and-continue, invalidate
//     the pod census and count the heals.
//
// DefaultTailLines/LogMaxBytes/LogTimeout are the log-tail quartet
// every log-scanning check redeclares as private consts (linkerd-h2,
// nats jetstream, ksm wedge, the cftunnel/cloudflared scanners, postgres
// WAL, scylla gossip) — one shared spelling so the values cannot drift
// apart. They are knobs of the LOG READ, not of a specific check, so
// they live in the check-agnostic framework.
package probefw

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// The log-tail read every log-scanning check shares: the last 200
// lines, capped at 256KiB, with an 8s per-read deadline. Values match
// every hand-rolled quartet (natsLogTailLines/ksmLogTailLines/
// cfTunnelLogTailLines/linkerdH2TailLines and friends) — adopting call
// sites swap their private consts for these.
const (
	// DefaultTailLines bounds one pod-log read to the trailing 200
	// lines — the window every log signature scans.
	DefaultTailLines = int64(200)
	// LogMaxBytes caps the read at 256KiB so a chatty pod cannot
	// blow the sweep's memory or the kubelet log path.
	LogMaxBytes = int64(256 * 1024)
	// LogTimeout bounds one pod-log read at 8s — the kubelet log
	// path is the sweep's slowest read and must not stall a check.
	LogTimeout = 8 * time.Second
)

// SafePodDelete is the sibling-guarded pod-delete heal — the
// fail-closed gate the gray-failure deletes share before they may
// bounce a still-Ready-looking pod:
//
//  1. a gone-or-terminating pod is skipped (nothing to bounce; the
//     replacement proxy/pod rebuilds state anyway);
//  2. an unowned pod is skipped — no controller means no sibling
//     population to prove traffic absorption;
//  3. fewer than minReadySiblings GENUINELY separate Ready siblings
//     under the same controller is skipped — ReadySiblings discounts
//     the target itself when it still reports Ready (a gray failure
//     keeps probes green), so 1 requires one other replica, 2 the
//     safe-evict posture where the stalled pod must itself still be
//     Ready and counted;
//  4. otherwise DeletePodHeal runs the cooldown + maintenance-mutex +
//     UID-delete + stamp sequence, still fail closed.
//
// readyByOwner is the census the caller already built over its pod
// list with ReadyByOwner — the primitive never re-lists. Skip logs
// carry the site-standard wording; the caller's Flag/Find reporting
// happens before it calls, so no result plumbing is needed.
func (d *Deps) SafePodDelete(ctx context.Context, log logr.Logger,
	checkName string, pod *corev1.Pod, readyByOwner map[types.UID]int,
	minReadySiblings int, cooldown time.Duration, now time.Time) {
	key := pod.Namespace + "/" + pod.Name
	if pod.DeletionTimestamp != nil {
		// Gone or going — nothing to bounce.
		return
	}
	if metav1.GetControllerOf(pod) == nil {
		log.Info("skip heal: unowned pod — no sibling can absorb traffic",
			"check", checkName, "pod", key)
		return
	}
	if ReadySiblings(readyByOwner, pod) < minReadySiblings {
		log.Info("skip heal: no Ready sibling replica — delete would blackhole the workload",
			"check", checkName, "pod", key,
			"readySiblings", ReadySiblings(readyByOwner, pod),
			"minReadySiblings", minReadySiblings)
		return
	}
	d.DeletePodHeal(ctx, log, checkName, kube.PodControllerKey(pod),
		pod, cooldown, now)
}

// BounceOperatorPod is the operator-bounce skeleton: the shared heal
// gate runs ONCE for the whole bounce (per-key cooldown on heals +
// the maintenance memoized mutex — unverifiable IncErrors the queue
// and returns 0, exactly like the hand-rolled preambles), the pod
// pool lists fresh from CS (ns-scoped, or cluster-wide when ns is ""
// — paged at the shared bound), pick selects the targets out of that
// pool (nil pick takes every pod), and each target takes the
// UID-preconditioned delete: an API failure IncErrors-and-continues,
// a delivery invalidates the pod census, stamps heals under key and
// counts one ControlPlanePodHealsTotal heal under checkName.
//
// Returns the delivered-delete count so post-actions key on real
// work (per-reason counters, the persisted STS stamp, a summary log).
//
// key is ONE ledger key for the whole bounce — gate and every delete
// stamp share it (olm-operator, localpv provisioner and the db
// operator heal under their operator/prefix names). Heals that key
// per pod (rabbitmq suspended) or gate on a persisted object stamp
// first (dragonfly operator) keep their hand-rolled loop; this
// primitive is the fixed-key majority shape. The cooldown ledger
// stamps only on DELIVERED deletes (heal.DeletePod's contract), so a
// failed delete never suppresses the retry for the window.
func (d *Deps) BounceOperatorPod(ctx context.Context, log logr.Logger,
	checkName, ns string, pick func([]corev1.Pod) []*corev1.Pod,
	heals *state.CooldownSet, key string, cooldown time.Duration,
	now time.Time) (deleted int) {

	// Confirm a heal target EXISTS before spending the global heal
	// budget: a selector that matches nothing (rollout in flight,
	// stale census) must not burn one of the cluster-wide tokens.
	// The in-RAM cooldown check is free and runs first.
	if heals != nil && heals.CooledDown(key, cooldown, now) {
		return 0
	}
	pods, err := kube.ListAll(ctx, metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.Pods(d.CS, nsScope(ns)))
	if err != nil {
		metrics.IncError(d.Name)
		log.Info("WARN: list pods failed — operator heal deferred",
			"check", checkName, "namespace", ns, "error", err)
		return 0
	}
	var targets []*corev1.Pod
	if pick != nil {
		for _, p := range pick(pods) {
			if p != nil {
				targets = append(targets, p)
			}
		}
	} else {
		for i := range pods {
			targets = append(targets, &pods[i])
		}
	}
	if len(targets) == 0 {
		return 0
	}
	proceed, unverifiable := d.HealAllowed(ctx, log, heals, key,
		cooldown, now)
	if unverifiable {
		metrics.IncError(d.Name)
		return 0
	}
	if !proceed {
		return 0
	}
	for _, pod := range targets {
		if _, err := heal.DeletePod(ctx, d.CS, heals, key, pod, now); err != nil {
			metrics.IncError(d.Name)
			log.Error(err, "operator pod delete failed",
				"check", checkName, "pod", pod.Namespace+"/"+pod.Name)
			continue
		}
		metrics.ControlPlanePodHealsTotal.WithLabelValues(checkName).Inc()
		deleted++
		log.Info("DELETE: pod heal — forcing operator resync",
			"check", checkName, "pod", pod.Namespace+"/"+pod.Name)
	}
	if deleted > 0 {
		d.InvalidatePods(ctx) // pods gone — drop the census once
	}
	return deleted
}

// nsScope maps the primitive's "" = cluster-wide spelling onto the
// clientset's namespace-all spelling.
func nsScope(ns string) string {
	if ns == "" {
		return metav1.NamespaceAll
	}
	return ns
}
