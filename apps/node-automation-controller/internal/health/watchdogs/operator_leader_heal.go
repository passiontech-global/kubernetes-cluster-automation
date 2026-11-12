// operator_leader_heal.go — the leader-pod heal path of the
// operator-workqueue-watchdog check (operator-workqueue-watchdog): once an operator's CRs
// stay unreconciled past the stuck window, healOperatorLeader deletes
// the leader pod to force re-election (1h cooldown, wider of the
// in-RAM ledger and the persisted passiontech.dev/last-operator-heal Lease
// stamp; maintenance-mutex gated), and leaderPods resolves the holder
// from the Lease's holderIdentity with the pod-selector fallback.
package watchdogs

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

const (
	// operatorHealCooldown bounds leader-pod deletes to one per
	// operator per hour — the wider of the in-RAM ledger and the
	// persisted passiontech.dev/last-operator-heal stamp on the Lease
	// (same wider-of-both shape as the helmrelease-unlocker).
	operatorHealCooldown = time.Hour
	// operatorHealAnno persists the last heal moment on the
	// operator's leader-election Lease — the restart-proof half of
	// the cooldown.
	operatorHealAnno = kube.AnnoLastOperatorHeal
)

var (
	// operator-workqueue-watchdog — stuck-operator leader pods deleted to force
	// re-election, by detected stall reason. Counts delivered heals
	// only (the counter increments after a delete landed).
	operatorWorkqueueHealsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_automation_operator_workqueue_heals_total",
		Help: "Stuck operator leader pods deleted to force re-election, by detected stall reason.",
	}, []string{"operator", "reason"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		operatorWorkqueueHealsTotal)
}

// healOperatorLeader deletes the stuck operator's leader pod to force
// re-election — the same unsticking nudge a manual
// `kubectl delete pod` applies. Gates, in order: a resolvable
// candidate leader pod (holderIdentity "<pod>_<uuid>" first, then the
// label selector in the Lease's namespace — Running, not terminating,
// and only deleted when a controller owner will recreate it), then
// the 1h cooldown (wider of in-RAM ledger keyed by
// kube.PodControllerKey and the persisted Lease stamp), then the
// maintenance mutex (never kill a leader mid-drain/upgrade). Every
// guard refusal is quiet — the frozen gauge + FAIL series already
// carry the alert.
func (p *operatorWorkqueueCheck) healOperatorLeader(ctx context.Context, log logr.Logger,
	op operatorTarget, lease *coordinationv1.Lease, reasons []string, now time.Time) {

	pods, err := p.leaderPods(ctx, op, lease)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: leader pod resolution failed — heal deferred",
			"operator", op.name, "error", err)
		return
	}
	if len(pods) == 0 {
		log.Info("no leader pod resolvable for stuck operator — heal deferred",
			"operator", op.name)
		return
	}
	// The cooldown ledger is keyed by the pod's CONTROLLER
	// (kube.PodControllerKey) — a re-created leader pod carries a
	// fresh name, so a "<ns>/<pod>" key would let the same failure
	// re-fire every sweep. The preamble is the shared
	// persisted-cooldown shape (Deps.HealAllowedPersisted →
	// heal.AllowedVPersisted): the 1h cooldown is the wider of the
	// in-RAM ledger and the persisted Lease stamp — the ledger
	// covers a heal whose anno patch never landed, the annotation
	// survives an operator restart — and only after it clears does
	// the maintenance mutex + global heal budget evaluate, fail
	// closed (an unverifiable drain state IncErrors the queue). A
	// nil lease (leaseOptional operators healing through the pod
	// fallback) collapses the gate to the ledger half + mutex. The
	// mutex verdict rides the Deps-wide memo: the first check to
	// need it this sweep pays the API reads, every later caller
	// within the Verdict TTL reuses the verdict.
	podKey := kube.PodControllerKey(&pods[0])
	// Free in-RAM cooldown first — the target pod is already
	// confirmed (pods[0] above), so a stamped key defers without
	// touching the persisted read, mutex verdict, or heal budget.
	if p.opHealed.CooledDown(podKey, operatorHealCooldown, now) {
		return
	}
	// Filter to controller-owned pods BEFORE the gated preamble: a
	// pod with no controller owner reference would NOT be recreated
	// after the delete — deleting a lone operator pod that nothing
	// restarts turns a stuck operator into a missing one — so it is
	// never a heal target. Discovering that inside the gated loop
	// burned a fleet budget grant on a heal that could not happen.
	targets := make([]corev1.Pod, 0, len(pods))
	for i := range pods {
		if metav1.GetControllerOf(&pods[i]) == nil {
			log.Info("operator pod has no controller owner — delete skipped",
				"operator", op.name, "pod", pods[i].Namespace+"/"+pods[i].Name)
			continue
		}
		targets = append(targets, pods[i])
	}
	if len(targets) == 0 {
		return
	}
	var leaseObj metav1.Object
	if lease != nil {
		leaseObj = lease
	}
	proceed, unverifiable := p.HealAllowedPersisted(ctx, log,
		&p.opHealed, leaseObj, operatorHealAnno,
		podKey, operatorHealCooldown, now)
	if unverifiable {
		metrics.IncError(p.Name)
		return
	}
	if !proceed {
		return
	}

	deleted := false
	apiErr := false
	for i := range targets {
		pod := &targets[i]
		// The UID precondition inside heal.DeletePod closes the
		// list→delete TOCTOU: a same-named replacement pod is not
		// ours to reap.
		didDelete, err := heal.DeletePod(ctx, p.CS, nil, "", pod, now)
		if err != nil {
			apiErr = true
			metrics.IncError(p.Name)
			log.Error(err, "stuck operator leader delete failed",
				"pod", pod.Namespace+"/"+pod.Name, "operator", op.name)
			continue
		}
		if !didDelete {
			// Quorum reservation denied — sibling pods of this
			// operator already spent the workload's one-disruption
			// slot this sweep; one leader bounce is the heal.
			continue
		}
		kube.MarkPodDeleted(ctx, pod.UID) // O(1) tombstone — no census reset
		deleted = true
		log.Info("DELETE: stuck operator leader pod — forcing re-election",
			"operator", op.name, "pod", pod.Namespace+"/"+pod.Name,
			"reasons", strings.Join(reasons, ","))
	}
	if !deleted {
		if !apiErr {
			heal.RefundGrant(now)
		}
		return
	}
	for _, r := range reasons {
		operatorWorkqueueHealsTotal.WithLabelValues(op.name, r).Inc()
	}
	// The pod delete already landed — stamp the in-RAM half
	// unconditionally so a failed anno patch cannot un-suppress a
	// delivered heal (StampPersisted's delivered-only contract is
	// for the annotation stamp, not the heal itself).
	p.opHealed.Stamp(podKey, now)
	// Persist the stamp on the Lease — the durable half of the
	// cooldown. A nil lease (leaseOptional operators healing through
	// the pod fallback) has nowhere to stamp; the in-RAM half is all
	// there is. A patch failure leaves the in-RAM half holding.
	if lease == nil {
		return
	}
	if err := heal.StampPersisted(ctx, lease,
		func(ctx context.Context, data []byte) error {
			_, err := p.CS.CoordinationV1().Leases(lease.Namespace).
				Patch(ctx, lease.Name, types.MergePatchType, data,
					metav1.PatchOptions{})
			return err
		},
		operatorHealAnno, nil, "", now); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "persist heal stamp failed", "operator", op.name)
	}
	// The stamp patch mutated the Lease — drop the sweep's lease
	// census + index so later checks don't read the pre-patch copy.
	p.InvalidateLeases(ctx)
}

// leaderPods resolves the operator's leader pod: holderIdentity is
// "<pod-name>_<uuid>" on client-go leader-election — the name prefix
// is tried first, then the verbatim identity (custom electors may
// not suffix); the operator's pod label selector inside the Lease's
// own namespace is the fallback when neither resolves.
func (p *operatorWorkqueueCheck) leaderPods(ctx context.Context, op operatorTarget,
	lease *coordinationv1.Lease) ([]corev1.Pod, error) {
	holder := ""
	// The pod namespace is the operator's own — podNS when the Lease
	// lives elsewhere (cert-manager elects in kube-system, runs in
	// cert-manager), else the Lease's namespace; for a nil lease
	// (leaseOptional operators) the selector scans targetPodNS(op).
	podNS := targetPodNS(op)
	if lease != nil {
		if lease.Spec.HolderIdentity != nil {
			holder = *lease.Spec.HolderIdentity
		}
	}
	if holder != "" {
		candidates := []string{holder}
		if i := strings.LastIndex(holder, "_"); i > 0 {
			candidates = append([]string{holder[:i]}, candidates...)
		}
		for _, name := range candidates {
			pod, err := p.CS.CoreV1().Pods(podNS).
				Get(ctx, name, metav1.GetOptions{})
			switch {
			case apierrors.IsNotFound(err):
				continue
			case err != nil:
				return nil, fmt.Errorf("get leader pod %s/%s: %w",
					podNS, name, err)
			}
			// Only a live candidate is deletable: a pod already
			// terminating (someone else is re-rolling it) or not
			// Running is not the leader to bounce — fall through
			// to the selector fallback.
			if pod.DeletionTimestamp != nil ||
				pod.Status.Phase != corev1.PodRunning {
				continue
			}
			return []corev1.Pod{*pod}, nil
		}
	}
	pods, err := p.PodsMatching(ctx, podNS, op.podSelector)
	if err != nil {
		return nil, fmt.Errorf("list operator pods in %s (selector %q): %w",
			podNS, op.podSelector, err)
	}
	// Candidate filter — terminating pods are already going away and
	// non-Running pods are not the elected holder; neither is a
	// leader-pod-delete target.
	live := pods[:0]
	for _, pod := range pods {
		if pod.DeletionTimestamp == nil &&
			pod.Status.Phase == corev1.PodRunning {
			live = append(live, pod)
		}
	}
	pods = live
	// hostNetwork leader identity: "<nodeHostname>-<rand>" never
	// equals a pod name, so the name GETs above all miss and the
	// oldest-pod heuristic below would bounce an arbitrary standby.
	// Match the holder's hostname prefix against each live pod's
	// scheduled node — positive attribution beats the age guess.
	if holder != "" {
		for i := range pods {
			if pods[i].Spec.NodeName != "" &&
				strings.HasPrefix(holder, pods[i].Spec.NodeName+"-") {
				return []corev1.Pod{*pods[i]}, nil
			}
		}
	}
	// The selector fallback cannot tell the leader from its
	// standbys — deleting every matched replica wedges the operator
	// outright (the 2026-11-04 cilium-operator triple-delete). Cap
	// the blast radius at one pod, preferring the oldest (the
	// longest-running replica is the likelier wedged holder): if
	// the survivor was the real holder the signature stays up and
	// the next post-cooldown sweep deletes it.
	if len(pods) > 1 {
		sort.Slice(pods, func(i, j int) bool {
			return pods[i].CreationTimestamp.
				Before(&pods[j].CreationTimestamp)
		})
		return []corev1.Pod{*pods[0]}, nil
	}
	out := make([]corev1.Pod, 0, len(pods))
	for _, pod := range pods {
		out = append(out, *pod)
	}
	return out, nil
}
