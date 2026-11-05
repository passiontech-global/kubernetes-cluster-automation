// operator_leader_heal.go — the leader-pod heal path of the
// operator-workqueue-watchdog check (W5.8): once an operator's CRs
// stay unreconciled past the stuck window, healOperatorLeader deletes
// the leader pod to force re-election (1h cooldown, wider of the
// in-RAM ledger and the persisted node.ops/last-operator-heal Lease
// stamp; maintenance-mutex gated), and leaderPods resolves the holder
// from the Lease's holderIdentity with the pod-selector fallback.
package watchdogs

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	// operatorHealCooldown bounds leader-pod deletes to one per
	// operator per hour — the wider of the in-RAM ledger and the
	// persisted node.ops/last-operator-heal stamp on the Lease
	// (same wider-of-both shape as the helmrelease-unlocker).
	operatorHealCooldown = time.Hour
	// operatorHealAnno persists the last heal moment on the
	// operator's leader-election Lease — the restart-proof half of
	// the cooldown.
	operatorHealAnno = "node.ops/last-operator-heal"
)

// healOperatorLeader deletes the stuck operator's leader pod to force
// re-election — the same unsticking nudge a manual
// `kubectl delete pod` applies. Gates, in order: the 1h cooldown
// (wider of in-RAM ledger and the persisted Lease stamp), the
// maintenance mutex (never kill a leader mid-drain/upgrade), and a
// resolvable leader pod (holderIdentity "<pod>_<uuid>" first, then
// the label selector in the Lease's namespace). Every guard refusal
// is quiet — the frozen gauge + FAIL series already carry the alert.
func (p *operatorWorkqueueCheck) healOperatorLeader(ctx context.Context, log logr.Logger,
	op operatorTarget, lease *coordinationv1.Lease, reasons []string, now time.Time) {

	if p.opHealed.CooledDown(op.name, operatorHealCooldown, now) {
		log.Info("skip heal: operator inside cooldown", "operator", op.name)
		return
	}
	if lease != nil {
		if ts := lease.Annotations[operatorHealAnno]; ts != "" {
			if t, err := time.Parse(time.RFC3339, ts); err == nil &&
				now.Sub(t) < operatorHealCooldown {
				log.Info("skip heal: persisted stamp inside cooldown",
					"operator", op.name,
					"ago", now.Sub(t).Truncate(time.Minute))
				return
			}
		}
	}
	// Maintenance mutex — "cannot verify" fails closed like every
	// other caller: an unverifiable drain state defers the heal.
	held, why, err := shared.MaintenanceActive(ctx, p.CS, p.Dyn)
	if err != nil {
		metrics.IncError(p.Name)
		log.Info("WARN: maintenance check unverifiable — heal deferred (fail closed)",
			"operator", op.name, "error", err)
		return
	}
	if held {
		log.Info("maintenance in progress — heal deferred",
			"operator", op.name, "why", why)
		return
	}

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

	deleted := false
	for i := range pods {
		pod := &pods[i]
		// UID precondition closes the list→delete TOCTOU: a
		// same-named replacement pod is not ours to reap.
		uid := pod.UID
		if err := p.CS.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name,
			metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &uid},
			}); err != nil {
			metrics.IncError(p.Name)
			log.Error(err, "stuck operator leader delete failed",
				"pod", pod.Namespace+"/"+pod.Name, "operator", op.name)
			continue
		}
		deleted = true
		log.Info("DELETE: stuck operator leader pod — forcing re-election",
			"operator", op.name, "pod", pod.Namespace+"/"+pod.Name,
			"reasons", strings.Join(reasons, ","))
	}
	if !deleted {
		return
	}
	for _, r := range reasons {
		metrics.OperatorWorkqueueHealsTotal.WithLabelValues(op.name, r).Inc()
	}
	p.opHealed.Stamp(op.name, now)
	// Persist the stamp on the Lease — the durable half of the
	// cooldown. A nil lease (leaseOptional operators healing through
	// the pod fallback) has nowhere to stamp; the in-RAM half is all
	// there is. A patch failure leaves the in-RAM half holding.
	if lease == nil {
		return
	}
	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"annotations": map[string]any{
			operatorHealAnno: now.UTC().Format(time.RFC3339),
		}},
	})
	if err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "marshal heal stamp", "operator", op.name)
		return
	}
	if _, err := p.CS.CoordinationV1().Leases(lease.Namespace).Patch(ctx, lease.Name,
		types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "persist heal stamp failed", "operator", op.name)
	}
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
			default:
				return []corev1.Pod{*pod}, nil
			}
		}
	}
	pods, err := p.CS.CoreV1().Pods(podNS).List(ctx,
		metav1.ListOptions{LabelSelector: op.podSelector})
	if err != nil {
		return nil, fmt.Errorf("list operator pods in %s (selector %q): %w",
			podNS, op.podSelector, err)
	}
	// The selector fallback cannot tell the leader from its
	// standbys — deleting every matched replica wedges the operator
	// outright (the 2026-11-04 cilium-operator triple-delete). Cap
	// the blast radius at one pod, preferring the oldest (the
	// longest-running replica is the likelier wedged holder): if
	// the survivor was the real holder the signature stays up and
	// the next post-cooldown sweep deletes it.
	if len(pods.Items) > 1 {
		sort.Slice(pods.Items, func(i, j int) bool {
			return pods.Items[i].CreationTimestamp.
				Before(&pods.Items[j].CreationTimestamp)
		})
		return pods.Items[:1], nil
	}
	return pods.Items, nil
}
