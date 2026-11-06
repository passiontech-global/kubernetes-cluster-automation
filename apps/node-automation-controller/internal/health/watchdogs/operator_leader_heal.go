// operator_leader_heal.go — the leader-pod heal path of the
// operator-workqueue-watchdog check (W5.8): once an operator's CRs
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
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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

	// The 1h cooldown is the wider of the in-RAM ledger and the
	// persisted Lease stamp — the ledger covers a heal whose anno
	// patch never landed, the annotation survives an operator
	// restart. A nil lease (leaseOptional operators healing through
	// the pod fallback) collapses the check to the ledger half.
	var leaseObj metav1.Object
	if lease != nil {
		leaseObj = lease
	}
	if heal.PersistedCooledDown(&p.opHealed, leaseObj, operatorHealAnno,
		op.name, operatorHealCooldown, now) {
		log.Info("skip heal: inside cooldown", "operator", op.name)
		return
	}
	// Maintenance mutex — "cannot verify" fails closed like every
	// other caller: an unverifiable drain state defers the heal.
	// heal.AllowedV runs with a nil ledger — the cooldown above is
	// the wider-of-both PersistedCooledDown, not a single key, so
	// only its mutex gate applies — shared via the check's verdict
	// so a sweep of stuck operators pays one evaluation.
	proceed, unverifiable := heal.AllowedV(ctx, log, &p.verdict,
		p.CS, p.Dyn, nil, op.name, 0, now)
	if unverifiable {
		metrics.IncError(p.Name)
		return
	}
	if !proceed {
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
		// The UID precondition inside heal.DeletePod closes the
		// list→delete TOCTOU: a same-named replacement pod is not
		// ours to reap.
		if _, err := heal.DeletePod(ctx, p.CS, nil, "", pod, now); err != nil {
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
	// The pod delete already landed — stamp the in-RAM half
	// unconditionally so a failed anno patch cannot un-suppress a
	// delivered heal (StampPersisted's delivered-only contract is
	// for the annotation stamp, not the heal itself).
	p.opHealed.Stamp(op.name, now)
	// Persist the stamp on the Lease — the durable half of the
	// cooldown. A nil lease (leaseOptional operators healing through
	// the pod fallback) has nowhere to stamp; the in-RAM half is all
	// there is. A patch failure leaves the in-RAM half holding.
	if lease == nil {
		return
	}
	if err := heal.StampPersisted(ctx,
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
