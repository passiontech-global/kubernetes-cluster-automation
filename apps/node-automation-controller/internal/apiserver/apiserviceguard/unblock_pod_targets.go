// unblock_pod_targets.go — the pod-target half of the APIService
// unblock healer: terminating-namespace discovery and the backing-
// pod delete pass. Split from unblock_heal.go (the candidate/gate
// half) to keep both under ~500 LOC.
package apiserviceguard

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// stuckTerminatingNamespaces returns "<ns name>" -> lowercased
// reference corpus (conditions + events) for every namespace that
// has been in phase Terminating for >= apiServiceUnblockMinAge. A
// namespace without a deletionTimestamp cannot prove its age — it
// is skipped (fail closed). The census itself is the shared
// per-run snapshot (the orphan pass lists the same input once).
func (u *unblockHealer) stuckTerminatingNamespaces(ctx context.Context,
	snap *apiServiceSnapshot, now time.Time) (map[string]string, error) {
	g := snap.g
	log := logf.FromContext(ctx)
	nss, err := snap.nss, snap.nsErr
	if err != nil {
		return nil, fmt.Errorf("list namespaces (unblock pass): %w", err)
	}
	out := map[string]string{}
	for i := range nss {
		ns := &nss[i]
		if ns.Status.Phase != corev1.NamespaceTerminating ||
			ns.DeletionTimestamp == nil ||
			now.Sub(ns.DeletionTimestamp.Time) < apiServiceUnblockMinAge {
			continue
		}
		var corpus strings.Builder
		for _, c := range ns.Status.Conditions {
			corpus.WriteString(strings.ToLower(string(c.Type)))
			corpus.WriteByte(' ')
			corpus.WriteString(strings.ToLower(c.Reason))
			corpus.WriteByte(' ')
			corpus.WriteString(strings.ToLower(c.Message))
			corpus.WriteByte('\n')
		}
		evs, err := kube.ListAll(ctx,
			metav1.ListOptions{Limit: apiServiceListPageSize},
			kube.Events(g.cs, ns.Name))
		if err != nil {
			// Conditions-only corpus still carries
			// NamespaceContentRemaining/DiscoveryFailed detail —
			// a partial corpus beats skipping the namespace.
			log.Info("WARN: events list failed — conditions-only corpus",
				"namespace", ns.Name, "error", err)
		} else {
			for j := range evs {
				e := &evs[j]
				corpus.WriteString(strings.ToLower(e.Reason))
				corpus.WriteByte(' ')
				corpus.WriteString(strings.ToLower(e.Message))
				corpus.WriteByte('\n')
			}
		}
		out[ns.Name] = corpus.String()
	}
	return out, nil
}

// backingPodTargets resolves the Service-backed pods an unblock heal
// may restart: the backing Service's selector pods that are alive and
// non-terminating (a pod already going down does not need the heal —
// deleting it again buys nothing and burns a budget grant). A gone
// Service or an empty selector yields no targets — the caller skips
// the candidate without touching the heal preamble. Caller has NOT
// yet taken the maintenance-mutex verdict: this is read-only.
func (u *unblockHealer) backingPodTargets(ctx context.Context,
	g *apiServiceGuard, svcNs, svcName string) ([]corev1.Pod, error) {
	log := logf.FromContext(ctx)
	svc, err := g.cs.CoreV1().Services(svcNs).Get(ctx, svcName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// The backend Service itself is gone — pod restart is
		// impossible; the operator that owns it must recreate it.
		log.Info("unblock heal skipped — backing service gone",
			"service", svcNs+"/"+svcName)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get backing service %s/%s: %w", svcNs, svcName, err)
	}
	if len(svc.Spec.Selector) == 0 {
		log.Info("unblock heal skipped — backing service has no selector",
			"service", svcNs+"/"+svcName)
		return nil, nil
	}
	pods, err := kube.ListAll(ctx, metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(svc.Spec.Selector).String(),
		Limit:         apiServiceListPageSize,
	}, kube.Pods(g.cs, svcNs))
	if err != nil {
		return nil, fmt.Errorf("list backing pods %s: %w", svcNs, err)
	}
	var targets []corev1.Pod
	for i := range pods {
		p := &pods[i]
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		if p.DeletionTimestamp != nil {
			continue // already terminating — its replacement carries the fix
		}
		targets = append(targets, *p)
	}
	return targets, nil
}

// deleteBackingPods evicts the pre-resolved restart targets, capped
// per call. Each kill rides heal.EvictPodV — the gate+act+refund
// composite: the UID-preconditioned, PDB-respecting Eviction API the
// unmeshed path runs on (a raw Delete would bypass every
// PodDisruptionBudget and could take the backend's last Ready replica
// mid-outage), the memoized maintenance-mutex verdict (nil heals — the
// per-APIService cooldown is healCandidate's stamp-on-delivered below,
// NOT a per-target pre-check: a multi-pod fan-out must not have its
// second target blocked by the first delivery's stamp), and a
// fleet-wide budget grant spent on DELIVERED evictions only — a 429
// refusal is refunded, keeping a PDB-hung backend from starving every
// other heal-gated module. A refusal is a deferral — the pod stays,
// nothing is metered, and `deleted` staying 0 keeps healCandidate from
// stamping the cooldown or logging an unblock that did not happen.
// NotFound races are quiet no-ops; any other eviction failure is
// metered and logged with the pod's own context. An unverifiable
// mutex check fails the pass closed: IncError once, stop — the memo
// makes the first target hit it anyway.
func (u *unblockHealer) deleteBackingPods(ctx context.Context,
	g *apiServiceGuard, apiService string, targets []corev1.Pod,
	now time.Time) int {
	log := logf.FromContext(ctx)
	deleted := 0
	for i := range targets {
		if deleted >= apiServiceUnblockPodCap ||
			u.sweepEvicted+deleted >= apiServiceUnblockSweepCap {
			break
		}
		p := &targets[i]
		// heals is nil (the cooldown is healCandidate's stamp-on-
		// delivered below) so key rides only the preamble's defer
		// logs — without it a refused/unverifiable target logs
		// "target=" with no APIService attribution.
		proceed, unverifiable, evicted, refused, err :=
			heal.EvictPodV(ctx, log, g.verdict, g.cs, g.dyn,
				nil, apiService, 0, p, now)
		switch {
		case unverifiable:
			metrics.IncError(g.queue)
			log.Info("heal deferred: maintenance check unverifiable — fail closed",
				"pod", p.Namespace+"/"+p.Name)
			return deleted
		case !proceed:
			continue // mutex held / budget denied — nothing this pass
		case refused:
			log.Info("DEFER: PDB refused backing pod eviction — keeping pod alive",
				"pod", p.Namespace+"/"+p.Name)
			continue
		case apierrors.IsNotFound(err):
			continue
		case err != nil:
			metrics.IncError(g.queue)
			log.Error(err, "backing pod eviction failed",
				"pod", p.Namespace+"/"+p.Name)
			continue
		case !evicted:
			continue // proceeded but nothing landed — treat like a race
		}
		deleted++
		u.sweepEvicted++
	}
	return deleted
}
