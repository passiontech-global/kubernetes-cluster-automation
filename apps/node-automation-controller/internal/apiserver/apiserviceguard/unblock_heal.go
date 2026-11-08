// unblock_heal.go — duty (c) of apiservice-guard, the W10-CP1
// dead-APIService unblocker: an aggregated APIService in a protected
// namespace that stays Available=False wedges every namespace
// termination whose GC still references its API group, so the sweep
// restarts the backing Service's pods — maintenance-gated,
// UID-preconditioned, capped, and cooled down per APIService. Its
// state (the per-APIService heal cooldown) lives on unblockHealer;
// shared deps are reached through snap.g.
package apiserviceguard

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

const (
	// W10-CP1 — dead-APIService unblocker. An aggregated APIService
	// in a protected namespace that stays Available=False wedges
	// every namespace termination whose GC still references its API
	// group. The unblock pass is the ONLY path allowed to restart
	// those backends, and only when the wedge is proven: unavailable
	// >=15m AND a namespace stuck Terminating >=15m whose
	// conditions/events name the group.
	apiServiceUnblockMinAge   = 15 * time.Minute
	apiServiceUnblockPodCap   = 10
	apiServiceUnblockCooldown = 15 * time.Minute
)

// apiServiceProtectedNamespaces is the plan's skipNamespaces set —
// APIServices backed in these namespaces are core-ish infra the
// guard otherwise never touches. Membership here does NOT skip the
// availability metric; it scopes which backends the unblock healer
// may restart.
var apiServiceProtectedNamespaces = map[string]bool{
	"kube-system": true,
	"linkerd":     true,
	"linkerd-viz": true,
	"monitoring":  true,
}

// unblockHealer owns the W10-CP1 sweep's per-sweep state — embedded
// in apiServiceGuard so the facade's method set (and every
// in-package test fixture built on it) is unchanged by the split.
// Shared deps (cs/dyn/now/verdict) are reached through snap.g; only
// the heal cooldown lives here.
type unblockHealer struct {
	// unblocked is "<apiservice name>" -> last unblock-heal time —
	// bounds restart churn on a backend that wedges again right
	// after its pods are recreated.
	unblocked state.CooldownSet
}

// sweepUnblock consumes the same per-run snapshot. It heals ONLY the
// protected-namespace backends (the plan's skipNamespaces set) and
// ONLY when the wedge is proven end-to-end:
//
//	spec.service.namespace in apiServiceProtectedNamespaces
//	AND Available=False for >= apiServiceUnblockMinAge (15m)
//	AND >=1 Namespace stuck Terminating >=15m whose conditions or
//	    events reference the APIService's API group.
//
// The heal is a backing-pod restart: the aggregated-apiserver pods
// behind spec.service are deleted (UID-preconditioned, capped) so
// their controllers recreate them — the least destructive action
// that clears a wedged aggregation without touching the
// operator-owned APIService object itself.
func (u *unblockHealer) sweepUnblock(ctx context.Context, snap *apiServiceSnapshot) error {
	g := snap.g
	log := logf.FromContext(ctx)
	now := g.now.Now()
	// PruneExpired runs BEFORE the error gate so the cooldown ledger
	// is pruned on EVERY cycle — an apiservices list flap must not
	// leave decommissioned backends' stamps accumulating forever.
	// unblocked keys on APIService names that die with the resource —
	// bound the map so decommissioned backends' stamps cannot
	// accumulate in the first place.
	u.unblocked.PruneExpired(now, apiServiceUnblockCooldown)
	if snap.err != nil {
		return fmt.Errorf("list apiservices — unblock pass skipped: %w", snap.err)
	}

	// Candidate pass — cheap unstructured reads only; the namespace
	// scan below is skipped entirely when nothing qualifies.
	type candidate struct {
		svc   *unstructured.Unstructured
		group string
	}
	var cands []candidate
	for i := range snap.svcs.Items {
		svc := &snap.svcs.Items[i]
		unavailSince, ok := apiServiceUnavailableSince(svc)
		if !ok || now.Sub(unavailSince) < apiServiceUnblockMinAge {
			continue
		}
		svcNs, _, _ := apiServiceBackend(svc)
		if !apiServiceProtectedNamespaces[svcNs] {
			continue
		}
		group := apiServiceGroup(svc.GetName())
		if group == "" {
			continue // "v1." core registration — never unblocked
		}
		cands = append(cands, candidate{svc: svc, group: group})
	}
	if len(cands) == 0 {
		return nil
	}

	// Wedge evidence: namespaces stuck Terminating >=15m, each with
	// a lowercased corpus of its conditions + events for group
	// matching.
	stuck, err := u.stuckTerminatingNamespaces(ctx, snap, now)
	if err != nil {
		return err
	}
	if len(stuck) == 0 {
		return nil
	}

	healed := 0
	for _, c := range cands {
		var refs []string
		for ns, corpus := range stuck {
			if strings.Contains(corpus, c.group) {
				refs = append(refs, ns)
			}
		}
		if len(refs) == 0 {
			continue
		}
		svcNs, svcName, _ := apiServiceBackend(c.svc)
		// Confirm a live restart target BEFORE the heal preamble: the
		// wedge evidence alone doesn't mean anything is left to
		// restart, and AllowedV spends a fleet-wide budget grant on
		// every proceed — a stale/empty backend must not burn one.
		targets, err := u.backingPodTargets(ctx, g, svcNs, svcName)
		if err != nil {
			log.Error(err, "unblock heal target lookup failed",
				"apiservice", c.svc.GetName(), "service", svcNs+"/"+svcName)
			metrics.IncError(g.queue)
			continue
		}
		if len(targets) == 0 {
			log.Info("unblock heal skipped — no live backing pod to restart",
				"apiservice", c.svc.GetName(), "service", svcNs+"/"+svcName)
			continue
		}
		// Wedge proven AND a target exists — the shared preamble gates
		// the heal: per-APIService cooldown first, then the
		// maintenance mutex (a cordon/drain/kured reboot or an
		// in-flight k0s upgrade defers the restart, and "cannot
		// verify" fails closed AND IncErrors the queue). The
		// facade's verdict memoizes the mutex so a run of candidates
		// pays one evaluation.
		proceed, unverifiable := heal.AllowedV(ctx, log, &g.verdict,
			g.cs, g.dyn, &u.unblocked, c.svc.GetName(),
			apiServiceUnblockCooldown, now)
		switch {
		case unverifiable:
			metrics.IncError(g.queue)
			continue
		case !proceed:
			continue
		}
		deleted := u.deleteBackingPods(ctx, g, targets, now)
		// Stamp the cooldown, count the heal and log ACTION only on a
		// DELIVERED heal — a pass that deleted nothing (NotFound
		// races) must not open the suppression window or log an
		// unblock that did not happen.
		if deleted > 0 {
			u.unblocked.Stamp(c.svc.GetName(), now)
			metrics.APIServiceUnblockHealsTotal.
				WithLabelValues(svcNs, "backing_pods_deleted").Inc()
			healed++
			log.Info("ACTION: unblocked dead APIService wedging namespace termination",
				"apiservice", c.svc.GetName(), "group", c.group,
				"service", svcNs+"/"+svcName,
				"terminatingNamespaces", refs, "podsDeleted", deleted)
		}
	}
	return nil
}

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

// deleteBackingPods deletes the pre-resolved restart targets, capped
// per call. NotFound races are quiet no-ops; any other delete failure
// is metered and logged with the pod's own context. Caller holds the
// maintenance-mutex verdict: these are LIVE pods.
func (u *unblockHealer) deleteBackingPods(ctx context.Context,
	g *apiServiceGuard, targets []corev1.Pod, now time.Time) int {
	log := logf.FromContext(ctx)
	deleted := 0
	for i := range targets {
		if deleted >= apiServiceUnblockPodCap {
			break
		}
		p := &targets[i]
		// heal.DeletePod carries the UID precondition the module
		// hand-rolled here before — a same-named pod recreated
		// between the list and the delete is not ours to restart.
		// The nil ledger leaves stamping to the caller: the
		// cooldown key is the APIService, not the pod.
		if _, err := heal.DeletePod(ctx, g.cs, nil, "", p, now); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			metrics.IncError(g.queue)
			log.Error(err, "backing pod delete failed",
				"pod", p.Namespace+"/"+p.Name)
			continue
		}
		deleted++
	}
	return deleted
}
