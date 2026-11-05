// apiservice-guard — 2.3, the aggregated APIService watchdog +
// fail-closed orphan reaper (apiregistration.k8s.io/v1).
//
// An aggregated APIService whose spec.service.namespace no longer
// exists is worse than dead weight: the orphaned object keeps
// wedging the namespace-terminating controller and the garbage
// collector (the apiservice still advertises a live Service backend
// that can never resolve — the same fail-closed shape as the
// admission webhook orphans this package already reaps, incident
// 2026-10-20).
//
// Two independent duties per 5m sweep:
//
//	(a) Fail-closed orphan cleanup. The Namespace list is the ONLY
//	    source of "deleted" truth and is snapshotted first — an
//	    error or an EMPTY list aborts the deletion pass before
//	    anything is touched (an API flap must never read as
//	    "namespace deleted"). Only APIServices with spec.service
//	    set are candidates; when the referenced namespace is
//	    absent from the snapshot the guard re-confirms with a
//	    direct Namespaces().Get — only an IsNotFound verdict
//	    deletes the object.
//	(b) Availability watchdog. An APIService holding
//	    Available=False for longer than apiServiceUnavailMinAge
//	    (measured from the condition's lastTransitionTime) exports
//	    node_automation_apiservice_unavailable{name,
//	    service_namespace, service_name}=1. A seen-set prunes
//	    series whose APIService recovered or vanished — a stale
//	    label tuple must not pin the alert forever.
//
// apiregistration.k8s.io has no in-tree typed client, so all
// APIService access goes through the dynamic client; the typed
// clientset still serves the namespace snapshot (fail-closed
// source) and the per-candidate Get confirmation.
package apiserviceguard

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

const (
	apiServiceGuardQueue     = "apiservice-guard"
	apiServiceGuardInterval  = 5 * time.Minute
	apiServiceUnavailMinAge  = 10 * time.Minute
	apiServiceAvailableCond  = "Available"
	apiServiceConditionFalse = "False"

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

// apiServiceGVR is the apiregistration.k8s.io/v1 APIService resource —
// cluster-scoped, no typed client in client-go.
var apiServiceGVR = shared.GVRAPIService

type apiServiceGuard struct {
	cs  kubernetes.Interface
	dyn dynamic.Interface
	// nowFn is the clock seam — tests pin it so the >10m
	// unavailable window is deterministic. nil → time.Now.
	nowFn shared.Clock
	// emitted is the ledger of APIServiceUnavailable label tuples
	// ("name/service_namespace/service_name") held at =1 — a tuple
	// not re-seen this sweep gets its series deleted via
	// DeleteLabelValues (same seen-set hygiene as brokenEmitted).
	emitted map[string]bool
	// unblocked is "<apiservice name>" -> last unblock-heal time —
	// bounds restart churn on a backend that wedges again right
	// after its pods are recreated.
	unblocked map[string]time.Time
}

// Setup registers the 5-minute sweep. Disabled
// clusters (APISERVICE_GUARD_ENABLED=false) skip registration
// entirely — same contract as cert-drift-auditor: no runnable, no
// periodic cluster LIST against the apiserver.
func Setup(d shared.Deps) error {
	mgr, cs, dyn := d.Mgr, d.CS, d.Dyn
	if !shared.Gate("APISERVICE_GUARD_ENABLED", true) {
		logf.Log.WithName(apiServiceGuardQueue).Info("disabled — module not registered")
		return nil
	}
	g := &apiServiceGuard{cs: cs, dyn: dyn, nowFn: time.Now,
		emitted: map[string]bool{}}
	return shared.AddPeriodic(mgr, apiServiceGuardQueue, apiServiceGuardInterval, g.run)
}

func (g *apiServiceGuard) run(ctx context.Context) error {
	// Lazily arm the zero-value struct — unit tests construct the
	// guard literally without the Setup path.
	if g.nowFn == nil {
		g.nowFn = time.Now
	}
	if g.emitted == nil {
		g.emitted = map[string]bool{}
	}
	if g.unblocked == nil {
		g.unblocked = map[string]time.Time{}
	}
	// The orphan sweep and the availability watchdog are
	// independent duties — a failure in one must never blind the
	// other, so both run and their errors join (nil+nil → nil). Both
	// read the same APIService set, so it is listed ONCE per run and
	// shared; a list failure is handed to each duty separately
	// (either may still act on the parts it does not need).
	svcs, svcsErr := g.dyn.Resource(apiServiceGVR).List(ctx, metav1.ListOptions{})
	orphanErr := g.sweepOrphans(ctx, svcs, svcsErr)
	watchErr := g.sweepAvailability(ctx, svcs, svcsErr)
	unblockErr := g.sweepUnblock(ctx, svcs, svcsErr)
	return errors.Join(orphanErr, watchErr, unblockErr)
}

// ---------------------------------------------------------------------------
// (a) Fail-closed orphan cleanup.
// ---------------------------------------------------------------------------

// sweepOrphans consumes the shared per-run APIService snapshot — a
// list error is delivered via svcsErr (recorded by run, not returned
// there) so this pass can still abort itself while the watchdog
// reports its own verdict on the same failure.
func (g *apiServiceGuard) sweepOrphans(ctx context.Context, svcs *unstructured.UnstructuredList, svcsErr error) error {
	log := logf.FromContext(ctx)

	// Namespace snapshot — the ONLY source of "deleted" truth. An
	// error aborts the whole pass; an EMPTY list means the
	// apiserver/RBAC lied (every APIService would look orphaned), so
	// the pass skips itself without failing the run — the
	// availability watchdog still evaluates.
	nsList, err := g.cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list namespaces (API flap) — abort orphan pass: %w", err)
	}
	if len(nsList.Items) == 0 {
		log.Info("WARN: empty namespace list (API flap) — orphan pass skipped")
		return nil
	}
	namespaces := make(map[string]bool, len(nsList.Items))
	for _, ns := range nsList.Items {
		namespaces[ns.Name] = true
	}
	nsList = nil

	if svcsErr != nil {
		return fmt.Errorf("list apiservices — abort orphan pass: %w", svcsErr)
	}

	deleted := 0
	for i := range svcs.Items {
		svc := &svcs.Items[i]
		svcNs, svcName, ok := apiServiceBackend(svc)
		if !ok {
			continue // no Service backend — nothing to orphan-check
		}
		if namespaces[svcNs] {
			continue
		}
		// The snapshot says the namespace is gone — but a List can be
		// stale where a Get is fresh, so the delete only fires after
		// the apiserver itself confirms NotFound (fail closed).
		_, getErr := g.cs.CoreV1().Namespaces().Get(ctx, svcNs, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(getErr):
		case getErr != nil:
			log.Info("WARN: namespace confirm failed — APIService kept (fail closed)",
				"apiservice", svc.GetName(), "namespace", svcNs, "error", getErr)
			metrics.IncError(apiServiceGuardQueue)
			continue
		default:
			// Namespace actually exists — the snapshot was stale.
			continue
		}
		log.Info("DELETE: orphan APIService (backend namespace gone)",
			"apiservice", svc.GetName(), "service", svcNs+"/"+svcName)
		// UID precondition closes the TOCTOU window between the
		// IsNotFound re-confirm and the delete — a same-named
		// APIService recreated in between is not ours to reap.
		uid := svc.GetUID()
		if err := g.dyn.Resource(apiServiceGVR).
			Delete(ctx, svc.GetName(), metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &uid},
			}); err != nil {
			log.Error(err, "orphan apiservice delete failed",
				"apiservice", svc.GetName())
			metrics.IncError(apiServiceGuardQueue)
			continue
		}
		deleted++
	}
	log.Info("orphan pass done", "deleted", deleted, "apiservices", len(svcs.Items))
	return nil
}

// ---------------------------------------------------------------------------
// (b) Availability watchdog.
// ---------------------------------------------------------------------------

// sweepAvailability consumes the same per-run snapshot — a list error
// is delivered via svcsErr and aborts only this duty (the orphan pass
// above already ran its own verdict).
func (g *apiServiceGuard) sweepAvailability(ctx context.Context, svcs *unstructured.UnstructuredList, svcsErr error) error {
	log := logf.FromContext(ctx)
	if svcsErr != nil {
		return fmt.Errorf("list apiservices — watchdog skipped: %w", svcsErr)
	}

	now := g.nowFn()
	emitted := map[string]bool{}
	for i := range svcs.Items {
		svc := &svcs.Items[i]
		unavailSince, ok := apiServiceUnavailableSince(svc)
		if !ok || now.Sub(unavailSince) < apiServiceUnavailMinAge {
			continue
		}
		svcNs, svcName, _ := apiServiceBackend(svc)
		key := svc.GetName() + "/" + svcNs + "/" + svcName
		metrics.APIServiceUnavailable.
			WithLabelValues(svc.GetName(), svcNs, svcName).Set(1)
		emitted[key] = true
		log.Info("APIService unavailable past threshold",
			"apiservice", svc.GetName(), "service", svcNs+"/"+svcName,
			"since", unavailSince.Format(time.RFC3339))
	}

	// Prune series whose APIService recovered or vanished — a label
	// tuple that stops being re-asserted must not pin
	// apiservice_unavailable=1 forever. Keys are
	// "name/service_namespace/service_name"; all three are DNS-1123
	// identifiers (or empty) so "/" is unambiguous.
	for k := range g.emitted {
		if emitted[k] {
			continue
		}
		if parts := strings.SplitN(k, "/", 3); len(parts) == 3 {
			metrics.APIServiceUnavailable.
				DeleteLabelValues(parts[0], parts[1], parts[2])
		}
	}
	g.emitted = emitted
	return nil
}

// apiServiceBackend returns the APIService's spec.service
// namespace/name — ok=false when the APIService is not Service-backed
// (e.g. the local "v1." core registration).
func apiServiceBackend(u *unstructured.Unstructured) (namespace, name string, ok bool) {
	ns, _ := shared.NestedString(u.Object, "spec", "service", "namespace")
	n, _ := shared.NestedString(u.Object, "spec", "service", "name")
	if ns == "" || n == "" {
		return "", "", false
	}
	return ns, n, true
}

// apiServiceUnavailableSince returns the Available=False condition's
// lastTransitionTime — ok=false when the condition is absent, not
// False, or the timestamp is unparseable (an APIService with no
// provable failure age is never flagged).
func apiServiceUnavailableSince(u *unstructured.Unstructured) (time.Time, bool) {
	c, ok := shared.ConditionOf(u.Object, apiServiceAvailableCond)
	if !ok || c.Status != apiServiceConditionFalse || c.LastTransitionTime.IsZero() {
		return time.Time{}, false
	}
	return c.LastTransitionTime, true
}

// ---------------------------------------------------------------------------
// (c) W10-CP1 — dead-APIService unblocker.
// ---------------------------------------------------------------------------

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
func (g *apiServiceGuard) sweepUnblock(ctx context.Context, svcs *unstructured.UnstructuredList, svcsErr error) error {
	log := logf.FromContext(ctx)
	if svcsErr != nil {
		return fmt.Errorf("list apiservices — unblock pass skipped: %w", svcsErr)
	}
	now := g.nowFn()

	// Candidate pass — cheap unstructured reads only; the namespace
	// scan below is skipped entirely when nothing qualifies.
	type candidate struct {
		svc   *unstructured.Unstructured
		group string
	}
	var cands []candidate
	for i := range svcs.Items {
		svc := &svcs.Items[i]
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
	stuck, err := g.stuckTerminatingNamespaces(ctx, now)
	if err != nil {
		return err
	}
	if len(stuck) == 0 {
		return nil
	}

	healed := 0
	for _, c := range cands {
		if last, ok := g.unblocked[c.svc.GetName()]; ok &&
			now.Sub(last) < apiServiceUnblockCooldown {
			continue
		}
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
		deleted, err := g.restartBackingPods(ctx, svcNs, svcName)
		if err != nil {
			log.Error(err, "unblock heal failed",
				"apiservice", c.svc.GetName(), "service", svcNs+"/"+svcName)
			metrics.IncError(apiServiceGuardQueue)
			continue
		}
		g.unblocked[c.svc.GetName()] = now
		healed++
		if deleted > 0 {
			metrics.APIServiceUnblockHealsTotal.
				WithLabelValues(svcNs, "backing_pods_deleted").Inc()
		}
		log.Info("ACTION: unblocked dead APIService wedging namespace termination",
			"apiservice", c.svc.GetName(), "group", c.group,
			"service", svcNs+"/"+svcName,
			"terminatingNamespaces", refs, "podsDeleted", deleted)
	}
	return nil
}

// stuckTerminatingNamespaces returns "<ns name>" -> lowercased
// reference corpus (conditions + events) for every namespace that
// has been in phase Terminating for >= apiServiceUnblockMinAge. A
// namespace without a deletionTimestamp cannot prove its age — it
// is skipped (fail closed).
func (g *apiServiceGuard) stuckTerminatingNamespaces(ctx context.Context, now time.Time) (map[string]string, error) {
	log := logf.FromContext(ctx)
	nsList, err := g.cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list namespaces (unblock pass): %w", err)
	}
	out := map[string]string{}
	for i := range nsList.Items {
		ns := &nsList.Items[i]
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
		evs, err := g.cs.CoreV1().Events(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			// Conditions-only corpus still carries
			// NamespaceContentRemaining/DiscoveryFailed detail —
			// a partial corpus beats skipping the namespace.
			log.Info("WARN: events list failed — conditions-only corpus",
				"namespace", ns.Name, "error", err)
		} else {
			for j := range evs.Items {
				e := &evs.Items[j]
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

// apiServiceGroup extracts the API group from an APIService name —
// "v1beta1.metrics.k8s.io" -> "metrics.k8s.io". "" for names without
// a group suffix (the core "v1." registration).
func apiServiceGroup(name string) string {
	idx := strings.Index(name, ".")
	if idx < 0 || idx == len(name)-1 {
		return ""
	}
	return name[idx+1:]
}

// restartBackingPods deletes the running pods selected by the
// APIService's backing Service so their controllers recreate them —
// the aggregated-apiserver restart that clears a wedged aggregation.
// Capped per call; NotFound service/pod races are quiet no-ops.
func (g *apiServiceGuard) restartBackingPods(ctx context.Context, svcNs, svcName string) (int, error) {
	log := logf.FromContext(ctx)
	svc, err := g.cs.CoreV1().Services(svcNs).Get(ctx, svcName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// The backend Service itself is gone — pod restart is
		// impossible; the operator that owns it must recreate it.
		log.Info("unblock heal skipped — backing service gone",
			"service", svcNs+"/"+svcName)
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("get backing service %s/%s: %w", svcNs, svcName, err)
	}
	if len(svc.Spec.Selector) == 0 {
		log.Info("unblock heal skipped — backing service has no selector",
			"service", svcNs+"/"+svcName)
		return 0, nil
	}
	pods, err := g.cs.CoreV1().Pods(svcNs).List(ctx, metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(svc.Spec.Selector).String(),
	})
	if err != nil {
		return 0, fmt.Errorf("list backing pods %s: %w", svcNs, err)
	}
	deleted := 0
	for i := range pods.Items {
		if deleted >= apiServiceUnblockPodCap {
			break
		}
		p := &pods.Items[i]
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		uid := p.UID
		if err := g.cs.CoreV1().Pods(svcNs).Delete(ctx, p.Name,
			metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &uid},
			}); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			log.Error(err, "backing pod delete failed",
				"pod", svcNs+"/"+p.Name)
			continue
		}
		deleted++
	}
	return deleted, nil
}
