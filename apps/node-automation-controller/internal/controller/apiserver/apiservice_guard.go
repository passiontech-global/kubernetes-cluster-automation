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
package apiserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/controller/shared"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

const (
	apiServiceGuardQueue     = "apiservice-guard"
	apiServiceGuardInterval  = 5 * time.Minute
	apiServiceUnavailMinAge  = 10 * time.Minute
	apiServiceAvailableCond  = "Available"
	apiServiceConditionFalse = "False"
)

// apiServiceGVR is the apiregistration.k8s.io/v1 APIService resource —
// cluster-scoped, no typed client in client-go.
var apiServiceGVR = schema.GroupVersionResource{
	Group:    "apiregistration.k8s.io",
	Version:  "v1",
	Resource: "apiservices",
}

type apiServiceGuard struct {
	cs  kubernetes.Interface
	dyn dynamic.Interface
	// nowFn is the clock seam — tests pin it so the >10m
	// unavailable window is deterministic. nil → time.Now.
	nowFn func() time.Time
	// emitted is the ledger of APIServiceUnavailable label tuples
	// ("name/service_namespace/service_name") held at =1 — a tuple
	// not re-seen this sweep gets its series deleted via
	// DeleteLabelValues (same seen-set hygiene as brokenEmitted).
	emitted map[string]bool
}

// SetupAPIServiceGuard registers the 5-minute sweep. Disabled
// clusters (APISERVICE_GUARD_ENABLED=false) skip registration
// entirely — same contract as cert-drift-auditor: no runnable, no
// periodic cluster LIST against the apiserver.
func SetupAPIServiceGuard(mgr ctrl.Manager, cs kubernetes.Interface, dyn dynamic.Interface, enabled bool) error {
	if !enabled {
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
	// The orphan sweep and the availability watchdog are
	// independent duties — a failure in one must never blind the
	// other, so both run and their errors join (nil+nil → nil).
	orphanErr := g.sweepOrphans(ctx)
	watchErr := g.sweepAvailability(ctx)
	return errors.Join(orphanErr, watchErr)
}

// ---------------------------------------------------------------------------
// (a) Fail-closed orphan cleanup.
// ---------------------------------------------------------------------------

func (g *apiServiceGuard) sweepOrphans(ctx context.Context) error {
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

	svcs, err := g.dyn.Resource(apiServiceGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list apiservices — abort orphan pass: %w", err)
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

func (g *apiServiceGuard) sweepAvailability(ctx context.Context) error {
	log := logf.FromContext(ctx)
	svcs, err := g.dyn.Resource(apiServiceGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list apiservices — watchdog skipped: %w", err)
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
	ns, _, _ := unstructured.NestedString(u.Object, "spec", "service", "namespace")
	n, _, _ := unstructured.NestedString(u.Object, "spec", "service", "name")
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
	conds, found, err := unstructured.NestedSlice(u.Object, "status", "conditions")
	if err != nil || !found {
		return time.Time{}, false
	}
	for _, c := range conds {
		m, ok := c.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := m["type"].(string)
		status, _ := m["status"].(string)
		if typ != apiServiceAvailableCond {
			continue
		}
		if status != apiServiceConditionFalse {
			return time.Time{}, false
		}
		ts, _ := m["lastTransitionTime"].(string)
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			return time.Time{}, false
		}
		return t, true
	}
	return time.Time{}, false
}
