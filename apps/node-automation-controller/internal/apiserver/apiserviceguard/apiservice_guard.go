// apiservice_guard.go — apiservice-guard, the aggregated APIService
// watchdog + fail-closed orphan reaper (apiregistration.k8s.io/v1).
//
// An aggregated APIService whose spec.service.namespace no longer
// exists is worse than dead weight: the orphaned object keeps
// wedging the namespace-terminating controller and the garbage
// collector (the apiservice still advertises a live Service backend
// that can never resolve — the same fail-closed shape as the
// admission webhook orphans webhookguard already reaps, incident
// 2026-10-20).
//
// Three independent duties per 5m sweep, one file each behind the
// apiServiceGuard facade (same split shape as webhookguard):
//
//	(a) orphan_sweep.go — fail-closed orphan cleanup. The Namespace
//	    list is the ONLY source of "deleted" truth and is
//	    snapshotted first — an error or an EMPTY list aborts the
//	    deletion pass before anything is touched (an API flap must
//	    never read as "namespace deleted"). Only APIServices with
//	    spec.service set are candidates; when the referenced
//	    namespace is absent from the snapshot the guard re-confirms
//	    with a direct Namespaces().Get — only an IsNotFound verdict
//	    deletes the object.
//	(b) availability_watch.go — the availability watchdog. An
//	    APIService holding Available=False for longer than
//	    apiServiceUnavailMinAge (measured from the condition's
//	    lastTransitionTime) exports
//	    node_automation_apiservice_unavailable{name,
//	    service_namespace, service_name}=1. A seen-set prunes
//	    series whose APIService recovered or vanished — a stale
//	    label tuple must not pin the alert forever.
//	(c) unblock_heal.go — the namespace-terminating-wedged dead-APIService unblocker:
//	    a protected-namespace APIService wedging a Terminating
//	    namespace gets its backing pods restarted (maintenance-
//	    gated, UID-preconditioned, capped).
//
// apiregistration.k8s.io has no in-tree typed client, so all
// APIService access goes through the dynamic client; the typed
// clientset still serves the namespace snapshot (fail-closed
// source) and the per-candidate Get confirmation.
package apiserviceguard

import (
	"context"
	"errors"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/maintenance"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

const (
	apiServiceGuardInterval = 5 * time.Minute

	apiServiceAvailableCond  = "Available"
	apiServiceConditionFalse = "False"

	// apiServiceListPageSize bounds each List page — continue-token
	// pagination keeps a large APIService/event set from arriving as
	// one giant response body.
	apiServiceListPageSize = kube.DefaultListPageSize
)

// apiServiceGVR is the apiregistration.k8s.io/v1 APIService resource —
// cluster-scoped, no typed client in client-go.
var apiServiceGVR = kube.GVRAPIService

// apiServiceGuard is the facade behind the single "apiservice-guard"
// periodic: it owns the shared clients, the clock seam and the
// maintenance-mutex verdict, and embeds the three independent duties
// — orphanSweep, availabilityWatch and unblockHealer — each of which
// owns only its own state. run() invokes them in a fixed order
// through the promoted methods, so the externally visible contract
// (queue name, interval, metric series) is unchanged by the split.
type apiServiceGuard struct {
	cs kubernetes.Interface
	// dyn lists the APIServices every duty consumes AND feeds the
	// autopilot-Plan signal of the maintenance mutex the unblock
	// healer gates on. A nil dyn makes the Plan check unverifiable,
	// which the mutex reports as an error: unverifiable fails
	// closed, never a silently-narrowed check.
	dyn dynamic.Interface
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name and every IncError label
	// come from one place.
	queue string
	// now is the clock seam — tests pin it so the >10m
	// unavailable window is deterministic. nil → time.Now.
	now shared.Clock
	// verdict memoizes the maintenance-mutex evaluation the unblock
	// healer's per-target heal preambles share within a run — one
	// evaluation per Verdict TTL instead of three API reads per
	// candidate.
	verdict *maintenance.Verdict

	// The three duties share cs/dyn/now through snap.g and hand
	// each other nothing else; embedding keeps the guard's method
	// set — and every in-package test fixture — stable across the
	// split.
	orphanSweep
	availabilityWatch
	unblockHealer
}

// Setup registers the 5-minute sweep. Disabled
// clusters (APISERVICE_GUARD_ENABLED=false — resolved by setupModules
// into Deps.Disabled) skip registration entirely — same contract as
// cert-drift-auditor: no runnable, no periodic cluster LIST against
// the apiserver.
func Setup(d shared.Deps) error {
	mgr, cs, dyn := d.Mgr, d.CS, d.Dyn
	return shared.SetupNoConfig(d, func() error {
		g := &apiServiceGuard{cs: cs, dyn: dyn, queue: d.Name, now: shared.SystemClock, verdict: d.Maintenance}
		return shared.AddPeriodic(mgr, g.queue, apiServiceGuardInterval, g.run)
	})
}

// apiServiceSnapshot carries the cluster state one run shares across
// its duties: all three read the same APIService set, so it is
// listed ONCE per run instead of once per consumer — the namespace
// census the orphan pass and the unblock pass both build gets the
// same treatment (one List per run, not two). A list failure is
// recorded on the snapshot, not returned — every duty still decides
// for itself whether the missing piece aborts it (fail-closed
// source) or merely skips a check.
type apiServiceSnapshot struct {
	g     *apiServiceGuard
	svcs  *unstructured.UnstructuredList
	err   error
	nss   []corev1.Namespace
	nsErr error
}

// takeSnapshot lists the shared APIService set once — see
// apiServiceSnapshot.
func (g *apiServiceGuard) takeSnapshot(ctx context.Context) *apiServiceSnapshot {
	items, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: apiServiceListPageSize},
		kube.DynamicPage(g.dyn.Resource(apiServiceGVR)))
	nss, nsErr := kube.ListAll(ctx,
		metav1.ListOptions{Limit: apiServiceListPageSize},
		kube.Namespaces(g.cs))
	return &apiServiceSnapshot{
		g:     g,
		svcs:  &unstructured.UnstructuredList{Items: items},
		err:   err,
		nss:   nss,
		nsErr: nsErr,
	}
}

func (g *apiServiceGuard) run(ctx context.Context) error {
	// No lazy arming: a nil Clock reads as system time and the
	// GaugeLedger/CooldownSet bookkeeping zero values are ready to
	// use, so unit tests can construct the guard literally without
	// the Setup path.
	// The orphan sweep, the availability watchdog and the unblock
	// healer are independent duties — a failure in one must never
	// blind the others, so all run and their errors join
	// (nil+nil+nil → nil).
	snap := g.takeSnapshot(ctx)
	orphanErr := g.sweepOrphans(ctx, snap)
	watchErr := g.sweepAvailability(ctx, snap)
	unblockErr := g.sweepUnblock(ctx, snap)
	return errors.Join(orphanErr, watchErr, unblockErr)
}

// apiServiceBackend returns the APIService's spec.service
// namespace/name — ok=false when the APIService is not Service-backed
// (e.g. the local "v1." core registration).
func apiServiceBackend(u *unstructured.Unstructured) (namespace, name string, ok bool) {
	ns, _ := kube.NestedString(u.Object, "spec", "service", "namespace")
	n, _ := kube.NestedString(u.Object, "spec", "service", "name")
	if ns == "" || n == "" {
		return "", "", false
	}
	return ns, n, true
}

// apiServiceUnavailableSince returns the Available=False condition's
// lastTransitionTime — ok=false when the condition is absent, not
// False, or the timestamp is unparseable (an APIService with no
// provable failure age is never flagged). Shared by the availability
// watchdog (10m window) and the unblock healer (15m window).
func apiServiceUnavailableSince(u *unstructured.Unstructured) (time.Time, bool) {
	c, ok := kube.ConditionOf(u.Object, apiServiceAvailableCond)
	if !ok || c.Status != apiServiceConditionFalse || c.LastTransitionTime.IsZero() {
		return time.Time{}, false
	}
	return c.LastTransitionTime, true
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
