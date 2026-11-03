// cilium-identity-auditor — v2 sweep for leaked Cilium identities:
// detect (v1 behavior) PLUS a two-pass safe GC.
//
// CiliumIdentity objects are the cluster-scoped backing store for
// security identities; the allocator normally garbage-collects them
// when the last endpoint using one disappears. When GC leaks (seen
// during agent churn/upgrades), identities accumulate toward the 65k
// identity range exhaustion — new pods then get no identity and lose
// all network policy.
//
// An identity is orphaned when no CiliumEndpoint references its
// numeric ID (status.identity.id) and no pod carries the
// cilium.io/identity annotation with it.
//
// v1 was detect-only because an in-flight endpoint create momentarily
// looks orphaned. v2 makes deletion safe with FOUR stacked gates —
// all must pass before any Delete is issued:
//
//  1. gcEnabled (CILIUM_IDENTITY_GC_ENABLED, default on): clusters
//     can opt the write path out entirely and keep detect-only.
//  2. gracePeriod: the identity must be observed orphaned for >15m —
//     at least two consecutive 15m scan cycles — so a transient gap
//     between pod start and endpoint publication can never look
//     collectible.
//  3. minAge: the identity object itself must be >30m old; a freshly
//     allocated ID whose first endpoint has not landed yet is left
//     alone no matter how long the sweep thinks it has been orphaned.
//  4. Node storm-gate: deletes run ONLY while every node in the
//     cluster is Ready=True. A NotReady node still runs pods whose
//     CiliumEndpoints may be unsynced/gone from the API — collecting
//     "orphans" mid-partition would strip live workloads of their
//     identity and network policy.
//
// Deletes are additionally capped at maxDelete (50) per cycle so a
// pathological mass-orphan event drains gradually instead of one
// burst hammering the apiserver. Each delete bumps
// metrics.CiliumIdentitiesCollectedTotal; orphans above
// ciliumOrphanMax still IncError on the legacy alert path.
package integration

import (
	"context"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
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
	ciliumAuditQueue    = "cilium-identity-auditor"
	ciliumIDAnnotation  = "cilium.io/identity"
	ciliumOrphanMax     = 100 // above this the leak is real, not noise — alert
	ciliumOrphanSamples = 5   // sample names in the warn log

	// ciliumOrphanMinAge: an identity younger than this is never
	// collected, however orphaned it looks — its first endpoint may
	// simply not exist yet.
	ciliumOrphanMinAge = 30 * time.Minute
	// ciliumOrphanGracePeriod: an identity must stay continuously
	// orphaned this long before GC touches it. At the 15m scan
	// interval that means at least two consecutive sweeps saw it
	// orphaned — a single-sweep sighting is never enough.
	ciliumOrphanGracePeriod = 15 * time.Minute
	// ciliumGCMaxDelete caps deletions per sweep: gradual drain beats
	// a burst of cluster-scoped Deletes hammering the apiserver when
	// a mass-orphan event finally converges.
	ciliumGCMaxDelete = 50
)

var (
	ciliumIdentityGVR = schema.GroupVersionResource{
		Group: "cilium.io", Version: "v2", Resource: "ciliumidentities"}
	ciliumEndpointGVR = schema.GroupVersionResource{
		Group: "cilium.io", Version: "v2", Resource: "ciliumendpoints"}
)

type ciliumIdentityAuditor struct {
	cs  kubernetes.Interface
	dyn dynamic.Interface
	// gcEnabled arms the v2 delete path (CILIUM_IDENTITY_GC_ENABLED
	// != "false"); false keeps the module detect-only (v1 behavior).
	gcEnabled bool
	// orphanFirstSeen: identity name → first sweep that saw it
	// orphaned. The gracePeriod gate measures from this stamp, not
	// from object age — an identity must LOOK orphaned across ≥2
	// consecutive sweeps. Pruned when the identity is referenced
	// again or vanishes; a restart re-arms it, biasing conservative.
	orphanFirstSeen map[string]time.Time
	// nowFn is the clock seam — tests pin it so the grace/minAge
	// windows are deterministic.
	nowFn func() time.Time
}

// SetupCiliumIdentityAuditor registers the 15m sweep. Disabled on
// clusters without the cilium component (Calico/cicd — the CRDs do
// not exist there).
func SetupCiliumIdentityAuditor(mgr ctrl.Manager, cs kubernetes.Interface,
	dyn dynamic.Interface, enabled bool) error {
	if !enabled {
		logf.Log.WithName(ciliumAuditQueue).Info("disabled — module not registered")
		return nil
	}
	a := &ciliumIdentityAuditor{
		cs:              cs,
		dyn:             dyn,
		gcEnabled:       os.Getenv("CILIUM_IDENTITY_GC_ENABLED") != "false",
		orphanFirstSeen: map[string]time.Time{},
		nowFn:           time.Now,
	}
	return shared.AddPeriodic(mgr, ciliumAuditQueue, 15*time.Minute, a.run)
}

func (a *ciliumIdentityAuditor) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	// Lazily arm the zero-value struct — unit tests construct the
	// auditor literally without the Setup path.
	if a.nowFn == nil {
		a.nowFn = time.Now
	}
	if a.orphanFirstSeen == nil {
		a.orphanFirstSeen = map[string]time.Time{}
	}
	now := a.nowFn()

	ids, err := a.dyn.Resource(ciliumIdentityGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err // wrapper IncErrors — a returned error must not count itself
	}
	// Keep only name → creationTimestamp: the audit never reads
	// identity bodies beyond the age gate, and dropping the whole
	// UnstructuredList here lets GC reclaim it while the two
	// cluster-wide lists below are still in flight.
	idCreated := make(map[string]time.Time, len(ids.Items))
	for i := range ids.Items {
		idCreated[ids.Items[i].GetName()] = ids.Items[i].GetCreationTimestamp().Time
	}
	ids = nil

	used := map[string]struct{}{}
	eps, err := a.dyn.Resource(ciliumEndpointGVR).Namespace(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return err // wrapper IncErrors — a returned error must not count itself
	}
	for i := range eps.Items {
		if id := endpointIdentityID(&eps.Items[i]); id != "" {
			used[id] = struct{}{}
		}
	}
	eps = nil // used-map extracted — release before the pod list lands

	// Server-side phase filter: terminal pods hold no live endpoints, so
	// they are dead weight in the biggest read this module makes. The
	// in-code phase check stays — fake clientsets ignore field
	// selectors and the belt costs nothing.
	pods, err := a.cs.CoreV1().Pods(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{
			FieldSelector: "status.phase!=Succeeded,status.phase!=Failed",
		})
	if err != nil {
		return err // wrapper IncErrors — a returned error must not count itself
	}
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Status.Phase == corev1.PodSucceeded ||
			p.Status.Phase == corev1.PodFailed {
			continue
		}
		if v := strings.TrimSpace(
			p.Annotations[ciliumIDAnnotation]); v != "" {
			used[v] = struct{}{}
		}
	}
	pods = nil

	// orphanSet doubles as the prune filter: entries whose identity is
	// referenced again (an endpoint/pod reappeared) or whose object
	// vanished entirely drop out of orphanFirstSeen so the map does
	// not grow forever and a re-orphaned identity re-arms the full
	// grace window from scratch.
	orphanSet := map[string]bool{}
	var orphans []string
	for name := range idCreated {
		if _, ok := used[name]; ok {
			continue
		}
		orphanSet[name] = true
		orphans = append(orphans, name)
		if _, ok := a.orphanFirstSeen[name]; !ok {
			a.orphanFirstSeen[name] = now
		}
	}
	for name := range a.orphanFirstSeen {
		if !orphanSet[name] {
			delete(a.orphanFirstSeen, name)
		}
	}

	if len(orphans) == 0 {
		log.Info("sweep done: identities clean", "total", len(idCreated))
		return nil
	}
	sort.Strings(orphans)
	sample := orphans
	if len(sample) > ciliumOrphanSamples {
		sample = sample[:ciliumOrphanSamples]
	}
	if len(orphans) > ciliumOrphanMax {
		// Real leak — surface through the existing alert path.
		metrics.IncError(ciliumAuditQueue)
		log.Info("ORPHANED cilium identities above threshold — identity "+
			"leak, 65k range exhaustion risk",
			"orphans", len(orphans), "total", len(idCreated),
			"threshold", ciliumOrphanMax, "sample", sample,
			"gcEnabled", a.gcEnabled)
	} else {
		log.Info("orphaned cilium identities detected — below threshold",
			"orphans", len(orphans), "total", len(idCreated),
			"sample", sample, "gcEnabled", a.gcEnabled)
	}

	if !a.gcEnabled {
		// Detect-only mode: the orphan ledger above still accrues
		// first-seen stamps, so flipping GC on later does not make
		// long-orphaned identities instantly collectible — they get
		// deleted on the very next sweep, which is the intended
		// behavior (they have been orphaned for days, not seconds).
		return nil
	}
	return a.gcOrphans(ctx, orphans, idCreated, now)
}

// gcOrphans is the v2 delete path: only orphans that satisfy BOTH the
// grace-period (orphaned across ≥2 sweeps) and min-age (object itself
// old enough to have had a fair chance at an endpoint) gates are
// eligible, and even then deletion only proceeds while every node is
// Ready — capped at ciliumGCMaxDelete per sweep.
func (a *ciliumIdentityAuditor) gcOrphans(ctx context.Context,
	orphans []string, idCreated map[string]time.Time, now time.Time) error {
	log := logf.FromContext(ctx)

	var eligible []string
	for _, name := range orphans {
		if now.Sub(a.orphanFirstSeen[name]) < ciliumOrphanGracePeriod {
			continue // first seen this sweep or still inside grace
		}
		if created, ok := idCreated[name]; !ok || now.Sub(created) < ciliumOrphanMinAge {
			continue // too young — endpoint may not exist yet
		}
		eligible = append(eligible, name)
	}
	if len(eligible) == 0 {
		log.Info("GC: no orphans past grace+age gates yet",
			"orphans", len(orphans))
		return nil
	}

	// Storm gate: a NotReady (or absent) node can still be running
	// pods whose CiliumEndpoints are unsynced — deleting "orphans"
	// underneath them strips live workloads of network policy. No
	// nodes at all means the cluster is too broken to judge, so an
	// empty list aborts too rather than vacuously passing "all
	// Ready".
	nodes, err := shared.ListNodes(ctx, a.cs)
	if err != nil {
		return err // propagates to run()'s return — wrapper IncErrors
	}
	if len(nodes) == 0 {
		log.Info("GC SKIP: no nodes listed — cannot verify cluster health",
			"eligible", len(eligible))
		return nil
	}
	for i := range nodes {
		if !shared.NodeReady(&nodes[i]) {
			log.Info("GC SKIP: node not Ready — identities may still be live on it",
				"node", nodes[i].Name, "eligible", len(eligible))
			return nil
		}
	}

	deleted := 0
	for _, name := range eligible {
		if deleted >= ciliumGCMaxDelete {
			log.Info("GC capped — remaining orphans drain next sweep",
				"cap", ciliumGCMaxDelete, "remaining", len(eligible)-deleted)
			break
		}
		log.Info("ACTION: GC orphaned CiliumIdentity",
			"identity", name,
			"orphanedFor", now.Sub(a.orphanFirstSeen[name]).Truncate(time.Minute))
		if err := a.dyn.Resource(ciliumIdentityGVR).
			Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
			if apierrors.IsNotFound(err) {
				continue // raced with cilium's own GC — already gone
			}
			metrics.IncError(ciliumAuditQueue)
			log.Error(err, "identity delete failed", "identity", name)
			continue // per-identity failure must not starve the rest
		}
		metrics.CiliumIdentitiesCollectedTotal.Inc()
		deleted++
	}
	log.Info("GC done", "eligible", len(eligible), "deleted", deleted)
	return nil
}

// endpointIdentityID extracts .status.identity.id — numeric in real
// objects (int64) but float64 in hand-built fixtures.
func endpointIdentityID(ep *unstructured.Unstructured) string {
	if id, found, _ := unstructured.NestedInt64(
		ep.Object, "status", "identity", "id"); found {
		return strconv.FormatInt(id, 10)
	}
	if f, found, _ := unstructured.NestedFloat64(
		ep.Object, "status", "identity", "id"); found {
		return strconv.FormatInt(int64(f), 10)
	}
	return ""
}
