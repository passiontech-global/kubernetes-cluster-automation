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
// numeric ID (status.identity.id), no CiliumEndpointSlice endpoint
// records it (.spec.endpoints[].identity.id — on CES-enabled clusters
// the agent stops writing CEPs entirely, so without the CES read
// every live identity would read orphaned), and no pod carries the
// cilium.io/identity annotation with it. Reserved-range identities
// (numeric name <=255, or a `reserved:` security label) are skipped
// before orphan accounting — upstream GC exempts them too. A failed
// usage-source list (CEP, CES, or pods) aborts the sweep: usage is
// indeterminate, so nothing is flagged or collected on partial data.
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
package ciliumidentityauditor

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

const (
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
	// ciliumListPageSize caps each cluster-wide List response — the
	// all-namespaces pod read is the biggest this module makes.
	ciliumListPageSize = 500
	// ciliumReservedIDMax is the top of Cilium's reserved identity
	// range (1–255: host, world, health, ingress, ...) — upstream GC
	// exempts it, so orphan accounting must too.
	ciliumReservedIDMax = 255
)

var (
	ciliumIdentityGVR = shared.GVRCiliumIdentity
	ciliumEndpointGVR = shared.GVRCiliumEndpoint
	// ciliumEndpointSliceGVR is the v2alpha1 CiliumEndpointSlice —
	// on CES-enabled clusters the agent stops writing CiliumEndpoints
	// entirely and records identity usage here instead.
	ciliumEndpointSliceGVR = shared.GVRCiliumEndpointSlice
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
	orphanFirstSeen shared.FirstSeenLedger
	// now is the clock seam — tests pin it so the grace/minAge
	// windows are deterministic.
	now shared.Clock
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name, the registration log and
	// every IncError label come from one place.
	queue string
}

// Setup registers the 15m sweep. Disabled on
// clusters without the cilium component (Calico/cicd — the CRDs do
// not exist there; CILIUM_IDENTITY_AUDITOR_ENABLED is opt-in and
// resolved by setupModules into Deps.Disabled).
func Setup(d shared.Deps) error {
	return shared.SetupWithConfig(d, gcEnabledFromEnv, func(gcEnabled bool) error {
		a := &ciliumIdentityAuditor{
			cs:        d.CS,
			dyn:       d.Dyn,
			gcEnabled: gcEnabled,
			now:       shared.SystemClock,
			queue:     d.Name,
		}
		logf.Log.WithName(a.queue).Info("registered", "gcEnabled", a.gcEnabled)
		return shared.AddPeriodic(d.Mgr, a.queue, 15*time.Minute, a.run)
	})
}

// gcEnabledFromEnv resolves the GC sub-feature gate. SetupWithConfig
// runs it before the Deps.Disabled check — see corednspatcher: an
// unparseable CILIUM_IDENTITY_GC_ENABLED must warn even on a
// gated-off cluster.
func gcEnabledFromEnv() bool {
	return shared.Gate("CILIUM_IDENTITY_GC_ENABLED", true)
}

func (a *ciliumIdentityAuditor) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	now := a.now.Now()

	ids, err := shared.ListAll(ctx,
		metav1.ListOptions{Limit: ciliumListPageSize},
		shared.DynamicPage(a.dyn.Resource(ciliumIdentityGVR)))
	if err != nil {
		return fmt.Errorf("list ciliumidentities: %w", err) // wrapper IncErrors — a returned error must not count itself
	}
	// Keep only name → (creationTimestamp, UID): the audit never
	// reads identity bodies beyond the age gate and the delete
	// precondition, and dropping the whole UnstructuredList here lets
	// GC reclaim it while the two cluster-wide lists below are still
	// in flight. Reserved-range identities (1–255, or a `reserved:`
	// security label) are skipped outright — upstream GC exempts
	// them, so they are neither orphans nor collectible.
	idCreated := make(map[string]time.Time, len(ids))
	idUIDs := make(map[string]types.UID, len(ids))
	for i := range ids {
		id := &ids[i]
		if reservedIdentity(id) {
			continue
		}
		idCreated[id.GetName()] = id.GetCreationTimestamp().Time
		idUIDs[id.GetName()] = id.GetUID()
	}
	ids = nil

	used := map[string]struct{}{}
	eps, err := shared.ListAll(ctx,
		metav1.ListOptions{Limit: ciliumListPageSize},
		shared.DynamicPage(a.dyn.Resource(ciliumEndpointGVR).Namespace(metav1.NamespaceAll)))
	if err != nil {
		return fmt.Errorf("list ciliumendpoints: %w", err) // wrapper IncErrors — a returned error must not count itself
	}
	for i := range eps {
		if id := endpointIdentityID(&eps[i]); id != "" {
			used[id] = struct{}{}
		}
	}
	eps = nil // used-map extracted — release before the next lists land

	// CiliumEndpointSlice is the SECOND identity-usage source: on
	// CES-enabled clusters the agent stops writing CiliumEndpoints
	// and records usage in .spec.endpoints[].identity.id instead —
	// without this read every live identity would read orphaned and
	// the GC path would reap them. A missing CRD means the cluster
	// simply does not run CES (fine); any other failure makes usage
	// indeterminate — fail closed like the CEP/pod lists (a returned
	// error aborts the run, so the GC path below is never reached on
	// partial data).
	slices, err := shared.ListAll(ctx,
		metav1.ListOptions{Limit: ciliumListPageSize},
		shared.DynamicPage(a.dyn.Resource(ciliumEndpointSliceGVR).
			Namespace(metav1.NamespaceAll)))
	switch {
	case err == nil:
		for i := range slices {
			for _, id := range sliceIdentityIDs(&slices[i]) {
				used[id] = struct{}{}
			}
		}
		slices = nil
	case apierrors.IsNotFound(err):
		// CES CRD absent — CEP-only cluster, nothing to merge.
	default:
		return fmt.Errorf("list ciliumendpointslices: %w", err) // wrapper IncErrors — a returned error must not count itself
	}

	// Server-side phase filter + continue-token pagination: terminal
	// pods hold no live endpoints, and the all-namespaces pod read is
	// the biggest this module makes — page it at ciliumListPageSize so
	// no single response dominates. The in-code phase check stays —
	// fake clientsets ignore field selectors and the belt costs
	// nothing.
	podOpts := metav1.ListOptions{
		FieldSelector: "status.phase!=Succeeded,status.phase!=Failed",
		Limit:         ciliumListPageSize,
	}
	err = shared.ListEach(ctx, podOpts, shared.Pods(a.cs, metav1.NamespaceAll),
		func(items []corev1.Pod) error {
			for i := range items {
				p := &items[i]
				if p.Status.Phase == corev1.PodSucceeded ||
					p.Status.Phase == corev1.PodFailed {
					continue
				}
				if v := strings.TrimSpace(
					p.Annotations[ciliumIDAnnotation]); v != "" {
					used[v] = struct{}{}
				}
			}
			return nil
		})
	if err != nil {
		return fmt.Errorf("list pods: %w", err) // wrapper IncErrors — a returned error must not count itself
	}

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
		a.orphanFirstSeen.Observe(name, now)
	}
	a.orphanFirstSeen.Prune(func(name string) bool { return orphanSet[name] })

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
		metrics.IncError(a.queue)
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
	return a.gcOrphans(ctx, orphans, idCreated, idUIDs, now)
}

// gcOrphans is the v2 delete path: only orphans that satisfy BOTH the
// grace-period (orphaned across ≥2 sweeps) and min-age (object itself
// old enough to have had a fair chance at an endpoint) gates are
// eligible, and even then deletion only proceeds while every node is
// Ready — capped at ciliumGCMaxDelete per sweep.
func (a *ciliumIdentityAuditor) gcOrphans(ctx context.Context,
	orphans []string, idCreated map[string]time.Time,
	idUIDs map[string]types.UID, now time.Time) error {
	log := logf.FromContext(ctx)

	var eligible []string
	for _, name := range orphans {
		orphanedFor, _ := a.orphanFirstSeen.Seen(name, now)
		if orphanedFor < ciliumOrphanGracePeriod {
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
		return fmt.Errorf("list nodes: %w", err) // propagates to run()'s return — wrapper IncErrors
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
		orphanedFor, _ := a.orphanFirstSeen.Seen(name, now)
		log.Info("ACTION: GC orphaned CiliumIdentity",
			"identity", name,
			"orphanedFor", orphanedFor.Truncate(time.Minute))
		// UID precondition closes the list→delete TOCTOU: a same-named
		// identity recreated between the List above and this Delete is
		// not the orphan this sweep vetted — the apiserver rejects the
		// delete with a Conflict, skipped like the NotFound race below.
		uid := idUIDs[name]
		if err := a.dyn.Resource(ciliumIdentityGVR).
			Delete(ctx, name, shared.UIDDeleteOptions(uid, "")); err != nil {
			switch {
			case apierrors.IsNotFound(err):
				log.Info("SKIP: identity already gone — raced with cilium's own GC",
					"identity", name)
				continue
			case apierrors.IsConflict(err):
				log.Info("SKIP: identity recreated since the list — UID precondition fired",
					"identity", name)
				continue
			}
			metrics.IncError(a.queue)
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
	if id, ok := shared.NestedInt64(
		ep.Object, "status", "identity", "id"); ok {
		return strconv.FormatInt(id, 10)
	}
	if f, ok := shared.NestedFloat64(
		ep.Object, "status", "identity", "id"); ok {
		return strconv.FormatInt(int64(f), 10)
	}
	return ""
}

// sliceIdentityIDs extracts every endpoint's identity id from a
// CiliumEndpointSlice's .spec.endpoints[].identity.id — the CES
// replacement for the CEP's .status.identity.id. Non-numeric entries
// are skipped like the CEP path does.
func sliceIdentityIDs(ces *unstructured.Unstructured) []string {
	endpoints, _ := shared.NestedSlice(
		ces.Object, "spec", "endpoints")
	out := make([]string, 0, len(endpoints))
	for _, e := range endpoints {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if id, ok := shared.NestedInt64(
			m, "identity", "id"); ok {
			out = append(out, strconv.FormatInt(id, 10))
			continue
		}
		if f, ok := shared.NestedFloat64(
			m, "identity", "id"); ok {
			out = append(out, strconv.FormatInt(int64(f), 10))
		}
	}
	return out
}

// reservedIdentity exempts Cilium's reserved identity range from
// orphan accounting: a numeric name <= ciliumReservedIDMax (upstream
// GC never reaps 1–255) or a security label carrying the `reserved:`
// prefix (reserved:host, reserved:world, ... — checked in both
// metadata.labels, where Cilium actually stores identity labels, and
// .spec.security-labels for shape tolerance).
func reservedIdentity(id *unstructured.Unstructured) bool {
	if n, err := strconv.ParseInt(id.GetName(), 10, 64); err == nil &&
		n <= ciliumReservedIDMax {
		return true
	}
	for k := range id.GetLabels() {
		if strings.HasPrefix(k, "reserved:") {
			return true
		}
	}
	secLabels, _, _ := unstructured.NestedStringMap(
		id.Object, "spec", "security-labels")
	for k := range secLabels {
		if strings.HasPrefix(k, "reserved:") {
			return true
		}
	}
	return false
}
