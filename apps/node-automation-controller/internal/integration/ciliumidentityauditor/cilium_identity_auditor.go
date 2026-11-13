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
//
// The sweep also exports node_automation_cilium_active_identities —
// the total identity-table occupancy from the same list the orphan
// audit already makes. Past ciliumActiveIdentityWarn the count alone
// does not say WHY the table is full, so the sweep profiles
// .spec.security-labels across the identities and logs the top-3
// label keys by distinct-value cardinality: each unique label SET
// mints an identity, so the high-cardinality key is the workload
// attribute inflating the eBPF identity table.
//
// File layout: this file holds the module contract, the auditor struct,
// Setup and the run sweep pipeline; cilium_identity_gc.go the v2 GC
// delete path, cilium_identity_usage.go the CEP/CES usage extraction
// and reserved-range exemption, cilium_identity_labels.go the
// security-label cardinality profiling.
package ciliumidentityauditor

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
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
	// ciliumReservedIDMax is the top of Cilium's reserved identity
	// range (1–255: host, world, health, ingress, ...) — upstream GC
	// exempts it, so orphan accounting must too.
	ciliumReservedIDMax = 255
	// ciliumActiveIdentityWarn — total CiliumIdentity objects past
	// which the table-occupancy count alone is not enough signal:
	// the sweep then profiles security-label cardinality and names
	// the keys inflating the table (65k range exhaustion risk).
	ciliumActiveIdentityWarn = 10000
)

var (
	ciliumIdentityGVR = kube.GVRCiliumIdentity
	ciliumEndpointGVR = kube.GVRCiliumEndpoint
	// ciliumEndpointSliceGVR is the v2alpha1 CiliumEndpointSlice —
	// on CES-enabled clusters the agent stops writing CiliumEndpoints
	// entirely and records identity usage here instead.
	ciliumEndpointSliceGVR = kube.GVRCiliumEndpointSlice
)

type ciliumIdentityAuditor struct {
	cs         kubernetes.Interface
	nodeReader kube.CachedNodeReader
	dyn        dynamic.Interface
	// gcEnabled arms the v2 delete path (CILIUM_IDENTITY_GC_ENABLED
	// != "false"); false keeps the module detect-only (v1 behavior).
	gcEnabled bool
	// orphanFirstSeen: identity name → first sweep that saw it
	// orphaned. The gracePeriod gate measures from this stamp, not
	// from object age — an identity must LOOK orphaned across ≥2
	// consecutive sweeps. Pruned when the identity is referenced
	// again or vanishes; a restart re-arms it, biasing conservative.
	orphanFirstSeen state.FirstSeenLedger
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
			cs:         d.CS,
			nodeReader: d.CachedClient(),
			dyn:        d.Dyn,
			gcEnabled:  gcEnabled,
			now:        shared.SystemClock,
			queue:      d.Name,
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
	return envx.Gate("CILIUM_IDENTITY_GC_ENABLED", true)
}

func (a *ciliumIdentityAuditor) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	now := a.now.Now()

	ids, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.DynamicPage(a.dyn.Resource(ciliumIdentityGVR)))
	if err != nil {
		return fmt.Errorf("list ciliumidentities: %w", err) // wrapper IncErrors — a returned error must not count itself
	}
	// Table occupancy gauge — the last-successful-list reading
	// stays when a list fails (a failed sweep returns before this
	// point, so the series mirrors real observed state, never a
	// fabricated zero). Past the warn threshold the count alone is
	// insufficient signal — profile security-label cardinality and
	// name the keys minting identities (each distinct label SET is
	// one identity; the top keys are the workload attributes
	// inflating the table).
	totalIDs := len(ids)
	metrics.CiliumActiveIdentities.Set(float64(totalIDs))
	if totalIDs > ciliumActiveIdentityWarn {
		log.Info("CiliumIdentity count above warn threshold — top "+
			"security-label keys by distinct values",
			"total", totalIDs, "threshold", ciliumActiveIdentityWarn,
			"topLabelKeys", topSecurityLabelKeys(ids, 3))
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

	// Pods FIRST, CEP/CES after — the TOCTOU order matters: cilium-
	// agent writes CiliumEndpoints/CiliumEndpointSlices
	// asynchronously AFTER pod creation, so a pod that exists at
	// pod-list time may not have its endpoint object yet. Listing
	// pods first captures the freshest pod set, and the endpoint
	// lists that follow still see endpoints materialized during
	// the pod read — an identity referenced by either side of the
	// window stays "used". The reverse order leaves a gap where a
	// new pod's endpoint exists in neither snapshot and its live
	// identity reads orphaned.
	//
	// Server-side phase filter + continue-token pagination:
	// terminal pods hold no live endpoints, and the all-namespaces
	// pod read is the biggest this module makes — page it at the
	// shared bound so no single response dominates. The in-code
	// phase check stays — fake clientsets ignore field selectors
	// and the belt costs nothing.
	podOpts := metav1.ListOptions{
		FieldSelector: "status.phase!=Succeeded,status.phase!=Failed",
		Limit:         kube.DefaultListPageSize,
	}
	err = kube.ListEach(ctx, podOpts, kube.Pods(a.cs, metav1.NamespaceAll),
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

	// CiliumEndpoints are the FIRST API-side usage source. Streamed
	// pages: only the identity-ID strings survive into the used set —
	// CEP bodies (per-endpoint networking state, the fattest objects
	// this sweep reads) die with their page instead of materializing
	// as one cluster-wide unstructured slice. The spec-path read keeps
	// the list full-object; metadata lists cannot see
	// .spec.endpoints[].identity-id.
	err = kube.ListEach(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.DynamicPage(a.dyn.Resource(ciliumEndpointGVR).Namespace(metav1.NamespaceAll)),
		func(page []unstructured.Unstructured) error {
			for i := range page {
				if id := endpointIdentityID(&page[i]); id != "" {
					used[id] = struct{}{}
				}
			}
			return nil
		})
	if err != nil {
		return fmt.Errorf("list ciliumendpoints: %w", err) // wrapper IncErrors — a returned error must not count itself
	}

	// CiliumEndpointSlice is the SECOND identity-usage source: on
	// CES-enabled clusters the agent stops writing CiliumEndpoints
	// and records usage in .spec.endpoints[].identity.id instead —
	// without this read every live identity would read orphaned and
	// the GC path would reap them. A missing CRD means the cluster
	// simply does not run CES (fine); any other failure makes usage
	// indeterminate — fail closed like the CEP/pod lists (a returned
	// error aborts the run, so the GC path below is never reached on
	// partial data). Streamed pages like the CEP read above.
	err = kube.ListEach(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.DynamicPage(a.dyn.Resource(ciliumEndpointSliceGVR).
			Namespace(metav1.NamespaceAll)),
		func(page []unstructured.Unstructured) error {
			for i := range page {
				for _, id := range sliceIdentityIDs(&page[i]) {
					used[id] = struct{}{}
				}
			}
			return nil
		})
	switch {
	case err == nil:
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		// CES CRD absent or API version not served — CEP-only
		// cluster, nothing to merge.
	default:
		return fmt.Errorf("list ciliumendpointslices: %w", err) // wrapper IncErrors — a returned error must not count itself
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
	slices.Sort(orphans)
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
