// snapshot_index.go — lazy ns/name indexes over the sweep's typed
// workload censuses: point lookups ("the pod's controller workload",
// the ownership joins the linkerd heal walks per violating pod) used
// to linear-scan the whole memoized census slice per call —
// O(census) per lookup, repeated for every offending pod. The index
// builds the ns/name → object map on the FIRST lookup for its census
// and stays for the rest of the sweep, memoized alongside the census
// like the lease/service joins: it drops WITH its census via the
// snapshot's resets list (a mid-sweep invalidation rebuilds both),
// and outside a sweep — empty snapshot per call — it costs one build
// per call, the pre-snapshot semantics of a fresh GET-per-call read.
//
// The returned pointers alias the census structs; snapshot payloads
// are read-only like every other memoized view.
package probefw

import (
	"context"
	"sync"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// censusIndex is one census's lazy ns/name map. The sweep drives its
// checks serially, but check bodies fan out into worker pools — the
// mutex covers the build-once race the same way memo does.
type censusIndex[T any] struct {
	mu     sync.Mutex
	byKey  map[types.NamespacedName]*T
	loaded bool
}

// reset returns the index to its never-built state — the resets-list
// twin of memo.reset; a census invalidation drops the index so the
// next lookup rebuilds from the fresh census.
func (ix *censusIndex[T]) reset() {
	ix.mu.Lock()
	ix.byKey, ix.loaded = nil, false
	ix.mu.Unlock()
}

// lookup returns the named object, building the index from the
// census on first call. The census error propagates (memoized like
// every snapshot read — every later caller in the sweep reads the
// same failure instead of re-LISTing). PT is the census element's
// pointer type — the ObjectMeta accessors hang off that.
func indexLookup[T any, PT interface {
	*T
	metav1.Object
}](ix *censusIndex[T], load func() ([]T, error),
	ns, name string) (*T, error) {

	ix.mu.Lock()
	defer ix.mu.Unlock()
	if !ix.loaded {
		items, err := load()
		if err != nil {
			return nil, err
		}
		m := make(map[types.NamespacedName]*T, len(items))
		for i := range items {
			p := PT(&items[i])
			m[types.NamespacedName{
				Namespace: p.GetNamespace(),
				Name:      p.GetName(),
			}] = &items[i]
		}
		ix.byKey, ix.loaded = m, true
	}
	return ix.byKey[types.NamespacedName{Namespace: ns, Name: name}], nil
}

// deployment resolves one Deployment from the shared census — the
// snapshot equivalent of Deployments(ns).Get(name): a hit returns the
// listed object, a miss returns nil (callers treat absent the same
// as a NotFound GET). List errors propagate.
func (d *Deps) Deployment(ctx context.Context,
	ns, name string) (*appsv1.Deployment, error) {

	s := sweepSnap(ctx)
	return indexLookup(&s.deploymentsIdx,
		func() ([]appsv1.Deployment, error) { return d.AllDeployments(ctx) },
		ns, name)
}

// StatefulSet is Deployment's statefulset twin.
func (d *Deps) StatefulSet(ctx context.Context,
	ns, name string) (*appsv1.StatefulSet, error) {

	s := sweepSnap(ctx)
	return indexLookup(&s.statefulSetsIdx,
		func() ([]appsv1.StatefulSet, error) { return d.AllStatefulSets(ctx) },
		ns, name)
}

// DaemonSet is Deployment's daemonset twin.
func (d *Deps) DaemonSet(ctx context.Context,
	ns, name string) (*appsv1.DaemonSet, error) {

	s := sweepSnap(ctx)
	return indexLookup(&s.daemonSetsIdx,
		func() ([]appsv1.DaemonSet, error) { return d.AllDaemonSets(ctx) },
		ns, name)
}

// ReplicaSet is the metadata-only twin — the ownership join reads
// ObjectMeta only, so the index rides AllReplicaSets'
// ListPartialOrFallback census.
func (d *Deps) ReplicaSet(ctx context.Context,
	ns, name string) (*metav1.PartialObjectMetadata, error) {

	s := sweepSnap(ctx)
	return indexLookup(&s.replicaSetsIdx,
		func() ([]metav1.PartialObjectMetadata, error) {
			return d.AllReplicaSets(ctx)
		}, ns, name)
}

// CronJob is Deployment's cronjob twin.
func (d *Deps) CronJob(ctx context.Context,
	ns, name string) (*batchv1.CronJob, error) {

	s := sweepSnap(ctx)
	return indexLookup(&s.cronJobsIdx,
		func() ([]batchv1.CronJob, error) { return d.AllCronJobs(ctx) },
		ns, name)
}

// Job is Deployment's job twin.
func (d *Deps) Job(ctx context.Context, ns, name string) (*batchv1.Job, error) {
	s := sweepSnap(ctx)
	return indexLookup(&s.jobsIdx,
		func() ([]batchv1.Job, error) { return d.AllJobs(ctx) },
		ns, name)
}

// ---------------------------------------------------------------------------
// Pod placement + EndpointSlice service indexes
// ---------------------------------------------------------------------------

// elemSliceSame is the generic twin of podSliceSame for non-pod
// censuses: two slices share one backing array iff their first
// elements alias — the memoized census hands back the same slice
// header every read, so this is the exact "same census" test.
func elemSliceSame[T any](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	return &a[0] == &b[0]
}

// podPlacementIndex lazily indexes the tombstone-FILTERED pod census
// two ways — namespace → pods (PodsIn) and spec.nodeName → pods
// (PodsOnNode) — so repeat lookups in one sweep stop re-scanning the
// whole census per call. It self-validates on every lookup against
// (podTombstoneGen, filtered-census identity): a MarkPodDeleted bump
// or an InvalidatePods refetch changes the key and the next call
// rebuilds, so the index needs no resets-list entry — the same
// identity-keyed laziness podCensusView/podNodeView already use.
// Elements alias the snapshot's pod structs — read-only like every
// other census payload.
type podPlacementIndex struct {
	mu     sync.Mutex
	gen    uint64
	src    []corev1.Pod
	byNS   map[string][]*corev1.Pod
	byNode map[string][]*corev1.Pod
	built  bool
}

// lookup returns the (byNS, byNode) pair for pods — the filtered
// census slice AllPods hands out. Both maps are built together:
// they share one pass and one validity key.
func (ix *podPlacementIndex) lookup(ctx context.Context,
	pods []corev1.Pod) (map[string][]*corev1.Pod, map[string][]*corev1.Pod) {

	gen := kube.PodTombstoneGen(ctx)
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if ix.built && ix.gen == gen && podSliceSame(ix.src, pods) {
		return ix.byNS, ix.byNode
	}
	byNS := make(map[string][]*corev1.Pod)
	byNode := make(map[string][]*corev1.Pod)
	for i := range pods {
		p := &pods[i]
		byNS[p.Namespace] = append(byNS[p.Namespace], p)
		byNode[p.Spec.NodeName] = append(byNode[p.Spec.NodeName], p)
	}
	ix.gen, ix.src, ix.byNS, ix.byNode, ix.built =
		gen, pods, byNS, byNode, true
	return byNS, byNode
}

// sliceServiceIndex lazily indexes the EndpointSlice census by its
// kubernetes.io/service-name binding (ns + label → slices) — the
// per-service join EndpointSlicesForService resolves without a
// cluster-wide rescan per call. Self-validating on census slice
// identity like podPlacementIndex (a slice delete invalidates the
// memo → new backing array → rebuild), so it needs no resets entry.
type sliceServiceIndex struct {
	mu    sync.Mutex
	src   []discoveryv1.EndpointSlice
	byKey map[types.NamespacedName][]*discoveryv1.EndpointSlice
	built bool
}

func (ix *sliceServiceIndex) lookup(
	slices []discoveryv1.EndpointSlice) map[types.NamespacedName][]*discoveryv1.EndpointSlice {

	ix.mu.Lock()
	defer ix.mu.Unlock()
	if ix.built && elemSliceSame(ix.src, slices) {
		return ix.byKey
	}
	m := make(map[types.NamespacedName][]*discoveryv1.EndpointSlice)
	for i := range slices {
		s := &slices[i]
		name := s.Labels[discoveryv1.LabelServiceName]
		if name == "" {
			continue
		}
		k := types.NamespacedName{Namespace: s.Namespace, Name: name}
		m[k] = append(m[k], s)
	}
	ix.src, ix.byKey, ix.built = slices, m, true
	return m
}
