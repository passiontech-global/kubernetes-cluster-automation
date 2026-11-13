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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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
