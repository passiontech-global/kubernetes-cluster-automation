// sweep_overlay.go — the per-sweep write overlay: the read-modify
// answer to "a check patched/deleted something mid-sweep but the
// shared snapshot still holds the pre-mutation copy".
//
// The sweep snapshot (probefw.sweepSnapshot) memoizes cluster-wide
// LISTs for the whole run() cycle and its contract is READ-ONLY:
// callers must not mutate returned objects. Before this overlay
// existed, ~a dozen heal paths broke that contract anyway —
// heal.syncFirstSeenAnno, probefw.MergeAnnoPatchLocally and friends
// applied a landed annotation merge-patch to the LISTED object in
// place so the next check in the same sweep would read the new
// value. That in-place write is a data race the moment two checks
// run concurrently (the sweep fans checks out over a worker pool)
// AND it corrupts the memoized census for every later reader: the
// "fixed" object no longer matches what the apiserver holds, and a
// second writer computing its patch from the mutated map can
// resurrect keys a sibling just cleared.
//
// SweepOverlay replaces the in-place mirror with a per-sweep delta:
// writers RECORD the patch (never touching the shared object), and
// readers consult EffectiveAnno for the keys they own. The overlay
// lives on the sweep ctx — probefw.WithSweepSnapshot installs one
// alongside the census memoizer — so it expires structurally with
// the sweep: no TTL, no cross-cycle staleness, and a fresh empty
// overlay for every ad-hoc Run outside a sweep (same nil-posture
// the snapshot itself takes).
//
// Three delta kinds:
//
//   - annos:        per-object annotation patches keyed by
//     overlayObjKey (UID, else ns/name) —
//     EffectiveAnno resolves base-map-then-overlay.
//   - tombstones:   pod UIDs deleted this sweep — IsPodDeleted /
//     FilterPodTombstones hide them from every later
//     census read WITHOUT invalidating the pod memo
//     (the O(1) replacement for InvalidatePods storms:
//     N deletes in one sweep used to cost N cluster-
//     wide re-LISTs).
//   - ownerDisrupt: per-workload disruption reservations —
//     TryReserveWorkloadDisruption lets parallel
//     checks share one "this workload already lost a
//     pod this sweep" slot so two checks cannot each
//     delete a pod of the same 2-replica Deployment
//     and take it to zero.
//
// Outside a sweep (no overlay on ctx) every helper degrades to the
// pre-overlay behavior: EffectiveAnno reads the object's own map,
// RecordAnnoPatch/MarkPodDeleted/TryReserveWorkloadDisruption are
// no-ops returning the permissive answer — a direct-Run check still
// sees fresh-per-call semantics and never blocks on bookkeeping.
package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// sweepOverlayCtxKey is the context key WithSweepOverlay installs
// the per-sweep overlay under. Unexported like probefw's
// sweepCtxKey: the sweep attaches it once and readers resolve it,
// so no other package can inject one.
type sweepOverlayCtxKey struct{}

// SweepOverlay is the per-sweep delta store described in the file
// header. All fields are guarded by one RWMutex: writers take the
// write lock briefly (patch recording, tombstone marking,
// reservation), readers take the read lock per lookup — the checks
// fan out over a worker pool so concurrent access is the norm, not
// the exception.
type SweepOverlay struct {
	mu sync.RWMutex
	// annos maps object UID -> annotation key -> effective value;
	// a nil *string records a deletion (the merge patch's null).
	annos map[types.UID]map[string]*string
	// tombstones is the set of pod UIDs deleted this sweep.
	tombstones map[types.UID]struct{}
	// podTombstoneGen counts MarkPodDeleted calls — the generation
	// the sweep snapshot keys its filtered pod views on: a bump
	// means "the tombstone set changed, rebuild the filtered
	// census/map once", and between bumps every check shares the
	// ONE cached view instead of re-copying the census per call.
	podTombstoneGen uint64
	// ownerDisrupt is the set of "<ns>/<kind>/<name>" workload
	// identities that already spent their one-disruption slot this
	// sweep. Presence IS the reservation — the overlay dies with
	// the sweep, so no expiry is needed (a mid-sweep TTL could only
	// ever fire on a >10-minute sweep, where re-allowing a second
	// disruption is exactly the quorum breach the slot exists to
	// prevent).
	ownerDisrupt map[string]struct{}
	// tmplAnnos maps object UID -> pod-template annotation key ->
	// value (nil = delete) — the spec.template.metadata.annotations
	// twin of annos. The linkerd opaque-ports heal mirrors its
	// landed template patch here instead of writing the shared
	// census object in place (the same race annos exists to kill,
	// one JSON path deeper).
	tmplAnnos map[types.UID]map[string]*string
}

// WithSweepOverlay installs a fresh, empty overlay on ctx. The
// sweep root reaches it through probefw.WithSweepSnapshot; callers
// outside a sweep never need it (helpers degrade gracefully).
func WithSweepOverlay(ctx context.Context) context.Context {
	return context.WithValue(ctx, sweepOverlayCtxKey{}, &SweepOverlay{
		annos:        map[types.UID]map[string]*string{},
		tombstones:   map[types.UID]struct{}{},
		ownerDisrupt: map[string]struct{}{},
		tmplAnnos:    map[types.UID]map[string]*string{},
	})
}

// sweepOverlay resolves the ctx-carried overlay, or nil outside a
// sweep — every public helper branches on this so the no-overlay
// path costs one ctx lookup and nothing else.
func sweepOverlay(ctx context.Context) *SweepOverlay {
	if ov, ok := ctx.Value(sweepOverlayCtxKey{}).(*SweepOverlay); ok {
		return ov
	}
	return nil
}

// overlayObjKey is the delta-map key for obj: its UID when the
// apiserver assigned one (a recreated same-name object gets a fresh
// UID and correctly misses the old incarnation's deltas), else a
// "<kind>/<ns>/<name>" synthetic key — test fixtures and UID-less
// objects still get overlay semantics instead of silently degrading
// to the in-place mirror on shared census copies. The kind
// qualifier keeps a Deployment "apps/web" from colliding with a
// Service "apps/web" (typed objects carry no GVK, so %T stands in;
// unstructured objects report their real Kind). Safe as a
// types.UID: real UIDs are UUIDs and can never contain '/'.
func overlayObjKey(obj metav1.Object) types.UID {
	if uid := obj.GetUID(); uid != "" {
		return uid
	}
	kind := ""
	if ro, ok := obj.(runtime.Object); ok {
		kind = ro.GetObjectKind().GroupVersionKind().Kind
	}
	if kind == "" {
		// Typed fixtures carry no TypeMeta — %T would yield
		// "*v1.Pod"; normalize to the bare type name so the
		// synthetic key reads like the Kind a real object reports
		// ("Pod"), keeping UID-less test objects from colliding
		// across packages that happen to share a type name.
		t := reflect.TypeOf(obj)
		for t != nil && t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		if t != nil {
			kind = t.Name()
		}
	}
	if kind == "" {
		kind = fmt.Sprintf("%T", obj)
	}
	return types.UID(kind + "/" + obj.GetNamespace() + "/" + obj.GetName())
}

// EffectiveAnno returns the effective value of one annotation on
// obj: the sweep overlay's recorded patch wins over the object's
// own map (a recorded null reads as ""), and an unpatched key — or
// no overlay at all — falls through to obj.GetAnnotations()[key].
//
// Readers MUST use this for any annotation key a heal path can
// patch mid-sweep (the passiontech.dev/first-seen-* family, the
// last-heal stamps): the object's own map is the PRE-patch snapshot
// copy and stays that way for the rest of the sweep.
func EffectiveAnno(ctx context.Context, obj metav1.Object, key string) string {
	if obj == nil {
		return ""
	}
	ov := sweepOverlay(ctx)
	if ov != nil {
		ov.mu.RLock()
		if m, ok := ov.annos[overlayObjKey(obj)]; ok {
			if v, ok := m[key]; ok {
				ov.mu.RUnlock()
				if v == nil {
					return ""
				}
				return *v
			}
		}
		ov.mu.RUnlock()
	}
	return obj.GetAnnotations()[key]
}

// RecordAnnoPatch records a landed metadata.annotations merge patch
// against obj — the write-side twin of EffectiveAnno. The patch
// shape is MergePatchAnnos output:
// {"metadata":{"annotations":{"k":"v"|null}}}. Each key lands in
// the overlay as *string (nil = deleted).
//
// Two postures by context:
//
//   - Inside a sweep (overlay on ctx): record ONLY — the shared
//     snapshot object is NEVER mutated. That in-place mirror was
//     the data race this overlay exists to remove: two parallel
//     checks writing sibling keys of one object's annotation map,
//     or a stale pre-patch read resurrecting a cleared key.
//   - Outside a sweep (no overlay): the object is caller-private —
//     a per-call GET or test fixture no other goroutine shares —
//     so the legacy in-place mirror still applies: same-run re-reads
//     see the landed patch exactly as they always have.
//
// Malformed payloads are ignored — the input is always
// MergePatchAnnos output, so a parse failure means a caller bug,
// and silently skipping keeps a bad patch from poisoning either
// store.
func RecordAnnoPatch(ctx context.Context, obj metav1.Object, patchBytes []byte) {
	if obj == nil {
		return
	}
	var doc struct {
		Metadata struct {
			Annotations map[string]*string `json:"annotations"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(patchBytes, &doc); err != nil {
		return
	}
	if len(doc.Metadata.Annotations) == 0 {
		return
	}
	ov := sweepOverlay(ctx)
	if ov == nil {
		// No overlay: caller-private object — keep the legacy
		// in-place mirror.
		annos := obj.GetAnnotations()
		if annos == nil {
			annos = map[string]string{}
		}
		for k, v := range doc.Metadata.Annotations {
			if v == nil {
				delete(annos, k)
			} else {
				annos[k] = *v
			}
		}
		obj.SetAnnotations(annos)
		return
	}
	ov.mu.Lock()
	defer ov.mu.Unlock()
	k := overlayObjKey(obj)
	m := ov.annos[k]
	if m == nil {
		m = map[string]*string{}
		ov.annos[k] = m
	}
	for k, v := range doc.Metadata.Annotations {
		m[k] = v
	}
}

// RecordTemplateAnnos records a landed pod-template annotation
// merge against obj — the write-side twin of EffectiveTemplateAnnos
// for keys living at spec.template.metadata.annotations (or the
// jobTemplate twin for CronJobs), which RecordAnnoPatch's
// metadata.annotations path cannot express. Returns false when no
// sweep overlay is on ctx — the caller then keeps the legacy
// in-place mirror on its caller-private object (direct GETs outside
// a sweep share nothing).
func RecordTemplateAnnos(ctx context.Context, obj metav1.Object,
	anno map[string]string) bool {

	ov := sweepOverlay(ctx)
	if ov == nil || obj == nil || len(anno) == 0 {
		return false
	}
	ov.mu.Lock()
	defer ov.mu.Unlock()
	k := overlayObjKey(obj)
	m := ov.tmplAnnos[k]
	if m == nil {
		m = map[string]*string{}
		ov.tmplAnnos[k] = m
	}
	for k, v := range anno {
		s := v
		m[k] = &s
	}
	return true
}

// EffectiveTemplateAnnos resolves the pod-template annotation view
// for obj: base (the census copy's own map — PRE-patch for the rest
// of the sweep) merged under this sweep's recorded deltas. Returns
// base UNCHANGED — no allocation — when nothing was recorded for the
// UID; a recorded delta produces a fresh merged map callers must
// treat as read-only (writes to it reach nothing).
func EffectiveTemplateAnnos(ctx context.Context, obj metav1.Object,
	base map[string]string) map[string]string {

	ov := sweepOverlay(ctx)
	if ov == nil || obj == nil {
		return base
	}
	ov.mu.RLock()
	m, ok := ov.tmplAnnos[overlayObjKey(obj)]
	if !ok || len(m) == 0 {
		ov.mu.RUnlock()
		return base
	}
	// Snapshot the delta pointers under the lock, merge outside it —
	// the values are immutable once recorded.
	delta := make(map[string]*string, len(m))
	for k, v := range m {
		delta[k] = v
	}
	ov.mu.RUnlock()
	out := make(map[string]string, len(base)+len(delta))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range delta {
		if v == nil {
			delete(out, k)
		} else {
			out[k] = *v
		}
	}
	return out
}

// MarkPodDeleted records pod uid as deleted this sweep — the O(1)
// tombstone that replaces a pod-census invalidation. Later census
// reads hide the pod via FilterPodTombstones/IsPodDeleted without
// paying a cluster-wide re-LIST. No-op outside a sweep.
func MarkPodDeleted(ctx context.Context, uid types.UID) {
	ov := sweepOverlay(ctx)
	if ov == nil || uid == "" {
		return
	}
	ov.mu.Lock()
	ov.tombstones[uid] = struct{}{}
	ov.podTombstoneGen++
	ov.mu.Unlock()
}

// PodTombstoneGen reports the overlay's tombstone generation — how
// many MarkPodDeleted calls this sweep has seen. The sweep snapshot
// keys its filtered pod views on it: an unchanged gen means the
// filtered census/map computed earlier is still exact, a bump means
// rebuild once. 0 outside a sweep (and for a fresh overlay — gen 0
// is a valid generation, the src-identity half of the cache key
// keeps it honest).
func PodTombstoneGen(ctx context.Context) uint64 {
	ov := sweepOverlay(ctx)
	if ov == nil {
		return 0
	}
	ov.mu.RLock()
	gen := ov.podTombstoneGen
	ov.mu.RUnlock()
	return gen
}

// IsPodDeleted reports whether uid was deleted this sweep. False
// outside a sweep and for never-marked UIDs.
func IsPodDeleted(ctx context.Context, uid types.UID) bool {
	ov := sweepOverlay(ctx)
	if ov == nil || uid == "" {
		return false
	}
	ov.mu.RLock()
	_, ok := ov.tombstones[uid]
	ov.mu.RUnlock()
	return ok
}

// FilterPodTombstones returns pods minus this sweep's deleted-UID
// tombstones. Fast path: with no overlay or an empty tombstone set
// the input slice is returned UNCHANGED (same backing array —
// callers already treat census payloads as read-only). With
// tombstones present a fresh slice is built; the memoized census
// backing array is never written through.
func FilterPodTombstones(ctx context.Context, pods []corev1.Pod) []corev1.Pod {
	ov := sweepOverlay(ctx)
	if ov == nil {
		return pods
	}
	// One RLock for the whole slice — IsPodDeleted reacquires the
	// lock per item, which turned an N-pod census filter into N
	// lock round-trips on the hot read path.
	ov.mu.RLock()
	defer ov.mu.RUnlock()
	if len(ov.tombstones) == 0 {
		return pods
	}
	out := make([]corev1.Pod, 0, len(pods))
	for i := range pods {
		if _, dead := ov.tombstones[pods[i].UID]; !dead {
			out = append(out, pods[i])
		}
	}
	return out
}

// TryReserveWorkloadDisruption claims the per-workload disruption
// slot for pod's controller identity ("<ns>/<kind>/<name>" of the
// controller ownerRef; the pod itself when it has none). Returns
// true when the caller may proceed to delete/evict — the first
// reservation for a workload in this sweep — and false when a
// sibling check already reserved it, meaning that workload already
// lost (or is about to lose) a pod this sweep and a second delete
// could breach its replica floor or quorum.
//
// This is the cross-check half of the quorum guard: heal cooldowns
// are per-CHECK keys, so two different checks acting on pods of the
// same 2-replica Deployment would each pass their own cooldown and
// each delete — the shared ownerDisrupt slot makes the second one
// defer regardless of which check asked first.
//
// Always true outside a sweep (no overlay = no sharing = the
// pre-overlay permissive behavior).
func TryReserveWorkloadDisruption(ctx context.Context, pod *corev1.Pod) bool {
	ov := sweepOverlay(ctx)
	if ov == nil || pod == nil {
		// No overlay = no sharing = permissive; a nil pod has no
		// workload identity to reserve against — same answer.
		return true
	}
	key := disruptionKey(pod)
	ov.mu.Lock()
	defer ov.mu.Unlock()
	if _, taken := ov.ownerDisrupt[key]; taken {
		return false
	}
	ov.ownerDisrupt[key] = struct{}{}
	return true
}

// disruptionKey derives the workload identity a pod belongs to:
// its controller ownerRef's "<ns>/<Kind>/<Name>" — the same
// identity a ReplicaSet/StatefulSet/Job owns its pods under — or
// the pod's own "<ns>/Pod/<name>" when it is bare (a bare pod's
// disruption only ever threatens itself, and its UID tombstone
// already covers the same-pod case; keying it here still stops two
// checks racing the same bare pod).
func disruptionKey(pod *corev1.Pod) string {
	for _, ref := range pod.OwnerReferences {
		if ref.Controller != nil && *ref.Controller {
			return pod.Namespace + "/" + ref.Kind + "/" + ref.Name
		}
	}
	return pod.Namespace + "/Pod/" + pod.Name
}
