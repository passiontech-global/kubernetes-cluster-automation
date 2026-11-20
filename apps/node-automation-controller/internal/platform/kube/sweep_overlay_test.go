// sweep_overlay_test.go — regression coverage for the per-sweep
// write overlay: annotation deltas, pod tombstones, and the
// ownerDisrupt quorum reservation that stops two parallel checks
// from each deleting a pod of the same workload in one sweep.
package kube

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func overlayPod(name string, owner *metav1.OwnerReference) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "ns",
			UID:       types.UID(name + "-uid"),
		},
	}
	if owner != nil {
		p.OwnerReferences = []metav1.OwnerReference{*owner}
	}
	return p
}

func controllerRef(kind, name string) *metav1.OwnerReference {
	ctrl := true
	return &metav1.OwnerReference{
		APIVersion: "apps/v1", Kind: kind, Name: name, Controller: &ctrl,
	}
}

func TestTryReserveWorkloadDisruption(t *testing.T) {
	ctx := WithSweepOverlay(t.Context())

	// Two pods of the same ReplicaSet share ONE disruption slot —
	// the second reservation is denied so a sibling check cannot
	// take the workload to zero in the same sweep.
	rs := controllerRef("ReplicaSet", "web-6d9f")
	if !TryReserveWorkloadDisruption(ctx, overlayPod("web-0", rs)) {
		t.Fatal("first reservation for a workload must succeed")
	}
	if TryReserveWorkloadDisruption(ctx, overlayPod("web-1", rs)) {
		t.Fatal("second pod of the same owner must be denied — quorum guard")
	}

	// A different workload gets its own slot.
	other := controllerRef("ReplicaSet", "api-77bc")
	if !TryReserveWorkloadDisruption(ctx, overlayPod("api-0", other)) {
		t.Fatal("a different owner must get its own slot")
	}

	// Bare pods (no controller ownerRef) key on themselves — each
	// is an independent slot.
	if !TryReserveWorkloadDisruption(ctx, overlayPod("bare-0", nil)) {
		t.Fatal("bare pod reservation must succeed")
	}
	if !TryReserveWorkloadDisruption(ctx, overlayPod("bare-1", nil)) {
		t.Fatal("a second bare pod is a different workload — must succeed")
	}
}

// A Deployment mid-rollout runs TWO ReplicaSets — pods of the old
// and new RS normalize onto the same "ns/Deployment/<deploy>" slot
// so two checks cannot each spend a disruption and take the
// workload to zero. A workload-key reservation (the
// RestartTemplatePatch restart sites) shares that same slot.
func TestDisruptionKeyNormalizesReplicaSetHash(t *testing.T) {
	ctx := WithSweepOverlay(t.Context())

	oldRS := controllerRef("ReplicaSet", "web-6d9f8b7c5d")
	newRS := controllerRef("ReplicaSet", "web-1a2b3c4d5e")
	if !TryReserveWorkloadDisruption(ctx, overlayPod("web-old-0", oldRS)) {
		t.Fatal("first RS pod reservation must succeed")
	}
	if TryReserveWorkloadDisruption(ctx, overlayPod("web-new-0", newRS)) {
		t.Fatal("new-RS pod must share the Deployment slot — mid-rollout quorum guard")
	}

	// The restart-patch reservation keys on the same identity.
	ctx2 := WithSweepOverlay(t.Context())
	if !TryReserveWorkloadKey(ctx2, "ns/Deployment/web") {
		t.Fatal("workload-key reservation must succeed")
	}
	if TryReserveWorkloadDisruption(ctx2, overlayPod("web-x", oldRS)) {
		t.Fatal("pod delete must see the restart's spent slot")
	}

	// A name with NO hash-shaped tail (no "-<alnum≤12>" suffix —
	// "web-6d9f" now normalizes under the widened {1,12} window)
	// keeps its own ReplicaSet identity — it must NOT merge into
	// the Deployment slot.
	ctx3 := WithSweepOverlay(t.Context())
	if !TryReserveWorkloadKey(ctx3, "ns/Deployment/web") {
		t.Fatal("deployment slot reservation must succeed")
	}
	plain := controllerRef("ReplicaSet", "web_rs_canary")
	if !TryReserveWorkloadDisruption(ctx3, overlayPod("p1", plain)) {
		t.Fatal("unhashed RS keeps its own key — must not merge into Deployment/web")
	}
	if TryReserveWorkloadDisruption(ctx3, overlayPod("p2", oldRS)) {
		t.Fatal("hashed RS pod shares the spent Deployment slot — must be denied")
	}
}

// Terminal pods (Succeeded/Failed) hold no traffic — GC of a dead
// pod must not consume the one-disruption slot, so a reaper can
// reap many terminal pods of the same controller while a sibling
// check can still heal its wedged Running replica in the same sweep.
func TestTryReserveWorkloadDisruptionTerminalPodsExempt(t *testing.T) {
	ctx := WithSweepOverlay(t.Context())
	rs := controllerRef("ReplicaSet", "web-6d9f")
	live := overlayPod("web-live", rs)
	deadA, deadB := overlayPod("web-dead-a", rs), overlayPod("web-dead-b", rs)
	deadA.Status.Phase, deadB.Status.Phase = corev1.PodSucceeded, corev1.PodFailed

	// Many terminal siblings all pass — no slot is consumed.
	for _, p := range []*corev1.Pod{deadA, deadB} {
		if !TryReserveWorkloadDisruption(ctx, p) {
			t.Fatalf("terminal pod %s must not need the disruption slot", p.Name)
		}
	}
	// The live replica of the SAME workload still gets its slot.
	if !TryReserveWorkloadDisruption(ctx, live) {
		t.Fatal("terminal reaping must not spend the live workload's disruption slot")
	}
	// ... and a second live sibling is still denied (the slot was
	// genuinely reserved by the first live pod).
	otherLive := overlayPod("web-live-2", rs)
	if TryReserveWorkloadDisruption(ctx, otherLive) {
		t.Fatal("live siblings still share one slot — the quorum guard must hold")
	}
}

func TestTryReserveWorkloadDisruptionOutsideSweep(t *testing.T) {
	// No overlay on ctx — every call is permissive (direct-Run
	// checks and module periodics never share a sweep).
	ctx := t.Context()
	rs := controllerRef("ReplicaSet", "web-6d9f")
	for i := 0; i < 3; i++ {
		if !TryReserveWorkloadDisruption(ctx, overlayPod("web-"+string(rune('0'+i)), rs)) {
			t.Fatal("outside a sweep the reservation must always succeed")
		}
	}
}

func TestPodTombstones(t *testing.T) {
	ctx := WithSweepOverlay(t.Context())
	pods := []corev1.Pod{
		*overlayPod("a", nil), *overlayPod("b", nil), *overlayPod("c", nil),
	}
	if IsPodDeleted(ctx, pods[0].UID) {
		t.Fatal("unmarked pod must not read as deleted")
	}
	MarkPodDeleted(ctx, pods[1].UID)
	if !IsPodDeleted(ctx, pods[1].UID) {
		t.Fatal("marked pod must read as deleted")
	}
	got := FilterPodTombstones(ctx, pods)
	if len(got) != 2 || got[0].Name != "a" || got[1].Name != "c" {
		t.Fatalf("FilterPodTombstones = %v, want [a c]", got)
	}
	// Empty tombstone set returns the input slice unchanged.
	ctx2 := WithSweepOverlay(t.Context())
	if got := FilterPodTombstones(ctx2, pods); len(got) != 3 {
		t.Fatalf("no tombstones must return all pods, got %d", len(got))
	}
}

func TestEffectiveAnnoAndRecordPatch(t *testing.T) {
	obj := overlayPod("p", nil)
	obj.SetAnnotations(map[string]string{"keep": "base", "stale": "old"})

	// Outside a sweep: RecordAnnoPatch mirrors in place (the
	// caller-private-object contract), EffectiveAnno reads through.
	ctx := t.Context()
	RecordAnnoPatch(ctx, obj, []byte(
		`{"metadata":{"annotations":{"stale":"new","added":"yes","keep":null}}}`))
	if got := EffectiveAnno(ctx, obj, "stale"); got != "new" {
		t.Fatalf("EffectiveAnno stale = %q, want new", got)
	}
	if got := EffectiveAnno(ctx, obj, "keep"); got != "" {
		t.Fatalf("EffectiveAnno keep = %q, want deleted", got)
	}
	if _, ok := obj.GetAnnotations()["keep"]; ok {
		t.Fatal("outside a sweep the in-place mirror must apply the delete")
	}

	// Inside a sweep the shared object is NEVER mutated — readers
	// resolve through the overlay instead.
	ctx = WithSweepOverlay(t.Context())
	obj2 := overlayPod("p2", nil)
	obj2.SetAnnotations(map[string]string{"k": "base"})
	RecordAnnoPatch(ctx, obj2, []byte(
		`{"metadata":{"annotations":{"k":"patched","extra":"e"}}}`))
	if obj2.GetAnnotations()["k"] != "base" {
		t.Fatal("sweep overlay must not mutate the shared snapshot object")
	}
	if got := EffectiveAnno(ctx, obj2, "k"); got != "patched" {
		t.Fatalf("EffectiveAnno k = %q, want patched", got)
	}
	if got := EffectiveAnno(ctx, obj2, "extra"); got != "e" {
		t.Fatalf("EffectiveAnno extra = %q, want e", got)
	}
	if got := EffectiveAnno(ctx, obj2, "absent"); got != "" {
		t.Fatalf("EffectiveAnno absent = %q, want empty", got)
	}
}

func TestTemplateAnnosAndPodTombstoneGen(t *testing.T) {
	obj := overlayPod("sts-pod", nil)
	base := map[string]string{"keep": "1", "over": "old"}

	// Outside a sweep: RecordTemplateAnnos returns false, EffectiveTemplateAnnos returns base, PodTombstoneGen=0.
	plainCtx := t.Context()
	if RecordTemplateAnnos(plainCtx, obj, map[string]string{"a": "b"}) {
		t.Fatal("expected RecordTemplateAnnos=false outside sweep")
	}
	if got := EffectiveTemplateAnnos(plainCtx, obj, base); got["over"] != "old" || len(got) != 2 {
		t.Fatalf("unexpected EffectiveTemplateAnnos outside sweep: %v", got)
	}
	if got := PodTombstoneGen(plainCtx); got != 0 {
		t.Fatalf("expected PodTombstoneGen=0 outside sweep, got %d", got)
	}

	// Inside a sweep.
	ctx := WithSweepOverlay(t.Context())
	if got := PodTombstoneGen(ctx); got != 0 {
		t.Fatalf("expected initial PodTombstoneGen=0, got %d", got)
	}
	MarkPodDeleted(ctx, "uid-1")
	if got := PodTombstoneGen(ctx); got != 1 {
		t.Fatalf("expected PodTombstoneGen=1 after MarkPodDeleted, got %d", got)
	}

	// Unrecorded object returns base unchanged.
	if got := EffectiveTemplateAnnos(ctx, obj, base); got["over"] != "old" || len(got) != 2 {
		t.Fatalf("expected base unchanged before recording, got %v", got)
	}
	if RecordTemplateAnnos(ctx, obj, nil) {
		t.Fatal("expected RecordTemplateAnnos=false for empty annos")
	}
	if !RecordTemplateAnnos(ctx, obj, map[string]string{"over": "new", "added": "yes"}) {
		t.Fatal("expected RecordTemplateAnnos=true inside sweep")
	}
	merged := EffectiveTemplateAnnos(ctx, obj, base)
	if merged["keep"] != "1" || merged["over"] != "new" || merged["added"] != "yes" {
		t.Fatalf("unexpected merged template annos: %v", merged)
	}
	if base["over"] != "old" {
		t.Fatal("base map must not be mutated")
	}
}

func TestReleaseWorkloadDisruption(t *testing.T) {
	// Outside a sweep and nil pod are safe no-ops.
	ReleaseWorkloadDisruption(t.Context(), nil)
	rs := controllerRef("ReplicaSet", "web-6d9f")
	ReleaseWorkloadDisruption(t.Context(), overlayPod("web-0", rs))

	ctx := WithSweepOverlay(t.Context())
	ReleaseWorkloadDisruption(ctx, nil)

	p1 := overlayPod("web-0", rs)
	p2 := overlayPod("web-1", rs)
	if !TryReserveWorkloadDisruption(ctx, p1) {
		t.Fatal("initial reserve must succeed")
	}
	if TryReserveWorkloadDisruption(ctx, p2) {
		t.Fatal("second live sibling must be blocked while reserved")
	}

	// Terminal pod release must NOT clear a live sibling's reservation.
	dead := overlayPod("web-dead", rs)
	dead.Status.Phase = corev1.PodSucceeded
	ReleaseWorkloadDisruption(ctx, dead)
	if TryReserveWorkloadDisruption(ctx, p2) {
		t.Fatal("terminal pod release erased live sibling's slot")
	}

	// Real release allows sibling reservation.
	ReleaseWorkloadDisruption(ctx, p1)
	if !TryReserveWorkloadDisruption(ctx, p2) {
		t.Fatal("sibling reserve must succeed after ReleaseWorkloadDisruption")
	}
}

func TestEffectiveAnnosFastPathZeroAllocsAndDelta(t *testing.T) {
	obj := overlayPod("p-annos", nil)
	obj.SetAnnotations(map[string]string{"a": "1", "b": "2"})
	other := overlayPod("p-other", nil)

	// 1. Outside a sweep: zero allocs, returns base map.
	plainCtx := t.Context()
	if got := EffectiveAnnos(plainCtx, obj); got["a"] != "1" || len(got) != 2 {
		t.Fatalf("outside sweep = %v, want {a:1 b:2}", got)
	}
	if allocs := testing.AllocsPerRun(20, func() {
		_ = EffectiveAnnos(plainCtx, obj)
	}); allocs != 0 {
		t.Fatalf("outside sweep EffectiveAnnos allocs = %v, want 0", allocs)
	}

	// 2. Inside a sweep with empty overlay: zero allocs.
	ctx := WithSweepOverlay(t.Context())
	if allocs := testing.AllocsPerRun(20, func() {
		_ = EffectiveAnnos(ctx, obj)
	}); allocs != 0 {
		t.Fatalf("empty overlay EffectiveAnnos allocs = %v, want 0", allocs)
	}

	// 3. Delta on another object only: still zero allocs for obj.
	RecordAnnoPatch(ctx, other, []byte(`{"metadata":{"annotations":{"x":"y"}}}`))
	if allocs := testing.AllocsPerRun(20, func() {
		_ = EffectiveAnnos(ctx, obj)
	}); allocs != 0 {
		t.Fatalf("unrelated delta EffectiveAnnos allocs = %v, want 0", allocs)
	}

	// 4. Delta on obj: add, edit, delete reflected without mutating obj.
	RecordAnnoPatch(ctx, obj, []byte(`{"metadata":{"annotations":{"a":"new","b":null,"c":"added"}}}`))
	got := EffectiveAnnos(ctx, obj)
	if got["a"] != "new" || got["c"] != "added" {
		t.Fatalf("overlay EffectiveAnnos = %v, want a=new c=added", got)
	}
	if _, ok := got["b"]; ok {
		t.Fatalf("overlay EffectiveAnnos kept deleted key b: %v", got)
	}
	if obj.GetAnnotations()["a"] != "1" || obj.GetAnnotations()["b"] != "2" {
		t.Fatal("EffectiveAnnos mutated base object map")
	}
}
