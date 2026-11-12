// annotools.go — annotation read/write helpers: the timestamp stamps
// (ParseAnnoTime/AnnoTime) and the merge-patch builder
// (MergePatchAnnos) every stamp site shares. They serve the
// passiontech.dev/last-* stamps (last-es-nudge, last-helm-unlock,
// last-source-nudge, last-immutable-job-heal, last-helm-stall-
// unwedge, ...) — the DURABLE half of their modules' cooldowns;
// they survive operator restarts where the in-RAM CooldownSet
// cannot. ~6 sites hand-roll the same read: try RFC3339 (what
// every current writer stamps), fall back to unix seconds (the
// legacy force-sync stamp format still live on older objects),
// treat absent/empty/unparseable as "no stamp" — a garbage value
// cannot prove a recent action, and stamping over it is exactly
// how a wedged object gets unstuck.
package kube

import (
	"context"
	"encoding/json"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

// ParseAnnoTime parses an annotation timestamp — RFC3339 first,
// then unix seconds (the legacy stamp format several annotations
// still carry). ok=false on absent/empty/unparseable input: callers
// treat a stamp they cannot read as no stamp at all, never as now.
func ParseAnnoTime(s string) (time.Time, bool) {
	return nodecond.ParseAnnoTime(s)
}

// AnnoTime reads obj's annotation key as a timestamp via
// ParseAnnoTime — the one-call form for the `obj.GetAnnotations()[key]`
// then parse-either-format shape every stamp reader repeats.
func AnnoTime(obj metav1.Object, key string) (time.Time, bool) {
	if obj == nil {
		return time.Time{}, false
	}
	return ParseAnnoTime(obj.GetAnnotations()[key])
}

// AnnoTimeCtx is AnnoTime resolved through the sweep overlay —
// EffectiveAnno supplies the value, so an annotation patch recorded
// mid-sweep (kube.RecordAnnoPatch) reads back instead of the
// pre-patch snapshot copy. Heal gates MUST use this variant: the
// object's own map is frozen at LIST time for the rest of the sweep.
// Outside a sweep it is byte-identical to AnnoTime.
func AnnoTimeCtx(ctx context.Context, obj metav1.Object, key string) (time.Time, bool) {
	if obj == nil {
		return time.Time{}, false
	}
	return ParseAnnoTime(EffectiveAnno(ctx, obj, key))
}

// MergePatchAnnos builds a MergePatchType patch doc setting (or, for
// a nil value, deleting) the given metadata.annotations keys —
// collapses the json.Marshal({"metadata":{"annotations":{...}}})
// boilerplate every stamp site hand-rolled. Stamp values are
// RFC3339 by contract (the unix branch of ParseAnnoTime is read-
// compat only); a nil value is the merge-patch delete used when a
// budget/marker annotation must be cleared on heal.
func MergePatchAnnos(annos map[string]any) ([]byte, error) {
	return json.Marshal(map[string]any{
		"metadata": map[string]any{"annotations": annos},
	})
}
