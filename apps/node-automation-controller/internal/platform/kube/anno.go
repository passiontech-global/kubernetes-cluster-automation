// anno.go — annotation timestamp helpers. The passiontech.dev/last-*
// stamps (last-es-nudge, last-helm-unlock, last-source-nudge,
// last-immutable-job-heal, last-helm-stall-unwedge, ...) are the
// DURABLE half of their modules' cooldowns — they survive operator
// restarts where the in-RAM CooldownSet cannot. ~6 sites hand-roll
// the same read: try RFC3339 (what every current writer stamps),
// fall back to unix seconds (the legacy force-sync stamp format
// still live on older objects), treat absent/empty/unparseable as
// "no stamp" — a garbage value cannot prove a recent action, and
// stamping over it is exactly how a wedged object gets unstuck.
package kube

import (
	"encoding/json"
	"strconv"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ParseAnnoTime parses an annotation timestamp — RFC3339 first,
// then unix seconds (the legacy stamp format several annotations
// still carry). ok=false on absent/empty/unparseable input: callers
// treat a stamp they cannot read as no stamp at all, never as now.
func ParseAnnoTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	if ts, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(ts, 0), true
	}
	return time.Time{}, false
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
