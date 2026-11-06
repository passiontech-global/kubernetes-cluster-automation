// anno.go — annotation timestamp helpers. The node.ops/last-*
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

// StampAnno sets obj's annotation key to t in RFC3339 — new stamps
// are always RFC3339; the unix-seconds branch of ParseAnnoTime is
// read-compat only and must never be written again. A nil
// annotations map is created (the same create-on-write the
// hand-rolled stampers each carried). The value lands in the map
// BEFORE SetAnnotations: unstructured objects deep-copy on set, so
// mutating the map afterwards would silently drop the stamp.
func StampAnno(obj metav1.Object, key string, t time.Time) {
	annos := obj.GetAnnotations()
	if annos == nil {
		annos = map[string]string{}
	}
	annos[key] = t.Format(time.RFC3339)
	obj.SetAnnotations(annos)
}
