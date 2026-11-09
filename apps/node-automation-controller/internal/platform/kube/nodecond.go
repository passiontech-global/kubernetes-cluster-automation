// nodecond.go — the node-condition helpers the node-lifecycle
// modules and nodehealth checks share: converting a libs/hostkit
// nodecond name list into corev1.NodeConditionTypes, and the
// lastHeartbeatTime freshness gate that decides whether an
// agent-emitted condition's True is live evidence or a zombie left
// by a dead reporter. Both used to be copy-pasted per module (the
// domain trees cannot import each other, so each carried a private
// mirror); platform/kube is the leaf both sides already import.
package kube

import (
	"time"

	corev1 "k8s.io/api/core/v1"
)

// CondTypes converts a nodecond name list into the
// corev1.NodeConditionType slice verdict loops compare against —
// nodecond (libs/hostkit) keeps the names as untyped strings so
// hostkit stays stdlib-only and cannot import k8s.io/api.
func CondTypes(names []string) []corev1.NodeConditionType {
	out := make([]corev1.NodeConditionType, len(names))
	for i, name := range names {
		out[i] = corev1.NodeConditionType(name)
	}
	return out
}

// CondHeartbeatLive reports whether a condition's lastHeartbeatTime
// is fresh enough to trust the value: the writer (nodereporter
// re-stamps every ~2m while alive; kubelet on every status post)
// keeps the heartbeat moving, so a heartbeat older than maxAge — or
// never set — means the condition may be a zombie left by a dead
// reporter. maxAge is the caller's window (the modules keep their
// own *CondHeartbeatMaxAge consts — all currently the same 10m
// zombie-latch convention, but each documents its own blast radius).
func CondHeartbeatLive(c *corev1.NodeCondition, maxAge time.Duration, now time.Time) bool {
	return !c.LastHeartbeatTime.IsZero() &&
		now.Sub(c.LastHeartbeatTime.Time) < maxAge
}
