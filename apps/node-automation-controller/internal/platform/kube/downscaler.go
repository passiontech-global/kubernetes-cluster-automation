// downscaler.go — the go-kube-downscaler awareness helper: a single
// canonical "is this zero-replica workload asleep on purpose" verdict
// the stateful/ArgoCD/KEDA probes share, so a check never remediates
// (pod delete, replica bump, stuck verdict) a workload the
// downscaler deliberately put to bed.
//
// go-kube-downscaler scales annotated workloads to a configured
// replica count (usually 0) on a schedule — the zero is INTENT, not
// a crash loop, cold-start deadlock, or stalled rollout. The signal
// is the annotation family the operator documents: any
// "downscaler/" prefixed key on the workload means the downscaler
// owns the replica count.
package kube

import "strings"

// DownscalerAnnotationPrefix is the go-kube-downscaler annotation
// family (downscaler/uptime, downscaler/downtime,
// downscaler/downtime-replicas, downscaler/force-downtime, ...).
const DownscalerAnnotationPrefix = "downscaler/"

// IsIntentionallyDownscaled reports whether a zero replica count is
// the downscaler's doing rather than a failure: replicas must be
// explicitly 0 (nil means "unset", i.e. the apiserver default of 1 —
// not downscaled) and the object must carry at least one
// downscaler/* annotation.
func IsIntentionallyDownscaled(annotations map[string]string, replicas *int32) bool {
	if replicas == nil || *replicas != 0 {
		return false
	}
	for k := range annotations {
		if strings.HasPrefix(k, DownscalerAnnotationPrefix) {
			return true
		}
	}
	return false
}
