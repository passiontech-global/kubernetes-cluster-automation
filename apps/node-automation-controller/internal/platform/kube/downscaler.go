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

// downscalerConfigKeys are downscaler/* annotations that configure
// the operator's behavior rather than mark the workload as asleep —
// exclude/exclude-until/force-uptime mean "the downscaler must NOT
// touch this workload", so their presence alone is never evidence of
// an intentional zero.
var downscalerConfigKeys = map[string]bool{
	"downscaler/exclude":       true,
	"downscaler/exclude-until": true,
	"downscaler/force-uptime":  true,
}

// IsIntentionallyDownscaled reports whether a zero replica count is
// the downscaler's doing rather than a failure: replicas must be
// explicitly 0 (nil means "unset", i.e. the apiserver default of 1 —
// not downscaled) and the object must carry at least one real
// downscaler/* schedule annotation. An explicit opt-out
// (downscaler/exclude or downscaler/force-uptime = "true") vetoes the
// verdict even when schedule annotations are also present — the
// workload is awake on purpose, so a zero is a crash, not sleep.
func IsIntentionallyDownscaled(annotations map[string]string, replicas *int32) bool {
	if replicas == nil || *replicas != 0 {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(annotations["downscaler/exclude"]), "true") ||
		strings.EqualFold(strings.TrimSpace(annotations["downscaler/force-uptime"]), "true") {
		return false
	}
	for k := range annotations {
		if downscalerConfigKeys[k] {
			continue
		}
		if strings.HasPrefix(k, DownscalerAnnotationPrefix) {
			return true
		}
	}
	return false
}
