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

import (
	"strconv"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

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

// ---------------------------------------------------------------------------
// Cluster-CR member pods — the dragonfly/rabbitmq operator shape
// ---------------------------------------------------------------------------

// DownscaledClusterCRs filters a cluster-CR census (AllUnstructured's
// paged dynamic LIST, memoized per GVR) to the CRs the
// go-kube-downscaler parked — spec.replicas explicitly 0 plus a
// downscaler/* annotation (IsIntentionallyDownscaled) — keyed
// "ns/name". listErr is that census read's memoized raw error: an
// absent CRD (NotFound/NoMatch) still reads as "none parked", any
// other failure returns (nil, err) — the calling check warns and
// keeps its pod-first posture without downscaler awareness.
func DownscaledClusterCRs(items []unstructured.Unstructured,
	listErr error) (map[string]bool, error) {
	switch {
	case listErr == nil, apierrors.IsNotFound(listErr),
		meta.IsNoMatchError(listErr):
	default:
		return nil, listErr
	}
	out := map[string]bool{}
	for i := range items {
		cr := &items[i]
		var reps *int32
		if n, found := NestedInt64(cr.Object, "spec", "replicas"); found {
			r := int32(n)
			reps = &r
		}
		if IsIntentionallyDownscaled(cr.GetAnnotations(), reps) {
			out[cr.GetNamespace()+"/"+cr.GetName()] = true
		}
	}
	return out, nil
}

// OwnsOrdinalPod reports whether podName is one of the cluster CR's
// member pods — the operators name them "<cr>-<ordinal>"
// (dragonfly) or "<cr>-server-<ordinal>" (rabbitmq), so the
// remainder after the "<cr>-" prefix must be an ordinal with an
// optional "server-" midfix. A bare prefix match would let a parked
// "db" cluster excuse a live "db-cache-0" pod.
func OwnsOrdinalPod(crName, podName string) bool {
	rest, ok := strings.CutPrefix(podName, crName+"-")
	if !ok {
		return false
	}
	rest = strings.TrimPrefix(rest, "server-")
	_, err := strconv.Atoi(rest)
	return err == nil
}

// DownscaledMemberPod reports whether ns/podName is a member pod of
// an intentionally-downscaled cluster CR (a key set built by
// DownscaledClusterCRs).
func DownscaledMemberPod(ns, podName string, downscaled map[string]bool) bool {
	for key := range downscaled {
		crNS, crName, ok := strings.Cut(key, "/")
		if !ok || crNS != ns {
			continue
		}
		if OwnsOrdinalPod(crName, podName) {
			return true
		}
	}
	return false
}
