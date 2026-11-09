// downscaler.go — go-kube-downscaler awareness shared by the
// datastore cluster-CR checks (rabbitmq-quorum-health,
// dragonfly-replica-sync-storm). Pure move out of
// stateful_masterless_services.go — see that file for the checks.
package datastore

import (
	"strconv"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// ---------------------------------------------------------------------------
// go-kube-downscaler awareness — shared by the datastore cluster-CR
// checks (rabbitmq-quorum-health, dragonfly-replica-sync-storm).
// ---------------------------------------------------------------------------

// downscaledClusterCRs filters the sweep's shared cluster-CR census
// (AllUnstructured's paged dynamic LIST, memoized per GVR) to the
// CRs the go-kube-downscaler parked — spec.replicas explicitly 0
// plus a downscaler/* annotation (kube.IsIntentionallyDownscaled) —
// keyed "ns/name". listErr is that census read's memoized raw error:
// an absent CRD (NotFound/NoMatch) still reads as "none parked", any
// other failure returns (nil, err) — the calling check warns and
// keeps its pod-first posture without downscaler awareness.
func downscaledClusterCRs(items []unstructured.Unstructured,
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
		if n, found := kube.NestedInt64(cr.Object, "spec", "replicas"); found {
			r := int32(n)
			reps = &r
		}
		if kube.IsIntentionallyDownscaled(cr.GetAnnotations(), reps) {
			out[cr.GetNamespace()+"/"+cr.GetName()] = true
		}
	}
	return out, nil
}

// ownsOrdinalPod reports whether podName is one of the cluster CR's
// member pods — the operators name them "<cr>-<ordinal>"
// (dragonfly) or "<cr>-server-<ordinal>" (rabbitmq), so the
// remainder after the "<cr>-" prefix must be an ordinal with an
// optional "server-" midfix. A bare prefix match would let a parked
// "db" cluster excuse a live "db-cache-0" pod.
func ownsOrdinalPod(crName, podName string) bool {
	rest, ok := strings.CutPrefix(podName, crName+"-")
	if !ok {
		return false
	}
	rest = strings.TrimPrefix(rest, "server-")
	_, err := strconv.Atoi(rest)
	return err == nil
}

// downscaledMemberPod reports whether ns/podName is a member pod of
// an intentionally-downscaled cluster CR (a key set built by
// downscaledClusterCRs).
func downscaledMemberPod(ns, podName string, downscaled map[string]bool) bool {
	for key := range downscaled {
		crNS, crName, ok := strings.Cut(key, "/")
		if !ok || crNS != ns {
			continue
		}
		if ownsOrdinalPod(crName, podName) {
			return true
		}
	}
	return false
}
