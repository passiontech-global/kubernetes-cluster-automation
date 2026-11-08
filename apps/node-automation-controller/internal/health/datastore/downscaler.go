// downscaler.go — go-kube-downscaler awareness shared by the
// datastore cluster-CR checks (rabbitmq-quorum-health,
// dragonfly-replica-sync-storm). Pure move out of
// stateful_masterless_services.go — see that file for the checks.
package datastore

import (
	"context"
	"strconv"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// ---------------------------------------------------------------------------
// go-kube-downscaler awareness — shared by the datastore cluster-CR
// checks (rabbitmq-quorum-health, dragonfly-replica-sync-storm).
// ---------------------------------------------------------------------------

// downscaledClusterCRs lists the cluster CRs of gvr the
// go-kube-downscaler parked — spec.replicas explicitly 0 plus a
// downscaler/* annotation (kube.IsIntentionallyDownscaled) — keyed
// "ns/name". A nil dynamic client or an absent CRD reads as "none
// parked": the calling check works pod-first and simply cannot
// prove the park, so the pod-level signatures keep their normal
// posture.
func downscaledClusterCRs(ctx context.Context, dyn dynamic.Interface,
	gvr schema.GroupVersionResource) (map[string]bool, error) {
	out := map[string]bool{}
	if dyn == nil {
		return out, nil
	}
	list, err := dyn.Resource(gvr).List(ctx, metav1.ListOptions{})
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		return out, nil
	case err != nil:
		return nil, err
	}
	for i := range list.Items {
		cr := &list.Items[i]
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
