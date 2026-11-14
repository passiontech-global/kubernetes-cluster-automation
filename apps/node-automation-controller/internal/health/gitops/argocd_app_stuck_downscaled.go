// argocd_app_stuck_downscaled.go — the downscaler-excuse half of the
// argocd-app-stuck check: resolving an Application's resource tree
// against the shared workload censuses to decide whether its
// Progressing state is intentional sleep (replicas:0 + downscaler/*)
// or real stuck evidence.
//
// split from argocd_app_stuck.go (see its header for the module contract).
package gitops

import (
	"context"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// rolloutZeroReplicas backs the rollout-scale-flap Rollout branch of
// argocdWorkloadDownscaled: unstructured Rollouts carry no typed
// *int32, so the zero-replica check needs a shared zero.
var rolloutZeroReplicas = int32(0)

// argocdAppOnlyDownscaled reports whether every non-Healthy entry
// in the Application's status.resources resolves to a live
// Deployment/StatefulSet the go-kube-downscaler intentionally
// parked at replicas:0 (kube.IsIntentionallyDownscaled). Fails
// closed on any other non-Healthy resource, an unreadable workload
// or NO non-Healthy resources at all — the Progressing signature
// then stands and the first-seen window decides as before.
func (p *argoCDAppStuckCheck) argocdAppOnlyDownscaled(ctx context.Context,
	app *unstructured.Unstructured) bool {
	res, found := kube.NestedSlice(app.Object, "status", "resources")
	if !found {
		return false
	}
	unhealthy := 0
	for _, r := range res {
		m, ok := r.(map[string]any)
		if !ok {
			return false
		}
		hs, _ := kube.NestedString(m, "health", "status")
		if hs == "" || hs == "Healthy" {
			continue
		}
		unhealthy++
		kind, _ := kube.NestedString(m, "kind")
		name, _ := kube.NestedString(m, "name")
		rns, _ := kube.NestedString(m, "namespace")
		if rns == "" {
			rns = app.GetNamespace() // app-namespace resource
		}
		if !p.argocdWorkloadDownscaled(ctx, kind, rns, name) {
			return false
		}
	}
	return unhealthy > 0
}

// argocdWorkloadDownscaled resolves one Application resource-tree
// entry to its live workload and asks the shared verdict — anything
// that is not a Deployment/StatefulSet/Rollout pinned at replicas:0
// with downscaler/* annotations counts as real stuck evidence. Verdicts
// memoize per sweep on downscaledSeen (kind/ns/name → verdict) so a
// workload shared by several Applications pays one Get, not one per
// app; the memo never changes a verdict, only its lookup count.
func (p *argoCDAppStuckCheck) argocdWorkloadDownscaled(ctx context.Context,
	kind, ns, name string) bool {
	key := kind + "/" + ns + "/" + name
	if v, memo := p.downscaledSeen[key]; memo {
		return v // same workload already resolved this sweep
	}
	var v bool
	switch kind {
	case "Deployment":
		v = p.deploymentDownscaled(ctx, ns, name)
	case "StatefulSet":
		v = p.statefulSetDownscaled(ctx, ns, name)
	case "Rollout":
		// rollout-scale-flap — Argo Rollouts workloads in the Application's
		// resource tree carry the same downscaled semantics: a
		// Rollout parked at spec.replicas:0 with downscaler/*
		// annotations is sleep, not stuck evidence. Rollouts are
		// unstructured CRs — read replicas off the unstructured spec.
		// The lookup rides the per-sweep unstructured snapshot — one
		// paged cluster LIST memoized per GVR, filtered client-side
		// to ns/name (the raw NotFound/NoMatch census error means no
		// Rollout CRD or failed read: fail closed, not downscaled).
		ros, err := p.AllUnstructured(ctx, kube.GVRArgoRollout)
		if err != nil {
			v = false
			break
		}
		var r *unstructured.Unstructured
		for i := range ros {
			if ros[i].GetNamespace() == ns && ros[i].GetName() == name {
				r = &ros[i]
				break
			}
		}
		if r == nil {
			v = false
			break
		}
		replicas, found := kube.NestedInt64(r.Object, "spec", "replicas")
		v = found && replicas == 0 &&
			kube.IsIntentionallyDownscaled(r.GetAnnotations(), &rolloutZeroReplicas)
	}
	if p.downscaledSeen == nil {
		p.downscaledSeen = map[string]bool{} // lazy init — Run seeds it
	}
	p.downscaledSeen[key] = v
	return v
}

// deploymentDownscaled resolves one workload via the sweep's shared
// per-ns/name index (single cluster-wide LIST on first lookup, O(1)
// thereafter; failures remain uncached on *probefw.Deps). Absent or
// unreadable reads false: not proven downscaled is stuck evidence,
// the fail-closed posture.
func (p *argoCDAppStuckCheck) deploymentDownscaled(ctx context.Context,
	ns, name string) bool {

	dep, err := p.Deployment(ctx, ns, name)
	if err != nil || dep == nil {
		return false
	}
	return kube.IsIntentionallyDownscaled(dep.Annotations, dep.Spec.Replicas)
}

// statefulSetDownscaled is the StatefulSet twin over *probefw.Deps.
func (p *argoCDAppStuckCheck) statefulSetDownscaled(ctx context.Context,
	ns, name string) bool {

	sts, err := p.StatefulSet(ctx, ns, name)
	if err != nil || sts == nil {
		return false
	}
	return kube.IsIntentionallyDownscaled(sts.Annotations, sts.Spec.Replicas)
}
