// flux_kustomization_ready.go — the HealthCheckFailed corroboration
// half of the flux-stuck check: resolving status.inventory entries to
// live workloads and checking ready-replica coverage on the shared
// Deployment/StatefulSet/Rollout censuses.
//
// split from flux_kustomization_health.go (see its header for the
// module contract).
package gitops

import (
	"context"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// fluxKustWorkloadsReady is the HealthCheckFailed corroboration:
// every Deployment/StatefulSet the Kustomization applied (resolved
// from status.inventory entries) must read Ready on the live object.
// A stale status poller leaves Ready=False latched while the pods it
// waits on are long since up — the nudge flushes it. Fails closed:
// no resolvable workload entries (or any unreadable/unready one)
// means the failure stands and no nudge fires.
func (p *fluxKustomizationHealthCheck) fluxKustWorkloadsReady(ctx context.Context,
	kust *unstructured.Unstructured) bool {

	entries, found := kube.NestedSlice(kust.Object, "status", "inventory", "entries")
	if !found {
		return false
	}
	workloads := 0
	for _, e := range entries {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		id, _ := m["id"].(string)
		ns, name, kind := parseFluxInventoryID(id)
		var ready bool
		switch kind {
		case "Deployment":
			ready = p.fluxDeploymentReady(ctx, ns, name)
		case "StatefulSet":
			ready = p.fluxStatefulSetReady(ctx, ns, name)
		case "Rollout":
			// argo-rollout-gates — argoproj.io Rollouts land in the inventory the
			// same way; same ready-replicas corroboration, read off
			// the unstructured CR.
			ready = p.fluxRolloutReady(ctx, ns, name)
		default:
			continue // not a readiness-workload entry — ignore
		}
		workloads++
		if !ready {
			return false
		}
	}
	return workloads > 0
}

// parseFluxInventoryID splits a status.inventory entry id —
// "<namespace>_<name>_<group>_<kind>" (fluxcd/pkg object.ObjMetadata
// String(); the entry's "v" carries the version separately). Object
// names, namespaces and groups cannot contain underscores
// (DNS-1123), so exactly four fields split cleanly; cluster-scoped
// entries carry an empty leading namespace field and core-group
// entries an empty group field. kind is the CamelCase Kind.
func parseFluxInventoryID(id string) (ns, name, kind string) {
	parts := strings.Split(id, "_")
	if len(parts) != 4 {
		return "", "", ""
	}
	return parts[0], parts[1], parts[3]
}

// fluxDeploymentReady reports whether the Deployment's ready replicas
// cover its desired count — resolved from the sweep's shared
// Deployment census (absent or unreadable is not ready: fail closed).
// A replicas:0 downscale reads ready.
func (p *fluxKustomizationHealthCheck) fluxDeploymentReady(ctx context.Context,
	ns, name string) bool {

	deps, err := p.AllDeployments(ctx)
	if err != nil {
		return false
	}
	for i := range deps {
		d := &deps[i]
		if d.Namespace != ns || d.Name != name {
			continue
		}
		return d.Status.ReadyReplicas >= desiredReplicas(d.Spec.Replicas)
	}
	return false
}

// fluxRolloutReady is the argoproj.io Rollout twin (argo-rollout-gates): the
// same ready-replicas cover check over the unstructured Rollout
// census — status.readyReplicas vs spec.replicas (absent spec
// replicas means the apiserver default of 1; a replicas:0
// downscale reads ready). Absent or unreadable is not ready:
// fail closed.
func (p *fluxKustomizationHealthCheck) fluxRolloutReady(ctx context.Context,
	ns, name string) bool {

	ros, err := p.AllUnstructured(ctx, kube.GVRArgoRollout)
	if err != nil {
		return false
	}
	for i := range ros {
		r := &ros[i]
		if r.GetNamespace() != ns || r.GetName() != name {
			continue
		}
		desired := int64(1)
		if d, found := kube.NestedInt64(r.Object, "spec", "replicas"); found {
			desired = d
		}
		ready, _ := kube.NestedInt64(r.Object, "status", "readyReplicas")
		return ready >= desired
	}
	return false
}

// fluxStatefulSetReady is the StatefulSet twin over the shared
// StatefulSet census.
func (p *fluxKustomizationHealthCheck) fluxStatefulSetReady(ctx context.Context,
	ns, name string) bool {

	stss, err := p.AllStatefulSets(ctx)
	if err != nil {
		return false
	}
	for i := range stss {
		s := &stss[i]
		if s.Namespace != ns || s.Name != name {
			continue
		}
		return s.Status.ReadyReplicas >= desiredReplicas(s.Spec.Replicas)
	}
	return false
}

// desiredReplicas dereferences the workload replica pointer — a nil
// spec.replicas means the apiserver default of 1.
func desiredReplicas(specReplicas *int32) int32 {
	if specReplicas == nil {
		return 1
	}
	return *specReplicas
}
