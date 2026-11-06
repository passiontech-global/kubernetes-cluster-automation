// operator_stuck_signatures.go — the generic per-CRD stuck
// predicates of the operator-workqueue-watchdog check (W5.8): the
// stale-observedGeneration signature and its deliberate-park
// carve-outs (flux spec.suspend, HelmRepository type=oci, percona
// spec.pause/mode) plus the never-reconciled signatures for CR
// types carrying no observedGeneration (absent
// status.conditions/phase/status). Split out of
// operator_watchdog_targets.go — see that file for the
// watched-operator table these predicates plug into; the
// gateway-API signatures live in gateway_targets.go.
package watchdogs

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// staleObservedGeneration is the canonical "controller never saw the
// last spec write" signature: status.observedGeneration lags
// metadata.generation. A missing observedGeneration reads as 0 — an
// object never touched by its controller is the strongest stuck
// signal there is (generation >= 1 for any real object).
func staleObservedGeneration(o *unstructured.Unstructured) bool {
	og, _ := kube.NestedInt64(o.Object, "status", "observedGeneration")
	return og < o.GetGeneration()
}

// fluxUnsuspendedStaleGen is staleObservedGeneration with the flux
// parking brake honored: a spec.suspend=true object is deliberately
// not reconciled — suspended work is parked, not stuck.
func fluxUnsuspendedStaleGen(o *unstructured.Unstructured) bool {
	if suspended, _ := kube.NestedBool(o.Object, "spec", "suspend"); suspended {
		return false
	}
	return staleObservedGeneration(o)
}

// helmRepoStaleGen is fluxUnsuspendedStaleGen plus the type=oci
// carve-out: since Flux v2.2 an OCI HelmRepository is a static
// reference — source-controller keeps no reconciler for it and never
// writes status, so observedGeneration stays absent forever and the
// generic signature would flag every healthy OCI repo (the actual
// OCI pull health lives on the generated HelmChart objects, which
// ARE watched by the helmcharts entry).
func helmRepoStaleGen(o *unstructured.Unstructured) bool {
	if t, _ := kube.NestedString(o.Object, "spec", "type"); t == "oci" {
		return false
	}
	return fluxUnsuspendedStaleGen(o)
}

// noStatusConditions is the "never reconciled" signature for CR
// types that lack a reliable observedGeneration (cert-manager
// Certificates, ExternalSecrets, KEDA ScaledObjects): the controller
// stamps status.conditions on its first reconcile pass, so an absent
// or empty list means it never picked the object up (W7-C2).
func noStatusConditions(o *unstructured.Unstructured) bool {
	conds, found := kube.NestedSlice(o.Object, "status", "conditions")
	return !found || len(conds) == 0
}

// emptyStatusPhase is the same never-reconciled signature for CR
// types that report a status.phase (ArgoCD): an absent/empty phase
// means the operator never touched the object (W7-C2).
func emptyStatusPhase(o *unstructured.Unstructured) bool {
	phase, found := kube.NestedString(o.Object, "status", "phase")
	return !found || phase == ""
}

// noStatusAtAll is the never-reconciled signature for CR types whose
// controllers write SPARSE status (medik8s NodeHealthCheck/
// SelfNodeRemediation): neither status.phase nor status.conditions
// means the operator never completed a reconcile pass. Either field
// alone can be legitimately absent on a healthy object — a paused
// NHC still carries phase=Paused, a finished SNR keeps its last
// phase — so only the both-absent shape proves "never reconciled".
func noStatusAtAll(o *unstructured.Unstructured) bool {
	if phase, found := kube.NestedString(o.Object, "status", "phase"); found && phase != "" {
		return false
	}
	conds, found := kube.NestedSlice(o.Object, "status", "conditions")
	return !found || len(conds) == 0
}

// perconaUnpausedStaleGen is staleObservedGeneration with the Percona
// pause brake honored: spec.pause=true (and psmdb's spec.mode=paused)
// parks reconciliation deliberately — paused clusters are parked,
// not stuck (W10-CP3).
func perconaUnpausedStaleGen(o *unstructured.Unstructured) bool {
	if paused, _ := kube.NestedBool(o.Object, "spec", "pause"); paused {
		return false
	}
	if mode, _ := kube.NestedString(o.Object, "spec", "mode"); mode == "paused" {
		return false
	}
	return staleObservedGeneration(o)
}
