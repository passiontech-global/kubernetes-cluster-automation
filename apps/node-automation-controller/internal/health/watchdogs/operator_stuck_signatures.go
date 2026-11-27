// operator_stuck_signatures.go — the generic per-CRD stuck
// predicates of the operator-workqueue-watchdog check (operator-workqueue-watchdog): the
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

// hasStatusSignals reports whether the CR already carries reconciled
// status signals (non-empty status.conditions or non-empty
// status.phase). Used to distinguish "observedGeneration: 0 because
// the CRD/controller does not populate it" from "never reconciled".
func hasStatusSignals(o *unstructured.Unstructured) bool {
	if phase, found := kube.NestedString(o.Object, "status", "phase"); found && phase != "" {
		return true
	}
	conds, found := kube.NestedSlice(o.Object, "status", "conditions")
	return found && len(conds) > 0
}

// staleObservedGeneration is the canonical "controller never saw the
// last spec write" signature: status.observedGeneration lags
// metadata.generation. A missing observedGeneration with an empty/absent
// status reads as 0 (never touched by its controller). If status IS
// already populated (len > 0) without status.observedGeneration, or
// carries observedGeneration: 0 alongside populated status.conditions /
// status.phase, the CRD does not implement/populate
// status.observedGeneration — do not fabricate 0 < gen.
func staleObservedGeneration(o *unstructured.Unstructured) bool {
	og, found := kube.NestedNumber(o.Object, "status", "observedGeneration")
	if !found {
		if st, ok := kube.NestedMap(o.Object, "status"); ok && len(st) > 0 {
			return false
		}
		return 0 < o.GetGeneration()
	}
	if og == 0 && hasStatusSignals(o) {
		return false
	}
	return og < o.GetGeneration()
}

// condObservedGenStale checks status.conditions[].observedGeneration for CR
// types that report observedGeneration inside conditions rather than at
// top-level status.observedGeneration (e.g. cert-manager Certificate).
// Absent/empty conditions are handled by noStatusConditions (returns false
// here so never-reconciled objects do not double-fire stale_observed_generation);
// if conditions exist but none carry a populated (>0) observedGeneration
// field, returns false.
func condObservedGenStale(o *unstructured.Unstructured) bool {
	raw, found := kube.NestedSlice(o.Object, "status", "conditions")
	if !found || len(raw) == 0 {
		return false
	}
	hasOG := false
	var maxOG int64
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if og, ok := kube.NestedNumber(m, "observedGeneration"); ok && og > 0 {
			if !hasOG || og > maxOG {
				maxOG = og
			}
			hasOG = true
		}
	}
	if !hasOG {
		return false
	}
	return maxOG < o.GetGeneration()
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
// or empty list means it never picked the object up (operator-watchdog-targets).
func noStatusConditions(o *unstructured.Unstructured) bool {
	conds, found := kube.NestedSlice(o.Object, "status", "conditions")
	return !found || len(conds) == 0
}

// emptyStatusPhase is the same never-reconciled signature for CR
// types that report a status.phase (ArgoCD): an absent/empty phase
// means the operator never touched the object (operator-watchdog-targets).
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
	return !hasStatusSignals(o)
}

// fluxOperatorStaleGen is staleObservedGeneration with the flux-operator
// reconcile brake honored: annotation fluxcd.controlplane.io/reconcile=disabled
// deliberately parks reconciliation — parked objects are not stuck.
func fluxOperatorStaleGen(o *unstructured.Unstructured) bool {
	if o.GetAnnotations()["fluxcd.controlplane.io/reconcile"] == "disabled" {
		return false
	}
	return staleObservedGeneration(o)
}

// farRemediationStuck catches a FenceAgentsRemediation CR that already
// received an initial status (so noStatusAtAll stays false) yet wedged
// mid-remediation or mid-deletion: either DeletionTimestamp is set (stuck
// on fence-agents-remediation.medik8s.io/far-finalizer, e.g. RBAC/watch
// wedge), or NHC stamped remediation.medik8s.io/nhc-timed-out without
// Succeeded=True.
func farRemediationStuck(o *unstructured.Unstructured) bool {
	if o.GetDeletionTimestamp() != nil {
		return true
	}
	if o.GetAnnotations()["remediation.medik8s.io/nhc-timed-out"] == "" {
		return false
	}
	cond, ok := kube.ConditionOf(o.Object, "Succeeded")
	return !ok || cond.Status != "True"
}

// perconaUnpausedStaleGen is staleObservedGeneration with the Percona
// pause brake honored: spec.pause=true (and psmdb's spec.mode=paused)
// parks reconciliation deliberately — paused clusters are parked,
// not stuck (operator-workqueue-watchdog).
func perconaUnpausedStaleGen(o *unstructured.Unstructured) bool {
	if paused, _ := kube.NestedBool(o.Object, "spec", "pause"); paused {
		return false
	}
	if mode, _ := kube.NestedString(o.Object, "spec", "mode"); mode == "paused" {
		return false
	}
	return staleObservedGeneration(o)
}
