package olm

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// autoApproveStuckInstallPlans approves everest-namespace InstallPlans
// that have sat unapproved past olmInstallPlanApproveMinAge — the
// OpenEverest DB-operator subscriptions carry
// installPlanApproval: Manual and no human reviews them, so their
// plans would otherwise wait forever. Approval is granted via
// spec.approved=true (spec.approval is the Automatic|Manual policy
// enum, not the granted state — patching it is a silent no-op), so
// an already-approved plan is skipped and the guard reads the same
// field the patch writes. A plan carrying a ResolutionFailed
// condition is left alone: approving a broken plan just moves the
// failure later. Production's intentional Manual gate on the medik8s
// subscriptions lives in the operators namespace and is out of scope
// by construction. The write is gated like every other write-heal
// (Deps.HealAllowedPersisted → heal.AllowedVPersisted): per-plan 30m
// cooldown, the wider of the in-RAM ledger and the
// passiontech.dev/last-installplan-approve stamp the patch leaves,
// then maintenance mutex + heal budget, fail closed on unverifiable.
func (p *olmHealthCheck) autoApproveStuckInstallPlans(ctx context.Context,
	log logr.Logger, now time.Time) {

	plans, err := p.AllUnstructured(ctx, olmInstallPlanGVR)
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		return
	case err != nil:
		metrics.IncError(p.Name)
		log.Info("WARN: olm installplan scan — list failed", "error", err)
		return
	}
	for i := range plans {
		plan := &plans[i]
		if plan.GetNamespace() != "everest" {
			continue
		}
		if approved, _ := kube.NestedBool(
			plan.Object, "spec", "approved"); approved {
			continue // already approved — nothing to heal
		}
		if now.Sub(plan.GetCreationTimestamp().Time) <
			olmInstallPlanApproveMinAge {
			continue
		}
		if resolutionFailed(plan.Object) {
			continue
		}
		// A Failed phase is terminal for this plan revision —
		// approving it again just re-asserts spec.approved every
		// sweep while the operator waits for a human (or a new
		// Subscription revision) to resolve the failure.
		if phase, _ := kube.NestedString(
			plan.Object, "status", "phase"); phase == "Failed" {
			continue
		}
		key := plan.GetNamespace() + "/" + plan.GetName()
		proceed, unverifiable := p.HealAllowedPersisted(ctx, log,
			&p.plansApproved, plan, olmInstallPlanApproveAnno, key,
			olmInstallPlanApproveCooldown, now)
		if unverifiable {
			metrics.IncError(p.Name)
			continue
		}
		if !proceed {
			continue
		}
		patch, err := json.Marshal(map[string]any{
			"spec": map[string]any{"approved": true},
			"metadata": map[string]any{"annotations": map[string]any{
				olmInstallPlanApproveAnno: now.UTC().Format(time.RFC3339)}},
		})
		if err != nil {
			metrics.IncError(p.Name)
			heal.RefundGrant(now)
			continue
		}
		if _, err := p.Dyn.Resource(olmInstallPlanGVR).
			Namespace(plan.GetNamespace()).Patch(ctx, plan.GetName(),
			types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
			metrics.IncError(p.Name)
			log.Error(err, "olm installplan auto-approve failed",
				"installplan", plan.GetNamespace()+"/"+plan.GetName())
			continue
		}
		kube.RecordAnnoPatch(ctx, plan, patch)
		p.plansApproved.Stamp(key, now) // delivered-only contract
		log.Info("PATCH: everest installplan auto-approved",
			"installplan", plan.GetNamespace()+"/"+plan.GetName())
	}
}

// resolutionFailed reports whether the InstallPlan's status
// conditions carry ResolutionFailed=True — approving a plan whose
// resolution already failed changes nothing but the label.
func resolutionFailed(obj map[string]any) bool {
	conds, found := kube.NestedSlice(obj,
		"status", "conditions")
	if !found {
		return false
	}
	for _, c := range conds {
		m, ok := c.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := kube.NestedString(m, "type")
		status, _ := kube.NestedString(m, "status")
		if typ == "ResolutionFailed" && status == "True" {
			return true
		}
	}
	return false
}
