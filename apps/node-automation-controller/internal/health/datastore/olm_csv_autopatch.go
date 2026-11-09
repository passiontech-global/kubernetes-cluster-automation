// olm_csv_autopatch.go — the W20-CP3 durable-patch duties of the
// olm-subscription-health check: two CSV spec mutations that used to
// live only as manual in-cluster `kubectl patch csv` notes in
// infrastructure/base/operators/*.yaml, plus the everest
// InstallPlan auto-approver.
//
//   - argocd-operator.* CSVs: the upstream bundle's probes kill the
//     manager before it finishes cache sync when the apiserver is
//     slow (incident documented in argocd-operator.yaml — the manual
//     patch added a ~30m startupProbe and initialDelaySeconds>=60).
//     OLM re-asserts the bundle spec on every CSV upgrade, so the
//     patch must be re-applied each sweep — same re-heal posture as
//     the medik8s boot fail-open sweep.
//   - node-maintenance-operator.* CSVs: the bundle passes
//     --leader-elect to a manager that exits silently on lease loss
//     (no os.Exit(1) path) — the flag is stripped from args.
//   - InstallPlans in the everest namespace: OpenEverest creates its
//     DB-operator Subscriptions with installPlanApproval: Manual and
//     nobody reviews them, so plans sit RequiresApproval forever.
//     Past the threshold the check approves them. The medik8s
//     subscriptions' Manual approval on production is an intentional
//     human gate — it is deliberately NOT in scope.
package datastore

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
)

const (
	// olmInstallPlanApproveMinAge is how long an everest InstallPlan
	// may sit unapproved before the check approves it — long enough
	// that a plan mid-resolution is never touched.
	olmInstallPlanApproveMinAge = 15 * time.Minute

	// olmArgocdStartupFailureThreshold/Period reproduce the manual
	// patch's startupProbe shape: 10s period x 180 failures ~ 30m of
	// startup runway for the slow-cache-sync manager.
	olmArgocdStartupPeriodSeconds    = int64(10)
	olmArgocdStartupFailureThreshold = int64(180)

	// olmLivenessMinInitialDelay is the floor the plan puts on
	// livenessProbe.initialDelaySeconds once a startupProbe exists.
	olmLivenessMinInitialDelay = int64(60)
)

// olmInstallPlanGVR is the operators.coreos.com/v1alpha1 InstallPlan
// the everest auto-approver patches. Defined beside the CSV/Subscription
// GVRs in olm_subscription_health.go's neighborhood — kept local like
// them (the check is the only consumer).
var olmInstallPlanGVR = schema.GroupVersionResource{
	Group: "operators.coreos.com", Version: "v1alpha1", Resource: "installplans"}

// autoPatchOperatorCSVs re-applies the durable CSV spec patches the
// operators/*.yaml manifests document as manual in-cluster edits.
// Each mutation is idempotent — a CSV already carrying the patch is
// left untouched, so the sweep only writes on real drift (OLM CSV
// upgrade re-asserting the upstream bundle).
func (p *olmHealthCheck) autoPatchOperatorCSVs(ctx context.Context,
	log logr.Logger) {

	csvs, err := p.AllUnstructured(ctx, olmCSVGVR)
	switch {
	case apierrors.IsNotFound(err):
		return // OLM not installed
	case err != nil:
		metrics.IncError(p.Name)
		log.Info("WARN: olm csv auto-patch — list failed", "error", err)
		return
	}
	for i := range csvs {
		csv := &csvs[i]
		var changed bool
		switch {
		case strings.HasPrefix(csv.GetName(), "argocd-operator."):
			changed = ensureArgocdOperatorProbes(csv.Object)
		case strings.HasPrefix(csv.GetName(), "node-maintenance-operator."):
			changed = stripManagerLeaderElect(csv.Object)
		}
		if !changed {
			continue
		}
		if _, err := p.Dyn.Resource(olmCSVGVR).
			Namespace(csv.GetNamespace()).Update(ctx, csv,
			metav1.UpdateOptions{}); err != nil {
			metrics.IncError(p.Name)
			log.Error(err, "olm csv auto-patch update failed",
				"csv", csv.GetNamespace()+"/"+csv.GetName())
			continue
		}
		log.Info("PATCH: olm csv durable spec patch re-applied",
			"csv", csv.GetNamespace()+"/"+csv.GetName())
	}
}

// ensureArgocdOperatorProbes walks spec.install.spec.deployments[].
// spec.template.spec.containers[] for the manager container and applies
// the documented patch: a startupProbe cloned from the livenessProbe
// (10s x 180 ~ 30m runway) when absent, and
// livenessProbe.initialDelaySeconds raised to >=60. Returns true when
// the object was mutated. A manager with NO livenessProbe gets no
// invented probe — there is no safe handler to clone.
func ensureArgocdOperatorProbes(obj map[string]any) bool {
	deployments, found, _ := unstructured.NestedSlice(
		obj, "spec", "install", "spec", "deployments")
	if !found {
		return false
	}
	changed := false
	for _, d := range deployments {
		dep, ok := d.(map[string]any)
		if !ok {
			continue
		}
		containers, found, _ := unstructured.NestedSlice(
			dep, "spec", "template", "spec", "containers")
		if !found {
			continue
		}
		for _, c := range containers {
			ctr, ok := c.(map[string]any)
			if !ok || ctr["name"] != "manager" {
				continue
			}
			if ensureManagerStartupProbe(ctr) {
				changed = true
			}
			if ensureLivenessInitialDelay(ctr) {
				changed = true
			}
		}
	}
	return changed
}

// ensureManagerStartupProbe clones the container's livenessProbe into
// startupProbe (periodSeconds=10, failureThreshold=180 — the ~30m
// startup runway) when startupProbe is absent. Returns true on write.
func ensureManagerStartupProbe(ctr map[string]any) bool {
	if _, ok := ctr["startupProbe"]; ok {
		return false
	}
	lp, ok := ctr["livenessProbe"].(map[string]any)
	if !ok {
		return false // no handler to clone — never invent one
	}
	probe := make(map[string]any, len(lp)+2)
	for k, v := range lp {
		probe[k] = v
	}
	probe["periodSeconds"] = olmArgocdStartupPeriodSeconds
	probe["failureThreshold"] = olmArgocdStartupFailureThreshold
	ctr["startupProbe"] = probe
	return true
}

// ensureLivenessInitialDelay raises livenessProbe.initialDelaySeconds
// to the 60s floor when the probe exists but starts sooner. Returns
// true on write.
func ensureLivenessInitialDelay(ctr map[string]any) bool {
	lp, ok := ctr["livenessProbe"].(map[string]any)
	if !ok {
		return false
	}
	delay, _ := lp["initialDelaySeconds"].(float64)
	if int64(delay) >= olmLivenessMinInitialDelay {
		return false
	}
	lp["initialDelaySeconds"] = olmLivenessMinInitialDelay
	return true
}

// stripManagerLeaderElect removes --leader-elect /
// --leader-elect=true from every deployment's manager container args —
// the node-maintenance-operator manager treats lease loss as a clean
// exit instead of crashing into re-election, so the flag must not
// survive a CSV upgrade. Returns true when args were mutated.
func stripManagerLeaderElect(obj map[string]any) bool {
	deployments, found, _ := unstructured.NestedSlice(
		obj, "spec", "install", "spec", "deployments")
	if !found {
		return false
	}
	changed := false
	for _, d := range deployments {
		dep, ok := d.(map[string]any)
		if !ok {
			continue
		}
		containers, found, _ := unstructured.NestedSlice(
			dep, "spec", "template", "spec", "containers")
		if !found {
			continue
		}
		for _, c := range containers {
			ctr, ok := c.(map[string]any)
			if !ok || ctr["name"] != "manager" {
				continue
			}
			args, ok := ctr["args"].([]any)
			if !ok {
				continue
			}
			kept := args[:0]
			for _, a := range args {
				if s, ok := a.(string); ok &&
					(s == "--leader-elect" || s == "--leader-elect=true") {
					changed = true
					continue
				}
				kept = append(kept, a)
			}
			if changed {
				ctr["args"] = kept
			}
		}
	}
	return changed
}

// autoApproveStuckInstallPlans approves everest-namespace InstallPlans
// that have sat unapproved past olmInstallPlanApproveMinAge — the
// OpenEverest DB-operator subscriptions carry
// installPlanApproval: Manual and no human reviews them, so their
// plans would otherwise wait forever. A plan carrying a
// ResolutionFailed condition is left alone: approving a broken plan
// just moves the failure later. Production's intentional Manual gate
// on the medik8s subscriptions lives in the operators namespace and
// is out of scope by construction.
func (p *olmHealthCheck) autoApproveStuckInstallPlans(ctx context.Context,
	log logr.Logger, now time.Time) {

	plans, err := p.AllUnstructured(ctx, olmInstallPlanGVR)
	switch {
	case apierrors.IsNotFound(err):
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
		approval, _, _ := unstructured.NestedString(plan.Object,
			"spec", "approval")
		if approval == "Approved" {
			continue
		}
		if now.Sub(plan.GetCreationTimestamp().Time) <
			olmInstallPlanApproveMinAge {
			continue
		}
		if resolutionFailed(plan.Object) {
			continue
		}
		patch, err := json.Marshal(map[string]any{
			"spec": map[string]any{"approval": "Approved"}})
		if err != nil {
			metrics.IncError(p.Name)
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
		log.Info("PATCH: everest installplan auto-approved",
			"installplan", plan.GetNamespace()+"/"+plan.GetName())
	}
}

// resolutionFailed reports whether the InstallPlan's status
// conditions carry ResolutionFailed=True — approving a plan whose
// resolution already failed changes nothing but the label.
func resolutionFailed(obj map[string]any) bool {
	conds, found, _ := unstructured.NestedSlice(obj,
		"status", "conditions")
	if !found {
		return false
	}
	for _, c := range conds {
		m, ok := c.(map[string]any)
		if !ok {
			continue
		}
		typ, _, _ := unstructured.NestedString(m, "type")
		status, _, _ := unstructured.NestedString(m, "status")
		if typ == "ResolutionFailed" && status == "True" {
			return true
		}
	}
	return false
}
