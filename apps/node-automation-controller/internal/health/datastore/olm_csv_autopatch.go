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
		// Patch (not Update): the controller's RBAC on
		// clusterserviceversions is get/list/patch — an Update call
		// would 403 every sweep. A merge patch carrying the WHOLE
		// mutated spec is equivalent here because the unstructured
		// object already holds the complete spec — nothing is
		// invented or dropped.
		spec, _ := csv.Object["spec"].(map[string]any)
		patch, err := json.Marshal(map[string]any{"spec": spec})
		if err != nil {
			metrics.IncError(p.Name)
			continue
		}
		if _, err := p.Dyn.Resource(olmCSVGVR).
			Namespace(csv.GetNamespace()).Patch(ctx, csv.GetName(),
			types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
			metrics.IncError(p.Name)
			log.Error(err, "olm csv auto-patch failed",
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
		// NestedSlice returns a DEEP COPY — mutations on dep/ctr
		// above live only inside `deployments`. Write the slice
		// back or the patch payload below ships the unmutated spec.
		_ = unstructured.SetNestedSlice(dep, containers,
			"spec", "template", "spec", "containers")
	}
	if changed {
		_ = unstructured.SetNestedSlice(obj, deployments,
			"spec", "install", "spec", "deployments")
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
	delay, ok := unstructuredNumber(lp["initialDelaySeconds"])
	if ok && delay >= float64(olmLivenessMinInitialDelay) {
		return false
	}
	lp["initialDelaySeconds"] = olmLivenessMinInitialDelay
	return true
}

// unstructuredNumber reads a JSON number out of an unstructured
// field. The dynamic client's decoder preserves integers as int64 —
// a bare .(float64) assertion silently fails on them, which made
// every already-patched CSV look unpatched and PATCH-looped the API
// server every sweep.
func unstructuredNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case int64:
		return float64(n), true
	case float64:
		return n, true
	case int:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
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
			kept := make([]any, 0, len(args))
			stripped := false
			for _, a := range args {
				if s, ok := a.(string); ok &&
					(s == "--leader-elect" || s == "--leader-elect=true") {
					stripped = true
					continue
				}
				kept = append(kept, a)
			}
			if stripped {
				changed = true
				ctr["args"] = kept
			}
		}
		// Same NestedSlice deep-copy contract as
		// ensureArgocdOperatorProbes — write containers back into
		// dep, then dep back into obj below.
		_ = unstructured.SetNestedSlice(dep, containers,
			"spec", "template", "spec", "containers")
	}
	if changed {
		_ = unstructured.SetNestedSlice(obj, deployments,
			"spec", "install", "spec", "deployments")
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
