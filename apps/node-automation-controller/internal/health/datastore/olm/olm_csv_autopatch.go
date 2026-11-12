// olm_csv_autopatch.go — the olm-csv-autopatch durable-patch duties of the
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
package olm

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

const (
	// olmInstallPlanApproveMinAge is how long an everest InstallPlan
	// may sit unapproved before the check approves it — long enough
	// that a plan mid-resolution is never touched.
	olmInstallPlanApproveMinAge = 15 * time.Minute

	// olmInstallPlanApproveCooldown / olmCSVPatchCooldown bound the
	// two write-heals below to one write per object per 30m — both
	// run through the maintenance mutex + heal budget like every
	// other write-heal, and the cooldown keeps an OLM flip-flop from
	// spending a budget grant per sweep. 30m matches the flux/
	// argocd annotation-nudge cooldowns.
	olmInstallPlanApproveCooldown = 30 * time.Minute
	olmCSVPatchCooldown           = 30 * time.Minute

	// olmInstallPlanApproveAnno / olmCSVPatchHealAnno persist the
	// last approve / durable-spec patch moment on the InstallPlan /
	// CSV the heal acted on — the restart-proof half of the 30m
	// cooldowns (HealAllowedPersisted reads them via kube.AnnoTime).
	// Kept local like olmInstallPlanGVR: single-writer stamps, and
	// the shared passiontech.dev/last-* home (kube/annos.go) is
	// outside this check's ownership.
	olmInstallPlanApproveAnno = "passiontech.dev/last-installplan-approve"
	olmCSVPatchHealAnno       = "passiontech.dev/last-olm-csv-spec-patch"

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
// upgrade re-asserting the upstream bundle). The write is gated like
// every other write-heal (Deps.HealAllowedPersisted →
// heal.AllowedVPersisted): the cooldown is the wider of the in-RAM
// ledger and the passiontech.dev/last-olm-csv-spec-patch stamp the
// patch itself leaves on the CSV, and only after it clears do the
// maintenance mutex + global heal budget evaluate (fail closed).
func (p *olmHealthCheck) autoPatchOperatorCSVs(ctx context.Context,
	log logr.Logger, now time.Time) {

	csvs, err := p.AllUnstructured(ctx, olmCSVGVR)
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		return // OLM not installed (or its CRDs absent — same quiet skip)
	case err != nil:
		metrics.IncError(p.Name)
		log.Info("WARN: olm csv auto-patch — list failed", "error", err)
		return
	}
	for i := range csvs {
		csv := &csvs[i]
		// The ensure/strip mutators write through unstructured
		// SetNested* — run them on a CLONE: csvs is the sweep's
		// memoized census, and mutating csv.Object in place would
		// corrupt every sibling reader (and leave phantom spec
		// behind when the heal gate below refuses the patch).
		work := csv.DeepCopy()
		var changed bool
		switch {
		case strings.HasPrefix(csv.GetName(), "argocd-operator."):
			changed = ensureArgocdOperatorProbes(work.Object)
		case strings.HasPrefix(csv.GetName(), "node-maintenance-operator."):
			changed = stripManagerLeaderElect(work.Object)
		}
		if !changed {
			continue
		}
		// Gate: per-CSV cooldown + persisted CSV stamp + maintenance
		// mutex (memoized on the Deps-wide verdict), fail closed on
		// unverifiable. Drift that re-appears mid-cooldown (OLM
		// re-asserting the bundle) waits out the window — an OLM
		// upgrade is exactly when the mutex/budget protection is for.
		key := csv.GetNamespace() + "/" + csv.GetName()
		proceed, unverifiable := p.HealAllowedPersisted(ctx, log,
			&p.csvPatched, csv, olmCSVPatchHealAnno, key,
			olmCSVPatchCooldown, now)
		if unverifiable {
			metrics.IncError(p.Name)
			continue
		}
		if !proceed {
			continue
		}
		// SSA ping-pong defense: a Git-applied CSV (a kustomize-
		// controller manager on the object) re-asserts the Git spec
		// every reconcile — the deployments restore past the loop
		// threshold is the Heal-Revert Loop. Skip + report; the
		// spec belongs in Git.
		if !heal.FluxPatchGate("csv", csv, key, now) {
			// Gate proceeded (grant consumed) but the revert-loop
			// guard refuses the write — no patch executes, so the
			// grant goes back (refund-on-skip contract).
			heal.RefundGrant(now)
			log.Info("skip heal: Flux Heal-Revert Loop detected — olm csv spec patch deferred",
				"csv", key)
			continue
		}
		// Patch (not Update): the controller's RBAC on
		// clusterserviceversions is get/list/patch — an Update call
		// would 403 every sweep. The merge patch carries ONLY the
		// subtree the autopatch mutates (spec.install.spec.deployments
		// — the array every mutator above writes back): shipping the
		// whole listed spec would fold every stale-snapshot key
		// (scalars, other arrays) back over the live object,
		// reverting OLM writes that landed in the List→Patch window.
		// RFC 7386 merges maps recursively and replaces arrays
		// wholesale, so sibling spec keys survive untouched and the
		// mutated deployments array lands in full. The cooldown stamp
		// rides the SAME merge patch (metadata.annotations folds into
		// the existing map) so one write lands the heal and its
		// persisted cooldown together.
		deployments, _ := kube.NestedSlice(
			work.Object, "spec", "install", "spec", "deployments")
		// metadata.resourceVersion pins the write — the listed
		// snapshot's deployments array goes back wholesale, so an
		// OLM write landing in the List→Patch window (mid-upgrade
		// bundle re-assertion) becomes a 409 conflict, retried
		// next sweep against a fresh read, instead of a silent
		// revert of the newer spec.
		patch, err := json.Marshal(map[string]any{
			"spec": map[string]any{
				"install": map[string]any{
					"spec": map[string]any{
						"deployments": deployments,
					},
				},
			},
			"metadata": map[string]any{
				"resourceVersion": csv.GetResourceVersion(),
				"annotations": map[string]any{
					olmCSVPatchHealAnno: now.UTC().Format(time.RFC3339)}},
		})
		if err != nil {
			metrics.IncError(p.Name)
			// Marshal failed BEFORE the patch was attempted — no
			// mutation executed, hand the grant back.
			heal.RefundGrant(now)
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
		// Record the annotation half of the delivered patch on the
		// sweep overlay — a later check reading this CSV's
		// olmCSVPatchHealAnno through EffectiveAnno/AnnoTimeCtx sees
		// the stamp this sweep instead of the pre-patch snapshot.
		kube.RecordAnnoPatch(ctx, csv, patch)
		p.csvPatched.Stamp(key, now) // delivered-only contract
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
	deployments, found := kube.NestedSlice(
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
		containers, found := kube.NestedSlice(
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
	deployments, found := kube.NestedSlice(
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
		containers, found := kube.NestedSlice(
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
			for i, a := range args {
				if s, ok := a.(string); ok &&
					(s == "--leader-elect" || s == "--leader-elect=true") {
					stripped = true
					continue
				}
				// Two-arg form: "--leader-elect false" strips the
				// flag AND its value token — leaving the bare
				// "false" would hand the manager a stray
				// positional arg. Only a literal true/false is
				// consumed; a following real flag is kept.
				if stripped && i > 0 {
					if prev, _ := args[i-1].(string); prev == "--leader-elect" {
						if s, ok := a.(string); ok && (s == "true" || s == "false") {
							continue
						}
					}
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
		// The approve and its cooldown stamp land in ONE merge patch
		// (RFC 7386 folds metadata.annotations in, sibling keys
		// survive) — a delivered approve is never un-cooled by a
		// failed second write.
		patch, err := json.Marshal(map[string]any{
			"spec": map[string]any{"approved": true},
			"metadata": map[string]any{"annotations": map[string]any{
				olmInstallPlanApproveAnno: now.UTC().Format(time.RFC3339)}},
		})
		if err != nil {
			metrics.IncError(p.Name)
			// Marshal failed BEFORE the patch was attempted — no
			// mutation executed, hand the grant back.
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
