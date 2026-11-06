package gitops

import (
	"context"
	"errors"
	"fmt"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// fluxHRRetriesCheck is the W10-CP4 Flux HelmRelease
// retries-exhausted remediator.
type fluxHRRetriesCheck struct {
	*probefw.Deps

	//   - hrRetryHealed: "ns/name" → last reconcile-annotation patch —
	//     the 30m per-HelmRelease cooldown for the retries-exhausted
	//     remediator (W10-CP4). The requestedAt annotation we stamp is
	//     the durable half across restarts.
	hrRetryHealed state.CooldownSet
}

// newFluxHRRetriesCheck builds the W10-CP4 check — the constructor
// that used to seed the cooldown map inside the monolithic
// newClusterHealthProber literal; the ledger is zero-value ready.
func NewFluxHRRetriesCheck(d *probefw.Deps) probefw.Check {
	return &fluxHRRetriesCheck{Deps: d}
}

// ---------------------------------------------------------------------------
// W10-CP4 — flux HelmRelease retries-exhausted remediator.
// ---------------------------------------------------------------------------

const (
	// CheckNameFluxHRRetries is the check's kuberhealthy_check
	// label value — W10-CP4; not a ported HealthCheck but reports
	// under its own check name so the generic FAIL alerting path
	// covers it.
	CheckNameFluxHRRetries = "flux-helmrelease-retries"
	// fluxHRStuckMinAge: a Ready=False HelmRelease must hold the
	// failure this long before it counts as stuck — transient helm
	// errors self-heal inside the controller's own retry backoff.
	fluxHRStuckMinAge = 15 * time.Minute
	// fluxHRHealCooldown bounds reconcile-annotation patches to one
	// per HelmRelease per 30m.
	fluxHRHealCooldown = 30 * time.Minute
	// The stamped pair is kube.AnnoFluxRequestedAt /
	// kube.AnnoFluxForceAt — requestedAt asks for a reconcile,
	// forceAt skips the artifact-cache freshness check (same pair
	// the flux CLI `reconcile --with-source` writes).
)

// helmReleaseRetryGVRs are the HelmRelease API versions the check
// probes — v2 is current, v2beta2 the previous storage version; the
// first List that succeeds wins.
var helmReleaseRetryGVRs = kube.HelmReleaseGVRs

// fluxHRFailureReasons are the Ready=False reasons that mean the
// helm action itself failed — combined with the "retries exhausted"
// message substring they cover every spelling helm-controller uses
// once spec.upgrade.remediation.retries is spent (W10-CP4).
var fluxHRFailureReasons = map[string]bool{
	"InstallFailed":    true,
	"UpgradeFailed":    true,
	"RetriesExhausted": true,
	"RetriesExceeded":  true,
}

// checkFluxHelmReleaseRetries detects HelmReleases parked at
// Ready=False past fluxHRStuckMinAge whose failure reads as
// retries-exhausted, and — when every spec.dependsOn HelmRelease is
// itself Ready — nudges the object back to work by stamping the
// reconcile.fluxcd.io/requestedAt+forceAt annotations (30m per-HR
// cooldown, wider of the in-RAM ledger and the requestedAt stamp we
// leave behind). The check FAILs while qualifying HRs exist —
// remediation is best-effort, detection is the contract.
func (p *fluxHRRetriesCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	if p.Dyn == nil {
		return probefw.Result{Infra: errors.New(
			"no dynamic client — helmrelease retry check unverifiable")}
	}
	now := p.Now()

	// Find the served HelmRelease version — try v2 then v2beta2.
	var gvr schema.GroupVersionResource
	var hrs *unstructured.UnstructuredList
	var listErr error
	for _, g := range helmReleaseRetryGVRs {
		l, err := p.Dyn.Resource(g).List(ctx, metav1.ListOptions{})
		if err == nil {
			gvr, hrs = g, l
			break
		}
		if !apierrors.IsNotFound(err) && !meta.IsNoMatchError(err) {
			listErr = err
		}
	}
	if hrs == nil {
		if listErr != nil {
			return probefw.Result{Infra: fmt.Errorf(
				"list helmreleases: %w", listErr)}
		}
		return probefw.Result{Pass: true} // CRD not installed
	}

	var stuck []string
	for i := range hrs.Items {
		hr := &hrs.Items[i]
		if suspended, _ := kube.NestedBool(
			hr.Object, "spec", "suspend"); suspended {
			continue
		}
		status, reason, message, since, ok := fluxHRReadyCondition(hr)
		if !ok || status != "False" {
			continue
		}
		if !fluxHRFailureReasons[reason] &&
			!strings.Contains(strings.ToLower(message), "retries exhausted") {
			continue
		}
		// The failure must persist — a HR still inside its first
		// retry window is working as designed. No transition
		// timestamp → cannot prove the 15m window; stay quiet
		// rather than remediate blind.
		if since.IsZero() || now.Sub(since) < fluxHRStuckMinAge {
			continue
		}
		key := hr.GetNamespace() + "/" + hr.GetName()
		stuck = append(stuck, key)

		// Only remediate once every upstream dependsOn
		// HelmRelease is Ready — patching a HR whose dependency is
		// itself broken just re-fails on the same wall.
		if !p.fluxHRDepsReady(ctx, gvr, hr) {
			continue
		}
		p.maybePatchHRRetry(ctx, log, gvr, hr, key, now)
	}
	if len(stuck) > 0 {
		return probefw.Result{Why: fmt.Sprintf(
			"helmreleases retries-exhausted >=%s: %s",
			fluxHRStuckMinAge, strings.Join(stuck, ", "))}
	}
	return probefw.Result{Pass: true}
}

// fluxHRReadyCondition extracts the Ready condition's status, reason,
// message and lastTransitionTime from a HelmRelease. ok=false when no
// Ready condition exists at all.
func fluxHRReadyCondition(hr *unstructured.Unstructured) (status, reason, message string, since time.Time, ok bool) {
	c, ok := kube.ConditionOf(hr.Object, "Ready")
	if !ok {
		return "", "", "", time.Time{}, false
	}
	return c.Status, c.Reason, c.Message, c.LastTransitionTime, true
}

// fluxHRDepsReady reports whether every spec.dependsOn HelmRelease
// reference resolves to a Ready=True object. A missing or unreadable
// dependency fails closed — never remediate on an unverifiable chain.
func (p *fluxHRRetriesCheck) fluxHRDepsReady(ctx context.Context,
	gvr schema.GroupVersionResource, hr *unstructured.Unstructured) bool {
	deps, found := kube.NestedSlice(hr.Object, "spec", "dependsOn")
	if !found {
		return true // no dependsOn — vacuously ready
	}
	for _, d := range deps {
		m, ok := d.(map[string]any)
		if !ok {
			return false
		}
		name, _ := m["name"].(string)
		if name == "" {
			return false
		}
		ns, _ := m["namespace"].(string)
		if ns == "" {
			ns = hr.GetNamespace()
		}
		dep, err := p.Dyn.Resource(gvr).Namespace(ns).
			Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false
		}
		if st, _, _ := fluxHRReadyStrings(dep); st != "True" {
			return false
		}
	}
	return true
}

// fluxHRReadyStrings is the status-only half of fluxHRReadyCondition
// for dependency checks.
func fluxHRReadyStrings(obj *unstructured.Unstructured) (status, reason, message string) {
	c, ok := kube.ConditionOf(obj.Object, "Ready")
	if !ok {
		return "", "", ""
	}
	return c.Status, c.Reason, c.Message
}

// maybePatchHRRetry stamps the reconcile annotations on a stuck
// HelmRelease unless the 30m cooldown (in-RAM ledger OR the
// requestedAt stamp a previous patch — ours or an operator's —
// already left) is still warm.
func (p *fluxHRRetriesCheck) maybePatchHRRetry(ctx context.Context, log logr.Logger,
	gvr schema.GroupVersionResource, hr *unstructured.Unstructured,
	key string, now time.Time) {
	if p.hrRetryHealed.CooledDown(key, fluxHRHealCooldown, now) {
		return
	}
	// The requestedAt annotation is the durable half: a stamp younger
	// than the cooldown — whether we wrote it or `flux reconcile`
	// did — means a reconcile is already queued.
	if t, ok := kube.AnnoTime(hr, kube.AnnoFluxRequestedAt); ok &&
		now.Sub(t) < fluxHRHealCooldown {
		return
	}
	token := now.UTC().Format(time.RFC3339)
	patch, err := kube.MergePatchAnnos(map[string]any{
		kube.AnnoFluxRequestedAt: token,
		kube.AnnoFluxForceAt:     token,
	})
	if err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "marshal hr retry patch failed", "hr", key)
		return
	}
	if _, err := p.Dyn.Resource(gvr).Namespace(hr.GetNamespace()).
		Patch(ctx, hr.GetName(), types.MergePatchType, patch,
			metav1.PatchOptions{}); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "helmrelease retry patch failed", "hr", key)
		return
	}
	p.hrRetryHealed.Stamp(key, now)
	log.Info("patched helmrelease reconcile annotations",
		"hr", key, "requestedAt", token)
}
