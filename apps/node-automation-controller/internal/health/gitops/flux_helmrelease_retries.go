// flux_helmrelease_retries.go — the flux-helmrelease-retries check
// (flux-helmrelease-retries): HelmReleases parked Ready=False past the stuck window
// with a retries-exhausted failure get the reconcile annotation
// triple stamped (requestedAt/forceAt/resetAt) so helm-controller
// runs the release again.
package gitops

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// fluxHRRetriesCheck is the flux-helmrelease-retries Flux HelmRelease
// retries-exhausted remediator.
type fluxHRRetriesCheck struct {
	*probefw.Deps

	//   - hrRetryHealed: "ns/name" → last reconcile-annotation patch —
	//     the 30m per-HelmRelease cooldown for the retries-exhausted
	//     remediator (flux-helmrelease-retries). The requestedAt annotation we stamp is
	//     the durable half across restarts.
	hrRetryHealed state.CooldownSet
}

// newFluxHRRetriesCheck builds the flux-helmrelease-retries check — the constructor
// that used to seed the cooldown map inside the monolithic
// newClusterHealthProber literal; the ledger is zero-value ready.
func NewFluxHRRetriesCheck(d *probefw.Deps) probefw.Check {
	return &fluxHRRetriesCheck{Deps: d}
}

// ---------------------------------------------------------------------------
// flux-helmrelease-retries — flux HelmRelease retries-exhausted remediator.
// ---------------------------------------------------------------------------

const (
	// CheckNameFluxHRRetries is the check's kuberhealthy_check
	// label value — flux-helmrelease-retries; not a ported HealthCheck but reports
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
	// The stamped triple is kube.AnnoFluxRequestedAt /
	// kube.AnnoFluxForceAt / kube.AnnoFluxResetAt — requestedAt asks
	// for a reconcile, forceAt skips the artifact-cache freshness
	// check (same pair the flux CLI `reconcile --with-source`
	// writes), and resetAt clears the exhausted retry counter —
	// helm-controller >= v0.37.0 ignores requestedAt/forceAt on a
	// RetriesExceeded/Stalled HR without it (flux-reset-at).
)

// helmReleaseRetryGVRs are the HelmRelease API versions the check
// probes — v2 is current, v2beta2 the previous storage version; the
// first List that succeeds wins.
var helmReleaseRetryGVRs = kube.HelmReleaseGVRs

// fluxHRFailureReasons are the Ready=False reasons that mean the
// helm action itself failed — combined with the "retries exhausted"
// message substring they cover every spelling helm-controller uses
// once spec.upgrade.remediation.retries is spent (flux-helmrelease-retries).
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
	if r := p.RequireDyn("helmrelease retry check"); r != nil {
		return *r
	}
	now := p.Now()
	p.hrRetryHealed.PruneExpired(now, fluxHRHealCooldown)

	// Find the served HelmRelease version — v2 then v2beta2 through
	// the sweep-memoized reader: each GVR's LIST is paid at most once
	// per cycle, a v2 NoMatch falls through to v2beta2, and a real
	// API failure is preferred over benign misses (kube.ListFirstGVR
	// semantics via probefw.AllUnstructuredFirst).
	hrs, gvr, err := p.AllUnstructuredFirst(ctx, helmReleaseRetryGVRs)
	if err != nil {
		if apierrors.IsNotFound(err) || meta.IsNoMatchError(err) {
			return probefw.Result{Pass: true} // CRD not installed
		}
		return probefw.Result{Infra: fmt.Errorf("list helmreleases: %w", err)}
	}

	var stuck []string
	for i := range hrs {
		hr := &hrs[i]
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
	return probefw.WhyFold(probefw.Section(
		"helmreleases retries-exhausted >=%s: %s",
		stuck, fluxHRStuckMinAge))
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
		// The sweep-memoized unstructured census for this GVR
		// replaces the per-dependency GET — dependsOn chains resolve
		// against the same paged LIST the check already paid for.
		items, err := p.AllUnstructured(ctx, gvr)
		if err != nil {
			return false
		}
		var dep *unstructured.Unstructured
		for i := range items {
			if items[i].GetNamespace() == ns && items[i].GetName() == name {
				dep = &items[i]
				break
			}
		}
		if dep == nil {
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
// HelmRelease unless the 30m cooldown is still warm — the wider of
// the in-RAM ledger and the requestedAt stamp a previous patch (ours
// or `flux reconcile`'s) already left. The preamble is the shared
// persisted-cooldown shape (Deps.HealAllowedPersisted →
// heal.AllowedVPersisted, the sibling kustomization nudge's gate):
// only after the cooldown clears do the maintenance mutex + global
// heal budget evaluate (fail closed) — a reconcile nudge during a
// drain churns the release exactly like any other heal.
//
// The write side is heal.StampPersistedMulti — the source-nudge
// shape, replacing the hand-rolled patch that bypassed the sweep
// overlay: a landed patch is recorded via kube.RecordAnnoPatch so
// same-sweep readers resolve the fresh stamp through
// EffectiveAnno/AnnoTimeCtx instead of the pre-patch census copy,
// the ledger stamp stays delivered-only (a failed patch never
// starts a cooldown), and a re-stamp can never overwrite a warm
// cooldown — the gate above holds the wider-of window before any
// stamp is issued, and StampPersistedMulti's only error source is
// the PATCH itself (the annotation map is three RFC3339 strings —
// its marshal cannot fail), so no grant is ever burned before the
// API send and a failed patch keeps its spent grant (the
// attempted-mutation rule).
func (p *fluxHRRetriesCheck) maybePatchHRRetry(ctx context.Context, log logr.Logger,
	gvr schema.GroupVersionResource, hr *unstructured.Unstructured,
	key string, now time.Time) {
	ck := probefw.SelfHealKey(CheckNameFluxHRRetries, key)
	proceed, unverifiable := p.HealAllowedPersisted(ctx, log,
		&p.hrRetryHealed, hr, kube.AnnoFluxRequestedAt, ck,
		fluxHRHealCooldown, now)
	if unverifiable {
		metrics.IncError(p.Name)
		return
	}
	if !proceed {
		return
	}
	if err := heal.StampPersistedMulti(ctx, hr,
		func(ctx context.Context, data []byte) error {
			_, err := p.Dyn.Resource(gvr).Namespace(hr.GetNamespace()).
				Patch(ctx, hr.GetName(), types.MergePatchType, data,
					metav1.PatchOptions{})
			return err
		},
		// requestedAt asks for a reconcile, forceAt skips the
		// artifact-cache freshness check (same pair the flux CLI
		// `reconcile --with-source` writes), and resetAt clears the
		// exhausted retry counter — helm-controller >= v0.37.0
		// ignores requestedAt/forceAt on a RetriesExceeded/Stalled
		// HR without it (flux-reset-at). One atomic merge patch, the
		// same triple helmrelease-unlocker stamps.
		[]string{kube.AnnoFluxRequestedAt, kube.AnnoFluxForceAt,
			kube.AnnoFluxResetAt},
		&p.hrRetryHealed, ck, now); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "helmrelease retry patch failed", "hr", key)
		return
	}
	log.Info("patched helmrelease reconcile annotations",
		"hr", key, "requestedAt", now.UTC().Format(time.RFC3339))
}
