// flux_kustomization_health.go — the flux-kustomization-health check
// (flux-stuck): Flux Kustomizations parked Ready=False for >=15m emit
// the stuck gauge; when every spec.dependsOn is Ready=True and the
// failure is ArtifactFailed/SourceNotReady — or HealthCheckFailed
// while the applied workloads are actually Ready — the check stamps
// reconcile.fluxcd.io/requestedAt (30m cooldown, maintenance-mutex +
// heal-budget gated) so kustomize-controller retries the reconcile
// and unfreezes the dependsOn domino chain.
//
// Parity note: the HelmRelease twin of this signature is
// flux-helmrelease-retries (flux-helmrelease-retries); the domino incident this covers
// is a stuck `wait: true` Kustomization leaving every downstream
// Kustomization parked at DependencyNotReady.
//
// File layout: this file holds the module contract, the check struct
// and the Run sweep pipeline; flux_kustomization_nudge.go the
// requestedAt/source-artifact nudges and their gates,
// flux_kustomization_ready.go the inventory workload-readiness
// corroboration.
package gitops

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// fluxKustomizationHealthCheck is the flux-stuck Flux Kustomization
// stuck detector + reconcile nudger.
type fluxKustomizationHealthCheck struct {
	*probefw.Deps

	// reconcileHealed is the in-RAM half of the 30m per-Kustomization
	// nudge cooldown — the durable half is the requestedAt stamp the
	// patch leaves behind (heal.PersistedCooledDown reads the wider
	// of the two, so `flux reconcile` stamps count too).
	reconcileHealed state.CooldownSet
	// sourceNudgeHealed is the same cooldown shape for the flux-source-artifact-heal
	// source-side nudge — keyed per source object, since one source
	// artifact failure fans out to every consumer Kustomization.
	sourceNudgeHealed state.CooldownSet
	// emitted is the emitted-gauge ledger — a tuple that stops being
	// reported gets DeleteLabelValues'd rather than leaking a stale 1.
	emitted state.GaugeLedger[string]
}

// NewFluxKustomizationHealthCheck builds the flux-stuck check — its
// state is the cooldown/gauge ledgers (zero value usable); the
// maintenance verdict rides the shared Deps memo.
func NewFluxKustomizationHealthCheck(d *probefw.Deps) probefw.Check {
	return &fluxKustomizationHealthCheck{Deps: d}
}

const (
	// CheckNameFluxKustomizationHealth is the check's
	// kuberhealthy_check label value — flux-stuck; not a ported
	// HealthCheck but reports under its own check name so the
	// generic FAIL alerting path covers it.
	CheckNameFluxKustomizationHealth = "flux-kustomization-health"
	// fluxKustStuckMinAge: a Ready=False Kustomization must hold the
	// failure this long before it counts as stuck — the
	// kustomize-controller's own retry backoff resolves transients
	// inside the window.
	fluxKustStuckMinAge = 15 * time.Minute
	// fluxKustHealCooldown bounds requestedAt patches to one per
	// Kustomization per 30m.
	fluxKustHealCooldown = 30 * time.Minute
	// sourceNudgeFreshWindow mirrors helmrelease-unlocker's per-source
	// last-source-nudge cooldown: while the stamp is younger, the
	// source-side artifact fix is in flight and the consumer-side
	// nudge defers.
	sourceNudgeFreshWindow = 30 * time.Minute
)

// fluxKustomizationGVR is the kustomize.toolkit.fluxcd.io/v1
// Kustomization CRD the check scans.
var fluxKustomizationGVR = kube.GVRFluxKustomization

// fluxKustNudgeReasons are the Ready=False reasons whose usual fix is
// a fresh reconcile attempt — a stale source artifact or a source
// that recovered after the failure latched. HealthCheckFailed is NOT
// listed: it qualifies only when the applied workloads are provably
// Ready (stale status poller), verified per object.
var fluxKustNudgeReasons = map[string]bool{
	"ArtifactFailed": true,
	"SourceNotReady": true,
}

var (
	// flux-stuck — Flux Kustomization stuck.
	fluxKustomizationStuckGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_flux_kustomization_stuck",
		Help: "1 while the Flux Kustomization reports Ready=False for >=15m — flux-stuck.",
	}, []string{"namespace", "name", "reason"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		fluxKustomizationStuckGauge)
}

// Run audits Flux Kustomizations for the stuck-Ready=False signature:
// Ready=False persisting >=15m (the condition's own
// lastTransitionTime is the persistence clock — suspended objects
// are skipped, an absent CRD is a clean pass on Flux-less clusters).
// Every stuck object gets the requestedAt reconcile nudge when its
// whole dependsOn chain is Ready AND the failure reads as
// nudgeable: ArtifactFailed/SourceNotReady unconditionally,
// HealthCheckFailed only when every Deployment/StatefulSet in its
// status.inventory is already Ready (a stale status write, not a
// real health failure). The check FAILs while qualifying
// Kustomizations exist — remediation is best-effort, detection is
// the contract.
func (p *fluxKustomizationHealthCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	if r := p.RequireDyn("flux kustomization check"); r != nil {
		return *r
	}
	now := p.Now()
	// reconcileHealed keys on Kustomization names that die with the
	// object — bound the map so decommissioned names' stamps cannot
	// accumulate (pruned every sweep, not only on a stuck hit).
	p.reconcileHealed.PruneExpired(now, fluxKustHealCooldown)
	// sourceNudgeHealed is the flux-source-artifact-heal ArtifactFailed source-side
	// twin — same append-only ledger, same prune cadence.
	p.sourceNudgeHealed.PruneExpired(now, fluxKustHealCooldown)
	var rep probefw.SweepReport
	// The snapshot's per-GVR census memoizes the RAW error — the
	// IsNotFound/NoMatch "Flux not installed" interpretation stays
	// here.
	kusts, err := p.AllUnstructured(ctx, fluxKustomizationGVR)
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		// CRD absent — Flux not installed. The sweep IS complete
		// (nothing can exist), so the emitted ledger still closes
		// out: tuples flagged while the CRD existed are dead series
		// now and must be DeleteLabelValues'd, not leaked.
		return rep.Result(&p.emitted, fluxKustomizationStuckGauge.DeleteLabelValues,
			"flux kustomizations stuck: ", ", ")
	case err != nil:
		return probefw.Result{Infra: fmt.Errorf("list kustomizations: %w", err)}
	}

	for i := range kusts {
		kust := &kusts[i]
		if suspended, _ := kube.NestedBool(
			kust.Object, "spec", "suspend"); suspended {
			continue
		}
		cond, ok := kube.ConditionOf(kust.Object, "Ready")
		if !ok || cond.Status != "False" {
			continue
		}
		// The failure must persist — lastTransitionTime is the
		// condition's own clock; absent/malformed means the window
		// cannot be proven, so stay quiet rather than flag and
		// remediate blind (same posture as flux-helmrelease-retries).
		if cond.LastTransitionTime.IsZero() ||
			now.Sub(cond.LastTransitionTime) < fluxKustStuckMinAge {
			continue
		}
		ns, name, reason := kust.GetNamespace(), kust.GetName(), cond.Reason
		rep.Emit(fluxKustomizationStuckGauge, ns+"/"+name+"/"+reason,
			[]string{ns, name, reason},
			fmt.Sprintf("%s/%s(%s)", ns, name, reason))
		p.maybeNudgeKustomization(ctx, log, kust, reason, now)
	}
	return rep.Result(&p.emitted, fluxKustomizationStuckGauge.DeleteLabelValues,
		"flux kustomizations stuck: ", ", ")
}
