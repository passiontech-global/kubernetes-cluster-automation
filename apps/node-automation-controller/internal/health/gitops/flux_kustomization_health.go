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
// flux-helmrelease-retries (W10-CP4); the domino incident this covers
// is a stuck `wait: true` Kustomization leaving every downstream
// Kustomization parked at DependencyNotReady.
package gitops

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
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

// maybeNudgeKustomization stamps reconcile.fluxcd.io/requestedAt on a
// stuck Kustomization when the nudge criteria hold: every
// spec.dependsOn reference resolves to a Ready=True Kustomization
// (patching an object whose upstream is itself broken just re-fails
// on the same wall — the domino this check exists to break), the
// failure reason is nudgeable, the 30m cooldown is cold (the wider
// of the in-RAM ledger and the requestedAt stamp a previous patch —
// ours or `flux reconcile`'s — left), and heal.AllowedV admits the
// write (maintenance mutex + global heal budget). A nudge is an
// annotation, not a delete, so there is no UID precondition to take
// — the merge patch is idempotent.
func (p *fluxKustomizationHealthCheck) maybeNudgeKustomization(ctx context.Context,
	log logr.Logger, kust *unstructured.Unstructured, reason string, now time.Time) {

	key := kust.GetNamespace() + "/" + kust.GetName()
	if !p.fluxKustDepsReady(ctx, kust) {
		return
	}
	nudgeable := fluxKustNudgeReasons[reason] ||
		(reason == "HealthCheckFailed" && p.fluxKustWorkloadsReady(ctx, kust))
	if !nudgeable {
		return
	}
	// Double-remediation guard: on the artifact-fail signature, the
	// SOURCE object is the primary remediation target
	// (helmrelease-unlocker's artifact healer). When that healer
	// already stamped a fresh passiontech.dev/last-source-nudge on
	// the consumer's source, the source-controller refetch is in
	// flight — nudging the consumer here would churn its backoff on
	// top of the source fix, so this check defers. Non-artifact
	// reasons (HealthCheckFailed with provably-Ready workloads) keep
	// the current consumer-side behavior.
	if fluxKustNudgeReasons[reason] ||
		kube.FluxArtifactStale(kust, now, fluxKustStuckMinAge) {
		if p.fluxSourceNudgeFresh(ctx, kust, now) {
			log.V(1).Info("skip: consumer nudge deferred — source nudge fresh",
				"kustomization", key, "reason", reason)
			return
		}
	}
	ck := probefw.SelfHealKey(CheckNameFluxKustomizationHealth, key)
	// The preamble is the shared persisted-cooldown shape
	// (Deps.HealAllowedPersisted → heal.AllowedVPersisted): the
	// cooldown is the wider of the in-RAM ledger and the requestedAt
	// stamp a previous patch — ours or `flux reconcile`'s — left; only
	// after it clears do the maintenance mutex + global heal budget
	// evaluate (fail closed), on the Deps-wide memoized verdict.
	proceed, unverifiable := p.HealAllowedPersisted(ctx, log,
		&p.reconcileHealed, kust,
		kube.AnnoFluxRequestedAt, ck, fluxKustHealCooldown, now)
	if unverifiable {
		metrics.IncError(p.Name)
		return
	}
	if !proceed {
		return
	}
	// StampPersisted emits the {"metadata":{"annotations":
	// {requestedAt: now}}} merge patch through the closure and
	// stamps the in-RAM ledger only when the patch lands — a failed
	// patch must not suppress the next attempt for the window.
	err := heal.StampPersisted(ctx,
		func(ctx context.Context, data []byte) error {
			_, err := p.Dyn.Resource(fluxKustomizationGVR).
				Namespace(kust.GetNamespace()).
				Patch(ctx, kust.GetName(), types.MergePatchType,
					data, metav1.PatchOptions{})
			return err
		},
		kube.AnnoFluxRequestedAt, &p.reconcileHealed, ck, now)
	if err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "kustomization requestedAt patch failed",
			"kustomization", key)
		return
	}
	log.Info("PATCH: flux kustomization reconcile requestedAt",
		"kustomization", key, "reason", reason)
}

// fluxSourceNudgeFresh reports whether the Kustomization's Flux
// source object already carries a fresh passiontech.dev/last-source-nudge
// stamp (helmrelease-unlocker's 30m cooldown) — the signal that the
// source-side artifact fix is in flight and the consumer-side nudge
// must defer. Any lookup failure (absent source, unknown kind,
// unreadable dynamic response) fails OPEN: the gitops nudge keeps its
// current behavior rather than losing remediation to a read error.
func (p *fluxKustomizationHealthCheck) fluxSourceNudgeFresh(ctx context.Context,
	kust *unstructured.Unstructured, now time.Time) bool {

	kind, ns, name, ok := kube.FluxConsumerSourceRef(kust)
	if !ok {
		return false
	}
	gvr, ok := kube.FluxSourceGVR(kind)
	if !ok {
		return false
	}
	src, err := p.Dyn.Resource(gvr).Namespace(ns).
		Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		logf.FromContext(ctx).V(1).Info(
			"source nudge lookup failed — deferral guard fails open",
			"kind", kind, "source", ns+"/"+name, "error", err)
		return false
	}
	return kube.FluxSourceNudgeFresh(src, now, sourceNudgeFreshWindow)
}

// fluxKustDepsReady reports whether every spec.dependsOn entry of the
// Kustomization resolves to a Ready=True Kustomization — the domino
// gate: nudging a blocked downstream while its upstream is still
// failing wastes the cooldown. A missing or unreadable dependency
// fails closed; absent dependsOn is vacuously ready. Entries default
// namespace to the Kustomization's own (the CRD's semantics).
func (p *fluxKustomizationHealthCheck) fluxKustDepsReady(ctx context.Context,
	kust *unstructured.Unstructured) bool {

	deps, found := kube.NestedSlice(kust.Object, "spec", "dependsOn")
	if !found {
		return true
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
			ns = kust.GetNamespace()
		}
		dep, err := p.Dyn.Resource(fluxKustomizationGVR).Namespace(ns).
			Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false
		}
		c, ok := kube.ConditionOf(dep.Object, "Ready")
		if !ok || c.Status != "True" {
			return false
		}
	}
	return true
}

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
			// W18-5 — argoproj.io Rollouts land in the inventory the
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

// fluxRolloutReady is the argoproj.io Rollout twin (W18-5): the
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
		if d, found, _ := unstructured.NestedInt64(r.Object, "spec", "replicas"); found {
			desired = d
		}
		ready, _, _ := unstructured.NestedInt64(r.Object, "status", "readyReplicas")
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
