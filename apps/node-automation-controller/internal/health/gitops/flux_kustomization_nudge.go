// flux_kustomization_nudge.go — the heal half of the flux-stuck
// check: the requestedAt reconcile nudge on a stuck Kustomization,
// the source-artifact nudge, and the dependsOn/nudgeability gates
// that decide whether a nudge may fire.
//
// split from flux_kustomization_health.go (see its header for the
// module contract).
package gitops

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

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
	// flux-source-artifact-heal: an ArtifactFailed signature usually means the SOURCE
	// object's cached artifact is corrupt (source-controller pod
	// restart mid-fetch) — stamping requestedAt on the Kustomization
	// alone re-reads the same bad tarball. The source-side nudge is
	// independent of the dependsOn chain: a broken upstream artifact
	// is the source's problem, not the consumer's.
	if reason == "ArtifactFailed" {
		p.nudgeFluxSourceArtifact(ctx, log, kust, now)
	}
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

// nudgeFluxSourceArtifact stamps reconcile.fluxcd.io/requestedAt on
// the Kustomization's spec.sourceRef object (GitRepository /
// OCIRepository / Bucket) so source-controller refetches the artifact
// instead of serving the corrupt cached tarball that produced the
// ArtifactFailed signature. Same 30m cooldown + maintenance-mutex +
// heal-budget gate as the consumer nudge, keyed per source so N
// consumers of one broken source do not stamp it N times.
func (p *fluxKustomizationHealthCheck) nudgeFluxSourceArtifact(ctx context.Context,
	log logr.Logger, kust *unstructured.Unstructured, now time.Time) {

	kind, ns, name, ok := kube.FluxConsumerSourceRef(kust)
	if !ok {
		return
	}
	gvr, ok := kube.FluxSourceGVR(kind)
	if !ok {
		return
	}
	src, err := p.Dyn.Resource(gvr).Namespace(ns).
		Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		log.V(1).Info("source artifact nudge — source lookup failed",
			"kind", kind, "source", ns+"/"+name, "error", err)
		return
	}
	ck := probefw.SelfHealKey(CheckNameFluxKustomizationHealth,
		"source/"+kind+"/"+ns+"/"+name)
	proceed, unverifiable := p.HealAllowedPersisted(ctx, log,
		&p.sourceNudgeHealed, src,
		kube.AnnoFluxRequestedAt, ck, fluxKustHealCooldown, now)
	if unverifiable {
		metrics.IncError(p.Name)
		return
	}
	if !proceed {
		return
	}
	if err := heal.StampPersisted(ctx,
		func(ctx context.Context, data []byte) error {
			_, err := p.Dyn.Resource(gvr).Namespace(ns).
				Patch(ctx, name, types.MergePatchType,
					data, metav1.PatchOptions{})
			return err
		},
		kube.AnnoFluxRequestedAt, &p.sourceNudgeHealed, ck, now); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "flux source requestedAt patch failed",
			"source", kind+"/"+ns+"/"+name)
		return
	}
	log.Info("PATCH: flux source reconcile requestedAt (artifact refetch)",
		"source", kind+"/"+ns+"/"+name)
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
		// Same memoized census as the HelmRelease twin — the
		// dependsOn chain resolves against the paged LIST the
		// sweep already paid for, not a per-object GET.
		items, err := p.AllUnstructured(ctx, fluxKustomizationGVR)
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
		c, ok := kube.ConditionOf(dep.Object, "Ready")
		if !ok || c.Status != "True" {
			return false
		}
	}
	return true
}
