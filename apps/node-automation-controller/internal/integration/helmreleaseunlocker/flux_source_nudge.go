// flux_source_nudge.go — the C1 stale-artifact source healer of
// helmrelease-unlocker: a HelmRelease or Kustomization stuck
// Ready=False >=15m on an artifact-fetch signature is almost always
// a source-controller cache problem, so the fix is stamping
// reconcile.fluxcd.io/requestedAt on the SOURCE object (HelmChart,
// GitRepository, HelmRepository, OCIRepository, Bucket) — the
// sourceRef→GVR mapping and the nudge itself live here.
package helmreleaseunlocker

import (
	"context"
	"errors"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

const (
	// fluxLastNudgeAnno is the per-source 30m cooldown stamp written
	// onto the Flux source object by the artifact healer.
	fluxLastNudgeAnno = kube.AnnoLastSourceNudge
	// artifactStuckMinAge: a consumer Ready=False on an artifact-
	// fetch signature this long is a stale source cache, not a
	// transient fetch retry.
	artifactStuckMinAge = 15 * time.Minute
	sourceNudgeCooldown = 30 * time.Minute // max 1 nudge per Flux source
)

// fluxKustomizationGVR is the second consumer kind the artifact
// healer scans (kustomize-controller owns the same stale-artifact
// failure class as helm-controller).
var fluxKustomizationGVR = kube.GVRFluxKustomization

// fluxSourceRef is a resolved source object coordinates tuple.
type fluxSourceRef struct{ kind, namespace, name string }

// healArtifactSources scans every HelmRelease (listed by the caller)
// and every Kustomization (also listed by the caller — shared with
// the immutable-Job healer so the sweep pages it once, nil on
// pre-v1 flux) for the stale-artifact signature, resolves each
// consumer's Flux source, and stamps
// reconcile.fluxcd.io/requestedAt on it — source-controller refetches
// the artifact, which is what actually unstucks the consumer. The
// passiontech.dev/last-source-nudge stamp on the source caps this at once
// per source per 30m across ALL consumers pointing at it.
func (u *helmReleaseUnlocker) healArtifactSources(ctx context.Context,
	hrs, kustomizations *unstructured.UnstructuredList) {
	log := logf.FromContext(ctx)
	nudged := 0
	now := u.now.Now()
	// One Get+patch per source per sweep — several consumers (or a
	// consumer's two refs) can point at the same source object.
	seen := map[fluxSourceRef]bool{}
	for i := range hrs.Items {
		hr := &hrs.Items[i]
		if !kube.FluxArtifactStale(hr, now, artifactStuckMinAge) {
			continue
		}
		if ref, ok := hrSourceRef(hr); ok &&
			u.nudgeSource(ctx, ref, consumerID("HelmRelease", hr), seen) {
			nudged++
		}
		if hcRef, ok := hrStatusHelmChartRef(hr); ok &&
			u.nudgeSource(ctx, hcRef, consumerID("HelmRelease", hr), seen) {
			nudged++
		}
	}
	if kustomizations != nil {
		for i := range kustomizations.Items {
			k := &kustomizations.Items[i]
			if !kube.FluxArtifactStale(k, now, artifactStuckMinAge) {
				continue
			}
			if ref, ok := ksSourceRef(k); ok &&
				u.nudgeSource(ctx, ref, consumerID("Kustomization", k), seen) {
				nudged++
			}
		}
	}
	log.Info("flux artifact-source sweep done", "sourcesNudged", nudged)
}

// hrSourceRef resolves the source a HelmRelease pulls its artifact
// from: spec.chartRef (v2 — HelmChart/OCIRepository) or the legacy
// spec.chart.spec.sourceRef (HelmRepository/GitRepository). The
// namespace defaults to the HR's own (flux convention).
func hrSourceRef(hr *unstructured.Unstructured) (fluxSourceRef, bool) {
	kind, ns, name, ok := kube.FluxConsumerSourceRef(hr)
	if !ok {
		return fluxSourceRef{}, false
	}
	return fluxSourceRef{kind: kind, namespace: ns, name: name}, true
}

// hrStatusHelmChartRef resolves the synthesized HelmChart recorded in
// status.helmChart ("<namespace>/<name>") when the HelmRelease uses
// spec.chart.spec.sourceRef (not spec.chartRef: HelmChart), so both the
// upstream repository and the HelmChart artifact are nudged.
func hrStatusHelmChartRef(hr *unstructured.Unstructured) (fluxSourceRef, bool) {
	if cKind, _ := kube.NestedString(hr.Object, "spec", "chartRef", "kind"); cKind == "HelmChart" {
		return fluxSourceRef{}, false
	}
	hc, _ := kube.NestedString(hr.Object, "status", "helmChart")
	ns, name, ok := strings.Cut(hc, "/")
	if !ok || ns == "" || name == "" {
		return fluxSourceRef{}, false
	}
	return fluxSourceRef{kind: "HelmChart", namespace: ns, name: name}, true
}

// ksSourceRef is spec.sourceRef on a Kustomization — same flux
// convention (namespace defaults to the object's own).
func ksSourceRef(k *unstructured.Unstructured) (fluxSourceRef, bool) {
	kind, ns, name, ok := kube.FluxConsumerSourceRef(k)
	if !ok {
		return fluxSourceRef{}, false
	}
	return fluxSourceRef{kind: kind, namespace: ns, name: name}, true
}

// consumerID renders the complaining consumer for log lines.
func consumerID(kind string, o *unstructured.Unstructured) string {
	return kind + " " + o.GetNamespace() + "/" + o.GetName()
}

// nudgeSource stamps reconcile.fluxcd.io/requestedAt + the
// passiontech.dev/last-source-nudge cooldown onto a Flux source object.
// The write is gated through heal.AllowedVPersisted: the persisted
// last-source-nudge annotation is the cooldown, then the maintenance
// mutex + global heal budget admit the patch (fail closed; an
// unverifiable check IncErrors the queue). Failures are per-source:
// IncError + false, never an aborted sweep.
// seen dedupes within the sweep: the first consumer to name a source
// claims its one Get+patch — a shared source is never fetched twice
// (and a failed Get is not retried for every other consumer).
func (u *helmReleaseUnlocker) nudgeSource(ctx context.Context,
	ref fluxSourceRef, consumer string, seen map[fluxSourceRef]bool) bool {
	log := logf.FromContext(ctx)
	key := ref.namespace + "/" + ref.name
	gvr, ok := kube.FluxSourceGVR(ref.kind)
	if !ok {
		log.Info("skip: source kind is not a nudgeable Flux source",
			"kind", ref.kind, "consumer", consumer)
		return false
	}
	if seen[ref] {
		return false // already handled for another consumer this sweep
	}
	seen[ref] = true
	src, err := u.dyn.Resource(gvr).Namespace(ref.namespace).
		Get(ctx, ref.name, metav1.GetOptions{})
	gone, err := kube.ConfirmAbsent(err)
	if err != nil {
		metrics.IncError(u.queue)
		log.Error(err, "flux source get failed", "kind", ref.kind, "source", key)
		return false
	}
	if gone {
		log.Info("skip: flux source gone",
			"kind", ref.kind, "source", key, "consumer", consumer)
		return false
	}
	now := u.now.Now()
	// The mutex-aligned gate: the persisted last-source-nudge
	// annotation is the cooldown (the wider of it and no in-RAM
	// ledger — this healer stamps the source object itself), then
	// the maintenance mutex + global heal budget evaluate fail-
	// closed, the same posture every annotation nudge runs under.
	// Unverifiable IncErrors the queue — the signal must reach the
	// alert path.
	proceed, unverifiable := heal.AllowedVPersisted(ctx, log, nil,
		u.cs, u.dyn, nil, src, fluxLastNudgeAnno, key,
		sourceNudgeCooldown, now)
	if unverifiable {
		metrics.IncError(u.queue)
		log.Error(errors.New("maintenance check unverifiable"),
			"flux source nudge deferred — mutex unverifiable (fail closed)",
			"kind", ref.kind, "source", key)
		return false
	}
	if !proceed {
		return false
	}
	stamp := now.UTC().Format(time.RFC3339)
	patch, err := kube.MergePatchAnnos(map[string]any{
		fluxReconcileAnno: stamp,
		fluxLastNudgeAnno: stamp,
	})
	if err != nil {
		return false
	}
	if _, err := u.dyn.Resource(gvr).Namespace(ref.namespace).Patch(ctx, ref.name,
		types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
		metrics.IncError(u.queue)
		log.Error(err, "flux source nudge patch failed", "kind", ref.kind, "source", key)
		return false
	}
	metrics.FluxSourceReconcilesTriggeredTotal.
		WithLabelValues(ref.kind, ref.namespace, ref.name).Inc()
	// The counter series is born here — remember it so the sweep-end
	// prune can delete it once no consumer resolves to this source
	// anymore. fluxSourceKey is the exact label tuple of the series.
	u.fluxSources.Add(fluxSourceKey(ref))
	log.Info("ACTION: requested flux source reconcile — consumer reports a stale artifact",
		"kind", ref.kind, "source", key, "consumer", consumer)
	return true
}

// fluxSourceKey renders the metric label tuple (kind, namespace,
// name) as one map key — "/" cannot appear in any of the three parts,
// so splitting it back into label values is unambiguous.
func fluxSourceKey(ref fluxSourceRef) string {
	return ref.kind + "/" + ref.namespace + "/" + ref.name
}

// fluxSourceInventory resolves every consumer→source ref this sweep's
// COMPLETE consumer lists can produce — the same pure spec reads the
// emit path above uses (hrSourceRef / hrStatusHelmChartRef /
// ksSourceRef), so every key a nudge could ever emit is covered by
// it. Costs no API calls: the lists were already paged for the sweep.
func fluxSourceInventory(hrs, kustomizations *unstructured.UnstructuredList) map[string]bool {
	inv := map[string]bool{}
	add := func(ref fluxSourceRef) { inv[fluxSourceKey(ref)] = true }
	for i := range hrs.Items {
		hr := &hrs.Items[i]
		if ref, ok := hrSourceRef(hr); ok {
			add(ref)
		}
		if hcRef, ok := hrStatusHelmChartRef(hr); ok {
			add(hcRef)
		}
	}
	if kustomizations != nil {
		for i := range kustomizations.Items {
			if ref, ok := ksSourceRef(&kustomizations.Items[i]); ok {
				add(ref)
			}
		}
	}
	return inv
}

// pruneFluxSourceSeries carries the 2-set carry-forward prune for
// FluxSourceReconcilesTriggeredTotal{kind,namespace,name}: the
// fluxSources SeenSet holds the series past sweeps emitted, the
// inventory is this sweep's complete consumer→source resolution, and
// a set key absent from the inventory means its source no longer has
// a single consumer — DeleteLabelValues it. A key still in the
// inventory keeps both its series and its count. The caller skips
// this on an incomplete sweep (Kustomization list error): a half
// inventory would delete still-referenced series — the same complete-
// sweep precondition SeenSet.Prune documents.
func (u *helmReleaseUnlocker) pruneFluxSourceSeries(
	hrs, kustomizations *unstructured.UnstructuredList) {
	inv := fluxSourceInventory(hrs, kustomizations)
	u.fluxSources.Prune(func(key string) bool {
		if inv[key] {
			return true
		}
		kind, rest, _ := strings.Cut(key, "/")
		ns, name, _ := strings.Cut(rest, "/")
		metrics.FluxSourceReconcilesTriggeredTotal.
			DeleteLabelValues(kind, ns, name)
		return false
	})
}
