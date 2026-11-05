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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

const (
	// fluxLastNudgeAnno is the per-source 30m cooldown stamp written
	// onto the Flux source object by the artifact healer.
	fluxLastNudgeAnno = "node.ops/last-source-nudge"
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

// fluxSourceGVRs maps the sourceRef kinds flux consumers carry to
// their source.toolkit.fluxcd.io/v1 GVRs — the objects a stale-
// artifact nudge actually lands on.
var fluxSourceGVRs = map[string]schema.GroupVersionResource{
	"HelmChart":      kube.GVRFluxHelmChart,
	"GitRepository":  kube.GVRFluxGitRepository,
	"HelmRepository": kube.GVRFluxHelmRepository,
	"OCIRepository":  kube.GVRFluxOCIRepository,
	// Bucket is a first-class v1 source kind — a Kustomization or HR
	// sourcing artifacts from an S3/GCS bucket needs the same nudge.
	"Bucket": kube.GVRFluxBucket,
}

// artifactFailMsgs are the Ready=False message fragments marking a
// stale artifact on the SOURCE side — refetching the source is the
// fix, not churning the consumer's own backoff.
var artifactFailMsgs = []string{
	"artifact not found", "failed to fetch", "chart pull error", "failed to untar",
}

// fluxSourceRef is a resolved source object coordinates tuple.
type fluxSourceRef struct{ kind, namespace, name string }

// healArtifactSources scans every HelmRelease (already listed by the
// caller) and every Kustomization for the stale-artifact signature,
// resolves each consumer's Flux source, and stamps
// reconcile.fluxcd.io/requestedAt on it — source-controller refetches
// the artifact, which is what actually unstucks the consumer. The
// node.ops/last-source-nudge stamp on the source caps this at once
// per source per 30m across ALL consumers pointing at it.
func (u *helmReleaseUnlocker) healArtifactSources(ctx context.Context,
	hrs *unstructured.UnstructuredList) error {
	log := logf.FromContext(ctx)
	kustomizations, err := u.listAllPages(ctx, u.dyn.Resource(fluxKustomizationGVR))
	if err != nil {
		if apierrors.IsNotFound(err) {
			kustomizations = nil // pre-v1 flux — the HR half still runs
		} else {
			return fmt.Errorf("list kustomizations: %w", err)
		}
	}
	nudged := 0
	now := u.now.Now()
	for i := range hrs.Items {
		hr := &hrs.Items[i]
		if !fluxArtifactStale(hr, now) {
			continue
		}
		if ref, ok := hrSourceRef(hr); ok &&
			u.nudgeSource(ctx, ref, consumerID("HelmRelease", hr)) {
			nudged++
		}
		if hcRef, ok := hrStatusHelmChartRef(hr); ok &&
			u.nudgeSource(ctx, hcRef, consumerID("HelmRelease", hr)) {
			nudged++
		}
	}
	if kustomizations != nil {
		for i := range kustomizations.Items {
			k := &kustomizations.Items[i]
			if !fluxArtifactStale(k, now) {
				continue
			}
			if ref, ok := ksSourceRef(k); ok &&
				u.nudgeSource(ctx, ref, consumerID("Kustomization", k)) {
				nudged++
			}
		}
	}
	log.Info("flux artifact-source sweep done", "sourcesNudged", nudged)
	return nil
}

// fluxArtifactStale is the stale-artifact signature: a non-suspended
// consumer Ready=False continuously for >=15m (measured against now)
// with a message pointing at the source's artifact (not the
// consumer's own logic).
func fluxArtifactStale(o *unstructured.Unstructured, now time.Time) bool {
	if suspended, _ := kube.NestedBool(o.Object, "spec", "suspend"); suspended {
		return false // suspended objects are parked, not broken
	}
	c, _ := kube.ConditionOf(o.Object, "Ready")
	if c.Status != "False" {
		return false
	}
	lower := strings.ToLower(c.Message)
	hit := false
	for _, s := range artifactFailMsgs {
		if strings.Contains(lower, s) {
			hit = true
			break
		}
	}
	if !hit {
		return false
	}
	since := c.LastTransitionTime
	if since.IsZero() {
		since = o.GetCreationTimestamp().Time
	}
	return now.Sub(since) >= artifactStuckMinAge
}

// hrSourceRef resolves the source a HelmRelease pulls its artifact
// from: spec.chartRef (v2 — HelmChart/OCIRepository) or the legacy
// spec.chart.spec.sourceRef (HelmRepository/GitRepository). The
// namespace defaults to the HR's own (flux convention).
func hrSourceRef(hr *unstructured.Unstructured) (fluxSourceRef, bool) {
	kind, _ := kube.NestedString(hr.Object, "spec", "chartRef", "kind")
	name, _ := kube.NestedString(hr.Object, "spec", "chartRef", "name")
	ns, _ := kube.NestedString(hr.Object, "spec", "chartRef", "namespace")
	if kind == "" || name == "" {
		kind, _ = kube.NestedString(
			hr.Object, "spec", "chart", "spec", "sourceRef", "kind")
		name, _ = kube.NestedString(
			hr.Object, "spec", "chart", "spec", "sourceRef", "name")
		ns, _ = kube.NestedString(
			hr.Object, "spec", "chart", "spec", "sourceRef", "namespace")
	}
	if kind == "" || name == "" {
		return fluxSourceRef{}, false
	}
	if ns == "" {
		ns = hr.GetNamespace()
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
	kind, _ := kube.NestedString(k.Object, "spec", "sourceRef", "kind")
	name, _ := kube.NestedString(k.Object, "spec", "sourceRef", "name")
	ns, _ := kube.NestedString(k.Object, "spec", "sourceRef", "namespace")
	if kind == "" || name == "" {
		return fluxSourceRef{}, false
	}
	if ns == "" {
		ns = k.GetNamespace()
	}
	return fluxSourceRef{kind: kind, namespace: ns, name: name}, true
}

// consumerID renders the complaining consumer for log lines.
func consumerID(kind string, o *unstructured.Unstructured) string {
	return kind + " " + o.GetNamespace() + "/" + o.GetName()
}

// nudgeSource stamps reconcile.fluxcd.io/requestedAt + the
// node.ops/last-source-nudge cooldown onto a Flux source object.
// Failures are per-source: IncError + false, never an aborted sweep.
func (u *helmReleaseUnlocker) nudgeSource(ctx context.Context,
	ref fluxSourceRef, consumer string) bool {
	log := logf.FromContext(ctx)
	key := ref.namespace + "/" + ref.name
	gvr, ok := fluxSourceGVRs[ref.kind]
	if !ok {
		log.Info("skip: source kind is not a nudgeable Flux source",
			"kind", ref.kind, "consumer", consumer)
		return false
	}
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
	if ts := src.GetAnnotations()[fluxLastNudgeAnno]; ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil &&
			now.Sub(t) < sourceNudgeCooldown {
			log.Info("skip: source nudged inside cooldown",
				"kind", ref.kind, "source", key,
				"ago", now.Sub(t).Truncate(time.Minute))
			return false
		}
	}
	stamp := now.UTC().Format(time.RFC3339)
	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"annotations": map[string]string{
			fluxReconcileAnno: stamp,
			fluxLastNudgeAnno: stamp,
		}},
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
	log.Info("ACTION: requested flux source reconcile — consumer reports a stale artifact",
		"kind", ref.kind, "source", key, "consumer", consumer)
	return true
}
