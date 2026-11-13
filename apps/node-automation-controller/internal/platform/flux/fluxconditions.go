// fluxconditions.go — the shared stale-artifact signature for Flux
// consumers (HelmRelease, Kustomization): a non-suspended object
// parked Ready=False on a source-artifact fetch failure. Two modules
// remediate this failure class — helmrelease-unlocker's source healer
// (nudges the SOURCE object) and health/gitops' flux-stuck check
// (nudges the CONSUMER) — and both must read the SAME signature off
// the same message list, or a stuck artifact gets double-remediated
// with independent cooldowns. The message fragments are the UNION of
// the historical per-module lists: only helmrelease-unlocker ever
// carried fragments ("artifact not found", "failed to fetch", "chart
// pull error", "failed to untar"); health/gitops' kustomization check
// gated on the Ready Reason names (ArtifactFailed/SourceNotReady) and
// flux-helmrelease-retries on reason names plus the consumer-local
// "retries exhausted" fragment — that one is deliberately NOT here:
// exhausted controller retries are a backoff state on the consumer,
// not a fetch failure, and refetching the source cannot fix them.
package flux

import (
	"context"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// FluxArtifactFailMsgs is the Ready=False message-fragment list
// marking a stale source artifact (lowercase, matched with
// strings.Contains against the lowercased condition message).
var FluxArtifactFailMsgs = []string{
	"artifact not found", "failed to fetch", "chart pull error", "failed to untar",
}

// FluxArtifactFailMessage reports whether a Ready-condition message
// points at the source's artifact rather than the consumer's own
// logic — the message half of the stale-artifact signature.
func FluxArtifactFailMessage(message string) bool {
	lower := strings.ToLower(message)
	for _, s := range FluxArtifactFailMsgs {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// FluxArtifactStale is the one-call stale-artifact signature: the
// object is not suspended (suspended objects are parked, not
// broken), its Ready condition reads False, the condition message
// matches an artifact-fetch failure fragment, and the failure has
// held since lastTransitionTime (falling back to the creation
// timestamp when the condition carries no clock) for at least
// minAge. minAge is a parameter — helmrelease-unlocker and
// health/gitops both use 15m but the window is each site's own
// contract, not the signature's.
func FluxArtifactStale(o *unstructured.Unstructured, now time.Time,
	minAge time.Duration) bool {

	if suspended, _ := kube.NestedBool(o.Object, "spec", "suspend"); suspended {
		return false
	}
	c, ok := kube.ConditionOf(o.Object, "Ready")
	if !ok || c.Status != "False" {
		return false
	}
	if !FluxArtifactFailMessage(c.Message) {
		return false
	}
	since := c.LastTransitionTime
	if since.IsZero() {
		since = o.GetCreationTimestamp().Time
	}
	return now.Sub(since) >= minAge
}

// FluxSourceGVRs maps the sourceRef kinds Flux consumers carry to
// their source.toolkit.fluxcd.io/v1 GVRs — the objects a stale-
// artifact nudge actually lands on (helmrelease-unlocker's healer
// and health/gitops' source-freshness probe share it).
var FluxSourceGVRs = map[string]schema.GroupVersionResource{
	"HelmChart":      kube.GVRFluxHelmChart,
	"GitRepository":  kube.GVRFluxGitRepository,
	"HelmRepository": kube.GVRFluxHelmRepository,
	"OCIRepository":  kube.GVRFluxOCIRepository,
	// Bucket is a first-class v1 source kind — a Kustomization or HR
	// sourcing artifacts from an S3/GCS bucket needs the same nudge.
	"Bucket": kube.GVRFluxBucket,
}

// FluxSourceGVR resolves a sourceRef kind to its GVR.
func FluxSourceGVR(kind string) (schema.GroupVersionResource, bool) {
	gvr, ok := FluxSourceGVRs[kind]
	return gvr, ok
}

// FluxConsumerSourceRef resolves the Flux source a consumer object
// pulls its artifact from: spec.sourceRef on a Kustomization, or
// spec.chartRef / the legacy spec.chart.spec.sourceRef on a
// HelmRelease. The namespace defaults to the object's own (the flux
// convention). ok=false when the object carries no resolvable
// sourceRef.
func FluxConsumerSourceRef(o *unstructured.Unstructured) (kind, ns, name string, ok bool) {
	kind, _ = kube.NestedString(o.Object, "spec", "sourceRef", "kind")
	name, _ = kube.NestedString(o.Object, "spec", "sourceRef", "name")
	ns, _ = kube.NestedString(o.Object, "spec", "sourceRef", "namespace")
	if kind == "" || name == "" {
		kind, _ = kube.NestedString(o.Object, "spec", "chartRef", "kind")
		name, _ = kube.NestedString(o.Object, "spec", "chartRef", "name")
		ns, _ = kube.NestedString(o.Object, "spec", "chartRef", "namespace")
		if kind == "" || name == "" {
			kind, _ = kube.NestedString(
				o.Object, "spec", "chart", "spec", "sourceRef", "kind")
			name, _ = kube.NestedString(
				o.Object, "spec", "chart", "spec", "sourceRef", "name")
			ns, _ = kube.NestedString(
				o.Object, "spec", "chart", "spec", "sourceRef", "namespace")
		}
	}
	if kind == "" || name == "" {
		return "", "", "", false
	}
	if ns == "" {
		ns = o.GetNamespace()
	}
	return kind, ns, name, true
}

// FluxSourceNudgeFresh reports whether obj already carries a fresh
// passiontech.dev/last-source-nudge stamp — helmrelease-unlocker's
// cooldown annotation (RFC3339, read via kube.AnnoTime). Consumers call
// this to defer their own remediation while the source healer is
// inside its cooldown window, so one stuck artifact is remediated
// once, not twice.
func FluxSourceNudgeFresh(ctx context.Context, obj metav1.Object, now time.Time,
	cooldown time.Duration) bool {

	t, ok := kube.AnnoTimeCtx(ctx, obj, kube.AnnoLastSourceNudge)
	return ok && now.Sub(t) < cooldown
}
