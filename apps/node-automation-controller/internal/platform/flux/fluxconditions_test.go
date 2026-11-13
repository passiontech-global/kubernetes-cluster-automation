// fluxconditions_test.go — coverage for the shared stale-artifact
// signature both Flux consumers (helmrelease-unlocker, health/gitops)
// read: the message-fragment match, the full FluxArtifactStale gate
// (suspend / Ready=False / fragment / minAge with the
// creationTimestamp fallback), the sourceRef resolution order, the
// source-kind GVR map, and the nudge-cooldown freshness read.
package flux

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/testhelp"
)

var fluxHRGVK = schema.GroupVersionKind{
	Group: "helm.toolkit.fluxcd.io", Version: "v2", Kind: "HelmRelease"}

// fluxObj builds a HelmRelease-shaped unstructured carrying the given
// spec blob and Ready condition (status "", message "", transition
// `age` ago; a zero age omits lastTransitionTime entirely).
func fluxObj(suspend bool, readyStatus, message string, age time.Duration) *unstructured.Unstructured {
	fields := map[string]any{}
	if suspend {
		fields["spec"] = map[string]any{"suspend": true}
	}
	cond := map[string]any{
		"type":    "Ready",
		"status":  readyStatus,
		"reason":  "Progressing",
		"message": message,
	}
	if age != 0 {
		cond["lastTransitionTime"] = time.Now().Add(-age).UTC().Format(time.RFC3339)
	}
	fields["status"] = map[string]any{
		"conditions": []any{cond},
	}
	return testhelp.Unstructured(fluxHRGVK, "apps", "hr-1", fields)
}

func TestFluxArtifactFailMessage(t *testing.T) {
	for _, tc := range []struct {
		name    string
		message string
		want    bool
	}{
		{"artifact not found", "artifact not found for revision", true},
		{"failed to fetch", "failed to fetch artifact from source", true},
		{"chart pull error", "chart pull error: rpc error", true},
		{"failed to untar", "failed to untar chart archive", true},
		{"case-insensitive", "ARTIFACT NOT FOUND in registry", true},
		{"retries exhausted is consumer-local", "retries exhausted", false},
		{"empty message", "", false},
		{"unrelated failure", "deployment timed out", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := FluxArtifactFailMessage(tc.message); got != tc.want {
				t.Fatalf("FluxArtifactFailMessage(%q) = %v, want %v",
					tc.message, got, tc.want)
			}
		})
	}
}

func TestFluxArtifactStale(t *testing.T) {
	now := time.Now()
	minAge := 15 * time.Minute
	staleMsg := "artifact not found for revision 42"

	cases := []struct {
		name string
		obj  *unstructured.Unstructured
		want bool
	}{
		{"stale artifact breach", fluxObj(false, "False", staleMsg, 20*time.Minute), true},
		{"fresh failure inside window", fluxObj(false, "False", staleMsg, time.Minute), false},
		{"suspended object is parked not broken",
			fluxObj(true, "False", staleMsg, time.Hour), false},
		{"ready true is not stale", fluxObj(false, "True", staleMsg, time.Hour), false},
		{"non-artifact failure message",
			fluxObj(false, "False", "retries exhausted", time.Hour), false},
		{"no ready condition", testhelp.Unstructured(fluxHRGVK, "apps", "hr-1",
			map[string]any{"spec": map[string]any{}}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FluxArtifactStale(tc.obj, now, minAge); got != tc.want {
				t.Fatalf("FluxArtifactStale = %v, want %v", got, tc.want)
			}
		})
	}
}

// A Ready=False with no lastTransitionTime falls back to the object's
// creationTimestamp as the persistence clock.
func TestFluxArtifactStaleCreationTimestampFallback(t *testing.T) {
	now := time.Now()
	obj := fluxObj(false, "False", "failed to fetch artifact", 0)
	obj.SetCreationTimestamp(metav1.NewTime(now.Add(-time.Hour)))
	if !FluxArtifactStale(obj, now, 15*time.Minute) {
		t.Fatal("artifact failure older than minAge via creationTimestamp = false, want true")
	}
	// A brand-new object with no transition stamp is inside the
	// window — the fallback must not read as infinitely old.
	fresh := fluxObj(false, "False", "failed to fetch artifact", 0)
	fresh.SetCreationTimestamp(metav1.NewTime(now.Add(-time.Minute)))
	if FluxArtifactStale(fresh, now, 15*time.Minute) {
		t.Fatal("fresh object without transition stamp = true, want false")
	}
}

func TestFluxSourceGVR(t *testing.T) {
	for kind, wantRes := range map[string]string{
		"HelmChart":      "helmcharts",
		"GitRepository":  "gitrepositories",
		"HelmRepository": "helmrepositories",
		"OCIRepository":  "ocirepositories",
		"Bucket":         "buckets",
	} {
		gvr, ok := FluxSourceGVR(kind)
		if !ok {
			t.Fatalf("FluxSourceGVR(%q) ok=false", kind)
		}
		if gvr.Resource != wantRes || gvr.Group != "source.toolkit.fluxcd.io" {
			t.Fatalf("FluxSourceGVR(%q) = %v", kind, gvr)
		}
	}
	if _, ok := FluxSourceGVR("ConfigMap"); ok {
		t.Fatal("FluxSourceGVR(ConfigMap) ok=true, want false")
	}
}

func TestFluxConsumerSourceRef(t *testing.T) {
	mk := func(fields map[string]any) *unstructured.Unstructured {
		return testhelp.Unstructured(fluxHRGVK, "apps", "hr-1", fields)
	}
	ref := func(kind, name, ns string) map[string]any {
		m := map[string]any{"kind": kind, "name": name}
		if ns != "" {
			m["namespace"] = ns
		}
		return m
	}

	cases := []struct {
		name     string
		obj      *unstructured.Unstructured
		wantKind string
		wantNS   string
		wantName string
		wantOK   bool
	}{
		{"kustomization spec.sourceRef",
			mk(map[string]any{"spec": map[string]any{
				"sourceRef": ref("GitRepository", "infra", "flux-system")}}),
			"GitRepository", "flux-system", "infra", true},
		{"helmrelease chartRef",
			mk(map[string]any{"spec": map[string]any{
				"chartRef": ref("HelmRepository", "bitnami", "")}}),
			"HelmRepository", "apps", "bitnami", true}, // ns defaults to object's
		{"helmrelease legacy chart.spec.sourceRef",
			mk(map[string]any{"spec": map[string]any{
				"chart": map[string]any{"spec": map[string]any{
					"sourceRef": ref("OCIRepository", "charts", "libs")}}}}),
			"OCIRepository", "libs", "charts", true},
		{"sourceRef wins over chartRef",
			mk(map[string]any{"spec": map[string]any{
				"sourceRef": ref("GitRepository", "primary", ""),
				"chartRef":  ref("HelmRepository", "secondary", "")}}),
			"GitRepository", "apps", "primary", true},
		{"no sourceRef at all",
			mk(map[string]any{"spec": map[string]any{"chart": "stable/app"}}),
			"", "", "", false},
		{"kind without name is unresolved",
			mk(map[string]any{"spec": map[string]any{
				"sourceRef": map[string]any{"kind": "GitRepository"}}}),
			"", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, ns, name, ok := FluxConsumerSourceRef(tc.obj)
			if ok != tc.wantOK || kind != tc.wantKind ||
				ns != tc.wantNS || name != tc.wantName {
				t.Fatalf("FluxConsumerSourceRef = (%q,%q,%q,%v), want (%q,%q,%q,%v)",
					kind, ns, name, ok, tc.wantKind, tc.wantNS, tc.wantName, tc.wantOK)
			}
		})
	}
}

func TestFluxSourceNudgeFresh(t *testing.T) {
	now := time.Now()
	obj := testhelp.Unstructured(fluxHRGVK, "apps", "hr-1", nil)
	stamp := func(t time.Time) {
		obj.SetAnnotations(map[string]string{
			kube.AnnoLastSourceNudge: t.UTC().Format(time.RFC3339)})
	}

	if FluxSourceNudgeFresh(context.Background(), obj, now, 15*time.Minute) {
		t.Fatal("no stamp read as fresh")
	}
	stamp(now.Add(-time.Minute))
	if !FluxSourceNudgeFresh(context.Background(), obj, now, 15*time.Minute) {
		t.Fatal("fresh stamp read as stale")
	}
	stamp(now.Add(-time.Hour))
	if FluxSourceNudgeFresh(context.Background(), obj, now, 15*time.Minute) {
		t.Fatal("stale stamp read as fresh")
	}
	obj.SetAnnotations(map[string]string{kube.AnnoLastSourceNudge: "garbage"})
	if FluxSourceNudgeFresh(context.Background(), obj, now, 15*time.Minute) {
		t.Fatal("unparseable stamp read as fresh")
	}
}
