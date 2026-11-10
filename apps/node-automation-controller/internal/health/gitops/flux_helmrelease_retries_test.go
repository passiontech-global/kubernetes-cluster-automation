// flux_helmrelease_retries_test.go — the flux-helmrelease-retries flux
// HelmRelease retries-exhausted remediator driven through the
// fake clientset + fake dynamic client.
package gitops

import (
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// flux-helmrelease-retries — flux HelmRelease retries-exhausted remediator
// ---------------------------------------------------------------------------

// shHR builds a HelmRelease carrying a Ready condition at `since`.
func shHR(ns, name, status, reason, message string, since time.Time) *unstructured.Unstructured {
	hr := probetest.UnstructuredObj("helm.toolkit.fluxcd.io/v2", "HelmRelease",
		ns, name, 5, 3)
	_ = unstructured.SetNestedSlice(hr.Object, []any{
		map[string]any{
			"type":               "Ready",
			"status":             status,
			"reason":             reason,
			"message":            message,
			"lastTransitionTime": since.UTC().Format(time.RFC3339),
		},
	}, "status", "conditions")
	return hr
}

var hrRetryGVR = kube.GVRHelmReleaseV2

// A HelmRelease parked Ready=False/UpgradeFailed for 20m gets patched
// with the reconcile annotations and the check FAILs.
func TestCheckFluxHelmReleaseRetriesPatches(t *testing.T) {
	base := time.Now()
	hr := shHR("apps", "hr", "False", "UpgradeFailed",
		"upgrade failed: timed out", base.Add(-20*time.Minute))
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(hr))
	p.Now = func() time.Time { return base }

	res := probetest.MustCheck[*fluxHRRetriesCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("retries-exhausted HelmRelease must FAIL")
	}
	got, err := p.Dyn.Resource(hrRetryGVR).Namespace("apps").
		Get(ctx, "hr", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, anno := range []string{
		kube.AnnoFluxRequestedAt, kube.AnnoFluxForceAt,
		kube.AnnoFluxResetAt, // flux-reset-at — required to clear RetriesExceeded
	} {
		v, found, _ := unstructured.NestedString(
			got.Object, "metadata", "annotations", anno)
		if !found || v == "" {
			t.Fatalf("annotation %s not stamped: %v", anno, got.GetAnnotations())
		}
	}
}

// A failure younger than 15m is still inside the retry window — quiet.
func TestCheckFluxHelmReleaseRetriesFreshQuiet(t *testing.T) {
	base := time.Now()
	hr := shHR("apps", "hr", "False", "UpgradeFailed",
		"upgrade failed", base.Add(-5*time.Minute))
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(hr))
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*fluxHRRetriesCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("fresh failure must pass: %+v", res)
	}
}

// A dependsOn HelmRelease that is itself not Ready blocks the patch —
// the HR still FAILs (detection is independent of remediation).
func TestCheckFluxHelmReleaseRetriesDepNotReady(t *testing.T) {
	base := time.Now()
	hr := shHR("apps", "hr", "False", "RetriesExhausted",
		"retries exhausted", base.Add(-20*time.Minute))
	_ = unstructured.SetNestedSlice(hr.Object, []any{
		map[string]any{"name": "upstream"},
	}, "spec", "dependsOn")
	dep := shHR("apps", "upstream", "False", "InstallFailed",
		"install failed", base.Add(-time.Hour))
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(hr, dep))
	p.Now = func() time.Time { return base }

	res := probetest.MustCheck[*fluxHRRetriesCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("stuck HR must FAIL even when remediation is deferred")
	}
	got, _ := p.Dyn.Resource(hrRetryGVR).Namespace("apps").
		Get(ctx, "hr", metav1.GetOptions{})
	if _, found, _ := unstructured.NestedString(
		got.Object, "metadata", "annotations", kube.AnnoFluxRequestedAt); found {
		t.Fatal("patch applied despite unready dependsOn")
	}
}

// The persisted half of the gate, restart-resume shape: a FRESH check
// process (empty in-RAM ledger) reads the requestedAt stamp a previous
// patch — ours or `flux reconcile`'s — left on the HR and holds off
// inside the 30m window. Detection still FAILs; only remediation is
// suppressed (the HealAllowedPersisted preamble the kustomization
// sibling runs).
func TestCheckFluxHelmReleaseRetriesPersistedGate(t *testing.T) {
	base := time.Now()
	hr := shHR("apps", "hr", "False", "UpgradeFailed",
		"upgrade failed", base.Add(-time.Hour))
	hr.SetAnnotations(map[string]string{
		kube.AnnoFluxRequestedAt: base.Add(-10 * time.Minute).
			UTC().Format(time.RFC3339)})
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(hr))
	p.Now = func() time.Time { return base }

	res := probetest.MustCheck[*fluxHRRetriesCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatal("still-stuck HR must keep FAILING")
	}
	got, err := p.Dyn.Resource(hrRetryGVR).Namespace("apps").
		Get(ctx, "hr", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// requestedAt is the PRE-EXISTING stamp — the patch would show as
	// forceAt/resetAt (only the triple patch writes those) and a
	// rewritten requestedAt token.
	for _, anno := range []string{kube.AnnoFluxForceAt, kube.AnnoFluxResetAt} {
		if _, found, _ := unstructured.NestedString(
			got.Object, "metadata", "annotations", anno); found {
			t.Fatalf("reconcile annotation %s patched through the persisted gate", anno)
		}
	}
	token, _, _ := unstructured.NestedString(
		got.Object, "metadata", "annotations", kube.AnnoFluxRequestedAt)
	if want := base.Add(-10 * time.Minute).UTC().Format(time.RFC3339); token != want {
		t.Fatalf("requestedAt rewritten %q inside the persisted gate, want %q",
			token, want)
	}
}

// The 30m cooldown: a second sweep inside the window must not re-patch
// — the requestedAt stamp we left is the durable half.
func TestCheckFluxHelmReleaseRetriesCooldown(t *testing.T) {
	base := time.Now()
	hr := shHR("apps", "hr", "False", "UpgradeFailed",
		"upgrade failed", base.Add(-time.Hour))
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn(hr))
	p.Now = func() time.Time { return base }

	if res := probetest.MustCheck[*fluxHRRetriesCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("precondition: stuck HR must FAIL")
	}
	first, _ := p.Dyn.Resource(hrRetryGVR).Namespace("apps").
		Get(ctx, "hr", metav1.GetOptions{})
	firstToken, _, _ := unstructured.NestedString(
		first.Object, "metadata", "annotations", kube.AnnoFluxRequestedAt)

	// 10m later — still inside the 30m cooldown.
	p.Now = func() time.Time { return base.Add(10 * time.Minute) }
	if res := probetest.MustCheck[*fluxHRRetriesCheck](t, p).Run(ctx); res.Pass {
		t.Fatal("still-stuck HR must keep FAILING")
	}
	got, _ := p.Dyn.Resource(hrRetryGVR).Namespace("apps").
		Get(ctx, "hr", metav1.GetOptions{})
	token, _, _ := unstructured.NestedString(
		got.Object, "metadata", "annotations", kube.AnnoFluxRequestedAt)
	if token != firstToken {
		t.Fatal("re-patched inside the 30m cooldown")
	}
}

// maybePatchHRRetry's failure half: once the persisted cooldown and
// the maintenance/budget gates clear, a failed annotation patch is
// metabolized — IncError'd, ledger unstamped so the next sweep
// retries instead of cooling down on a write that never landed.
func TestMaybePatchHRRetryPatchError(t *testing.T) {
	now := time.Now()
	hr := shHR("apps", "hr", "False", "UpgradeFailed",
		"upgrade failed: timed out", now.Add(-20*time.Minute))
	dyn := probetest.OpDyn(hr)
	dyn.PrependReactor("patch", "helmreleases",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("apiserver down")
		})
	p := &fluxHRRetriesCheck{Deps: &probefw.Deps{
		Name: CheckNameFluxHRRetries,
		CS:   fake.NewSimpleClientset(),
		Dyn:  dyn,
	}}
	before := testutil.QueueErrorCount(t, CheckNameFluxHRRetries)
	p.maybePatchHRRetry(ctx, logr.Discard(), hrRetryGVR, hr,
		"apps/hr", now)
	if got := testutil.QueueErrorCount(t, CheckNameFluxHRRetries) - before; got != 1 {
		t.Fatalf("patch failure metered %v errors, want 1", got)
	}
	ck := probefw.SelfHealKey(CheckNameFluxHRRetries, "apps/hr")
	if p.hrRetryHealed.CooledDown(ck, fluxHRHealCooldown, now) {
		t.Fatal("failed patch stamped the cooldown — next sweep would skip the retry")
	}
}
