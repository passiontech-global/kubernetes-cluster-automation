// unlock_pending_secret_test.go — the pending-secret decision path:
// the unlock itself, the no-rollback refusal, the v2beta2 fallback,
// unparseable versions, delete errors and the NotFound race, plus the
// flux release/storage namespace resolvers.
package helmreleaseunlocker

import (
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	kfake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// Stuck >30m + newest revision pending + older deployed revision →
// pending secret deleted and reconcile requested on the HR.
func TestHelmReleaseUnlockerDeletesPendingSecret(t *testing.T) {
	hr := hrObj("apps", "myapp", "v2")
	hrReady(hr, "False", "Helm upgrade failed: another operation (install/upgrade/rollback) is in progress")

	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(
		helmRelSecret("apps", "sh.helm.release.v1.myrel.v1", "myapp", 1, "superseded"),
		helmRelSecret("apps", "sh.helm.release.v1.myrel.v2", "myapp", 2, "deployed"),
		helmRelSecret("apps", "sh.helm.release.v1.myrel.v3", "myapp", 3, "pending-upgrade"),
		// unrelated release pending secret — must NOT be touched
		helmRelSecret("apps", "sh.helm.release.v1.other.v9", "other", 9, "pending-install"),
		// unrelated namespace secret — must NOT be touched
		helmRelSecret("other-ns", "sh.helm.release.v1.myapp.v3", "myapp", 3, "pending-upgrade"),
	)
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if secretExists(t, cs, "apps", "sh.helm.release.v1.myrel.v3") {
		t.Fatal("newest pending secret not deleted")
	}
	for _, n := range []string{"sh.helm.release.v1.myrel.v1", "sh.helm.release.v1.myrel.v2"} {
		if !secretExists(t, cs, "apps", n) {
			t.Fatalf("rollback revision %s deleted — must be kept", n)
		}
	}
	if !secretExists(t, cs, "apps", "sh.helm.release.v1.other.v9") {
		t.Fatal("other release's pending secret deleted")
	}
	if !secretExists(t, cs, "other-ns", "sh.helm.release.v1.myapp.v3") {
		t.Fatal("secret outside target ns deleted")
	}
	if got := hrAnnotation(t, dyn, helmReleaseGVRs[0], "apps", "myapp", fluxReconcileAnno); got == "" {
		t.Fatal("reconcile.fluxcd.io/requestedAt annotation not stamped")
	}
}

// pending-install with no deployed/superseded predecessor → refuse:
// deleting it would orphan the release.
func TestHelmReleaseUnlockerNoOlderDeployed(t *testing.T) {
	hr := hrObj("apps", "myapp", "v2")
	hrReady(hr, "False", "Helm install failed: another operation is in progress")

	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v1", "myapp", 1, "pending-install"))
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v1") {
		t.Fatal("pending secret deleted despite no rollback target")
	}
	if got := hrAnnotation(t, dyn, helmReleaseGVRs[0], "apps", "myapp", fluxReconcileAnno); got != "" {
		t.Fatal("HR annotated despite refused unlock")
	}
}

// v2 list fails (older flux / CRDs absent) → fall back to v2beta2.
func TestHelmReleaseUnlockerV2beta2Fallback(t *testing.T) {
	hr := hrObj("apps", "myapp", "v2beta2")
	hrReady(hr, "False", "another operation is in progress")

	dyn := newDynFake(hr)
	dyn.PrependReactor("list", "helmreleases",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			if action.GetResource().Version == "v2" {
				return true, nil, errors.New("the server could not find the requested resource")
			}
			return false, nil, nil
		})

	cs := kfake.NewSimpleClientset(
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v1", "myapp", 1, "deployed"),
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v2", "myapp", 2, "pending-uninstall"))
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("pending secret not deleted via v2beta2 fallback")
	}
	if got := hrAnnotation(t, dyn, helmReleaseGVRs[1], "apps", "myapp", fluxReconcileAnno); got == "" {
		t.Fatal("HR not annotated on the v2beta2 GVR")
	}
}

// A release secret whose version label is not an integer is skipped —
// it must not crash the revision scan nor become the deletion target.
func TestHelmReleaseUnlockerUnparseableVersionSkipsSecret(t *testing.T) {
	dyn, secrets := stuckHRFixture()
	// A newer pending secret with a garbage version label — the scan
	// skips it and still finds the real newest pending revision.
	bad := helmRelSecret("apps", "sh.helm.release.v1.myapp.vX", "myapp", 3, "pending-upgrade")
	bad.Labels["version"] = "not-a-rev"
	secrets = append(secrets, bad)
	cs := kfake.NewSimpleClientset(secrets...)
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.vX") {
		t.Fatal("secret with unparseable version was deleted")
	}
	if secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("real newest pending secret not deleted")
	}
}

// A failing pending-secret delete aborts that HR's unlock (logged,
// continue) — the run stays nil and no reconcile is requested.
func TestHelmReleaseUnlockerPendingDeleteError(t *testing.T) {
	dyn, secrets := stuckHRFixture()
	cs := kfake.NewSimpleClientset(secrets...)
	cs.PrependReactor("delete", "secrets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("finalizer wedged")
		})
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")
	if err := u.run(ctx); err != nil {
		t.Fatalf("a per-HR unlock failure must not error the run: %v", err)
	}
	if !secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("pending secret vanished despite the failing delete")
	}
	if got := hrAnnotation(t, dyn, helmReleaseGVRs[0], "apps", "myapp", fluxReconcileAnno); got != "" {
		t.Fatal("HR annotated although the pending secret still exists")
	}
	if _, ok := u.pending.unlocked.Entries()["apps/myapp"]; ok {
		t.Fatal("HR marked unlocked although unlock failed")
	}
}

// The three resolvers mirror upstream flux exactly:
//   - hrReleaseName = GetReleaseName(): spec.releaseName, then
//     "<targetNamespace>-<name>" when targetNamespace is set, then the
//     bare object name;
//   - hrStorageNS = GetStorageNamespace(): spec.storageNamespace ||
//     HR namespace — where the release secrets live (targetNamespace
//     is NOT in this chain);
//   - hrReleaseNS = spec.targetNamespace || HR namespace — where the
//     release (and its hook Jobs) is installed.
func TestHRNameAndNamespaceFallbacks(t *testing.T) {
	hr := hrObj("apps", "myapp", "v2")
	if got := hrReleaseName(hr); got != "myapp" {
		t.Fatalf("hrReleaseName fallback = %q, want myapp", got)
	}
	if got := hrStorageNS(hr); got != "apps" {
		t.Fatalf("hrStorageNS fallback = %q, want apps", got)
	}
	if got := hrReleaseNS(hr); got != "apps" {
		t.Fatalf("hrReleaseNS fallback = %q, want apps", got)
	}

	// targetNamespace alone prefixes the release name (flux's rule —
	// same-named HRs released into different namespaces must not
	// collide) and moves the RELEASE ns, but the secrets stay in the
	// HR's own namespace (the storage default).
	hr.Object["spec"] = map[string]any{"targetNamespace": "target-ns"}
	if got := hrReleaseName(hr); got != "target-ns-myapp" {
		t.Fatalf("hrReleaseName = %q, want target-ns-myapp", got)
	}
	if got := hrStorageNS(hr); got != "apps" {
		t.Fatalf("hrStorageNS = %q, want apps (targetNamespace is not storage)", got)
	}
	if got := hrReleaseNS(hr); got != "target-ns" {
		t.Fatalf("hrReleaseNS = %q, want target-ns", got)
	}

	// releaseName wins over the prefix rule.
	hr.Object["spec"].(map[string]any)["releaseName"] = "customrel"
	if got := hrReleaseName(hr); got != "customrel" {
		t.Fatalf("hrReleaseName = %q, want customrel", got)
	}

	// storageNamespace moves ONLY the secrets — release name and
	// release namespace are untouched by it.
	hr.Object["spec"].(map[string]any)["storageNamespace"] = "storage-ns"
	if got := hrStorageNS(hr); got != "storage-ns" {
		t.Fatalf("hrStorageNS = %q, want storage-ns", got)
	}
	if got := hrReleaseName(hr); got != "customrel" {
		t.Fatalf("hrReleaseName = %q, want customrel (storageNamespace must not leak)", got)
	}
	if got := hrReleaseNS(hr); got != "target-ns" {
		t.Fatalf("hrReleaseNS = %q, want target-ns (storageNamespace must not leak)", got)
	}
}

// Release secrets with only deployed/superseded revisions — no
// pending-* — mean the deadlock signature is absent: clean skip, no
// delete, no annotate.
func TestHelmReleaseUnlockerNoPendingSecret(t *testing.T) {
	hr := hrObj("apps", "myapp", "v2")
	cs := kfake.NewSimpleClientset(
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v1", "myapp", 1, "deployed"),
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v2", "myapp", 2, "superseded"))
	dyn := newDynFake(hr)
	u := newUnlocker(cs, dyn, 0, "")
	acted, err := u.unlock(ctx, helmReleaseGVRs[0], hr)
	if err != nil {
		t.Fatalf("absent pending secret must be a clean skip: %v", err)
	}
	if acted {
		t.Fatal("skip path must not report acted — the caller stamps the unlock ledger on acted")
	}
	for _, name := range []string{
		"sh.helm.release.v1.myapp.v1", "sh.helm.release.v1.myapp.v2"} {
		if !secretExists(t, cs, "apps", name) {
			t.Fatalf("non-pending secret %s touched", name)
		}
	}
	if got := hrAnnotation(t, dyn, helmReleaseGVRs[0], "apps", "myapp", fluxReconcileAnno); got != "" {
		t.Fatal("reconcile requested despite no pending release")
	}
}

// A pending-secret delete racing helm-controller's own cleanup
// (NotFound) is a benign skip: no IncError, no unlock stamp, and the
// next sweep re-evaluates the now secret-less HR.
func TestHelmReleaseUnlockerPendingSecretDeleteNotFound(t *testing.T) {
	dyn, secrets := stuckHRFixture()
	cs := kfake.NewSimpleClientset(secrets...)
	cs.PrependReactor("delete", "secrets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(
				corev1.Resource("secrets"), "sh.helm.release.v1.myapp.v2")
		})
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")

	before := testutil.QueueErrorCount(t, "helmrelease-unlocker")
	if err := u.run(ctx); err != nil {
		t.Fatalf("a NotFound race must not error the run: %v", err)
	}
	if got := testutil.QueueErrorCount(t, "helmrelease-unlocker") - before; got != 0 {
		t.Fatalf("NotFound delete counted as an error: +%v", got)
	}
	if _, ok := u.pending.unlocked.Entries()["apps/myapp"]; ok {
		t.Fatal("HR stamped unlocked although the delete raced away")
	}
	if got := hrAnnotation(t, dyn, helmReleaseGVRs[0], "apps", "myapp", fluxReconcileAnno); got != "" {
		t.Fatal("requestedAt stamped although the delete raced away")
	}
}
