// unlock_semantics_test.go — the run-level error paths and the
// corrected Flux namespace semantics: list failures, absorbed
// per-HR errors with IncError, the annotate-error cooldown contract,
// storage/target namespace behavior and the server-side label
// selector.
package helmreleaseunlocker

import (
	"errors"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	kfake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// Both GVRs failing → real error propagates (periodic wrapper IncError).
func TestHelmReleaseUnlockerListError(t *testing.T) {
	dyn := newDynFake()
	dyn.PrependReactor("list", "helmreleases",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	u := newUnlocker(kfake.NewSimpleClientset(), dyn, 0, "")
	if err := u.run(ctx); err == nil {
		t.Fatal("expected error when every HR list fails")
	}
}

// The helm-controller pod list is a real error — unlocking blind while
// the controller might be down cannot converge.
func TestHelmReleaseUnlockerControllerListError(t *testing.T) {
	dyn, secrets := stuckHRFixture()
	cs := kfake.NewSimpleClientset(secrets...)
	cs.PrependReactor("list", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")
	if err := u.run(ctx); err == nil {
		t.Fatal("expected error when the helm-controller pod list fails")
	}
}

// A release-secrets list failure is a wrapped per-HR error: logged,
// HR skipped — the run itself stays nil and nothing is marked unlocked.
func TestHelmReleaseUnlockerSecretsListError(t *testing.T) {
	dyn, secrets := stuckHRFixture()
	cs := kfake.NewSimpleClientset(secrets...)
	cs.PrependReactor("list", "secrets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("secrets list boom")
		})
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")
	if err := u.run(ctx); err != nil {
		t.Fatalf("a per-HR unlock failure must not error the run: %v", err)
	}
	if !secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("pending secret deleted despite the failed list")
	}
	if _, ok := u.pending.unlocked.Entries()["apps/myapp"]; ok {
		t.Fatal("HR marked unlocked although unlock never ran")
	}
}

// A tolerated per-HR unlock failure is absorbed by the run (logged +
// continue, nil return) — it never reaches the periodic wrapper, so
// run() itself must IncError the queue once to keep it on the alert
// path.
func TestHelmReleaseUnlockerUnlockFailureIncError(t *testing.T) {
	dyn, secrets := stuckHRFixture()
	cs := kfake.NewSimpleClientset(secrets...)
	cs.PrependReactor("delete", "secrets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("finalizer wedged")
		})
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")

	before := testutil.ReconcileErrorCount(t, "helmrelease-unlocker")
	if err := u.run(ctx); err != nil {
		t.Fatalf("a per-HR unlock failure must not error the run: %v", err)
	}
	if got := testutil.ReconcileErrorCount(t, "helmrelease-unlocker"); got != before+1 {
		t.Fatalf("tolerated unlock failure did not IncError: got %v, want %v", got, before+1)
	}
}

// A failing requestedAt patch on the HR surfaces as an unlock error —
// the secret is already gone and the RAM cooldown is already stamped
// (the destructive half landed; only the reconcile hint + persisted
// stamp were lost). The next sweep must NOT re-delete a fresh
// pending-* revision helm-controller's retry creates inside the 24h
// window — that is exactly what the early in-RAM stamp buys.
func TestHelmReleaseUnlockerAnnotateError(t *testing.T) {
	dyn, secrets := stuckHRFixture()
	dyn.PrependReactor("patch", "helmreleases",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("hr patch rejected")
		})
	cs := kfake.NewSimpleClientset(secrets...)
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")
	if err := u.run(ctx); err != nil {
		t.Fatalf("a per-HR unlock failure must not error the run: %v", err)
	}
	if secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("pending secret kept although its delete succeeded")
	}
	if _, ok := u.pending.unlocked.Entries()["apps/myapp"]; !ok {
		t.Fatal("pending-secret delete landed but the 24h cooldown was not stamped — a retried pending revision could be re-deleted next sweep")
	}
}

// End-to-end on the corrected Flux semantics: a targetNamespace-only
// HR in namespace "ops" reads its release secrets from the STORAGE
// namespace (the HR's own — no storageNamespace set) under the
// flux-derived release name "<targetNS>-<name>", and failed hook Jobs
// are swept in the RELEASE namespace (target-ns), not the storage one.
func TestHelmReleaseUnlockerTargetNamespaceSemantics(t *testing.T) {
	hr := hrObj("ops", "myapp", "v2")
	hrTarget(hr, "target-ns")
	hrReady(hr, "False", "another operation is in progress")

	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(
		// Secrets live in the HR namespace (storage default) under
		// the prefixed release name.
		helmRelSecret("ops", "sh.helm.release.v1.r.v1", "target-ns-myapp", 1, "deployed"),
		helmRelSecret("ops", "sh.helm.release.v1.r.v2", "target-ns-myapp", 2, "pending-upgrade"),
		// Secrets under the UNPREFIXED name or in the target ns are
		// not this release's storage — must be left alone.
		helmRelSecret("ops", "sh.helm.release.v1.myapp.v2", "myapp", 2, "pending-upgrade"),
		helmRelSecret("target-ns", "sh.helm.release.v1.r.v2", "target-ns-myapp", 2, "pending-upgrade"),
		// Hook Jobs live in the RELEASE namespace.
		hookJob("target-ns", "myapp-pre-upgrade", "target-ns-myapp", true),
		hookJob("ops", "misplaced-hook", "target-ns-myapp", true), // storage ns — not where hooks run
	)
	u := newUnlocker(cs, dyn, time.Hour, "ops/myapp")

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if secretExists(t, cs, "ops", "sh.helm.release.v1.r.v2") {
		t.Fatal("pending secret in the HR (storage) ns not deleted")
	}
	if !secretExists(t, cs, "ops", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("unprefixed-name secret touched — wrong release")
	}
	if !secretExists(t, cs, "target-ns", "sh.helm.release.v1.r.v2") {
		t.Fatal("secret in the release ns touched — secrets live in storage ns")
	}
	if jobExists(t, cs, "target-ns", "myapp-pre-upgrade") {
		t.Fatal("failed hook Job in the release namespace not reaped")
	}
	if !jobExists(t, cs, "ops", "misplaced-hook") {
		t.Fatal("hook Job in the storage ns reaped — hooks only live in the release ns")
	}
}

// storageNamespace set → the release secrets are read (and the pending
// one deleted) there, not in the HR's namespace.
func TestHelmReleaseUnlockerStorageNamespaceSecrets(t *testing.T) {
	hr := hrObj("ops", "myapp", "v2")
	hr.Object["spec"] = map[string]any{"storageNamespace": "helm-store"}
	hrReady(hr, "False", "another operation is in progress")

	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(
		helmRelSecret("helm-store", "sh.helm.release.v1.myapp.v1", "myapp", 1, "deployed"),
		helmRelSecret("helm-store", "sh.helm.release.v1.myapp.v2", "myapp", 2, "pending-upgrade"),
		// Same-looking secrets in the HR ns — not this release's storage.
		helmRelSecret("ops", "sh.helm.release.v1.myapp.v2", "myapp", 2, "pending-upgrade"),
	)
	u := newUnlocker(cs, dyn, time.Hour, "ops/myapp")

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if secretExists(t, cs, "helm-store", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("pending secret in storageNamespace not deleted")
	}
	if !secretExists(t, cs, "ops", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("secret in the HR ns touched — storage lives in storageNamespace")
	}
}

// The release-secret list is scoped server-side to this release's own
// secrets — the same owner=helm + name=<release> pair the revision
// scan matches on (the fake ignores selectors; assert the request).
func TestHelmReleaseUnlockerSecretListUsesLabelSelector(t *testing.T) {
	dyn, secrets := stuckHRFixture()
	cs := kfake.NewSimpleClientset(secrets...)
	var got labels.Selector
	cs.PrependReactor("list", "secrets",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			if la, ok := a.(ktesting.ListAction); ok {
				got = la.GetListRestrictions().Labels
			}
			return false, nil, nil
		})
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Empty() {
		t.Fatal("release-secret list sent without a label selector")
	}
	if !got.Matches(labels.Set{"owner": "helm", "name": "myapp"}) {
		t.Fatalf("secret list selector %q does not match this release's secrets", got)
	}
	if got.Matches(labels.Set{"owner": "helm", "name": "other"}) {
		t.Fatalf("secret list selector %q is not scoped to the release", got)
	}
	if got.Matches(labels.Set{"name": "myapp"}) { // owner=helm required too
		t.Fatalf("secret list selector %q dropped the owner=helm requirement", got)
	}
}
