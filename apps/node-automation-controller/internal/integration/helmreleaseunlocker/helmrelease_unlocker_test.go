package helmreleaseunlocker

import (
	"errors"
	"strconv"
	"testing"
	"time"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
	kfake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

func newDynFake(objs ...runtime.Object) *fake.FakeDynamicClient {
	return testutil.NewDynamicClient(objs...)
}

func hrObj(ns, name, version string) *unstructured.Unstructured {
	return testutil.Unstructured(
		schema.FromAPIVersionAndKind("helm.toolkit.fluxcd.io/"+version, "HelmRelease"),
		ns, name, nil)
}

func hrReady(u *unstructured.Unstructured, status, msg string) {
	u.Object["status"] = map[string]any{
		"conditions": []any{map[string]any{
			"type":               "Ready",
			"status":             status,
			"message":            msg,
			"lastTransitionTime": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		}},
	}
}

func hrTarget(u *unstructured.Unstructured, ns string) {
	u.Object["spec"] = map[string]any{"targetNamespace": ns}
}

func helmRelSecret(ns, name, release string, rev int, status string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
			Labels: map[string]string{
				"owner":   "helm",
				"name":    release,
				"status":  status,
				"version": strconv.Itoa(rev),
			},
		},
		Type: corev1.SecretType(helmSecretType),
	}
}

func secretExists(t *testing.T, cs *kfake.Clientset, ns, name string) bool {
	t.Helper()
	_, err := cs.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		return true
	}
	if !apierrors.IsNotFound(err) {
		t.Fatalf("get secret %s/%s: %v", ns, name, err)
	}
	return false
}

func hrAnnotation(t *testing.T, dyn *fake.FakeDynamicClient, gvr schema.GroupVersionResource, ns, name, anno string) string {
	t.Helper()
	u, err := dyn.Resource(gvr).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get hr %s/%s: %v", ns, name, err)
	}
	return u.GetAnnotations()[anno]
}

func newUnlocker(cs *kfake.Clientset, dyn *fake.FakeDynamicClient, stuckFor time.Duration, key string) *helmReleaseUnlocker {
	u := &helmReleaseUnlocker{queue: "helmrelease-unlocker",
		cs:  cs,
		dyn: dyn,
	}
	if key != "" {
		u.pending.firstSeen.Observe(key, time.Now().Add(-stuckFor))
	}
	return u
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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

// An HR that is stuck again inside the 24h cooldown: the previous
// unlock did not fix it → alert (IncError), no action.
func TestHelmReleaseUnlockerCooldownAlert(t *testing.T) {
	hr := hrObj("apps", "myapp", "v2")
	hrReady(hr, "False", "another operation is in progress")

	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v1", "myapp", 1, "deployed"),
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v2", "myapp", 2, "pending-upgrade"))
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")
	u.pending.unlocked.Stamp("apps/myapp", time.Now().Add(-time.Hour)) // unlocked 1h ago

	before := testutil.ReconcileErrorCount(t, "helmrelease-unlocker")
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("secret deleted inside the 24h cooldown")
	}
	if got := hrAnnotation(t, dyn, helmReleaseGVRs[0], "apps", "myapp", fluxReconcileAnno); got != "" {
		t.Fatal("HR annotated inside the 24h cooldown")
	}
	if got := testutil.ReconcileErrorCount(t, "helmrelease-unlocker"); got != before+1 {
		t.Fatalf("cooldown alert did not IncError: got %v, want %v", got, before+1)
	}
}

// Cooldown expired (>24h) → a fresh unlock IS allowed.
func TestHelmReleaseUnlockerCooldownExpired(t *testing.T) {
	hr := hrObj("apps", "myapp", "v2")
	hrReady(hr, "False", "another operation is in progress")

	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v1", "myapp", 1, "deployed"),
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v2", "myapp", 2, "pending-rollback"))
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")
	u.pending.unlocked.Stamp("apps/myapp", time.Now().Add(-25*time.Hour))

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("pending secret not deleted after cooldown expiry")
	}
}

// helm-controller CrashLoopBackOff → warn + skip the whole run:
// without a working controller the unlock cannot converge.
func TestHelmReleaseUnlockerCrashLoopSkip(t *testing.T) {
	hr := hrObj("apps", "myapp", "v2")
	hrReady(hr, "False", "another operation is in progress")

	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v1", "myapp", 1, "deployed"),
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v2", "myapp", 2, "pending-upgrade"),
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "helm-controller-abc",
				Namespace: "flux-system",
				Labels:    map[string]string{"app.kubernetes.io/name": "helm-controller"},
			},
			Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
				Name:  "manager",
				State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
			}}},
		})
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("secret deleted while helm-controller is crashlooping")
	}
}

// The 30m first-seen gate: a fresh "in progress" must be tracked but
// never acted on until the window elapses.
func TestHelmReleaseUnlockerFirstSeenGate(t *testing.T) {
	hr := hrObj("apps", "myapp", "v2")
	hrReady(hr, "False", "another operation is in progress")

	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v1", "myapp", 1, "deployed"),
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v2", "myapp", 2, "pending-upgrade"))
	u := newUnlocker(cs, dyn, 0, "")

	// First run: records first-seen, must NOT act.
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := u.pending.firstSeen.Seen("apps/myapp", time.Now()); !ok {
		t.Fatal("stuck HR not tracked in firstSeen")
	}
	if !secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("acted before the 30m window elapsed")
	}

	// Second run inside the window: still no action.
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("acted before the 30m window elapsed (2nd tick)")
	}

	// Window elapsed → act. Forget+Observe re-seeds the first-seen
	// stamp unconditionally (Observe alone only stamps absent keys).
	u.pending.firstSeen.Forget("apps/myapp")
	u.pending.firstSeen.Observe("apps/myapp", time.Now().Add(-helmStuckThreshold-time.Minute))
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("pending secret not deleted after the 30m window")
	}
}

// Recovery prunes the first-seen marker so a later stall re-arms.
func TestHelmReleaseUnlockerRecoveryPrunesFirstSeen(t *testing.T) {
	hr := hrObj("apps", "myapp", "v2")
	hrReady(hr, "False", "another operation is in progress")

	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset()
	u := newUnlocker(cs, dyn, 0, "")

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := u.pending.firstSeen.Seen("apps/myapp", time.Now()); !ok {
		t.Fatal("stuck HR not tracked")
	}

	// HR reconciled fine — message cleared.
	hrReady(hr, "True", "Reconciliation finished")
	if _, err := dyn.Resource(helmReleaseGVRs[0]).Namespace("apps").
		Update(ctx, hr, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := u.pending.firstSeen.Seen("apps/myapp", time.Now()); ok {
		t.Fatal("recovered HR not pruned from firstSeen")
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

// stuckHRFixture builds the standard due-for-unlock scene: HR stuck on
// "in progress" past the 30m window plus a deployed + pending secret pair.
func stuckHRFixture() (*fake.FakeDynamicClient, []runtime.Object) {
	hr := hrObj("apps", "myapp", "v2")
	hrReady(hr, "False", "another operation is in progress")
	return newDynFake(hr), []runtime.Object{
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v1", "myapp", 1, "deployed"),
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v2", "myapp", 2, "pending-upgrade"),
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

// The unlock ledger prunes entries whose HelmRelease vanished or whose
// stamp aged past the 24h cooldown, and keeps a live HR still inside it.
func TestHelmReleaseUnlockerPrunesUnlockedLedger(t *testing.T) {
	live := hrObj("apps", "myapp", "v2")
	hrReady(live, "True", "Reconciliation finished")
	old := hrObj("apps", "oldrel", "v2")
	hrReady(old, "True", "Reconciliation finished")
	dyn := newDynFake(live, old)
	u := newUnlocker(kfake.NewSimpleClientset(), dyn, 0, "")
	u.pending.unlocked.Stamp("apps/myapp", time.Now()) // live HR inside cooldown → keep
	u.pending.unlocked.Stamp("apps/gone", time.Now())  // HR vanished → prune
	// Live HR past the cooldown → pruned by age, not absence.
	u.pending.unlocked.Stamp("apps/oldrel", time.Now().Add(-helmUnlockCooldown-time.Minute))

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := u.pending.unlocked.Entries()["apps/gone"]; ok {
		t.Fatal("unlocked entry for a deleted HR not pruned")
	}
	if _, ok := u.pending.unlocked.Entries()["apps/oldrel"]; ok {
		t.Fatal("live HR's unlocked entry past the cooldown not pruned")
	}
	if _, ok := u.pending.unlocked.Entries()["apps/myapp"]; !ok {
		t.Fatal("live HR inside the cooldown lost its unlock-ledger entry")
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

// ---------------------------------------------------------------------------
// C3a — failed helm-hook Job reaper
// ---------------------------------------------------------------------------

// hookJob builds a Job carrying the helm.sh/hook annotation and the
// meta.helm.sh/release-name label helm stamps on every rendered
// resource, hooks included; failed controls whether it reports
// JobFailed=True.
func hookJob(ns, name, release string, failed bool) *batchv1.Job {
	j := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   ns,
			Name:        name,
			Annotations: map[string]string{"helm.sh/hook": "pre-upgrade"},
			Labels:      map[string]string{helmReleaseNameLabel: release},
		},
	}
	if failed {
		j.Status.Conditions = []batchv1.JobCondition{{
			Type:   batchv1.JobFailed,
			Status: corev1.ConditionTrue,
		}}
	}
	return j
}

// plainFailedJob: JobFailed=True but NO helm.sh/hook annotation — the
// reaper must never touch non-hook Jobs (failed-jobs-janitor's turf).
func plainFailedJob(ns, name string) *batchv1.Job {
	j := hookJob(ns, name, "myapp", true)
	j.Annotations = nil
	return j
}

func jobExists(t *testing.T, cs *kfake.Clientset, ns, name string) bool {
	t.Helper()
	_, err := cs.BatchV1().Jobs(ns).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		return true
	}
	if !apierrors.IsNotFound(err) {
		t.Fatalf("get job %s/%s: %v", ns, name, err)
	}
	return false
}

// On a real unlock, a FAILED helm-hook Job in the HR's target namespace
// is reaped (it would block the retried release's hooks), while a
// still-running hook Job, a non-hook failed Job, a hook Job of
// ANOTHER release (wrong or missing meta.helm.sh/release-name), and
// hook Jobs in other namespaces are all left alone.
func TestHelmReleaseUnlockerReapsFailedHookJobs(t *testing.T) {
	dyn, secrets := stuckHRFixture()
	foreign := hookJob("apps", "foreign-release-hook", "other-release", true)
	unattributed := hookJob("apps", "unattributed-hook", "myapp", true)
	unattributed.Labels = nil // helm.sh/hook without release attribution
	cs := kfake.NewSimpleClientset(append(secrets,
		hookJob("apps", "myapp-pre-upgrade", "myapp", true),   // reaped
		hookJob("apps", "myapp-post-upgrade", "myapp", false), // still running — kept
		plainFailedJob("apps", "unrelated-batch"),             // no hook anno — kept
		foreign,      // another release's hook — kept
		unattributed, // no release label — kept
		hookJob("other-ns", "other-hook", "myapp", true), // wrong ns — kept
	)...)
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")

	before := promtestutil.ToFloat64(
		metrics.HelmHookJobsCleanedTotal.WithLabelValues("apps"))
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if jobExists(t, cs, "apps", "myapp-pre-upgrade") {
		t.Fatal("failed helm-hook Job not reaped on unlock")
	}
	for _, n := range []string{"myapp-post-upgrade", "unrelated-batch",
		"foreign-release-hook", "unattributed-hook"} {
		if !jobExists(t, cs, "apps", n) {
			t.Fatalf("job %s reaped — only FAILED Jobs attributed to THIS release may go", n)
		}
	}
	if !jobExists(t, cs, "other-ns", "other-hook") {
		t.Fatal("hook Job outside the target namespace reaped")
	}
	if got := promtestutil.ToFloat64(
		metrics.HelmHookJobsCleanedTotal.WithLabelValues("apps")) - before; got != 1 {
		t.Fatalf("HelmHookJobsCleanedTotal{apps} delta = %v, want 1", got)
	}
}

// The same Job list now feeds the live-upgrade progress gate BEFORE
// the destructive delete, so a failing Job list fails closed: without
// evidence the namespace is quiet, the pending secret must NOT be
// deleted (unlocking blind is exactly what the gate exists to
// prevent). The refusal IncErrors, stamps nothing, and the next sweep
// re-evaluates.
func TestHelmReleaseUnlockerHookJobListErrorFailsClosed(t *testing.T) {
	dyn, secrets := stuckHRFixture()
	cs := kfake.NewSimpleClientset(secrets...)
	cs.PrependReactor("list", "jobs",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("jobs list boom")
		})
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")

	before := testutil.QueueErrorCount(t, "helmrelease-unlocker")
	if err := u.run(ctx); err != nil {
		t.Fatalf("per-HR gate failure must not error the run: %v", err)
	}
	if got := testutil.QueueErrorCount(t, "helmrelease-unlocker") - before; got < 1 {
		t.Fatal("hook-job gate failure did not IncError")
	}
	if !secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("pending secret deleted although progress could not be verified")
	}
	if _, ok := u.pending.unlocked.Entries()["apps/myapp"]; ok {
		t.Fatal("HR stamped unlocked although the unlock was refused")
	}
	if got := hrAnnotation(t, dyn, helmReleaseGVRs[0], "apps", "myapp", fluxReconcileAnno); got != "" {
		t.Fatal("requestedAt stamped although the unlock was refused")
	}
}

// A refused unlock (pending-install with no rollback target) never
// reaches the hook sweep — nothing is touched.
func TestHelmReleaseUnlockerRefusedUnlockSkipsHookSweep(t *testing.T) {
	hr := hrObj("apps", "myapp", "v2")
	hrReady(hr, "False", "Helm install failed: another operation is in progress")
	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v1", "myapp", 1, "pending-install"),
		hookJob("apps", "myapp-pre-install", "myapp", true))
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !jobExists(t, cs, "apps", "myapp-pre-install") {
		t.Fatal("hook Job reaped although the unlock was refused")
	}
}

// ---------------------------------------------------------------------------
// Live-upgrade progress gate (before the pending-secret delete)
// ---------------------------------------------------------------------------

// hookJobStarted builds a hook Job with NO terminal condition created
// createdAgo ago; pods sets Status.Active (a genuinely running Job has
// active pods; a wedged or not-yet-scheduled one has none).
func hookJobStarted(ns, name, release string, createdAgo time.Duration, pods int32) *batchv1.Job {
	j := hookJob(ns, name, release, false)
	j.CreationTimestamp = metav1.NewTime(time.Now().Add(-createdAgo))
	j.Status.Active = pods
	return j
}

// Branch 1 — a hook Job still running in the release namespace is
// live reconcile evidence: the pending-secret delete must NOT fire on
// an upgrade that is genuinely mid-flight, and the skip stamps
// neither the unlock cooldown nor the requestedAt hint.
func TestHelmReleaseUnlockerSkipsRunningHookJob(t *testing.T) {
	dyn, secrets := stuckHRFixture()
	cs := kfake.NewSimpleClientset(append(secrets,
		hookJobStarted("apps", "myapp-pre-upgrade", "myapp", time.Hour, 1), // Running — upgrade alive
	)...)
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("pending secret deleted although a hook Job is still running")
	}
	if _, ok := u.pending.unlocked.Entries()["apps/myapp"]; ok {
		t.Fatal("HR stamped unlocked although the upgrade looked alive")
	}
	if got := hrAnnotation(t, dyn, helmReleaseGVRs[0], "apps", "myapp", fluxReconcileAnno); got != "" {
		t.Fatal("requestedAt stamped although the upgrade looked alive")
	}
	// The running hook Job itself is never reaped (only FAILED ones are).
	if !jobExists(t, cs, "apps", "myapp-pre-upgrade") {
		t.Fatal("running hook Job reaped although the unlock was skipped")
	}
}

// Branch 1b — a hook Job freshly created (inside helmHookFreshWindow)
// whose pods have not shown up yet is the same evidence: helm just
// started its hook, deleting the pending secret now would truncate it.
func TestHelmReleaseUnlockerSkipsFreshHookJob(t *testing.T) {
	dyn, secrets := stuckHRFixture()
	cs := kfake.NewSimpleClientset(append(secrets,
		hookJobStarted("apps", "myapp-pre-upgrade", "myapp", time.Minute, 0), // just created, pods pending
	)...)
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("pending secret deleted although a hook Job was just created")
	}
	if _, ok := u.pending.unlocked.Entries()["apps/myapp"]; ok {
		t.Fatal("HR stamped unlocked although the upgrade looked alive")
	}
}

// Branch 2 — terminal hook Jobs are the residue of the WEDGED
// attempt, not progress: a Failed hook Job and a stale pod-less hook
// Job (created long before the fresh window, no active pods) both
// leave the unlock free to act exactly as before.
func TestHelmReleaseUnlockerTerminalHookResidueStillUnlocks(t *testing.T) {
	dyn, secrets := stuckHRFixture()
	cs := kfake.NewSimpleClientset(append(secrets,
		hookJob("apps", "myapp-pre-upgrade", "myapp", true),               // Failed — residue
		hookJobStarted("apps", "myapp-old-hook", "myapp", 2*time.Hour, 0), // stale, no pods — residue
	)...)
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("wedged pending secret not unlocked — terminal hook residue blocked the unlock")
	}
	if _, ok := u.pending.unlocked.Entries()["apps/myapp"]; !ok {
		t.Fatal("HR not stamped unlocked")
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

// A hook Job delete losing the race (NotFound) is equally benign for
// the sweep: the unlock still lands and no error is counted.
func TestHelmReleaseUnlockerHookJobDeleteNotFoundIsBenign(t *testing.T) {
	dyn, secrets := stuckHRFixture()
	cs := kfake.NewSimpleClientset(append(secrets,
		hookJob("apps", "myapp-pre-upgrade", "myapp", true))...)
	cs.PrependReactor("delete", "jobs",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(
				batchv1.Resource("jobs"), "myapp-pre-upgrade")
		})
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")

	before := testutil.QueueErrorCount(t, "helmrelease-unlocker")
	if err := u.run(ctx); err != nil {
		t.Fatalf("a NotFound race must not error the run: %v", err)
	}
	if got := testutil.QueueErrorCount(t, "helmrelease-unlocker") - before; got != 0 {
		t.Fatalf("NotFound hook delete counted as an error: +%v", got)
	}
	if secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("unlock skipped — a benign NotFound hook delete blocked it")
	}
	if _, ok := u.pending.unlocked.Entries()["apps/myapp"]; !ok {
		t.Fatal("unlock undone by a benign NotFound hook delete")
	}
}

// jobFailed is True only on an explicit JobFailed=True condition —
// absent conditions, JobFailed=False, Suspended and Complete all stay.
func TestJobFailedCondition(t *testing.T) {
	cond := func(tpe batchv1.JobConditionType, st corev1.ConditionStatus) *batchv1.Job {
		return &batchv1.Job{Status: batchv1.JobStatus{
			Conditions: []batchv1.JobCondition{{Type: tpe, Status: st}}}}
	}
	for _, tc := range []struct {
		name string
		job  *batchv1.Job
		want bool
	}{
		{"no conditions", &batchv1.Job{}, false},
		{"failed true", cond(batchv1.JobFailed, corev1.ConditionTrue), true},
		{"failed false", cond(batchv1.JobFailed, corev1.ConditionFalse), false},
		{"suspended", cond(batchv1.JobSuspended, corev1.ConditionTrue), false},
		{"complete", cond(batchv1.JobComplete, corev1.ConditionTrue), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := jobFailed(tc.job); got != tc.want {
				t.Fatalf("jobFailed = %v, want %v", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 2.1 — passiontech.dev/last-helm-unlock persistence & C1 — flux source healer
// ---------------------------------------------------------------------------

func fluxSourceObj(kind, apiVersion, ns, name string) *unstructured.Unstructured {
	return testutil.Unstructured(
		schema.FromAPIVersionAndKind(apiVersion, kind), ns, name, nil)
}

func hrChartRef(hr *unstructured.Unstructured, kind, ns, name string) {
	spec, _, _ := unstructured.NestedMap(hr.Object, "spec")
	if spec == nil {
		spec = map[string]any{}
	}
	ref := map[string]any{"kind": kind, "name": name}
	if ns != "" {
		ref["namespace"] = ns
	}
	spec["chartRef"] = ref
	hr.Object["spec"] = spec
}

func ksObj(ns, name string, staleMsg string, failingFor time.Duration) *unstructured.Unstructured {
	k := testutil.Unstructured(
		fluxKustomizationGVR.GroupVersion().WithKind("Kustomization"), ns, name, nil)
	hrReady(k, "False", staleMsg)
	k.Object["status"].(map[string]any)["conditions"].([]any)[0].(map[string]any)["lastTransitionTime"] = time.Now().Add(-failingFor).UTC().Format(time.RFC3339)
	return k
}

// The persisted passiontech.dev/last-helm-unlock stamp IS the cooldown: with
// an empty in-RAM ledger (post-restart) an HR still inside 24h is
// alerted, not re-unlocked.
func TestHelmReleaseUnlockerPersistedCooldown(t *testing.T) {
	hr := hrObj("apps", "myapp", "v2")
	hrReady(hr, "False", "another operation is in progress")
	hr.SetAnnotations(map[string]string{
		helmLastUnlockAnno: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	})
	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v1", "myapp", 1, "deployed"),
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v2", "myapp", 2, "pending-upgrade"))
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")

	before := testutil.ReconcileErrorCount(t, "helmrelease-unlocker")
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("secret deleted inside the persisted 24h cooldown")
	}
	if got := testutil.ReconcileErrorCount(t, "helmrelease-unlocker"); got != before+1 {
		t.Fatalf("persisted-cooldown alert did not IncError: got %v, want %v", got, before+1)
	}
}

// A successful unlock stamps BOTH reconcile.fluxcd.io/requestedAt and
// passiontech.dev/last-helm-unlock on the HR.
func TestHelmReleaseUnlockerStampsLastUnlockAnnotation(t *testing.T) {
	dyn, secrets := stuckHRFixture()
	cs := kfake.NewSimpleClientset(secrets...)
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	got := hrAnnotation(t, dyn, helmReleaseGVRs[0], "apps", "myapp", helmLastUnlockAnno)
	if got == "" {
		t.Fatal("passiontech.dev/last-helm-unlock not persisted on unlock")
	}
	if _, err := time.Parse(time.RFC3339, got); err != nil {
		t.Fatalf("last-helm-unlock %q is not RFC3339: %v", got, err)
	}
}

// C1 — an HR Ready=False >=15m on "artifact not found" nudges its
// chartRef HelmChart source: requestedAt + last-source-nudge land and
// the counter increments. A stale message on a fresh failure does not.
func TestFluxSourceHealerHelmRelease(t *testing.T) {
	hr := hrObj("apps", "myapp", "v2")
	hrReady(hr, "False", "HelmChart 'flux-system/apps-myapp' artifact not found")
	hrChartRef(hr, "HelmChart", "flux-system", "apps-myapp")
	// A sibling HR failing for a non-artifact reason — untouched.
	other := hrObj("apps", "other", "v2")
	hrReady(other, "False", "rendering failed: values.schema violation")
	// A fresh artifact failure (<15m) — still inside flux's retry, not ours.
	fresh := hrObj("apps", "fresh", "v2")
	fresh.Object["status"] = map[string]any{"conditions": []any{map[string]any{
		"type": "Ready", "status": "False",
		"message":            "artifact not found",
		"lastTransitionTime": time.Now().Add(-2 * time.Minute).UTC().Format(time.RFC3339),
	}}}
	hrChartRef(fresh, "HelmChart", "flux-system", "apps-fresh")
	src := fluxSourceObj("HelmChart", "source.toolkit.fluxcd.io/v1",
		"flux-system", "apps-myapp")
	srcFresh := fluxSourceObj("HelmChart", "source.toolkit.fluxcd.io/v1",
		"flux-system", "apps-fresh")
	dyn := newDynFake(hr, other, fresh, src, srcFresh)
	u := newUnlocker(kfake.NewSimpleClientset(), dyn, 0, "")

	before := promtestutil.ToFloat64(metrics.FluxSourceReconcilesTriggeredTotal.
		WithLabelValues("HelmChart", "flux-system", "apps-myapp"))
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := hrAnnotation(t, dyn, kube.FluxSourceGVRs["HelmChart"], "flux-system",
		"apps-myapp", fluxReconcileAnno); got == "" {
		t.Fatal("HelmChart source not stamped with requestedAt")
	}
	if got := hrAnnotation(t, dyn, kube.FluxSourceGVRs["HelmChart"], "flux-system",
		"apps-myapp", fluxLastNudgeAnno); got == "" {
		t.Fatal("HelmChart source not stamped with last-source-nudge")
	}
	if got := hrAnnotation(t, dyn, kube.FluxSourceGVRs["HelmChart"], "flux-system",
		"apps-fresh", fluxReconcileAnno); got != "" {
		t.Fatal("fresh artifact failure nudged its source — 15m gate broken")
	}
	if got := promtestutil.ToFloat64(metrics.FluxSourceReconcilesTriggeredTotal.
		WithLabelValues("HelmChart", "flux-system", "apps-myapp")) - before; got != 1 {
		t.Fatalf("FluxSourceReconcilesTriggeredTotal delta = %v, want 1", got)
	}
}

// C1 — Kustomization with spec.sourceRef GitRepository gets the same
// treatment, and the 30m per-source cooldown blocks a repeat nudge.
func TestFluxSourceHealerKustomization(t *testing.T) {
	k := ksObj("apps", "root", "failed to fetch artifact: revision not found", 30*time.Minute)
	k.Object["spec"] = map[string]any{
		"sourceRef": map[string]any{"kind": "GitRepository", "name": "flux-system"},
	}
	src := fluxSourceObj("GitRepository", "source.toolkit.fluxcd.io/v1",
		"apps", "flux-system")
	dyn := newDynFake(k, src)
	u := newUnlocker(kfake.NewSimpleClientset(), dyn, 0, "")

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	stamp := hrAnnotation(t, dyn, kube.FluxSourceGVRs["GitRepository"], "apps",
		"flux-system", fluxReconcileAnno)
	if stamp == "" {
		t.Fatal("GitRepository source not stamped")
	}
	// Second sweep inside the 30m cooldown → stamp must not change.
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := hrAnnotation(t, dyn, kube.FluxSourceGVRs["GitRepository"], "apps",
		"flux-system", fluxReconcileAnno); got != stamp {
		t.Fatal("source re-nudged inside the 30m per-source cooldown")
	}
}

// C1 sweep economy: N stale consumers sharing one GitRepository cost
// exactly ONE Get + one patch (the per-sweep dedupe claims the source
// for the first consumer), and the Kustomization list is paged once
// for BOTH K-scanning healers.
func TestFluxSourceHealerDedupesSharedSource(t *testing.T) {
	ks := func(name string) *unstructured.Unstructured {
		k := ksObj("apps", name, "failed to fetch artifact", time.Hour)
		k.Object["spec"] = map[string]any{
			"sourceRef": map[string]any{"kind": "GitRepository", "name": "flux-system"},
		}
		return k
	}
	src := fluxSourceObj("GitRepository", "source.toolkit.fluxcd.io/v1",
		"apps", "flux-system")
	dyn := newDynFake(ks("root"), ks("apps"), src)
	var gets, patches, ksLists int
	dyn.PrependReactor("get", "gitrepositories",
		func(ktesting.Action) (bool, runtime.Object, error) {
			gets++
			return false, nil, nil
		})
	dyn.PrependReactor("patch", "gitrepositories",
		func(ktesting.Action) (bool, runtime.Object, error) {
			patches++
			return false, nil, nil
		})
	dyn.PrependReactor("list", "kustomizations",
		func(ktesting.Action) (bool, runtime.Object, error) {
			ksLists++
			return false, nil, nil
		})
	u := newUnlocker(kfake.NewSimpleClientset(), dyn, 0, "")

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if gets != 1 || patches != 1 {
		t.Fatalf("shared source: %d Gets + %d patches, want 1 each", gets, patches)
	}
	if ksLists != 1 {
		t.Fatalf("kustomizations listed %d times in one sweep, want 1", ksLists)
	}
}

// FluxSourceReconcilesTriggeredTotal{kind,namespace,name} carries a
// 2-set carry-forward prune: once the sweep no longer resolves ANY
// consumer to a nudged source, its series is DeleteLabelValues'd; a
// source a consumer still resolves keeps both its series and its
// counter value (no reset, no re-Inc inside the 30m cooldown).
func TestFluxSourceSeriesPrunedWhenConsumerVanishes(t *testing.T) {
	staleHR := func(ns, name, repo string) *unstructured.Unstructured {
		hr := hrObj(ns, name, "v2")
		hrReady(hr, "False", "artifact not found: failed to fetch from origin")
		hr.Object["spec"] = map[string]any{
			"chart": map[string]any{"spec": map[string]any{
				"sourceRef": map[string]any{"kind": "GitRepository", "name": repo},
			}},
		}
		return hr
	}
	dyn := newDynFake(staleHR("apps", "stale-a", "repo-a"),
		staleHR("apps", "stale-c", "repo-c"),
		fluxSourceObj("GitRepository", "source.toolkit.fluxcd.io/v1", "apps", "repo-a"),
		fluxSourceObj("GitRepository", "source.toolkit.fluxcd.io/v1", "apps", "repo-c"))
	u := newUnlocker(kfake.NewSimpleClientset(), dyn, 0, "")
	for _, lv := range [][]string{
		{"GitRepository", "apps", "repo-a"},
		{"GitRepository", "apps", "repo-c"},
	} {
		testutil.CleanupMetric(t, metrics.FluxSourceReconcilesTriggeredTotal, lv...)
	}

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, repo := range []string{"repo-a", "repo-c"} {
		if got := promtestutil.ToFloat64(metrics.FluxSourceReconcilesTriggeredTotal.
			WithLabelValues("GitRepository", "apps", repo)); got != 1 {
			t.Fatalf("%s nudge counter = %v, want 1 after the first sweep", repo, got)
		}
	}

	// The consumer of repo-a is gone; repo-c keeps its consumer. The
	// next sweep prunes repo-a's series and leaves repo-c's untouched.
	if err := dyn.Resource(helmReleaseGVRs[0]).Namespace("apps").
		Delete(ctx, "stale-a", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if metrics.FluxSourceReconcilesTriggeredTotal.DeleteLabelValues(
		"GitRepository", "apps", "repo-a") {
		t.Fatal("series for a source with no consumer left was not deleted")
	}
	if got := promtestutil.ToFloat64(metrics.FluxSourceReconcilesTriggeredTotal.
		WithLabelValues("GitRepository", "apps", "repo-c")); got != 1 {
		t.Fatalf("surviving source's counter reset: got %v, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// kine-bloat-guard — superseded helm release secret pruner
// ---------------------------------------------------------------------------

// A release with more than maxSupersededSecrets superseded secrets
// loses the OLDEST excess — deployed/pending/failed secrets and the
// highest-version secret are never touched, and each delivered delete
// bumps HelmSecretsPrunedTotal{namespace}.
func TestHelmReleaseUnlockerPrunesSupersededSecrets(t *testing.T) {
	var objs []runtime.Object
	// 12 superseded revisions v1..v12 for release myrel.
	for v := 1; v <= 12; v++ {
		objs = append(objs, helmRelSecret("apps",
			"sh.helm.release.v1.myrel.v"+strconv.Itoa(v), "myrel", v, "superseded"))
	}
	// Live-state secrets that must survive: deployed v13 (also the
	// highest version), pending-upgrade v14, failed v15.
	objs = append(objs,
		helmRelSecret("apps", "sh.helm.release.v1.myrel.v13", "myrel", 13, "deployed"),
		helmRelSecret("apps", "sh.helm.release.v1.myrel.v14", "myrel", 14, "pending-upgrade"),
		helmRelSecret("apps", "sh.helm.release.v1.myrel.v15", "myrel", 15, "failed"),
		// A second release under the cap — untouched.
		helmRelSecret("apps", "sh.helm.release.v1.small.v1", "small", 1, "superseded"),
		helmRelSecret("apps", "sh.helm.release.v1.small.v2", "small", 2, "superseded"),
		// Not a helm release secret — ignored entirely.
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "plain",
			Labels: map[string]string{"owner": "helm", "name": "myrel",
				"status": "superseded", "version": "1"}},
			Type: corev1.SecretTypeOpaque},
	)
	cs := kfake.NewSimpleClientset(objs...)
	dyn := newDynFake()
	u := newUnlocker(cs, dyn, 0, "")

	before := promtestutil.ToFloat64(
		metrics.HelmSecretsPrunedTotal.WithLabelValues("apps"))
	if err := u.pruneSupersededSecrets(ctx); err != nil {
		t.Fatal(err)
	}
	after := promtestutil.ToFloat64(
		metrics.HelmSecretsPrunedTotal.WithLabelValues("apps"))
	if got := after - before; got != 2 {
		t.Fatalf("pruned counter delta = %v, want 2 (12 superseded - cap 10)", got)
	}
	// Oldest two superseded gone.
	for _, v := range []int{1, 2} {
		if secretExists(t, cs, "apps",
			"sh.helm.release.v1.myrel.v"+strconv.Itoa(v)) {
			t.Fatalf("superseded v%d must be pruned", v)
		}
	}
	// The remaining 10 superseded + all live-state secrets survive.
	for v := 3; v <= 15; v++ {
		if !secretExists(t, cs, "apps",
			"sh.helm.release.v1.myrel.v"+strconv.Itoa(v)) {
			t.Fatalf("secret v%d must survive", v)
		}
	}
	for _, s := range []string{
		"sh.helm.release.v1.small.v1", "sh.helm.release.v1.small.v2", "plain"} {
		if !secretExists(t, cs, "apps", s) {
			t.Fatalf("%s must survive", s)
		}
	}
}

// A release at exactly the cap is a no-op — and the highest-version
// secret is protected even when it is itself superseded.
func TestHelmReleaseUnlockerPrunerKeepsHighestAndCap(t *testing.T) {
	var objs []runtime.Object
	// Exactly 10 superseded — at the cap, nothing pruned.
	for v := 1; v <= 10; v++ {
		objs = append(objs, helmRelSecret("apps",
			"sh.helm.release.v1.cap.v"+strconv.Itoa(v), "cap", v, "superseded"))
	}
	// 11 superseded where the NEWEST is itself superseded — the
	// highest-version secret must survive even though it is a
	// prune candidate by status.
	for v := 1; v <= 11; v++ {
		objs = append(objs, helmRelSecret("apps",
			"sh.helm.release.v1.top.v"+strconv.Itoa(v), "top", v, "superseded"))
	}
	cs := kfake.NewSimpleClientset(objs...)
	u := newUnlocker(cs, newDynFake(), 0, "")
	if err := u.pruneSupersededSecrets(ctx); err != nil {
		t.Fatal(err)
	}
	for v := 1; v <= 10; v++ {
		if !secretExists(t, cs, "apps",
			"sh.helm.release.v1.cap.v"+strconv.Itoa(v)) {
			t.Fatalf("at-cap release lost v%d", v)
		}
	}
	// top: 11 superseded, cap 10 → delete 1 oldest (v1); v11 is the
	// highest version and stays even though superseded.
	if secretExists(t, cs, "apps", "sh.helm.release.v1.top.v1") {
		t.Fatal("oldest superseded of over-cap release must be pruned")
	}
	for v := 2; v <= 11; v++ {
		if !secretExists(t, cs, "apps",
			"sh.helm.release.v1.top.v"+strconv.Itoa(v)) {
			t.Fatalf("top release lost v%d", v)
		}
	}
}
