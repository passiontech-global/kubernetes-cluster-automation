package controller

import (
	"errors"
	"strconv"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
	kfake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

func newDynFake(objs ...runtime.Object) *fake.FakeDynamicClient {
	return fake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			helmReleaseGVRs[0]:    "HelmReleaseList",
			helmReleaseGVRs[1]:    "HelmReleaseList",
			clusterSecretStoreGVR: "ClusterSecretStoreList",
			externalSecretGVR:     "ExternalSecretList",
		},
		objs...)
}

func hrObj(ns, name, version string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "helm.toolkit.fluxcd.io/" + version,
		"kind":       "HelmRelease",
		"metadata": map[string]any{
			"namespace": ns,
			"name":      name,
		},
	}}
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
	u := &helmReleaseUnlocker{
		cs:        cs,
		dyn:       dyn,
		firstSeen: map[string]time.Time{},
		unlocked:  map[string]time.Time{},
	}
	if key != "" {
		u.firstSeen[key] = time.Now().Add(-stuckFor)
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
	hrTarget(hr, "apps")
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
	hrTarget(hr, "apps")
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
	hrTarget(hr, "apps")
	hrReady(hr, "False", "another operation is in progress")

	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v1", "myapp", 1, "deployed"),
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v2", "myapp", 2, "pending-upgrade"))
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")
	u.unlocked["apps/myapp"] = time.Now().Add(-time.Hour) // unlocked 1h ago

	before := reconcileErrorCount(t, helmUnlockQueue)
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("secret deleted inside the 24h cooldown")
	}
	if got := hrAnnotation(t, dyn, helmReleaseGVRs[0], "apps", "myapp", fluxReconcileAnno); got != "" {
		t.Fatal("HR annotated inside the 24h cooldown")
	}
	if got := reconcileErrorCount(t, helmUnlockQueue); got != before+1 {
		t.Fatalf("cooldown alert did not IncError: got %v, want %v", got, before+1)
	}
}

// Cooldown expired (>24h) → a fresh unlock IS allowed.
func TestHelmReleaseUnlockerCooldownExpired(t *testing.T) {
	hr := hrObj("apps", "myapp", "v2")
	hrTarget(hr, "apps")
	hrReady(hr, "False", "another operation is in progress")

	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v1", "myapp", 1, "deployed"),
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v2", "myapp", 2, "pending-rollback"))
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")
	u.unlocked["apps/myapp"] = time.Now().Add(-25 * time.Hour)

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
	hrTarget(hr, "apps")
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
	hrTarget(hr, "apps")
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
	if _, ok := u.firstSeen["apps/myapp"]; !ok {
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

	// Window elapsed → act.
	u.firstSeen["apps/myapp"] = time.Now().Add(-helmStuckThreshold - time.Minute)
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
	hrTarget(hr, "apps")
	hrReady(hr, "False", "another operation is in progress")

	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset()
	u := newUnlocker(cs, dyn, 0, "")

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := u.firstSeen["apps/myapp"]; !ok {
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
	if _, ok := u.firstSeen["apps/myapp"]; ok {
		t.Fatal("recovered HR not pruned from firstSeen")
	}
}

// v2 list fails (older flux / CRDs absent) → fall back to v2beta2.
func TestHelmReleaseUnlockerV2beta2Fallback(t *testing.T) {
	hr := hrObj("apps", "myapp", "v2beta2")
	hrTarget(hr, "apps")
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
	hrTarget(hr, "apps")
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
	if _, ok := u.unlocked["apps/myapp"]; ok {
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
	if _, ok := u.unlocked["apps/myapp"]; ok {
		t.Fatal("HR marked unlocked although unlock failed")
	}
}

// A failing requestedAt patch on the HR surfaces as an unlock error —
// the secret is already gone but the HR is NOT marked unlocked (the
// reconcile hint never landed).
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
	if _, ok := u.unlocked["apps/myapp"]; ok {
		t.Fatal("HR marked unlocked although the annotate failed")
	}
}

// spec.releaseName / spec.targetNamespace drive where the release
// secrets live; both fall back to the object meta when absent.
func TestHRNameAndNamespaceFallbacks(t *testing.T) {
	hr := hrObj("apps", "myapp", "v2")
	if got := hrReleaseName(hr); got != "myapp" {
		t.Fatalf("hrReleaseName fallback = %q, want myapp", got)
	}
	if got := hrTargetNS(hr); got != "apps" {
		t.Fatalf("hrTargetNS fallback = %q, want apps", got)
	}

	hr.Object["spec"] = map[string]any{
		"releaseName":     "customrel",
		"targetNamespace": "target-ns",
	}
	if got := hrReleaseName(hr); got != "customrel" {
		t.Fatalf("hrReleaseName = %q, want customrel", got)
	}
	if got := hrTargetNS(hr); got != "target-ns" {
		t.Fatalf("hrTargetNS = %q, want target-ns", got)
	}
}
