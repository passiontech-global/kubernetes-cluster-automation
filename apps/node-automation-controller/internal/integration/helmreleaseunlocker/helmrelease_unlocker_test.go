package helmreleaseunlocker

import (
	"strconv"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
	kfake "k8s.io/client-go/kubernetes/fake"

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

// ---------------------------------------------------------------------------
// C3a — failed helm-hook Job reaper fixtures
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
