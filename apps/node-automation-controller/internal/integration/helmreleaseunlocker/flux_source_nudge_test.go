// flux_source_nudge_test.go — the source-healer nudge gate: the
// maintenance mutex defers the source stamp entirely (fail closed),
// and the persisted last-source-nudge annotation caps it at one
// nudge per source per 30m.
package helmreleaseunlocker

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fake "k8s.io/client-go/dynamic/fake"
	kfake "k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// nudgeKust builds a Kustomization stuck Ready=False on an artifact-
// fetch signature, sourcing from a GitRepository in its own namespace.
func nudgeKust(ns, name string, since time.Time) *unstructured.Unstructured {
	k := testutil.Unstructured(
		schema.FromAPIVersionAndKind("kustomize.toolkit.fluxcd.io/v1", "Kustomization"),
		ns, name, nil)
	k.Object["spec"] = map[string]any{
		"sourceRef": map[string]any{"kind": "GitRepository", "name": "repo"},
	}
	k.Object["status"] = map[string]any{
		"conditions": []any{map[string]any{
			"type":               "Ready",
			"status":             "False",
			"reason":             "ArtifactFailed",
			"message":            "artifact not found: failed to fetch from origin",
			"lastTransitionTime": since.UTC().Format(time.RFC3339),
		}},
	}
	return k
}

func nudgeRepo(ns, name string, annos map[string]string) *unstructured.Unstructured {
	repo := testutil.Unstructured(
		schema.FromAPIVersionAndKind("source.toolkit.fluxcd.io/v1", "GitRepository"),
		ns, name, nil)
	if annos != nil {
		repo.SetAnnotations(annos)
	}
	return repo
}

func nudgeSourceAnno(t *testing.T, dyn *fake.FakeDynamicClient, ns, name, anno string) string {
	t.Helper()
	u, err := dyn.Resource(kube.GVRFluxGitRepository).Namespace(ns).
		Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get source %s/%s: %v", ns, name, err)
	}
	return u.GetAnnotations()[anno]
}

// The full sweep: one stuck Kustomization nudges its source once —
// both the requestedAt reconcile hint and the last-source-nudge
// cooldown stamp land on the SOURCE object.
func TestFluxSourceNudgeStampsSource(t *testing.T) {
	base := time.Now()
	k := nudgeKust("flux-system", "apps", base.Add(-20*time.Minute))
	dyn := testutil.NewDynamicClient(k, nudgeRepo("flux-system", "repo", nil))
	u := &helmReleaseUnlocker{queue: "helmrelease-unlocker",
		cs:  kfake.NewSimpleClientset(),
		dyn: dyn,
		now: func() time.Time { return base }}

	ks, err := dyn.Resource(kube.GVRFluxKustomization).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	u.healArtifactSources(ctx, &unstructured.UnstructuredList{}, ks)
	if got := nudgeSourceAnno(t, dyn, "flux-system", "repo", fluxReconcileAnno); got == "" {
		t.Fatal("requestedAt not stamped on the source")
	}
	if got := nudgeSourceAnno(t, dyn, "flux-system", "repo", fluxLastNudgeAnno); got == "" {
		t.Fatal("last-source-nudge not stamped on the source")
	}
}

// (a) Maintenance in flight: the source nudge is a heal and defers
// with the mutex — no requestedAt, no last-source-nudge, even though
// the artifact-fail signature holds.
func TestFluxSourceNudgeSkippedWhileMaintenanceActive(t *testing.T) {
	base := time.Now()
	k := nudgeKust("flux-system", "apps", base.Add(-20*time.Minute))
	dyn := testutil.NewDynamicClient(k, nudgeRepo("flux-system", "repo", nil))
	fresh := metav1.NewTime(base.Add(-time.Minute))
	cs := kfake.NewSimpleClientset(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "w1"},
		Spec: corev1.NodeSpec{
			Unschedulable: true,
			Taints: []corev1.Taint{{
				Key:       kube.UnschedulableTaintKey,
				TimeAdded: &fresh,
			}},
		},
	})
	u := &helmReleaseUnlocker{queue: "helmrelease-unlocker",
		cs:  cs,
		dyn: dyn,
		now: func() time.Time { return base }}

	ks, err := dyn.Resource(kube.GVRFluxKustomization).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	u.healArtifactSources(ctx, &unstructured.UnstructuredList{}, ks)
	if got := nudgeSourceAnno(t, dyn, "flux-system", "repo", fluxReconcileAnno); got != "" {
		t.Fatal("requestedAt stamped while maintenance holds — nudge must defer")
	}
	if got := nudgeSourceAnno(t, dyn, "flux-system", "repo", fluxLastNudgeAnno); got != "" {
		t.Fatal("last-source-nudge stamped while maintenance holds — nudge must defer")
	}
}

// The persisted cooldown: a fresh last-source-nudge stamp on the
// source suppresses the re-nudge across sweep boundaries.
func TestFluxSourceNudgeCooldownFromAnno(t *testing.T) {
	base := time.Now()
	k := nudgeKust("flux-system", "apps", base.Add(-20*time.Minute))
	repo := nudgeRepo("flux-system", "repo", map[string]string{
		kube.AnnoLastSourceNudge: base.Add(-5 * time.Minute).UTC().Format(time.RFC3339),
	})
	dyn := testutil.NewDynamicClient(k, repo)
	u := &helmReleaseUnlocker{queue: "helmrelease-unlocker",
		cs:  kfake.NewSimpleClientset(),
		dyn: dyn,
		now: func() time.Time { return base }}

	ks, err := dyn.Resource(kube.GVRFluxKustomization).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	u.healArtifactSources(ctx, &unstructured.UnstructuredList{}, ks)
	if got := nudgeSourceAnno(t, dyn, "flux-system", "repo", fluxReconcileAnno); got != "" {
		t.Fatal("requestedAt stamped inside the last-source-nudge cooldown")
	}
}
