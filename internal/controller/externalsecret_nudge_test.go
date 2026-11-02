package controller

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
	kfake "k8s.io/client-go/kubernetes/fake"
)

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

func cssObj(name, ready string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "external-secrets.io/v1beta1",
		"kind":       "ClusterSecretStore",
		"metadata":   map[string]any{"name": name},
		"status": map[string]any{
			"conditions": []any{map[string]any{
				"type":               "Ready",
				"status":             ready,
				"lastTransitionTime": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
			}},
		},
	}}
}

func esObj(ns, name, ready string, failingFor time.Duration) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "external-secrets.io/v1beta1",
		"kind":       "ExternalSecret",
		"metadata": map[string]any{
			"namespace": ns,
			"name":      name,
		},
		"status": map[string]any{
			"conditions": []any{map[string]any{
				"type":               "Ready",
				"status":             ready,
				"lastTransitionTime": time.Now().Add(-failingFor).UTC().Format(time.RFC3339),
			}},
		},
	}}
}

func esAnnotation(t *testing.T, dyn *fake.FakeDynamicClient, gvr schema.GroupVersionResource, ns, name, anno string) string {
	t.Helper()
	u, err := dyn.Resource(gvr).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get externalsecret %s/%s: %v", ns, name, err)
	}
	return u.GetAnnotations()[anno]
}

func newNudge(dyn *fake.FakeDynamicClient, enabled bool) *externalSecretNudge {
	return &externalSecretNudge{
		cs:         kfake.NewSimpleClientset(),
		dyn:        dyn,
		enabled:    enabled,
		storeReady: map[string]bool{},
		nudged:     map[string]time.Time{},
	}
}

// setStoreReady flips a ClusterSecretStore's Ready condition inside the
// fake tracker (the run only ever lists — this simulates the flap).
func setStoreReady(t *testing.T, dyn *fake.FakeDynamicClient, name, ready string) {
	t.Helper()
	u, err := dyn.Resource(clusterSecretStoreGVR).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get store %s: %v", name, err)
	}
	if err := unstructured.SetNestedSlice(u.Object, []any{map[string]any{
		"type":               "Ready",
		"status":             ready,
		"lastTransitionTime": time.Now().UTC().Format(time.RFC3339),
	}}, "status", "conditions"); err != nil {
		t.Fatal(err)
	}
	if _, err := dyn.Resource(clusterSecretStoreGVR).Update(ctx, u, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update store %s: %v", name, err)
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// Store Ready False→True transition: every ExternalSecret stuck
// Ready=False >15m gets force-sync; fresh failures and healthy ESs
// are left alone. A second tick without a new transition re-nudges
// nothing.
func TestExternalSecretNudgeRecoveryTransition(t *testing.T) {
	old := esObj("apps", "es-stuck", "False", 20*time.Minute)
	young := esObj("apps", "es-fresh", "False", 5*time.Minute)
	healthy := esObj("apps", "es-ok", "True", 2*time.Hour)
	dyn := newDynFake(cssObj("css1", "False"), old, young, healthy)
	n := newNudge(dyn, true)

	// Tick 1: seeds storeReady (store currently False) — no nudges.
	if err := n.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := esAnnotation(t, dyn, externalSecretGVR, "apps", "es-stuck", esForceSyncAnno); got != "" {
		t.Fatal("nudged on first sight — no transition happened yet")
	}
	if r, ok := n.storeReady["css1"]; !ok || r {
		t.Fatal("store state not seeded as not-ready")
	}

	// Store recovers → tick 2 nudges the old-failing ES only.
	setStoreReady(t, dyn, "css1", "True")
	if err := n.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := esAnnotation(t, dyn, externalSecretGVR, "apps", "es-stuck", esForceSyncAnno); got == "" {
		t.Fatal("stuck ES not force-synced on store recovery")
	}
	for _, name := range []string{"es-fresh", "es-ok"} {
		if got := esAnnotation(t, dyn, externalSecretGVR, "apps", name, esForceSyncAnno); got != "" {
			t.Fatalf("ES %s nudged but should not be (fresh/healthy)", name)
		}
	}

	// Tick 3 with no new transition: value must not change again.
	stamp := esAnnotation(t, dyn, externalSecretGVR, "apps", "es-stuck", esForceSyncAnno)
	if err := n.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := esAnnotation(t, dyn, externalSecretGVR, "apps", "es-stuck", esForceSyncAnno); got != stamp {
		t.Fatal("ES re-nudged without a new recovery transition")
	}
}

// Rate limit: a second recovery inside the hour must not re-stamp.
func TestExternalSecretNudgeRateLimit(t *testing.T) {
	dyn := newDynFake(cssObj("css1", "False"),
		esObj("apps", "es-stuck", "False", time.Hour))
	n := newNudge(dyn, true)

	if err := n.run(ctx); err != nil { // seed: False
		t.Fatal(err)
	}
	setStoreReady(t, dyn, "css1", "True")
	if err := n.run(ctx); err != nil { // transition → nudge
		t.Fatal(err)
	}
	stamp := esAnnotation(t, dyn, externalSecretGVR, "apps", "es-stuck", esForceSyncAnno)
	if stamp == "" {
		t.Fatal("first nudge did not stamp force-sync")
	}

	// Flap again inside the hour: False → True → run.
	setStoreReady(t, dyn, "css1", "False")
	if err := n.run(ctx); err != nil {
		t.Fatal(err)
	}
	setStoreReady(t, dyn, "css1", "True")
	if err := n.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := esAnnotation(t, dyn, externalSecretGVR, "apps", "es-stuck", esForceSyncAnno); got != stamp {
		t.Fatal("ES re-nudged inside the 1h rate-limit window")
	}
}

// A store seen for the first time already Ready=True is a seed, not a
// recovery — no nudges fire.
func TestExternalSecretNudgeNoTransitionOnFirstSight(t *testing.T) {
	dyn := newDynFake(cssObj("css1", "True"),
		esObj("apps", "es-stuck", "False", time.Hour))
	n := newNudge(dyn, true)

	if err := n.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := esAnnotation(t, dyn, externalSecretGVR, "apps", "es-stuck", esForceSyncAnno); got != "" {
		t.Fatal("nudged on first sight of an already-ready store")
	}
}

// enabled=false → log + nil, nothing is listed or patched.
func TestExternalSecretNudgeDisabled(t *testing.T) {
	dyn := newDynFake(cssObj("css1", "False"),
		esObj("apps", "es-stuck", "False", time.Hour))
	n := newNudge(dyn, false)

	if err := n.run(ctx); err != nil {
		t.Fatal(err)
	}
	setStoreReady(t, dyn, "css1", "True")
	if err := n.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := esAnnotation(t, dyn, externalSecretGVR, "apps", "es-stuck", esForceSyncAnno); got != "" {
		t.Fatal("disabled module stamped force-sync")
	}
	if len(n.storeReady) != 0 {
		t.Fatal("disabled module tracked store state")
	}
}
