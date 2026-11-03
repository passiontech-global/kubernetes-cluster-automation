package controller

import (
	"errors"
	"testing"
	"time"

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

// A ClusterSecretStore list failure is a real error — probing on a
// partial store view could misread "vanished" as a transition.
func TestExternalSecretNudgeStoreListError(t *testing.T) {
	dyn := newDynFake(cssObj("css1", "False"))
	dyn.PrependReactor("list", "clustersecretstores",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	n := newNudge(dyn, true)
	if err := n.run(ctx); err == nil {
		t.Fatal("expected error when the store list fails")
	}
}

// Cluster has the flag enabled but the ESO CRDs are not installed
// yet (opt-in before the rollout) -> List 404 "could not find the
// requested resource" — must skip quietly, must not count as a
// periodic run error.
func TestExternalSecretNudgeCRDsAbsent(t *testing.T) {
	dyn := newDynFake(cssObj("css1", "False"))
	dyn.PrependReactor("list", "clustersecretstores",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(
				clusterSecretStoreGVR.GroupResource(), "")
		})
	n := newNudge(dyn, true)
	if err := n.run(ctx); err != nil {
		t.Fatalf("absent ESO CRDs must skip cleanly, got %v", err)
	}
}

// A store pruned while absent re-seeds on reappearance: delete+recreate
// must NOT count as a False→True recovery transition (tracked=false).
func TestExternalSecretNudgePrunedStoreReseeds(t *testing.T) {
	dyn := newDynFake(cssObj("css1", "False"),
		esObj("apps", "es-stuck", "False", time.Hour))
	n := newNudge(dyn, true)

	if err := n.run(ctx); err != nil { // seed: False
		t.Fatal(err)
	}
	// Store vanishes — the prune must drop it from storeReady.
	if err := dyn.Resource(clusterSecretStoreGVR).
		Delete(ctx, "css1", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := n.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := n.storeReady["css1"]; ok {
		t.Fatal("vanished store not pruned from storeReady")
	}

	// Recreated already-True: first sight again — seed, no nudge.
	if _, err := dyn.Resource(clusterSecretStoreGVR).
		Create(ctx, cssObj("css1", "True"), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := n.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := esAnnotation(t, dyn, externalSecretGVR, "apps", "es-stuck", esForceSyncAnno); got != "" {
		t.Fatal("recreated store treated as a recovery transition — must re-seed")
	}
	if r, ok := n.storeReady["css1"]; !ok || !r {
		t.Fatal("recreated store not re-seeded as ready")
	}
}

// The ExternalSecret list inside nudge() is a real error — the store
// transition already consumed the mutex-protected run.
func TestExternalSecretNudgeESListError(t *testing.T) {
	dyn := newDynFake(cssObj("css1", "False"),
		esObj("apps", "es-stuck", "False", time.Hour))
	n := newNudge(dyn, true)
	if err := n.run(ctx); err != nil { // seed
		t.Fatal(err)
	}
	setStoreReady(t, dyn, "css1", "True")
	dyn.PrependReactor("list", "externalsecrets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("es list boom")
		})
	if err := n.run(ctx); err == nil {
		t.Fatal("expected error when the ExternalSecret list fails inside nudge")
	}
}

// A Ready=False condition without a parseable lastTransitionTime falls
// back to the object's creationTimestamp — an ES old enough is nudged.
func TestExternalSecretNudgeReadySinceFallback(t *testing.T) {
	es := esObj("apps", "es-stuck", "False", time.Hour)
	// Malformed timestamp → readySince fails, creationTimestamp wins.
	if err := unstructured.SetNestedSlice(es.Object, []any{map[string]any{
		"type":               "Ready",
		"status":             "False",
		"lastTransitionTime": "not-a-timestamp",
	}}, "status", "conditions"); err != nil {
		t.Fatal(err)
	}
	es.SetCreationTimestamp(metav1.NewTime(time.Now().Add(-time.Hour)))
	dyn := newDynFake(cssObj("css1", "False"), es)
	n := newNudge(dyn, true)

	if err := n.run(ctx); err != nil { // seed: False
		t.Fatal(err)
	}
	setStoreReady(t, dyn, "css1", "True")
	if err := n.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := esAnnotation(t, dyn, externalSecretGVR, "apps", "es-stuck", esForceSyncAnno); got == "" {
		t.Fatal("old ES with malformed lastTransitionTime not nudged — creationTimestamp fallback broken")
	}
}

// The nudged ledger prunes stamps whose ES vanished or aged past the
// 1h cooldown, keeps a live ES still inside it, and lets an expired
// entry re-nudge a still-stuck ES.
func TestExternalSecretNudgePrunesNudgedLedger(t *testing.T) {
	live := esObj("apps", "es-live", "False", 30*time.Minute)
	expired := esObj("apps", "es-expired", "False", 2*time.Hour)
	healed := esObj("apps", "es-healed", "True", 3*time.Hour)
	dyn := newDynFake(live, expired, healed)
	n := newNudge(dyn, true)
	fresh := time.Now().Add(-10 * time.Minute)
	stale := time.Now().Add(-esNudgeCooldown - time.Minute)
	n.nudged["apps/es-live"] = fresh    // live + inside cooldown → keep
	n.nudged["apps/es-expired"] = stale // live + past cooldown → re-nudge
	n.nudged["apps/es-healed"] = stale  // healed → prune, nothing re-adds
	n.nudged["apps/es-gone"] = fresh    // vanished → prune

	if err := n.nudge(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := n.nudged["apps/es-gone"]; ok {
		t.Fatal("nudged entry for a deleted ES not pruned")
	}
	if _, ok := n.nudged["apps/es-healed"]; ok {
		t.Fatal("expired entry on a healed ES not pruned")
	}
	if got := n.nudged["apps/es-live"]; !got.Equal(fresh) {
		t.Fatal("live ES inside the cooldown lost/re-stamped its nudge entry")
	}
	if got := n.nudged["apps/es-expired"]; !got.After(stale) {
		t.Fatal("ES past the cooldown was not re-nudged")
	}
	if got := esAnnotation(t, dyn, externalSecretGVR, "apps", "es-expired", esForceSyncAnno); got == "" {
		t.Fatal("expired entry's ES was pruned but never re-stamped")
	}
}

// The unstructured Ready-condition helpers must tolerate absent and
// malformed shapes (real objects in the wild are inconsistent).
func TestReadyConditionHelpersEdgeCases(t *testing.T) {
	bare := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "external-secrets.io/v1beta1",
		"kind":       "ExternalSecret",
		"metadata":   map[string]any{"name": "bare"},
	}}
	if s, m := readyCond(bare); s != "" || m != "" {
		t.Fatalf("readyCond on condition-less object = %q,%q", s, m)
	}
	if _, ok := readySince(bare); ok {
		t.Fatal("readySince true on condition-less object")
	}
	if got := readyConds(bare); len(got) != 0 {
		t.Fatalf("readyConds on condition-less object = %v", got)
	}

	// Non-map entries inside .status.conditions are skipped.
	junk := &unstructured.Unstructured{Object: map[string]any{
		"status": map[string]any{
			"conditions": []any{"garbage", int64(42), nil},
		},
	}}
	if s, _ := readyCond(junk); s != "" {
		t.Fatalf("readyCond saw a non-map entry: %q", s)
	}
	if got := readyConds(junk); len(got) != 0 {
		t.Fatalf("readyConds kept non-map entries: %v", got)
	}

	// A non-Ready condition is ignored by both helpers.
	nonReady := &unstructured.Unstructured{Object: map[string]any{
		"status": map[string]any{
			"conditions": []any{map[string]any{
				"type": "Synced", "status": "True",
				"lastTransitionTime": time.Now().UTC().Format(time.RFC3339),
			}},
		},
	}}
	if s, _ := readyCond(nonReady); s != "" {
		t.Fatalf("readyCond returned a non-Ready status: %q", s)
	}
	if _, ok := readySince(nonReady); ok {
		t.Fatal("readySince true for a non-Ready condition")
	}

	// Malformed lastTransitionTime → readySince false.
	badTS := &unstructured.Unstructured{Object: map[string]any{
		"status": map[string]any{
			"conditions": []any{map[string]any{
				"type": "Ready", "status": "False",
				"lastTransitionTime": "yesterday-ish",
			}},
		},
	}}
	if s, _ := readyCond(badTS); s != "False" {
		t.Fatalf("readyCond = %q, want False", s)
	}
	if _, ok := readySince(badTS); ok {
		t.Fatal("readySince true on malformed lastTransitionTime")
	}
}

// A per-ES patch failure is logged and the sweep continues to the
// next ExternalSecret — it must neither error the run nor record a
// delivered nudge.
func TestExternalSecretNudgePatchErrorTolerated(t *testing.T) {
	dyn := newDynFake(
		esObj("apps", "es-bad", "False", 30*time.Minute),
		esObj("apps", "es-good", "False", 30*time.Minute))
	dyn.PrependReactor("patch", "externalsecrets",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			if pa, ok := a.(ktesting.PatchAction); ok && pa.GetName() == "es-bad" {
				return true, nil, errors.New("patch rejected")
			}
			return false, nil, nil
		})
	n := newNudge(dyn, true)
	if err := n.nudge(ctx); err != nil {
		t.Fatalf("per-ES patch failure must not fail the nudge: %v", err)
	}
	if _, ok := n.nudged["apps/es-bad"]; ok {
		t.Fatal("failed nudge recorded as delivered")
	}
	if _, ok := n.nudged["apps/es-good"]; !ok {
		t.Fatal("healthy patch skipped after a sibling's failure")
	}
}
