package externalsecretnudge

import (
	"errors"
	"fmt"
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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	ktesting "k8s.io/client-go/testing"
)

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

func cssObj(name, ready string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "external-secrets.io/v1",
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
		"apiVersion": "external-secrets.io/v1",
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

// esStoreRef points the ES's spec.secretStoreRef at a store — the
// state-based nudge gate reads it. kind "" exercises ESO's real
// default (namespaced SecretStore), which never qualifies — only an
// explicit kind=ClusterSecretStore does.
func esStoreRef(es *unstructured.Unstructured, kind, name string) {
	ref := map[string]any{"name": name}
	if kind != "" {
		ref["kind"] = kind
	}
	_ = unstructured.SetNestedMap(es.Object, ref, "spec", "secretStoreRef")
}

// esDataFromStoreRef appends a spec.dataFrom[] entry whose
// sourceRef.storeRef overrides the store for that pull — the second
// store-reference shape the v1beta1 CRD carries.
func esDataFromStoreRef(es *unstructured.Unstructured, kind, name string) {
	ref := map[string]any{"name": name}
	if kind != "" {
		ref["kind"] = kind
	}
	_ = unstructured.SetNestedSlice(es.Object, []any{
		map[string]any{"sourceRef": map[string]any{"storeRef": ref}},
	}, "spec", "dataFrom")
}

// esDataStoreRef appends a spec.data[] entry whose sourceRef.storeRef
// overrides the store for that key — the third store-reference shape,
// sibling to the dataFrom override.
func esDataStoreRef(es *unstructured.Unstructured, kind, name string) {
	ref := map[string]any{"name": name}
	if kind != "" {
		ref["kind"] = kind
	}
	_ = unstructured.SetNestedSlice(es.Object, []any{
		map[string]any{
			"secretKey": "k",
			"remoteRef": map[string]any{"key": "k"},
			"sourceRef": map[string]any{"storeRef": ref},
		},
	}, "spec", "data")
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
	return &externalSecretNudge{queue: "externalsecret-nudge",
		cs:         kfake.NewSimpleClientset(),
		dyn:        dyn,
		enabled:    enabled,
		storeReady: map[string]bool{},
	}
}

// setStoreReady flips a ClusterSecretStore's Ready condition inside the
// fake tracker (the run only ever lists — this simulates the flap).
func setStoreReady(t *testing.T, dyn *fake.FakeDynamicClient, name, ready string) {
	t.Helper()
	u, err := dyn.Resource(clusterSecretStoreGVRs[0]).Get(ctx, name, metav1.GetOptions{})
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
	if _, err := dyn.Resource(clusterSecretStoreGVRs[0]).Update(ctx, u, metav1.UpdateOptions{}); err != nil {
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
	if got := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-stuck", esForceSyncAnno); got != "" {
		t.Fatal("nudged on first sight — no transition happened yet")
	}
	if r, ok := n.storeReady["ClusterSecretStore//css1"]; !ok || r {
		t.Fatal("store state not seeded as not-ready")
	}

	// Store recovers → tick 2 nudges the old-failing ES only.
	setStoreReady(t, dyn, "css1", "True")
	if err := n.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-stuck", esForceSyncAnno); got == "" {
		t.Fatal("stuck ES not force-synced on store recovery")
	}
	for _, name := range []string{"es-fresh", "es-ok"} {
		if got := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", name, esForceSyncAnno); got != "" {
			t.Fatalf("ES %s nudged but should not be (fresh/healthy)", name)
		}
	}

	// Tick 3 with no new transition: value must not change again.
	stamp := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-stuck", esForceSyncAnno)
	if err := n.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-stuck", esForceSyncAnno); got != stamp {
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
	stamp := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-stuck", esForceSyncAnno)
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
	if got := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-stuck", esForceSyncAnno); got != stamp {
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
	if got := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-stuck", esForceSyncAnno); got != "" {
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
	if got := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-stuck", esForceSyncAnno); got != "" {
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
				clusterSecretStoreGVRs[0].GroupResource(), "")
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
	if err := dyn.Resource(clusterSecretStoreGVRs[0]).
		Delete(ctx, "css1", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := n.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := n.storeReady["ClusterSecretStore//css1"]; ok {
		t.Fatal("vanished store not pruned from storeReady")
	}

	// Recreated already-True: first sight again — seed, no nudge.
	if _, err := dyn.Resource(clusterSecretStoreGVRs[0]).
		Create(ctx, cssObj("css1", "True"), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := n.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-stuck", esForceSyncAnno); got != "" {
		t.Fatal("recreated store treated as a recovery transition — must re-seed")
	}
	if r, ok := n.storeReady["ClusterSecretStore//css1"]; !ok || !r {
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
	if got := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-stuck", esForceSyncAnno); got == "" {
		t.Fatal("old ES with malformed lastTransitionTime not nudged — creationTimestamp fallback broken")
	}
}

// The nudged cooldown suppresses a still-stuck ES inside the 1h
// window and lets an expired stamp re-nudge. CooldownSet has no
// enumeration — stamps for vanished ESs are dead weight that ages
// out of the window on its own.
func TestExternalSecretNudgeNudgedCooldown(t *testing.T) {
	live := esObj("apps", "es-live", "False", 30*time.Minute)
	expired := esObj("apps", "es-expired", "False", 2*time.Hour)
	healed := esObj("apps", "es-healed", "True", 3*time.Hour)
	dyn := newDynFake(live, expired, healed)
	n := newNudge(dyn, true)
	now := time.Now()
	fresh := now.Add(-10 * time.Minute)
	stale := now.Add(-esNudgeCooldown - time.Minute)
	n.nudged.Stamp("apps/es-live", fresh)    // live + inside cooldown → suppress
	n.nudged.Stamp("apps/es-expired", stale) // live + past cooldown → re-nudge
	n.nudged.Stamp("apps/es-healed", stale)  // healed → nothing re-adds
	n.nudged.Stamp("apps/es-gone", fresh)    // vanished → dead weight

	if err := n.nudge(ctx, true, true); err != nil { // edge path — all stuck ESs eligible
		t.Fatal(err)
	}
	if !n.nudged.CooledDown("apps/es-live", esNudgeCooldown, now) {
		t.Fatal("live ES inside the cooldown lost its nudge suppression")
	}
	if got := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-live", esForceSyncAnno); got != "" {
		t.Fatal("ES re-nudged inside the in-RAM cooldown")
	}
	if !n.nudged.CooledDown("apps/es-expired", esNudgeCooldown, now) {
		t.Fatal("re-nudged ES did not re-stamp the cooldown")
	}
	if got := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-expired", esForceSyncAnno); got == "" {
		t.Fatal("ES past the cooldown was not re-nudged")
	}
	if n.nudged.CooledDown("apps/es-healed", esNudgeCooldown, now) {
		t.Fatal("stale stamp on a healed ES still reads cooled")
	}
}

// The unstructured Ready-condition helpers must tolerate absent and
// malformed shapes (real objects in the wild are inconsistent).
func TestReadyConditionHelpersEdgeCases(t *testing.T) {
	bare := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "external-secrets.io/v1",
		"kind":       "ExternalSecret",
		"metadata":   map[string]any{"name": "bare"},
	}}
	if c, ok := kube.ConditionOf(bare.Object, "Ready"); ok || c.Status != "" || c.Message != "" {
		t.Fatalf("ConditionOf on condition-less object = %v,%q,%q", ok, c.Status, c.Message)
	}
	if got := kube.Conditions(bare.Object, "status", "conditions"); len(got) != 0 {
		t.Fatalf("Conditions on condition-less object = %v", got)
	}

	// Non-map entries inside .status.conditions are skipped.
	junk := &unstructured.Unstructured{Object: map[string]any{
		"status": map[string]any{
			"conditions": []any{"garbage", int64(42), nil},
		},
	}}
	if _, ok := kube.ConditionOf(junk.Object, "Ready"); ok {
		t.Fatal("ConditionOf saw a non-map entry")
	}
	if got := kube.Conditions(junk.Object, "status", "conditions"); len(got) != 0 {
		t.Fatalf("Conditions kept non-map entries: %v", got)
	}

	// A non-Ready condition is ignored.
	nonReady := &unstructured.Unstructured{Object: map[string]any{
		"status": map[string]any{
			"conditions": []any{map[string]any{
				"type": "Synced", "status": "True",
				"lastTransitionTime": time.Now().UTC().Format(time.RFC3339),
			}},
		},
	}}
	if _, ok := kube.ConditionOf(nonReady.Object, "Ready"); ok {
		t.Fatal("ConditionOf returned a non-Ready condition")
	}

	// Malformed lastTransitionTime decodes as zero.
	badTS := &unstructured.Unstructured{Object: map[string]any{
		"status": map[string]any{
			"conditions": []any{map[string]any{
				"type": "Ready", "status": "False",
				"lastTransitionTime": "yesterday-ish",
			}},
		},
	}}
	c, ok := kube.ConditionOf(badTS.Object, "Ready")
	if !ok || c.Status != "False" {
		t.Fatalf("ConditionOf = %v,%q, want found/False", ok, c.Status)
	}
	if !c.LastTransitionTime.IsZero() {
		t.Fatal("malformed lastTransitionTime did not decode as zero")
	}
}

// A per-ES patch failure is logged and the sweep continues to the
// next ExternalSecret — it must neither error the run nor record a
// delivered nudge, and the absorbed failure still IncErrors once (the
// run returns nil so the periodic wrapper never sees it).
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
	before := testutil.QueueErrorCount(t, "externalsecret-nudge")
	if err := n.nudge(ctx, true, true); err != nil {
		t.Fatalf("per-ES patch failure must not fail the nudge: %v", err)
	}
	if n.nudged.CooledDown("apps/es-bad", esNudgeCooldown, time.Now()) {
		t.Fatal("failed nudge recorded as delivered")
	}
	if !n.nudged.CooledDown("apps/es-good", esNudgeCooldown, time.Now()) {
		t.Fatal("healthy patch skipped after a sibling's failure")
	}
	if got := testutil.QueueErrorCount(t, "externalsecret-nudge") - before; got != 1 {
		t.Fatalf("absorbed patch failure did not IncError once, delta %v", got)
	}
}

// ---------------------------------------------------------------------------
// State-based nudge + persisted cooldown (2.1)
// ---------------------------------------------------------------------------

// No False→True edge needed: a store reporting Ready=True from first
// sight nudges every stuck ES whose spec.secretStoreRef points at it —
// the stuck state itself is the trigger after a controller restart
// wiped the edge bookkeeping.
func TestExternalSecretNudgeStateBasedWithoutEdge(t *testing.T) {
	stuck := esObj("apps", "es-stuck", "False", time.Hour)
	esStoreRef(stuck, "ClusterSecretStore", "css1")
	other := esObj("apps", "es-other-store", "False", time.Hour)
	esStoreRef(other, "ClusterSecretStore", "css-gone") // refs an untracked store
	namespaced := esObj("apps", "es-namespaced", "False", time.Hour)
	esStoreRef(namespaced, "SecretStore", "css1") // namespaced store — can't tell
	defaulted := esObj("apps", "es-default-kind", "False", time.Hour)
	esStoreRef(defaulted, "", "css1") // kind unset — ESO default is SecretStore, not CSS
	broken := esObj("apps", "es-broken-store", "False", time.Hour)
	esStoreRef(broken, "ClusterSecretStore", "css2") // store still False
	// No top-level secretStoreRef at all — the ES only pulls via a
	// dataFrom sourceRef.storeRef override pointing at the ready CSS.
	viaDataFrom := esObj("apps", "es-via-datafrom", "False", time.Hour)
	esDataFromStoreRef(viaDataFrom, "ClusterSecretStore", "css1")
	// Default store healthy but a dataFrom override still hangs off
	// the BROKEN store — nudging could never succeed, don't churn.
	mixedBroken := esObj("apps", "es-mixed-broken", "False", time.Hour)
	esStoreRef(mixedBroken, "ClusterSecretStore", "css1")
	esDataFromStoreRef(mixedBroken, "ClusterSecretStore", "css2")
	// Default store healthy but a dataFrom override is namespaced —
	// can't tell → conservative skip.
	mixedNamespaced := esObj("apps", "es-mixed-namespaced", "False", time.Hour)
	esStoreRef(mixedNamespaced, "ClusterSecretStore", "css1")
	esDataFromStoreRef(mixedNamespaced, "SecretStore", "ss-ns")
	// No top-level secretStoreRef — the ES's only store link is a
	// spec.data[].sourceRef.storeRef override pointing at the ready CSS.
	viaData := esObj("apps", "es-via-data", "False", time.Hour)
	esDataStoreRef(viaData, "ClusterSecretStore", "css1")
	// Default store healthy but a spec.data[] override hangs off the
	// BROKEN store — same conservative skip as the dataFrom variant.
	mixedDataBroken := esObj("apps", "es-mixed-data-broken", "False", time.Hour)
	esStoreRef(mixedDataBroken, "ClusterSecretStore", "css1")
	esDataStoreRef(mixedDataBroken, "ClusterSecretStore", "css2")
	// W9-GO1 storm guard: this fixture carries 10 failing ESs — enough
	// to trip the >=5 && >=50% storm signature and suppress every
	// stamp. Pad the population with healthy ESs so the failing ratio
	// stays under half and the per-store gating assertions below still
	// exercise the nudge path.
	var healthyObjs []runtime.Object
	for i := 0; i < 11; i++ {
		healthy := esObj("apps", fmt.Sprintf("es-healthy-%d", i), "True", time.Hour)
		esStoreRef(healthy, "ClusterSecretStore", "css1")
		healthyObjs = append(healthyObjs, healthy)
	}
	dyn := newDynFake(append([]runtime.Object{
		cssObj("css1", "True"), cssObj("css2", "False"),
		stuck, other, namespaced, defaulted, broken,
		viaDataFrom, mixedBroken, mixedNamespaced, viaData, mixedDataBroken,
	}, healthyObjs...)...)
	n := newNudge(dyn, true)

	if err := n.run(ctx); err != nil { // seeds both stores, no edge
		t.Fatal(err)
	}
	if got := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-stuck", esForceSyncAnno); got == "" {
		t.Fatal("stuck ES on a Ready=True store not nudged without an edge")
	}
	if got := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-stuck", esLastNudgeAnno); got == "" {
		t.Fatal("node.ops/last-es-nudge not persisted alongside force-sync")
	}
	if got := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-via-datafrom", esForceSyncAnno); got == "" {
		t.Fatal("ES whose only store ref is a dataFrom CSS override not nudged")
	}
	if got := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-via-data", esForceSyncAnno); got == "" {
		t.Fatal("ES whose only store ref is a spec.data[] CSS override not nudged")
	}
	for _, name := range []string{
		"es-other-store", "es-namespaced", "es-default-kind", "es-broken-store",
		"es-mixed-broken", "es-mixed-namespaced", "es-mixed-data-broken"} {
		if got := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", name, esForceSyncAnno); got != "" {
			t.Fatalf("ES %s nudged although its referenced store is not Ready=True", name)
		}
	}
}

// The persisted stamp IS the cooldown: an ES force-synced 30m ago by
// a previous controller run (in-RAM ledger empty after restart) is
// not re-stamped even on a fresh recovery edge; a stamp older than
// the cooldown is overwritten.
func TestExternalSecretNudgePersistedCooldown(t *testing.T) {
	recent := esObj("apps", "es-recent", "False", 2*time.Hour)
	esStoreRef(recent, "ClusterSecretStore", "css1")
	recent.SetAnnotations(map[string]string{
		esForceSyncAnno: strconv.FormatInt(time.Now().Add(-30*time.Minute).Unix(), 10),
	})
	stale := esObj("apps", "es-stale", "False", 2*time.Hour)
	esStoreRef(stale, "ClusterSecretStore", "css1")
	stale.SetAnnotations(map[string]string{
		esLastNudgeAnno: time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339),
	})
	dyn := newDynFake(cssObj("css1", "True"), recent, stale)
	n := newNudge(dyn, true)

	if err := n.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-recent", esLastNudgeAnno); got != "" {
		t.Fatal("ES re-stamped inside the persisted 1h cooldown")
	}
	if got := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-stale", esForceSyncAnno); got == "" {
		t.Fatal("ES with a stale last-es-nudge stamp not re-nudged")
	}
}

// ---------------------------------------------------------------------------
// W9-GO1 — storm guard + 1Password Connect auto-heal
// ---------------------------------------------------------------------------

// esNudgeDynFake builds the dyn fake with every ESO GVR plus the
// autopilot Plan GVR kube.MaintenanceActive lists — without the
// latter the maintenance mutex panics inside the fake.
func esNudgeDynFake(objs ...runtime.Object) *fake.FakeDynamicClient {
	kinds := map[schema.GroupVersionResource]string{}
	for _, gvr := range clusterSecretStoreGVRs {
		kinds[gvr] = "ClusterSecretStoreList"
	}
	for _, gvr := range secretStoreGVRs {
		kinds[gvr] = "SecretStoreList"
	}
	for _, gvr := range externalSecretGVRs {
		kinds[gvr] = "ExternalSecretList"
	}
	kinds[kube.AutopilotPlanGVR] = "PlanList"
	return testutil.NewFakeDyn(kinds, objs...)
}

// A mass ExternalSecret failure (>=5 failing AND >=half the fleet)
// is an upstream ESO/1Password outage: the storm guard suppresses
// every force-sync stamp, sets the gauge and logs STORM-GUARD —
// poking each wedged ES would only amplify the outage.
func TestExternalSecretNudgeStormGuardSuppresses(t *testing.T) {
	var objs []runtime.Object
	objs = append(objs, cssObj("store", "True"))
	for i := 0; i < 5; i++ {
		es := esObj("apps", fmt.Sprintf("es-bad-%d", i), "False", 2*time.Hour)
		esStoreRef(es, "ClusterSecretStore", "store")
		objs = append(objs, es)
	}
	ok := esObj("apps", "es-ok", "True", time.Hour)
	esStoreRef(ok, "ClusterSecretStore", "store")
	objs = append(objs, ok)

	dyn := esNudgeDynFake(objs...)
	n := newNudge(dyn, true)
	if err := n.run(ctx); err != nil { // seed store state
		t.Fatal(err)
	}
	if err := n.run(ctx); err != nil { // storm census
		t.Fatal(err)
	}
	if got := ptestutil.ToFloat64(metrics.ExternalSecretStormSuppressed); got != 1 {
		t.Fatalf("storm gauge = %v, want 1", got)
	}
	for i := 0; i < 5; i++ {
		if v := esAnnotation(t, dyn, externalSecretGVRs[0], "apps",
			fmt.Sprintf("es-bad-%d", i), esForceSyncAnno); v != "" {
			t.Fatalf("storm must suppress force-sync on es-bad-%d, got %q", i, v)
		}
	}
	// A non-storm population resets the gauge.
	healthy := esNudgeDynFake(cssObj("store", "True"),
		esObj("apps", "es-fine", "True", time.Hour))
	n2 := newNudge(healthy, true)
	if err := n2.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := ptestutil.ToFloat64(metrics.ExternalSecretStormSuppressed); got != 0 {
		t.Fatalf("non-storm gauge = %v, want 0", got)
	}
}

// A ClusterSecretStore down for >=15m triggers the connect auto-heal:
// the oldest running onepassword-connect pod is deleted with a UID
// precondition, once per hour.
func TestExternalSecretNudgeConnectHeal(t *testing.T) {
	oldPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "external-secrets",
			Name:              "onepassword-connect-aaa",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-48 * time.Hour)),
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	newPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "external-secrets",
			Name:              "onepassword-connect-bbb",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	cs := kfake.NewSimpleClientset(oldPod, newPod)
	dyn := esNudgeDynFake(cssObj("store", "False"))
	n := &externalSecretNudge{queue: "externalsecret-nudge",
		cs:         cs,
		dyn:        dyn,
		enabled:    true,
		storeReady: map[string]bool{},
	}
	// The store has been observed down since 20m ago — past the
	// 15m persistence window.
	n.storeDownSince.Observe("ClusterSecretStore//store", time.Now().Add(-20*time.Minute))
	if err := n.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.CoreV1().Pods("external-secrets").Get(ctx,
		"onepassword-connect-aaa", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("oldest connect pod must be deleted, get err=%v", err)
	}
	if _, err := cs.CoreV1().Pods("external-secrets").Get(ctx,
		"onepassword-connect-bbb", metav1.GetOptions{}); err != nil {
		t.Fatalf("younger connect pod must survive, get err=%v", err)
	}
	// Cooldown: a second sweep inside the hour must not delete the
	// survivor even though the store is still down.
	if err := n.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.CoreV1().Pods("external-secrets").Get(ctx,
		"onepassword-connect-bbb", metav1.GetOptions{}); err != nil {
		t.Fatalf("cooldown must protect the surviving pod, get err=%v", err)
	}
}

// A transient first False observation must NOT heal — the down-since
// clock starts at first sight and needs the full 15m.
func TestExternalSecretNudgeConnectHealTransient(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "external-secrets",
			Name:              "onepassword-connect-aaa",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-48 * time.Hour)),
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	cs := kfake.NewSimpleClientset(pod)
	dyn := esNudgeDynFake(cssObj("store", "False"))
	n := &externalSecretNudge{queue: "externalsecret-nudge",
		cs:         cs,
		dyn:        dyn,
		enabled:    true,
		storeReady: map[string]bool{},
	}
	if err := n.run(ctx); err != nil { // first sight — clock starts now
		t.Fatal(err)
	}
	if _, err := cs.CoreV1().Pods("external-secrets").Get(ctx,
		"onepassword-connect-aaa", metav1.GetOptions{}); err != nil {
		t.Fatalf("transient observation must not delete the pod, get err=%v", err)
	}
}
