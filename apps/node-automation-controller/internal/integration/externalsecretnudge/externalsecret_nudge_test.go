package externalsecretnudge

import (
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
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

func cssObj(name, ready string) *unstructured.Unstructured {
	return testutil.Unstructured(
		kube.GVRClusterSecretStoreV1.GroupVersion().WithKind("ClusterSecretStore"),
		"", name, map[string]any{"status": map[string]any{
			"conditions": []any{map[string]any{
				"type":               "Ready",
				"status":             ready,
				"lastTransitionTime": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
			}},
		}})
}

func esObj(ns, name, ready string, failingFor time.Duration) *unstructured.Unstructured {
	return testutil.Unstructured(
		kube.GVRExternalSecretV1.GroupVersion().WithKind("ExternalSecret"),
		ns, name, map[string]any{"status": map[string]any{
			"conditions": []any{map[string]any{
				"type":               "Ready",
				"status":             ready,
				"lastTransitionTime": time.Now().Add(-failingFor).UTC().Format(time.RFC3339),
			}},
		}})
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

func newNudge(dyn *fake.FakeDynamicClient) *externalSecretNudge {
	return &externalSecretNudge{queue: "externalsecret-nudge",
		cs:         kfake.NewSimpleClientset(),
		dyn:        dyn,
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
	n := newNudge(dyn)

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
	n := newNudge(dyn)

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
	n := newNudge(dyn)

	if err := n.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-stuck", esForceSyncAnno); got != "" {
		t.Fatal("nudged on first sight of an already-ready store")
	}
}

// The disabled-module case is covered by the registration contract in
// setup_test.go — EXTERNALSECRET_NUDGE_ENABLED is a registration gate,
// so there is no run-time disabled path left to test.

// A ClusterSecretStore list failure is a real error — probing on a
// partial store view could misread "vanished" as a transition.
func TestExternalSecretNudgeStoreListError(t *testing.T) {
	dyn := newDynFake(cssObj("css1", "False"))
	dyn.PrependReactor("list", "clustersecretstores",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	n := newNudge(dyn)
	if err := n.run(ctx); err == nil {
		t.Fatal("expected error when the store list fails")
	}
}

// Cluster is registered (the gate is opt-in at registration) but the
// ESO CRDs are not installed yet — opted in before the rollout -> List
// 404 "could not find the requested resource" — must skip quietly,
// must not count as a periodic run error.
func TestExternalSecretNudgeCRDsAbsent(t *testing.T) {
	dyn := newDynFake(cssObj("css1", "False"))
	dyn.PrependReactor("list", "clustersecretstores",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(
				clusterSecretStoreGVRs[0].GroupResource(), "")
		})
	n := newNudge(dyn)
	if err := n.run(ctx); err != nil {
		t.Fatalf("absent ESO CRDs must skip cleanly, got %v", err)
	}
}

// A store pruned while absent re-seeds on reappearance: delete+recreate
// must NOT count as a False→True recovery transition (tracked=false).
func TestExternalSecretNudgePrunedStoreReseeds(t *testing.T) {
	dyn := newDynFake(cssObj("css1", "False"),
		esObj("apps", "es-stuck", "False", time.Hour))
	n := newNudge(dyn)

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
	n := newNudge(dyn)
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
	n := newNudge(dyn)

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

// The persisted stamp IS the cooldown: a still-stuck ES whose
// force-sync is inside the 1h window is suppressed, while an
// expired stamp re-nudges — the same guarantee the dropped in-RAM
// ledger provided, durable across restarts.
func TestExternalSecretNudgeNudgedCooldown(t *testing.T) {
	now := time.Now()
	live := esObj("apps", "es-live", "False", 30*time.Minute)
	live.SetAnnotations(map[string]string{
		esForceSyncAnno: strconv.FormatInt(now.Add(-10*time.Minute).Unix(), 10),
	})
	expired := esObj("apps", "es-expired", "False", 2*time.Hour)
	expired.SetAnnotations(map[string]string{
		esLastNudgeAnno: now.Add(-esNudgeCooldown - time.Minute).UTC().Format(time.RFC3339),
	})
	healed := esObj("apps", "es-healed", "True", 3*time.Hour)
	dyn := newDynFake(live, expired, healed)
	n := newNudge(dyn)
	freshStamp := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-live", esForceSyncAnno)

	if err := n.nudge(ctx, true, true); err != nil { // edge path — all stuck ESs eligible
		t.Fatal(err)
	}
	if got := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-live", esForceSyncAnno); got != freshStamp {
		t.Fatal("ES re-nudged inside the persisted cooldown")
	}
	if got := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-live", esLastNudgeAnno); got != "" {
		t.Fatal("suppressed ES got a fresh last-es-nudge stamp")
	}
	if got := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-expired", esForceSyncAnno); got == "" {
		t.Fatal("ES past the cooldown was not re-nudged")
	}
	if got := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-healed", esForceSyncAnno); got != "" {
		t.Fatal("healed ES got a nudge stamp")
	}
}

// The unstructured Ready-condition helpers must tolerate absent and
// malformed shapes (real objects in the wild are inconsistent).
func TestReadyConditionHelpersEdgeCases(t *testing.T) {
	bare := testutil.Unstructured(
		kube.GVRExternalSecretV1.GroupVersion().WithKind("ExternalSecret"),
		"", "bare", nil)
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
	n := newNudge(dyn)
	before := testutil.QueueErrorCount(t, "externalsecret-nudge")
	if err := n.nudge(ctx, true, true); err != nil {
		t.Fatalf("per-ES patch failure must not fail the nudge: %v", err)
	}
	if got := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-bad", esForceSyncAnno); got != "" {
		t.Fatal("failed nudge stamped force-sync")
	}
	if got := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-good", esForceSyncAnno); got == "" {
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
	// externalsecret-storm-guard storm guard: this fixture carries 10 failing ESs — enough
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
	n := newNudge(dyn)

	if err := n.run(ctx); err != nil { // seeds both stores, no edge
		t.Fatal(err)
	}
	if got := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-stuck", esForceSyncAnno); got == "" {
		t.Fatal("stuck ES on a Ready=True store not nudged without an edge")
	}
	if got := esAnnotation(t, dyn, externalSecretGVRs[0], "apps", "es-stuck", esLastNudgeAnno); got == "" {
		t.Fatal("passiontech.dev/last-es-nudge not persisted alongside force-sync")
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
	n := newNudge(dyn)

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
// externalsecret-storm-guard — storm guard + 1Password Connect auto-heal
// ---------------------------------------------------------------------------

// esNudgeDynFake builds the dyn fake with every ESO GVR plus the
// autopilot Plan GVR kube.MaintenanceActive lists — without the
// latter the maintenance mutex panics inside the fake.
func esNudgeDynFake(objs ...runtime.Object) *fake.FakeDynamicClient {
	return testutil.NewDynamicClient(objs...)
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
	n := newNudge(dyn)
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
	n2 := newNudge(healthy)
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

// ---------------------------------------------------------------------------
// empty-key-audit — empty/whitespace-key audit + empty-skeleton Secret reaper
// ---------------------------------------------------------------------------

// esDataKeys declares spec.data[] entries pulling each key — the
// "expected to exist in the target Secret" list the audit checks.
func esDataKeys(es *unstructured.Unstructured, keys ...string) {
	data := make([]any, 0, len(keys))
	for _, k := range keys {
		data = append(data, map[string]any{
			"secretKey": k,
			"remoteRef": map[string]any{"key": k},
		})
	}
	_ = unstructured.SetNestedSlice(es.Object, data, "spec", "data")
}

// esTarget points spec.target.name at a differently-named Secret —
// the non-default target shape.
func esTarget(es *unstructured.Unstructured, name string) {
	_ = unstructured.SetNestedMap(es.Object,
		map[string]any{"name": name}, "spec", "target")
}

// esSecret builds the target Secret fixture — data nil leaves a
// zero-key skeleton.
func esSecret(ns, name string, data map[string][]byte, owner *metav1.OwnerReference) *corev1.Secret {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Data:       data,
	}
	if owner != nil {
		s.OwnerReferences = []metav1.OwnerReference{*owner}
	}
	return s
}

// A Ready=True ES whose target Secret carries empty/whitespace keys —
// or lacks a key spec.data[] declares — emits one series per offender;
// a populated key is silent, and a vanished target is just skipped.
func TestExternalSecretEmptyKeyAudit(t *testing.T) {
	es := esObj("apps", "es-ok", "True", time.Hour)
	esDataKeys(es, "username", "password", "missing-key")
	secret := esSecret("apps", "es-ok", map[string][]byte{
		"username": []byte("admin"),
		"password": []byte(""),
		"token":    []byte("  \n\t"),
	}, nil)
	dyn := newDynFake(es)
	n := &externalSecretNudge{queue: "externalsecret-nudge",
		cs: kfake.NewSimpleClientset(secret), dyn: dyn,
		storeReady: map[string]bool{}}
	if err := n.nudge(ctx, true, true); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"password", "token", "missing-key"} {
		if !metrics.ExternalSecretEmptyKey.DeleteLabelValues("apps", "es-ok", key) {
			t.Fatalf("missing empty-key series for %q", key)
		}
	}
	if metrics.ExternalSecretEmptyKey.DeleteLabelValues("apps", "es-ok", "username") {
		t.Fatal("populated key flagged as empty")
	}
}

// A key that syncs populated on the next sweep gets its series pruned
// — the ledger never leaks a stale "empty" series.
func TestExternalSecretEmptyKeyPrunesResolved(t *testing.T) {
	es := esObj("apps", "es-ok", "True", time.Hour)
	secret := esSecret("apps", "es-ok", map[string][]byte{
		"password": []byte(""),
	}, nil)
	cs := kfake.NewSimpleClientset(secret)
	dyn := newDynFake(es)
	n := &externalSecretNudge{queue: "externalsecret-nudge",
		cs: cs, dyn: dyn, storeReady: map[string]bool{}}
	if err := n.nudge(ctx, true, true); err != nil {
		t.Fatal(err)
	}
	if !metrics.ExternalSecretEmptyKey.DeleteLabelValues("apps", "es-ok", "password") {
		t.Fatal("empty key not flagged")
	}
	// ESO fills the value — the series must disappear, not pin.
	secret.Data["password"] = []byte("s3cret")
	if _, err := cs.CoreV1().Secrets("apps").Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := n.nudge(ctx, true, true); err != nil {
		t.Fatal(err)
	}
	if metrics.ExternalSecretEmptyKey.DeleteLabelValues("apps", "es-ok", "password") {
		t.Fatal("resolved key still carries an empty-key series")
	}
}

// The opt-out annotation silences the audit for Secrets that
// legitimately carry empty values; spec.target.name redirects the
// lookup away from the ES's own name.
func TestExternalSecretEmptyKeyOptOutAndTargetName(t *testing.T) {
	opted := esObj("apps", "es-opted", "True", time.Hour)
	opted.SetAnnotations(map[string]string{kube.AnnoAllowEmptySecretKey: "true"})
	renamed := esObj("apps", "es-renamed", "True", time.Hour)
	esTarget(renamed, "real-secret")
	dyn := newDynFake(opted, renamed)
	cs := kfake.NewSimpleClientset(
		esSecret("apps", "es-opted", map[string][]byte{"k": []byte("")}, nil),
		esSecret("apps", "real-secret", map[string][]byte{"k": []byte("")}, nil),
	)
	n := &externalSecretNudge{queue: "externalsecret-nudge",
		cs: cs, dyn: dyn, storeReady: map[string]bool{}}
	if err := n.nudge(ctx, true, true); err != nil {
		t.Fatal(err)
	}
	if metrics.ExternalSecretEmptyKey.DeleteLabelValues("apps", "es-opted", "k") {
		t.Fatal("opt-out ES flagged for an empty key")
	}
	if !metrics.ExternalSecretEmptyKey.DeleteLabelValues("apps", "es-renamed", "k") {
		t.Fatal("spec.target.name lookup missed the renamed Secret")
	}
}

// The empty skeleton an ESO-owned Secret can be left as after a failed
// sync is deleted (UID precondition) right before the force-sync stamp
// lands — the forced reconcile recreates it populated.
func TestExternalSecretSkeletonSecretDeleted(t *testing.T) {
	es := esObj("apps", "es-stuck", "False", time.Hour)
	es.SetUID("es-uid-1")
	skeleton := esSecret("apps", "es-stuck", nil, &metav1.OwnerReference{
		APIVersion: "external-secrets.io/v1", Kind: "ExternalSecret",
		Name: "es-stuck", UID: "es-uid-1",
	})
	dyn := newDynFake(es)
	cs := kfake.NewSimpleClientset(skeleton)
	var gotUID *types.UID
	cs.PrependReactor("delete", "secrets",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			opts := a.(ktesting.DeleteAction).GetDeleteOptions()
			if opts.Preconditions != nil {
				gotUID = opts.Preconditions.UID
			}
			return false, nil, nil
		})
	n := &externalSecretNudge{queue: "externalsecret-nudge",
		cs: cs, dyn: dyn, storeReady: map[string]bool{}}
	if err := n.nudge(ctx, true, true); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.CoreV1().Secrets("apps").Get(ctx,
		"es-stuck", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("empty skeleton must be deleted, get err=%v", err)
	}
	if gotUID == nil || *gotUID != skeleton.UID {
		t.Fatalf("skeleton delete missing the UID precondition: %v", gotUID)
	}
	if got := esAnnotation(t, dyn, externalSecretGVRs[0],
		"apps", "es-stuck", esForceSyncAnno); got == "" {
		t.Fatal("force-sync not stamped after the skeleton delete")
	}
}

// A Secret that is NOT provably owned by the failing ES is never
// deleted — no ownerRef, a UID mismatch, or real data all keep it.
func TestExternalSecretSkeletonSecretKept(t *testing.T) {
	noOwner := esObj("apps", "es-noowner", "False", time.Hour)
	noOwner.SetUID("es-uid-2")
	mismatched := esObj("apps", "es-mismatch", "False", time.Hour)
	mismatched.SetUID("es-uid-3")
	withData := esObj("apps", "es-data", "False", time.Hour)
	withData.SetUID("es-uid-4")
	dyn := newDynFake(noOwner, mismatched, withData)
	cs := kfake.NewSimpleClientset(
		// Same name, no ownerReferences — could be hand-made: keep.
		esSecret("apps", "es-noowner", nil, nil),
		// Owned by an ExternalSecret of the same name but a different
		// UID — belongs to a deleted ES instance: keep.
		esSecret("apps", "es-mismatch", nil, &metav1.OwnerReference{
			APIVersion: "external-secrets.io/v1", Kind: "ExternalSecret",
			Name: "es-mismatch", UID: "stale-uid",
		}),
		// Provably owned but carries data — not the skeleton shape.
		esSecret("apps", "es-data", map[string][]byte{"k": []byte("v")},
			&metav1.OwnerReference{
				APIVersion: "external-secrets.io/v1", Kind: "ExternalSecret",
				Name: "es-data", UID: "es-uid-4",
			}),
	)
	n := &externalSecretNudge{queue: "externalsecret-nudge",
		cs: cs, dyn: dyn, storeReady: map[string]bool{}}
	if err := n.nudge(ctx, true, true); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"es-noowner", "es-mismatch", "es-data"} {
		if _, err := cs.CoreV1().Secrets("apps").Get(ctx,
			name, metav1.GetOptions{}); err != nil {
			t.Fatalf("secret %s must survive, get err=%v", name, err)
		}
	}
}

// ---------------------------------------------------------------------------
// connect-sync stall detection + auto-heal
// ---------------------------------------------------------------------------

// connectPod builds a Running onepassword-connect pod declaring the
// connect-api + connect-sync pair; syncReady/restarts shape the
// connect-sync container status.
func connectPod(ns, name string, age time.Duration,
	syncReady bool, restarts int32) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         ns,
			Name:              name,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: "connect-api"}, {Name: "connect-sync"},
		}},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "connect-api", Ready: true},
				{Name: "connect-sync", Ready: syncReady,
					RestartCount: restarts},
			},
		},
	}
}

// A connect-sync container stuck !Ready (or crashlooping) while
// connect-api stays Ready is a stalled sync plane: once the degraded
// state persists >=15m the DEGRADED pod is bounced — not the oldest
// connect pod — under the same 1h cooldown.
func TestConnectPodHealOnSyncContainerUnhealthy(t *testing.T) {
	oldPod := connectPod("external-secrets", "onepassword-connect-aaa",
		48*time.Hour, false, 0)
	newPod := connectPod("external-secrets", "onepassword-connect-bbb",
		time.Hour, false, 0)
	cs := kfake.NewSimpleClientset(oldPod, newPod)
	dyn := esNudgeDynFake(cssObj("store", "True"))
	n := &externalSecretNudge{queue: "externalsecret-nudge",
		cs:         cs,
		dyn:        dyn,
		storeReady: map[string]bool{},
	}

	// First sight: the pod is flagged degraded but NOT deleted —
	// the persistence clock only starts now.
	if err := n.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.CoreV1().Pods("external-secrets").Get(ctx,
		"onepassword-connect-aaa", metav1.GetOptions{}); err != nil {
		t.Fatalf("transient connect-sync degradation must not delete the pod: %v", err)
	}
	if _, ok := n.syncDegradedSince.Seen(
		"external-secrets/onepassword-connect-aaa", time.Now()); !ok {
		t.Fatal("degraded pod not tracked in syncDegradedSince")
	}

	// The degradation has actually persisted past the 15m window —
	// seed the ledger with the original sighting and re-run. The
	// DEGRADED pod goes (not the oldest healthy one).
	n.syncDegradedSince.Seed("external-secrets/onepassword-connect-aaa",
		time.Now().Add(-20*time.Minute))
	if err := n.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.CoreV1().Pods("external-secrets").Get(ctx,
		"onepassword-connect-aaa", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("degraded connect pod must be deleted, get err=%v", err)
	}
	if _, err := cs.CoreV1().Pods("external-secrets").Get(ctx,
		"onepassword-connect-bbb", metav1.GetOptions{}); err != nil {
		t.Fatalf("older healthy connect pod must survive, get err=%v", err)
	}
}

// A crashlooping connect-sync (RestartCount >= 3) is the same
// degraded signature even when its Ready flag still reads true — but
// only while the loop is LIVE: CrashLoopBackOff waiting or a last
// termination finished within the 15m window. Stale restart counts
// from a long-recovered container and freshly-created pods inside
// the grace window are not degraded.
func TestConnectSyncCrashloopCountsDegraded(t *testing.T) {
	now := time.Now()
	pod := connectPod("onepassword", "onepassword-connect-xyz",
		time.Hour, true, esConnectSyncRestartMax)
	pod.Status.ContainerStatuses[1].LastTerminationState.Terminated =
		&corev1.ContainerStateTerminated{
			FinishedAt: metav1.NewTime(now.Add(-2 * time.Minute))}
	if why, bad := connectSyncDegraded(pod, now); !bad {
		t.Fatal("crashlooping connect-sync not flagged degraded")
	} else if why != "connect-sync container crashlooping" {
		t.Fatalf("why=%q", why)
	}

	// CrashLoopBackOff waiting reason — degraded even without a
	// usable last-termination timestamp.
	clb := connectPod("onepassword", "onepassword-connect-clb",
		time.Hour, true, esConnectSyncRestartMax)
	clb.Status.ContainerStatuses[1].State.Waiting =
		&corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}
	if _, bad := connectSyncDegraded(clb, now); !bad {
		t.Fatal("CrashLoopBackOff connect-sync not flagged degraded")
	}

	// Last termination finished 5m ago — inside the window, degraded.
	recent := connectPod("onepassword", "onepassword-connect-recent",
		time.Hour, true, esConnectSyncRestartMax)
	recent.Status.ContainerStatuses[1].LastTerminationState.Terminated =
		&corev1.ContainerStateTerminated{
			FinishedAt: metav1.NewTime(now.Add(-5 * time.Minute))}
	if _, bad := connectSyncDegraded(recent, now); !bad {
		t.Fatal("connect-sync with recent last termination not flagged degraded")
	}

	// Last termination finished 2h ago — stale restarts, NOT degraded.
	stale := connectPod("onepassword", "onepassword-connect-stale",
		48*time.Hour, true, esConnectSyncRestartMax)
	stale.Status.ContainerStatuses[1].LastTerminationState.Terminated =
		&corev1.ContainerStateTerminated{
			FinishedAt: metav1.NewTime(now.Add(-2 * time.Hour))}
	if _, bad := connectSyncDegraded(stale, now); bad {
		t.Fatal("stale restart count flagged degraded")
	}

	// Freshly-created pod inside the grace window — startup retries
	// are not a proven crashloop yet.
	fresh := connectPod("onepassword", "onepassword-connect-fresh",
		time.Minute, true, esConnectSyncRestartMax)
	fresh.Status.ContainerStatuses[1].State.Waiting =
		&corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}
	if _, bad := connectSyncDegraded(fresh, now); bad {
		t.Fatal("fresh pod inside grace window flagged degraded")
	}

	// Healthy pair — not degraded.
	ok := connectPod("onepassword", "onepassword-connect-ok",
		time.Hour, true, 0)
	if _, bad := connectSyncDegraded(ok, now); bad {
		t.Fatal("healthy connect-sync flagged degraded")
	}
	// A pod without a connect-sync container is not ours to judge.
	alien := &corev1.Pod{
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "connect-api"}}},
	}
	if _, bad := connectSyncDegraded(alien, now); bad {
		t.Fatal("pod without connect-sync flagged degraded")
	}
}

// ---------------------------------------------------------------------------
// listFirst/listES — real-error preservation vs benign v1beta1 fallback
// ---------------------------------------------------------------------------

// A REAL API failure on one candidate GVR (RBAC denial, throttling,
// timeout) must never be overwritten by the benign NotFound/NoMatch
// the next candidate produces: the sweep would then quietly skip a
// cluster it can actually see. The real error wins.
func TestListFirstPreservesRealError(t *testing.T) {
	dyn := newDynFake(cssObj("store", "True"))
	realErr := apierrors.NewForbidden(
		clusterSecretStoreGVRs[0].GroupResource(), "", errors.New("rbac"))
	dyn.PrependReactor("list", "clustersecretstores",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			if action.GetResource().Version == "v1" {
				return true, nil, realErr
			}
			// v1beta1 answers with the benign not-installed shape —
			// the OLD code returned this and swallowed realErr.
			return true, nil, apierrors.NewNotFound(
				clusterSecretStoreGVRs[1].GroupResource(), "")
		})
	n := &externalSecretNudge{dyn: dyn}
	_, err := n.listFirst(ctx, clusterSecretStoreGVRs)
	if err == nil {
		t.Fatal("listFirst returned nil despite a real API error")
	}
	if !apierrors.IsForbidden(err) {
		t.Fatalf("real API error must win over the v1beta1 fallback, got %v", err)
	}
	// Same rule for the ES list used to pick the patch GVR.
	realESErr := apierrors.NewForbidden(
		externalSecretGVRs[0].GroupResource(), "", errors.New("rbac"))
	dyn.PrependReactor("list", "externalsecrets",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			if action.GetResource().Version == "v1" {
				return true, nil, realESErr
			}
			return true, nil, apierrors.NewNotFound(
				externalSecretGVRs[1].GroupResource(), "")
		})
	if _, _, err := n.listES(ctx); !apierrors.IsForbidden(err) {
		t.Fatalf("listES must preserve the real API error, got %v", err)
	}
}

// A NotFound or NoKindMatch on one candidate GVR stays a benign
// fallback: listFirst moves on to the next served version.
func TestListFirstBenignFallback(t *testing.T) {
	dyn := newDynFake(cssObj("store", "True"))
	nf := apierrors.NewNotFound(
		clusterSecretStoreGVRs[0].GroupResource(), "")
	dyn.PrependReactor("list", "clustersecretstores",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			if action.GetResource().Version == "v1" {
				return true, nil, nf
			}
			return false, nil, nil // v1beta1 serves the list
		})
	n := &externalSecretNudge{dyn: dyn}
	list, err := n.listFirst(ctx, clusterSecretStoreGVRs)
	if err != nil {
		t.Fatalf("benign v1 404 must fall through to v1beta1, got %v", err)
	}
	if list == nil {
		t.Fatal("expected the v1beta1 list, got nil")
	}

	// A NoKindMatchError is equally benign — run() skips quietly
	// instead of IncErroring every sweep.
	dyn2 := newDynFake(cssObj("store", "True"))
	nomatch := &meta.NoKindMatchError{
		GroupKind: schema.GroupKind{
			Group: clusterSecretStoreGVRs[0].Group,
			Kind:  "ClusterSecretStore"}}
	dyn2.PrependReactor("list", "clustersecretstores",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, nomatch
		})
	cs := kfake.NewSimpleClientset()
	n2 := &externalSecretNudge{queue: "externalsecret-nudge",
		cs: cs, dyn: dyn2, storeReady: map[string]bool{}}
	if err := n2.run(ctx); err != nil {
		t.Fatalf("NoKindMatch on the store list must skip quietly, got %v", err)
	}
}

// A store listed before its controller has written the Ready condition
// is not an observation of False — the down clock for the connect
// auto-heal must not start until a real condition exists.
func TestExternalSecretNudgeMissingConditionNoDownClock(t *testing.T) {
	// Builder twin of cssObj with no status.conditions at all.
	unconditioned := testutil.Unstructured(
		kube.GVRClusterSecretStoreV1.GroupVersion().WithKind("ClusterSecretStore"),
		"", "css-young", nil)
	dyn := newDynFake(unconditioned, esObj("apps", "es-stuck", "False", time.Hour))
	n := newNudge(dyn)

	if err := n.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, tracked := n.storeReady["ClusterSecretStore//css-young"]; tracked {
		t.Fatal("condition-less store must not be tracked as any readiness state")
	}
	if _, down := n.storeDownSince.Seen("ClusterSecretStore//css-young", time.Now()); down {
		t.Fatal("down clock started for a condition-less store — would bounce connect pod after 15m")
	}

	// The clock only arms once the condition appears (as False).
	setStoreReady(t, dyn, "css-young", "False")
	if err := n.run(ctx); err != nil {
		t.Fatal(err)
	}
	if r, tracked := n.storeReady["ClusterSecretStore//css-young"]; !tracked || r {
		t.Fatal("store not tracked after its Ready condition appeared")
	}
	if _, down := n.storeDownSince.Seen("ClusterSecretStore//css-young", time.Now()); !down {
		t.Fatal("down clock did not start on a real Ready=False observation")
	}
}
