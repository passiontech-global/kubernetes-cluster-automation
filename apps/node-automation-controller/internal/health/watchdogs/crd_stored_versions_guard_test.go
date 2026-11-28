package watchdogs

import (
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

var crdStoredVerTestFooGVR = schema.GroupVersionResource{
	Group: "example.com", Version: "v1", Resource: "foos",
}

func crdStoredVerTestMakeCRD(name, group, plural, kind string, versions []any, stored []any, annos map[string]string) *unstructured.Unstructured {
	metaMap := map[string]any{"name": name}
	if len(annos) > 0 {
		a := make(map[string]any, len(annos))
		for k, v := range annos {
			a[k] = v
		}
		metaMap["annotations"] = a
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apiextensions.k8s.io/v1",
		"kind":       "CustomResourceDefinition",
		"metadata":   metaMap,
		"spec": map[string]any{
			"group": group,
			"names": map[string]any{
				"plural": plural,
				"kind":   kind,
			},
			"scope":    "Namespaced",
			"versions": versions,
		},
		"status": map[string]any{
			"storedVersions": stored,
		},
	}}
}

func crdStoredVerTestMakeCR(ns, name string, annos map[string]string) *unstructured.Unstructured {
	metaMap := map[string]any{"namespace": ns, "name": name}
	if len(annos) > 0 {
		a := make(map[string]any, len(annos))
		for k, v := range annos {
			a[k] = v
		}
		metaMap["annotations"] = a
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "example.com/v1",
		"kind":       "Foo",
		"metadata":   metaMap,
	}}
}

func TestCRDStoredVersionsGuardDetection(t *testing.T) {
	t.Run("multi-version and unserved storedVersions detected without migrating when disabled", func(t *testing.T) {
		crdMulti := crdStoredVerTestMakeCRD(
			"foos.example.com", "example.com", "foos", "Foo",
			[]any{
				map[string]any{"name": "v1alpha1", "served": true, "storage": false},
				map[string]any{"name": "v1", "served": true, "storage": true},
			},
			[]any{"v1alpha1", "v1"},
			nil,
		)
		crdUnserved := crdStoredVerTestMakeCRD(
			"bars.example.com", "example.com", "bars", "Bar",
			[]any{
				map[string]any{"name": "v1beta1", "served": false, "storage": false},
				map[string]any{"name": "v1", "served": true, "storage": true},
			},
			[]any{"v1beta1"},
			nil,
		)
		crdHealthy := crdStoredVerTestMakeCRD(
			"ok.example.com", "example.com", "oks", "Ok",
			[]any{
				map[string]any{"name": "v1", "served": true, "storage": true},
			},
			[]any{"v1"},
			nil,
		)
		cr1 := crdStoredVerTestMakeCR("app", "foo-1", nil)

		kinds := maps.Clone(testutil.DynListKinds())
		kinds[testutil.CRDGVR] = "CustomResourceDefinitionList"
		kinds[crdStoredVerTestFooGVR] = "FooList"
		dyn := testutil.NewFakeDyn(kinds, crdMulti, crdUnserved, crdHealthy, cr1)
		cs := fake.NewSimpleClientset()
		p := probetest.NewCheckProber(cs, dyn, NewCRDStoredVersionsGuardCheck)
		chk := probetest.MustCheck[*crdStoredVerCheck](t, p)

		res := probetest.RunCheck(ctx, chk.Deps, chk)
		if res.Pass {
			t.Fatal("expected FAIL when CRDs have storedVersions drift")
		}
		if !strings.Contains(res.Why, "foos.example.com(multi_stored_versions") ||
			!strings.Contains(res.Why, "bars.example.com(unserved_stored_version") {
			t.Fatalf("unexpected Why: %s", res.Why)
		}
		if m := probetest.FindMetric(t, "node_automation_crd_stored_versions_drift", map[string]string{
			"crd": "foos.example.com", "reason": crdStoredVerReasonMulti,
		}); m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatalf("expected multi_stored_versions gauge=1, got %v", m)
		}
		if m := probetest.FindMetric(t, "node_automation_crd_stored_versions_drift", map[string]string{
			"crd": "bars.example.com", "reason": crdStoredVerReasonUnserved,
		}); m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatalf("expected unserved_stored_version gauge=1, got %v", m)
		}
		if m := probetest.FindMetric(t, "node_automation_crd_stored_versions_drift", map[string]string{
			"crd": "ok.example.com", "reason": crdStoredVerReasonMulti,
		}); m != nil {
			t.Fatalf("healthy CRD must not be flagged: %v", m)
		}

		// Warning Events emitted in default namespace.
		evs, err := cs.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
		if err != nil || len(evs.Items) != 2 {
			t.Fatalf("expected 2 Warning events, got %d (err=%v)", len(evs.Items), err)
		}
		for _, ev := range evs.Items {
			if ev.Reason != crdStoredVerEventReason {
				t.Fatalf("event reason = %q, want %q", ev.Reason, crdStoredVerEventReason)
			}
		}

		// Migration must NOT have run (default false).
		gotCR, _ := dyn.Resource(crdStoredVerTestFooGVR).Namespace("app").Get(ctx, "foo-1", metav1.GetOptions{})
		if gotCR.GetAnnotations()[crdStoredVerAnnoMigratedVersion] != "" {
			t.Fatalf("CR should not be migrated when migration disabled, got %v", gotCR.GetAnnotations())
		}
	})
}

func TestCRDStoredVersionsGuardMigration(t *testing.T) {
	t.Run("opt-in annotation migrates CRs and patches CRD /status", func(t *testing.T) {
		crd := crdStoredVerTestMakeCRD(
			"foos.example.com", "example.com", "foos", "Foo",
			[]any{
				map[string]any{"name": "v1alpha1", "served": true, "storage": false},
				map[string]any{"name": "v1", "served": true, "storage": true},
			},
			[]any{"v1alpha1", "v1"},
			map[string]string{crdStoredVerAnnoAutoMigrate: "true"},
		)
		cr1 := crdStoredVerTestMakeCR("ns1", "foo-1", nil)
		cr2 := crdStoredVerTestMakeCR("ns2", "foo-2", map[string]string{crdStoredVerAnnoMigratedVersion: "v1"})

		kinds := maps.Clone(testutil.DynListKinds())
		kinds[testutil.CRDGVR] = "CustomResourceDefinitionList"
		kinds[crdStoredVerTestFooGVR] = "FooList"
		dyn := testutil.NewFakeDyn(kinds, crd, cr1, cr2)
		cs := fake.NewSimpleClientset()
		p := probetest.NewCheckProber(cs, dyn, NewCRDStoredVersionsGuardCheck)
		chk := probetest.MustCheck[*crdStoredVerCheck](t, p)

		res := probetest.RunCheck(ctx, chk.Deps, chk)
		if res.Pass {
			t.Fatal("first sweep detects drift while migrating")
		}

		gotCR1, err := dyn.Resource(crdStoredVerTestFooGVR).Namespace("ns1").Get(ctx, "foo-1", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if gotCR1.GetAnnotations()[crdStoredVerAnnoMigratedVersion] != "v1" {
			t.Fatalf("foo-1 migrated annotation = %q, want v1", gotCR1.GetAnnotations()[crdStoredVerAnnoMigratedVersion])
		}

		gotCRD, err := dyn.Resource(testutil.CRDGVR).Get(ctx, "foos.example.com", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		svs, _, _ := unstructured.NestedStringSlice(gotCRD.Object, "status", "storedVersions")
		if len(svs) != 1 || svs[0] != "v1" {
			t.Fatalf("CRD storedVersions = %v, want [v1]", svs)
		}

		// Next sweep re-lists invalidated CRD GVR and passes + prunes gauge.
		res2 := probetest.RunCheck(ctx, chk.Deps, chk)
		if !res2.Pass {
			t.Fatalf("expected PASS after CRD storedVersions converged, got %+v", res2)
		}
		if m := probetest.FindMetric(t, "node_automation_crd_stored_versions_drift", map[string]string{
			"crd": "foos.example.com", "reason": crdStoredVerReasonMulti,
		}); m != nil {
			t.Fatalf("stale drift gauge not pruned: %v", m)
		}
	})

	t.Run("cap truncation does NOT patch CRD /status until all CRs migrated", func(t *testing.T) {
		t.Setenv("NODE_AUTOMATION_CRD_STORED_VERSIONS_MIGRATE_ENABLED", "true")

		crd := crdStoredVerTestMakeCRD(
			"foos.example.com", "example.com", "foos", "Foo",
			[]any{
				map[string]any{"name": "v1alpha1", "served": false, "storage": false},
				map[string]any{"name": "v1", "served": true, "storage": true},
			},
			[]any{"v1alpha1", "v1"},
			nil,
		)
		objs := []runtime.Object{crd}
		for i := 0; i < 51; i++ {
			objs = append(objs, crdStoredVerTestMakeCR("ns1", fmt.Sprintf("foo-%02d", i), nil))
		}

		kinds := maps.Clone(testutil.DynListKinds())
		kinds[testutil.CRDGVR] = "CustomResourceDefinitionList"
		kinds[crdStoredVerTestFooGVR] = "FooList"
		dyn := testutil.NewFakeDyn(kinds, objs...)
		cs := fake.NewSimpleClientset()
		p := probetest.NewCheckProber(cs, dyn, NewCRDStoredVersionsGuardCheck)
		base := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*crdStoredVerCheck](t, p)

		_ = probetest.RunCheck(ctx, chk.Deps, chk)

		gotCRD, _ := dyn.Resource(testutil.CRDGVR).Get(ctx, "foos.example.com", metav1.GetOptions{})
		svs, _, _ := unstructured.NestedStringSlice(gotCRD.Object, "status", "storedVersions")
		if len(svs) != 2 {
			t.Fatalf("cap-truncated sweep must NOT patch /status, got storedVersions=%v", svs)
		}
		// foo-50 should not be migrated yet (cap 50).
		got50, _ := dyn.Resource(crdStoredVerTestFooGVR).Namespace("ns1").Get(ctx, "foo-50", metav1.GetOptions{})
		if got50.GetAnnotations()[crdStoredVerAnnoMigratedVersion] != "" {
			t.Fatalf("expected foo-50 skipped due to 50-CR cap")
		}

		// After 30m cooldown, second sweep migrates foo-50 and patches /status.
		probetest.FreezeNow(p.Deps, base.Add(31*time.Minute))
		_ = probetest.RunCheck(ctx, chk.Deps, chk)

		got50, _ = dyn.Resource(crdStoredVerTestFooGVR).Namespace("ns1").Get(ctx, "foo-50", metav1.GetOptions{})
		if got50.GetAnnotations()[crdStoredVerAnnoMigratedVersion] != "v1" {
			t.Fatalf("expected foo-50 migrated on second sweep, got %v", got50.GetAnnotations())
		}
		gotCRD, _ = dyn.Resource(testutil.CRDGVR).Get(ctx, "foos.example.com", metav1.GetOptions{})
		svs, _, _ = unstructured.NestedStringSlice(gotCRD.Object, "status", "storedVersions")
		if len(svs) != 1 || svs[0] != "v1" {
			t.Fatalf("expected CRD storedVersions=[v1] after all CRs migrated, got %v", svs)
		}
	})

	t.Run("partial CR patch error does NOT patch CRD /status", func(t *testing.T) {
		t.Setenv("NODE_AUTOMATION_CRD_STORED_VERSIONS_MIGRATE_ENABLED", "true")

		crd := crdStoredVerTestMakeCRD(
			"foos.example.com", "example.com", "foos", "Foo",
			[]any{
				map[string]any{"name": "v1alpha1", "served": true, "storage": false},
				map[string]any{"name": "v1", "served": true, "storage": true},
			},
			[]any{"v1alpha1", "v1"},
			nil,
		)
		cr1 := crdStoredVerTestMakeCR("ns1", "foo-1", nil)
		cr2 := crdStoredVerTestMakeCR("ns1", "foo-2", nil)

		kinds := maps.Clone(testutil.DynListKinds())
		kinds[testutil.CRDGVR] = "CustomResourceDefinitionList"
		kinds[crdStoredVerTestFooGVR] = "FooList"
		dyn := testutil.NewFakeDyn(kinds, crd, cr1, cr2)
		dyn.PrependReactor("patch", "foos", func(a ktesting.Action) (bool, runtime.Object, error) {
			pa := a.(ktesting.PatchAction)
			if pa.GetName() == "foo-2" {
				return true, nil, errors.New("simulated conflict")
			}
			return false, nil, nil
		})
		cs := fake.NewSimpleClientset()
		p := probetest.NewCheckProber(cs, dyn, NewCRDStoredVersionsGuardCheck)
		chk := probetest.MustCheck[*crdStoredVerCheck](t, p)

		_ = probetest.RunCheck(ctx, chk.Deps, chk)

		gotCRD, _ := dyn.Resource(testutil.CRDGVR).Get(ctx, "foos.example.com", metav1.GetOptions{})
		svs, _, _ := unstructured.NestedStringSlice(gotCRD.Object, "status", "storedVersions")
		if len(svs) != 2 {
			t.Fatalf("partial CR patch error must NOT patch CRD /status, got %v", svs)
		}
	})

	t.Run("explicit opt-out annotation false blocks migration even when env enabled", func(t *testing.T) {
		t.Setenv("NODE_AUTOMATION_CRD_STORED_VERSIONS_MIGRATE_ENABLED", "true")

		crd := crdStoredVerTestMakeCRD(
			"foos.example.com", "example.com", "foos", "Foo",
			[]any{
				map[string]any{"name": "v1alpha1", "served": true, "storage": false},
				map[string]any{"name": "v1", "served": true, "storage": true},
			},
			[]any{"v1alpha1", "v1"},
			map[string]string{crdStoredVerAnnoAutoMigrate: "false"},
		)
		cr1 := crdStoredVerTestMakeCR("ns1", "foo-1", nil)

		kinds := maps.Clone(testutil.DynListKinds())
		kinds[testutil.CRDGVR] = "CustomResourceDefinitionList"
		kinds[crdStoredVerTestFooGVR] = "FooList"
		dyn := testutil.NewFakeDyn(kinds, crd, cr1)
		cs := fake.NewSimpleClientset()
		p := probetest.NewCheckProber(cs, dyn, NewCRDStoredVersionsGuardCheck)
		chk := probetest.MustCheck[*crdStoredVerCheck](t, p)

		_ = probetest.RunCheck(ctx, chk.Deps, chk)

		gotCR1, _ := dyn.Resource(crdStoredVerTestFooGVR).Namespace("ns1").Get(ctx, "foo-1", metav1.GetOptions{})
		if gotCR1.GetAnnotations()[crdStoredVerAnnoMigratedVersion] != "" {
			t.Fatalf("opt-out CRD must not migrate CRs")
		}
	})
}

func TestCRDStoredVersionsGuard403GracefulSkipAndBudgetRefund(t *testing.T) {
	t.Run("403 on CRD list skips gracefully without Infra error", func(t *testing.T) {
		dyn := testutil.NewDynamicClientWithCRDs()
		dyn.PrependReactor("list", "customresourcedefinitions", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "apiextensions.k8s.io", Resource: "customresourcedefinitions"}, "", errors.New("forbidden"))
		})
		cs := fake.NewSimpleClientset()
		p := probetest.NewCheckProber(cs, dyn, NewCRDStoredVersionsGuardCheck)
		chk := probetest.MustCheck[*crdStoredVerCheck](t, p)

		res := probetest.RunCheck(ctx, chk.Deps, chk)
		if !res.Pass || res.Infra != nil {
			t.Fatalf("expected PASS with no Infra error on 403 CRD list, got %+v", res)
		}
	})

	t.Run("403 on CR list skips gracefully and refunds fleet budget", func(t *testing.T) {
		t.Setenv("NODE_AUTOMATION_CRD_STORED_VERSIONS_MIGRATE_ENABLED", "true")
		heal.ConfigureBudget(1, time.Hour)
		t.Cleanup(func() { heal.ConfigureBudget(0, 0) })

		crd := crdStoredVerTestMakeCRD(
			"foos.example.com", "example.com", "foos", "Foo",
			[]any{
				map[string]any{"name": "v1alpha1", "served": true, "storage": false},
				map[string]any{"name": "v1", "served": true, "storage": true},
			},
			[]any{"v1alpha1", "v1"},
			nil,
		)
		kinds := maps.Clone(testutil.DynListKinds())
		kinds[testutil.CRDGVR] = "CustomResourceDefinitionList"
		kinds[crdStoredVerTestFooGVR] = "FooList"
		dyn := testutil.NewFakeDyn(kinds, crd)
		var crLists atomic.Int32
		dyn.PrependReactor("list", "foos", func(ktesting.Action) (bool, runtime.Object, error) {
			crLists.Add(1)
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "example.com", Resource: "foos"}, "", errors.New("forbidden"))
		})

		cs := fake.NewSimpleClientset()
		p := probetest.NewCheckProber(cs, dyn, NewCRDStoredVersionsGuardCheck)
		base := time.Date(2026, 11, 25, 11, 0, 0, 0, time.UTC)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*crdStoredVerCheck](t, p)

		res := probetest.RunCheck(ctx, chk.Deps, chk)
		if res.Pass || res.Infra != nil {
			t.Fatalf("expected FAIL (drift detected) with nil Infra on 403 CR list, got %+v", res)
		}
		if crLists.Load() != 1 {
			t.Fatalf("expected 1 CR list attempt, got %d", crLists.Load())
		}
		// Fleet budget of 1 must have been refunded on 403 CR list.
		if ok, _ := chk.HealAllowed(ctx, logr.Discard(), nil, "sibling-key", time.Minute, base); !ok {
			t.Fatal("expected fleet budget grant to be refunded on 403 CR list skip")
		}
	})

	t.Run("CR patch failure does NOT refund budget and terminating CR blocks premature /status prune", func(t *testing.T) {
		t.Setenv("NODE_AUTOMATION_CRD_STORED_VERSIONS_MIGRATE_ENABLED", "true")
		heal.ConfigureBudget(1, time.Hour)
		t.Cleanup(func() { heal.ConfigureBudget(0, 0) })

		crd := crdStoredVerTestMakeCRD(
			"foos.example.com", "example.com", "foos", "Foo",
			[]any{
				map[string]any{"name": "v1alpha1", "served": true, "storage": false},
				map[string]any{"name": "v1", "served": true, "storage": true},
			},
			[]any{"v1alpha1", "v1"},
			nil,
		)
		crErr := crdStoredVerTestMakeCR("ns1", "foo-err", nil)
		kinds := maps.Clone(testutil.DynListKinds())
		kinds[testutil.CRDGVR] = "CustomResourceDefinitionList"
		kinds[crdStoredVerTestFooGVR] = "FooList"
		dyn := testutil.NewFakeDyn(kinds, crd, crErr)
		dyn.PrependReactor("patch", "foos", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("webhook conversion error")
		})
		cs := fake.NewSimpleClientset()
		p := probetest.NewCheckProber(cs, dyn, NewCRDStoredVersionsGuardCheck)
		base := time.Date(2026, 11, 25, 11, 0, 0, 0, time.UTC)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*crdStoredVerCheck](t, p)

		_ = probetest.RunCheck(ctx, chk.Deps, chk)
		if ok, _ := chk.HealAllowed(ctx, logr.Discard(), nil, "sibling-key", time.Minute, base); ok {
			t.Fatal("failed CR patch must spend fleet budget grant, not refund it")
		}

		// Terminating CR without migrated annotation must prevent /status prune.
		heal.ConfigureBudget(5, time.Hour)
		termCR := crdStoredVerTestMakeCR("ns1", "foo-term", nil)
		termTime := metav1.NewTime(base.Add(-time.Minute))
		termCR.SetDeletionTimestamp(&termTime)
		dyn2 := testutil.NewFakeDyn(kinds, crd.DeepCopy(), termCR)
		p2 := probetest.NewCheckProber(fake.NewSimpleClientset(), dyn2, NewCRDStoredVersionsGuardCheck)
		probetest.FreezeNow(p2.Deps, base)
		chk2 := probetest.MustCheck[*crdStoredVerCheck](t, p2)
		_ = probetest.RunCheck(ctx, chk2.Deps, chk2)
		gotCRD, _ := dyn2.Resource(testutil.CRDGVR).Get(ctx, "foos.example.com", metav1.GetOptions{})
		svs, _, _ := unstructured.NestedStringSlice(gotCRD.Object, "status", "storedVersions")
		if len(svs) != 2 {
			t.Fatalf("terminating unmigrated CR must block /status storedVersions prune, got %v", svs)
		}
	})
}
