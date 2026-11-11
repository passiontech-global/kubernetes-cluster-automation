// api_object_sprawl_report_gc_test.go — coverage for the
// api-object-sprawl-report-gc check: dead-owner report GC, census
// gauges and the superseded helm-secret cap.
package sprawl

import (
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// sprawlReport builds an unstructured report CR owned by ownerRef,
// created `age` ago. kind must pluralize to the GVR's resource — the
// fake dynamic client stores by guessed resource (same convention as
// every module test seeding unstructured CRs).
func sprawlReport(gvr schema.GroupVersionResource, kind, ns, name string,
	age time.Duration, owner *metav1.OwnerReference) *unstructured.Unstructured {

	obj := testutil.Unstructured(
		gvr.GroupVersion().WithKind(kind), ns, name, nil)
	obj.SetCreationTimestamp(metav1.NewTime(time.Now().Add(-age)))
	obj.SetUID(types.UID("uid-" + ns + "-" + name))
	if owner != nil {
		obj.SetOwnerReferences([]metav1.OwnerReference{*owner})
	}
	return obj
}

func sprawlOwner(kind, name string) *metav1.OwnerReference {
	return &metav1.OwnerReference{
		Kind: kind, Name: name, Controller: ptr.To(true)}
}

func liveReplicaSet(ns, name string) *appsv1.ReplicaSet {
	return &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: ns, Name: name}}
}

func helmSecret(ns, release string, version int, status string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      fmt.Sprintf("sh.helm.release.v1.%s.v%d", release, version),
			Labels: map[string]string{
				"owner": "helm", "name": release,
				"version": fmt.Sprint(version), "status": status},
			UID: types.UID(fmt.Sprintf("uid-%s-%s-%d", ns, release, version)),
		},
		// The Secret type helm writes per revision — the literal the
		// shared prune (kube.PruneSupersededHelmSecrets) selects on.
		Type: corev1.SecretType("helm.sh/release.v1"),
	}
}

// sprawlDyn builds a dynamic fake covering the shared CRD table plus
// the argo rollouts kinds the rollout-scale-flap census/GC reads and
// the apiextensions CRDs the kine large-object census scans (the
// shared OpDyn table predates them).
func sprawlDyn(objs ...runtime.Object) dynamic.Interface {
	kinds := maps.Clone(testutil.DynListKinds())
	kinds[kube.GVRArgoAnalysisRun] = "AnalysisRunList"
	kinds[kube.GVRArgoExperiment] = "ExperimentList"
	kinds[kube.GVRCustomResourceDefinition] = "CustomResourceDefinitionList"
	return testutil.NewFakeDyn(kinds, objs...)
}

func TestSprawlGCDeletesDeadOwnerReports(t *testing.T) {
	// Orphaned: owned by a ReplicaSet that is gone.
	orphan := sprawlReport(kube.GVRVulnerabilityReport, "VulnerabilityReport",
		"apps", "vr-orphan", 3*time.Hour, sprawlOwner("ReplicaSet", "gone-rs"))
	// Live owner: the ReplicaSet exists.
	liveOwner := sprawlReport(kube.GVRVulnerabilityReport, "VulnerabilityReport",
		"apps", "vr-live", 3*time.Hour, sprawlOwner("ReplicaSet", "live-rs"))
	// Too young: owner gone but under the orphan window.
	young := sprawlReport(kube.GVRVulnerabilityReport, "VulnerabilityReport",
		"apps", "vr-young", 30*time.Minute, sprawlOwner("ReplicaSet", "gone-rs"))
	rs := liveReplicaSet("apps", "live-rs")
	cs := fake.NewSimpleClientset(rs)
	p := testProberDyn(cs, sprawlDyn(orphan, liveOwner, young))
	res := probetest.MustCheck[*apiObjectSprawlReportGCCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("live orphans must fail: %+v", res)
	}
	if !strings.Contains(res.Why, "vulnerabilityreports") {
		t.Fatalf("why missing report kind: %q", res.Why)
	}
	if _, err := p.Dyn.Resource(kube.GVRVulnerabilityReport).Namespace("apps").
		Get(ctx, "vr-orphan", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("dead-owner report should be deleted, err=%v", err)
	}
	for _, name := range []string{"vr-live", "vr-young"} {
		if _, err := p.Dyn.Resource(kube.GVRVulnerabilityReport).Namespace("apps").
			Get(ctx, name, metav1.GetOptions{}); err != nil {
			t.Fatalf("report %s must survive: %v", name, err)
		}
	}
	if _, ok := testutil.GaugeSeriesValue(t, "node_automation_api_object_count",
		map[string]string{"resource": "vulnerabilityreports", "namespace": "apps"}); !ok {
		t.Fatal("census gauge missing for vulnerabilityreports")
	}
	if v, ok := testutil.GaugeSeriesValue(t, "node_automation_ephemeral_reports_orphaned",
		map[string]string{"kind": "vulnerabilityreport"}); !ok || v != 1 {
		t.Fatalf("orphan gauge = %v,%v want 1,true (only the dead-owner report)", v, ok)
	}
}

// sprawlArgoCR builds an AnalysisRun/Experiment with a status.phase.
func sprawlArgoCR(gvr schema.GroupVersionResource, kind, ns, name string,
	age time.Duration, phase string) *unstructured.Unstructured {
	obj := testutil.Unstructured(gvr.GroupVersion().WithKind(kind), ns, name,
		map[string]any{"status": map[string]any{"phase": phase}})
	obj.SetCreationTimestamp(metav1.NewTime(time.Now().Add(-age)))
	obj.SetUID(types.UID("uid-" + ns + "-" + name))
	return obj
}

// rollout-scale-flap — terminal-phase AnalysisRuns past the retention threshold
// are GC'd (the Rollouts controller never prunes them); Running ones
// and records inside the window survive.
func TestSprawlGCCollectsCompletedAnalysisRuns(t *testing.T) {
	done := sprawlArgoCR(kube.GVRArgoAnalysisRun, "AnalysisRun",
		"apps", "ar-done", 3*time.Hour, "Successful")
	failed := sprawlArgoCR(kube.GVRArgoAnalysisRun, "AnalysisRun",
		"apps", "ar-failed", 4*time.Hour, "Failed")
	running := sprawlArgoCR(kube.GVRArgoAnalysisRun, "AnalysisRun",
		"apps", "ar-running", 5*time.Hour, "Running")
	young := sprawlArgoCR(kube.GVRArgoAnalysisRun, "AnalysisRun",
		"apps", "ar-young", 30*time.Minute, "Successful")
	p := testProberDyn(fake.NewSimpleClientset(),
		sprawlDyn(done, failed, running, young))
	res := probetest.MustCheck[*apiObjectSprawlReportGCCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("uncollected completed AnalysisRuns must fail: %+v", res)
	}
	for _, name := range []string{"ar-done", "ar-failed"} {
		if _, err := p.Dyn.Resource(kube.GVRArgoAnalysisRun).Namespace("apps").
			Get(ctx, name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatalf("completed AnalysisRun %s should be GC'd, err=%v", name, err)
		}
	}
	for _, name := range []string{"ar-running", "ar-young"} {
		if _, err := p.Dyn.Resource(kube.GVRArgoAnalysisRun).Namespace("apps").
			Get(ctx, name, metav1.GetOptions{}); err != nil {
			t.Fatalf("AnalysisRun %s must survive: %v", name, err)
		}
	}
}

// rollout-scale-flap — the same GC covers Experiments: only the terminal phases
// (Successful/Failed/Error/Inconclusive) age out.
func TestSprawlGCCollectsCompletedExperiments(t *testing.T) {
	done := sprawlArgoCR(kube.GVRArgoExperiment, "Experiment",
		"apps", "exp-done", 3*time.Hour, "Inconclusive")
	running := sprawlArgoCR(kube.GVRArgoExperiment, "Experiment",
		"apps", "exp-running", 3*time.Hour, "Running")
	p := testProberDyn(fake.NewSimpleClientset(),
		sprawlDyn(done, running))
	res := probetest.MustCheck[*apiObjectSprawlReportGCCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("uncollected completed Experiment must fail: %+v", res)
	}
	if _, err := p.Dyn.Resource(kube.GVRArgoExperiment).Namespace("apps").
		Get(ctx, "exp-done", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("completed Experiment should be GC'd, err=%v", err)
	}
	if _, err := p.Dyn.Resource(kube.GVRArgoExperiment).Namespace("apps").
		Get(ctx, "exp-running", metav1.GetOptions{}); err != nil {
		t.Fatalf("running Experiment must survive: %v", err)
	}
}

func TestSprawlGCPrunesSupersededHelmSecrets(t *testing.T) {
	var objs []runtime.Object
	for v := 1; v <= 13; v++ {
		objs = append(objs, helmSecret("apps", "myrelease", v, "superseded"))
	}
	// The newest revision is deployed — never a prune candidate.
	objs = append(objs, helmSecret("apps", "myrelease", 14, "deployed"))
	cs := fake.NewSimpleClientset(objs...)
	p := testProberDyn(cs, sprawlDyn())
	res := probetest.MustCheck[*apiObjectSprawlReportGCCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("superseded excess must fail: %+v", res)
	}
	remaining := 0
	list, err := cs.CoreV1().Secrets("apps").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list secrets: %v", err)
	}
	for _, s := range list.Items {
		if s.Labels["status"] == "superseded" {
			remaining++
		}
	}
	if remaining != sprawlMaxSuperseded {
		t.Fatalf("superseded secrets = %d want %d", remaining, sprawlMaxSuperseded)
	}
	if _, err := cs.CoreV1().Secrets("apps").Get(ctx,
		"sh.helm.release.v1.myrelease.v14", metav1.GetOptions{}); err != nil {
		t.Fatalf("deployed revision must survive: %v", err)
	}
	// The OLDEST superseded die first — v1..v3 are the excess.
	if _, err := cs.CoreV1().Secrets("apps").Get(ctx,
		"sh.helm.release.v1.myrelease.v1", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("oldest superseded secret should be pruned, err=%v", err)
	}
	if v, ok := testutil.GaugeSeriesValue(t, "node_automation_helm_release_secrets_excess",
		map[string]string{"namespace": "apps", "release": "myrelease"}); !ok || v != 3 {
		t.Fatalf("excess gauge = %v,%v want 3,true", v, ok)
	}
}

// Kine large-object census — ConfigMap/Secret objects above the 512 KiB Kine row guard
// emit node_automation_kine_large_object_bytes and fail the check;
// objects at or below the threshold stay silent; shrinking (here:
// deleting) the offenders prunes their series and lets the check pass
// again — the emittedLargeObjects ledger reset.
func TestSprawlGCKineLargeObjects(t *testing.T) {
	blob := make([]byte, kineLargeObjectThreshold+1024)
	bigCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "big-cm"},
		BinaryData: map[string][]byte{"blob": blob},
	}
	smallCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "small-cm"},
		Data:       map[string]string{"k": "v"},
	}
	bigSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "big-secret"},
		Data:       map[string][]byte{"release": blob},
		Type:       corev1.SecretTypeOpaque,
	}
	testutil.CleanupMetric(t, kineLargeObjectBytesGauge, "configmap", "apps", "big-cm")
	testutil.CleanupMetric(t, kineLargeObjectBytesGauge, "secret", "apps", "big-secret")

	cs := fake.NewSimpleClientset(bigCM, smallCM, bigSecret)
	p := testProberDyn(cs, sprawlDyn())
	chk := probetest.MustCheck[*apiObjectSprawlReportGCCheck](t, p)

	res := chk.Run(ctx)
	if res.Pass {
		t.Fatalf("large objects must fail the check: %+v", res)
	}
	for _, want := range []struct{ kind, name string }{
		{"configmap", "big-cm"}, {"secret", "big-secret"},
	} {
		v, ok := testutil.GaugeSeriesValue(t, "node_automation_kine_large_object_bytes",
			map[string]string{"kind": want.kind, "namespace": "apps", "name": want.name})
		if !ok || v <= kineLargeObjectThreshold {
			t.Fatalf("%s %s gauge = %v,%v want >%d,true", want.kind, want.name, v, ok, kineLargeObjectThreshold)
		}
		if !strings.Contains(res.Why, want.name) {
			t.Fatalf("why missing %s finding: %q", want.name, res.Why)
		}
	}
	if _, ok := testutil.GaugeSeriesValue(t, "node_automation_kine_large_object_bytes",
		map[string]string{"kind": "configmap", "namespace": "apps", "name": "small-cm"}); ok {
		t.Fatal("small ConfigMap wrongly flagged as a large object")
	}

	// Ledger reset: once the large objects are gone the series prune
	// and the check passes again.
	if err := cs.CoreV1().ConfigMaps("apps").Delete(ctx, "big-cm", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := cs.CoreV1().Secrets("apps").Delete(ctx, "big-secret", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	res2 := chk.Run(ctx)
	if !res2.Pass {
		t.Fatalf("check must pass once the large objects are gone: %+v", res2)
	}
	if _, ok := testutil.GaugeSeriesValue(t, "node_automation_kine_large_object_bytes",
		map[string]string{"kind": "configmap", "namespace": "apps", "name": "big-cm"}); ok {
		t.Fatal("resolved ConfigMap series not pruned by the ledger")
	}
	if _, ok := testutil.GaugeSeriesValue(t, "node_automation_kine_large_object_bytes",
		map[string]string{"kind": "secret", "namespace": "apps", "name": "big-secret"}); ok {
		t.Fatal("resolved Secret series not pruned by the ledger")
	}
}

// Kine large-object census — the CRD-backed kinds ride the same
// 512 KiB row guard through AllUnstructured: CRDs and CSVs are
// cluster-scoped (empty namespace label), Applications and
// HelmCharts carry theirs, and every hit lands on the shared verdict.
func TestSprawlGCKineLargeObjectsCRDKinds(t *testing.T) {
	blob := strings.Repeat("x", kineLargeObjectThreshold+1024)
	big := func(gvk schema.GroupVersionKind, ns, name string) *unstructured.Unstructured {
		return testutil.Unstructured(gvk, ns, name, map[string]any{
			"spec": map[string]any{"blob": blob},
		})
	}
	crd := big(schema.GroupVersionKind{Group: "apiextensions.k8s.io",
		Version: "v1", Kind: "CustomResourceDefinition"}, "", "big-crd")
	csv := big(schema.GroupVersionKind{Group: "operators.coreos.com",
		Version: "v1alpha1", Kind: "ClusterServiceVersion"}, "", "big-csv")
	app := big(schema.GroupVersionKind{Group: "argoproj.io",
		Version: "v1alpha1", Kind: "Application"}, "argocd", "big-app")
	chart := big(schema.GroupVersionKind{Group: "source.toolkit.fluxcd.io",
		Version: "v1", Kind: "HelmChart"}, "flux-system", "big-chart")
	small := testutil.Unstructured(schema.GroupVersionKind{Group: "argoproj.io",
		Version: "v1alpha1", Kind: "Application"}, "argocd", "small-app",
		map[string]any{"spec": map[string]any{"replicas": int64(1)}})
	for _, kv := range []struct{ kind, ns, name string }{
		{"customresourcedefinition", "", "big-crd"},
		{"clusterserviceversion", "", "big-csv"},
		{"application", "argocd", "big-app"},
		{"helmchart", "flux-system", "big-chart"},
	} {
		testutil.CleanupMetric(t, kineLargeObjectBytesGauge, kv.kind, kv.ns, kv.name)
	}
	testutil.CleanupMetric(t, kineLargeObjectBytesGauge, "application", "argocd", "small-app")

	p := testProberDyn(fake.NewSimpleClientset(), sprawlDyn(crd, csv, app, chart, small))
	res := probetest.MustCheck[*apiObjectSprawlReportGCCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("large CRD-backed objects must fail the check: %+v", res)
	}
	for _, want := range []struct{ kind, ns, name string }{
		{"customresourcedefinition", "", "big-crd"},
		{"clusterserviceversion", "", "big-csv"},
		{"application", "argocd", "big-app"},
		{"helmchart", "flux-system", "big-chart"},
	} {
		v, ok := testutil.GaugeSeriesValue(t, "node_automation_kine_large_object_bytes",
			map[string]string{"kind": want.kind, "namespace": want.ns, "name": want.name})
		if !ok || v <= kineLargeObjectThreshold {
			t.Fatalf("%s %s/%s gauge = %v,%v want >%d,true",
				want.kind, want.ns, want.name, v, ok, kineLargeObjectThreshold)
		}
		if !strings.Contains(res.Why, want.name) {
			t.Fatalf("why missing %s finding: %q", want.name, res.Why)
		}
	}
	if _, ok := testutil.GaugeSeriesValue(t, "node_automation_kine_large_object_bytes",
		map[string]string{"kind": "application", "namespace": "argocd", "name": "small-app"}); ok {
		t.Fatal("small Application wrongly flagged as a large object")
	}
}

// An absent API resource (the CRD/API not served on this cluster)
// skips quietly — IsNotFound on the dynamic LIST is not infra.
func TestSprawlGCKineLargeObjectsCRDSkipAbsent(t *testing.T) {
	blob := strings.Repeat("x", kineLargeObjectThreshold+1024)
	crd := testutil.Unstructured(schema.GroupVersionKind{Group: "apiextensions.k8s.io",
		Version: "v1", Kind: "CustomResourceDefinition"}, "", "big-crd",
		map[string]any{"spec": map[string]any{"blob": blob}})
	dyn := sprawlDyn(crd).(*dynamicfake.FakeDynamicClient)
	// Every operator API absent: NotFound on each dynamic LIST.
	for _, res := range []string{
		"clusterserviceversions", "applications", "helmcharts",
	} {
		resource := res
		dyn.PrependReactor("list", resource,
			func(a ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, apierrors.NewNotFound(
					schema.GroupResource{Resource: resource}, "")
			})
	}
	for _, kv := range []struct{ kind, ns, name string }{
		{"customresourcedefinition", "", "big-crd"},
		{"clusterserviceversion", "", "x"},
		{"application", "argocd", "x"},
		{"helmchart", "flux-system", "x"},
	} {
		testutil.CleanupMetric(t, kineLargeObjectBytesGauge, kv.kind, kv.ns, kv.name)
	}
	p := testProberDyn(fake.NewSimpleClientset(), dyn)
	res := probetest.MustCheck[*apiObjectSprawlReportGCCheck](t, p).Run(ctx)
	if res.Pass {
		t.Fatalf("the surviving CRD census must still fail: %+v", res)
	}
	if _, ok := testutil.GaugeSeriesValue(t, "node_automation_kine_large_object_bytes",
		map[string]string{"kind": "customresourcedefinition", "namespace": "", "name": "big-crd"}); !ok {
		t.Fatal("CRD census series missing after absent-API skips")
	}
}

// A failed dynamic read is infra: the check reports Infra and the
// ledger never Closes, so previously emitted series survive the
// flap instead of being pruned.
func TestSprawlGCKineLargeObjectsCRDInfraErrorKeepsSeries(t *testing.T) {
	blob := strings.Repeat("x", kineLargeObjectThreshold+1024)
	chart := testutil.Unstructured(schema.GroupVersionKind{Group: "source.toolkit.fluxcd.io",
		Version: "v1", Kind: "HelmChart"}, "flux-system", "big-chart",
		map[string]any{"spec": map[string]any{"blob": blob}})
	dyn := sprawlDyn(chart).(*dynamicfake.FakeDynamicClient)
	testutil.CleanupMetric(t, kineLargeObjectBytesGauge, "helmchart", "flux-system", "big-chart")
	p := testProberDyn(fake.NewSimpleClientset(), dyn)
	chk := probetest.MustCheck[*apiObjectSprawlReportGCCheck](t, p)

	if res := chk.Run(ctx); res.Pass {
		t.Fatalf("large HelmChart must fail the check: %+v", res)
	}
	if _, ok := testutil.GaugeSeriesValue(t, "node_automation_kine_large_object_bytes",
		map[string]string{"kind": "helmchart", "namespace": "flux-system", "name": "big-chart"}); !ok {
		t.Fatal("helmchart series missing after first sweep")
	}

	// Second sweep: the HelmChart LIST fails AND the object is gone —
	// the stale series must survive because the ledger never Closes.
	dyn.PrependReactor("list", "helmcharts",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, fmt.Errorf("apiserver down")
		})
	res := chk.Run(ctx)
	if res.Infra == nil {
		t.Fatalf("failed dynamic read must be Infra, got %+v", res)
	}
	if _, ok := testutil.GaugeSeriesValue(t, "node_automation_kine_large_object_bytes",
		map[string]string{"kind": "helmchart", "namespace": "flux-system", "name": "big-chart"}); !ok {
		t.Fatal("infra-failed sweep pruned the live gauge series")
	}
}

// The kine census reconciles its OWN GaugeScope (kineRep under
// kineLargeObjectBytesGauge) — the counts ledger stays free of kine
// tuples and the kine ledger free of census tuples, so one ledger's
// stale keys can never cross-prune or cross-pollute the other gauge's
// series.
func TestSprawlGCKineGaugeScopeSeparate(t *testing.T) {
	blob := make([]byte, kineLargeObjectThreshold+1024)
	bigCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "big-cm"},
		Data:       map[string]string{"blob": string(blob)},
	}
	// A live census object — the counts ledger must hold its
	// "resource/ns" tuple next to the kine ledger's "kind/ns/name".
	rep := sprawlReport(kube.GVRVulnerabilityReport, "VulnerabilityReport",
		"apps", "vr-census", 30*time.Minute, sprawlOwner("ReplicaSet", "rs-census"))
	testutil.CleanupMetric(t, kineLargeObjectBytesGauge, "configmap", "apps", "big-cm")
	testutil.CleanupMetric(t, apiObjectCountGauge, "vulnerabilityreports", "apps")

	cs := fake.NewSimpleClientset(liveReplicaSet("apps", "rs-census"), bigCM)
	p := testProberDyn(cs, sprawlDyn(rep))
	chk := probetest.MustCheck[*apiObjectSprawlReportGCCheck](t, p)

	if res := chk.Run(ctx); res.Pass {
		t.Fatalf("large object must fail the check: %+v", res)
	}
	// Kine ledger: exactly the kine tuple, no census tuples leaked in.
	if got := chk.emittedLargeObjects.Last(); len(got) != 1 {
		t.Fatalf("kine ledger holds %v, want only the configmap tuple", got)
	}
	if _, ok := chk.emittedLargeObjects.Last()["configmap/apps/big-cm"]; !ok {
		t.Fatal("kine large-object tuple missing from its own ledger")
	}
	// Counts ledger: exactly the census tuple, no kine keys leaked in.
	if got := chk.emittedObjects.Last(); len(got) != 1 {
		t.Fatalf("counts ledger holds %v, want only the census tuple", got)
	}
	if _, ok := chk.emittedObjects.Last()["vulnerabilityreports/apps"]; !ok {
		t.Fatal("census tuple missing from the counts ledger")
	}
}

// deleteOrphanReport is the GC's UID-preconditioned delete: success
// and already-gone both count as collected; a Forbidden (RBAC still
// rolling out) skips without metering; any other failure is metered
// and reported so the sweep's error accounting stays honest.
func TestDeleteOrphanReportVerdicts(t *testing.T) {
	rk := sprawlKindRef{kube.GVRVulnerabilityReport,
		"vulnerabilityreport", "vulnerabilityreports"}
	obj := sprawlReport(kube.GVRVulnerabilityReport, "VulnerabilityReport",
		"apps", "vr-x", time.Hour, nil)
	dyn := sprawlDyn(obj).(*dynamicfake.FakeDynamicClient)
	p := &apiObjectSprawlReportGCCheck{Deps: &probefw.Deps{
		Name: "api-object-sprawl-report-gc", Dyn: dyn}}

	if !p.deleteOrphanReport(ctx, logr.Discard(), rk, obj) {
		t.Fatal("live orphan report delete must succeed")
	}
	if _, err := dyn.Resource(kube.GVRVulnerabilityReport).Namespace("apps").
		Get(ctx, "vr-x", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("report not deleted: %v", err)
	}
	// Already gone — GC achieved, still counts as collected.
	if !p.deleteOrphanReport(ctx, logr.Discard(), rk, obj) {
		t.Fatal("NotFound delete must count as collected")
	}
	// Forbidden — the RBAC rollout pending shape: skip quietly.
	dyn.PrependReactor("delete", "vulnerabilityreports",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(
				rk.gvr.GroupResource(), "vr-y",
				fmt.Errorf("rbac pending"))
		})
	if p.deleteOrphanReport(ctx, logr.Discard(), rk,
		sprawlReport(kube.GVRVulnerabilityReport, "VulnerabilityReport",
			"apps", "vr-y", time.Hour, nil)) {
		t.Fatal("forbidden delete must not count as collected")
	}
	// Any other failure — metered once, reported false.
	before := testutil.QueueErrorCount(t, "api-object-sprawl-report-gc")
	dyn.PrependReactor("delete", "vulnerabilityreports",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, fmt.Errorf("apiserver down")
		})
	if p.deleteOrphanReport(ctx, logr.Discard(), rk,
		sprawlReport(kube.GVRVulnerabilityReport, "VulnerabilityReport",
			"apps", "vr-z", time.Hour, nil)) {
		t.Fatal("generic delete failure must report false")
	}
	if got := testutil.QueueErrorCount(t, "api-object-sprawl-report-gc") - before; got != 1 {
		t.Fatalf("delete failure metered %v times, want 1", got)
	}
}
