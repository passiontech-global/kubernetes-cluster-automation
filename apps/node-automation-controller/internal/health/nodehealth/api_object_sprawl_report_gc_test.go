// api_object_sprawl_report_gc_test.go — coverage for the
// api-object-sprawl-report-gc check: dead-owner report GC, census
// gauges and the superseded helm-secret cap.
package nodehealth

import (
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
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
		Type: corev1.SecretType(sprawlHelmSecretType),
	}
}

// sprawlDyn builds a dynamic fake covering the shared CRD table plus
// the argo rollouts kinds the W16-G1 census/GC reads (the shared
// OpDyn table predates them).
func sprawlDyn(objs ...runtime.Object) dynamic.Interface {
	kinds := maps.Clone(testutil.DynListKinds())
	kinds[kube.GVRArgoAnalysisRun] = "AnalysisRunList"
	kinds[kube.GVRArgoExperiment] = "ExperimentList"
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

// W16-G1 — terminal-phase AnalysisRuns past the retention threshold
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

// W16-G1 — the same GC covers Experiments: only the terminal phases
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
