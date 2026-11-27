// orphan_scrape_audit_test.go — unit tests for the orphan scrape CRD auditor
// (VMServiceScrape, VMPodScrape, ServiceMonitor, PodMonitor) inside
// api-object-sprawl-report-gc.
package sprawl

import (
	"fmt"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func scrapeCR(gvr schema.GroupVersionResource, kind, ns, name string,
	age time.Duration, labels, annos map[string]string, owner *metav1.OwnerReference) *unstructured.Unstructured {
	obj := testutil.Unstructured(gvr.GroupVersion().WithKind(kind), ns, name, nil)
	obj.SetCreationTimestamp(metav1.NewTime(time.Now().Add(-age)))
	obj.SetUID(types.UID("uid-" + kind + "-" + ns + "-" + name))
	if labels != nil {
		obj.SetLabels(labels)
	}
	if annos != nil {
		obj.SetAnnotations(annos)
	}
	if owner != nil {
		obj.SetOwnerReferences([]metav1.OwnerReference{*owner})
	}
	return obj
}

// Detect-only default (ORPHAN_SCRAPE_CRD_GC_ENABLED unset/false): unmanaged >7d
// scrape CRDs emit node_automation_orphan_scrape_crd_count{kind,namespace,name}
// without being deleted, while owned, GitOps/Helm/KRO-labeled, and <7d objects
// are ignored.
func TestOrphanScrapeAuditDetectOnlyAndFilters(t *testing.T) {
	const oldAge = 8 * 24 * time.Hour
	const youngAge = 6 * 24 * time.Hour

	orphanVMSvc := scrapeCR(kube.GVRVMServiceScrape, "VMServiceScrape", "monitoring", "orphan-vms", oldAge, nil, nil, nil)
	orphanVMPod := scrapeCR(kube.GVRVMPodScrape, "VMPodScrape", "monitoring", "orphan-vmp", oldAge, nil, nil, nil)
	orphanSM := scrapeCR(kube.GVRServiceMonitor, "ServiceMonitor", "apps", "orphan-sm", oldAge, nil, nil, nil)
	orphanPM := scrapeCR(kube.GVRPodMonitor, "PodMonitor", "apps", "orphan-pm", oldAge, nil, nil, nil)

	// Managed / young objects that MUST be ignored.
	youngOrphan := scrapeCR(kube.GVRVMServiceScrape, "VMServiceScrape", "monitoring", "young-vms", youngAge, nil, nil, nil)
	owned := scrapeCR(kube.GVRVMServiceScrape, "VMServiceScrape", "monitoring", "owned-vms", oldAge, nil, nil, sprawlOwner("VMAgent", "vm"))
	fluxKS := scrapeCR(kube.GVRServiceMonitor, "ServiceMonitor", "apps", "flux-sm", oldAge,
		map[string]string{"kustomize.toolkit.fluxcd.io/name": "infra"}, nil, nil)
	fluxHelm := scrapeCR(kube.GVRServiceMonitor, "ServiceMonitor", "apps", "flux-hr-sm", oldAge,
		map[string]string{"helm.toolkit.fluxcd.io/name": "stack"}, nil, nil)
	managedHelm := scrapeCR(kube.GVRPodMonitor, "PodMonitor", "apps", "helm-pm", oldAge,
		map[string]string{"app.kubernetes.io/managed-by": "Helm"}, nil, nil)
	managedKRO := scrapeCR(kube.GVRVMPodScrape, "VMPodScrape", "apps", "kro-vmp", oldAge,
		map[string]string{"app.kubernetes.io/managed-by": "kro"}, nil, nil)
	managedFlux := scrapeCR(kube.GVRVMServiceScrape, "VMServiceScrape", "apps", "managed-flux", oldAge,
		map[string]string{"app.kubernetes.io/managed-by": "kustomize-controller"}, nil, nil)
	helmLabel := scrapeCR(kube.GVRServiceMonitor, "ServiceMonitor", "apps", "helm-label-sm", oldAge,
		map[string]string{"meta.helm.sh/release-name": "prom"}, nil, nil)
	helmAnno := scrapeCR(kube.GVRServiceMonitor, "ServiceMonitor", "apps", "helm-anno-sm", oldAge,
		nil, map[string]string{"meta.helm.sh/release-name": "prom"}, nil)

	for _, want := range []struct{ kind, ns, name string }{
		{"vmservicescrape", "monitoring", "orphan-vms"},
		{"vmpodscrape", "monitoring", "orphan-vmp"},
		{"servicemonitor", "apps", "orphan-sm"},
		{"podmonitor", "apps", "orphan-pm"},
	} {
		testutil.CleanupMetric(t, orphanScrapeCRDCountGauge, want.kind, want.ns, want.name)
	}

	dyn := sprawlDyn(
		orphanVMSvc, orphanVMPod, orphanSM, orphanPM,
		youngOrphan, owned, fluxKS, fluxHelm, managedHelm, managedKRO, managedFlux, helmLabel, helmAnno,
	)
	p := testProberDyn(fake.NewSimpleClientset(), dyn)
	chk := probetest.MustCheck[*apiObjectSprawlReportGCCheck](t, p)
	if chk.orphanScrapeGCEnabled {
		t.Fatal("ORPHAN_SCRAPE_CRD_GC_ENABLED must default to false")
	}

	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatalf("orphan scrape CRDs must fail the sweep: %+v", res)
	}

	// All 4 unmanaged >7d orphans must emit gauge=1 AND survive (detect-only).
	for _, want := range []struct {
		gvr  schema.GroupVersionResource
		kind string
		ns   string
		name string
	}{
		{kube.GVRVMServiceScrape, "vmservicescrape", "monitoring", "orphan-vms"},
		{kube.GVRVMPodScrape, "vmpodscrape", "monitoring", "orphan-vmp"},
		{kube.GVRServiceMonitor, "servicemonitor", "apps", "orphan-sm"},
		{kube.GVRPodMonitor, "podmonitor", "apps", "orphan-pm"},
	} {
		v, ok := testutil.GaugeSeriesValue(t, "node_automation_orphan_scrape_crd_count",
			map[string]string{"kind": want.kind, "namespace": want.ns, "name": want.name})
		if !ok || v != 1 {
			t.Fatalf("%s %s/%s gauge = %v,%v want 1,true", want.kind, want.ns, want.name, v, ok)
		}
		if _, err := dyn.Resource(want.gvr).Namespace(want.ns).Get(ctx, want.name, metav1.GetOptions{}); err != nil {
			t.Fatalf("detect-only mode must not delete %s/%s: %v", want.ns, want.name, err)
		}
	}

	// Managed and young objects must NOT emit the gauge.
	for _, skip := range []struct{ kind, ns, name string }{
		{"vmservicescrape", "monitoring", "young-vms"},
		{"vmservicescrape", "monitoring", "owned-vms"},
		{"servicemonitor", "apps", "flux-sm"},
		{"servicemonitor", "apps", "flux-hr-sm"},
		{"podmonitor", "apps", "helm-pm"},
		{"vmpodscrape", "apps", "kro-vmp"},
		{"vmservicescrape", "apps", "managed-flux"},
		{"servicemonitor", "apps", "helm-label-sm"},
		{"servicemonitor", "apps", "helm-anno-sm"},
	} {
		if _, ok := testutil.GaugeSeriesValue(t, "node_automation_orphan_scrape_crd_count",
			map[string]string{"kind": skip.kind, "namespace": skip.ns, "name": skip.name}); ok {
			t.Fatalf("managed/young %s %s/%s must not emit orphan scrape gauge", skip.kind, skip.ns, skip.name)
		}
	}
}

// Opt-in GC (ORPHAN_SCRAPE_CRD_GC_ENABLED=true): UID-deletes unmanaged >7d
// scrape CRDs up to the per-sweep cap of 5, oldest first.
func TestOrphanScrapeAuditOptInGCRespectsCapAndUID(t *testing.T) {
	t.Setenv("ORPHAN_SCRAPE_CRD_GC_ENABLED", "true")

	var objs []runtime.Object
	for i := 1; i <= 7; i++ {
		name := fmt.Sprintf("orphan-sm-%d", i)
		// Distinct ages so oldest 5 (1..5) are deterministically chosen.
		age := time.Duration(14-i) * 24 * time.Hour
		objs = append(objs, scrapeCR(kube.GVRServiceMonitor, "ServiceMonitor", "apps", name, age, nil, nil, nil))
		testutil.CleanupMetric(t, orphanScrapeCRDCountGauge, "servicemonitor", "apps", name)
	}
	// Plus one managed object that must survive GC.
	managed := scrapeCR(kube.GVRServiceMonitor, "ServiceMonitor", "apps", "managed-sm",
		12*24*time.Hour, map[string]string{"app.kubernetes.io/managed-by": "Helm"}, nil, nil)
	objs = append(objs, managed)

	dyn := sprawlDyn(objs...).(*dynamicfake.FakeDynamicClient)
	deletedUIDs := map[string]types.UID{}
	dyn.PrependReactor("delete", "servicemonitors", func(action ktesting.Action) (bool, runtime.Object, error) {
		da := action.(ktesting.DeleteAction)
		opts := da.GetDeleteOptions()
		if opts.Preconditions == nil || opts.Preconditions.UID == nil {
			t.Errorf("ServiceMonitor %s deleted without UID precondition", da.GetName())
		} else {
			deletedUIDs[da.GetName()] = *opts.Preconditions.UID
		}
		return false, nil, nil
	})

	p := testProberDyn(fake.NewSimpleClientset(), dyn)
	chk := probetest.MustCheck[*apiObjectSprawlReportGCCheck](t, p)
	if !chk.orphanScrapeGCEnabled {
		t.Fatal("ORPHAN_SCRAPE_CRD_GC_ENABLED=true must enable GC")
	}

	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatalf("sweep with orphan scrape CRDs must report findings: %+v", res)
	}
	if len(deletedUIDs) != orphanScrapeMaxDeletes {
		t.Fatalf("deleted %d orphan scrape CRDs (%v), want cap %d",
			len(deletedUIDs), deletedUIDs, orphanScrapeMaxDeletes)
	}
	for i := 1; i <= 5; i++ {
		name := fmt.Sprintf("orphan-sm-%d", i)
		if got, ok := deletedUIDs[name]; !ok || !strings.Contains(string(got), name) {
			t.Fatalf("expected oldest orphan %s deleted with UID, got %q (ok=%v)", name, got, ok)
		}
	}
	for _, mustStay := range []string{"orphan-sm-6", "orphan-sm-7", "managed-sm"} {
		if _, err := dyn.Resource(kube.GVRServiceMonitor).Namespace("apps").
			Get(ctx, mustStay, metav1.GetOptions{}); err != nil {
			t.Fatalf("%s must survive sweep 1: %v", mustStay, err)
		}
	}
}

// Fail-open when scrape CRDs are absent (404) or RBAC-forbidden (403).
func TestOrphanScrapeAuditFailOpenOnAbsentAndForbidden(t *testing.T) {
	dyn := sprawlDyn().(*dynamicfake.FakeDynamicClient)
	dyn.PrependReactor("list", "vmservicescrapes", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewNotFound(kube.GVRVMServiceScrape.GroupResource(), "")
	})
	dyn.PrependReactor("list", "servicemonitors", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(kube.GVRServiceMonitor.GroupResource(), "", fmt.Errorf("rbac pending"))
	})

	p := testProberDyn(fake.NewSimpleClientset(), dyn)
	chk := probetest.MustCheck[*apiObjectSprawlReportGCCheck](t, p)
	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Infra != nil || !res.Pass {
		t.Fatalf("404/403 on scrape CRDs must fail open and pass, got %+v", res)
	}
}
