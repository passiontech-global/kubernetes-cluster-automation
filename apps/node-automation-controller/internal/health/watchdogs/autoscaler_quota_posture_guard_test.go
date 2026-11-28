package watchdogs

import (
	"errors"
	"maps"
	"strings"
	"testing"

	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func autoscalerPostureTestVPA(ns, name, mode, targetKind, targetName string, controlled []string) *unstructured.Unstructured {
	spec := map[string]any{
		"targetRef": map[string]any{
			"apiVersion": "apps/v1",
			"kind":       targetKind,
			"name":       targetName,
		},
	}
	if mode != "" {
		spec["updatePolicy"] = map[string]any{"updateMode": mode}
	}
	if controlled != nil {
		items := make([]any, 0, len(controlled))
		for _, r := range controlled {
			items = append(items, r)
		}
		spec["resourcePolicy"] = map[string]any{
			"containerPolicies": []any{
				map[string]any{
					"containerName":       "*",
					"controlledResources": items,
				},
			},
		}
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "autoscaling.k8s.io/v1",
		"kind":       "VerticalPodAutoscaler",
		"metadata":   map[string]any{"namespace": ns, "name": name},
		"spec":       spec,
	}}
}

func autoscalerPostureTestScaledObj(ns, name, targetKind, targetName string, triggers ...string) *unstructured.Unstructured {
	trigs := make([]any, 0, len(triggers))
	for _, t := range triggers {
		trigs = append(trigs, map[string]any{"type": t})
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "keda.sh/v1alpha1",
		"kind":       "ScaledObject",
		"metadata":   map[string]any{"namespace": ns, "name": name},
		"spec": map[string]any{
			"scaleTargetRef": map[string]any{
				"kind": targetKind,
				"name": targetName,
			},
			"triggers": trigs,
		},
	}}
}

func TestAutoscalerQuotaPostureGuardVPAConflicts(t *testing.T) {
	t.Run("VPA Off and Initial skipped, VPA Auto + HPA CPU flagged, custom-metric-only NOT flagged", func(t *testing.T) {
		vpaOff := autoscalerPostureTestVPA("app", "vpa-off", "Off", "Deployment", "web-off", nil)
		vpaInitial := autoscalerPostureTestVPA("app", "vpa-init", "Initial", "Deployment", "web-init", nil)
		vpaAutoCPU := autoscalerPostureTestVPA("app", "vpa-auto", "Auto", "Deployment", "web-cpu", nil)
		vpaCustom := autoscalerPostureTestVPA("app", "vpa-custom", "Auto", "Deployment", "web-custom", nil)
		vpaMemOnly := autoscalerPostureTestVPA("app", "vpa-mem", "Recreate", "StatefulSet", "db", []string{"memory"})

		hpaOff := &autoscalingv2.HorizontalPodAutoscaler{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "hpa-off"},
			Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
				ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{Kind: "Deployment", Name: "web-off"},
				Metrics: []autoscalingv2.MetricSpec{{
					Type:     autoscalingv2.ResourceMetricSourceType,
					Resource: &autoscalingv2.ResourceMetricSource{Name: corev1.ResourceCPU},
				}},
			},
		}
		hpaInit := &autoscalingv2.HorizontalPodAutoscaler{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "hpa-init"},
			Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
				ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{Kind: "Deployment", Name: "web-init"},
				Metrics: []autoscalingv2.MetricSpec{{
					Type:     autoscalingv2.ResourceMetricSourceType,
					Resource: &autoscalingv2.ResourceMetricSource{Name: corev1.ResourceMemory},
				}},
			},
		}
		hpaCPU := &autoscalingv2.HorizontalPodAutoscaler{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "hpa-cpu"},
			Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
				ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{Kind: "Deployment", Name: "web-cpu"},
				Metrics: []autoscalingv2.MetricSpec{{
					Type:     autoscalingv2.ResourceMetricSourceType,
					Resource: &autoscalingv2.ResourceMetricSource{Name: corev1.ResourceCPU},
				}},
			},
		}
		hpaCustom := &autoscalingv2.HorizontalPodAutoscaler{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "hpa-custom"},
			Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
				ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{Kind: "Deployment", Name: "web-custom"},
				Metrics: []autoscalingv2.MetricSpec{{
					Type: autoscalingv2.PodsMetricSourceType,
					Pods: &autoscalingv2.PodsMetricSource{Metric: autoscalingv2.MetricIdentifier{Name: "http_requests_per_second"}},
				}},
			},
		}
		// Mem-only VPA + CPU-only HPA -> NO overlap -> NOT flagged.
		hpaCPUForMemVPA := &autoscalingv2.HorizontalPodAutoscaler{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "hpa-db-cpu"},
			Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
				ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{Kind: "StatefulSet", Name: "db"},
				Metrics: []autoscalingv2.MetricSpec{{
					Type:     autoscalingv2.ResourceMetricSourceType,
					Resource: &autoscalingv2.ResourceMetricSource{Name: corev1.ResourceCPU},
				}},
			},
		}

		kinds := maps.Clone(testutil.DynListKinds())
		kinds[autoscalerPostureVPAGVR] = "VerticalPodAutoscalerList"
		dyn := testutil.NewFakeDyn(kinds, vpaOff, vpaInitial, vpaAutoCPU, vpaCustom, vpaMemOnly)
		cs := fake.NewSimpleClientset(hpaOff, hpaInit, hpaCPU, hpaCustom, hpaCPUForMemVPA)
		p := probetest.NewCheckProber(cs, dyn, NewAutoscalerQuotaPostureGuardCheck)
		chk := probetest.MustCheck[*autoscalerPostureCheck](t, p)

		res := probetest.RunCheck(ctx, chk.Deps, chk)
		if res.Pass {
			t.Fatal("expected FAIL for VPA Auto + HPA CPU conflict")
		}
		if !strings.Contains(res.Why, "VPA app/vpa-auto + HPA hpa-cpu on Deployment/web-cpu (cpu)") {
			t.Fatalf("unexpected Why: %s", res.Why)
		}
		if strings.Contains(res.Why, "vpa-off") || strings.Contains(res.Why, "vpa-init") ||
			strings.Contains(res.Why, "vpa-custom") || strings.Contains(res.Why, "vpa-mem") {
			t.Fatalf("non-conflicting VPAs should not appear in Why: %s", res.Why)
		}
		if m := probetest.FindMetric(t, "node_automation_vpa_hpa_conflict", map[string]string{
			"namespace": "app", "vpa": "vpa-auto", "autoscaler_kind": "HorizontalPodAutoscaler",
			"autoscaler": "hpa-cpu", "target": "Deployment/web-cpu",
		}); m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatalf("expected vpa_hpa_conflict=1, got %v", m)
		}
		evs, _ := cs.EventsV1().Events("app").List(ctx, metav1.ListOptions{})
		if len(evs.Items) != 1 || evs.Items[0].Reason != autoscalerPostureEventReasonConflict {
			t.Fatalf("expected 1 AutoscalerConflict event, got %+v", evs.Items)
		}
	})

	t.Run("KEDA cpu trigger + VPA flagged, prometheus trigger skipped", func(t *testing.T) {
		vpaCPU := autoscalerPostureTestVPA("keda-ns", "vpa-worker", "InPlaceOrRecreate", "Deployment", "worker", []string{})
		vpaProm := autoscalerPostureTestVPA("keda-ns", "vpa-queue", "", "Deployment", "queue-worker", nil)
		soCPU := autoscalerPostureTestScaledObj("keda-ns", "so-worker", "Deployment", "worker", "cpu")
		soProm := autoscalerPostureTestScaledObj("keda-ns", "so-queue", "Deployment", "queue-worker", "prometheus")

		kinds := maps.Clone(testutil.DynListKinds())
		kinds[autoscalerPostureVPAGVR] = "VerticalPodAutoscalerList"
		dyn := testutil.NewFakeDyn(kinds, vpaCPU, vpaProm, soCPU, soProm)
		cs := fake.NewSimpleClientset()
		p := probetest.NewCheckProber(cs, dyn, NewAutoscalerQuotaPostureGuardCheck)
		chk := probetest.MustCheck[*autoscalerPostureCheck](t, p)

		res := probetest.RunCheck(ctx, chk.Deps, chk)
		if res.Pass {
			t.Fatal("expected FAIL for VPA + KEDA cpu trigger conflict")
		}
		if !strings.Contains(res.Why, "VPA keda-ns/vpa-worker + ScaledObject so-worker on Deployment/worker (cpu)") {
			t.Fatalf("unexpected Why: %s", res.Why)
		}
		if strings.Contains(res.Why, "so-queue") {
			t.Fatalf("KEDA prometheus trigger must not conflict: %s", res.Why)
		}
	})
}

func TestAutoscalerQuotaPostureGuardResourceQuotaWithoutLimitRange(t *testing.T) {
	nsMissing := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "team-a"},
		Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
	}
	nsWithLR := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "team-b"},
		Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
	}
	nsTerm := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "team-dead"},
		Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating},
	}
	nsSys := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-system"},
		Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
	}

	rqTeamA := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "compute-quota"},
		Spec: corev1.ResourceQuotaSpec{
			Hard: corev1.ResourceList{
				corev1.ResourceRequestsCPU: resource.MustParse("4"),
			},
		},
	}
	rqTeamB := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-b", Name: "compute-quota"},
		Spec: corev1.ResourceQuotaSpec{
			Hard: corev1.ResourceList{
				corev1.ResourceLimitsMemory: resource.MustParse("8Gi"),
			},
		},
	}
	lrTeamB := &corev1.LimitRange{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-b", Name: "defaults"},
		Spec: corev1.LimitRangeSpec{
			Limits: []corev1.LimitRangeItem{{
				Type: corev1.LimitTypeContainer,
				DefaultRequest: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("100m"),
					corev1.ResourceMemory: resource.MustParse("128Mi"),
				},
			}},
		},
	}
	// Non-compute ResourceQuota (pods only) without LimitRange -> NOT flagged.
	rqPodsOnly := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-b", Name: "pods-only"},
		Spec: corev1.ResourceQuotaSpec{
			Hard: corev1.ResourceList{corev1.ResourcePods: resource.MustParse("50")},
		},
	}
	rqTerm := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-dead", Name: "compute-quota"},
		Spec: corev1.ResourceQuotaSpec{
			Hard: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2")},
		},
	}
	rqSys := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "sys-quota"},
		Spec: corev1.ResourceQuotaSpec{
			Hard: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("4Gi")},
		},
	}

	kinds := maps.Clone(testutil.DynListKinds())
	kinds[autoscalerPostureVPAGVR] = "VerticalPodAutoscalerList"
	dyn := testutil.NewFakeDyn(kinds)
	cs := fake.NewSimpleClientset(nsMissing, nsWithLR, nsTerm, nsSys, rqTeamA, rqTeamB, lrTeamB, rqPodsOnly, rqTerm, rqSys)
	p := probetest.NewCheckProber(cs, dyn, NewAutoscalerQuotaPostureGuardCheck)
	chk := probetest.MustCheck[*autoscalerPostureCheck](t, p)

	res := probetest.RunCheck(ctx, chk.Deps, chk)
	if res.Pass {
		t.Fatal("expected FAIL for team-a ResourceQuota without LimitRange")
	}
	if !strings.Contains(res.Why, "ResourceQuota team-a/compute-quota") {
		t.Fatalf("unexpected Why: %s", res.Why)
	}
	if strings.Contains(res.Why, "team-b") || strings.Contains(res.Why, "team-dead") || strings.Contains(res.Why, "kube-system") {
		t.Fatalf("unexpected namespaces flagged in Why: %s", res.Why)
	}
	if m := probetest.FindMetric(t, "node_automation_quota_without_limitrange", map[string]string{
		"namespace": "team-a", "quota": "compute-quota",
	}); m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("expected quota_without_limitrange=1 for team-a, got %v", m)
	}

	// Add LimitRange to team-a -> PASS and stale gauge pruned.
	_, err := cs.CoreV1().LimitRanges("team-a").Create(ctx, &corev1.LimitRange{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "defaults"},
		Spec: corev1.LimitRangeSpec{
			Limits: []corev1.LimitRangeItem{{
				Type: corev1.LimitTypeContainer,
				Default: corev1.ResourceList{
					corev1.ResourceCPU: resource.MustParse("500m"),
				},
			}},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	res2 := probetest.RunCheck(ctx, chk.Deps, chk)
	if !res2.Pass {
		t.Fatalf("expected PASS after LimitRange added to team-a, got %+v", res2)
	}
	if m := probetest.FindMetric(t, "node_automation_quota_without_limitrange", map[string]string{
		"namespace": "team-a", "quota": "compute-quota",
	}); m != nil {
		t.Fatalf("stale quota gauge not pruned: %v", m)
	}
}

func TestAutoscalerQuotaPostureGuard403And404Skip(t *testing.T) {
	// Missing VPA CRD (404) + 403 on ResourceQuotas -> graceful Pass with nil Infra.
	kinds := maps.Clone(testutil.DynListKinds())
	kinds[autoscalerPostureVPAGVR] = "VerticalPodAutoscalerList"
	dyn := testutil.NewFakeDyn(kinds)
	dyn.PrependReactor("list", "verticalpodautoscalers", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewNotFound(schema.GroupResource{Group: "autoscaling.k8s.io", Resource: "verticalpodautoscalers"}, "")
	})
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "resourcequotas", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "resourcequotas"}, "", errors.New("forbidden"))
	})

	p := probetest.NewCheckProber(cs, dyn, NewAutoscalerQuotaPostureGuardCheck)
	chk := probetest.MustCheck[*autoscalerPostureCheck](t, p)

	res := probetest.RunCheck(ctx, chk.Deps, chk)
	if !res.Pass || res.Infra != nil {
		t.Fatalf("expected PASS with nil Infra on 404/403 skip, got %+v", res)
	}
}

func TestAutoscalerQuotaPostureGuardScopesAndKEDAMemUtil(t *testing.T) {
	// BestEffort and Terminating scoped ResourceQuotas must NOT require LimitRange.
	rqBestEffort := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{Namespace: "batch", Name: "be-quota"},
		Spec: corev1.ResourceQuotaSpec{
			Scopes: []corev1.ResourceQuotaScope{corev1.ResourceQuotaScopeBestEffort},
			Hard:   corev1.ResourceList{corev1.ResourceRequestsCPU: resource.MustParse("1")},
		},
	}
	rqTerm := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{Namespace: "batch", Name: "term-quota"},
		Spec: corev1.ResourceQuotaSpec{
			Scopes: []corev1.ResourceQuotaScope{corev1.ResourceQuotaScopeTerminating},
			Hard:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("2Gi")},
		},
	}

	// VPA + KEDA memory-utilization trigger conflict.
	vpaMem := autoscalerPostureTestVPA("keda-ns", "vpa-mem", "Auto", "Deployment", "mem-worker", nil)
	soMemUtil := autoscalerPostureTestScaledObj("keda-ns", "so-mem", "Deployment", "mem-worker", "memory-utilization")

	kinds := maps.Clone(testutil.DynListKinds())
	kinds[autoscalerPostureVPAGVR] = "VerticalPodAutoscalerList"
	dyn := testutil.NewFakeDyn(kinds, vpaMem, soMemUtil)
	cs := fake.NewSimpleClientset(rqBestEffort, rqTerm)
	p := probetest.NewCheckProber(cs, dyn, NewAutoscalerQuotaPostureGuardCheck)
	chk := probetest.MustCheck[*autoscalerPostureCheck](t, p)

	res := probetest.RunCheck(ctx, chk.Deps, chk)
	if res.Pass {
		t.Fatal("expected FAIL for VPA + KEDA memory-utilization conflict")
	}
	if strings.Contains(res.Why, "batch/") {
		t.Fatalf("BestEffort/Terminating ResourceQuota falsely flagged: %s", res.Why)
	}
	if !strings.Contains(res.Why, "VPA keda-ns/vpa-mem + ScaledObject so-mem on Deployment/mem-worker (memory)") {
		t.Fatalf("missing memory-utilization conflict in Why: %s", res.Why)
	}
}
