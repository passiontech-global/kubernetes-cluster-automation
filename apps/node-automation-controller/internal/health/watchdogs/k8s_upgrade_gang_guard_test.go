package watchdogs

import (
	"maps"
	"net/http"
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
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func gangListKinds() map[schema.GroupVersionResource]string {
	kinds := maps.Clone(testutil.DynListKinds())
	kinds[gvrPodGroupV1Alpha2] = "PodGroupList"
	kinds[gvrPodGroupV1Alpha1] = "PodGroupList"
	kinds[gvrKueueWorkload] = "WorkloadList"
	return kinds
}

func TestK8sUpgradeGangGuardDetectionAndPruning(t *testing.T) {
	base := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)

	podGit := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "legacy-pod", UID: "p1"},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{{
				Name:         "repo",
				VolumeSource: corev1.VolumeSource{GitRepo: &corev1.GitRepoVolumeSource{Repository: "https://example.com/r.git"}}, //nolint:staticcheck // testing deprecated gitRepo detection
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	depGit := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "legacy-dep", UID: "d1"},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Volumes: []corev1.Volume{{
						Name:         "repo",
						VolumeSource: corev1.VolumeSource{GitRepo: &corev1.GitRepoVolumeSource{Repository: "https://example.com/r.git"}}, //nolint:staticcheck // testing deprecated gitRepo detection
					}},
				},
			},
		},
	}

	pgStuck := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "scheduling.k8s.io/v1alpha2",
		"kind":       "PodGroup",
		"metadata":   map[string]any{"namespace": "ml", "name": "pg-stuck", "uid": "pg1"},
		"status": map[string]any{
			"conditions": []any{map[string]any{
				"type":               "PodGroupScheduled",
				"status":             "False",
				"reason":             "PreEnqueue",
				"lastTransitionTime": base.Add(-20 * time.Minute).Format(time.RFC3339),
			}},
		},
	}}
	kwStuck := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "kueue.x-k8s.io/v1beta1",
		"kind":       "Workload",
		"metadata":   map[string]any{"namespace": "ml", "name": "wl-stuck", "uid": "kw1"},
		"status": map[string]any{
			"conditions": []any{map[string]any{
				"type":               "QuotaReserved",
				"status":             "False",
				"reason":             "Inadmissible",
				"lastTransitionTime": base.Add(-20 * time.Minute).Format(time.RFC3339),
			}},
		},
	}}
	kwYoung := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "kueue.x-k8s.io/v1beta1",
		"kind":       "Workload",
		"metadata":   map[string]any{"namespace": "ml", "name": "wl-young", "uid": "kw2"},
		"status": map[string]any{
			"conditions": []any{map[string]any{
				"type":               "QuotaReserved",
				"status":             "False",
				"reason":             "Inadmissible",
				"lastTransitionTime": base.Add(-5 * time.Minute).Format(time.RFC3339),
			}},
		},
	}}

	cs := fake.NewSimpleClientset(podGit, depGit)
	dyn := testutil.NewFakeDyn(gangListKinds(), pgStuck, kwStuck, kwYoung)
	p := testProberDyn(cs, dyn)
	chk := probetest.MustCheck[*k8sUpgradeGangGuardCheck](t, p)
	probetest.FreezeNow(p.Deps, base)

	res := probetest.RunCheck(ctx, p.Deps, chk)
	if res.Pass {
		t.Fatalf("expected failure, got pass")
	}
	if strings.Contains(res.Why, "wl-young") {
		t.Fatalf("young Kueue workload should not trigger before 15m: %s", res.Why)
	}
	for _, want := range []struct{ ns, kind, name, reason string }{
		{"apps", "Pod", "legacy-pod", reasonDeprecatedGitRepo},
		{"apps", "Deployment", "legacy-dep", reasonDeprecatedGitRepo},
		{"ml", "PodGroup", "pg-stuck", reasonGangPodGroupStuck},
		{"ml", "Workload", "wl-stuck", reasonKueueWorkloadStuck},
	} {
		if m := probetest.FindMetric(t, "node_automation_k8s_upgrade_gang_issue", map[string]string{
			"namespace": want.ns, "kind": want.kind, "name": want.name, "reason": want.reason,
		}); m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatalf("expected gauge=1 for %+v, got %v", want, m)
		}
	}

	// Resolve all -> pass + pruned gauges.
	_ = cs.CoreV1().Pods("apps").Delete(ctx, "legacy-pod", metav1.DeleteOptions{})
	_ = cs.AppsV1().Deployments("apps").Delete(ctx, "legacy-dep", metav1.DeleteOptions{})
	_ = dyn.Resource(gvrPodGroupV1Alpha2).Namespace("ml").Delete(ctx, "pg-stuck", metav1.DeleteOptions{})
	_ = dyn.Resource(gvrKueueWorkload).Namespace("ml").Delete(ctx, "wl-stuck", metav1.DeleteOptions{})

	probetest.FreezeNow(p.Deps, base.Add(2*time.Minute))
	res2 := probetest.RunCheck(ctx, p.Deps, chk)
	if !res2.Pass {
		t.Fatalf("expected pass after resolution, got %+v", res2)
	}
	if m := probetest.FindMetric(t, "node_automation_k8s_upgrade_gang_issue", map[string]string{
		"namespace": "ml", "kind": "Workload", "name": "wl-stuck", "reason": reasonKueueWorkloadStuck,
	}); m != nil {
		t.Fatalf("expected pruned gauge, got %v", m)
	}
}

func TestK8sUpgradeGangGuardCRDAbsentAnd403Skip(t *testing.T) {
	// Default OpDyn has no PodGroup / Kueue Workload registered -> must skip cleanly without panic/error.
	cs := fake.NewSimpleClientset()
	p := testProber(cs)
	chk := probetest.MustCheck[*k8sUpgradeGangGuardCheck](t, p)
	if res := probetest.RunCheck(ctx, p.Deps, chk); !res.Pass || res.Infra != nil {
		t.Fatalf("expected graceful pass when PodGroup/Workload CRDs absent, got %+v", res)
	}

	// Explicit 404 and 403 on PodGroups/Workloads -> graceful skip.
	dyn := testutil.NewFakeDyn(gangListKinds())
	dyn.PrependReactor("list", "podgroups", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewNotFound(schema.GroupResource{Group: "scheduling.k8s.io", Resource: "podgroups"}, "")
	})
	dyn.PrependReactor("list", "workloads", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, &apierrors.StatusError{ErrStatus: metav1.Status{
			Status: metav1.StatusFailure,
			Code:   http.StatusForbidden,
			Reason: metav1.StatusReasonForbidden,
		}}
	})
	p2 := testProberDyn(cs, dyn)
	chk2 := probetest.MustCheck[*k8sUpgradeGangGuardCheck](t, p2)
	if res := probetest.RunCheck(ctx, p2.Deps, chk2); !res.Pass || res.Infra != nil {
		t.Fatalf("expected graceful pass on 404/403, got %+v", res)
	}
}
