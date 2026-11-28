package watchdogs

import (
	"net/http"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	nodev1 "k8s.io/api/node/v1"
	schedulingv1 "k8s.io/api/scheduling/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

func TestWorkloadDanglingRefsGuardDetectionAndCadence(t *testing.T) {
	base := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)

	depMissing := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "api", UID: "dep-1"},
		Spec: appsv1.DeploymentSpec{
			Replicas: new(int32(2)),
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					ServiceAccountName: "missing-sa",
					PriorityClassName:  "missing-pc",
					RuntimeClassName:   new("missing-rc"),
					Containers: []corev1.Container{{
						Name: "app",
						EnvFrom: []corev1.EnvFromSource{
							{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "missing-cm"}}},
							{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "opt-sec"}, Optional: new(true)}},
						},
						Env: []corev1.EnvVar{{
							Name: "TOK",
							ValueFrom: &corev1.EnvVarSource{
								SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "missing-sec"}},
							},
						}},
					}},
					Volumes: []corev1.Volume{
						{Name: "opt-vol", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "opt-cm"}, Optional: new(true)}}},
						{Name: "ok-vol", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "ok-cm"}}}},
					},
				},
			},
		},
	}

	// Downscaled deployment + suspended cronjob must be skipped.
	depZero := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "apps",
			Name:        "sleepy",
			Annotations: map[string]string{"downscaler/uptime": "Mon-Fri 08:00-18:00"},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: new(int32(0)),
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: "gone-sa"}},
		},
	}
	cjSuspended := &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "paused"},
		Spec: batchv1.CronJobSpec{
			Suspend: new(true),
			JobTemplate: batchv1.JobTemplateSpec{
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: "gone-sa"}},
				},
			},
		},
	}

	okCM := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "ok-cm"}}
	okPC := &schedulingv1.PriorityClass{ObjectMeta: metav1.ObjectMeta{Name: "ok-pc"}, Value: 100}
	okRC := &nodev1.RuntimeClass{ObjectMeta: metav1.ObjectMeta{Name: "ok-rc"}, Handler: "runc"}

	cs := fake.NewSimpleClientset(depMissing, depZero, cjSuspended, okCM, okPC, okRC)
	p := testProber(cs)
	chk := probetest.MustCheck[*workloadDanglingRefsGuardCheck](t, p)
	probetest.FreezeNow(p.Deps, base)

	// Cycle 1: runs heavy scan.
	res1 := probetest.RunCheck(ctx, p.Deps, chk)
	if res1.Pass {
		t.Fatalf("expected failure for missing refs, got pass")
	}
	for _, refKind := range []string{"ServiceAccount", "PriorityClass", "RuntimeClass", "ConfigMap", "Secret"} {
		if m := probetest.FindMetric(t, "node_automation_workload_dangling_ref", map[string]string{
			"namespace": "apps", "kind": "Deployment", "name": "api", "ref_kind": refKind,
		}); m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatalf("expected dangling ref gauge for %s, got %v", refKind, m)
		}
	}
	if strings.Contains(res1.Why, "opt-cm") || strings.Contains(res1.Why, "opt-sec") ||
		strings.Contains(res1.Why, "ok-cm") || strings.Contains(res1.Why, "sleepy") || strings.Contains(res1.Why, "paused") {
		t.Fatalf("unexpected optional/ok/downscaled workload in Why: %s", res1.Why)
	}

	// Cycle 2..HeavyScanCycles: carries findings/gauges forward without re-listing.
	listCalls := 0
	cs.PrependReactor("list", "deployments", func(ktesting.Action) (bool, runtime.Object, error) {
		listCalls++
		return false, nil, nil
	})
	res2 := probetest.RunCheck(ctx, p.Deps, chk)
	if res2.Pass || res2.Why != res1.Why || listCalls != 0 {
		t.Fatalf("cycle 2 expected carried verdict with 0 deployment lists: res2=%+v listCalls=%d", res2, listCalls)
	}

	// Fix missing refs, advance to next heavy cycle (HeavyScanCycles+1) -> pass + gauges pruned.
	_ = cs.CoreV1().ConfigMaps("apps").Delete(ctx, "ok-cm", metav1.DeleteOptions{})
	_, _ = cs.CoreV1().ConfigMaps("apps").Create(ctx, okCM, metav1.CreateOptions{})
	_, _ = cs.CoreV1().ConfigMaps("apps").Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "missing-cm"}}, metav1.CreateOptions{})
	_, _ = cs.CoreV1().Secrets("apps").Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "missing-sec"}}, metav1.CreateOptions{})
	_, _ = cs.CoreV1().ServiceAccounts("apps").Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "missing-sa"}}, metav1.CreateOptions{})
	_, _ = cs.SchedulingV1().PriorityClasses().Create(ctx, &schedulingv1.PriorityClass{ObjectMeta: metav1.ObjectMeta{Name: "missing-pc"}, Value: 10}, metav1.CreateOptions{})
	_, _ = cs.NodeV1().RuntimeClasses().Create(ctx, &nodev1.RuntimeClass{ObjectMeta: metav1.ObjectMeta{Name: "missing-rc"}, Handler: "runc"}, metav1.CreateOptions{})

	for i := 2; i < probefw.HeavyScanCycles; i++ {
		_ = probetest.RunCheck(ctx, p.Deps, chk)
	}
	resHeavy := probetest.RunCheck(ctx, p.Deps, chk)
	if !resHeavy.Pass || listCalls == 0 {
		t.Fatalf("expected pass on next heavy cycle after fixes (listCalls=%d), got %+v", listCalls, resHeavy)
	}
	if m := probetest.FindMetric(t, "node_automation_workload_dangling_ref", map[string]string{
		"namespace": "apps", "kind": "Deployment", "name": "api", "ref_kind": "ConfigMap",
	}); m != nil {
		t.Fatalf("expected pruned ConfigMap gauge, got %v", m)
	}
}

func TestWorkloadDanglingRefsGuardForbidden403Skip(t *testing.T) {
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "api"},
		Spec: appsv1.DeploymentSpec{
			Replicas: new(int32(1)),
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name: "app",
						EnvFrom: []corev1.EnvFromSource{
							{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "sec-a"}}},
						},
					}},
				},
			},
		},
	}
	cs := fake.NewSimpleClientset(dep)
	cs.PrependReactor("list", "secrets", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, &apierrors.StatusError{ErrStatus: metav1.Status{
			Status: metav1.StatusFailure,
			Code:   http.StatusForbidden,
			Reason: metav1.StatusReasonForbidden,
		}}
	})
	p := testProber(cs)
	chk := probetest.MustCheck[*workloadDanglingRefsGuardCheck](t, p)
	res := probetest.RunCheck(ctx, p.Deps, chk)
	if !res.Pass || res.Infra != nil {
		t.Fatalf("expected graceful pass on 403 secrets list, got %+v", res)
	}
}
