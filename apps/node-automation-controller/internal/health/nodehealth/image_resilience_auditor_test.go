// image_resilience_auditor_test.go — coverage for Wave 4C #14 critical
// workload mutable-image resilience auditor: default/custom namespace filter,
// Deployment/StatefulSet/DaemonSet/standalone Pod auditing, owned/terminal/
// mirror/terminating/exempt skips, InitContainers + Containers, registry
// host:port & @sha256: tag parsing, default PASS vs FAIL_ON_RISK=true, and
// GaugeLedger cleanup on resolution.
package nodehealth

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func TestHasMutableImageTag(t *testing.T) {
	cases := []struct {
		image string
		want  bool
	}{
		{"nginx:1.25.4", false},
		{"localhost:5000/foo:v1.2.3", false},
		{"registry.example.com:8443/team/app:release-42", false},
		{"nginx:latest@sha256:deadbeef", false},
		{"localhost:5000/foo@sha256:deadbeef", false},
		{"nginx", true},
		{"localhost:5000/foo", true},
		{"nginx:latest", true},
		{"ghcr.io/org/app:main", true},
		{"ghcr.io/org/app:master", true},
		{"ghcr.io/org/app:", true},
		{"", false},
	}
	for _, tc := range cases {
		if got := hasMutableImageTag(tc.image); got != tc.want {
			t.Errorf("hasMutableImageTag(%q) = %v, want %v", tc.image, got, tc.want)
		}
	}
}

func TestImageResilienceAuditor_PassiveDefaultAndFailOnRisk(t *testing.T) {
	now := metav1.Now()
	depRisk := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "coredns"},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{{
						Name:            "init-cfg",
						Image:           "ghcr.io/org/init:main",
						ImagePullPolicy: corev1.PullIfNotPresent,
					}},
					Containers: []corev1.Container{{
						Name:            "coredns",
						Image:           "registry.k8s.io/coredns:v1.11.1",
						ImagePullPolicy: corev1.PullAlways,
					}},
				},
			},
		},
	}
	stsExempt := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "flux-system",
			Name:        "source-controller",
			Annotations: map[string]string{kube.AnnoMutableImageExempt: "true"},
		},
		Spec: appsv1.StatefulSetSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:            "ctrl",
						Image:           "ghcr.io/fluxcd/source-controller:latest",
						ImagePullPolicy: corev1.PullAlways,
					}},
				},
			},
		},
	}
	dsTerminating := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "cilium",
			Name:              "cilium-old",
			DeletionTimestamp: &now,
		},
		Spec: appsv1.DaemonSetSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:            "agent",
						Image:           "cilium:latest",
						ImagePullPolicy: corev1.PullAlways,
					}},
				},
			},
		},
	}
	nonCriticalDep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "user-app", Name: "web"},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:            "web",
						Image:           "nginx:latest",
						ImagePullPolicy: corev1.PullAlways,
					}},
				},
			},
		},
	}
	standalonePod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "node-ops", Name: "diag-pod"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:            "diag",
				Image:           "busybox",
				ImagePullPolicy: corev1.PullIfNotPresent,
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	ownedPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       "kube-system",
			Name:            "coredns-abc",
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "coredns-rs", Controller: ptr.To(true)}},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:            "coredns",
				Image:           "nginx:latest",
				ImagePullPolicy: corev1.PullAlways,
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	mirrorPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "kube-system",
			Name:        "kube-apiserver-cp1",
			Annotations: map[string]string{"kubernetes.io/config.mirror": "abc"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:            "apiserver",
				Image:           "kube-apiserver:latest",
				ImagePullPolicy: corev1.PullAlways,
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	terminalPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "done-pod"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:            "job",
				Image:           "alpine:latest",
				ImagePullPolicy: corev1.PullAlways,
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
	}

	t.Run("default pass emits gauge and prunes on recovery", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			depRisk.DeepCopy(), stsExempt.DeepCopy(), dsTerminating.DeepCopy(),
			nonCriticalDep.DeepCopy(), standalonePod.DeepCopy(), ownedPod.DeepCopy(),
			mirrorPod.DeepCopy(), terminalPod.DeepCopy(),
		)
		p := testProber(cs)
		ch := probetest.MustCheck[*imageResilienceAuditorCheck](t, p)
		res := ch.Run(probetest.SweepCtx(ctx, p.Deps))
		if !res.Pass {
			t.Fatalf("default mode must return PASS even with risks, got %+v", res)
		}

		for _, tc := range []struct {
			ns, workload, reason string
			want                 bool
		}{
			{"kube-system", "Deployment/coredns", imageRiskMutableTag, true},
			{"kube-system", "Deployment/coredns", imageRiskPullPolicyAlways, true},
			{"node-ops", "Pod/diag-pod", imageRiskMutableTag, true},
			{"flux-system", "StatefulSet/source-controller", imageRiskMutableTag, false},
			{"cilium", "DaemonSet/cilium-old", imageRiskMutableTag, false},
			{"user-app", "Deployment/web", imageRiskMutableTag, false},
			{"kube-system", "Pod/coredns-abc", imageRiskMutableTag, false},
			{"kube-system", "Pod/kube-apiserver-cp1", imageRiskMutableTag, false},
			{"kube-system", "Pod/done-pod", imageRiskMutableTag, false},
		} {
			v, ok := testutil.GaugeSeriesValue(t, "node_automation_workload_image_resilience_risk",
				map[string]string{"namespace": tc.ns, "workload": tc.workload, "reason": tc.reason})
			if ok != tc.want || (tc.want && v != 1) {
				t.Errorf("gauge(%s, %s, %s) = (%v, %v), want present=%v", tc.ns, tc.workload, tc.reason, v, ok, tc.want)
			}
		}

		// Fix Deployment coredns and verify GaugeLedger deletes stale series.
		fixed := depRisk.DeepCopy()
		fixed.Spec.Template.Spec.InitContainers[0].Image = "ghcr.io/org/init:v1.0.0"
		fixed.Spec.Template.Spec.Containers[0].ImagePullPolicy = corev1.PullIfNotPresent
		if _, err := cs.AppsV1().Deployments("kube-system").Update(ctx, fixed, metav1.UpdateOptions{}); err != nil {
			t.Fatalf("update coredns: %v", err)
		}
		ch.Run(probetest.SweepCtx(ctx, p.Deps))
		if _, ok := testutil.GaugeSeriesValue(t, "node_automation_workload_image_resilience_risk",
			map[string]string{"namespace": "kube-system", "workload": "Deployment/coredns", "reason": imageRiskMutableTag}); ok {
			t.Fatal("stale mutable_tag series not pruned after fix")
		}
		if _, ok := testutil.GaugeSeriesValue(t, "node_automation_workload_image_resilience_risk",
			map[string]string{"namespace": "kube-system", "workload": "Deployment/coredns", "reason": imageRiskPullPolicyAlways}); ok {
			t.Fatal("stale pull_policy_always series not pruned after fix")
		}
	})

	t.Run("custom namespaces and FAIL_ON_RISK=true", func(t *testing.T) {
		t.Setenv("NODE_AUTOMATION_IMAGE_AUDIT_NAMESPACES", "user-app")
		t.Setenv("NODE_AUTOMATION_IMAGE_RESILIENCE_FAIL_ON_RISK", "true")

		dsPinned := &appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: "user-app", Name: "node-agent"},
			Spec: appsv1.DaemonSetSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{
							Name:            "agent",
							Image:           "localhost:5000/agent:v1",
							ImagePullPolicy: corev1.PullIfNotPresent,
						}},
					},
				},
			},
		}
		cs := fake.NewSimpleClientset(depRisk.DeepCopy(), nonCriticalDep.DeepCopy(), dsPinned)
		p := testProber(cs)
		ch := probetest.MustCheck[*imageResilienceAuditorCheck](t, p)
		res := ch.Run(probetest.SweepCtx(ctx, p.Deps))
		if res.Pass {
			t.Fatalf("expected FAIL when FAIL_ON_RISK=true, got PASS")
		}
		if !strings.Contains(res.Why, "user-app/Deployment/web (mutable_tag)") ||
			!strings.Contains(res.Why, "user-app/Deployment/web (pull_policy_always)") {
			t.Fatalf("unexpected Why: %q", res.Why)
		}
		if strings.Contains(res.Why, "kube-system") || strings.Contains(res.Why, "node-agent") {
			t.Fatalf("unexpected non-matching workload in Why: %q", res.Why)
		}
	})

	t.Run("non-controller OwnerReference Pod is flagged as standalone Pod", func(t *testing.T) {
		nonCtrlFalsePod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "kube-system",
				Name:      "cm-owned-false",
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "v1",
					Kind:       "ConfigMap",
					Name:       "some-cm",
					Controller: ptr.To(false),
				}},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:            "tool",
					Image:           "nginx:latest",
					ImagePullPolicy: corev1.PullAlways,
				}},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		}
		nonCtrlNilPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "kube-system",
				Name:      "cm-owned-nil",
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "v1",
					Kind:       "ConfigMap",
					Name:       "other-cm",
				}},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:            "tool",
					Image:           "busybox",
					ImagePullPolicy: corev1.PullIfNotPresent,
				}},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		}

		cs := fake.NewSimpleClientset(nonCtrlFalsePod, nonCtrlNilPod, ownedPod.DeepCopy())
		p := testProber(cs)
		ch := probetest.MustCheck[*imageResilienceAuditorCheck](t, p)
		res := ch.Run(probetest.SweepCtx(ctx, p.Deps))
		if !res.Pass {
			t.Fatalf("default mode must return PASS, got %+v", res)
		}

		for _, tc := range []struct {
			workload, reason string
			want             bool
		}{
			{"Pod/cm-owned-false", imageRiskMutableTag, true},
			{"Pod/cm-owned-false", imageRiskPullPolicyAlways, true},
			{"Pod/cm-owned-nil", imageRiskMutableTag, true},
			{"Pod/coredns-abc", imageRiskMutableTag, false},
			{"Pod/coredns-abc", imageRiskPullPolicyAlways, false},
		} {
			v, ok := testutil.GaugeSeriesValue(t, "node_automation_workload_image_resilience_risk",
				map[string]string{"namespace": "kube-system", "workload": tc.workload, "reason": tc.reason})
			if ok != tc.want || (tc.want && v != 1) {
				t.Errorf("gauge(kube-system, %s, %s) = (%v, %v), want present=%v", tc.workload, tc.reason, v, ok, tc.want)
			}
		}
	})
}
