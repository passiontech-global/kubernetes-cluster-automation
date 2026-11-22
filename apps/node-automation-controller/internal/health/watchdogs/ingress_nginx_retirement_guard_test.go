package watchdogs

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	ptestutil "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	typednetworkingv1 "k8s.io/client-go/kubernetes/typed/networking/v1"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

func TestIngressNginxRetirementGuardAutoSkipAndNegatives(t *testing.T) {
	base := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	delAt := metav1.NewTime(base.Add(-time.Minute))
	traefikClass := "traefik"
	nginxClass := "nginx"

	cases := []struct {
		name string
		objs []runtime.Object
	}{
		{name: "empty cluster auto-skips cleanly"},
		{
			name: "plain nginx and nginxinc pods are not flagged",
			objs: []runtime.Object{
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "nginx-web", Labels: map[string]string{"app": "nginx"}},
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "nginx", Image: "nginx:1.27.3"}}},
					Status:     corev1.PodStatus{Phase: corev1.PodRunning},
				},
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ingress", Name: "nginxinc", Labels: map[string]string{"app": "nginx-ingress"}},
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "ic", Image: "nginx/nginx-ingress:3.7.0"}}},
					Status:     corev1.PodStatus{Phase: corev1.PodRunning},
				},
			},
		},
		{
			name: "terminating, completed, and non-controller helper pods are ignored",
			objs: []runtime.Object{
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ingress-nginx", Name: "term-ctrl", DeletionTimestamp: &delAt,
						Labels: map[string]string{"app.kubernetes.io/name": "ingress-nginx"},
					},
					Status: corev1.PodStatus{Phase: corev1.PodRunning},
				},
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ingress-nginx", Name: "admission-create",
						Labels: map[string]string{"app.kubernetes.io/name": "ingress-nginx", "app.kubernetes.io/component": "admission-webhook"},
					},
					Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
				},
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ingress-nginx", Name: "default-backend",
						Labels: map[string]string{"app.kubernetes.io/name": "ingress-nginx", "app.kubernetes.io/component": "default-backend"},
					},
					Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "backend", Image: "registry.k8s.io/defaultbackend-amd64:1.5"}}},
					Status: corev1.PodStatus{Phase: corev1.PodRunning},
				},
			},
		},
		{
			name: "non-ingress-nginx IngressClass and Ingress (incl. nginx owned by another controller) pass",
			objs: []runtime.Object{
				&networkingv1.IngressClass{
					ObjectMeta: metav1.ObjectMeta{Name: "traefik"},
					Spec:       networkingv1.IngressClassSpec{Controller: "traefik.io/ingress-controller"},
				},
				&networkingv1.IngressClass{
					ObjectMeta: metav1.ObjectMeta{Name: "nginx"},
					Spec:       networkingv1.IngressClassSpec{Controller: "nginx.org/ingress-controller"},
				},
				&networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:   "apps",
						Name:        "api",
						Annotations: map[string]string{legacyIngressClassAnnotation: "nginx"},
					},
					Spec: networkingv1.IngressSpec{IngressClassName: &traefikClass},
				},
				&networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web"},
					Spec:       networkingv1.IngressSpec{IngressClassName: &nginxClass},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ingressNginxDetectedGauge.Reset()
			cs := fake.NewSimpleClientset(tc.objs...)
			p := testProber(cs)
			probetest.FreezeNow(p.Deps, base)
			chk := probetest.MustCheck[*ingressNginxRetirementGuardCheck](t, p)

			sctx := probetest.SweepCtx(ctx, chk.Deps)
			res := chk.Run(sctx)
			probetest.VerifySweep(sctx)
			if !res.Pass || res.Infra != nil {
				t.Fatalf("Run = %+v, want Pass=true Infra=nil", res)
			}
		})
	}
}

func TestIngressNginxRetirementGuardDetectionEventsAndPruning(t *testing.T) {
	base := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	ingressNginxDetectedGauge.Reset()

	customIC := "nginx-internal"
	objs := []runtime.Object{
		// Pod 1: matched by app.kubernetes.io/name + component=controller
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "ingress-nginx", Name: "ctrl-lbl", UID: "pod-u1",
				Labels: map[string]string{"app.kubernetes.io/name": "ingress-nginx", "app.kubernetes.io/component": "controller"},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		},
		// Pod 2: matched by app=ingress-nginx
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "ingress-nginx", Name: "ctrl-app", UID: "pod-u2",
				Labels: map[string]string{"app": "ingress-nginx"},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		},
		// Pod 3: matched by container image
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "ctrl-img", UID: "pod-u3"},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{
				Name:  "controller",
				Image: "registry.k8s.io/ingress-nginx/controller:v1.11.2",
			}}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		},
		// Default IngressClass with k8s.io/ingress-nginx
		&networkingv1.IngressClass{
			ObjectMeta: metav1.ObjectMeta{
				Name:        customIC,
				UID:         types.UID("ic-u1"),
				Annotations: map[string]string{networkingv1.AnnotationIsDefaultIngressClass: "true"},
			},
			Spec: networkingv1.IngressClassSpec{Controller: ingressNginxControllerName},
		},
		// Ingress 1: explicit spec.ingressClassName -> nginx-internal
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "ing-class", UID: "ing-u1"},
			Spec:       networkingv1.IngressSpec{IngressClassName: &customIC},
		},
		// Ingress 2: legacy annotation "nginx" (no non-nginx class owns "nginx")
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "apps", Name: "ing-legacy", UID: "ing-u2",
				Annotations: map[string]string{legacyIngressClassAnnotation: "nginx"},
			},
		},
		// Ingress 3: unset class falls back to default ingress-nginx IngressClass
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "ing-default", UID: "ing-u3"},
		},
	}

	cs := fake.NewSimpleClientset(objs...)
	p := testProber(cs)
	probetest.FreezeNow(p.Deps, base)
	chk := probetest.MustCheck[*ingressNginxRetirementGuardCheck](t, p)

	sctx := probetest.SweepCtx(ctx, chk.Deps)
	res := chk.Run(sctx)
	probetest.VerifySweep(sctx)
	if res.Pass || res.Infra != nil {
		t.Fatalf("Run = %+v, want Pass=false Infra=nil", res)
	}

	wantSeries := [][3]string{
		{"Pod", "ingress-nginx", "ctrl-lbl"},
		{"Pod", "ingress-nginx", "ctrl-app"},
		{"Pod", "kube-system", "ctrl-img"},
		{"IngressClass", "", customIC},
		{"Ingress", "apps", "ing-class"},
		{"Ingress", "apps", "ing-legacy"},
		{"Ingress", "apps", "ing-default"},
	}
	for _, lv := range wantSeries {
		if v := ptestutil.ToFloat64(ingressNginxDetectedGauge.WithLabelValues(lv[0], lv[1], lv[2])); v != 1 {
			t.Fatalf("gauge %v = %v, want 1", lv, v)
		}
	}

	// Verify cluster-scoped IngressClass event landed in "default" namespace.
	defEvs, err := cs.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
	if err != nil || len(defEvs.Items) != 1 || defEvs.Items[0].Reason != ingressNginxEventReason ||
		defEvs.Items[0].Regarding.Kind != "IngressClass" {
		t.Fatalf("default namespace IngressClass events = %+v (err=%v)", defEvs.Items, err)
	}
	appsEvs, _ := cs.EventsV1().Events("apps").List(ctx, metav1.ListOptions{})
	if len(appsEvs.Items) != 3 {
		t.Fatalf("apps namespace Ingress events = %d, want 3", len(appsEvs.Items))
	}

	// Cooldown suppresses duplicate events within 6h.
	probetest.FreezeNow(p.Deps, base.Add(time.Hour))
	sctx2 := probetest.SweepCtx(ctx, chk.Deps)
	_ = chk.Run(sctx2)
	probetest.VerifySweep(sctx2)
	defEvs2, _ := cs.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
	if len(defEvs2.Items) != 1 {
		t.Fatalf("expected cooldown dedup on default events, got %d", len(defEvs2.Items))
	}

	// After 6h cooldown expires, events fire again.
	probetest.FreezeNow(p.Deps, base.Add(ingressNginxEventCooldown))
	sctx3 := probetest.SweepCtx(ctx, chk.Deps)
	_ = chk.Run(sctx3)
	probetest.VerifySweep(sctx3)
	defEvs3, _ := cs.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
	if len(defEvs3.Items) != 2 {
		t.Fatalf("expected 2nd event after 6h cooldown, got %d", len(defEvs3.Items))
	}

	// Delete all detected resources -> Pass=true and gauges pruned back to 0.
	_ = cs.CoreV1().Pods("ingress-nginx").Delete(ctx, "ctrl-lbl", metav1.DeleteOptions{})
	_ = cs.CoreV1().Pods("ingress-nginx").Delete(ctx, "ctrl-app", metav1.DeleteOptions{})
	_ = cs.CoreV1().Pods("kube-system").Delete(ctx, "ctrl-img", metav1.DeleteOptions{})
	_ = cs.NetworkingV1().IngressClasses().Delete(ctx, customIC, metav1.DeleteOptions{})
	_ = cs.NetworkingV1().Ingresses("apps").Delete(ctx, "ing-class", metav1.DeleteOptions{})
	_ = cs.NetworkingV1().Ingresses("apps").Delete(ctx, "ing-legacy", metav1.DeleteOptions{})
	_ = cs.NetworkingV1().Ingresses("apps").Delete(ctx, "ing-default", metav1.DeleteOptions{})
	p.InvalidatePods(ctx)

	sctx4 := probetest.SweepCtx(ctx, chk.Deps)
	res4 := chk.Run(sctx4)
	probetest.VerifySweep(sctx4)
	if !res4.Pass || res4.Infra != nil {
		t.Fatalf("post-cleanup Run = %+v, want Pass=true Infra=nil", res4)
	}
	for _, lv := range wantSeries {
		if v := ptestutil.ToFloat64(ingressNginxDetectedGauge.WithLabelValues(lv[0], lv[1], lv[2])); v != 0 {
			t.Fatalf("pruned gauge %v = %v, want 0", lv, v)
		}
	}
}

func TestIngressNginxRetirementGuardErrorsAnd403(t *testing.T) {
	base := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)

	t.Run("403 and 404 skip gracefully and carry held gauge tuples", func(t *testing.T) {
		for _, errCase := range []struct {
			name string
			err  error
		}{
			{
				name: "403 Forbidden",
				err:  apierrors.NewForbidden(schema.GroupResource{Group: "networking.k8s.io", Resource: "ingressclasses"}, "", errors.New("forbidden")),
			},
			{
				name: "404 NotFound",
				err:  apierrors.NewNotFound(schema.GroupResource{Group: "networking.k8s.io", Resource: "ingressclasses"}, ""),
			},
		} {
			t.Run(errCase.name, func(t *testing.T) {
				ingressNginxDetectedGauge.Reset()
				ic := &networkingv1.IngressClass{
					ObjectMeta: metav1.ObjectMeta{Name: "nginx"},
					Spec:       networkingv1.IngressClassSpec{Controller: ingressNginxControllerName},
				}
				ing := &networkingv1.Ingress{
					ObjectMeta: metav1.ObjectMeta{
						Namespace:   "apps",
						Name:        "ing-1",
						Annotations: map[string]string{legacyIngressClassAnnotation: "nginx"},
					},
				}
				cs := fake.NewSimpleClientset(ic, ing)
				p := testProber(cs)
				probetest.FreezeNow(p.Deps, base)
				chk := probetest.MustCheck[*ingressNginxRetirementGuardCheck](t, p)

				// First sweep populates gauge ledger for IngressClass and Ingress.
				sctx1 := probetest.SweepCtx(ctx, chk.Deps)
				res1 := chk.Run(sctx1)
				probetest.VerifySweep(sctx1)
				if res1.Pass {
					t.Fatal("expected initial sweep to detect resources")
				}

				// Now inject 403/404 on both IngressClass and Ingress lists -> Pass=true, Infra=nil, held gauges carried.
				cs.PrependReactor("list", "ingressclasses", func(ktesting.Action) (bool, runtime.Object, error) {
					return true, nil, errCase.err
				})
				cs.PrependReactor("list", "ingresses", func(ktesting.Action) (bool, runtime.Object, error) {
					return true, nil, errCase.err
				})
				sctx2 := probetest.SweepCtx(ctx, chk.Deps)
				res2 := chk.Run(sctx2)
				probetest.VerifySweep(sctx2)
				if !res2.Pass || res2.Infra != nil {
					t.Fatalf("skipped 403/404 Run = %+v, want Pass=true Infra=nil", res2)
				}
				if v := ptestutil.ToFloat64(ingressNginxDetectedGauge.WithLabelValues("IngressClass", "", "nginx")); v != 1 {
					t.Fatalf("held IngressClass gauge dropped on 403/404: %v", v)
				}
				if v := ptestutil.ToFloat64(ingressNginxDetectedGauge.WithLabelValues("Ingress", "apps", "ing-1")); v != 1 {
					t.Fatalf("held Ingress gauge dropped on 403/404: %v", v)
				}
			})
		}
	})

	t.Run("non-403/404 list errors record InfraErr and preserve held tuples", func(t *testing.T) {
		ingressNginxDetectedGauge.Reset()
		ic := &networkingv1.IngressClass{
			ObjectMeta: metav1.ObjectMeta{Name: "nginx"},
			Spec:       networkingv1.IngressClassSpec{Controller: ingressNginxControllerName},
		}
		cs := fake.NewSimpleClientset(ic)
		p := testProber(cs)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*ingressNginxRetirementGuardCheck](t, p)

		sctx1 := probetest.SweepCtx(ctx, chk.Deps)
		_ = chk.Run(sctx1)
		probetest.VerifySweep(sctx1)

		cs.PrependReactor("list", "ingressclasses", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewGenericServerResponse(http.StatusInternalServerError, "list", schema.GroupResource{Resource: "ingressclasses"}, "", "boom", 0, false)
		})
		sctx2 := probetest.SweepCtx(ctx, chk.Deps)
		res2 := chk.Run(sctx2)
		probetest.VerifySweep(sctx2)
		if res2.Pass || res2.Infra == nil {
			t.Fatalf("expected Infra error on 500, got %+v", res2)
		}
		if v := ptestutil.ToFloat64(ingressNginxDetectedGauge.WithLabelValues("IngressClass", "", "nginx")); v != 1 {
			t.Fatalf("held gauge dropped on 500 error: %v", v)
		}
	})

	t.Run("pods list error returns Infra and event create error does not stamp cooldown", func(t *testing.T) {
		ingressNginxDetectedGauge.Reset()
		cs := fake.NewSimpleClientset()
		cs.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("pods unavailable")
		})
		p := testProber(cs)
		chk := probetest.MustCheck[*ingressNginxRetirementGuardCheck](t, p)
		sctx := probetest.SweepCtx(ctx, chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)
		if res.Pass || res.Infra == nil {
			t.Fatalf("expected Infra error on pods list failure, got %+v", res)
		}

		// Event create error does not fail check or stamp cooldown.
		cs2 := fake.NewSimpleClientset(&networkingv1.IngressClass{
			ObjectMeta: metav1.ObjectMeta{Name: "nginx"},
			Spec:       networkingv1.IngressClassSpec{Controller: ingressNginxControllerName},
		})
		cs2.PrependReactor("create", "events", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("events 403")
		})
		p2 := testProber(cs2)
		probetest.FreezeNow(p2.Deps, base)
		chk2 := probetest.MustCheck[*ingressNginxRetirementGuardCheck](t, p2)
		before := probetest.CounterSnapshot(t, p2.Deps.Name)
		sctx2 := probetest.SweepCtx(ctx, chk2.Deps)
		res2 := chk2.Run(sctx2)
		probetest.VerifySweep(sctx2)
		probetest.AssertCounterDelta(t, p2.Deps.Name, before, 0)
		if res2.Pass || res2.Infra != nil {
			t.Fatalf("Run with event create failure = %+v, want Pass=false Infra=nil", res2)
		}
		if chk2.eventCooldown.CooledDown("ingressnginx.ic.nginx", ingressNginxEventCooldown, base) {
			t.Fatal("eventCooldown must not stamp on create failure")
		}
	})
}

func TestIngressNginxRetirementGuardIngressClassFailureWithIngressesSucceeding(t *testing.T) {
	base := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	nginxName := "nginx"
	customIC := "custom-nginx"

	t.Run("IngressClasses failure does not false-flag nginx class or legacy nginx annotation", func(t *testing.T) {
		cases := []struct {
			name      string
			err       error
			wantPass  bool
			wantInfra bool
		}{
			{
				name:      "403 Forbidden",
				err:       apierrors.NewForbidden(schema.GroupResource{Group: "networking.k8s.io", Resource: "ingressclasses"}, "", errors.New("forbidden")),
				wantPass:  true,
				wantInfra: false,
			},
			{
				name:      "404 NotFound",
				err:       apierrors.NewNotFound(schema.GroupResource{Group: "networking.k8s.io", Resource: "ingressclasses"}, ""),
				wantPass:  true,
				wantInfra: false,
			},
			{
				name:      "500 InternalServerError",
				err:       apierrors.NewGenericServerResponse(http.StatusInternalServerError, "list", schema.GroupResource{Resource: "ingressclasses"}, "", "boom", 0, false),
				wantPass:  false,
				wantInfra: true,
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				ingressNginxDetectedGauge.Reset()
				cs := fake.NewSimpleClientset(
					&networkingv1.Ingress{
						ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-class", UID: "ing-1"},
						Spec:       networkingv1.IngressSpec{IngressClassName: &nginxName},
					},
					&networkingv1.Ingress{
						ObjectMeta: metav1.ObjectMeta{
							Namespace:   "apps",
							Name:        "web-legacy",
							UID:         "ing-2",
							Annotations: map[string]string{legacyIngressClassAnnotation: "nginx"},
						},
					},
				)
				cs.PrependReactor("list", "ingressclasses", func(ktesting.Action) (bool, runtime.Object, error) {
					return true, nil, tc.err
				})

				p := testProber(cs)
				probetest.FreezeNow(p.Deps, base)
				chk := probetest.MustCheck[*ingressNginxRetirementGuardCheck](t, p)

				sctx := probetest.SweepCtx(ctx, chk.Deps)
				res := chk.Run(sctx)
				probetest.VerifySweep(sctx)

				if res.Pass != tc.wantPass {
					t.Fatalf("Pass = %v, want %v (res=%+v)", res.Pass, tc.wantPass, res)
				}
				if (res.Infra != nil) != tc.wantInfra {
					t.Fatalf("Infra = %v, wantInfra=%v", res.Infra, tc.wantInfra)
				}
				if res.Why != "" {
					t.Fatalf("Why = %q, want empty", res.Why)
				}
				for _, ingName := range []string{"web-class", "web-legacy"} {
					if v := ptestutil.ToFloat64(ingressNginxDetectedGauge.WithLabelValues("Ingress", "apps", ingName)); v != 0 {
						t.Fatalf("Ingress/apps/%s gauge = %v, want 0", ingName, v)
					}
				}
				evs, err := cs.EventsV1().Events("apps").List(ctx, metav1.ListOptions{})
				if err != nil {
					t.Fatalf("list events: %v", err)
				}
				if len(evs.Items) != 0 {
					t.Fatalf("expected 0 Warning Events, got %d: %+v", len(evs.Items), evs.Items)
				}
			})
		}
	})

	t.Run("unambiguous legacy controller annotation still flags on IngressClasses 403", func(t *testing.T) {
		ingressNginxDetectedGauge.Reset()
		cs := fake.NewSimpleClientset(
			&networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:   "apps",
					Name:        "web-explicit",
					UID:         "ing-exp",
					Annotations: map[string]string{legacyIngressClassAnnotation: ingressNginxControllerName},
				},
			},
			&networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-ambiguous", UID: "ing-amb"},
				Spec:       networkingv1.IngressSpec{IngressClassName: &nginxName},
			},
		)
		cs.PrependReactor("list", "ingressclasses", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "networking.k8s.io", Resource: "ingressclasses"}, "", errors.New("forbidden"))
		})

		p := testProber(cs)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*ingressNginxRetirementGuardCheck](t, p)

		sctx := probetest.SweepCtx(ctx, chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)
		if res.Pass || res.Infra != nil {
			t.Fatalf("Run = %+v, want Pass=false Infra=nil", res)
		}
		if v := ptestutil.ToFloat64(ingressNginxDetectedGauge.WithLabelValues("Ingress", "apps", "web-explicit")); v != 1 {
			t.Fatalf("explicit legacy Ingress gauge = %v, want 1", v)
		}
		if v := ptestutil.ToFloat64(ingressNginxDetectedGauge.WithLabelValues("Ingress", "apps", "web-ambiguous")); v != 0 {
			t.Fatalf("ambiguous nginx Ingress gauge = %v, want 0", v)
		}
	})

	t.Run("held custom and default Ingress gauges stay 1 while non-nginx class stays 0 across IngressClasses 500 and 403", func(t *testing.T) {
		cases := []struct {
			name      string
			err       error
			wantPass  bool
			wantInfra bool
		}{
			{
				name:      "500 InternalServerError",
				err:       apierrors.NewGenericServerResponse(http.StatusInternalServerError, "list", schema.GroupResource{Resource: "ingressclasses"}, "", "boom", 0, false),
				wantPass:  false,
				wantInfra: true,
			},
			{
				name:      "403 Forbidden",
				err:       apierrors.NewForbidden(schema.GroupResource{Group: "networking.k8s.io", Resource: "ingressclasses"}, "", errors.New("forbidden")),
				wantPass:  true,
				wantInfra: false,
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				ingressNginxDetectedGauge.Reset()
				cs := fake.NewSimpleClientset(
					&networkingv1.IngressClass{
						ObjectMeta: metav1.ObjectMeta{
							Name:        customIC,
							UID:         "ic-custom",
							Annotations: map[string]string{networkingv1.AnnotationIsDefaultIngressClass: "true"},
						},
						Spec: networkingv1.IngressClassSpec{Controller: ingressNginxControllerName},
					},
					&networkingv1.IngressClass{
						ObjectMeta: metav1.ObjectMeta{Name: nginxName, UID: "ic-other"},
						Spec:       networkingv1.IngressClassSpec{Controller: "nginx.org/ingress-controller"},
					},
					&networkingv1.Ingress{
						ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "uses-custom", UID: "ing-custom"},
						Spec:       networkingv1.IngressSpec{IngressClassName: &customIC},
					},
					&networkingv1.Ingress{
						ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "uses-default", UID: "ing-default"},
					},
					&networkingv1.Ingress{
						ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "uses-other-nginx", UID: "ing-other"},
						Spec:       networkingv1.IngressSpec{IngressClassName: &nginxName},
					},
				)
				p := testProber(cs)
				probetest.FreezeNow(p.Deps, base)
				chk := probetest.MustCheck[*ingressNginxRetirementGuardCheck](t, p)

				// Sweep 1: healthy list populates held gauges for custom-nginx, uses-custom, uses-default.
				sctx1 := probetest.SweepCtx(ctx, chk.Deps)
				res1 := chk.Run(sctx1)
				probetest.VerifySweep(sctx1)
				if res1.Pass || res1.Infra != nil {
					t.Fatalf("Sweep 1 = %+v, want Pass=false Infra=nil", res1)
				}
				if v := ptestutil.ToFloat64(ingressNginxDetectedGauge.WithLabelValues("Ingress", "apps", "uses-custom")); v != 1 {
					t.Fatalf("Sweep 1 uses-custom gauge = %v, want 1", v)
				}
				if v := ptestutil.ToFloat64(ingressNginxDetectedGauge.WithLabelValues("Ingress", "apps", "uses-default")); v != 1 {
					t.Fatalf("Sweep 1 uses-default gauge = %v, want 1", v)
				}
				if v := ptestutil.ToFloat64(ingressNginxDetectedGauge.WithLabelValues("Ingress", "apps", "uses-other-nginx")); v != 0 {
					t.Fatalf("Sweep 1 uses-other-nginx gauge = %v, want 0", v)
				}
				evsBefore, _ := cs.EventsV1().Events("apps").List(ctx, metav1.ListOptions{})

				// Sweep 2: IngressClasses fails while Ingresses succeeds.
				cs.PrependReactor("list", "ingressclasses", func(ktesting.Action) (bool, runtime.Object, error) {
					return true, nil, tc.err
				})
				probetest.FreezeNow(p.Deps, base.Add(time.Minute))
				sctx2 := probetest.SweepCtx(ctx, chk.Deps)
				res2 := chk.Run(sctx2)
				probetest.VerifySweep(sctx2)

				if res2.Pass != tc.wantPass {
					t.Fatalf("Sweep 2 Pass = %v, want %v (res=%+v)", res2.Pass, tc.wantPass, res2)
				}
				if (res2.Infra != nil) != tc.wantInfra {
					t.Fatalf("Sweep 2 Infra = %v, wantInfra=%v", res2.Infra, tc.wantInfra)
				}
				if res2.Why != "" {
					t.Fatalf("Sweep 2 Why = %q, want empty (no false findings)", res2.Why)
				}
				if v := ptestutil.ToFloat64(ingressNginxDetectedGauge.WithLabelValues("IngressClass", "", customIC)); v != 1 {
					t.Fatalf("Sweep 2 IngressClass custom-nginx gauge = %v, want 1", v)
				}
				if v := ptestutil.ToFloat64(ingressNginxDetectedGauge.WithLabelValues("Ingress", "apps", "uses-custom")); v != 1 {
					t.Fatalf("Sweep 2 held uses-custom gauge = %v, want 1", v)
				}
				if v := ptestutil.ToFloat64(ingressNginxDetectedGauge.WithLabelValues("Ingress", "apps", "uses-default")); v != 1 {
					t.Fatalf("Sweep 2 held uses-default gauge = %v, want 1", v)
				}
				if v := ptestutil.ToFloat64(ingressNginxDetectedGauge.WithLabelValues("Ingress", "apps", "uses-other-nginx")); v != 0 {
					t.Fatalf("Sweep 2 uses-other-nginx gauge = %v, want 0 (false positive)", v)
				}
				evsAfter, _ := cs.EventsV1().Events("apps").List(ctx, metav1.ListOptions{})
				if len(evsAfter.Items) != len(evsBefore.Items) {
					t.Fatalf("Sweep 2 emitted unexpected Warning Events: before=%d after=%d", len(evsBefore.Items), len(evsAfter.Items))
				}

				// Sweep 3: deleting uses-custom while IngressClasses still fails prunes uses-custom to 0, keeps uses-default at 1.
				_ = cs.NetworkingV1().Ingresses("apps").Delete(ctx, "uses-custom", metav1.DeleteOptions{})
				probetest.FreezeNow(p.Deps, base.Add(2*time.Minute))
				sctx3 := probetest.SweepCtx(ctx, chk.Deps)
				_ = chk.Run(sctx3)
				probetest.VerifySweep(sctx3)
				if v := ptestutil.ToFloat64(ingressNginxDetectedGauge.WithLabelValues("Ingress", "apps", "uses-custom")); v != 0 {
					t.Fatalf("Sweep 3 deleted uses-custom gauge = %v, want 0", v)
				}
				if v := ptestutil.ToFloat64(ingressNginxDetectedGauge.WithLabelValues("Ingress", "apps", "uses-default")); v != 1 {
					t.Fatalf("Sweep 3 held uses-default gauge = %v, want 1", v)
				}
			})
		}
	})
}

func TestIngressNginxRetirementGuardListOptions(t *testing.T) {
	ingressNginxDetectedGauge.Reset()
	fakeCS := fake.NewSimpleClientset()
	recCS := &listOptsRecordingCS{Interface: fakeCS}

	p := testProber(fakeCS)
	p.Deps.CS = recCS
	chk := probetest.MustCheck[*ingressNginxRetirementGuardCheck](t, p)

	sctx := probetest.SweepCtx(ctx, chk.Deps)
	res := chk.Run(sctx)
	probetest.VerifySweep(sctx)
	if !res.Pass || res.Infra != nil {
		t.Fatalf("Run = %+v, want Pass=true Infra=nil", res)
	}

	seenActions := map[string]bool{}
	for _, a := range fakeCS.Actions() {
		la, ok := a.(ktesting.ListAction)
		if !ok {
			continue
		}
		seenActions[la.GetResource().Resource] = true
	}
	for _, resource := range []string{"ingressclasses", "ingresses"} {
		if !seenActions[resource] {
			t.Fatalf("expected fake clientset ListAction for %q; actions=%v", resource, fakeCS.Actions())
		}
		opts, ok := recCS.optsByResource[resource]
		if !ok {
			t.Fatalf("missing recorded ListOptions for %q", resource)
		}
		if opts.ResourceVersion != "0" {
			t.Fatalf("%s ListOptions.ResourceVersion = %q, want %q", resource, opts.ResourceVersion, "0")
		}
		if opts.Limit != 0 {
			t.Fatalf("%s ListOptions.Limit = %d, want 0 after pageOpts", resource, opts.Limit)
		}
	}
}

type listOptsRecordingCS struct {
	kubernetes.Interface
	optsByResource map[string]metav1.ListOptions
}

func (c *listOptsRecordingCS) NetworkingV1() typednetworkingv1.NetworkingV1Interface {
	return &listOptsRecordingNetV1{
		NetworkingV1Interface: c.Interface.NetworkingV1(),
		parent:                c,
	}
}

type listOptsRecordingNetV1 struct {
	typednetworkingv1.NetworkingV1Interface
	parent *listOptsRecordingCS
}

func (n *listOptsRecordingNetV1) IngressClasses() typednetworkingv1.IngressClassInterface {
	return &listOptsRecordingIC{
		IngressClassInterface: n.NetworkingV1Interface.IngressClasses(),
		parent:                n.parent,
	}
}

func (n *listOptsRecordingNetV1) Ingresses(namespace string) typednetworkingv1.IngressInterface {
	return &listOptsRecordingIng{
		IngressInterface: n.NetworkingV1Interface.Ingresses(namespace),
		parent:           n.parent,
	}
}

type listOptsRecordingIC struct {
	typednetworkingv1.IngressClassInterface
	parent *listOptsRecordingCS
}

func (i *listOptsRecordingIC) List(ctx context.Context, opts metav1.ListOptions) (*networkingv1.IngressClassList, error) {
	if i.parent.optsByResource == nil {
		i.parent.optsByResource = map[string]metav1.ListOptions{}
	}
	i.parent.optsByResource["ingressclasses"] = opts
	return i.IngressClassInterface.List(ctx, opts)
}

type listOptsRecordingIng struct {
	typednetworkingv1.IngressInterface
	parent *listOptsRecordingCS
}

func (i *listOptsRecordingIng) List(ctx context.Context, opts metav1.ListOptions) (*networkingv1.IngressList, error) {
	if i.parent.optsByResource == nil {
		i.parent.optsByResource = map[string]metav1.ListOptions{}
	}
	i.parent.optsByResource["ingresses"] = opts
	return i.IngressInterface.List(ctx, opts)
}
