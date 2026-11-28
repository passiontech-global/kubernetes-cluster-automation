package nethealth

import (
	"net/http"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

func TestServiceLBLifecycleGuardDetectionAndPruning(t *testing.T) {
	base := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)

	liveNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "apps"}}
	termNS := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "dying-ns", DeletionTimestamp: new(metav1.NewTime(base.Add(-30 * time.Minute)))},
		Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating},
	}

	svcTerm := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "lb-term", UID: "s1",
			DeletionTimestamp: new(metav1.NewTime(base.Add(-20 * time.Minute))),
		},
		Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
	}
	svcTermInDyingNS := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "dying-ns", Name: "lb-dying-ns", UID: "s2",
			DeletionTimestamp: new(metav1.NewTime(base.Add(-20 * time.Minute))),
		},
		Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
	}
	svcPending := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "lb-pending", UID: "s3",
			CreationTimestamp: metav1.NewTime(base.Add(-12 * time.Minute)),
		},
		Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
	}
	svcHealthy := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "lb-ok", UID: "s4",
			CreationTimestamp: metav1.NewTime(base.Add(-1 * time.Hour)),
		},
		Spec:   corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
		Status: corev1.ServiceStatus{LoadBalancer: corev1.LoadBalancerStatus{Ingress: []corev1.LoadBalancerIngress{{IP: "1.2.3.4"}}}},
	}
	ingTerm := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "ing-term", UID: "i1",
			DeletionTimestamp: new(metav1.NewTime(base.Add(-16 * time.Minute))),
		},
	}

	cs := fake.NewSimpleClientset(liveNS, termNS, svcTerm, svcTermInDyingNS, svcPending, svcHealthy, ingTerm)
	p := testProber(cs)
	chk := probetest.MustCheck[*serviceLBLifecycleGuardCheck](t, p)
	probetest.FreezeNow(p.Deps, base)

	res := probetest.RunCheck(ctx, p.Deps, chk)
	if res.Pass {
		t.Fatalf("expected failure, got pass")
	}
	if strings.Contains(res.Why, "lb-dying-ns") || strings.Contains(res.Why, "lb-ok") {
		t.Fatalf("unexpected dying-ns or healthy svc in Why: %s", res.Why)
	}
	for _, want := range []struct{ kind, name, reason string }{
		{"Service", "lb-term", svcLBReasonTerminatingStuck},
		{"Service", "lb-pending", svcLBReasonPendingIngress},
		{"Ingress", "ing-term", svcLBReasonTerminatingStuck},
	} {
		if m := probetest.FindMetric(t, "node_automation_service_lb_lifecycle_stuck", map[string]string{
			"namespace": "apps", "kind": want.kind, "name": want.name, "reason": want.reason,
		}); m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatalf("missing gauge for %+v: %v", want, m)
		}
	}

	evs, err := cs.EventsV1().Events("apps").List(ctx, metav1.ListOptions{})
	if err != nil || len(evs.Items) != 3 {
		t.Fatalf("expected 3 ServiceLBLifecycleStuck events, got %d err=%v", len(evs.Items), err)
	}

	// Resolve all findings -> pass + pruned gauges.
	_ = cs.CoreV1().Services("apps").Delete(ctx, "lb-term", metav1.DeleteOptions{})
	_ = cs.NetworkingV1().Ingresses("apps").Delete(ctx, "ing-term", metav1.DeleteOptions{})
	svcPendingUpdated := svcPending.DeepCopy()
	svcPendingUpdated.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "1.2.3.5"}}
	_, _ = cs.CoreV1().Services("apps").UpdateStatus(ctx, svcPendingUpdated, metav1.UpdateOptions{})

	probetest.FreezeNow(p.Deps, base.Add(5*time.Minute))
	res2 := probetest.RunCheck(ctx, p.Deps, chk)
	if !res2.Pass {
		t.Fatalf("expected pass after resolution, got %+v", res2)
	}
	if m := probetest.FindMetric(t, "node_automation_service_lb_lifecycle_stuck", map[string]string{
		"namespace": "apps", "kind": "Service", "name": "lb-pending", "reason": svcLBReasonPendingIngress,
	}); m != nil {
		t.Fatalf("expected pruned gauge, got %v", m)
	}
}

func TestServiceLBLifecycleGuardIngress403Skip(t *testing.T) {
	cs := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "apps"}})
	cs.PrependReactor("list", "ingresses", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, &apierrors.StatusError{ErrStatus: metav1.Status{
			Status: metav1.StatusFailure,
			Code:   http.StatusForbidden,
			Reason: metav1.StatusReasonForbidden,
		}}
	})
	p := testProber(cs)
	chk := probetest.MustCheck[*serviceLBLifecycleGuardCheck](t, p)
	res := probetest.RunCheck(ctx, p.Deps, chk)
	if !res.Pass || res.Infra != nil {
		t.Fatalf("expected graceful pass on 403 ingresses, got %+v", res)
	}
}
