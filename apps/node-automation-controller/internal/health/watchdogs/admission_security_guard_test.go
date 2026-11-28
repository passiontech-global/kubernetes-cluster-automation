package watchdogs

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

var rfc1123SubdomainRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)

func assertValidRFC1123EventNames(t *testing.T, cs *fake.Clientset, ns string) {
	t.Helper()
	evs, err := cs.EventsV1().Events(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs.Items) == 0 {
		t.Fatalf("expected at least 1 event in namespace %q", ns)
	}
	for _, ev := range evs.Items {
		if len(ev.Name) > 253 {
			t.Fatalf("Event.Name exceeds 253 chars (%d): %q", len(ev.Name), ev.Name)
		}
		if !rfc1123SubdomainRe.MatchString(ev.Name) {
			t.Fatalf("Event.Name %q is not a valid RFC 1123 subdomain", ev.Name)
		}
	}
}

func secValidatingWebhook(ns, svcName string) *admissionv1.ValidatingWebhookConfiguration {
	return &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "vwc-" + svcName},
		Webhooks: []admissionv1.ValidatingWebhook{{
			Name: "hook.example.com",
			ClientConfig: admissionv1.WebhookClientConfig{
				Service: &admissionv1.ServiceReference{Namespace: ns, Name: svcName, Port: ptr.To(int32(443))},
			},
		}},
	}
}

func secWebhookService(ns, name string, svcType corev1.ServiceType) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: corev1.ServiceSpec{
			Type:     svcType,
			Selector: map[string]string{"app": name},
			Ports:    []corev1.ServicePort{{Port: 443}},
		},
	}
}

func secWebhookPod(ns, name, app string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: map[string]string{"app": app}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func TestAdmissionSecurityGuardWebhookIsolation(t *testing.T) {
	t.Run("ClusterIP without NetworkPolicy flags and cleans up when NetworkPolicy added", func(t *testing.T) {
		vwc := secValidatingWebhook("ns1", "wh-svc")
		svc := secWebhookService("ns1", "wh-svc", corev1.ServiceTypeClusterIP)
		pod := secWebhookPod("ns1", "wh-pod-1", "wh-svc")
		// Egress-only NetworkPolicy must NOT satisfy ingress isolation.
		egressNP := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "egress-only"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "wh-svc"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			},
		}

		cs := fake.NewSimpleClientset(vwc, svc, pod, egressNP)
		dyn := testutil.NewDynamicClientWithCRDs()
		p := testProberDyn(cs, dyn)
		now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
		p.Now = func() time.Time { return now }
		chk := probetest.MustCheck[*admissionSecurityGuardCheck](t, p)

		res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if res.Pass {
			t.Fatal("expected FAIL when webhook has only egress NetworkPolicy")
		}
		if m := probetest.FindMetric(t, "node_automation_admission_webhook_exposed", map[string]string{
			"namespace": "ns1", "service": "wh-svc", "reason": "webhook_no_networkpolicy",
		}); m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatalf("expected webhook_no_networkpolicy=1, got %v", m)
		}

		// Second sweep within 6h cooldown must not emit duplicate event.
		now = now.Add(time.Hour)
		_ = chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		evs, _ := cs.EventsV1().Events("ns1").List(ctx, metav1.ListOptions{})
		if len(evs.Items) != 1 || evs.Items[0].Reason != admissionSecEventReason {
			t.Fatalf("expected 1 deduped event, got %d (%+v)", len(evs.Items), evs.Items)
		}

		// After 6h cooldown expires, a fresh event may emit.
		now = now.Add(6 * time.Hour)
		_ = chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		evs, _ = cs.EventsV1().Events("ns1").List(ctx, metav1.ListOptions{})
		if len(evs.Items) != 2 {
			t.Fatalf("expected 2 events after 6h cooldown, got %d", len(evs.Items))
		}
		assertValidRFC1123EventNames(t, cs, "ns1")

		// Add Ingress NetworkPolicy -> PASS and GaugeLedger prunes stale series.
		ingressNP := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "allow-apiserver"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "wh-svc"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			},
		}
		if _, err := cs.NetworkingV1().NetworkPolicies("ns1").Create(ctx, ingressNP, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		res = chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if !res.Pass {
			t.Fatalf("expected PASS after Ingress NetworkPolicy added, got %+v", res)
		}
		if m := probetest.FindMetric(t, "node_automation_admission_webhook_exposed", map[string]string{
			"namespace": "ns1", "service": "wh-svc", "reason": "webhook_no_networkpolicy",
		}); m != nil {
			t.Fatalf("stale webhook_no_networkpolicy series not pruned: %v", m)
		}
	})

	t.Run("CiliumNetworkPolicy and CiliumClusterwideNetworkPolicy isolate webhook", func(t *testing.T) {
		vwc := secValidatingWebhook("ns1", "cnp-svc")
		mwc := &admissionv1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "mwc-ccnp"},
			Webhooks: []admissionv1.MutatingWebhook{{
				Name: "mhook.example.com",
				ClientConfig: admissionv1.WebhookClientConfig{
					Service: &admissionv1.ServiceReference{Namespace: "ns2", Name: "ccnp-svc"},
				},
			}},
		}
		svc1 := secWebhookService("ns1", "cnp-svc", corev1.ServiceTypeClusterIP)
		svc2 := secWebhookService("ns2", "ccnp-svc", corev1.ServiceTypeClusterIP)
		pod1 := secWebhookPod("ns1", "p1", "cnp-svc")
		pod2 := secWebhookPod("ns2", "p2", "ccnp-svc")

		cnp := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "cilium.io/v2",
			"kind":       "CiliumNetworkPolicy",
			"metadata":   map[string]any{"namespace": "ns1", "name": "cnp-ingress"},
			"spec": map[string]any{
				"endpointSelector": map[string]any{
					"matchLabels": map[string]any{"k8s:app": "cnp-svc"},
				},
				"ingress": []any{map[string]any{}},
			},
		}}
		ccnp := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "cilium.io/v2",
			"kind":       "CiliumClusterwideNetworkPolicy",
			"metadata":   map[string]any{"name": "ccnp-ingress"},
			"spec": map[string]any{
				"endpointSelector": map[string]any{
					"matchLabels": map[string]any{
						"k8s:io.kubernetes.pod.namespace": "ns2",
						"app":                             "ccnp-svc",
					},
				},
				"ingress": []any{map[string]any{}},
			},
		}}

		cs := fake.NewSimpleClientset(vwc, mwc, svc1, svc2, pod1, pod2)
		dyn := testutil.NewDynamicClientWithCRDs(cnp, ccnp)
		p := testProberDyn(cs, dyn)
		chk := probetest.MustCheck[*admissionSecurityGuardCheck](t, p)

		res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if !res.Pass {
			t.Fatalf("expected PASS when CNP & CCNP isolate both webhooks, got %+v", res)
		}
	})

	t.Run("CRD conversion webhook Service NodePort LoadBalancer and exempt list", func(t *testing.T) {
		t.Setenv("NODE_AUTOMATION_ADMISSION_SEC_EXEMPT_SERVICES", "exempt-ns/exempt-svc")

		crdExposed := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "apiextensions.k8s.io/v1",
			"kind":       "CustomResourceDefinition",
			"metadata":   map[string]any{"name": "foos.example.com"},
			"spec": map[string]any{
				"conversion": map[string]any{
					"strategy": "Webhook",
					"webhook": map[string]any{
						"clientConfig": map[string]any{
							"service": map[string]any{"namespace": "conv-ns", "name": "conv-svc", "port": int64(443)},
						},
					},
				},
			},
		}}
		vwcExempt := secValidatingWebhook("exempt-ns", "exempt-svc")

		svcConv := secWebhookService("conv-ns", "conv-svc", corev1.ServiceTypeNodePort)
		svcExempt := secWebhookService("exempt-ns", "exempt-svc", corev1.ServiceTypeLoadBalancer)
		npConv := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: "conv-ns", Name: "np-conv"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			},
		}

		cs := fake.NewSimpleClientset(vwcExempt, svcConv, svcExempt, npConv)
		dyn := testutil.NewDynamicClientWithCRDs(crdExposed)
		p := testProberDyn(cs, dyn)
		chk := probetest.MustCheck[*admissionSecurityGuardCheck](t, p)

		res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if res.Pass {
			t.Fatal("expected FAIL for NodePort conversion webhook service")
		}
		if m := probetest.FindMetric(t, "node_automation_admission_webhook_exposed", map[string]string{
			"namespace": "conv-ns", "service": "conv-svc", "reason": "service_externally_exposed",
		}); m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatalf("expected service_externally_exposed=1 for conv-svc, got %v", m)
		}
		if m := probetest.FindMetric(t, "node_automation_admission_webhook_exposed", map[string]string{
			"namespace": "exempt-ns", "service": "exempt-svc", "reason": "service_externally_exposed",
		}); m != nil {
			t.Fatalf("exempt service should not be flagged: %v", m)
		}
		assertValidRFC1123EventNames(t, cs, "conv-ns")
	})

	t.Run("CCNP matchExpressions namespace In/NotIn/reserved and CNP ingress nil", func(t *testing.T) {
		vwcIn := secValidatingWebhook("ns1", "wh-in")
		mwcOther := &admissionv1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "mwc-ns2"},
			Webhooks: []admissionv1.MutatingWebhook{{
				Name: "mhook.ns2.example.com",
				ClientConfig: admissionv1.WebhookClientConfig{
					Service: &admissionv1.ServiceReference{Namespace: "ns2", Name: "wh-in"},
				},
			}},
		}
		svc1 := secWebhookService("ns1", "wh-in", corev1.ServiceTypeClusterIP)
		svc2 := secWebhookService("ns2", "wh-in", corev1.ServiceTypeClusterIP)
		pod1 := secWebhookPod("ns1", "p1", "wh-in")
		pod2 := secWebhookPod("ns2", "p2", "wh-in")

		// CCNP selecting only ns1 via matchExpressions In -> isolates ns1, NOT ns2.
		ccnpIn := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "cilium.io/v2",
			"kind":       "CiliumClusterwideNetworkPolicy",
			"metadata":   map[string]any{"name": "ccnp-ns-in"},
			"spec": map[string]any{
				"endpointSelector": map[string]any{
					"matchExpressions": []any{
						map[string]any{
							"key":      "k8s:io.kubernetes.pod.namespace",
							"operator": "In",
							"values":   []any{"ns1"},
						},
						map[string]any{
							"key":      "app",
							"operator": "In",
							"values":   []any{"wh-in"},
						},
					},
				},
				"ingress": []any{map[string]any{}},
			},
		}}

		// CCNP with NotIn ns2 -> must NOT match ns2 (must NOT false-negative on ns2).
		ccnpNotIn := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "cilium.io/v2",
			"kind":       "CiliumClusterwideNetworkPolicy",
			"metadata":   map[string]any{"name": "ccnp-ns-notin"},
			"spec": map[string]any{
				"endpointSelector": map[string]any{
					"matchExpressions": []any{
						map[string]any{
							"key":      "k8s:io.kubernetes.pod.namespace",
							"operator": "NotIn",
							"values":   []any{"ns1", "ns2"},
						},
					},
				},
				"ingress": []any{map[string]any{}},
			},
		}}

		// CCNP with reserved:* in matchExpressions must be rejected.
		ccnpReserved := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "cilium.io/v2",
			"kind":       "CiliumClusterwideNetworkPolicy",
			"metadata":   map[string]any{"name": "ccnp-reserved"},
			"spec": map[string]any{
				"endpointSelector": map[string]any{
					"matchExpressions": []any{
						map[string]any{"key": "reserved:world", "operator": "Exists"},
					},
				},
				"ingress": []any{map[string]any{}},
			},
		}}

		// Egress-only CNP serialized with explicit "ingress": nil in ns2 must NOT count as ingress isolation.
		cnpIngressNil := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "cilium.io/v2",
			"kind":       "CiliumNetworkPolicy",
			"metadata":   map[string]any{"namespace": "ns2", "name": "cnp-egress-nil-ingress"},
			"spec": map[string]any{
				"endpointSelector": map[string]any{
					"matchLabels": map[string]any{"app": "wh-in"},
				},
				"ingress": nil,
				"egress":  []any{map[string]any{}},
			},
		}}

		cs := fake.NewSimpleClientset(vwcIn, mwcOther, svc1, svc2, pod1, pod2)
		dyn := testutil.NewDynamicClientWithCRDs(ccnpIn, ccnpNotIn, ccnpReserved, cnpIngressNil)
		p := testProberDyn(cs, dyn)
		chk := probetest.MustCheck[*admissionSecurityGuardCheck](t, p)

		res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if res.Pass {
			t.Fatal("expected FAIL because ns2 is not isolated")
		}
		if m := probetest.FindMetric(t, "node_automation_admission_webhook_exposed", map[string]string{
			"namespace": "ns1", "service": "wh-in", "reason": "webhook_no_networkpolicy",
		}); m != nil {
			t.Fatalf("ns1 should be isolated by CCNP matchExpressions In: %v", m)
		}
		if m := probetest.FindMetric(t, "node_automation_admission_webhook_exposed", map[string]string{
			"namespace": "ns2", "service": "wh-in", "reason": "webhook_no_networkpolicy",
		}); m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatalf("ns2 should be flagged webhook_no_networkpolicy=1 (NotIn excluded & ingress=nil), got %v", m)
		}

		// Now add CCNP NotIn excluding only ns1 -> ns2 becomes isolated!
		ccnpNotInNs1Only := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "cilium.io/v2",
			"kind":       "CiliumClusterwideNetworkPolicy",
			"metadata":   map[string]any{"name": "ccnp-notin-ns1-only"},
			"spec": map[string]any{
				"endpointSelector": map[string]any{
					"matchExpressions": []any{
						map[string]any{
							"key":      "k8s:io.kubernetes.pod.namespace",
							"operator": "NotIn",
							"values":   []any{"ns1"},
						},
					},
				},
				"ingress": []any{map[string]any{}},
			},
		}}
		if _, err := dyn.Resource(ccnpNotInNs1Only.GroupVersionKind().GroupVersion().WithResource("ciliumclusterwidenetworkpolicies")).
			Create(ctx, ccnpNotInNs1Only, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		res = chk.Run(probetest.SweepCtx(ctx, chk.Deps))
		if !res.Pass {
			t.Fatalf("expected PASS once ns2 covered by CCNP NotIn [ns1], got %+v", res)
		}
	})
}

func TestAdmissionSecurityGuardAnonymousRBAC(t *testing.T) {
	t.Setenv("NODE_AUTOMATION_ADMISSION_SEC_ALLOW_ANON_ROLES", "custom-public-health")

	crbAllow := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-discovery"},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "system:discovery"},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.GroupKind, Name: "system:unauthenticated"}},
	}
	crbCustomAllow := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-custom"},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "custom-public-health"},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "system:anonymous"}},
	}
	crbDangerous := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "system:danger_admin:ClusterRole"},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.GroupKind, Name: "system:unauthenticated"}},
	}
	rbDangerous := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "Danger_Role..Bind:1"},
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "edit"},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "system:anonymous"}},
	}

	cs := fake.NewSimpleClientset(crbAllow, crbCustomAllow, crbDangerous, rbDangerous)
	p := testProberDyn(cs, testutil.NewDynamicClientWithCRDs())
	chk := probetest.MustCheck[*admissionSecurityGuardCheck](t, p)

	res := chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if res.Pass {
		t.Fatal("expected FAIL for dangerous anonymous RBAC bindings")
	}
	assertValidRFC1123EventNames(t, cs, "default")
	assertValidRFC1123EventNames(t, cs, "prod")
	if m := probetest.FindMetric(t, "node_automation_anonymous_rbac_binding", map[string]string{
		"kind": "ClusterRoleBinding", "namespace": "", "binding": "system:danger_admin:ClusterRole", "role": "cluster-admin",
	}); m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("expected danger-admin gauge=1, got %v", m)
	}
	if m := probetest.FindMetric(t, "node_automation_anonymous_rbac_binding", map[string]string{
		"kind": "RoleBinding", "namespace": "prod", "binding": "Danger_Role..Bind:1", "role": "edit",
	}); m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("expected danger-ns-edit gauge=1, got %v", m)
	}
	if m := probetest.FindMetric(t, "node_automation_anonymous_rbac_binding", map[string]string{
		"kind": "ClusterRoleBinding", "namespace": "", "binding": "allow-discovery", "role": "system:discovery",
	}); m != nil {
		t.Fatalf("allowlisted role system:discovery flagged: %v", m)
	}
	if m := probetest.FindMetric(t, "node_automation_anonymous_rbac_binding", map[string]string{
		"kind": "ClusterRoleBinding", "namespace": "", "binding": "allow-custom", "role": "custom-public-health",
	}); m != nil {
		t.Fatalf("env allowlisted role flagged: %v", m)
	}

	// Delete dangerous bindings -> PASS and stale gauge series deleted.
	_ = cs.RbacV1().ClusterRoleBindings().Delete(ctx, "system:danger_admin:ClusterRole", metav1.DeleteOptions{})
	_ = cs.RbacV1().RoleBindings("prod").Delete(ctx, "Danger_Role..Bind:1", metav1.DeleteOptions{})
	res = chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if !res.Pass {
		t.Fatalf("expected PASS after dangerous bindings deleted, got %+v", res)
	}
	if m := probetest.FindMetric(t, "node_automation_anonymous_rbac_binding", map[string]string{
		"kind": "ClusterRoleBinding", "namespace": "", "binding": "system:danger_admin:ClusterRole", "role": "cluster-admin",
	}); m != nil {
		t.Fatalf("stale RBAC gauge not pruned: %v", m)
	}
}

func TestAdmissionSecurityGuard403And404GracefulSkip(t *testing.T) {
	vwc := secValidatingWebhook("ns1", "wh-svc")
	svc := secWebhookService("ns1", "wh-svc", corev1.ServiceTypeClusterIP)
	pod := secWebhookPod("ns1", "wh-pod", "wh-svc")

	cs := fake.NewSimpleClientset(vwc, svc, pod)
	cs.PrependReactor("list", "networkpolicies", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "networking.k8s.io", Resource: "networkpolicies"}, "", errors.New("forbidden"))
	})
	cs.PrependReactor("list", "clusterrolebindings", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "rbac.authorization.k8s.io", Resource: "clusterrolebindings"}, "", errors.New("forbidden"))
	})
	cs.PrependReactor("list", "rolebindings", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "rbac.authorization.k8s.io", Resource: "rolebindings"}, "", errors.New("forbidden"))
	})

	// Use NewDynamicClient WITHOUT Cilium/CRD types? Instead return 404 on CRD/Cilium via reactor.
	dyn := testutil.NewDynamicClientWithCRDs()
	dyn.PrependReactor("list", "ciliumnetworkpolicies", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewNotFound(schema.GroupResource{Group: "cilium.io", Resource: "ciliumnetworkpolicies"}, "")
	})
	dyn.PrependReactor("list", "ciliumclusterwidenetworkpolicies", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "cilium.io", Resource: "ciliumclusterwidenetworkpolicies"}, "", errors.New("forbidden"))
	})

	d := probetest.NewDeps(cs, dyn)
	chk := NewAdmissionSecurityGuardCheck(d)
	res := chk.Run(probetest.SweepCtx(ctx, d))
	if !res.Pass || res.Infra != nil {
		t.Fatalf("expected PASS with no Infra error on 403/404 graceful skip, got %+v", res)
	}
	// Must NOT false-flag webhook_no_networkpolicy when NetworkPolicy/CCNP returned 403.
	if m := probetest.FindMetric(t, "node_automation_admission_webhook_exposed", map[string]string{
		"namespace": "ns1", "service": "wh-svc", "reason": "webhook_no_networkpolicy",
	}); m != nil {
		t.Fatalf("false-flagged webhook_no_networkpolicy on 403: %v", m)
	}
}

func TestAdmissionSecurityGuardListsUseRV0(t *testing.T) {
	gotRVs := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		rv := r.URL.Query().Get("resourceVersion")
		switch {
		case strings.HasSuffix(r.URL.Path, "/validatingwebhookconfigurations"):
			_, _ = w.Write([]byte(`{"apiVersion":"admissionregistration.k8s.io/v1","kind":"ValidatingWebhookConfigurationList","items":[{"metadata":{"name":"vwc-1"},"webhooks":[{"name":"h.example.com","clientConfig":{"service":{"namespace":"ns1","name":"wh-svc"}}}]}]}`))
		case strings.HasSuffix(r.URL.Path, "/mutatingwebhookconfigurations"):
			_, _ = w.Write([]byte(`{"apiVersion":"admissionregistration.k8s.io/v1","kind":"MutatingWebhookConfigurationList","items":[]}`))
		case strings.HasSuffix(r.URL.Path, "/customresourcedefinitions"):
			gotRVs["customresourcedefinitions"] = rv
			_, _ = w.Write([]byte(`{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinitionList","items":[]}`))
		case strings.HasSuffix(r.URL.Path, "/services"):
			_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"ServiceList","items":[{"metadata":{"namespace":"ns1","name":"wh-svc"},"spec":{"type":"ClusterIP","selector":{"app":"wh-svc"}}}]}`))
		case strings.HasSuffix(r.URL.Path, "/pods"):
			_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"PodList","items":[]}`))
		case strings.HasSuffix(r.URL.Path, "/networkpolicies"):
			gotRVs["networkpolicies"] = rv
			_, _ = w.Write([]byte(`{"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicyList","items":[{"metadata":{"namespace":"ns1","name":"np-1"},"spec":{"podSelector":{"matchLabels":{"app":"wh-svc"}},"policyTypes":["Ingress"]}}]}`))
		case strings.HasSuffix(r.URL.Path, "/clusterrolebindings"):
			gotRVs["clusterrolebindings"] = rv
			_, _ = w.Write([]byte(`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBindingList","items":[]}`))
		case strings.HasSuffix(r.URL.Path, "/rolebindings"):
			gotRVs["rolebindings"] = rv
			_, _ = w.Write([]byte(`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBindingList","items":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cs, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	dyn, err := dynamic.NewForConfig(&rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	d := probetest.NewDeps(cs, dyn)
	chk := NewAdmissionSecurityGuardCheck(d)
	res := chk.Run(probetest.SweepCtx(ctx, d))
	if !res.Pass || res.Infra != nil {
		t.Fatalf("unexpected result: %+v", res)
	}
	for _, resName := range []string{"customresourcedefinitions", "networkpolicies", "clusterrolebindings", "rolebindings"} {
		if got := gotRVs[resName]; got != "0" {
			t.Fatalf("%s resourceVersion = %q, want \"0\"", resName, got)
		}
	}
}

func TestAdmissionSecurityGuardPriorityClassAbuse(t *testing.T) {
	// Non-system Pod using system-cluster-critical -> flagged.
	badClusterCrit := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app-ns", Name: "greedy-api"},
		Spec:       corev1.PodSpec{PriorityClassName: "system-cluster-critical"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	// Non-system Pod using system-node-critical -> flagged.
	badNodeCrit := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "greedy-daemon"},
		Spec:       corev1.PodSpec{PriorityClassName: "system-node-critical"},
		Status:     corev1.PodStatus{Phase: corev1.PodPending},
	}
	// Opt-out annotation -> allowed.
	optedOut := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "app-ns",
			Name:        "approved-agent",
			Annotations: map[string]string{admissionSecAnnoAllowSysPrio: "true"},
		},
		Spec:   corev1.PodSpec{PriorityClassName: "system-node-critical"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	// System namespaces -> allowed.
	sysKube := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "coredns"},
		Spec:       corev1.PodSpec{PriorityClassName: "system-cluster-critical"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	sysK0s := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "k0s-system", Name: "konnectivity"},
		Spec:       corev1.PodSpec{PriorityClassName: "system-node-critical"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	// Terminal Pod -> skipped.
	terminalPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app-ns", Name: "done-job-pod"},
		Spec:       corev1.PodSpec{PriorityClassName: "system-cluster-critical"},
		Status:     corev1.PodStatus{Phase: corev1.PodSucceeded},
	}
	// Normal PriorityClass -> allowed.
	normalPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app-ns", Name: "normal-web"},
		Spec:       corev1.PodSpec{PriorityClassName: "high-priority"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	// Static/mirror pod -> excluded.
	mirrorPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "app-ns",
			Name:        "static-mirror",
			Annotations: map[string]string{"kubernetes.io/config.mirror": "node-1"},
		},
		Spec:   corev1.PodSpec{PriorityClassName: "system-node-critical"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}

	cs := fake.NewSimpleClientset(badClusterCrit, badNodeCrit, optedOut, sysKube, sysK0s, terminalPod, normalPod, mirrorPod)
	p := testProberDyn(cs, testutil.NewDynamicClientWithCRDs())
	chk := probetest.MustCheck[*admissionSecurityGuardCheck](t, p)

	res := probetest.RunCheck(ctx, chk.Deps, chk)
	if res.Pass {
		t.Fatal("expected FAIL for non-system Pods abusing system PriorityClass")
	}
	if !strings.Contains(res.Why, "Pod/app-ns/greedy-api priorityClass=system-cluster-critical") ||
		!strings.Contains(res.Why, "Pod/prod/greedy-daemon priorityClass=system-node-critical") {
		t.Fatalf("unexpected Why: %s", res.Why)
	}
	if m := probetest.FindMetric(t, "node_automation_system_priorityclass_abuse", map[string]string{
		"namespace": "app-ns", "pod": "greedy-api", "priority_class": "system-cluster-critical",
	}); m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("expected system_priorityclass_abuse=1 for greedy-api, got %v", m)
	}
	if m := probetest.FindMetric(t, "node_automation_system_priorityclass_abuse", map[string]string{
		"namespace": "app-ns", "pod": "approved-agent", "priority_class": "system-node-critical",
	}); m != nil {
		t.Fatalf("opted-out pod should not be flagged: %v", m)
	}
	if m := probetest.FindMetric(t, "node_automation_system_priorityclass_abuse", map[string]string{
		"namespace": "kube-system", "pod": "coredns", "priority_class": "system-cluster-critical",
	}); m != nil {
		t.Fatalf("system namespace pod should not be flagged: %v", m)
	}
	assertValidRFC1123EventNames(t, cs, "app-ns")
	assertValidRFC1123EventNames(t, cs, "prod")

	// Delete abusive pods -> PASS and gauge series pruned.
	_ = cs.CoreV1().Pods("app-ns").Delete(ctx, "greedy-api", metav1.DeleteOptions{})
	_ = cs.CoreV1().Pods("prod").Delete(ctx, "greedy-daemon", metav1.DeleteOptions{})
	res = probetest.RunCheck(ctx, chk.Deps, chk)
	if !res.Pass {
		t.Fatalf("expected PASS after abusive pods deleted, got %+v", res)
	}
	if m := probetest.FindMetric(t, "node_automation_system_priorityclass_abuse", map[string]string{
		"namespace": "app-ns", "pod": "greedy-api", "priority_class": "system-cluster-critical",
	}); m != nil {
		t.Fatalf("stale priorityclass gauge not pruned: %v", m)
	}
}
