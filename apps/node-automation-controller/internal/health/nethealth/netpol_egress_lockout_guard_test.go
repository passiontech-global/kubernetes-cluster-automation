// netpol_egress_lockout_guard_test.go — unit tests for netpol-egress-lockout-guard.
package nethealth

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func netpolLockoutTestProber(t *testing.T, cs *fake.Clientset, dyn dynamic.Interface, now time.Time) *probetest.Prober {
	t.Helper()
	t.Cleanup(netpolLockoutGauge.Reset)
	p := probetest.NewCheckProber(cs, dyn, NewNetpolEgressLockoutGuardCheck)
	probetest.FreezeNow(p.Deps, now)
	return p
}

func netpolLockoutPod(ns, name string, lbls map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
			Labels:    lbls,
			UID:       types.UID("uid-" + ns + "-" + name),
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func TestNetpolEgressLockoutGuard(t *testing.T) {
	now := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)

	t.Run("single default-deny Egress NetworkPolicy flags dns_egress_blocked and emits Warning Event", func(t *testing.T) {
		pod := netpolLockoutPod("apps", "web-1", map[string]string{"app": "web"})
		denyNP := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:         "apps",
				Name:              "default-deny-egress",
				CreationTimestamp: metav1.NewTime(now.Add(-time.Hour)),
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			},
		}

		cs := fake.NewSimpleClientset(pod, denyNP)
		dyn := testutil.NewDynamicClientWithCRDs()
		p := netpolLockoutTestProber(t, cs, dyn, now)
		chk := probetest.MustCheck[*netpolLockoutCheck](t, p)

		sctx := probetest.SweepCtx(context.Background(), chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)

		if res.Pass {
			t.Fatalf("expected FAIL for default-deny egress NP, got %+v", res)
		}
		if !strings.Contains(res.Why, "apps/web-1 (dns_egress_blocked") {
			t.Fatalf("unexpected Why: %q", res.Why)
		}
		if m := probetest.FindMetric(t, "node_automation_netpol_egress_lockout", map[string]string{
			"namespace": "apps", "pod": "web-1", "reason": netpolLockoutReasonDNS,
		}); m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatalf("expected dns_egress_blocked=1, got %v", m)
		}
		// Simple web pod must NOT false-positive on apiserver_egress_blocked.
		if m := probetest.FindMetric(t, "node_automation_netpol_egress_lockout", map[string]string{
			"namespace": "apps", "pod": "web-1", "reason": netpolLockoutReasonAPIServer,
		}); m != nil {
			t.Fatalf("unexpected apiserver_egress_blocked on simple web pod: %v", m)
		}

		evs, err := cs.EventsV1().Events("apps").List(context.Background(), metav1.ListOptions{})
		if err != nil || len(evs.Items) != 1 || evs.Items[0].Reason != netpolLockoutEventReason {
			t.Fatalf("expected 1 Warning Event, got err=%v items=%+v", err, evs.Items)
		}
	})

	t.Run("companion allow-dns NetworkPolicy prevents false positive on simple web pod", func(t *testing.T) {
		pod := netpolLockoutPod("apps", "web-1", map[string]string{"app": "web"})
		denyNP := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "default-deny-egress"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			},
		}
		udp := corev1.ProtocolUDP
		allowDNS := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "allow-dns"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				Egress: []networkingv1.NetworkPolicyEgressRule{{
					To: []networkingv1.NetworkPolicyPeer{{
						NamespaceSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"},
						},
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"k8s-app": "kube-dns"},
						},
					}},
					Ports: []networkingv1.NetworkPolicyPort{{
						Protocol: &udp,
						Port:     ptr.To(intstr.FromInt32(53)),
					}},
				}},
			},
		}

		cs := fake.NewSimpleClientset(pod, denyNP, allowDNS)
		dyn := testutil.NewDynamicClientWithCRDs()
		p := netpolLockoutTestProber(t, cs, dyn, now)
		chk := probetest.MustCheck[*netpolLockoutCheck](t, p)

		sctx := probetest.SweepCtx(context.Background(), chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)

		if !res.Pass {
			t.Fatalf("expected PASS with companion allow-dns NP, got %+v", res)
		}
	})

	t.Run("CNP with toEntities kube-apiserver plus DNS allowed vs locked out", func(t *testing.T) {
		ctrlPod := netpolLockoutPod("ops", "my-controller-0", map[string]string{"app": "my-controller"})
		ctrlPod.Spec.ServiceAccountName = "my-controller-sa"
		ctrlPod.Spec.Containers = []corev1.Container{{
			Name: "ctrl",
			Env:  []corev1.EnvVar{{Name: "KUBERNETES_SERVICE_HOST", Value: "10.96.0.1"}},
		}}

		// Case A: CNP allows kube-apiserver AND kube-dns -> PASS.
		cnpBoth := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "cilium.io/v2",
			"kind":       "CiliumNetworkPolicy",
			"metadata":   map[string]any{"namespace": "ops", "name": "ctrl-egress"},
			"spec": map[string]any{
				"endpointSelector": map[string]any{
					"matchLabels": map[string]any{"app": "my-controller"},
				},
				"egress": []any{
					map[string]any{
						"toEntities": []any{"kube-apiserver"},
					},
					map[string]any{
						"toEndpoints": []any{
							map[string]any{
								"matchLabels": map[string]any{
									"k8s:io.kubernetes.pod.namespace": "kube-system",
									"k8s:k8s-app":                     "kube-dns",
								},
							},
						},
						"toPorts": []any{
							map[string]any{
								"ports": []any{map[string]any{"port": "53", "protocol": "ANY"}},
							},
						},
					},
				},
			},
		}}

		cs := fake.NewSimpleClientset(ctrlPod)
		dyn := testutil.NewDynamicClientWithCRDs(cnpBoth)
		p := netpolLockoutTestProber(t, cs, dyn, now)
		chk := probetest.MustCheck[*netpolLockoutCheck](t, p)

		sctx := probetest.SweepCtx(context.Background(), chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)
		if !res.Pass {
			t.Fatalf("expected PASS when CNP allows both kube-apiserver and DNS, got %+v", res)
		}

		// Case B: CNP allows ONLY kube-apiserver -> flags dns_egress_blocked only.
		cnpAPIOnly := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "cilium.io/v2",
			"kind":       "CiliumNetworkPolicy",
			"metadata":   map[string]any{"namespace": "ops", "name": "ctrl-egress"},
			"spec": map[string]any{
				"endpointSelector": map[string]any{
					"matchLabels": map[string]any{"app": "my-controller"},
				},
				"egress": []any{
					map[string]any{"toEntities": []any{"kube-apiserver"}},
				},
			},
		}}
		dynAPIOnly := testutil.NewDynamicClientWithCRDs(cnpAPIOnly)
		p2 := netpolLockoutTestProber(t, cs, dynAPIOnly, now)
		chk2 := probetest.MustCheck[*netpolLockoutCheck](t, p2)
		sctx2 := probetest.SweepCtx(context.Background(), chk2.Deps)
		res2 := chk2.Run(sctx2)
		probetest.VerifySweep(sctx2)
		if res2.Pass || !strings.Contains(res2.Why, netpolLockoutReasonDNS) || strings.Contains(res2.Why, netpolLockoutReasonAPIServer) {
			t.Fatalf("expected only dns_egress_blocked, got %+v", res2)
		}

		// Case C: CNP allows ONLY DNS -> controller pod flags apiserver_egress_blocked only.
		cnpDNSOnly := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "cilium.io/v2",
			"kind":       "CiliumNetworkPolicy",
			"metadata":   map[string]any{"namespace": "ops", "name": "ctrl-egress"},
			"spec": map[string]any{
				"endpointSelector": map[string]any{
					"matchLabels": map[string]any{"app": "my-controller"},
				},
				"egress": []any{
					map[string]any{
						"toEndpoints": []any{
							map[string]any{
								"matchLabels": map[string]any{
									"k8s:io.kubernetes.pod.namespace": "kube-system",
									"k8s:k8s-app":                     "kube-dns",
								},
							},
						},
						"toPorts": []any{
							map[string]any{
								"ports": []any{map[string]any{"port": "53", "protocol": "UDP"}},
							},
						},
					},
				},
			},
		}}
		dynDNSOnly := testutil.NewDynamicClientWithCRDs(cnpDNSOnly)
		p3 := netpolLockoutTestProber(t, cs, dynDNSOnly, now)
		chk3 := probetest.MustCheck[*netpolLockoutCheck](t, p3)
		sctx3 := probetest.SweepCtx(context.Background(), chk3.Deps)
		res3 := chk3.Run(sctx3)
		probetest.VerifySweep(sctx3)
		if res3.Pass || !strings.Contains(res3.Why, netpolLockoutReasonAPIServer) || strings.Contains(res3.Why, netpolLockoutReasonDNS) {
			t.Fatalf("expected only apiserver_egress_blocked, got %+v", res3)
		}
	})

	t.Run("CNP 404 skips cleanly without Infra error", func(t *testing.T) {
		pod := netpolLockoutPod("apps", "web-1", map[string]string{"app": "web"})
		cs := fake.NewSimpleClientset(pod)
		dyn := testutil.NewDynamicClientWithCRDs()
		dyn.PrependReactor("list", "ciliumnetworkpolicies", func(action ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(schema.GroupResource{Group: "cilium.io", Resource: "ciliumnetworkpolicies"}, "")
		})

		p := netpolLockoutTestProber(t, cs, dyn, now)
		chk := probetest.MustCheck[*netpolLockoutCheck](t, p)
		sctx := probetest.SweepCtx(context.Background(), chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)
		if !res.Pass || res.Infra != nil {
			t.Fatalf("expected PASS with nil Infra on CNP 404, got %+v", res)
		}
	})

	t.Run("PromQL policy-drop spike correlates recent policy in finding and Warning Event", func(t *testing.T) {
		pod := netpolLockoutPod("payments", "checkout-0", map[string]string{"app": "checkout"})
		recentNP := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:         "payments",
				Name:              "tight-egress",
				CreationTimestamp: metav1.NewTime(now.Add(-5 * time.Minute)),
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "checkout"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			},
		}

		srv, lastQuery := probetest.PromTestServer(t, func(query string) []probetest.PromTestSample {
			if strings.Contains(query, "cilium_drop_count_total") {
				return []probetest.PromTestSample{{
					Labels: map[string]string{"namespace": "payments"},
					Value:  42,
				}}
			}
			return nil
		})

		cs := fake.NewSimpleClientset(pod, recentNP)
		dyn := testutil.NewDynamicClientWithCRDs()
		p := netpolLockoutTestProber(t, cs, dyn, now)
		p.Cfg.HTTPContent.URL = srv.URL
		p.HTTPClient = srv.Client()
		chk := probetest.MustCheck[*netpolLockoutCheck](t, p)

		sctx := probetest.SweepCtx(context.Background(), chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)

		if res.Pass {
			t.Fatalf("expected FAIL, got %+v", res)
		}
		if !strings.Contains(*lastQuery, "cilium_drop_count_total") {
			t.Fatalf("expected PromQL query on cilium_drop_count_total, got %q", *lastQuery)
		}
		if !strings.Contains(res.Why, "NetworkPolicy/tight-egress") || !strings.Contains(res.Why, "42 cilium policy drops/15m") {
			t.Fatalf("expected correlated recent policy + drop count in Why, got %q", res.Why)
		}
		evs, _ := cs.EventsV1().Events("payments").List(context.Background(), metav1.ListOptions{})
		if len(evs.Items) != 1 || !strings.Contains(evs.Items[0].Note, "NetworkPolicy/tight-egress") ||
			!strings.Contains(evs.Items[0].Note, "42 cilium policy drops/15m") {
			t.Fatalf("expected correlated policy in Warning Event note, got %+v", evs.Items)
		}
	})

	t.Run("PromQL server 500 error does not fail check (best-effort correlation)", func(t *testing.T) {
		pod := netpolLockoutPod("apps", "web-1", map[string]string{"app": "web"})
		denyNP := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "deny"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			},
		}
		cs := fake.NewSimpleClientset(pod, denyNP)
		p := netpolLockoutTestProber(t, cs, testutil.NewDynamicClientWithCRDs(), now)
		p.HTTPClient = &http.Client{
			Transport: netpolLockoutRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusInternalServerError, Body: http.NoBody}, nil
			}),
		}
		chk := probetest.MustCheck[*netpolLockoutCheck](t, p)
		sctx := probetest.SweepCtx(context.Background(), chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)
		if res.Pass || res.Infra != nil {
			t.Fatalf("expected FAIL with nil Infra when PromQL fails best-effort, got %+v", res)
		}
	})

	t.Run("CNP egressDeny-only non-DNS does not false-positive, egressDeny DNS overrides allow, and opt-out annotation skips", func(t *testing.T) {
		pod := netpolLockoutPod("apps", "web-1", map[string]string{"app": "web"})
		optedOut := netpolLockoutPod("apps", "sandbox-0", map[string]string{"app": "sandbox"})
		optedOut.Annotations = map[string]string{netpolLockoutIgnoreAnno: "true"}

		// CNP with ONLY egressDeny on SMTP port 25 -> must NOT trigger DNS lockout.
		denySMTP := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "cilium.io/v2",
			"kind":       "CiliumNetworkPolicy",
			"metadata":   map[string]any{"namespace": "apps", "name": "deny-smtp"},
			"spec": map[string]any{
				"endpointSelector": map[string]any{"matchLabels": map[string]any{"app": "web"}},
				"egressDeny": []any{
					map[string]any{
						"toPorts": []any{map[string]any{"ports": []any{map[string]any{"port": "25"}}}},
					},
				},
			},
		}}
		// CNP in apps with egressDeny on sandbox pod (opted out) -> skipped.
		denySandbox := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "cilium.io/v2",
			"kind":       "CiliumNetworkPolicy",
			"metadata":   map[string]any{"namespace": "apps", "name": "sandbox-deny"},
			"spec": map[string]any{
				"endpointSelector": map[string]any{"matchLabels": map[string]any{"app": "sandbox"}},
				"egress":           []any{},
			},
		}}
		cs := fake.NewSimpleClientset(pod, optedOut)
		dyn := testutil.NewDynamicClientWithCRDs(denySMTP, denySandbox)
		p := netpolLockoutTestProber(t, cs, dyn, now)
		chk := probetest.MustCheck[*netpolLockoutCheck](t, p)

		sctx := probetest.SweepCtx(context.Background(), chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)
		if !res.Pass {
			t.Fatalf("expected PASS for egressDeny-SMTP and opted-out sandbox, got %+v", res)
		}

		// Companion allow-DNS NP + CNP egressDeny blocking port 53 -> MUST flag dns_egress_blocked!
		allowDNS := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "allow-dns"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
				Egress: []networkingv1.NetworkPolicyEgressRule{{
					Ports: []networkingv1.NetworkPolicyPort{{Port: ptr.To(intstr.FromInt32(53))}},
				}},
			},
		}
		denyDNS := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "cilium.io/v2",
			"kind":       "CiliumNetworkPolicy",
			"metadata":   map[string]any{"namespace": "apps", "name": "deny-dns"},
			"spec": map[string]any{
				"endpointSelector": map[string]any{"matchLabels": map[string]any{"app": "web"}},
				"egressDeny": []any{
					map[string]any{
						"toPorts": []any{map[string]any{"ports": []any{map[string]any{"port": "53"}}}},
					},
				},
			},
		}}
		cs2 := fake.NewSimpleClientset(pod, allowDNS)
		dyn2 := testutil.NewDynamicClientWithCRDs(denyDNS)
		p2 := netpolLockoutTestProber(t, cs2, dyn2, now)
		chk2 := probetest.MustCheck[*netpolLockoutCheck](t, p2)

		sctx2 := probetest.SweepCtx(context.Background(), chk2.Deps)
		res2 := chk2.Run(sctx2)
		probetest.VerifySweep(sctx2)
		if res2.Pass || !strings.Contains(res2.Why, netpolLockoutReasonDNS) {
			t.Fatalf("expected dns_egress_blocked when egressDeny overrides allow NP, got %+v", res2)
		}

		// CNP in apps with toEndpoints: [{}] (no namespace label) does NOT reach kube-system DNS.
		cnpSameNS := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "cilium.io/v2",
			"kind":       "CiliumNetworkPolicy",
			"metadata":   map[string]any{"namespace": "apps", "name": "same-ns-only"},
			"spec": map[string]any{
				"endpointSelector": map[string]any{"matchLabels": map[string]any{"app": "web"}},
				"egress": []any{
					map[string]any{
						"toEndpoints": []any{map[string]any{}},
						"toPorts":     []any{map[string]any{"ports": []any{map[string]any{"port": "53"}}}},
					},
				},
			},
		}}
		cs3 := fake.NewSimpleClientset(pod)
		dyn3 := testutil.NewDynamicClientWithCRDs(cnpSameNS)
		p3 := netpolLockoutTestProber(t, cs3, dyn3, now)
		chk3 := probetest.MustCheck[*netpolLockoutCheck](t, p3)
		sctx3 := probetest.SweepCtx(context.Background(), chk3.Deps)
		res3 := chk3.Run(sctx3)
		probetest.VerifySweep(sctx3)
		if res3.Pass || !strings.Contains(res3.Why, netpolLockoutReasonDNS) {
			t.Fatalf("expected dns_egress_blocked when CNP toEndpoints lacks kube-system namespace, got %+v", res3)
		}
	})

	t.Run("CiliumClusterwideNetworkPolicy evaluated and nodeSelector host policies ignored", func(t *testing.T) {
		pod := netpolLockoutPod("apps", "web-1", map[string]string{"app": "web"})
		ccnpNodeOnly := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "cilium.io/v2",
			"kind":       "CiliumClusterwideNetworkPolicy",
			"metadata":   map[string]any{"name": "host-fw"},
			"spec": map[string]any{
				"nodeSelector": map[string]any{"matchLabels": map[string]any{"role": "worker"}},
				"egress":       []any{},
			},
		}}
		ccnpPodLockout := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "cilium.io/v2",
			"kind":       "CiliumClusterwideNetworkPolicy",
			"metadata":   map[string]any{"name": "cluster-deny-dns"},
			"spec": map[string]any{
				"endpointSelector": map[string]any{"matchLabels": map[string]any{"app": "web"}},
				"egress":           []any{},
			},
		}}

		cs := fake.NewSimpleClientset(pod)
		pHost := netpolLockoutTestProber(t, cs, testutil.NewDynamicClientWithCRDs(ccnpNodeOnly), now)
		chkHost := probetest.MustCheck[*netpolLockoutCheck](t, pHost)
		if res := chkHost.Run(probetest.SweepCtx(context.Background(), chkHost.Deps)); !res.Pass {
			t.Fatalf("nodeSelector-only CCNP must not flag pod: %+v", res)
		}

		pLock := netpolLockoutTestProber(t, cs, testutil.NewDynamicClientWithCRDs(ccnpPodLockout), now)
		chkLock := probetest.MustCheck[*netpolLockoutCheck](t, pLock)
		res := chkLock.Run(probetest.SweepCtx(context.Background(), chkLock.Deps))
		if res.Pass || !strings.Contains(res.Why, "CiliumClusterwideNetworkPolicy/cluster-deny-dns") {
			t.Fatalf("expected CCNP lockout finding, got %+v", res)
		}
	})

	t.Run("partial 403 carries forward held tuples without clearing", func(t *testing.T) {
		pod := netpolLockoutPod("apps", "web-1", map[string]string{"app": "web"})
		denyCNP := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "cilium.io/v2",
			"kind":       "CiliumNetworkPolicy",
			"metadata":   map[string]any{"namespace": "apps", "name": "deny-all"},
			"spec": map[string]any{
				"endpointSelector": map[string]any{"matchLabels": map[string]any{"app": "web"}},
				"egress":           []any{},
			},
		}}
		cs := fake.NewSimpleClientset(pod)
		dyn := testutil.NewDynamicClientWithCRDs(denyCNP)
		p := netpolLockoutTestProber(t, cs, dyn, now)
		chk := probetest.MustCheck[*netpolLockoutCheck](t, p)

		// Sweep 1 flags via CNP.
		if res := chk.Run(probetest.SweepCtx(context.Background(), chk.Deps)); res.Pass {
			t.Fatalf("expected FAIL on sweep 1, got %+v", res)
		}

		// Sweep 2: NP succeeds (empty), CNP returns 403 -> partial 403 must carry held tuple.
		dyn.PrependReactor("list", "ciliumnetworkpolicies", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "cilium.io", Resource: "ciliumnetworkpolicies"}, "", apierrors.NewUnauthorized("rbac"))
		})
		res2 := chk.Run(probetest.SweepCtx(context.Background(), chk.Deps))
		if !res2.Pass || res2.Infra != nil {
			t.Fatalf("expected PASS with nil Infra on partial 403 carry, got %+v", res2)
		}
		if m := probetest.FindMetric(t, "node_automation_netpol_egress_lockout", map[string]string{
			"namespace": "apps", "pod": "web-1", "reason": netpolLockoutReasonDNS,
		}); m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatalf("expected held dns_egress_blocked=1 carried on partial 403, got %v", m)
		}
	})

	t.Run("ordinary Helm workload with non-default SA without API signals does not flag apiserver lockout", func(t *testing.T) {
		helmPod := netpolLockoutPod("apps", "my-nginx-0", map[string]string{"app": "nginx"})
		helmPod.Spec.ServiceAccountName = "my-nginx-sa"
		denyNP := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "default-deny-egress"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			},
		}
		cs := fake.NewSimpleClientset(helmPod, denyNP)
		p := netpolLockoutTestProber(t, cs, testutil.NewDynamicClientWithCRDs(), now)
		chk := probetest.MustCheck[*netpolLockoutCheck](t, p)
		res := chk.Run(probetest.SweepCtx(context.Background(), chk.Deps))
		if res.Pass {
			t.Fatalf("expected dns_egress_blocked failure, got %+v", res)
		}
		if strings.Contains(res.Why, netpolLockoutReasonAPIServer) {
			t.Fatalf("ordinary Helm pod with non-default SA must not flag apiserver_egress_blocked: %q", res.Why)
		}
	})
}

type netpolLockoutRoundTripFunc func(*http.Request) (*http.Response, error)

func (f netpolLockoutRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
