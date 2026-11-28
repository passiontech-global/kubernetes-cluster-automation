// service_cidr_exhaustion_guard_test.go — unit tests for service-cidr-exhaustion-guard.
package nethealth

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

func svcCIDRTestProber(t *testing.T, cs *fake.Clientset, now time.Time) *probetest.Prober {
	t.Helper()
	t.Cleanup(svcCIDRExhaustionGauge.Reset)
	p := probetest.NewCheckProber(cs, nil, NewServiceCIDRExhaustionGuardCheck)
	probetest.FreezeNow(p.Deps, now)
	return p
}

func svcCIDRMakeClusterIPServices(ns string, startHost, count int, basePrefix string) []runtime.Object {
	objs := make([]runtime.Object, 0, count)
	for i := range count {
		ip := fmt.Sprintf("%s.%d", basePrefix, startHost+i)
		objs = append(objs, &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: fmt.Sprintf("svc-%d", startHost+i)},
			Spec: corev1.ServiceSpec{
				ClusterIP:  ip,
				ClusterIPs: []string{ip},
			},
		})
	}
	return objs
}

func TestServiceCIDRExhaustionGuard(t *testing.T) {
	now := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)

	t.Run("ServiceCIDR discovery flags warning at >=80% and critical at >=90% with top-3 namespaces", func(t *testing.T) {
		cidrObj := &networkingv1.ServiceCIDR{
			ObjectMeta: metav1.ObjectMeta{Name: "kubernetes"},
			Spec: networkingv1.ServiceCIDRSpec{
				CIDRs: []string{"10.96.0.0/24"}, // usable capacity = 254
			},
		}

		var objs []runtime.Object
		objs = append(objs, cidrObj)
		// 204/254 = 80.3% (warning)
		// Top namespaces: alpha(100), beta(60), gamma(30), delta(14)
		objs = append(objs, svcCIDRMakeClusterIPServices("alpha", 1, 100, "10.96.0")...)
		objs = append(objs, svcCIDRMakeClusterIPServices("beta", 101, 60, "10.96.0")...)
		objs = append(objs, svcCIDRMakeClusterIPServices("gamma", 161, 30, "10.96.0")...)
		objs = append(objs, svcCIDRMakeClusterIPServices("delta", 191, 14, "10.96.0")...)
		// Headless service must be skipped.
		objs = append(objs, &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "delta", Name: "headless"},
			Spec:       corev1.ServiceSpec{ClusterIP: corev1.ClusterIPNone},
		})

		cs := fake.NewSimpleClientset(objs...)
		p := svcCIDRTestProber(t, cs, now)
		chk := probetest.MustCheck[*svcCIDRCheck](t, p)

		sctx := probetest.SweepCtx(context.Background(), chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)

		if res.Pass {
			t.Fatalf("expected FAIL at 80.3%% occupancy, got %+v", res)
		}
		if !strings.Contains(res.Why, "10.96.0.0/24") || !strings.Contains(res.Why, "[warning]") ||
			!strings.Contains(res.Why, "top=alpha(100),beta(60),gamma(30)") || strings.Contains(res.Why, "delta(") {
			t.Fatalf("unexpected Why: %q", res.Why)
		}
		if m := probetest.FindMetric(t, "node_automation_service_cidr_exhaustion", map[string]string{
			"pool_type": "cluster_ip", "pool": "10.96.0.0/24", "severity": "warning",
		}); m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatalf("expected warning gauge=1, got %v", m)
		}

		// Add 25 more -> 229/254 = 90.2% (critical); warning series must be pruned.
		for _, o := range svcCIDRMakeClusterIPServices("alpha", 205, 25, "10.96.0") {
			if _, err := cs.CoreV1().Services("alpha").Create(context.Background(), o.(*corev1.Service), metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
		}

		sctx2 := probetest.SweepCtx(context.Background(), chk.Deps)
		res2 := chk.Run(sctx2)
		probetest.VerifySweep(sctx2)

		if res2.Pass || !strings.Contains(res2.Why, "[critical]") {
			t.Fatalf("expected critical finding at 90.2%%, got %+v", res2)
		}
		if m := probetest.FindMetric(t, "node_automation_service_cidr_exhaustion", map[string]string{
			"pool_type": "cluster_ip", "pool": "10.96.0.0/24", "severity": "critical",
		}); m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatalf("expected critical gauge=1, got %v", m)
		}
		if m := probetest.FindMetric(t, "node_automation_service_cidr_exhaustion", map[string]string{
			"pool_type": "cluster_ip", "pool": "10.96.0.0/24", "severity": "warning",
		}); m != nil {
			t.Fatalf("expected stale warning series pruned, got %v", m)
		}
		evs, _ := cs.EventsV1().Events("kube-system").List(context.Background(), metav1.ListOptions{})
		if len(evs.Items) != 2 || evs.Items[0].Reason != svcCIDREventReason {
			t.Fatalf("expected 2 ServicePoolExhaustion events (warning then critical), got %+v", evs.Items)
		}
	})

	t.Run("env fallback activates on ServiceCIDR 404 or 403", func(t *testing.T) {
		for _, status := range []string{"404", "403"} {
			t.Run("status_"+status, func(t *testing.T) {
				t.Setenv("NODE_AUTOMATION_SERVICE_CLUSTER_CIDRS", "10.97.0.0/29") // usable = 6
				objs := svcCIDRMakeClusterIPServices("ns1", 1, 5, "10.97.0")      // 5/6 = 83.3%
				cs := fake.NewSimpleClientset(objs...)
				cs.PrependReactor("list", "servicecidrs", func(ktesting.Action) (bool, runtime.Object, error) {
					if status == "403" {
						return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "networking.k8s.io", Resource: "servicecidrs"}, "", fmt.Errorf("forbidden"))
					}
					return true, nil, apierrors.NewNotFound(schema.GroupResource{Group: "networking.k8s.io", Resource: "servicecidrs"}, "")
				})

				p := svcCIDRTestProber(t, cs, now)
				chk := probetest.MustCheck[*svcCIDRCheck](t, p)
				sctx := probetest.SweepCtx(context.Background(), chk.Deps)
				res := chk.Run(sctx)
				probetest.VerifySweep(sctx)

				if res.Pass || res.Infra != nil {
					t.Fatalf("expected FAIL without Infra on %s fallback, got %+v", status, res)
				}
				if !strings.Contains(res.Why, "10.97.0.0/29") {
					t.Fatalf("expected fallback CIDR in Why, got %q", res.Why)
				}
			})
		}
	})

	t.Run("IPv6 prefix does not overflow and handles /64 safely", func(t *testing.T) {
		cap64, unbounded := svcCIDRUsableCapacity(netip.MustParsePrefix("fd00:10:96::/64"))
		if !unbounded || cap64 != 0 {
			t.Fatalf("expected /64 IPv6 to be unbounded without overflow, got cap=%d unbounded=%v", cap64, unbounded)
		}
		cap120, unbounded120 := svcCIDRUsableCapacity(netip.MustParsePrefix("fd00:10:96::/120"))
		if unbounded120 || cap120 != 256 {
			t.Fatalf("expected /120 IPv6 cap=256, got cap=%d unbounded=%v", cap120, unbounded120)
		}

		cidrObj := &networkingv1.ServiceCIDR{
			ObjectMeta: metav1.ObjectMeta{Name: "ipv6"},
			Spec:       networkingv1.ServiceCIDRSpec{CIDRs: []string{"fd00:10:96::/64"}},
		}
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "v6-svc"},
			Spec:       corev1.ServiceSpec{ClusterIP: "fd00:10:96::1"},
		}
		cs := fake.NewSimpleClientset(cidrObj, svc)
		p := svcCIDRTestProber(t, cs, now)
		chk := probetest.MustCheck[*svcCIDRCheck](t, p)

		sctx := probetest.SweepCtx(context.Background(), chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)
		if !res.Pass {
			t.Fatalf("expected PASS for /64 IPv6 ServiceCIDR, got %+v", res)
		}
	})

	t.Run("NodePort saturation and custom range", func(t *testing.T) {
		t.Setenv("NODE_AUTOMATION_SERVICE_NODEPORT_RANGE", "31000-31009") // 10 ports
		t.Setenv("NODE_AUTOMATION_SERVICE_CIDR_WARN_PCT", "80")
		t.Setenv("NODE_AUTOMATION_SERVICE_CIDR_CRIT_PCT", "90")

		var objs []runtime.Object
		// 9 unique NodePorts (31000..31008) across 2 namespaces, plus 1 duplicate port on another Service.
		for i := range 6 {
			objs = append(objs, &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ingress", Name: fmt.Sprintf("np-%d", i)},
				Spec: corev1.ServiceSpec{
					Type:  corev1.ServiceTypeNodePort,
					Ports: []corev1.ServicePort{{Port: 80, NodePort: int32(31000 + i)}},
				},
			})
		}
		for i := range 3 {
			objs = append(objs, &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Namespace: "games", Name: fmt.Sprintf("np-g-%d", i)},
				Spec: corev1.ServiceSpec{
					Type:  corev1.ServiceTypeNodePort,
					Ports: []corev1.ServicePort{{Port: 80, NodePort: int32(31006 + i)}},
				},
			})
		}
		// Duplicate NodePort 31000 must not push count to 10/10.
		objs = append(objs, &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "dup"},
			Spec: corev1.ServiceSpec{
				Type:  corev1.ServiceTypeNodePort,
				Ports: []corev1.ServicePort{{Port: 80, NodePort: 31000}},
			},
		})

		cs := fake.NewSimpleClientset(objs...)
		p := svcCIDRTestProber(t, cs, now)
		chk := probetest.MustCheck[*svcCIDRCheck](t, p)

		sctx := probetest.SweepCtx(context.Background(), chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)

		if res.Pass {
			t.Fatalf("expected FAIL at 9/10 NodePorts, got %+v", res)
		}
		if !strings.Contains(res.Why, "nodeport 31000-31009 90.0% (9/10) [critical] top=ingress(6),games(3)") {
			t.Fatalf("unexpected Why: %q", res.Why)
		}
		if m := probetest.FindMetric(t, "node_automation_service_cidr_exhaustion", map[string]string{
			"pool_type": "nodeport", "pool": "31000-31009", "severity": "critical",
		}); m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatalf("expected nodeport critical gauge=1, got %v", m)
		}
	})

	t.Run("TCP+UDP same NodePort counted once and warn > crit clamps critPct to warnPct", func(t *testing.T) {
		t.Setenv("NODE_AUTOMATION_SERVICE_NODEPORT_RANGE", "31000-31009")
		t.Setenv("NODE_AUTOMATION_SERVICE_CIDR_WARN_PCT", "85")
		t.Setenv("NODE_AUTOMATION_SERVICE_CIDR_CRIT_PCT", "70")

		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "dns", Name: "coredns-np"},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeNodePort,
				Ports: []corev1.ServicePort{
					{Port: 53, Protocol: corev1.ProtocolUDP, NodePort: 31000},
					{Port: 53, Protocol: corev1.ProtocolTCP, NodePort: 31000},
				},
			},
		}
		cs := fake.NewSimpleClientset(svc)
		p := svcCIDRTestProber(t, cs, now)
		chk := probetest.MustCheck[*svcCIDRCheck](t, p)
		if chk.warnPct != 85 || chk.critPct != 85 {
			t.Fatalf("expected critPct clamped to warnPct=85, got warn=%d crit=%d", chk.warnPct, chk.critPct)
		}
		sctx := probetest.SweepCtx(context.Background(), chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)
		if !res.Pass {
			t.Fatalf("single shared TCP+UDP NodePort (10%%) must pass, got %+v", res)
		}
	})
}
