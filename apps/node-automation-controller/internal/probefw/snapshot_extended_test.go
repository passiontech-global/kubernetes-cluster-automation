package probefw

import (
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestExtendedSnapshotCensusesAndServicesByNS(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "app"}},
		&networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "nginx"}},
		&storagev1.StorageClass{ObjectMeta: metav1.ObjectMeta{Name: "fast"}, Provisioner: "ebs.csi.aws.com"},
		&networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "deny-all", Namespace: "app"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "crb-1"}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "rb-1", Namespace: "app"}},
		&corev1.ResourceQuota{ObjectMeta: metav1.ObjectMeta{Name: "rq-1", Namespace: "app"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "svc-a", Namespace: "app"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "svc-b", Namespace: "other"}},
	)

	resources := []string{
		"ingresses",
		"ingressclasses",
		"storageclasses",
		"networkpolicies",
		"clusterrolebindings",
		"rolebindings",
		"resourcequotas",
		"services",
	}
	counts := make(map[string]*atomic.Int32, len(resources))
	for _, r := range resources {
		var c atomic.Int32
		counts[r] = &c
		counter := &c
		cs.PrependReactor("list", r, func(ktesting.Action) (bool, runtime.Object, error) {
			counter.Add(1)
			return false, nil, nil
		})
	}

	d := &Deps{CS: cs}
	ctx := WithSweepSnapshot(t.Context(), d)

	// Query every extended memo twice within one sweep; each resource should issue 1 LIST.
	for range 2 {
		if items, err := d.AllIngresses(ctx); err != nil || len(items) != 1 {
			t.Fatalf("AllIngresses = (%d, %v), want (1, nil)", len(items), err)
		}
		if items, err := d.AllIngressClasses(ctx); err != nil || len(items) != 1 {
			t.Fatalf("AllIngressClasses = (%d, %v), want (1, nil)", len(items), err)
		}
		if items, err := d.AllStorageClasses(ctx); err != nil || len(items) != 1 {
			t.Fatalf("AllStorageClasses = (%d, %v), want (1, nil)", len(items), err)
		}
		if items, err := d.AllNetworkPolicies(ctx); err != nil || len(items) != 1 {
			t.Fatalf("AllNetworkPolicies = (%d, %v), want (1, nil)", len(items), err)
		}
		if items, err := d.AllClusterRoleBindings(ctx); err != nil || len(items) != 1 {
			t.Fatalf("AllClusterRoleBindings = (%d, %v), want (1, nil)", len(items), err)
		}
		if items, err := d.AllRoleBindings(ctx); err != nil || len(items) != 1 {
			t.Fatalf("AllRoleBindings = (%d, %v), want (1, nil)", len(items), err)
		}
		if items, err := d.AllResourceQuotas(ctx); err != nil || len(items) != 1 {
			t.Fatalf("AllResourceQuotas = (%d, %v), want (1, nil)", len(items), err)
		}
	}

	appSvcs, err := d.ServicesByNS(ctx, "app")
	if err != nil || len(appSvcs) != 1 || appSvcs[0].Name != "svc-a" {
		t.Fatalf("ServicesByNS(app) = (%v, %v), want [svc-a]", appSvcs, err)
	}
	otherSvcs, err := d.ServicesByNS(ctx, "other")
	if err != nil || len(otherSvcs) != 1 || otherSvcs[0].Name != "svc-b" {
		t.Fatalf("ServicesByNS(other) = (%v, %v), want [svc-b]", otherSvcs, err)
	}
	if emptySvcs, err := d.ServicesByNS(ctx, "missing"); err != nil || len(emptySvcs) != 0 {
		t.Fatalf("ServicesByNS(missing) = (%v, %v), want empty", emptySvcs, err)
	}

	for _, r := range resources {
		if got := counts[r].Load(); got != 1 {
			t.Fatalf("resource %q LIST count = %d, want 1", r, got)
		}
	}

	// InvalidateSweep resets memos so the next lookup issues a fresh LIST.
	d.InvalidateSweep(ctx)
	if items, err := d.AllIngresses(ctx); err != nil || len(items) != 1 {
		t.Fatalf("AllIngresses after invalidate = (%d, %v)", len(items), err)
	}
	if got := counts["ingresses"].Load(); got != 2 {
		t.Fatalf("ingresses LIST count after InvalidateSweep = %d, want 2", got)
	}
}
