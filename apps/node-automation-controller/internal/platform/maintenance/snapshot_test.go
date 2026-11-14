// snapshot_test.go — unit tests for WithMaintenanceSnapshot and the
// provider-backed maintenanceNodeList / maintenanceDaemonSet paths.
package maintenance

import (
	"context"
	"errors"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

type stubSnapshotProvider struct {
	nodes    []corev1.Node
	nodesErr error
	ds       []appsv1.DaemonSet
	dsErr    error
}

func (s *stubSnapshotProvider) Nodes(_ context.Context) ([]corev1.Node, error) {
	return s.nodes, s.nodesErr
}

func (s *stubSnapshotProvider) DaemonSets(_ context.Context) ([]appsv1.DaemonSet, error) {
	return s.ds, s.dsErr
}

func TestWithMaintenanceSnapshot(t *testing.T) {
	t.Parallel()

	base := context.Background()
	if got := WithMaintenanceSnapshot(base, nil); got != base {
		t.Fatal("nil provider must return ctx unchanged")
	}

	prov := &stubSnapshotProvider{
		nodes: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "snap-node"}}},
		ds: []appsv1.DaemonSet{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "kured"},
		}},
	}
	ctx := WithMaintenanceSnapshot(base, prov)
	cs := fake.NewClientset()

	nodes, err := maintenanceNodeList(ctx, cs, nil)
	if err != nil || len(nodes) != 1 || nodes[0].Name != "snap-node" {
		t.Fatalf("maintenanceNodeList = %v, %v", nodes, err)
	}

	ds, err := maintenanceDaemonSet(ctx, cs, "kube-system", "kured")
	if err != nil || ds == nil || ds.Name != "kured" {
		t.Fatalf("maintenanceDaemonSet(hit) = %v, %v", ds, err)
	}

	if ds, err := maintenanceDaemonSet(ctx, cs, "kube-system", "absent"); err != nil || ds != nil {
		t.Fatalf("maintenanceDaemonSet(miss) = %v, %v, want (nil, nil)", ds, err)
	}

	provErr := &stubSnapshotProvider{dsErr: errors.New("ds list boom")}
	if _, err := maintenanceDaemonSet(WithMaintenanceSnapshot(base, provErr), cs, "kube-system", "kured"); err == nil {
		t.Fatal("expected ds list error to propagate")
	}
}
