// pin_test.go — ReplicaPin coverage: the Enabled gate, the
// wantReplicas computation off a fake node list (incl. the no-touch
// disabled path and list-error propagation), and both WatchNodes
// branches completed through a StubManager builder.
package pinnedworkload

import (
	"context"
	"errors"
	"fmt"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// MinReplicas<=0 disables the pin entirely — the reconciler then
// never reads the node count and the patch body never sends
// spec.replicas, so a re-enabled standalone CPA is not fought.
func TestReplicaPinEnabled(t *testing.T) {
	for _, tc := range []struct {
		name string
		pin  ReplicaPin
		want bool
	}{
		{"zero minReplicas", ReplicaPin{MinReplicas: 0, NodesPerReplica: 1}, false},
		{"negative minReplicas", ReplicaPin{MinReplicas: -2, NodesPerReplica: 1}, false},
		{"one", ReplicaPin{MinReplicas: 1}, true},
		{"typical pin", ReplicaPin{MinReplicas: 4, NodesPerReplica: 2}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.pin.Enabled(); got != tc.want {
				t.Fatalf("Enabled=%v, want %v", got, tc.want)
			}
		})
	}
}

// Disabled Want returns (0, nil) WITHOUT touching the cluster — a
// node list there would mean the pin's off switch leaks cluster reads.
func TestReplicaPinWantDisabledSkipsList(t *testing.T) {
	cs := fake.NewSimpleClientset()
	var listed bool
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			listed = true
			return true, nil, errors.New("must not be called")
		})
	got, err := (ReplicaPin{}).Want(t.Context(), cs)
	if err != nil || got != 0 {
		t.Fatalf("Want=(%d, %v), want (0, nil)", got, err)
	}
	if listed {
		t.Fatal("disabled pin listed nodes — the disabled path must not " +
			"touch the cluster at all")
	}
}

// Want is the CPA "linear" formula over the live node count —
// max(minReplicas, ceil(totalNodes/nodesPerReplica)), see
// kube.ProportionalReplicas.
func TestReplicaPinWant(t *testing.T) {
	for _, tc := range []struct {
		name  string
		nodes int
		pin   ReplicaPin
		want  int32
	}{
		{"zero nodes floors at min", 0, ReplicaPin{MinReplicas: 4, NodesPerReplica: 1}, 4},
		{"below floor", 3, ReplicaPin{MinReplicas: 4, NodesPerReplica: 1}, 4},
		{"ceil rounds up", 9, ReplicaPin{MinReplicas: 4, NodesPerReplica: 2}, 5},
		{"ceil exact", 8, ReplicaPin{MinReplicas: 1, NodesPerReplica: 2}, 4},
		{"nodesPerReplica zero clamps to 1",
			5, ReplicaPin{MinReplicas: 2, NodesPerReplica: 0}, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs := make([]runtime.Object, 0, tc.nodes)
			for i := range tc.nodes {
				objs = append(objs, testutil.Node(
					fmt.Sprintf("n%d", i), corev1.ConditionTrue, nil))
			}
			cs := fake.NewSimpleClientset(objs...)
			got, err := tc.pin.Want(t.Context(), cs)
			if err != nil {
				t.Fatalf("want: %v", err)
			}
			if got != tc.want {
				t.Fatalf("Want=%d, want %d", got, tc.want)
			}
		})
	}
}

// A node list failure surfaces — the replica count must never be
// computed off a partial picture.
func TestReplicaPinWantListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	got, err := (ReplicaPin{MinReplicas: 4, NodesPerReplica: 1}).
		Want(t.Context(), cs)
	if err == nil {
		t.Fatal("expected error when the node list fails")
	}
	if got != 0 {
		t.Fatalf("Want=%d on list error, want 0", got)
	}
}

// WatchNodes: enabled installs the create/delete-only Node watch,
// disabled returns the builder untouched — both branches Complete
// into exactly one runnable on the stub manager. The watch-source
// count itself is not introspected (testutil watch-unit convention),
// but completing the enabled branch proves the wiring is well-formed.
func TestReplicaPinWatchNodes(t *testing.T) {
	noop := reconcile.Func(func(context.Context, reconcile.Request) (ctrl.Result, error) {
		return ctrl.Result{}, nil
	})
	for _, tc := range []struct {
		name string
		pin  ReplicaPin
	}{
		{"disabled keeps the bare builder", ReplicaPin{}},
		{"enabled adds the node watch", ReplicaPin{MinReplicas: 4, NodesPerReplica: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := testutil.NewStubManager()
			b := ctrl.NewControllerManagedBy(m).For(&appsv1.Deployment{})
			if err := tc.pin.WatchNodes(b, "pin-test-sweep").
				Complete(noop); err != nil {
				t.Fatalf("complete: %v", err)
			}
			if len(m.Added) != 1 {
				t.Fatalf("builder registered %d runnables, want 1", len(m.Added))
			}
		})
	}
}
