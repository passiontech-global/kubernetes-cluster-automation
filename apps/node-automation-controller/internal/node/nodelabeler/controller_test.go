package nodelabeler

import (
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func TestNodeLabeler(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "labels.txt")
	if err := os.WriteFile(cfg,
		[]byte("# comment\n\npassiontech.dev/workload=app w1 w2 gone-node\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cs := fake.NewSimpleClientset(
		testutil.Node("cp1", corev1.ConditionTrue,
			map[string]string{"node-role.kubernetes.io/control-plane": ""}),
		testutil.Node("w1", corev1.ConditionTrue, nil),
		testutil.Node("w2", corev1.ConditionTrue,
			map[string]string{"node-role.kubernetes.io/worker": ""}),
	)
	r := &nodeLabeler{cs: cs, configPath: cfg}
	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
		t.Fatal(err)
	}

	if _, ok := testutil.GetNode(t, cs, "cp1").Labels["node-role.kubernetes.io/worker"]; ok {
		t.Fatal("control-plane got a worker label")
	}
	if _, ok := testutil.GetNode(t, cs, "w1").Labels["node-role.kubernetes.io/worker"]; !ok {
		t.Fatal("worker role label not asserted")
	}
	if got := testutil.GetNode(t, cs, "w1").Labels["passiontech.dev/workload"]; got != "app" {
		t.Fatalf("labels.txt entry not applied, got %q", got)
	}
	if got := testutil.GetNode(t, cs, "w2").Labels["passiontech.dev/workload"]; got != "app" {
		t.Fatalf("labels.txt entry not applied on w2, got %q", got)
	}
	// gone-node does not exist -> warn+continue, no error.
}
