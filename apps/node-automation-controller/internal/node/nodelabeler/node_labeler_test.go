package nodelabeler

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// ---------------------------------------------------------------------------
// node-labeler
// ---------------------------------------------------------------------------

// nodePatchActions counts Patch calls issued against nodes — the
// observable difference between "label applied" and "already correct,
// skipped".
func nodePatchActions(cs *fake.Clientset) int {
	n := 0
	for _, a := range cs.Actions() {
		if a.GetVerb() == "patch" && a.GetResource().Resource == "nodes" {
			n++
		}
	}
	return n
}

func writeLabelsFile(t *testing.T, content string) string {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "labels.txt")
	if err := os.WriteFile(cfg, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// Worker-role sweep variants: both control-plane label flavours are
// skipped, an already-labeled worker is not re-patched, and an
// unlabeled worker gets node-role.kubernetes.io/worker.
func TestNodeLabelerWorkerRoleVariants(t *testing.T) {
	cs := fake.NewSimpleClientset(
		// control-plane label — skipped by the worker-role sweep.
		testutil.Node("cp1", corev1.ConditionTrue,
			map[string]string{"node-role.kubernetes.io/control-plane": ""}),
		// legacy master label — also treated as control-plane.
		testutil.Node("cp2", corev1.ConditionTrue,
			map[string]string{"node-role.kubernetes.io/master": ""}),
		// worker role already asserted — must not be re-patched.
		testutil.Node("w1", corev1.ConditionTrue,
			map[string]string{workerRoleLabel: ""}),
		// plain worker missing the role label — gets patched.
		testutil.Node("w2", corev1.ConditionTrue, nil),
	)
	r := &nodeLabeler{cs: cs, configPath: filepath.Join(t.TempDir(), "labels.txt")}
	res, err := r.Reconcile(ctx, reconcile.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if res.RequeueAfter != 30*time.Minute {
		t.Fatalf("expected 30m requeue, got %s", res.RequeueAfter)
	}

	for _, name := range []string{"cp1", "cp2"} {
		if _, ok := testutil.GetNode(t, cs, name).Labels[workerRoleLabel]; ok {
			t.Fatalf("control-plane node %s got a worker label", name)
		}
	}
	if _, ok := testutil.GetNode(t, cs, "w2").Labels[workerRoleLabel]; !ok {
		t.Fatal("worker role label not asserted on unlabeled worker")
	}
	// Exactly one patch: w2 only — cp nodes are skipped and w1
	// already carried the role label.
	if n := nodePatchActions(cs); n != 1 {
		t.Fatalf("expected exactly 1 node patch, got %d", n)
	}
}

// A missing labels.txt must not fail the reconcile and must not skip
// the worker-role sweep — the CM may simply not be mounted yet.
func TestNodeLabelerMissingConfigFile(t *testing.T) {
	cs := fake.NewSimpleClientset(testutil.Node("w1", corev1.ConditionTrue, nil))
	r := &nodeLabeler{cs: cs, configPath: filepath.Join(t.TempDir(), "no-such-labels.txt")}
	res, err := r.Reconcile(ctx, reconcile.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if res.RequeueAfter != 30*time.Minute {
		t.Fatalf("expected 30m requeue, got %s", res.RequeueAfter)
	}
	if _, ok := testutil.GetNode(t, cs, "w1").Labels[workerRoleLabel]; !ok {
		t.Fatal("worker role label not applied when config file is missing")
	}
	if n := nodePatchActions(cs); n != 1 {
		t.Fatalf("expected only the worker-role patch, got %d", n)
	}
}

// Same for a present-but-empty labels.txt.
func TestNodeLabelerEmptyConfigFile(t *testing.T) {
	cs := fake.NewSimpleClientset(testutil.Node("w1", corev1.ConditionTrue, nil))
	r := &nodeLabeler{cs: cs, configPath: writeLabelsFile(t, "")}
	res, err := r.Reconcile(ctx, reconcile.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if res.RequeueAfter != 30*time.Minute {
		t.Fatalf("expected 30m requeue, got %s", res.RequeueAfter)
	}
	if _, ok := testutil.GetNode(t, cs, "w1").Labels[workerRoleLabel]; !ok {
		t.Fatal("worker role label not applied when config file is empty")
	}
	if n := nodePatchActions(cs); n != 1 {
		t.Fatalf("expected only the worker-role patch, got %d", n)
	}
}

// labels.txt grammar: comment lines (# anywhere in leading whitespace),
// trailing comments after the node list, blank lines,
// "<key=val> node1 node2 ..." rows, already-correct labels
// (no-op, no patch), nodes that no longer exist (warn+continue, never
// an error) and rows naming a control-plane node (labels.txt applies
// to whatever is named — unlike the worker-role sweep).
func TestNodeLabelerLabelsFileParsing(t *testing.T) {
	cfg := writeLabelsFile(t, `# full-line comment — skipped

    # comment after leading whitespace — skipped too
passiontech.dev/workload=app w1 w2 ghost-node
passiontech.dev/tier=db w2  # trailing comment — words after # are not node names
passiontech.dev/already=set w1
passiontech.dev/vip=lb cp1
key-without-equals-sign-and-no-nodes
`)
	cs := fake.NewSimpleClientset(
		testutil.Node("cp1", corev1.ConditionTrue,
			map[string]string{"node-role.kubernetes.io/control-plane": ""}),
		testutil.Node("w1", corev1.ConditionTrue,
			map[string]string{"passiontech.dev/already": "set"}),
		testutil.Node("w2", corev1.ConditionTrue, nil),
	)
	r := &nodeLabeler{cs: cs, configPath: cfg}
	before := testutil.QueueErrorCount(t, "node-labeler")
	res, err := r.Reconcile(ctx, reconcile.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if res.RequeueAfter != 30*time.Minute {
		t.Fatalf("expected 30m requeue, got %s", res.RequeueAfter)
	}

	// The labels.txt sweep resolves node objects from the listed
	// snapshot — per-entry Nodes().Get would N+1 the apiserver.
	// (Checked before the testutil.GetNode assertions below, which
	// issue their own gets.)
	for _, a := range cs.Actions() {
		if a.GetVerb() == "get" && a.GetResource().Resource == "nodes" {
			t.Fatalf("labels.txt sweep issued a per-entry node get: %v", a)
		}
	}

	if got := testutil.GetNode(t, cs, "w1").Labels["passiontech.dev/workload"]; got != "app" {
		t.Fatalf("workload label not applied on w1, got %q", got)
	}
	if got := testutil.GetNode(t, cs, "w1").Labels["passiontech.dev/already"]; got != "set" {
		t.Fatalf("pre-existing label clobbered on w1, got %q", got)
	}
	w2 := testutil.GetNode(t, cs, "w2")
	if w2.Labels["passiontech.dev/workload"] != "app" ||
		w2.Labels["passiontech.dev/tier"] != "db" {
		t.Fatalf("labels.txt entries not applied on w2: %v", w2.Labels)
	}
	// ghost-node is absent from the cluster — warn+continue (and the
	// Reconcile above still returned nil), but it must be metered so
	// a lingering labels.txt entry is not invisible to alerting.
	if got := testutil.QueueErrorCount(t, "node-labeler") - before; got != 1 {
		t.Fatalf("ghost node not IncError'd, delta %v", got)
	}

	cp1 := testutil.GetNode(t, cs, "cp1")
	if got := cp1.Labels["passiontech.dev/vip"]; got != "lb" {
		t.Fatalf("labels.txt entry not applied on cp1, got %q", got)
	}
	if _, ok := cp1.Labels[workerRoleLabel]; ok {
		t.Fatal("control-plane node got a worker role label")
	}

	// Patch budget: w1 worker + w1 workload, w2 worker + w2 workload +
	// w2 tier, cp1 vip = 6. The already-correct label on w1, the ghost
	// node, comments, blanks and the node-less row produce none.
	if n := nodePatchActions(cs); n != 6 {
		t.Fatalf("expected 6 node patches, got %d", n)
	}
}

// A second sweep must be a pure no-op — every label already correct.
func TestNodeLabelerIdempotent(t *testing.T) {
	cfg := writeLabelsFile(t, "passiontech.dev/workload=app w1\n")
	cs := fake.NewSimpleClientset(testutil.Node("w1", corev1.ConditionTrue, nil))
	r := &nodeLabeler{cs: cs, configPath: cfg}

	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if first := nodePatchActions(cs); first != 2 { // worker role + workload label
		t.Fatalf("expected 2 patches on first pass, got %d", first)
	}

	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if n := nodePatchActions(cs); n != 2 {
		t.Fatalf("second reconcile issued %d extra patches — not idempotent", n-2)
	}
}

// A node list failure is a real error — labeling on a partial view
// must not happen.
func TestNodeLabelerListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	r := &nodeLabeler{cs: cs, configPath: filepath.Join(t.TempDir(), "labels.txt")}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err == nil {
		t.Fatal("expected error when the node list fails")
	}
}

// A worker-role patch failure warns + continues (never hot-loops):
// the sibling worker still gets labeled and the reconcile stays nil.
func TestNodeLabelerWorkerPatchErrorContinues(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("w1", corev1.ConditionTrue, nil),
		testutil.Node("w2", corev1.ConditionTrue, nil))
	cs.PrependReactor("patch", "nodes",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			if action.(ktesting.PatchAction).GetName() == "w1" {
				return true, nil, errors.New("patch rejected")
			}
			return false, nil, nil
		})
	r := &nodeLabeler{cs: cs, configPath: filepath.Join(t.TempDir(), "labels.txt")}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatalf("per-node patch failures must not error the reconcile: %v", err)
	}
	if _, ok := testutil.GetNode(t, cs, "w2").Labels[workerRoleLabel]; !ok {
		t.Fatal("w2 not labeled after w1's patch failure")
	}
	if _, ok := testutil.GetNode(t, cs, "w1").Labels[workerRoleLabel]; ok {
		t.Fatal("w1 labeled despite the failing patch")
	}
}

// Same warn+continue for labels.txt entries: a rejected per-node patch
// does not stop the rest of the file.
func TestNodeLabelerLabelsFilePatchErrorContinues(t *testing.T) {
	cfg := writeLabelsFile(t, "passiontech.dev/workload=app w1 w2\n")
	cs := fake.NewSimpleClientset(
		testutil.Node("w1", corev1.ConditionTrue, map[string]string{workerRoleLabel: ""}),
		testutil.Node("w2", corev1.ConditionTrue, map[string]string{workerRoleLabel: ""}))
	cs.PrependReactor("patch", "nodes",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			if action.(ktesting.PatchAction).GetName() == "w1" {
				return true, nil, errors.New("patch rejected")
			}
			return false, nil, nil
		})
	r := &nodeLabeler{cs: cs, configPath: cfg}
	if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
		t.Fatalf("per-node patch failures must not error the reconcile: %v", err)
	}
	if got := testutil.GetNode(t, cs, "w2").Labels["passiontech.dev/workload"]; got != "app" {
		t.Fatalf("labels.txt entry not applied on w2 after w1's failure, got %q", got)
	}
	if got := testutil.GetNode(t, cs, "w1").Labels["passiontech.dev/workload"]; got != "" {
		t.Fatalf("workload label on w1 despite the failing patch: %q", got)
	}
}
