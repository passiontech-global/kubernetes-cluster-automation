package nodelabeler

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
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
	res, err := r.Reconcile(t.Context(), reconcile.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if res.RequeueAfter < 27*time.Minute || res.RequeueAfter >= 33*time.Minute {
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
	res, err := r.Reconcile(t.Context(), reconcile.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if res.RequeueAfter < 27*time.Minute || res.RequeueAfter >= 33*time.Minute {
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
	res, err := r.Reconcile(t.Context(), reconcile.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if res.RequeueAfter < 27*time.Minute || res.RequeueAfter >= 33*time.Minute {
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
	r := &nodeLabeler{cs: cs, queue: "node-labeler", configPath: cfg}
	before := testutil.QueueErrorCount(t, "node-labeler")
	res, err := r.Reconcile(t.Context(), reconcile.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if res.RequeueAfter < 27*time.Minute || res.RequeueAfter >= 33*time.Minute {
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

	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
		t.Fatal(err)
	}
	if first := nodePatchActions(cs); first != 2 { // worker role + workload label
		t.Fatalf("expected 2 patches on first pass, got %d", first)
	}

	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
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
	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err == nil {
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
	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
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
	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
		t.Fatalf("per-node patch failures must not error the reconcile: %v", err)
	}
	if got := testutil.GetNode(t, cs, "w2").Labels["passiontech.dev/workload"]; got != "app" {
		t.Fatalf("labels.txt entry not applied on w2 after w1's failure, got %q", got)
	}
	if got := testutil.GetNode(t, cs, "w1").Labels["passiontech.dev/workload"]; got != "" {
		t.Fatalf("workload label on w1 despite the failing patch: %q", got)
	}
}

// A successful patch must be mirrored into the in-memory byName
// snapshot: duplicate rows (and a worker-role row after the worker
// sweep) consult the same map for their already-applied check, and a
// stale map re-patches what the sweep just fixed.
func TestNodeLabelerInMemoryLabelsUpdated(t *testing.T) {
	t.Run("duplicate labels.txt row for the same node", func(t *testing.T) {
		cfg := writeLabelsFile(t,
			"passiontech.dev/workload=app w1\npassiontech.dev/workload=app w1\n")
		cs := fake.NewSimpleClientset(
			testutil.Node("w1", corev1.ConditionTrue, map[string]string{workerRoleLabel: ""}))
		r := &nodeLabeler{cs: cs, configPath: cfg}
		if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
			t.Fatal(err)
		}
		// The patch budget is the observable: the duplicate row must
		// read its own patch out of memory, not re-patch.
		if n := nodePatchActions(cs); n != 1 {
			t.Fatalf("expected 1 node patch for a duplicated row, got %d", n)
		}
	})

	t.Run("labels.txt row repeating the worker-role patch", func(t *testing.T) {
		cfg := writeLabelsFile(t, "node-role.kubernetes.io/worker= w1\n")
		cs := fake.NewSimpleClientset(testutil.Node("w1", corev1.ConditionTrue, nil))
		r := &nodeLabeler{cs: cs, configPath: cfg}
		if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
			t.Fatal(err)
		}
		// Worker sweep patches first, mirrors into the snapshot; the
		// file row then sees the label already applied.
		if n := nodePatchActions(cs); n != 1 {
			t.Fatalf("expected 1 node patch (worker role), got %d", n)
		}
	})

	t.Run("changed value on a duplicated row still re-patches", func(t *testing.T) {
		cfg := writeLabelsFile(t,
			"passiontech.dev/tier=db w1\npassiontech.dev/tier=cache w1\n")
		cs := fake.NewSimpleClientset(
			testutil.Node("w1", corev1.ConditionTrue, map[string]string{workerRoleLabel: ""}))
		r := &nodeLabeler{cs: cs, configPath: cfg}
		if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
			t.Fatal(err)
		}
		if n := nodePatchActions(cs); n != 2 {
			t.Fatalf("expected 2 node patches for two distinct values, got %d", n)
		}
		if got := testutil.GetNode(t, cs, "w1").Labels["passiontech.dev/tier"]; got != "cache" {
			t.Fatalf("final tier value = %q, want cache", got)
		}
	})
}

// A labels.txt read failure that is NOT a missing file (permissions,
// dangling symlink, volume trouble) silently disables file labels —
// it must be metered like every other absorbed failure.
func TestNodeLabelerReadFileErrorMetered(t *testing.T) {
	// A directory path: os.ReadFile fails with EISDIR, not NotExist.
	cfg := t.TempDir()
	cs := fake.NewSimpleClientset(
		testutil.Node("w1", corev1.ConditionTrue, map[string]string{workerRoleLabel: ""}))
	r := &nodeLabeler{cs: cs, queue: "node-labeler", configPath: cfg}
	before := testutil.QueueErrorCount(t, "node-labeler")

	if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
		t.Fatalf("read failure must not error the reconcile: %v", err)
	}
	if got := testutil.QueueErrorCount(t, "node-labeler") - before; got != 1 {
		t.Fatalf("labels.txt read failure not IncError'd, delta %v", got)
	}
}

// P0.2b — the one-way GA→deprecated compat sync fills missing
// beta.kubernetes.io/*, failure-domain.beta.kubernetes.io/* and
// master role labels so DaemonSets on deprecated selectors schedule
// again; already-synced nodes are not re-patched, and compatHeal=false
// disables the pass entirely.
func TestNodeLabelerCompatHeal(t *testing.T) {
	newFixture := func() *fake.Clientset {
		return fake.NewSimpleClientset(
			// GA labels present, deprecated twins missing.
			testutil.Node("w1", corev1.ConditionTrue, map[string]string{
				workerRoleLabel:               "",
				"kubernetes.io/os":            "linux",
				"kubernetes.io/arch":          "amd64",
				"topology.kubernetes.io/zone": "z1",
			}),
			// Control-plane: gains the master role labels too.
			testutil.Node("cp1", corev1.ConditionTrue, map[string]string{
				"node-role.kubernetes.io/control-plane": "",
				"kubernetes.io/os":                      "linux",
			}),
			// Fully synced — must not be re-patched.
			testutil.Node("w2", corev1.ConditionTrue, map[string]string{
				workerRoleLabel:         "",
				"kubernetes.io/os":      "linux",
				"beta.kubernetes.io/os": "linux",
			}),
		)
	}

	t.Run("syncs missing deprecated twins", func(t *testing.T) {
		cs := newFixture()
		r := &nodeLabeler{cs: cs, queue: "node-labeler",
			configPath: filepath.Join(t.TempDir(), "labels.txt"), compatHeal: true}
		if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
			t.Fatal(err)
		}
		w1 := testutil.GetNode(t, cs, "w1").Labels
		for k, v := range map[string]string{
			"beta.kubernetes.io/os":                  "linux",
			"beta.kubernetes.io/arch":                "amd64",
			"failure-domain.beta.kubernetes.io/zone": "z1",
		} {
			if w1[k] != v {
				t.Fatalf("w1 missing compat label %s=%q: %v", k, v, w1)
			}
		}
		cp1 := testutil.GetNode(t, cs, "cp1").Labels
		if cp1["beta.kubernetes.io/os"] != "linux" ||
			cp1["node-role.kubernetes.io/master"] != "" ||
			cp1["master"] != "" {
			t.Fatalf("cp1 compat labels wrong: %v", cp1)
		}
		// w2 was already synced — exactly 2 compat patches (w1, cp1);
		// the worker-role sweep patched nothing (all roles present).
		if n := nodePatchActions(cs); n != 2 {
			t.Fatalf("expected 2 compat patches, got %d", n)
		}
	})

	t.Run("disabled gate patches nothing", func(t *testing.T) {
		cs := newFixture()
		r := &nodeLabeler{cs: cs, queue: "node-labeler",
			configPath: filepath.Join(t.TempDir(), "labels.txt"), compatHeal: false}
		if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
			t.Fatal(err)
		}
		if n := nodePatchActions(cs); n != 0 {
			t.Fatalf("compatHeal=false still patched %d nodes", n)
		}
	})

	t.Run("idempotent second sweep", func(t *testing.T) {
		cs := newFixture()
		r := &nodeLabeler{cs: cs, queue: "node-labeler",
			configPath: filepath.Join(t.TempDir(), "labels.txt"), compatHeal: true}
		if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
			t.Fatal(err)
		}
		first := nodePatchActions(cs)
		if _, err := r.Reconcile(t.Context(), reconcile.Request{}); err != nil {
			t.Fatal(err)
		}
		if n := nodePatchActions(cs); n != first {
			t.Fatalf("second sweep issued %d extra patches", n-first)
		}
	})
}
