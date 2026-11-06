// hostconverge_test.go — converge-once flag layer plus the HostRoot
// / RunnerFactory seams: usage exits, the missing-topology runtime
// failure, and the clean self-gating converge against a tempdir
// host root.

package hostconverge

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/hostconfig"
)

// quietRunner answers every host command with empty output + nil
// error — the converge then self-gates on topology alone (a node
// absent from the registry runs no group).
type quietRunner struct{}

func (quietRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	return "", nil
}

// stubHost points the production seams at a tempdir host root and a
// never-failing runner so Cmd runs a scripted converge instead of
// exec'ing real host commands.
func stubHost(t *testing.T) {
	t.Helper()
	oldRoot, oldRunner := HostRoot, RunnerFactory
	t.Cleanup(func() { HostRoot, RunnerFactory = oldRoot, oldRunner })
	HostRoot = t.TempDir()
	RunnerFactory = func() hostconfig.Runner { return quietRunner{} }
}

func TestCmdArgParsing(t *testing.T) {
	for _, args := range [][]string{
		{"--bogus"},
		{"--vars-dir"}, // value flag missing its argument
	} {
		if code := Cmd(context.Background(), args); code != 2 {
			t.Fatalf("Cmd(%v)=%d want 2", args, code)
		}
	}
	// -h/--help exit 0 — flag.ErrHelp is a clean exit, not a usage
	// error.
	for _, h := range []string{"-h", "--help"} {
		if code := Cmd(context.Background(), []string{h}); code != 0 {
			t.Fatalf("Cmd(%s)=%d want 0", h, code)
		}
	}
}

func TestCmdMissingTopology(t *testing.T) {
	stubHost(t)
	// A vars dir without the topology files → the cycle counts the
	// load error and the command exits 1 (converge-once reports
	// errs > 0 — the timer/CI "did not converge" contract).
	code := Cmd(context.Background(), []string{
		"--vars-dir=" + t.TempDir(), "--node-name=testnode"})
	if code != 1 {
		t.Fatalf("Cmd(missing topology)=%d want 1", code)
	}
}

func TestCmdCleanConverge(t *testing.T) {
	stubHost(t)
	dir := t.TempDir()
	for name, content := range map[string]string{
		"interdc_nodes.yaml": "{}\n",
		"cluster.yaml":       "{}\n",
		"defaults.yaml":      "interdc_nebula_enabled: false\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A node absent from the registry self-gates every group →
	// errs == 0 → exit 0 (the timer/CI "converged" contract).
	code := Cmd(context.Background(), []string{
		"--vars-dir=" + dir, "--node-name=testnode"})
	if code != 0 {
		t.Fatalf("Cmd(clean converge)=%d want 0", code)
	}
}
