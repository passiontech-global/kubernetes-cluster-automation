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

// testOpts returns Options pointing at a tempdir host root and a
// never-failing runner so CmdWith runs a scripted converge instead of
// exec'ing real host commands.
func testOpts(t *testing.T) Options {
	t.Helper()
	return Options{
		HostRoot: t.TempDir(),
		Runner:   func() hostconfig.Runner { return quietRunner{} },
	}
}

func TestCmdArgParsing(t *testing.T) {
	for _, args := range [][]string{
		{"--bogus"},
		{"--vars-dir"}, // value flag missing its argument
	} {
		if code := CmdWith(context.Background(), args, testOpts(t)); code != 2 {
			t.Fatalf("CmdWith(%v)=%d want 2", args, code)
		}
	}
	// -h/--help exit 0 — flag.ErrHelp is a clean exit, not a usage
	// error.
	for _, h := range []string{"-h", "--help"} {
		if code := CmdWith(context.Background(), []string{h}, testOpts(t)); code != 0 {
			t.Fatalf("CmdWith(%s)=%d want 0", h, code)
		}
	}
}

func TestCmdMissingTopology(t *testing.T) {
	// A vars dir without the topology files → the cycle counts the
	// load error and the command exits 1 (converge-once reports
	// errs > 0 — the timer/CI "did not converge" contract).
	code := CmdWith(context.Background(), []string{
		"--vars-dir=" + t.TempDir(), "--node-name=testnode"}, testOpts(t))
	if code != 1 {
		t.Fatalf("CmdWith(missing topology)=%d want 1", code)
	}
}

func TestCmdCleanConverge(t *testing.T) {
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
	code := CmdWith(context.Background(), []string{
		"--vars-dir=" + dir, "--node-name=testnode"}, testOpts(t))
	if code != 0 {
		t.Fatalf("CmdWith(clean converge)=%d want 0", code)
	}
}

// No --node-name and no env override → the OS hostname is the final
// fallback (converge keeps it unlike the daemon's fail-loud path).
func TestCmdHostnameFallback(t *testing.T) {
	t.Setenv("NODE_HOST_AGENT_NODE_NAME", "")
	t.Setenv("NODE_NAME", "")
	code := CmdWith(context.Background(), []string{"--vars-dir=" + t.TempDir()}, testOpts(t))
	if code != 1 {
		t.Fatalf("CmdWith(no node name, missing topology)=%d want 1", code)
	}
}
