// main_test.go — emit's markdown row rendering: empty cells become
// "—", populated cells get backtick-quoted. main() itself runs in a
// helper subprocess (the cmd/agent re-exec pattern): flag.Parse +
// os.Exit make it untestable in-process.
package main

import (
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestEmit(t *testing.T) {
	for name, tc := range map[string]struct {
		envFlag, subsystem, def, want string
	}{
		"full row": {
			envFlag:   "NODE_HOST_AGENT_ENABLE_SWEEPER",
			subsystem: "sweeper", def: "auto",
			want: "| `NODE_HOST_AGENT_ENABLE_SWEEPER` | sweeper | `auto` |\n",
		},
		"all empty": {
			want: "| — | — | — |\n",
		},
		"unwired gate (no subsystem/default)": {
			envFlag: "NODE_HOST_AGENT_ENABLE_FEEDER",
			want:    "| `NODE_HOST_AGENT_ENABLE_FEEDER` | — | — |\n",
		},
		"hubsync (no env gate)": {
			subsystem: "hubsync",
			want:      "| — | hubsync | — |\n",
		},
		"default onOff flip (both faces)": {
			envFlag:   "NODE_HOST_AGENT_ENABLE_SWEEPER",
			subsystem: "sweeper", def: "onOff(w.defKube)",
			want: "| `NODE_HOST_AGENT_ENABLE_SWEEPER` | sweeper | `on` (pod) / `off` (standalone) |\n",
		},
		"default ModeOn": {
			envFlag:   "NODE_HOST_AGENT_ENABLE_APIPROBER",
			subsystem: "apiprober", def: "envx.ModeOn",
			want: "| `NODE_HOST_AGENT_ENABLE_APIPROBER` | apiprober | `on` |\n",
		},
		"default ModeOff": {
			envFlag:   "NODE_HOST_AGENT_ENABLE_X",
			subsystem: "x", def: "envx.ModeOff",
			want: "| `NODE_HOST_AGENT_ENABLE_X` | x | `off` |\n",
		},
		"default ModeAuto": {
			envFlag:   "NODE_HOST_AGENT_ENABLE_KINEDB",
			subsystem: "kinedb", def: "envx.ModeAuto",
			want: "| `NODE_HOST_AGENT_ENABLE_KINEDB` | kinedb | `auto` |\n",
		},
		"unrecognized default falls back verbatim": {
			envFlag:   "NODE_HOST_AGENT_ENABLE_Y",
			subsystem: "y", def: "someOther(w)",
			want: "| `NODE_HOST_AGENT_ENABLE_Y` | y | `someOther(w)` |\n",
		},
	} {
		var b strings.Builder
		emitRow(&b, tc.envFlag, tc.subsystem, tc.def)
		if got := b.String(); got != tc.want {
			t.Fatalf("%s: emit row = %q want %q", name, got, tc.want)
		}
	}
}

// moduleRoot is the node-host-agent module root relative to this
// package's dir — go test runs each package with its own dir as
// working directory, so "../../../.." lands on the module root
// (genenvdoc → cmd → envdoc → internal → node-host-agent).
const moduleRoot = "../../../.."

// runMainInHelper re-execs the test binary as the genenvdoc command:
// the helper rebuilds flag.CommandLine (the testing binary already
// consumed it), points -root at root, and calls main(). env carries
// the helper's trigger var plus GENENVDOC_ROOT.
func runMainInHelper(t *testing.T, env string, root string) (stdout, stderr string, exitCode int) {
	t.Helper()
	if os.Getenv(env) == "1" {
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		os.Args = []string{"genenvdoc", "-root", os.Getenv("GENENVDOC_ROOT")}
		main()
		os.Exit(0) // unreachable on the fatal path — main exits 1
	}

	rootAbs, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run="+t.Name()+"$")
	cmd.Env = append(os.Environ(), env+"=1", "GENENVDOC_ROOT="+rootAbs)
	var so, se strings.Builder
	cmd.Stdout = &so
	cmd.Stderr = &se
	err = cmd.Run()
	if err == nil {
		return so.String(), se.String(), 0
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("helper failed without an exit status: %v", err)
	}
	return so.String(), se.String(), exitErr.ExitCode()
}

// TestMainRendersGatesTable runs main() end-to-end against the real
// module tree: the emitted table must carry the wired descriptor rows
// (source order, Default expressions rendered as their resolved
// tri-state value) plus the declared-but-unwired ENABLE_FEEDER gate
// appended at the end.
func TestMainRendersGatesTable(t *testing.T) {
	out, stderr, code := runMainInHelper(t, "GO_HELPER_GENENVDOC", moduleRoot)
	if code != 0 {
		t.Fatalf("genenvdoc exit=%d stderr=%q", code, stderr)
	}
	for _, want := range []string{
		"| `NODE_HOST_AGENT_ENABLE_SWEEPER` | sweeper | `on` (pod) / `off` (standalone) |",
		"| — | hubsync | — |",
		"| `NODE_HOST_AGENT_ENABLE_FEEDER` | — | — |",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing row %q:\n%s", want, out)
		}
	}
	// The unwired gate sorts after every wired row's emission —
	// gates emit first, unwired appended last.
	if strings.Index(out, "ENABLE_FEEDER") <
		strings.Index(out, "ENABLE_KINEDB") {
		t.Fatalf("unwired gate row not appended after wired rows:\n%s", out)
	}
}

// TestMainFatalOnBadRoot drives the fatal() tail: an unreadable
// -root makes CollectContract fail, fatal prints "genenvdoc: <err>"
// on stderr and exits 1 so the calling script's `set -e` leaves
// ENV.md untouched.
func TestMainFatalOnBadRoot(t *testing.T) {
	_, stderr, code := runMainInHelper(t, "GO_HELPER_GENENVDOC_BAD", "/nonexistent/genenvdoc-root")
	if code != 1 {
		t.Fatalf("genenvdoc exit=%d want 1 (stderr=%q)", code, stderr)
	}
	if !strings.Contains(stderr, "genenvdoc:") {
		t.Fatalf("stderr missing fatal prefix: %q", stderr)
	}
}
