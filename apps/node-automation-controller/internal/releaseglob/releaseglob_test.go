// Package releaseglob guards the release trigger contract: the
// `paths:` globs in .github/workflows/release-node-automation-controller.yml must
// name exactly the hostkit/jinja trees this module's ./cmd/... actually
// imports (plus the module's go.mod/go.sum). A stale glob silently
// fires empty releases; a missing one silently skips a release that
// shipped changed shared-library code. This test fails on either
// direction by comparing `go list -deps ./cmd/...` against the
// workflow file.
package releaseglob

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
)

const (
	modulePrefix = "github.com/passiontech-global/kubernetes-cluster-automation/"
	workflowRel  = ".github/workflows/release-node-automation-controller.yml"
	workflowGlob = "release-node-automation-controller.yml"
)

// moduleFiles are libs/hostkit module files that subpackage globs
// never match but that change the module's dependency graph.
var moduleFiles = []string{"libs/hostkit/go.mod", "libs/hostkit/go.sum"}

var pathEntryRe = regexp.MustCompile(`-\s+"(libs/[^"]+)"`)

// TestReleaseWorkflowGlobsMatchCmdDeps asserts the release workflow's
// libs/ path globs equal the hostkit/jinja subpackage roots imported
// by ./cmd/... (non-test deps), plus libs/hostkit's module files.
func TestReleaseWorkflowGlobsMatchCmdDeps(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain not in PATH: %v", err)
	}
	// layout: <root>/apps/node-automation-controller/internal/releaseglob/releaseglob_test.go
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	appDir := filepath.Dir(filepath.Dir(filepath.Dir(thisFile))) // .../apps/<app>
	root := filepath.Dir(filepath.Dir(appDir))                   // repo root

	raw, err := os.ReadFile(filepath.Join(root, workflowRel))
	if err != nil {
		t.Fatalf("read %s: %v", workflowRel, err)
	}
	declared := map[string]bool{}
	for _, m := range pathEntryRe.FindAllStringSubmatch(string(raw), -1) {
		g := m[1]
		g = strings.TrimSuffix(g, "/**")
		declared[g] = true
	}
	if len(declared) == 0 {
		t.Fatalf("no libs/ path entries found in %s — parser out of date?", workflowRel)
	}

	out, err := (func() ([]byte, error) {
		cmd := exec.Command("go", "list", "-deps", "./cmd/...")
		cmd.Dir = appDir
		cmd.Env = append(os.Environ(), "GOWORK=off")
		return cmd.Output()
	})()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("go list -deps ./cmd/... failed: %v\n%s", err, ee.Stderr)
		}
		t.Fatalf("go list -deps ./cmd/... failed: %v", err)
	}

	imported := map[string]bool{}
	for line := range strings.FieldsSeq(string(out)) {
		rel, found := strings.CutPrefix(line, modulePrefix)
		if !found {
			continue
		}
		switch {
		case rel == "libs/jinja":
			imported["libs/jinja"] = true
		case strings.HasPrefix(rel, "libs/hostkit/"):
			pkg, _, _ := strings.Cut(strings.TrimPrefix(rel, "libs/hostkit/"), "/")
			if pkg == "" {
				t.Fatalf("unexpected hostkit module import path %q", line)
			}
			imported["libs/hostkit/"+pkg] = true
		}
	}
	if len(imported) == 0 {
		t.Fatal("go list reported no hostkit/jinja imports — modulePrefix out of date?")
	}

	expected := map[string]bool{}
	for k := range imported {
		expected[k] = true
	}
	for _, f := range moduleFiles {
		expected[f] = true
	}

	var missing, stale []string
	for k := range expected {
		if !declared[k] {
			missing = append(missing, k)
		}
	}
	for k := range declared {
		if !expected[k] {
			stale = append(stale, k)
		}
	}
	slices.Sort(missing)
	slices.Sort(stale)
	if len(missing) > 0 || len(stale) > 0 {
		t.Fatalf("%s libs/ paths out of sync with go list -deps ./cmd/...\n  missing globs: %v\n  stale globs:   %v\n  imported roots: %v",
			workflowGlob, missing, stale, sortedKeys(imported))
	}
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
