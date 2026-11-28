// Package releaseglob guards the monorepo's CI/release path contracts:
// each app's release-<app>.yml `paths:` globs (and `with.lib_paths`)
// and ci.yml's docker-detect `consumers()` / `ko-detect` rules must
// match what each app's `./cmd/...` actually imports under
// `GOWORK=off go list -deps ./cmd/...`.
//
// Test-only package (never imported by any app's `./cmd/...`);
// stdlib-only like the rest of libs/hostkit (depguard:
// hostkit-stdlib-only).
package releaseglob

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
)

const modulePrefix = "github.com/passiontech-global/kubernetes-cluster-automation/"

// moduleFiles are libs/hostkit module files that subpackage globs
// never match but that change the module's dependency graph.
var moduleFiles = []string{"libs/hostkit/go.mod", "libs/hostkit/go.sum"}

var (
	pathEntryRe = regexp.MustCompile(`-\s+"(libs/[^"]+)"`)
	// libPathsRe captures the caller's `with.lib_paths` string — the
	// space-separated globs release-app.yml turns into git-cliff
	// --include-path args.
	libPathsRe = regexp.MustCompile(`lib_paths:\s*"([^"]*)"`)
)

// RepoRoot returns the repository root by walking up from this file's
// location (<root>/libs/hostkit/releaseglob/releaseglob.go).
func RepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(thisFile))))
}

// appLibImports runs `go list -deps ./cmd/...` inside apps/<app> with
// GOWORK=off and returns the libs/ subtrees it imports: "libs/jinja"
// or "libs/hostkit/<pkg>" (subpackages collapse to their pkg root —
// httpx/pprofx is covered by the libs/hostkit/httpx/ glob).
func appLibImports(t *testing.T, root, app string) map[string]bool {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", "./cmd/...")
	cmd.Dir = filepath.Join(root, "apps", app)
	cmd.Env = append(os.Environ(), "GOWORK=off")
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Fatalf("%s: go list -deps ./cmd/... failed: %v\n%s", app, err, ee.Stderr)
		}
		t.Fatalf("%s: go list -deps ./cmd/... failed: %v", app, err)
	}
	imports := map[string]bool{}
	for line := range strings.FieldsSeq(string(out)) {
		rel, found := strings.CutPrefix(line, modulePrefix)
		if !found {
			continue
		}
		switch {
		case rel == "libs/jinja":
			imports["libs/jinja"] = true
		case strings.HasPrefix(rel, "libs/hostkit/"):
			pkg, _, _ := strings.Cut(strings.TrimPrefix(rel, "libs/hostkit/"), "/")
			if pkg == "" {
				t.Fatalf("unexpected hostkit module import path %q", line)
			}
			imports["libs/hostkit/"+pkg] = true
		}
	}
	return imports
}

// CheckReleaseWorkflowGlobs asserts that .github/workflows/release-<app>.yml's
// libs/ `paths:` globs and `with.lib_paths` equal the hostkit/jinja
// subpackage roots imported by apps/<app>/./cmd/... (non-test deps),
// plus libs/hostkit's module files.
func CheckReleaseWorkflowGlobs(t *testing.T, app string) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain not in PATH: %v", err)
	}
	root := RepoRoot(t)
	workflowGlob := "release-" + app + ".yml"
	workflowRel := ".github/workflows/" + workflowGlob

	raw, err := os.ReadFile(filepath.Join(root, workflowRel))
	if err != nil {
		t.Fatalf("read %s: %v", workflowRel, err)
	}
	declared := map[string]bool{}
	for _, m := range pathEntryRe.FindAllStringSubmatch(string(raw), -1) {
		g := strings.TrimSuffix(m[1], "/**")
		declared[g] = true
	}
	if len(declared) == 0 {
		t.Fatalf("no libs/ path entries found in %s — parser out of date?", workflowRel)
	}

	imported := appLibImports(t, root, app)
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

	missing, stale := diffSets(expected, declared)
	if len(missing) > 0 || len(stale) > 0 {
		t.Fatalf("%s libs/ paths out of sync with go list -deps ./cmd/...\n  missing globs: %v\n  stale globs:   %v\n  imported roots: %v",
			workflowGlob, missing, stale, sortedKeys(imported))
	}

	// with.lib_paths feeds git-cliff --include-path — the same roots
	// must be declared there or release notes silently drop commits
	// that touched shared-library code the app actually consumes.
	lpMatch := libPathsRe.FindStringSubmatch(string(raw))
	if lpMatch == nil {
		t.Fatalf("no lib_paths input found in %s — parser out of date?", workflowRel)
	}
	declaredLibPaths := map[string]bool{}
	for g := range strings.FieldsSeq(lpMatch[1]) {
		declaredLibPaths[strings.TrimSuffix(g, "/**")] = true
	}
	lpMissing, lpStale := diffSets(expected, declaredLibPaths)
	if len(lpMissing) > 0 || len(lpStale) > 0 {
		t.Fatalf("%s with.lib_paths out of sync with go list -deps ./cmd/...\n  missing: %v\n  stale:   %v",
			workflowGlob, lpMissing, lpStale)
	}
}

func diffSets(want, got map[string]bool) (missing, stale []string) {
	for k := range want {
		if !got[k] {
			missing = append(missing, k)
		}
	}
	for k := range got {
		if !want[k] {
			stale = append(stale, k)
		}
	}
	slices.Sort(missing)
	slices.Sort(stale)
	return missing, stale
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
