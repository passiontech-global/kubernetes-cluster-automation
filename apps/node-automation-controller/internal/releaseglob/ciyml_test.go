// ciyml_test.go — guards the ci.yml docker-detect consumers() mapping:
// the jq elif-chain that maps a changed libs/ path to the apps whose
// Docker image can actually be affected must equal the set of apps
// whose ./cmd/... dependency graph imports that library subtree
// (GOWORK=off `go list -deps`, same source of truth as
// TestReleaseWorkflowGlobsMatchCmdDeps). A stale arm silently skips
// the docker-build leg for a real dependency change; an over-broad
// one wastes matrix legs.
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

const ciWorkflowRel = ".github/workflows/ci.yml"

var appsUnderTest = []string{
	"node-host-agent",
	"node-automation-controller",
	"webhook-dispatcher",
}

// consumerArm is one `elif (...) then [...]` branch of the jq
// consumers() function: match patterns plus the app list it yields.
type consumerArm struct {
	prefixes []string // startswith("...") literals
	exacts   []string // == "..." literals
	apps     []string // the then-[...] app names, in order
}

var (
	startswithRe = regexp.MustCompile(`startswith\("([^"]+)"\)`)
	exactRe      = regexp.MustCompile(`==\s*"([^"]+)"`)
	thenAppsRe   = regexp.MustCompile(`then\s*\[([^\]]*)\]`)
	quotedRe     = regexp.MustCompile(`"([^"]+)"`)
)

// parseConsumerArms extracts the elif arms of consumers() from ci.yml,
// in file order (the jq elif chain is first-match-wins).
func parseConsumerArms(t *testing.T, root string) []consumerArm {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, ciWorkflowRel))
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflowRel, err)
	}
	text := string(raw)
	// Split on `elif ` boundaries inside the consumers() jq block —
	// each chunk carries its condition patterns and `then [apps]`.
	start := strings.Index(text, "def consumers")
	if start < 0 {
		t.Fatalf("consumers() not found in %s", ciWorkflowRel)
	}
	block := text[start:]
	// LastIndex: the apps/ `if` arm carries its own `else [] end`
	// before the elif chain's terminal one.
	if end := strings.LastIndex(block, "else [] end"); end >= 0 {
		block = block[:end]
	}
	var arms []consumerArm
	chunks := strings.Split(block, "elif ")
	for i, chunk := range chunks {
		chunk = strings.TrimSpace(chunk)
		// chunks[0] holds `def consumers` + the `if` apps/ arm —
		// apps/ paths are not libs/ consumers.
		if i == 0 || chunk == "" {
			continue
		}
		m := thenAppsRe.FindStringSubmatch(chunk)
		if m == nil {
			continue
		}
		arm := consumerArm{
			prefixes: matchAll(startswithRe, chunk),
			exacts:   matchAll(exactRe, chunk),
		}
		for _, a := range quotedRe.FindAllStringSubmatch(m[1], -1) {
			arm.apps = append(arm.apps, a[1])
		}
		if len(arm.apps) > 0 {
			arms = append(arms, arm)
		}
	}
	if len(arms) == 0 {
		t.Fatalf("no consumers() elif arms parsed from %s", ciWorkflowRel)
	}
	return arms
}

func matchAll(re *regexp.Regexp, s string) []string {
	var out []string
	for _, m := range re.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

// consumersFor simulates the jq first-match-wins elif chain for one
// changed path.
func consumersFor(arms []consumerArm, path string) []string {
	for _, arm := range arms {
		for _, p := range arm.prefixes {
			if strings.HasPrefix(path, p) {
				return arm.apps
			}
		}
		for _, p := range arm.exacts {
			if path == p {
				return arm.apps
			}
		}
	}
	return nil
}

// appLibImports runs `go list -deps ./cmd/...` inside apps/<app> and
// returns the libs/ subtrees it imports: "libs/jinja" or
// "libs/hostkit/<pkg>" (subpackages collapse to their pkg root —
// httpx/pprofx is covered by the libs/hostkit/httpx/ glob).
func appLibImports(t *testing.T, root, app string) map[string]bool {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", "./cmd/...")
	cmd.Dir = filepath.Join(root, "apps", app)
	cmd.Env = append(os.Environ(), "GOWORK=off")
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
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
				t.Fatalf("unexpected hostkit import path %q", line)
			}
			imports["libs/hostkit/"+pkg] = true
		}
	}
	return imports
}

// TestDockerDetectMappingMatchesDeps asserts consumers() in ci.yml
// routes every libs/ path to exactly the apps importing it.
func TestDockerDetectMappingMatchesDeps(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain not in PATH: %v", err)
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	appDir := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
	root := filepath.Dir(filepath.Dir(appDir))

	arms := parseConsumerArms(t, root)

	// want[libdir] = apps whose cmd deps import it.
	want := map[string]map[string]bool{}
	for _, app := range appsUnderTest {
		for lib := range appLibImports(t, root, app) {
			if want[lib] == nil {
				want[lib] = map[string]bool{}
			}
			want[lib][app] = true
		}
	}
	// libs/hostkit/go.mod|go.sum change the whole module's dep graph:
	// every hostkit importer consumes them.
	var hostkitApps map[string]bool
	for lib, apps := range want {
		if strings.HasPrefix(lib, "libs/hostkit/") {
			if hostkitApps == nil {
				hostkitApps = map[string]bool{}
			}
			for a := range apps {
				hostkitApps[a] = true
			}
		}
	}

	sorted := func(m map[string]bool) []string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}

	// Forward: every imported libdir's file probe must route to
	// exactly its importers.
	for lib, importers := range want {
		probe := lib + "/probe.go"
		got := map[string]bool{}
		for _, a := range consumersFor(arms, probe) {
			got[a] = true
		}
		if !slices.Equal(sorted(got), sorted(importers)) {
			t.Errorf("consumers(%q) = %v, want importers %v",
				probe, sorted(got), sorted(importers))
		}
	}
	// Module files route to every hostkit importer.
	for _, mf := range moduleFiles {
		got := map[string]bool{}
		for _, a := range consumersFor(arms, mf) {
			got[a] = true
		}
		if !slices.Equal(sorted(got), sorted(hostkitApps)) {
			t.Errorf("consumers(%q) = %v, want hostkit importers %v",
				mf, sorted(got), sorted(hostkitApps))
		}
	}

	// Reverse: every libs/hostkit subdir + libs/jinja on disk must
	// route to its importers (empty set for test-only pkgs like
	// envdoc — the else [] arm covers them).
	for _, dir := range []string{"libs/hostkit", "libs/jinja"} {
		entries, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			if !e.IsDir() {
				// libs/jinja is a single flat package — its .go
				// files live at the module root, so there is no
				// subdir for this loop to visit. Route each root
				// source file through consumers() explicitly or a
				// jinja-only change escapes the reverse check.
				if dir == "libs/jinja" && strings.HasSuffix(e.Name(), ".go") &&
					!strings.HasSuffix(e.Name(), "_test.go") {
					probe := dir + "/" + e.Name()
					got := map[string]bool{}
					for _, a := range consumersFor(arms, probe) {
						got[a] = true
					}
					importers := want["libs/jinja"]
					if importers == nil {
						importers = map[string]bool{}
					}
					if !slices.Equal(sorted(got), sorted(importers)) {
						t.Errorf("consumers(%q) = %v, want importers %v",
							probe, sorted(got), sorted(importers))
					}
				}
				continue
			}
			lib := dir + "/" + e.Name()
			var importers map[string]bool
			if dir == "libs/jinja" {
				importers = want["libs/jinja"]
			} else {
				importers = want[lib]
			}
			if importers == nil {
				importers = map[string]bool{}
			}
			got := map[string]bool{}
			for _, a := range consumersFor(arms, lib+"/probe.go") {
				got[a] = true
			}
			if !slices.Equal(sorted(got), sorted(importers)) {
				t.Errorf("consumers(%q) = %v, want importers %v",
					lib+"/probe.go", sorted(got), sorted(importers))
			}
		}
	}
}
