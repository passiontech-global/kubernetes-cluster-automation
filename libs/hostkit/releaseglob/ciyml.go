// ciyml.go — guards ci.yml's docker-detect consumers(), mise.toml
// consumers, and inline ko-detect case block against GOWORK=off
// `go list -deps ./cmd/...`.
package releaseglob

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

// parseConsumerArms extracts the elif arms of consumers() from ci.yml
// content, in file order (the jq elif chain is first-match-wins).
func parseConsumerArms(text string) ([]consumerArm, string) {
	// Split on `elif ` boundaries inside the consumers() jq block —
	// each chunk carries its condition patterns and `then [apps]`.
	start := strings.Index(text, "def consumers")
	if start < 0 {
		return nil, "consumers() not found"
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
		return nil, "no consumers() elif arms parsed"
	}
	return arms, ""
}

func readConsumerArms(t *testing.T, root string) []consumerArm {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, ciWorkflowRel))
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflowRel, err)
	}
	arms, errMsg := parseConsumerArms(string(raw))
	if errMsg != "" {
		t.Fatalf("%s in %s", errMsg, ciWorkflowRel)
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

// CheckDockerDetectMapping asserts consumers() in ci.yml routes every
// libs/ path to exactly the apps whose ./cmd/... imports it.
func CheckDockerDetectMapping(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain not in PATH: %v", err)
	}
	root := RepoRoot(t)
	arms := readConsumerArms(t, root)

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

	checkProbe := func(probe string, importers map[string]bool) {
		got := map[string]bool{}
		for _, a := range consumersFor(arms, probe) {
			got[a] = true
		}
		if !slices.Equal(sortedKeys(got), sortedKeys(importers)) {
			t.Errorf("consumers(%q) = %v, want importers %v",
				probe, sortedKeys(got), sortedKeys(importers))
		}
	}

	// Forward: every imported libdir's file probe must route to
	// exactly its importers.
	for lib, importers := range want {
		checkProbe(lib+"/probe.go", importers)
	}
	// Module files route to every hostkit importer.
	for _, mf := range moduleFiles {
		checkProbe(mf, hostkitApps)
	}

	// Reverse: every libs/hostkit subdir + libs/jinja on disk must
	// route to its importers (empty set for test-only pkgs like
	// envdoc/releaseglob — the else [] arm covers them).
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
					checkProbe(dir+"/"+e.Name(), want["libs/jinja"])
				}
				continue
			}
			lib := dir + "/" + e.Name()
			importers := want[lib]
			if dir == "libs/jinja" {
				importers = want["libs/jinja"]
			}
			checkProbe(lib+"/probe.go", importers)
		}
	}
}

// CheckMiseTomlConsumers asserts that ci.yml's consumers() maps
// mise.toml to all three apps (a toolchain bump can change any app's
// image).
func CheckMiseTomlConsumers(t *testing.T) {
	t.Helper()
	arms := readConsumerArms(t, RepoRoot(t))
	if got := consumersFor(arms, "mise.toml"); !slices.Equal(got, appsUnderTest) {
		t.Fatalf("consumers(\"mise.toml\") = %v, want %v", got, appsUnderTest)
	}
}

type koDetectArm struct {
	patterns   []*regexp.Regexp
	isContinue bool
	nac        bool
	wd         bool
}

func bashCasePatternToRegex(pat string) (*regexp.Regexp, error) {
	if pat == `""` {
		return regexp.Compile(`^$`)
	}
	var b strings.Builder
	b.WriteByte('^')
	for _, r := range pat {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteByte('$')
	return regexp.Compile(b.String())
}

func parseKoDetectArms(text string) ([]koDetectArm, string) {
	idIdx := strings.Index(text, "id: ko-detect")
	if idIdx < 0 {
		return nil, "id: ko-detect not found"
	}
	sub := text[idIdx:]
	caseIdx := strings.Index(sub, `case "$p" in`)
	if caseIdx < 0 {
		return nil, `case "$p" in not found under ko-detect`
	}
	body := sub[caseIdx+len(`case "$p" in`):]
	esacIdx := strings.Index(body, "esac")
	if esacIdx < 0 {
		return nil, "esac not found under ko-detect"
	}
	caseBody := body[:esacIdx]

	var arms []koDetectArm
	for rawArm := range strings.SplitSeq(caseBody, ";;") {
		trimmed := strings.TrimSpace(rawArm)
		if trimmed == "" {
			continue
		}
		paren := strings.IndexByte(trimmed, ')')
		if paren < 0 {
			return nil, "malformed ko-detect case arm: " + trimmed
		}
		patList := strings.TrimSpace(trimmed[:paren])
		armBody := strings.TrimSpace(trimmed[paren+1:])

		var arm koDetectArm
		arm.isContinue = strings.Contains(armBody, "continue")
		arm.nac = strings.Contains(armBody, "nac=true")
		arm.wd = strings.Contains(armBody, "wd=true")
		for p := range strings.SplitSeq(patList, "|") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			re, err := bashCasePatternToRegex(p)
			if err != nil {
				return nil, "compile ko-detect pattern " + p + ": " + err.Error()
			}
			arm.patterns = append(arm.patterns, re)
		}
		if len(arm.patterns) > 0 {
			arms = append(arms, arm)
		}
	}
	if len(arms) == 0 {
		return nil, "no ko-detect case arms parsed"
	}
	return arms, ""
}

func readKoDetectArms(t *testing.T, root string) []koDetectArm {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, ciWorkflowRel))
	if err != nil {
		t.Fatalf("read %s: %v", ciWorkflowRel, err)
	}
	arms, errMsg := parseKoDetectArms(string(raw))
	if errMsg != "" {
		t.Fatalf("%s in %s", errMsg, ciWorkflowRel)
	}
	return arms
}

func koDetectFor(arms []koDetectArm, path string) (nac, wd bool) {
	for _, arm := range arms {
		for _, re := range arm.patterns {
			if re.MatchString(path) {
				if arm.isContinue {
					return false, false
				}
				return arm.nac, arm.wd
			}
		}
	}
	return false, false
}

// CheckKoDetect asserts ci.yml's inline ko-detect case block triggers
// nac/wd ko builds in exact agreement with GOWORK=off go list -deps
// ./cmd/... for both ko-built apps.
func CheckKoDetect(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain not in PATH: %v", err)
	}
	root := RepoRoot(t)
	arms := readKoDetectArms(t, root)
	nacLibs := appLibImports(t, root, "node-automation-controller")
	wdLibs := appLibImports(t, root, "webhook-dispatcher")

	hasHostkit := func(libs map[string]bool) bool {
		for lib := range libs {
			if strings.HasPrefix(lib, "libs/hostkit/") {
				return true
			}
		}
		return false
	}

	assertKo := func(path string, wantNAC, wantWD bool) {
		t.Helper()
		gotNAC, gotWD := koDetectFor(arms, path)
		if gotNAC != wantNAC || gotWD != wantWD {
			t.Errorf("ko-detect(%q) = (nac=%v, wd=%v), want (nac=%v, wd=%v)",
				path, gotNAC, gotWD, wantNAC, wantWD)
		}
	}

	// Every libs/hostkit/* subdir on disk must match exact cmd deps.
	hkEntries, err := os.ReadDir(filepath.Join(root, "libs/hostkit"))
	if err != nil {
		t.Fatalf("read libs/hostkit: %v", err)
	}
	for _, e := range hkEntries {
		if !e.IsDir() {
			continue
		}
		lib := "libs/hostkit/" + e.Name()
		wantNAC := nacLibs[lib]
		wantWD := wdLibs[lib]
		assertKo(lib+"/probe.go", wantNAC, wantWD)
		assertKo(lib+"/sub/probe.go", wantNAC, wantWD)
		assertKo(lib+"/probe_test.go", false, false)
	}

	// libs/hostkit/go.{mod,sum} affect every hostkit consumer.
	for _, mf := range moduleFiles {
		assertKo(mf, hasHostkit(nacLibs), hasHostkit(wdLibs))
	}

	// libs/jinja is not imported by either ko-built app.
	jinjaEntries, err := os.ReadDir(filepath.Join(root, "libs/jinja"))
	if err != nil {
		t.Fatalf("read libs/jinja: %v", err)
	}
	for _, e := range jinjaEntries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		assertKo("libs/jinja/"+e.Name(), nacLibs["libs/jinja"], wdLibs["libs/jinja"])
	}
	assertKo("libs/jinja/probe.go", nacLibs["libs/jinja"], wdLibs["libs/jinja"])

	// App subtrees, non-ko app, mise.toml, and ignored files (*.md, *_test.go).
	assertKo("apps/node-automation-controller/cmd/manager/main.go", true, false)
	assertKo("apps/node-automation-controller/go.mod", true, false)
	assertKo("apps/node-automation-controller/cmd/manager/main_test.go", false, false)
	assertKo("apps/node-automation-controller/docs/env.md", false, false)

	assertKo("apps/webhook-dispatcher/cmd/dispatcher/main.go", false, true)
	assertKo("apps/webhook-dispatcher/go.mod", false, true)
	assertKo("apps/webhook-dispatcher/cmd/dispatcher/main_test.go", false, false)
	assertKo("apps/webhook-dispatcher/docs/env.md", false, false)

	assertKo("apps/node-host-agent/cmd/agent/main.go", false, false)
	assertKo("mise.toml", true, true)
	assertKo("README.md", false, false)
}
