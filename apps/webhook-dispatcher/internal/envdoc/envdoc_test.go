// Package envdoc holds a single source-coverage test keeping
// docs/env.md honest. docs/env.md is the operator-facing catalog of
// every env var the dispatcher reads — the required-var check and the
// envx.String optional knobs in cmd/dispatcher/main.go (the only
// places env is read). The catalog is maintained by hand, so it
// drifts the moment a knob lands in code without a matching table
// row; TestEnvDocCoversSource scans the module source via
// libs/hostkit/envdoc.ScanTree, collects every env-var name the code
// can read, and fails with a list of any names missing from the doc.
//
// The scan itself lives in hostkit — this module only declares its
// shape (module root, envx source dir, raw-os allowance) and keeps
// the doc-comparison assertions. The package intentionally ships
// only a _test.go file — there is nothing to compile into the
// operator; the coverage check is pure test code.
package envdoc

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envdoc"
)

// moduleRoot is the Go module root relative to this package's
// directory — go test runs each package with its own dir as working
// directory, so "../.." lands on apps/webhook-dispatcher regardless
// of which package pattern was passed.
const moduleRoot = "../.."

// envxDir is libs/hostkit/envx relative to this package's dir —
// ScanTree derives the env-reading helper set by parsing EVERY
// non-test .go file there (envx.go and its split siblings), so a
// helper moving between files cannot shrink coverage.
var envxDir = filepath.Join(moduleRoot, "..", "..",
	"libs", "hostkit", "envx")

// TestEnvDocCoversSource fails when source introduces an env knob
// not documented in docs/env.md. The scanner collects:
//
//   - first arguments of envx helper calls anywhere under the module
//     root — string literals and package-level string consts used as
//     the key;
//   - string literals inside `for _, k := range []string{...}` loops
//     whose bound variables feed an env read;
//   - raw os.Getenv/LookupEnv/ExpandEnv call sites — AllowRawOS is
//     true here because this module deliberately reads required vars
//     through os.Getenv in cmd/dispatcher/main.go (the required-var
//     check lists them explicitly); the names are collected for doc
//     coverage, not flagged.
//
// *_test.go files are skipped by the scanner, and internal/envdoc
// itself is pruned — a stray literal in the checker must not feed
// back as a fake knob.
func TestEnvDocCoversSource(t *testing.T) {
	res, err := envdoc.ScanTree(envdoc.Options{
		Root:       moduleRoot,
		EnvxDir:    envxDir,
		AllowRawOS: true,
		SkipDir: func(rel string) bool {
			return rel == "internal/envdoc"
		},
	})
	if err != nil {
		t.Fatalf("envdoc scan: %v — refusing to run with silently "+
			"reduced coverage", err)
	}
	where := res.Referenced

	// Self-checks before the doc comparison: a coverage test that
	// finds nothing passes vacuously, which is worse than no test.
	// The seven cataloged vars are the anchors — if the scan misses
	// any of them the walker or the helper set regressed.
	for _, want := range []string{
		"GITHUB_WEBHOOK_SECRET", "CI_WEBHOOK_TOKEN", "LOCAL_USERS",
		"CONCOURSE_URL", "CONCOURSE_TEAM", "LISTEN_ADDR", "METRICS_ADDR",
	} {
		if _, ok := where[want]; !ok {
			t.Fatalf("%s missing from scan results — the env scanner "+
				"regressed (checked cmd/dispatcher + internal)", want)
		}
	}

	docPath := filepath.Join(moduleRoot, "docs", "env.md")
	doc, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read %s: %v", docPath, err)
	}

	names := make([]string, 0, len(where))
	for name := range where {
		names = append(names, name)
	}
	sort.Strings(names)
	t.Logf("scanned source: %d distinct env vars", len(names))

	for _, name := range names {
		// Whole-token match: a bare strings.Contains would let FOO
		// pass on the strength of FOO_BAR's row — the doc must name
		// the var itself.
		if !regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`).Match(doc) {
			t.Errorf("env var %s (read at %s) is not documented in docs/env.md", name, where[name])
		}
	}

	// An env key the scanner cannot name is an env key docs/env.md
	// cannot be checked against — fail rather than skip it silently.
	for _, u := range res.Unresolved {
		t.Errorf("unresolvable env key at %s — pass a string literal or a "+
			"package-level string const so the coverage test can see it", u)
	}
}
