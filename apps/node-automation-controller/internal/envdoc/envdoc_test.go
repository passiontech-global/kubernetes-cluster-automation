// Package envdoc holds a single source-coverage test keeping
// docs/env.md honest. docs/env.md is the operator-facing catalog of
// every env var the controller reads — the REGISTRATION gates in the
// internal/registry module table (the GateEnv column) plus the
// run-behavior knobs and sub-feature gates each module resolves
// through the envx.Getenv*/envx.Gate helpers in libs/hostkit/envx.
// The catalog is maintained by hand, so it drifts the moment a knob
// lands in code without a matching table row; TestEnvDocCoversSource
// scans the module source via libs/hostkit/envdoc.ScanTree, collects
// every env-var name the code can read, and fails with a list of any
// names missing from the doc.
//
// The scan itself lives in hostkit — this module only declares its
// shape (module root, envx source dir, registry GateEnv dir, raw-os
// ban) and keeps the doc-comparison assertions. The package
// intentionally ships only a _test.go file — there is nothing to
// compile into the operator; the coverage check is pure test code.
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
// directory, so "../.." lands on apps/node-automation-controller
// regardless of which package pattern was passed.
const moduleRoot = "../.."

// envxDir is libs/hostkit/envx relative to this package's dir —
// ScanTree derives the env-reading helper set by parsing EVERY
// non-test .go file there, so a helper moving between files cannot
// shrink coverage.
var envxDir = filepath.Join(moduleRoot, "..", "..",
	"libs", "hostkit", "envx")

// registryDir is internal/registry relative to this package's dir —
// ScanTree collects `GateEnv: "NAME"` composite-literal fields there
// (the module registration gates) as env reads.
var registryDir = filepath.Join(moduleRoot, "internal", "registry")

// knownGaps exempts env vars the code reads that deliberately have no
// docs/env.md row — each entry is name -> reason the doc must NOT list
// it. Empty today: every knob is user-facing and belongs in the
// catalog. Add an entry ONLY for an internal-only seam (e.g. a test
// hook living in non-test source); an undocumented user-facing knob
// is a bug this test exists to catch, so fix the doc instead.
var knownGaps = map[string]string{}

// TestEnvDocCoversSource fails when source introduces an env knob not
// documented in docs/env.md. The scanner collects:
//
//   - `GateEnv: "NAME"` literals under internal/registry — the
//     registration gates on shared.Module registry rows;
//   - first arguments of envx.Getenv*/envx.Gate call sites anywhere
//     under the module root — string literals and package-level
//     string consts used as the key (partition-evictor keys its call
//     off `const partitionNSsEnv`);
//   - raw os.Getenv/LookupEnv/ExpandEnv call sites — AllowRawOS is
//     false here because raw env reads are depguard-banned under
//     internal/; any that slip through (e.g. a _test-adjacent seam the
//     depguard rule misses) land on Result.RawReads and fail below.
//
// *_test.go files are skipped by the scanner, and internal/envdoc
// itself is pruned — a stray literal in the checker must not feed
// back as a fake knob.
func TestEnvDocCoversSource(t *testing.T) {
	res, err := envdoc.ScanTree(envdoc.Options{
		Root:        moduleRoot,
		EnvxDir:     envxDir,
		AllowRawOS:  false,
		RegistryDir: registryDir,
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
	if len(where) == 0 {
		t.Fatalf("env scan collected 0 names — the scanner is broken " +
			"(checked GateEnv literals under internal/registry and " +
			"envx.Getenv*/envx.Gate call sites under cmd/manager + " +
			"internal)")
	}
	// PARTITION_EVICT_NAMESPACES is the one call site whose env key is
	// a package const rather than a literal; its presence proves
	// const-key resolution works. If the var is renamed this check
	// must be updated.
	if _, ok := where["PARTITION_EVICT_NAMESPACES"]; !ok {
		t.Errorf("PARTITION_EVICT_NAMESPACES missing from scan results — " +
			"const-key resolution in the scanner regressed")
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
		if reason, exempt := knownGaps[name]; exempt {
			t.Logf("%s: exempted from docs/env.md coverage — %s", name, reason)
			continue
		}
		// Whole-token match: a bare strings.Contains would let FOO
		// pass on the strength of FOO_BAR's row — the doc must name
		// the var itself.
		if !regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`).Match(doc) {
			t.Errorf("env var %s (read at %s) is not documented in docs/env.md", name, where[name])
		}
	}

	// An env key the scanner cannot name is an env key docs/env.md
	// cannot be checked against — fail rather than skip it silently.
	// Dynamic selector keys (m.GateEnv in internal/registry) resolve
	// at the GateEnv literal declaration instead.
	for _, u := range res.Unresolved {
		t.Errorf("unresolvable env key at %s — pass a string literal or a "+
			"package-level string const so the coverage test can see it", u)
	}

	// A raw os.Getenv/LookupEnv/ExpandEnv call is invisible to the
	// helper-call scan — the var it reads never reaches docs/env.md.
	// Every knob must go through envx.* (the depguard rule bans the
	// os import too; this check has no such gap — it covers every
	// non-test file the walk sees).
	for _, r := range res.RawReads {
		t.Errorf("raw env read at %s — read the knob through an "+
			"envx.* helper so envdoc coverage (and docs/env.md) applies", r)
	}
}
