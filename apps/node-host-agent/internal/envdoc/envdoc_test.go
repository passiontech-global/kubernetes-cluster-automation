// envdoc_test.go — keeps ENV.md honest against the envnames contract.
// ENV.md is GENERATED (scripts/gen-envdoc.sh — do not regenerate it
// here; this file is a coverage/freshness check, never a generator)
// and internal/envnames is the single source of truth: every
// NODE_HOST_AGENT_* var the binary reads is declared once there as an
// Env* const, and call sites reference envnames.EnvX rather than the
// literal so a typo'd env name cannot compile. Three drift modes are
// caught: a knob referenced by non-test code that never lands in
// ENV.md, a var documented in ENV.md that no longer exists as a const
// (removed knob still documented), and a raw "NODE_HOST_AGENT_*"
// literal / const declaration smuggled in outside envnames.
//
// The AST scanning itself (contract collection, the source walk, the
// wiring.go gates table) lives in internal/envdoc/scan, so the
// gates-table generator (internal/envdoc/cmd/genenvdoc, called by
// scripts/gen-envdoc.sh) shares the exact same logic the test checks
// against. The package ships only this _test.go file on top of that —
// nothing here compiles into the agent, so depguard's platform-leaf
// rules do not apply.
package envdoc

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envdoc/scan"
)

// moduleRoot is the Go module root relative to this package's dir —
// go test runs each package with its own dir as working directory, so
// "../.." lands on apps/node-host-agent regardless of the package
// pattern passed.
const moduleRoot = "../.."

// docVars parses ENV.md for backticked NODE_HOST_AGENT_* tokens —
// every documented var appears as `VAR` in a table row or list item,
// and requiring a full match keeps header prose (`NODE_HOST_AGENT_*`)
// out of the set.
func docVars(t *testing.T) map[string]bool {
	t.Helper()
	docPath := filepath.Join(moduleRoot, "ENV.md")
	doc, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read %s: %v", docPath, err)
	}
	vars := map[string]bool{}
	for _, m := range regexp.MustCompile("`([^`\n]+)`").FindAllStringSubmatch(string(doc), -1) {
		if scan.EnvVarRE.MatchString(m[1]) {
			vars[m[1]] = true
		}
	}
	if len(vars) == 0 {
		t.Fatalf("parsed 0 vars from %s — the doc format must have "+
			"changed; a coverage check that sees nothing passes "+
			"vacuously", docPath)
	}
	return vars
}

// TestEnvDocCoversContract is the ENV.md honesty check. Collected
// once, asserted in subtests:
//
//   - references-resolve: every envnames.Env* a call site names is a
//     declared contract const (belt-and-braces — the compiler already
//     refuses a missing const, but this also pins the scan itself);
//   - referenced-knobs-documented: every contract value referenced by
//     non-test code appears in ENV.md;
//   - documented-knobs-declared: every var ENV.md lists is still a
//     declared const — catches a removed knob whose doc row survived;
//   - no-raw-literals: no "NODE_HOST_AGENT_*" string literal outside
//     envnames — the convention is const references only, and a
//     straggler means either a missed refactor or a knob never
//     extracted into the contract;
//   - no-duplicate-const-decls: no `= "NODE_HOST_AGENT_*"` const
//     declaration outside envnames.
func TestEnvDocCoversContract(t *testing.T) {
	c, err := scan.CollectContract(moduleRoot)
	if err != nil {
		t.Fatal(err)
	}
	res, err := scan.ScanSource(moduleRoot, c)
	if err != nil {
		t.Fatal(err)
	}
	doc := docVars(t)

	// Self-checks: a coverage test collecting nothing passes
	// vacuously, which is worse than no test. The anchors pin both
	// ends of the scan — a const that must exist and a var cmd/agent
	// provably reads.
	if len(c.ByConst) < 100 {
		t.Fatalf("envnames parse yielded only %d contract consts — "+
			"the contract is ~140 names; the scanner is broken", len(c.ByConst))
	}
	if v := c.ByConst["EnvStandalone"]; v != "NODE_HOST_AGENT_STANDALONE" {
		t.Fatalf("anchor const EnvStandalone = %q, want "+
			"NODE_HOST_AGENT_STANDALONE — const extraction regressed", v)
	}
	if len(res.Referenced) == 0 {
		t.Fatal("reference scan collected 0 vars — the scanner is broken")
	}
	if _, ok := res.Referenced["NODE_HOST_AGENT_STANDALONE"]; !ok {
		t.Fatal("NODE_HOST_AGENT_STANDALONE missing from scan results — " +
			"envnames.Env* resolution regressed")
	}
	t.Logf("contract: %d consts; referenced: %d vars; documented: %d vars",
		len(c.ByConst), len(res.Referenced), len(doc))

	t.Run("references-resolve", func(t *testing.T) {
		for _, u := range res.Unresolved {
			t.Errorf("envnames reference at %s names no declared const", u)
		}
	})

	t.Run("referenced-knobs-documented", func(t *testing.T) {
		vars := make([]string, 0, len(res.Referenced))
		for v := range res.Referenced {
			vars = append(vars, v)
		}
		slices.Sort(vars)
		for _, v := range vars {
			if !doc[v] {
				t.Errorf("%s (read at %s) is not documented in ENV.md — "+
					"run scripts/gen-envdoc.sh", v, res.Referenced[v])
			}
		}
	})

	t.Run("documented-knobs-declared", func(t *testing.T) {
		vars := make([]string, 0, len(doc))
		for v := range doc {
			vars = append(vars, v)
		}
		slices.Sort(vars)
		for _, v := range vars {
			if !c.Values[v] {
				t.Errorf("ENV.md documents %s but envnames declares no "+
					"const with that value — stale doc row (regenerate "+
					"ENV.md) or an undocumented external var", v)
			}
		}
	})

	t.Run("no-raw-literals", func(t *testing.T) {
		for _, s := range res.Stragglers {
			t.Errorf("raw NODE_HOST_AGENT_* literal at %s — reference "+
				"the envnames.Env* const instead (extract it into "+
				"internal/envnames first if none exists)", s)
		}
	})

	t.Run("no-duplicate-const-decls", func(t *testing.T) {
		for _, d := range res.DupDecls {
			t.Errorf("const declaration of a NODE_HOST_AGENT_* value at "+
				"%s outside internal/envnames — env names are declared "+
				"exactly once in the contract package", d)
		}
	})
}

// TestEnvDocOneRowPerVar pins the knob-table dedup: a var referenced
// in several files of one package must render as ONE row listing
// every source (comma-joined), never one row per reference. Before
// the join, NODE_HOST_AGENT_NODE_NAME shipped as two rows
// (deps_env.go:119 and hostctx.go:30).
func TestEnvDocOneRowPerVar(t *testing.T) {
	docPath := filepath.Join(moduleRoot, "ENV.md")
	doc, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read %s: %v", docPath, err)
	}
	var want = "- `NODE_HOST_AGENT_NODE_NAME` — `deps_env.go:119, hostctx.go:30`\n"
	if n := strings.Count(string(doc), "- `NODE_HOST_AGENT_NODE_NAME`"); n != 1 {
		t.Fatalf("ENV.md has %d knob rows for NODE_HOST_AGENT_NODE_NAME, "+
			"want exactly 1 (run scripts/gen-envdoc.sh — the per-package "+
			"rows must dedupe with sources joined)", n)
	}
	if !strings.Contains(string(doc), want) {
		t.Fatalf("ENV.md knob row for NODE_HOST_AGENT_NODE_NAME does not "+
			"list both sources (want %q); run scripts/gen-envdoc.sh", want)
	}
}

// TestEnvDocMode0644 pins the published file mode: gen-envdoc.sh must
// chmod the generated doc world-readable (mktemp stages 0600 and mv
// preserves the mode — a dropped chmod silently republishes the doc
// as a 0600 secret).
func TestEnvDocMode0644(t *testing.T) {
	docPath := filepath.Join(moduleRoot, "ENV.md")
	fi, err := os.Stat(docPath)
	if err != nil {
		t.Fatalf("stat %s: %v", docPath, err)
	}
	if fi.Mode().Perm() != 0644 {
		t.Fatalf("%s mode = %o, want 644 — gen-envdoc.sh must chmod "+
			"0644 after mv (the doc is operator-facing, not a secret)",
			docPath, fi.Mode().Perm())
	}
}
