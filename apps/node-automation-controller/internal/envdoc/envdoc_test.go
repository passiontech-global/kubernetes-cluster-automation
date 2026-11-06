// Package envdoc holds a single source-coverage test keeping docs/env.md
// honest. docs/env.md is the operator-facing catalog of every env var the
// controller reads — the REGISTRATION gates in the internal/registry
// module table (the GateEnv column) plus the run-behavior knobs and
// sub-feature gates each module resolves through the envx.Getenv* /
// envx.Gate helpers in libs/hostkit/envx. The catalog is
// maintained by hand, so it drifts the moment a knob lands in code
// without a matching table row; TestEnvDocCoversSource walks the module
// source, collects every env-var name the code can read, and fails with a
// list of any names missing from the doc.
//
// The package intentionally ships only a _test.go file — there is nothing
// to compile into the operator; the coverage check is pure test code.
package envdoc

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// moduleRoot is the Go module root relative to this package's directory —
// go test runs each package with its own dir as working directory, so
// "../.." lands on apps/node-automation-controller regardless of which
// package pattern was passed.
const moduleRoot = "../.."

// envHelpers is the complete set of env-reading helpers exported by
// libs/hostkit/envx (the strict Getenv* family + Gate — the lenient
// helpers there have different names and are not this app's contract).
// A call `envx.Xxx("NAME", ...)` — or an unqualified `Xxx("NAME", ...)`
// inside an in-tree envx package — reads the env var named by its first
// argument. Keep this set in sync with the strict family in envx.go:
// adding a new helper there without listing it here silently drops its
// call sites from coverage.
var envHelpers = map[string]bool{
	"Getenv":              true,
	"GetenvInt":           true,
	"GetenvDuration":      true,
	"GetenvFloat":         true,
	"GetenvIntMin":        true,
	"GetenvFloatPositive": true,
	"Gate":                true,
}

// envNameRE restricts collected string literals to tokens that look like
// env-var names — ALL_CAPS with digits/underscores. It keeps the scanner
// from flagging ordinary string arguments (none of the helpers currently
// takes a string first arg that ISN'T an env key, but a stray literal
// like "" would otherwise be collected).
var envNameRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// knownGaps exempts env vars the code reads that deliberately have no
// docs/env.md row — each entry is name -> reason the doc must NOT list
// it. Empty today: every knob below is user-facing and belongs in the
// catalog. Add an entry ONLY for an internal-only seam (e.g. a test hook
// living in non-test source); an undocumented user-facing knob is a bug
// this test exists to catch, so fix the doc instead.
var knownGaps = map[string]string{}

// TestEnvDocCoversSource fails when source introduces an env knob not
// documented in docs/env.md. Three sources feed the check:
//
//   - `GateEnv: "NAME"` literals in internal/registry/*.go — the
//     registration gates on shared.Module registry rows;
//   - first arguments of envx.Getenv*/envx.Gate call sites in
//     cmd/manager/*.go and internal/**/*.go — both string literals and
//     package-level string consts used as the key (partition-evictor keys
//     its call off `const partitionNSsEnv`);
//   - unqualified Getenv/Gate-family calls inside an in-tree envx
//     package (dormant today — the helpers moved out to libs/hostkit,
//     which this module-local scan never reaches, but a future
//     internal/platform/envx-style package would land here). Helper
//     DEFINITIONS take a `key` parameter, not a literal, so they
//     collect nothing.
//
// *_test.go files are skipped (test-only env seams like GO_HELPER_PROCESS
// are not operator surface) and internal/envdoc itself is never scanned —
// a stray literal in the checker must not feed back as a fake knob.
func TestEnvDocCoversSource(t *testing.T) {
	where, unresolved := collectEnvNames(t)

	// Self-checks before the doc comparison: a coverage test that finds
	// nothing passes vacuously, which is worse than no test.
	if len(where) == 0 {
		t.Fatalf("env scan collected 0 names — the scanner is broken " +
			"(checked GateEnv literals under internal/registry and " +
			"envx.Getenv*/envx.Gate call sites under cmd/manager + " +
			"internal)")
	}
	// PARTITION_EVICT_NAMESPACES is the one call site whose env key is a
	// package const rather than a literal; its presence proves const-key
	// resolution works. If the var is renamed this check must be updated.
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
		// Whole-token match: a bare strings.Contains would let FOO pass on
		// the strength of FOO_BAR's row — the doc must name the var itself.
		if !regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`).Match(doc) {
			t.Errorf("env var %s (read at %s) is not documented in docs/env.md", name, where[name])
		}
	}

	// An env key the scanner cannot name is an env key docs/env.md cannot
	// be checked against — fail rather than skip it silently. Dynamic
	// selector keys (m.GateEnv in internal/registry) are excluded by
	// collectEnvNames because the same literal is caught at its registry
	// declaration.
	for _, u := range unresolved {
		t.Errorf("unresolvable env key at %s — pass a string literal or a "+
			"package-level string const so the coverage test can see it", u)
	}
}

// collectEnvNames parses every non-test .go file under cmd/manager and
// internal/ (internal/envdoc excluded) and returns:
//
//	where       — env-var name -> "relpath:line" of one use site, for
//	              failure messages;
//	unresolved  — use sites whose env key is an identifier that does not
//	              resolve to a package-level string const in the same
//	              package — reported as test failures by the caller.
//
// Keys written as arbitrary other expressions (a field read like
// `m.GateEnv`, a concatenation, a call) are ignored rather than flagged:
// internal/registry resolves `envx.Gate(m.GateEnv, ...)` per registry
// row, and the literal it dereferences is caught by the GateEnv
// composite-literal scan where it is declared.
func collectEnvNames(t *testing.T) (map[string]string, []string) {
	t.Helper()

	envdocDir := filepath.Join(moduleRoot, "internal", "envdoc")
	// envx moved out to libs/hostkit — outside this module's scan
	// tree — so envxDir matches nothing today; the inEnvx branch stays
	// so a future in-tree envx package is covered.
	envxDir := filepath.Join(moduleRoot, "internal", "platform", "envx")
	registryDir := filepath.Join(moduleRoot, "internal", "registry")

	dirs := []string{filepath.Join(moduleRoot, "cmd", "manager")}
	internalRoot := filepath.Join(moduleRoot, "internal")
	err := filepath.WalkDir(internalRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == envdocDir {
				return filepath.SkipDir
			}
			dirs = append(dirs, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", internalRoot, err)
	}

	where := make(map[string]string)
	var unresolved []string

	record := func(fset *token.FileSet, value string, pos token.Pos) {
		if !envNameRE.MatchString(value) {
			return
		}
		if _, seen := where[value]; seen {
			return
		}
		// Positions are rendered module-relative so failure messages read
		// like every other path in this repo (internal/..., cmd/...).
		p := fset.Position(pos)
		rel, err := filepath.Rel(moduleRoot, p.Filename)
		if err != nil {
			rel = p.Filename
		}
		where[value] = fmt.Sprintf("%s:%d", rel, p.Line)
	}

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read dir %s: %v", dir, err)
		}

		fset := token.NewFileSet()
		var files []*ast.File
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", filepath.Join(dir, name), err)
			}
			files = append(files, f)
		}

		// Pass 1 — collect this package's string consts so an env key
		// written as `envx.Getenv(someConst, ...)` still resolves to a
		// name. Bare rows in a const block repeat the previous expression,
		// handled by carrying `vals` forward.
		consts := make(map[string]string)
		for _, f := range files {
			for _, decl := range f.Decls {
				gen, ok := decl.(*ast.GenDecl)
				if !ok || gen.Tok != token.CONST {
					continue
				}
				var vals []ast.Expr
				for _, spec := range gen.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					if len(vs.Values) > 0 {
						vals = vs.Values
					}
					for i, n := range vs.Names {
						if i >= len(vals) {
							continue
						}
						lit, ok := vals[i].(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							continue
						}
						if v, err := strconv.Unquote(lit.Value); err == nil {
							consts[n.Name] = v
						}
					}
				}
			}
		}

		// Pass 2 — walk each file for env-reading call sites and, in the
		// registry package, GateEnv keys on module registry rows.
		inRegistry := dir == registryDir
		inEnvx := dir == envxDir

		addKey := func(expr ast.Expr, pos token.Pos) {
			switch k := expr.(type) {
			case *ast.BasicLit:
				if k.Kind != token.STRING {
					return
				}
				if v, err := strconv.Unquote(k.Value); err == nil {
					record(fset, v, pos)
				}
			case *ast.Ident:
				if v, ok := consts[k.Name]; ok {
					record(fset, v, pos)
					return
				}
				// An identifier that is not a string const in this
				// package — the scanner cannot name the key.
				p := fset.Position(pos)
				rel, err := filepath.Rel(moduleRoot, p.Filename)
				if err != nil {
					rel = p.Filename
				}
				unresolved = append(unresolved, fmt.Sprintf("%s:%d (%s)", rel, p.Line, k.Name))
			default:
				// Selector (m.GateEnv), concatenation, call result, … —
				// a computed key; see collectEnvNames' doc comment.
			}
		}

		for _, f := range files {
			ast.Inspect(f, func(n ast.Node) bool {
				switch e := n.(type) {
				case *ast.CallExpr:
					if !isEnvCall(e, inEnvx) || len(e.Args) == 0 {
						return true
					}
					addKey(e.Args[0], e.Pos())
				case *ast.KeyValueExpr:
					if !inRegistry {
						return true
					}
					key, ok := e.Key.(*ast.Ident)
					if !ok || key.Name != "GateEnv" {
						return true
					}
					addKey(e.Value, e.Pos())
				}
				return true
			})
		}
	}

	return where, unresolved
}

// isEnvCall reports whether call is a read of an env var through one of
// the shared helpers — either the qualified `envx.Xxx(...)` form used
// everywhere, or the bare `Xxx(...)` form that can only mean the env.go
// helper when it appears inside package envx itself. An unqualified
// same-named function anywhere else is not our business.
func isEnvCall(call *ast.CallExpr, inEnvx bool) bool {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		recv, ok := fun.X.(*ast.Ident)
		return ok && recv.Name == "envx" && envHelpers[fun.Sel.Name]
	case *ast.Ident:
		return inEnvx && envHelpers[fun.Name]
	}
	return false
}
