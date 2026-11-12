// Package envdoc holds a single source-coverage test keeping
// docs/env.md honest. docs/env.md is the operator-facing catalog of
// every env var the dispatcher reads — the required-var check and the
// envx.String optional knobs in cmd/dispatcher/main.go (the only
// places env is read). The catalog is maintained by hand, so it
// drifts the moment a knob lands in code without a matching table
// row; TestEnvDocCoversSource walks the module source, collects every
// env-var name the code can read, and fails with a list of any names
// missing from the doc.
//
// The package intentionally ships only a _test.go file — there is
// nothing to compile into the operator; the coverage check is pure
// test code.
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

// moduleRoot is the Go module root relative to this package's
// directory — go test runs each package with its own dir as working
// directory, so "../.." lands on apps/webhook-dispatcher regardless
// of which package pattern was passed.
const moduleRoot = "../.."

// envxImportPath is the package whose first-arg-is-an-env-key helpers
// envHelpers collects. Whatever local name a scanned file binds it to
// resolves through the import decl, so an aliased import cannot evade
// the scan.
const envxImportPath = "github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"

// envxSource is libs/hostkit/envx/envx.go relative to the module
// root — the file envHelpers is derived from. The workspace (go.work)
// places it at ../../../../libs/... from this package's dir ; a
// missing file MUST fail loudly —
// silently shrinking the helper set would silently shrink coverage.
var envxSource = filepath.Join(moduleRoot, "..", "..",
	"libs", "hostkit", "envx", "envx.go")

// envHelpers is the complete set of env-reading helpers exported by
// libs/hostkit/envx — every exported func whose first parameter is a
// string named `key` or `name`. Derived by walking envx.go itself in
// envHelpersFromSource: a new getter ships in the scan the moment it
// lands in the library.
var envHelpers map[string]bool

// envHelpersFromSource derives envHelpers by parsing envxSource. A
// first param that is a string named `key`/`name` marks a helper
// whose first argument is an env key — envx's signature convention.
// Every read/parse failure is fatal: coverage that quietly finds
// nothing is worse than no coverage.
func envHelpersFromSource(t *testing.T) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, envxSource, nil, 0)
	if err != nil {
		t.Fatalf("parse envx source %s: %v — the helper set cannot "+
			"be derived; refusing to run with silently reduced coverage",
			envxSource, err)
	}
	helpers := map[string]bool{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || !fn.Name.IsExported() || fn.Type.Params == nil {
			continue
		}
		first := fn.Type.Params.List[0]
		typ, ok := first.Type.(*ast.Ident)
		if !ok || typ.Name != "string" {
			continue
		}
		for _, n := range first.Names {
			if n.Name == "key" || n.Name == "name" {
				helpers[fn.Name.Name] = true
			}
		}
	}
	// Self-check: the strict family's two anchors must be present or
	// the parse yielded garbage (renamed params, wrong file) — never
	// proceed with a silently reduced set.
	for _, want := range []string{"Getenv", "Gate"} {
		if !helpers[want] {
			t.Fatalf("envx helper derivation missed %s — the strict "+
				"family must anchor the derived set (got %v)", want, helpers)
		}
	}
	return helpers
}

// envNameRE restricts collected string literals to tokens that look
// like env-var names — ALL_CAPS with digits/underscores.
var envNameRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// rawEnvReads are the os package members that pull values from the
// process environment. Unlike node-automation-controller this module
// deliberately reads required vars through os.Getenv in
// cmd/dispatcher/main.go (the required-var check lists them
// explicitly) — the names are collected for doc coverage, not
// flagged.
var rawEnvReads = map[string]bool{
	"Getenv":    true,
	"LookupEnv": true,
	"ExpandEnv": true,
}

// TestEnvDocCoversSource fails when source introduces an env knob
// not documented in docs/env.md. Two sources feed the check:
//
//   - first arguments of envx.Getenv*/envx.String-family call sites
//     in cmd/dispatcher/*.go and internal/**/*.go — both string
//     literals and package-level string consts used as the key;
//   - os.Getenv/LookupEnv/ExpandEnv call sites — the required-var
//     check in main.go reads its keys this way on purpose.
//
// *_test.go files are skipped (test-only env seams are not operator
// surface) and internal/envdoc itself is never scanned — a stray
// literal in the checker must not feed back as a fake knob.
func TestEnvDocCoversSource(t *testing.T) {
	envHelpers = envHelpersFromSource(t)
	where, unresolved := collectEnvNames(t)

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
	for _, u := range unresolved {
		t.Errorf("unresolvable env key at %s — pass a string literal or a "+
			"package-level string const so the coverage test can see it", u)
	}
}

// collectEnvNames parses every non-test .go file under cmd/dispatcher
// and internal/ (internal/envdoc excluded) and returns:
//
//	where      — env-var name -> "relpath:line" of one use site, for
//	             failure messages;
//	unresolved — use sites whose env key is an identifier that does
//	             not resolve to a package-level string const in the
//	             same package — reported as test failures by the caller.
//
// Keys written as arbitrary other expressions (a field read, a
// concatenation, a call result) are ignored rather than flagged.
func collectEnvNames(t *testing.T) (map[string]string, []string) {
	t.Helper()

	envdocDir := filepath.Join(moduleRoot, "internal", "envdoc")

	// Env is read only on the operator surface: the entrypoint and
	// the internal packages. docs/ and module-root files carry no
	// Go source this scan cares about.
	dirs := []string{filepath.Join(moduleRoot, "cmd", "dispatcher")}
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

	// site renders a position module-relative so failure messages
	// read like every other path in this repo.
	site := func(fset *token.FileSet, pos token.Pos) string {
		p := fset.Position(pos)
		rel, err := filepath.Rel(moduleRoot, p.Filename)
		if err != nil {
			rel = p.Filename
		}
		return fmt.Sprintf("%s:%d", rel, p.Line)
	}

	record := func(fset *token.FileSet, value string, pos token.Pos) {
		if !envNameRE.MatchString(value) {
			return
		}
		if _, seen := where[value]; seen {
			return
		}
		where[value] = site(fset, pos)
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

		// Pass 1 — collect this package's string consts so an env
		// key written as `envx.String(someConst, ...)` still resolves
		// to a name. Bare rows in a const block repeat the previous
		// expression, handled by carrying `vals` forward.
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

		// Pass 2 — walk each file for env-reading call sites.
		for _, f := range files {
			// Per-file import-alias resolution: the envx/os
			// receiver is whatever local name THIS file binds the
			// import to.
			envxName, envxDot := importLocalName(f, envxImportPath)
			osName, _ := importLocalName(f, "os")
			// rangeVars marks loop variables bound to a []string
			// literal — the required-var check reads its keys that
			// way (`for _, key := range []string{...} { os.Getenv(key) }`).
			// The literals themselves are recorded when the RangeStmt
			// is visited (preorder, before the body's call sites).
			rangeVars := map[string]bool{}

			ast.Inspect(f, func(n ast.Node) bool {
				switch e := n.(type) {
				case *ast.RangeStmt:
					cl, ok := e.X.(*ast.CompositeLit)
					if !ok {
						return true
					}
					for _, elt := range cl.Elts {
						lit, ok := elt.(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							return true
						}
						if v, err := strconv.Unquote(lit.Value); err == nil {
							record(fset, v, e.Pos())
						}
					}
					for _, id := range []ast.Expr{e.Key, e.Value} {
						if ident, ok := id.(*ast.Ident); ok {
							rangeVars[ident.Name] = true
						}
					}
				case *ast.CallExpr:
					if len(e.Args) == 0 {
						return true
					}
					isEnv := isRawEnvRead(e, osName) ||
						isEnvCall(e, envxName, envxDot)
					if !isEnv {
						return true
					}
					addKey(e.Args[0], fset, e.Pos(), consts,
						rangeVars, record, &unresolved)
				}
				return true
			})
		}
	}

	return where, unresolved
}

// addKey records a literal env key or resolves a package-level
// string const; anything else lands on the unresolved list.
func addKey(expr ast.Expr, fset *token.FileSet, pos token.Pos,
	consts map[string]string, rangeVars map[string]bool,
	record func(*token.FileSet, string, token.Pos),
	unresolved *[]string) {
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
		if rangeVars[k.Name] {
			// Bound to a []string literal already recorded at
			// the RangeStmt — the keys are covered.
			return
		}
		// An identifier that is neither a string const nor a
		// recorded range variable — the scanner cannot name the key.
		p := fset.Position(pos)
		*unresolved = append(*unresolved,
			fmt.Sprintf("%s (%s)", p.Filename, k.Name))
	default:
		// Selector, concatenation, call result — a computed key.
	}
}

// importLocalName returns the identifier a file binds importPath
// to — the explicit alias when present, else the package's default
// name — plus whether it is dot-imported (unqualified calls). A
// blank/_ import yields ("", false): the package's funcs are
// unreachable.
func importLocalName(f *ast.File, importPath string) (string, bool) {
	for _, spec := range f.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil || path != importPath {
			continue
		}
		switch {
		case spec.Name == nil:
			return importPath[strings.LastIndex(importPath, "/")+1:], false
		case spec.Name.Name == ".":
			return "", true
		case spec.Name.Name == "_":
			return "", false
		default:
			return spec.Name.Name, false
		}
	}
	return "", false
}

// isEnvCall reports whether call is a read of an env var through one
// of the shared helpers — the qualified `envxName.Xxx(...)` form
// (alias resolved from the file's imports), the bare `Xxx(...)` form
// a dot import produces.
func isEnvCall(call *ast.CallExpr, envxName string, envxDot bool) bool {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		recv, ok := fun.X.(*ast.Ident)
		return ok && envxName != "" && recv.Name == envxName && envHelpers[fun.Sel.Name]
	case *ast.Ident:
		return envxDot && envHelpers[fun.Name]
	}
	return false
}

// isRawEnvRead reports whether call is os.Getenv/LookupEnv/
// ExpandEnv under whatever local name the file binds the os import
// to.
func isRawEnvRead(call *ast.CallExpr, osName string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	recv, ok := sel.X.(*ast.Ident)
	return ok && osName != "" && recv.Name == osName && rawEnvReads[sel.Sel.Name]
}
