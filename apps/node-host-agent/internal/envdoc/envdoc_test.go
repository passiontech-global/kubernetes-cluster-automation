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
// The package ships only this _test.go file — nothing here compiles
// into the agent, so depguard's platform-leaf rules do not apply.
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

// moduleRoot is the Go module root relative to this package's dir —
// go test runs each package with its own dir as working directory, so
// "../.." lands on apps/node-host-agent regardless of the package
// pattern passed.
const moduleRoot = "../.."

// envnamesImportPath lets the scanner resolve `envnames.EnvX` refs
// through each file's own import decl, so a future aliased import
// cannot evade the scan.
const envnamesImportPath = "github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"

// envVarRE is the contract shape: NODE_HOST_AGENT_ plus at least one
// ALL_CAPS/digit/underscore segment. It deliberately requires a full
// match so prose tokens like `NODE_HOST_AGENT_*` or
// `NODE_HOST_AGENT_ENABLE_*` in ENV.md's header never collect.
var envVarRE = regexp.MustCompile(`^NODE_HOST_AGENT_[A-Z0-9_]+$`)

// docExempt lists referenced knobs ENV.md deliberately has no row
// for — name -> reason. Entries must justify a REAL gap in the
// generator, not excuse missing docs; the test also asserts each
// exempted var is genuinely absent from ENV.md so the map cannot
// silently cover a fixed generator.
var docExempt = map[string]string{
	// ENABLE_FEEDER is read via envx.BoolKnob inside
	// controllerhygiene's ConfigFromEnv, not wired as a Descriptor
	// EnvFlag — gen-envdoc.sh builds the enable-gates table from
	// cmd/agent/wiring.go only, and filters every ENABLE_* var out
	// of the knob rows, so this bool sub-gate has no table to land
	// in. Undocumented by generator design, not by choice.
	"NODE_HOST_AGENT_ENABLE_FEEDER": "bool sub-gate resolved inside " +
		"controllerhygiene (envx.BoolKnob), not a Descriptor EnvFlag — " +
		"gen-envdoc.sh's gates table only sees wiring.go",
}

// contract is the parsed envnames package: byConst maps each Env*
// const name to its NODE_HOST_AGENT_* value, values is the value set,
// and declared holds every const name in the package (env-valued or
// not — e.g. DefaultSweepBaseDir) so a reference to a non-env const
// is skipped rather than misreported.
type contract struct {
	byConst  map[string]string
	values   map[string]bool
	declared map[string]bool
}

// scanResult is everything the source walk collects in one pass:
// referenced var values with a use site, envnames.Env* references
// that do not resolve to a contract const, raw NODE_HOST_AGENT_*
// literals outside envnames (stragglers — a missed refactor site or a
// not-yet-extracted knob), and const-style declarations of those
// literals outside envnames (a duplicated contract declaration).
type scanResult struct {
	referenced map[string]string // var value -> "relpath:line"
	unresolved []string          // "relpath:line (EnvFoo)" — no such const
	stragglers []string          // "relpath:line (literal)"
	dupDecls   []string          // "relpath:line (Name)" — const decl outside envnames
}

// collectContract parses internal/envnames/*.go (non-test) and pulls
// every string const. Bare rows in a const block repeat the previous
// expression, so `vals` carries forward exactly like the sibling
// app's envdoc does.
func collectContract(t *testing.T) contract {
	t.Helper()
	dir := filepath.Join(moduleRoot, "internal", "envnames")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	c := contract{
		byConst:  map[string]string{},
		values:   map[string]bool{},
		declared: map[string]bool{},
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", filepath.Join(dir, name), err)
		}
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
					c.declared[n.Name] = true
					if i >= len(vals) {
						continue
					}
					lit, ok := vals[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					v, err := strconv.Unquote(lit.Value)
					if err != nil || !envVarRE.MatchString(v) {
						continue
					}
					if !strings.HasPrefix(n.Name, "Env") {
						t.Fatalf("%s declares %s = %q — env-name consts "+
							"must use the Env* prefix (the const name IS "+
							"the contract handle)", filepath.Join(dir, name), n.Name, v)
					}
					c.byConst[n.Name] = v
					c.values[v] = true
				}
			}
		}
	}
	return c
}

// scanSource walks every non-test .go file under cmd/ and internal/
// (internal/envnames and internal/envdoc excluded — the contract's own
// literals live in the former, and a stray literal in the checker must
// not feed back as a fake reference) collecting envnames.Env*
// references, raw literals, and duplicated const declarations.
func scanSource(t *testing.T, c contract) scanResult {
	t.Helper()

	envnamesDir := filepath.Join(moduleRoot, "internal", "envnames")
	envdocDir := filepath.Join(moduleRoot, "internal", "envdoc")

	var dirs []string
	for _, root := range []string{filepath.Join(moduleRoot, "cmd"), filepath.Join(moduleRoot, "internal")} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if path == envnamesDir || path == envdocDir {
					return filepath.SkipDir
				}
				dirs = append(dirs, path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	sort.Strings(dirs)

	res := scanResult{referenced: map[string]string{}}

	site := func(fset *token.FileSet, pos token.Pos) string {
		p := fset.Position(pos)
		rel, err := filepath.Rel(moduleRoot, p.Filename)
		if err != nil {
			rel = p.Filename
		}
		return fmt.Sprintf("%s:%d", rel, p.Line)
	}

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read dir %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(dir, name)
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			envName := importLocalName(f, envnamesImportPath)
			if envName == "." {
				// A dot import makes refs bare (`EnvFoo`, no
				// selector) — invisible to this scan. Fail loudly
				// rather than silently skip the file's references.
				t.Fatalf("%s dot-imports internal/envnames — env "+
					"consts must stay qualified so the coverage "+
					"scan can see them", path)
			}

			// Const declarations carrying a contract literal outside
			// envnames duplicate the source of truth — collect them
			// separately from use-site literals so the failure message
			// can say which fix applies.
			for _, decl := range f.Decls {
				gen, ok := decl.(*ast.GenDecl)
				if !ok || gen.Tok != token.CONST {
					continue
				}
				for _, spec := range gen.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, v := range vs.Values {
						lit, ok := v.(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							continue
						}
						if s, err := strconv.Unquote(lit.Value); err == nil && envVarRE.MatchString(s) {
							who := "const"
							if i < len(vs.Names) {
								who = vs.Names[i].Name
							}
							res.dupDecls = append(res.dupDecls,
								fmt.Sprintf("%s (%s)", site(fset, lit.Pos()), who))
						}
					}
				}
			}

			ast.Inspect(f, func(n ast.Node) bool {
				switch e := n.(type) {
				case *ast.BasicLit:
					if e.Kind != token.STRING {
						return true
					}
					if s, err := strconv.Unquote(e.Value); err == nil && envVarRE.MatchString(s) {
						res.stragglers = append(res.stragglers,
							fmt.Sprintf("%s (%q)", site(fset, e.Pos()), s))
					}
				case *ast.SelectorExpr:
					recv, ok := e.X.(*ast.Ident)
					if !ok || envName == "" || recv.Name != envName {
						return true
					}
					sel := e.Sel.Name
					if !strings.HasPrefix(sel, "Env") {
						return true // Default*/other non-env consts
					}
					if v, ok := c.byConst[sel]; ok {
						if _, seen := res.referenced[v]; !seen {
							res.referenced[v] = site(fset, e.Pos())
						}
						return true
					}
					if !c.declared[sel] {
						res.unresolved = append(res.unresolved,
							fmt.Sprintf("%s (envnames.%s)", site(fset, e.Pos()), sel))
					}
					// Declared but not env-valued: an Env* const
					// holding a non-NODE_HOST_AGENT_* value — the
					// contract scan already refuses those, so
					// nothing to record here.
				}
				return true
			})
		}
	}
	return res
}

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
		if envVarRE.MatchString(m[1]) {
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

// importLocalName returns the identifier a file binds importPath to —
// the explicit alias when present, else the package's default name.
// Blank imports yield "": the package's consts are unreachable.
func importLocalName(f *ast.File, importPath string) string {
	for _, spec := range f.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil || path != importPath {
			continue
		}
		switch {
		case spec.Name == nil:
			return importPath[strings.LastIndex(importPath, "/")+1:]
		case spec.Name.Name == ".":
			// A dot import makes the consts UNQUALIFIED — the
			// selector scan cannot see `EnvFoo` bare refs, so fail
			// loudly rather than scan half the file.
			return "."
		case spec.Name.Name == "_":
			return ""
		default:
			return spec.Name.Name
		}
	}
	return ""
}

// TestEnvDocCoversContract is the ENV.md honesty check. Collected
// once, asserted in subtests:
//
//   - references-resolve: every envnames.Env* a call site names is a
//     declared contract const (belt-and-braces — the compiler already
//     refuses a missing const, but this also pins the scan itself);
//   - referenced-knobs-documented: every contract value referenced by
//     non-test code appears in ENV.md (docExempt aside);
//   - documented-knobs-declared: every var ENV.md lists is still a
//     declared const — catches a removed knob whose doc row survived;
//   - no-raw-literals: no "NODE_HOST_AGENT_*" string literal outside
//     envnames — the convention is const references only, and a
//     straggler means either a missed refactor or a knob never
//     extracted into the contract;
//   - no-duplicate-const-decls: no `= "NODE_HOST_AGENT_*"` const
//     declaration outside envnames.
func TestEnvDocCoversContract(t *testing.T) {
	c := collectContract(t)
	res := scanSource(t, c)
	doc := docVars(t)

	// Self-checks: a coverage test collecting nothing passes
	// vacuously, which is worse than no test. The anchors pin both
	// ends of the scan — a const that must exist and a var cmd/agent
	// provably reads.
	if len(c.byConst) < 100 {
		t.Fatalf("envnames parse yielded only %d contract consts — "+
			"the contract is ~140 names; the scanner is broken", len(c.byConst))
	}
	if v := c.byConst["EnvStandalone"]; v != "NODE_HOST_AGENT_STANDALONE" {
		t.Fatalf("anchor const EnvStandalone = %q, want "+
			"NODE_HOST_AGENT_STANDALONE — const extraction regressed", v)
	}
	if len(res.referenced) == 0 {
		t.Fatal("reference scan collected 0 vars — the scanner is broken")
	}
	if _, ok := res.referenced["NODE_HOST_AGENT_STANDALONE"]; !ok {
		t.Fatal("NODE_HOST_AGENT_STANDALONE missing from scan results — " +
			"envnames.Env* resolution regressed")
	}
	t.Logf("contract: %d consts; referenced: %d vars; documented: %d vars",
		len(c.byConst), len(res.referenced), len(doc))

	t.Run("references-resolve", func(t *testing.T) {
		for _, u := range res.unresolved {
			t.Errorf("envnames reference at %s names no declared const", u)
		}
	})

	t.Run("referenced-knobs-documented", func(t *testing.T) {
		vars := make([]string, 0, len(res.referenced))
		for v := range res.referenced {
			vars = append(vars, v)
		}
		sort.Strings(vars)
		for _, v := range vars {
			if reason, exempt := docExempt[v]; exempt {
				if doc[v] {
					t.Errorf("%s is in docExempt (%s) but IS documented — "+
						"remove the stale exemption", v, reason)
				}
				continue
			}
			if !doc[v] {
				t.Errorf("%s (read at %s) is not documented in ENV.md — "+
					"run scripts/gen-envdoc.sh", v, res.referenced[v])
			}
		}
	})

	t.Run("documented-knobs-declared", func(t *testing.T) {
		vars := make([]string, 0, len(doc))
		for v := range doc {
			vars = append(vars, v)
		}
		sort.Strings(vars)
		for _, v := range vars {
			if !c.values[v] {
				t.Errorf("ENV.md documents %s but envnames declares no "+
					"const with that value — stale doc row (regenerate "+
					"ENV.md) or an undocumented external var", v)
			}
		}
	})

	t.Run("no-raw-literals", func(t *testing.T) {
		for _, s := range res.stragglers {
			t.Errorf("raw NODE_HOST_AGENT_* literal at %s — reference "+
				"the envnames.Env* const instead (extract it into "+
				"internal/envnames first if none exists)", s)
		}
	})

	t.Run("no-duplicate-const-decls", func(t *testing.T) {
		for _, d := range res.dupDecls {
			t.Errorf("const declaration of a NODE_HOST_AGENT_* value at "+
				"%s outside internal/envnames — env names are declared "+
				"exactly once in the contract package", d)
		}
	})
}
