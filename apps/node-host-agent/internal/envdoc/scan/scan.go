// Package scan is the importable core of the ENV.md pipeline: it
// parses the envnames contract package, every non-test call site
// under cmd/ and internal/, and the descriptor registry in
// cmd/agent/wiring.go — the same three AST passes the envdoc honesty
// test (internal/envdoc) and the gates-table generator
// (internal/envdoc/cmd/genenvdoc, called by scripts/gen-envdoc.sh)
// both need. CollectContract and ScanSource moved here verbatim from
// the test's collectContract/scanSource; ScanGates replaces the
// line-based awk over wiring.go and is comment-proof by construction.
//
// Callers pass the node-host-agent module root as root ("." for the
// generator, "../.." for the test, whose package dir is two levels
// deeper). The package imports only the stdlib: it documents the
// agent, it is never compiled into it, so depguard's platform-leaf
// rules do not apply.
package scan

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
)

// EnvVarRE is the contract shape: NODE_HOST_AGENT_ plus at least one
// ALL_CAPS/digit/underscore segment. It deliberately requires a full
// match so prose tokens like `NODE_HOST_AGENT_*` or
// `NODE_HOST_AGENT_ENABLE_*` in ENV.md's header never collect.
var EnvVarRE = regexp.MustCompile(`^NODE_HOST_AGENT_[A-Z0-9_]+$`)

// envnamesImportPath lets the scanner resolve `envnames.EnvX` refs
// through each file's own import decl, so a future aliased import
// cannot evade the scan.
const envnamesImportPath = "github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"

// Contract is the parsed envnames package: ByConst maps each Env*
// const name to its NODE_HOST_AGENT_* value, Values is the value set,
// and Declared holds every const name in the package (env-valued or
// not — e.g. DefaultSweepBaseDir) so a reference to a non-env const
// is skipped rather than misreported.
type Contract struct {
	ByConst  map[string]string
	Values   map[string]bool
	Declared map[string]bool
}

// ScanResult is everything the source walk collects in one pass:
// referenced var values with a use site, envnames.Env* references
// that do not resolve to a contract const, raw NODE_HOST_AGENT_*
// literals outside envnames (stragglers — a missed refactor site or a
// not-yet-extracted knob), and const-style declarations of those
// literals outside envnames (a duplicated contract declaration).
type ScanResult struct {
	Referenced map[string]string // var value -> "relpath:line"
	Unresolved []string          // "relpath:line (EnvFoo)" — no such const
	Stragglers []string          // "relpath:line (literal)"
	DupDecls   []string          // "relpath:line (Name)" — const decl outside envnames
}

// CollectContract parses internal/envnames/*.go (non-test) under root
// and pulls every string const. Bare rows in a const block repeat the
// previous expression, so `vals` carries forward exactly like the
// sibling app's envdoc does. An env-valued const whose name lacks the
// Env* prefix is an error: the const name IS the contract handle.
func CollectContract(root string) (Contract, error) {
	dir := filepath.Join(root, "internal", "envnames")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return Contract{}, fmt.Errorf("read %s: %w", dir, err)
	}
	c := Contract{
		ByConst:  map[string]string{},
		Values:   map[string]bool{},
		Declared: map[string]bool{},
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
			return Contract{}, fmt.Errorf("parse %s: %w", path, err)
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
					c.Declared[n.Name] = true
					if i >= len(vals) {
						continue
					}
					lit, ok := vals[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					v, err := strconv.Unquote(lit.Value)
					if err != nil || !EnvVarRE.MatchString(v) {
						continue
					}
					if !strings.HasPrefix(n.Name, "Env") {
						return Contract{}, fmt.Errorf("%s declares %s = %q — env-name consts "+
							"must use the Env* prefix (the const name IS "+
							"the contract handle)", path, n.Name, v)
					}
					c.ByConst[n.Name] = v
					c.Values[v] = true
				}
			}
		}
	}
	return c, nil
}

// ScanSource walks every non-test .go file under cmd/ and internal/
// (internal/envnames and internal/envdoc excluded — the contract's own
// literals live in the former, and a stray literal in the envdoc
// packages must not feed back as a fake reference) collecting
// envnames.Env* references, raw literals, and duplicated const
// declarations.
func ScanSource(root string, c Contract) (ScanResult, error) {
	envnamesDir := filepath.Join(root, "internal", "envnames")
	envdocDir := filepath.Join(root, "internal", "envdoc")

	var dirs []string
	for _, dirRoot := range []string{filepath.Join(root, "cmd"), filepath.Join(root, "internal")} {
		err := filepath.WalkDir(dirRoot, func(path string, d fs.DirEntry, err error) error {
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
			return ScanResult{}, fmt.Errorf("walk %s: %w", dirRoot, err)
		}
	}
	sort.Strings(dirs)

	res := ScanResult{Referenced: map[string]string{}}

	site := func(fset *token.FileSet, pos token.Pos) string {
		p := fset.Position(pos)
		rel, err := filepath.Rel(root, p.Filename)
		if err != nil {
			rel = p.Filename
		}
		return fmt.Sprintf("%s:%d", rel, p.Line)
	}

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return ScanResult{}, fmt.Errorf("read dir %s: %w", dir, err)
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
				return ScanResult{}, fmt.Errorf("parse %s: %w", path, err)
			}
			envName := importLocalName(f, envnamesImportPath)
			if envName == "." {
				// A dot import makes refs bare (`EnvFoo`, no
				// selector) — invisible to this scan. Fail loudly
				// rather than silently skip the file's references.
				return ScanResult{}, fmt.Errorf("%s dot-imports internal/envnames — env "+
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
						if s, err := strconv.Unquote(lit.Value); err == nil && EnvVarRE.MatchString(s) {
							who := "const"
							if i < len(vs.Names) {
								who = vs.Names[i].Name
							}
							res.DupDecls = append(res.DupDecls,
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
					if s, err := strconv.Unquote(e.Value); err == nil && EnvVarRE.MatchString(s) {
						res.Stragglers = append(res.Stragglers,
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
					if v, ok := c.ByConst[sel]; ok {
						if _, seen := res.Referenced[v]; !seen {
							res.Referenced[v] = site(fset, e.Pos())
						}
						return true
					}
					if !c.Declared[sel] {
						res.Unresolved = append(res.Unresolved,
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
	return res, nil
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
