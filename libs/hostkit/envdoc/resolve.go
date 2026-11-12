// resolve.go — the envdoc scan's name-resolution layer: deriving
// the envx helper set from the envx package's own sources, the
// package string-const table, and the import/call-site classifiers
// that decide whether a CallExpr reads an env var. Split from
// envdoc.go (the walk + range-scope machinery) to keep both files
// under the size ceiling.
package envdoc

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// EnvxHelpers derives the complete set of env-reading helpers
// exported by the envx package: every exported func whose first
// parameter is a string named `key` (the getters) or `name` (the
// *Knob constructors). All non-test .go files directly inside
// envxDir are parsed — the helper set must not depend on which file
// a getter happens to live in (envx.go, strict.go and knobs.go all
// contribute). A missing Getenv or Gate anchor is an error: the
// parse yielded garbage (renamed params, wrong dir) and proceeding
// would silently shrink coverage.
func EnvxHelpers(envxDir string) (map[string]bool, error) {
	entries, err := os.ReadDir(envxDir)
	if err != nil {
		return nil, fmt.Errorf("envdoc: read envx dir %s: %w", envxDir, err)
	}
	fset := token.NewFileSet()
	helpers := map[string]bool{}
	parsed := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(envxDir, name), nil, 0)
		if err != nil {
			return nil, fmt.Errorf("envdoc: parse %s: %w", filepath.Join(envxDir, name), err)
		}
		parsed++
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() || fn.Type.Params == nil ||
				len(fn.Type.Params.List) == 0 {
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
	}
	if parsed == 0 {
		return nil, fmt.Errorf("envdoc: no .go files under %s", envxDir)
	}
	for _, want := range []string{"Getenv", "Gate"} {
		if !helpers[want] {
			return nil, fmt.Errorf("envdoc: envx helper derivation missed %s — "+
				"the strict family must anchor the derived set (got %v)", want, helpers)
		}
	}
	return helpers, nil
}

// PackageStringConsts collects a package's string consts so an env
// key written as `envx.String(someConst, ...)` still resolves to a
// name. Bare rows in a const block repeat the previous expression,
// handled by carrying `vals` forward. files must be the parsed
// non-test sources of ONE directory (one package).
func PackageStringConsts(files []*ast.File) map[string]string {
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
	return consts
}

// importLocalName returns the identifier a file binds importPath to
// — the explicit alias when present, else the package's default
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
// a dot import or an in-tree envx package produces. An unqualified
// same-named function anywhere else is not our business.
func isEnvCall(call *ast.CallExpr, envxName string, envxDot, inEnvx bool, helpers map[string]bool) bool {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		recv, ok := fun.X.(*ast.Ident)
		return ok && envxName != "" && recv.Name == envxName && helpers[fun.Sel.Name]
	case *ast.Ident:
		return (inEnvx || envxDot) && helpers[fun.Name]
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
	return ok && osName != "" && recv.Name == osName && rawEnvReadNames[sel.Sel.Name]
}
