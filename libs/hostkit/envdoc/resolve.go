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
	"slices"
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
// PackageStringConsts collects package-level string constants
// (literals, string concatenations, parenthesized expressions, and
// same-package const aliases) mapped from identifier name to value.
// Bare rows in a const block repeat the previous expression, handled
// by carrying `vals` forward. files must be the parsed non-test
// sources of ONE directory (one package).
func PackageStringConsts(files []*ast.File) map[string]string {
	consts := make(map[string]string)
	pending := make(map[string]ast.Expr)
	lookupConst := func(id *ast.Ident) (string, bool) {
		v, ok := consts[id.Name]
		return v, ok
	}
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
					if v, ok := evalStaticStringExpr(vals[i], lookupConst); ok {
						consts[n.Name] = v
					} else {
						pending[n.Name] = vals[i]
					}
				}
			}
		}
	}
	for len(pending) > 0 {
		progressed := false
		for name, expr := range pending {
			if v, ok := evalStaticStringExpr(expr, lookupConst); ok {
				consts[name] = v
				delete(pending, name)
				progressed = true
			}
		}
		if !progressed {
			break
		}
	}
	return consts
}

func evalStaticStringExpr(expr ast.Expr, resolveIdent func(*ast.Ident) (string, bool)) (string, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		v, err := strconv.Unquote(e.Value)
		return v, err == nil
	case *ast.ParenExpr:
		return evalStaticStringExpr(e.X, resolveIdent)
	case *ast.Ident:
		return resolveIdent(e)
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		l, lok := evalStaticStringExpr(e.X, resolveIdent)
		r, rok := evalStaticStringExpr(e.Y, resolveIdent)
		if lok && rok {
			return l + r, true
		}
	}
	return "", false
}

// importLocalNames collects every identifier a file binds importPath
// to (explicit aliases and default package names) plus whether
// importPath is dot-imported. Blank (_) imports are skipped without
// short-circuiting later imports of the same path.
func importLocalNames(f *ast.File, importPath string) ([]string, bool) {
	var names []string
	dot := false
	for _, spec := range f.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil || path != importPath {
			continue
		}
		switch {
		case spec.Name == nil:
			names = append(names, importPath[strings.LastIndex(importPath, "/")+1:])
		case spec.Name.Name == ".":
			dot = true
		case spec.Name.Name == "_":
			continue
		default:
			names = append(names, spec.Name.Name)
		}
	}
	return names, dot
}

// isEnvCall reports whether call is a read of an env var through one
// of the shared helpers — the qualified `envxName.Xxx(...)` form
// (aliases resolved from the file's imports), or the bare `Xxx(...)`
// form a dot import or an in-tree envx package produces, provided the
// receiver or function name is not shadowed by a local declaration.
func isEnvCall(call *ast.CallExpr, envxNames []string, envxDot, inEnvx bool, helpers map[string]bool, isLocal func(string) bool) bool {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		recv, ok := fun.X.(*ast.Ident)
		return ok && slices.Contains(envxNames, recv.Name) && !isLocal(recv.Name) && helpers[fun.Sel.Name]
	case *ast.Ident:
		return (inEnvx || envxDot) && !isLocal(fun.Name) && helpers[fun.Name]
	}
	return false
}

// isRawEnvRead reports whether call is os.Getenv/LookupEnv/ExpandEnv
// under any local name (or dot import) the file binds the os import
// to, provided the receiver or function name is not locally shadowed.
func isRawEnvRead(call *ast.CallExpr, osNames []string, osDot bool, isLocal func(string) bool) bool {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		recv, ok := fun.X.(*ast.Ident)
		return ok && slices.Contains(osNames, recv.Name) && !isLocal(recv.Name) && rawEnvReadNames[fun.Sel.Name]
	case *ast.Ident:
		return osDot && !isLocal(fun.Name) && rawEnvReadNames[fun.Name]
	}
	return false
}
