package scan

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
)

// Gate is one row of ENV.md's enable-gates table, parsed straight out
// of the Descriptor registry: Name is the subsystem name, EnvFlag the
// resolved NODE_HOST_AGENT_ENABLE_* var ("" = no env gate), Default
// the raw Default expression exactly as written in wiring.go
// ("" = the descriptor sets no default). The gates-table generator
// renders "" cells as "—", matching the awk output it replaced.
type Gate struct {
	Name    string
	EnvFlag string
	Default string
}

// ScanGates parses cmd/agent/wiring.go under root with go/ast and
// returns one Gate per element of the `[]Descriptor{...}` registry
// literal, in source order — which is also startup order. EnvFlag
// holds an envnames.Env* const, resolved through c (an unresolved
// const name is kept verbatim, and a bare "..." literal is accepted
// too, same as the awk it replaces). Because rows come from array
// elements rather than text lines, comments inside the registry can
// neither forge a row nor split one — the failure mode that motivated
// the move off awk.
func ScanGates(root string, c Contract) ([]Gate, error) {
	path := filepath.Join(root, "cmd", "agent", "wiring.go")
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	var gates []Gate
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		arr, ok := lit.Type.(*ast.ArrayType)
		if !ok {
			return true
		}
		elt, ok := arr.Elt.(*ast.Ident)
		if !ok || elt.Name != "Descriptor" {
			return true
		}
		for _, e := range lit.Elts {
			row, ok := e.(*ast.CompositeLit)
			if !ok {
				continue
			}
			g := Gate{}
			for _, kv := range row.Elts {
				kve, ok := kv.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kve.Key.(*ast.Ident)
				if !ok {
					continue
				}
				switch key.Name {
				case "Name":
					if s, ok := unquote(kve.Value); ok {
						g.Name = s
					}
				case "EnvFlag":
					g.EnvFlag = flagVar(kve.Value, c)
				case "Default":
					// Keep the expression text exactly as written —
					// the doc shows `onOff(w.defKube)`, `envx.ModeOn`.
					g.Default = sourceSlice(fset, src, kve.Value)
				}
			}
			gates = append(gates, g)
		}
		return true
	})
	return gates, nil
}

// flagVar resolves an EnvFlag value expression to the env var it
// names: an `envnames.EnvX` selector goes through the contract map
// (falling back to the bare selector name when the const is missing —
// the doc should still show the intent), and a string literal is
// taken as-is. Anything else yields "".
func flagVar(expr ast.Expr, c Contract) string {
	if sel, ok := expr.(*ast.SelectorExpr); ok {
		if _, ok := sel.X.(*ast.Ident); ok {
			name := sel.Sel.Name
			if v, ok := c.ByConst[name]; ok {
				return v
			}
			return name
		}
		return ""
	}
	s, _ := unquote(expr)
	return s
}

// sourceSlice returns the exact source text of expr — byte offsets
// come from the file the position belongs to, not the FileSet.
func sourceSlice(fset *token.FileSet, src []byte, expr ast.Expr) string {
	file := fset.File(expr.Pos())
	if file == nil || file.End() < expr.End() {
		return ""
	}
	return string(src[file.Offset(expr.Pos()):file.Offset(expr.End())])
}

// unquote extracts the value of a quoted string literal expression;
// ok is false for anything else (nil values, calls, constants).
func unquote(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return s, true
}
