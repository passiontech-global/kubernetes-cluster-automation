// latches_test.go — registry invariants for LatchDefs vs Latch* consts.
package latchdefs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

func TestLatchDefsCompletenessAndUniqueness(t *testing.T) {
	seen := make(map[string]bool, len(LatchDefs))
	for _, d := range LatchDefs {
		if d.Name == "" {
			t.Fatal("LatchDefs contains an entry with empty Name")
		}
		if d.Owner == "" {
			t.Fatalf("LatchDefs[%q] has empty Owner", d.Name)
		}
		if seen[d.Name] {
			t.Fatalf("duplicate LatchDefs entry %q", d.Name)
		}
		seen[d.Name] = true
		if d.Prefix && !strings.HasSuffix(d.Name, "-") {
			t.Fatalf("Prefix LatchDef %q must end with '-'", d.Name)
		}
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "latches.go", nil, 0)
	if err != nil {
		t.Fatalf("parse latches.go: %v", err)
	}
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
			for i, name := range vs.Names {
				if name.Name == "LatchFilePrefix" || !strings.HasPrefix(name.Name, "Latch") || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				val, err := strconv.Unquote(lit.Value)
				if err != nil {
					continue
				}
				if !seen[val] {
					t.Errorf("const %s (%q) is not registered in LatchDefs", name.Name, val)
				}
			}
		}
	}
}
