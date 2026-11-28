// range.go — AST lexical scope, range-variable binding, knob literal
// scanning, and env-key resolution for ScanTree.
package envdoc

import (
	"fmt"
	"go/ast"
	"go/token"
	"slices"
	"strconv"
)

// bindPos identifies which side of a `for K, V := range X` a name
// binds — coverage is tracked per position because a slice literal's
// elements bind the VALUE side while a map literal's keys and
// values bind different positions.
type bindPos uint8

const (
	bindKey bindPos = iota + 1
	bindValue
)

// rangeFrame is one RangeStmt's binding scope on the AST stack: the
// body positions an identifier must sit inside for the binding to
// apply, each bound name's position, and per-position coverage —
// cover reports a static (literal or package-const) element can
// bind that side, dyn reports a dynamic element can. A use of the
// variable as an env key is cleanly covered only when cover holds
// AND dyn does not: `[]string{"A", key()}` still leaves the scanner
// unable to name every key the variable might carry.
type rangeFrame struct {
	body       *ast.BlockStmt
	names      map[string]bindPos
	coverKey   bool
	coverValue bool
	dynKey     bool
	dynValue   bool
	scopeDepth int
}

// fileScan carries one file's scan state: import aliases, the
// package const table, the registry/envx directory flags, the
// lexical declaration scopes, and the live range-binding stack.
type fileScan struct {
	fset         *token.FileSet
	res          *Result
	consts       map[string]string
	envxNames    []string
	envxDot      bool
	osNames      []string
	osDot        bool
	inEnvx       bool
	inRegistry   bool
	allowRawOS   bool
	helpers      map[string]bool
	site         func(fset *token.FileSet, pos token.Pos) string
	record       func(fset *token.FileSet, value string, pos token.Pos)
	stack        []*rangeFrame
	scopes       []map[string]bool
	pendingKnobs map[*ast.CompositeLit]bool
}

type visitFrame struct {
	popRange   bool
	popScope   bool
	assignDecl *ast.AssignStmt
	valueDecl  *ast.ValueSpec
}

// rangeVisitor is the ast.Visitor Walk drives. It exists so a
// RangeStmt's frame and lexical declaration scopes can be pushed on
// entry and popped/committed on exit — ast.Inspect has no exit hook.
type rangeVisitor struct {
	s      *fileScan
	frames []visitFrame
}

func (v *rangeVisitor) Visit(n ast.Node) ast.Visitor {
	if n == nil {
		// Walk calls Visit(nil) on the visitor a node returned after
		// that node's children — commit any post-walk declarations
		// (RHS/Values are walked before the LHS/Name enters scope)
		// and unwind any pushed range/scope frames in LIFO order.
		if last := len(v.frames) - 1; last >= 0 {
			frame := v.frames[last]
			v.frames = v.frames[:last]
			if frame.assignDecl != nil {
				for _, lhs := range frame.assignDecl.Lhs {
					if id, ok := lhs.(*ast.Ident); ok {
						v.s.declareLocal(id.Name)
					}
				}
			}
			if frame.valueDecl != nil {
				for _, name := range frame.valueDecl.Names {
					v.s.declareLocal(name.Name)
				}
			}
			if frame.popRange && len(v.s.stack) > 0 {
				v.s.stack = v.s.stack[:len(v.s.stack)-1]
			}
			if frame.popScope && len(v.s.scopes) > 0 {
				v.s.scopes = v.s.scopes[:len(v.s.scopes)-1]
			}
		}
		return nil
	}
	v.frames = append(v.frames, v.s.inspect(n))
	return v
}

func (s *fileScan) pushScope() {
	s.scopes = append(s.scopes, nil)
}

func (s *fileScan) declareLocal(name string) {
	if name == "" || name == "_" || len(s.scopes) == 0 {
		return
	}
	top := len(s.scopes) - 1
	if s.scopes[top] == nil {
		s.scopes[top] = map[string]bool{}
	}
	s.scopes[top][name] = true
}

func (s *fileScan) declareFieldList(fl *ast.FieldList) {
	if fl == nil {
		return
	}
	for _, field := range fl.List {
		for _, name := range field.Names {
			s.declareLocal(name.Name)
		}
	}
}

func (s *fileScan) localDeclDepth(name string) int {
	for i := len(s.scopes) - 1; i >= 0; i-- {
		if s.scopes[i][name] {
			return i
		}
	}
	return -1
}

func (s *fileScan) isLocalAt(name string, pos token.Pos) bool {
	if s.localDeclDepth(name) >= 0 {
		return true
	}
	bound, _, _ := s.rangeResolve(name, pos)
	return bound
}

// inspect handles the node types the scan cares about and returns
// the visitFrame recording any range/scope pushes or deferred local
// declarations. Called for every node in preorder (before children).
func (s *fileScan) inspect(n ast.Node) visitFrame {
	var frame visitFrame
	switch e := n.(type) {
	case *ast.FuncDecl:
		frame.popScope = true
		s.pushScope()
		s.declareFieldList(e.Recv)
		if e.Type != nil {
			s.declareFieldList(e.Type.TypeParams)
			s.declareFieldList(e.Type.Params)
			s.declareFieldList(e.Type.Results)
		}
	case *ast.FuncLit:
		frame.popScope = true
		s.pushScope()
		if e.Type != nil {
			s.declareFieldList(e.Type.TypeParams)
			s.declareFieldList(e.Type.Params)
			s.declareFieldList(e.Type.Results)
		}
	case *ast.BlockStmt, *ast.IfStmt, *ast.ForStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.CaseClause, *ast.CommClause:
		frame.popScope = true
		s.pushScope()
	case *ast.RangeStmt:
		frame.popRange = s.scanRange(e)
	case *ast.CompositeLit:
		s.markKnobContainerElems(e)
		frame.popRange = s.scanKnobLit(e)
	case *ast.AssignStmt:
		if e.Tok == token.DEFINE && len(s.scopes) > 0 {
			frame.assignDecl = e
		} else if e.Tok == token.ASSIGN {
			s.taintReassignedRangeVars(e)
		}
	case *ast.ValueSpec:
		if len(s.scopes) > 0 {
			frame.valueDecl = e
		}
	case *ast.CallExpr:
		s.scanCall(e)
	case *ast.KeyValueExpr:
		if s.inRegistry {
			if key, ok := e.Key.(*ast.Ident); ok && key.Name == "GateEnv" {
				s.addKey(e.Value, e.Pos())
			}
		}
	}
	return frame
}

// scanRange classifies a `for ... range X` binding: a composite
// literal contributes per-position cover/dyn flags (and every
// literal element is recorded as a candidate env read), then the
// loop variables' binding frame is pushed so identifiers inside the
// body resolve against it — and only there. Reports whether a frame
// was pushed (a RangeStmt binding no identifiers pushes none).
func (s *fileScan) scanRange(e *ast.RangeStmt) bool {
	var coverKey, coverValue, dynKey, dynValue bool
	if cl, isLit := e.X.(*ast.CompositeLit); isLit {
		coverKey, coverValue, dynKey, dynValue = s.scanRangeLit(cl, e.Pos())
	}
	names := map[string]bindPos{}
	if id, ok := e.Key.(*ast.Ident); ok && id.Name != "_" {
		names[id.Name] = bindKey
	}
	if id, ok := e.Value.(*ast.Ident); ok && id.Name != "_" {
		names[id.Name] = bindValue
	}
	if len(names) == 0 {
		return false
	}
	s.stack = append(s.stack, &rangeFrame{
		body: e.Body, names: names,
		coverKey: coverKey, coverValue: coverValue,
		dynKey: dynKey, dynValue: dynValue,
		scopeDepth: len(s.scopes),
	})
	return true
}

// isKnobType reports whether t names envx.Knob (or bare Knob when
// dot-imported or inside the envx package).
func (s *fileScan) isKnobType(t ast.Expr) bool {
	switch x := t.(type) {
	case *ast.SelectorExpr:
		recv, ok := x.X.(*ast.Ident)
		return ok && x.Sel.Name == "Knob" && slices.Contains(s.envxNames, recv.Name) && s.localDeclDepth(recv.Name) < 0
	case *ast.Ident:
		return (s.inEnvx || s.envxDot) && x.Name == "Knob" && s.localDeclDepth(x.Name) < 0
	}
	return false
}

// markKnobContainerElems marks untyped element literals inside []envx.Knob{...},
// [N]envx.Knob{...}, or map[K]envx.Knob{...} so elided `{Name, Resolve}` rows
// are recognized by scanKnobLit when ast.Walk visits them next.
func (s *fileScan) markKnobContainerElems(cl *ast.CompositeLit) {
	mark := func(expr ast.Expr) {
		elem, ok := expr.(*ast.CompositeLit)
		if !ok || elem.Type != nil {
			return
		}
		if s.pendingKnobs == nil {
			s.pendingKnobs = map[*ast.CompositeLit]bool{}
		}
		s.pendingKnobs[elem] = true
	}
	switch t := cl.Type.(type) {
	case *ast.ArrayType:
		if !s.isKnobType(t.Elt) {
			return
		}
		for _, elt := range cl.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				mark(kv.Value)
			} else {
				mark(elt)
			}
		}
	case *ast.MapType:
		if !s.isKnobType(t.Value) {
			return
		}
		for _, elt := range cl.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				mark(kv.Value)
			}
		}
	}
}

// scanKnobLit handles the documented `envx.Knob{Name: "ENV_VAR", Resolve: func(k string) { ... }}`
// (and elided-type slice/unkeyed variants) idiom: records the Name expression
// as an env key and, when Name resolved cleanly and Resolve is a single-param
// FuncLit, pushes a rangeFrame binding that parameter across Resolve.Body so
// `envx.String(k, ...)` inside Resolve does not falsely report k as Unresolved.
func (s *fileScan) scanKnobLit(cl *ast.CompositeLit) bool {
	isPending := s.pendingKnobs[cl]
	if isPending {
		delete(s.pendingKnobs, cl)
	}
	if !isPending && !s.isKnobType(cl.Type) {
		return false
	}
	var nameExpr ast.Expr
	var namePos token.Pos
	var resolveLit *ast.FuncLit
	hasKV := false
	for _, elt := range cl.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		hasKV = true
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "Name":
			nameExpr = kv.Value
			namePos = kv.Pos()
		case "Resolve":
			if fn, ok := kv.Value.(*ast.FuncLit); ok {
				resolveLit = fn
			}
		}
	}
	if !hasKV && len(cl.Elts) == 2 {
		nameExpr = cl.Elts[0]
		namePos = cl.Elts[0].Pos()
		if fn, ok := cl.Elts[1].(*ast.FuncLit); ok {
			resolveLit = fn
		}
	}
	if nameExpr == nil {
		return false
	}
	unresolvedBefore := len(s.res.Unresolved)
	s.addKey(nameExpr, namePos)
	clean := len(s.res.Unresolved) == unresolvedBefore
	if resolveLit == nil || resolveLit.Body == nil || resolveLit.Type == nil || resolveLit.Type.Params == nil {
		return false
	}
	var paramName string
	for _, field := range resolveLit.Type.Params.List {
		for _, n := range field.Names {
			if paramName != "" {
				return false
			}
			paramName = n.Name
		}
	}
	if paramName == "" || paramName == "_" {
		return false
	}
	// Resolve's FuncLit pushes its own scope (+1) when entered, so the
	// binding's scopeDepth must exceed the FuncLit param scope (+1) so
	// addKey recognizes k as knob-bound rather than shadowed by the param.
	s.stack = append(s.stack, &rangeFrame{
		body:       resolveLit.Body,
		names:      map[string]bindPos{paramName: bindValue},
		coverValue: clean,
		dynValue:   !clean,
		scopeDepth: len(s.scopes) + 2,
	})
	return true
}

// taintReassignedRangeVars marks an enclosing range variable unclean if
// reassigned via `=` inside the loop body (e.g. `k = dynamic()`).
func (s *fileScan) taintReassignedRangeVars(e *ast.AssignStmt) {
	for _, lhs := range e.Lhs {
		id, ok := lhs.(*ast.Ident)
		if !ok || id.Name == "_" {
			continue
		}
		for i := len(s.stack) - 1; i >= 0; i-- {
			f := s.stack[i]
			pos, ok := f.names[id.Name]
			if !ok || e.Pos() <= f.body.Pos() || e.Pos() >= f.body.End() {
				continue
			}
			if s.localDeclDepth(id.Name) >= f.scopeDepth {
				// Reassignment targets an inner shadowing variable, not the loop var.
				break
			}
			if pos == bindKey {
				f.dynKey = true
			} else {
				f.dynValue = true
			}
			break
		}
	}
}

// scanRangeLit walks a ranged composite literal: every literal
// element is recorded as a candidate env read (the Referenced
// over-approximation is unchanged), then the elements are split per
// binding position — slice/array elements bind the value side (the
// key side is the index, never an env name), map KeyValueExprs split
// key vs value, and an opaque composite type (a named slice/map
// literal the scanner cannot type) covers both sides like the
// pre-split behavior did.
func (s *fileScan) scanRangeLit(cl *ast.CompositeLit, pos token.Pos) (coverKey, coverValue, dynKey, dynValue bool) {
	for _, elt := range cl.Elts {
		s.scanRangeElt(elt, pos)
	}
	var keyElts, valElts []ast.Expr
	splitKV := func(elts []ast.Expr) {
		for _, elt := range elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				keyElts = append(keyElts, kv.Key)
				valElts = append(valElts, kv.Value)
			} else {
				keyElts = append(keyElts, elt)
				valElts = append(valElts, elt)
			}
		}
	}
	switch cl.Type.(type) {
	case *ast.MapType:
		splitKV(cl.Elts)
	case *ast.ArrayType:
		valElts = cl.Elts
	default:
		splitKV(cl.Elts)
	}
	coverKey, dynKey = s.scanRangeCover(keyElts)
	coverValue, dynValue = s.scanRangeCover(valElts)
	return coverKey, coverValue, dynKey, dynValue
}

func (s *fileScan) resolvePkgConst(id *ast.Ident) (string, bool) {
	if bound, _, _ := s.rangeResolve(id.Name, id.Pos()); bound {
		return "", false
	}
	if s.localDeclDepth(id.Name) >= 0 {
		return "", false
	}
	v, ok := s.consts[id.Name]
	return v, ok
}

// scanRangeCover classifies one binding position's element list:
// cover reports at least one static element (string literal or
// unshadowed package-level string const — both already recorded as
// env reads), dyn reports at least one element the scanner cannot
// resolve. A non-string literal counts as dynamic: it cannot be an
// env name, so a binding that can take one is not provably covered.
func (s *fileScan) scanRangeCover(elts []ast.Expr) (cover, dyn bool) {
	var walk func(ast.Expr)
	walk = func(e ast.Expr) {
		switch v := e.(type) {
		case *ast.KeyValueExpr:
			walk(v.Key)
			walk(v.Value)
		case *ast.BasicLit:
			if v.Kind == token.STRING {
				if _, err := strconv.Unquote(v.Value); err == nil {
					cover = true
				}
			} else {
				dyn = true
			}
		case *ast.Ident:
			if _, ok := s.resolvePkgConst(v); ok {
				cover = true
			} else {
				dyn = true
			}
		default:
			dyn = true
		}
	}
	for _, elt := range elts {
		walk(elt)
	}
	return cover, dyn
}

// scanRangeElt records one element of a ranged composite literal:
// string literals and unshadowed package-level string consts are env
// reads; a KeyValueExpr (map literal) contributes BOTH sides —
// `for k := range` binds keys while `for _, v := range` binds values,
// and the scanner cannot tell which the caller treats as the env name.
func (s *fileScan) scanRangeElt(elt ast.Expr, pos token.Pos) {
	if kv, ok := elt.(*ast.KeyValueExpr); ok {
		s.scanRangeElt(kv.Key, pos)
		s.scanRangeElt(kv.Value, pos)
		return
	}
	switch v := elt.(type) {
	case *ast.BasicLit:
		if v.Kind == token.STRING {
			if lit, err := strconv.Unquote(v.Value); err == nil {
				s.record(s.fset, lit, pos)
			}
		}
	case *ast.Ident:
		if c, ok := s.resolvePkgConst(v); ok {
			s.record(s.fset, c, pos)
		}
	}
}

// rangeResolve reports whether name is bound by an enclosing range
// frame at pos and, when it is, whether that binding is cleanly
// covered — every element the variable can take was recorded as an
// env read — plus the scopeDepth at which the RangeStmt was entered.
// Walking the stack top-down finds the innermost binding first, so a
// non-literal inner range correctly shadows an outer literal one.
func (s *fileScan) rangeResolve(name string, pos token.Pos) (bound, clean bool, scopeDepth int) {
	for i := len(s.stack) - 1; i >= 0; i-- {
		f := s.stack[i]
		p, ok := f.names[name]
		if !ok {
			continue
		}
		if pos <= f.body.Pos() || pos >= f.body.End() {
			continue
		}
		switch p {
		case bindKey:
			return true, f.coverKey && !f.dynKey, f.scopeDepth
		case bindValue:
			return true, f.coverValue && !f.dynValue, f.scopeDepth
		}
		return true, false, f.scopeDepth
	}
	return false, false, 0
}

// scanCall resolves env-reading call sites: raw os.Getenv-family
// reads (collected or reported per AllowRawOS) and envx helper calls
// (qualified or dot-imported, alias resolved from this file's
// imports).
func (s *fileScan) scanCall(e *ast.CallExpr) {
	if len(e.Args) == 0 {
		return
	}
	isLocal := func(name string) bool {
		return s.isLocalAt(name, e.Pos())
	}
	if isRawEnvRead(e, s.osNames, s.osDot, isLocal) {
		if s.allowRawOS {
			s.addKey(e.Args[0], e.Pos())
		} else {
			s.res.RawReads = append(s.res.RawReads, s.site(s.fset, e.Pos()))
		}
		return
	}
	if !isEnvCall(e, s.envxNames, s.envxDot, s.inEnvx, s.helpers, isLocal) {
		return
	}
	s.addKey(e.Args[0], e.Pos())
}

// addKey records a literal env key, accepts a range variable bound to
// a recorded literal inside its loop body (unless shadowed by an
// inner local declaration), resolves an unshadowed package-level
// string const, and reports anything else as unresolved — an env key
// the scanner cannot name is one docs/env.md cannot be checked against.
func (s *fileScan) addKey(expr ast.Expr, pos token.Pos) {
	switch k := expr.(type) {
	case *ast.ParenExpr:
		s.addKey(k.X, pos)
	case *ast.BasicLit:
		if k.Kind != token.STRING {
			return
		}
		if v, err := strconv.Unquote(k.Value); err == nil {
			s.record(s.fset, v, pos)
		}
	case *ast.BinaryExpr:
		if v, ok := evalStaticStringExpr(k, s.resolvePkgConst); ok {
			s.record(s.fset, v, pos)
			return
		}
		s.res.Unresolved = append(s.res.Unresolved,
			s.site(s.fset, pos)+" (computed)")
	case *ast.Ident:
		localDepth := s.localDeclDepth(k.Name)
		if bound, clean, scopeDepth := s.rangeResolve(k.Name, k.Pos()); bound && localDepth < scopeDepth {
			if clean {
				// Bound to a []string literal already recorded at the
				// RangeStmt with no dynamic sibling — the keys are
				// covered.
				return
			}
			// Bound-but-unclean range variable shadows any outer
			// package const: never fall through to s.consts.
			s.res.Unresolved = append(s.res.Unresolved,
				fmt.Sprintf("%s (%s)", s.site(s.fset, pos), k.Name))
			return
		}
		if localDepth >= 0 {
			// Local var/const/:=/param shadows any package-level const.
			s.res.Unresolved = append(s.res.Unresolved,
				fmt.Sprintf("%s (%s)", s.site(s.fset, pos), k.Name))
			return
		}
		if v, ok := s.consts[k.Name]; ok {
			s.record(s.fset, v, pos)
			return
		}
		// An identifier that is neither a string const nor a
		// recorded range variable — the scanner cannot name the key.
		s.res.Unresolved = append(s.res.Unresolved,
			fmt.Sprintf("%s (%s)", s.site(s.fset, pos), k.Name))
	default:
		// Selector (e.g. envnames.EnvFoo) or call result — kept quiet
		// when another package owns the constant table.
	}
}
