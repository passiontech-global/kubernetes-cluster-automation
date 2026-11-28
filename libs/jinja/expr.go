// expr.go — the expression AST and its eval dispatch: literals,
// names, attr/index access, calls, filters, unary/binary ops,
// tests, ternary and list/dict literals. binOp — the binary
// operator engine — lives in binop.go next to this file.
package jinja

// ---------------- expressions ----------------

type expr interface{ eval(s *scope) (any, error) }

type litExpr struct{ v any }

func (e litExpr) eval(*scope) (any, error) { return e.v, nil }

type nameExpr struct{ n string }

func (e nameExpr) eval(s *scope) (any, error) { return s.get(e.n), nil }

type attrExpr struct {
	obj expr
	key string
}

func (e attrExpr) eval(s *scope) (any, error) {
	return evalPostfixChain(e, s)
}

type indexExpr struct {
	obj expr
	key expr
}

func (e indexExpr) eval(s *scope) (any, error) {
	return evalPostfixChain(e, s)
}

type callExpr struct {
	fn   expr
	args []expr
	kw   []kwarg
}

type kwarg struct {
	name string
	e    expr
}

func (e callExpr) eval(s *scope) (any, error) {
	return evalPostfixChain(e, s)
}

// evalPostfixChain unwinds left-leaning postfix chains (.attr, [idx],
// call(), |filter) iteratively so arbitrarily wide chains (e.g. thousands
// of filters or attribute hops) evaluate in O(1) Go stack space instead
// of recursing down the left spine.
func evalPostfixChain(root expr, s *scope) (any, error) {
	var chain []expr
	cur := root
	for {
		switch x := cur.(type) {
		case attrExpr:
			chain = append(chain, x)
			cur = x.obj
		case indexExpr:
			chain = append(chain, x)
			cur = x.obj
		case callExpr:
			chain = append(chain, x)
			cur = x.fn
		case filterExpr:
			chain = append(chain, x)
			cur = x.in
		default:
			goto evalBase
		}
	}
evalBase:
	v, err := cur.eval(s)
	if err != nil {
		return nil, err
	}
	for i := len(chain) - 1; i >= 0; i-- {
		switch x := chain[i].(type) {
		case attrExpr:
			v = getAttr(v, x.key)
		case indexExpr:
			k, err := x.key.eval(s)
			if err != nil {
				return nil, err
			}
			v, err = getIndex(v, k)
			if err != nil {
				return nil, err
			}
		case callExpr:
			args, kw, err := evalCallArgs(x.args, x.kw, s)
			if err != nil {
				return nil, err
			}
			v, err = callValue(v, args, kw, s)
			if err != nil {
				return nil, err
			}
		case filterExpr:
			args, kw, err := evalCallArgs(x.args, x.kw, s)
			if err != nil {
				return nil, err
			}
			v, err = applyFilter(x.name, v, args, kw, s)
			if err != nil {
				return nil, err
			}
		}
	}
	return v, nil
}

// evalCallArgs evaluates a call site's positional args and kwargs —
// the shared body of callExpr.eval and filterExpr.eval (the loops
// were duplicated verbatim). kw stays nil when the call has no
// kwargs — every consumer only READS the map, and nil-map lookups
// behave like empty ones, so the per-call allocation is skipped for
// the (dominant) plain positional call shape.
func evalCallArgs(argExprs []expr, kwExprs []kwarg, s *scope) ([]any, map[string]any, error) {
	var args []any
	for _, a := range argExprs {
		v, err := a.eval(s)
		if err != nil {
			return nil, nil, err
		}
		args = append(args, v)
	}
	var kw map[string]any
	if len(kwExprs) > 0 {
		kw = make(map[string]any, len(kwExprs))
		for _, k := range kwExprs {
			v, err := k.e.eval(s)
			if err != nil {
				return nil, nil, err
			}
			kw[k.name] = v
		}
	}
	return args, kw, nil
}

type filterExpr struct {
	in   expr
	name string
	args []expr
	kw   []kwarg
}

func (e filterExpr) eval(s *scope) (any, error) {
	return evalPostfixChain(e, s)
}

type unExpr struct {
	op string
	e  expr
}

func (e unExpr) eval(s *scope) (any, error) {
	v, err := e.e.eval(s)
	if err != nil {
		return nil, err
	}
	switch e.op {
	case "not":
		return !Truthy(v), nil
	case "-":
		return numNeg(v)
	}
	return v, nil
}

type binExpr struct {
	op   string
	l, r expr
}

func (e binExpr) eval(s *scope) (any, error) {
	// Unwind the left-leaning binary spine iteratively so wide flat
	// chains (e.g. 1 + 1 + ... or a or b or ...) run in O(1) Go stack.
	var chain []binExpr
	cur := expr(e)
	for {
		b, ok := cur.(binExpr)
		if !ok {
			break
		}
		chain = append(chain, b)
		cur = b.l
	}
	l, err := cur.eval(s)
	if err != nil {
		return nil, err
	}
	for i := len(chain) - 1; i >= 0; i-- {
		link := chain[i]
		switch link.op {
		case "and":
			if !Truthy(l) {
				continue
			}
			l, err = link.r.eval(s)
			if err != nil {
				return nil, err
			}
		case "or":
			if Truthy(l) {
				continue
			}
			l, err = link.r.eval(s)
			if err != nil {
				return nil, err
			}
		default:
			r, err := link.r.eval(s)
			if err != nil {
				return nil, err
			}
			l, err = binOp(link.op, l, r)
			if err != nil {
				return nil, err
			}
		}
	}
	return l, nil
}

type compareOp struct {
	op  string
	rhs expr
}

type compareExpr struct {
	first expr
	ops   []compareOp
}

func (e compareExpr) eval(s *scope) (any, error) {
	left, err := e.first.eval(s)
	if err != nil {
		return nil, err
	}
	for _, link := range e.ops {
		right, err := link.rhs.eval(s)
		if err != nil {
			return nil, err
		}
		var ok any
		if link.op == "not in" {
			ok, err = binOp("in", left, right)
			if err != nil {
				return nil, err
			}
			if Truthy(ok) {
				return false, nil
			}
		} else {
			ok, err = binOp(link.op, left, right)
			if err != nil {
				return nil, err
			}
			if !Truthy(ok) {
				return false, nil
			}
		}
		left = right
	}
	return true, nil
}

type testExpr struct {
	in   expr
	name string
	args []expr
	neg  bool
}

func (e testExpr) eval(s *scope) (any, error) {
	var chain []testExpr
	cur := expr(e)
	for {
		te, ok := cur.(testExpr)
		if !ok {
			break
		}
		chain = append(chain, te)
		cur = te.in
	}
	v, err := cur.eval(s)
	if err != nil {
		return nil, err
	}
	for i := len(chain) - 1; i >= 0; i-- {
		te := chain[i]
		var args []any
		for _, a := range te.args {
			x, err := a.eval(s)
			if err != nil {
				return nil, err
			}
			args = append(args, x)
		}
		r, err := runTest(te.name, v, args)
		if err != nil {
			return nil, err
		}
		if te.neg {
			r = !r
		}
		v = r
	}
	return v, nil
}

type condExpr struct {
	c, t, f expr
}

func (e condExpr) eval(s *scope) (any, error) {
	c, err := e.c.eval(s)
	if err != nil {
		return nil, err
	}
	if Truthy(c) {
		return e.t.eval(s)
	}
	if e.f == nil {
		return Undefined{"ternary"}, nil
	}
	return e.f.eval(s)
}

type listExpr []expr

func (e listExpr) eval(s *scope) (any, error) {
	out := make([]any, 0, len(e))
	for _, x := range e {
		v, err := x.eval(s)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return &List{out}, nil
}

type dictExpr [][2]expr

func (e dictExpr) eval(s *scope) (any, error) {
	m := NewOMapCap(len(e))
	for _, kv := range e {
		k, err := kv[0].eval(s)
		if err != nil {
			return nil, err
		}
		v, err := kv[1].eval(s)
		if err != nil {
			return nil, err
		}
		m.Set(Stringify(k), v)
	}
	return m, nil
}
