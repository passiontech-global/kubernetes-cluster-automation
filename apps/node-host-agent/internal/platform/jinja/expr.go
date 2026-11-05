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
	v, err := e.obj.eval(s)
	if err != nil {
		return nil, err
	}
	return getAttr(v, e.key), nil
}

type indexExpr struct {
	obj expr
	key expr
}

func (e indexExpr) eval(s *scope) (any, error) {
	v, err := e.obj.eval(s)
	if err != nil {
		return nil, err
	}
	k, err := e.key.eval(s)
	if err != nil {
		return nil, err
	}
	return getIndex(v, k)
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
	fnv, err := e.fn.eval(s)
	if err != nil {
		return nil, err
	}
	var args []any
	for _, a := range e.args {
		v, err := a.eval(s)
		if err != nil {
			return nil, err
		}
		args = append(args, v)
	}
	kw := map[string]any{}
	for _, k := range e.kw {
		v, err := k.e.eval(s)
		if err != nil {
			return nil, err
		}
		kw[k.name] = v
	}
	return callValue(fnv, args, kw, s)
}

type filterExpr struct {
	in   expr
	name string
	args []expr
	kw   []kwarg
}

func (e filterExpr) eval(s *scope) (any, error) {
	v, err := e.in.eval(s)
	if err != nil {
		return nil, err
	}
	var args []any
	for _, a := range e.args {
		x, err := a.eval(s)
		if err != nil {
			return nil, err
		}
		args = append(args, x)
	}
	kw := map[string]any{}
	for _, k := range e.kw {
		x, err := k.e.eval(s)
		if err != nil {
			return nil, err
		}
		kw[k.name] = x
	}
	return applyFilter(e.name, v, args, kw, s)
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
	switch e.op {
	case "and":
		l, err := e.l.eval(s)
		if err != nil || !Truthy(l) {
			return l, err
		}
		return e.r.eval(s)
	case "or":
		l, err := e.l.eval(s)
		if err != nil || Truthy(l) {
			return l, err
		}
		return e.r.eval(s)
	}
	l, err := e.l.eval(s)
	if err != nil {
		return nil, err
	}
	r, err := e.r.eval(s)
	if err != nil {
		return nil, err
	}
	return binOp(e.op, l, r)
}

type testExpr struct {
	in   expr
	name string
	args []expr
	neg  bool
}

func (e testExpr) eval(s *scope) (any, error) {
	v, err := e.in.eval(s)
	if err != nil {
		return nil, err
	}
	var args []any
	for _, a := range e.args {
		x, err := a.eval(s)
		if err != nil {
			return nil, err
		}
		args = append(args, x)
	}
	r, err := runTest(e.name, v, args)
	if err != nil {
		return nil, err
	}
	if e.neg {
		return !r, nil
	}
	return r, nil
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
	m := NewOMap()
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
