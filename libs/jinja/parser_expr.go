package jinja

import (
	"fmt"
	"strconv"
)

// ---------------- expression parser ----------------
//
// Pratt/recursive-descent expression grammar, split from parser.go
// (which owns the {{ }}/{% %} tag splitter and statement AST). The
// precedence chain, loosest to tightest: ternary → or → and → not →
// compare (==/!=/</<=/>/>=, in, not in, is [not] test) → ~ concat →
// additive → multiplicative → unary → postfix (filter |, .attr,
// [idx], call) → primary.

type parser struct {
	toks []tok
	pos  int
}

// tok returns toks[pos+off], or a synthetic eof past the slice end —
// a grammar path that consumed past the terminator must degrade to
// a parse error, not an index panic.
func (p *parser) tok(off int) tok {
	if i := p.pos + off; i >= 0 && i < len(p.toks) {
		return p.toks[i]
	}
	return tok{tokEOF, ""}
}

func (p *parser) peek() tok { return p.tok(0) }
func (p *parser) next() tok { t := p.tok(0); p.pos++; return t }
func (p *parser) at(v string) bool {
	t := p.tok(0)
	return t.kind == tokOp && t.val == v
}
func (p *parser) atName(v string) bool {
	t := p.tok(0)
	return t.kind == tokName && t.val == v
}
func (p *parser) atKind(k tokKind) bool { return p.tok(0).kind == k }
func (p *parser) expect(v string) error {
	if !p.at(v) {
		t := p.tok(0)
		return fmt.Errorf("expected %q got %q (%s)", v, t.val, t.kind)
	}
	p.next()
	return nil
}

func parseExpr(src string) (expr, error) {
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	e, err := p.parseTernary()
	if err != nil {
		return nil, fmt.Errorf("expr %q: %w", src, err)
	}
	if p.peek().kind != tokEOF {
		return nil, fmt.Errorf("expr %q: trailing %q", src, p.peek().val)
	}
	return e, nil
}

func (p *parser) parseTernary() (expr, error) {
	t, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.atName("if") {
		p.next()
		c, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		var f expr
		if p.atName("else") {
			p.next()
			f, err = p.parseTernary()
			if err != nil {
				return nil, err
			}
		}
		return condExpr{c: c, t: t, f: f}, nil
	}
	return t, nil
}

func (p *parser) parseOr() (expr, error) {
	l, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.atName("or") {
		p.next()
		r, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		l = binExpr{"or", l, r}
	}
	return l, nil
}

func (p *parser) parseAnd() (expr, error) {
	l, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.atName("and") {
		p.next()
		r, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		l = binExpr{"and", l, r}
	}
	return l, nil
}

func (p *parser) parseNot() (expr, error) {
	if p.atName("not") {
		p.next()
		e, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return unExpr{"not", e}, nil
	}
	return p.parseCompare()
}

func (p *parser) parseCompare() (expr, error) {
	l, err := p.parseConcat()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		if t.kind == tokOp && (t.val == "==" || t.val == "!=" || t.val == "<" || t.val == "<=" || t.val == ">" || t.val == ">=") {
			p.next()
			r, err := p.parseConcat()
			if err != nil {
				return nil, err
			}
			l = binExpr{t.val, l, r}
			continue
		}
		if t.kind == tokName && t.val == "in" {
			p.next()
			r, err := p.parseConcat()
			if err != nil {
				return nil, err
			}
			l = binExpr{"in", l, r}
			continue
		}
		if t.kind == tokName && t.val == "not" && p.tok(1).kind == tokName && p.tok(1).val == "in" {
			p.next()
			p.next()
			r, err := p.parseConcat()
			if err != nil {
				return nil, err
			}
			l = unExpr{"not", binExpr{"in", l, r}}
			continue
		}
		if t.kind == tokName && t.val == "is" {
			p.next()
			neg := false
			if p.atName("not") {
				p.next()
				neg = true
			}
			// `x is` / `x is not` at eof: without this guard next()
			// eats the terminator and the at("(") probe indexes out
			// of range — a panic, not a parse error.
			if !p.atKind(tokName) {
				return nil, fmt.Errorf("is: expected test name, got %q", p.peek().val)
			}
			name := p.next().val
			var args []expr
			if p.at("(") {
				p.next()
				for !p.at(")") {
					a, err := p.parseTernary()
					if err != nil {
						return nil, err
					}
					args = append(args, a)
					if p.at(",") {
						p.next()
					} else if !p.at(")") {
						// `default('n/a' 0)` must not silently
						// bind 0 as the second argument — a
						// missing comma changes which
						// positional slot each value lands in.
						return nil, fmt.Errorf("is: expected ',' or ')' between arguments, got %q", p.peek().val)
					}
				}
				p.next()
			}
			l = testExpr{in: l, name: name, args: args, neg: neg}
			continue
		}
		break
	}
	return l, nil
}

// parseConcat handles `~` string concatenation at LOWER precedence
// than `+`/`-` (jinja2/ansible semantics): each operand is a full
// additive expression, so "node-" ~ i + 1 computes i + 1 first and
// concatenates "node-3" — previously ~ shared +/'s precedence level
// and evaluated left-to-right with them.
func (p *parser) parseConcat() (expr, error) {
	l, err := p.parseAdd()
	if err != nil {
		return nil, err
	}
	for p.at("~") {
		p.next()
		r, err := p.parseAdd()
		if err != nil {
			return nil, err
		}
		l = binExpr{"~", l, r}
	}
	return l, nil
}

func (p *parser) parseAdd() (expr, error) {
	l, err := p.parseMul()
	if err != nil {
		return nil, err
	}
	for p.at("+") || p.at("-") {
		op := p.next().val
		r, err := p.parseMul()
		if err != nil {
			return nil, err
		}
		l = binExpr{op, l, r}
	}
	return l, nil
}

func (p *parser) parseMul() (expr, error) {
	l, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.at("*") || p.at("/") || p.at("//") || p.at("%") {
		op := p.next().val
		r, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		l = binExpr{op, l, r}
	}
	return l, nil
}

func (p *parser) parseUnary() (expr, error) {
	if p.at("-") {
		p.next()
		e, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return unExpr{"-", e}, nil
	}
	if p.at("+") {
		p.next()
		return p.parseUnary()
	}
	return p.parsePostfix()
}

func (p *parser) parsePostfix() (expr, error) {
	e, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	for {
		switch {
		case p.at("|"):
			p.next()
			// The filter name must be a name token — `x | }` or
			// `x | 1` used to consume the token blindly and build
			// a filterExpr with an empty/garbage name that failed
			// (or worse, matched) at render time.
			if !p.atKind(tokName) {
				return nil, fmt.Errorf("filter: expected filter name after '|', got %q", p.peek().val)
			}
			name := p.next().val
			var args []expr
			var kw []kwarg
			if p.at("(") {
				p.next()
				args, kw, err = p.parseCallArgs("filter")
				if err != nil {
					return nil, err
				}
			}
			e = filterExpr{in: e, name: name, args: args, kw: kw}
		case p.at("."):
			p.next()
			// Same contract after '.': the attribute must be a
			// name token (`x.` at eof, `x.0`, `x."k"`), not an
			// anonymous accessor.
			if !p.atKind(tokName) {
				return nil, fmt.Errorf("attribute: expected name after '.', got %q", p.peek().val)
			}
			e = attrExpr{e, p.next().val}
		case p.at("["):
			p.next()
			k, err := p.parseTernary()
			if err != nil {
				return nil, err
			}
			if err := p.expect("]"); err != nil {
				return nil, err
			}
			e = indexExpr{e, k}
		case p.at("("):
			p.next()
			var args []expr
			var kw []kwarg
			args, kw, err = p.parseCallArgs("call")
			if err != nil {
				return nil, err
			}
			e = callExpr{e, args, kw}
		default:
			return e, nil
		}
	}
}

// parseCallArgs consumes a parenthesized argument list — the parser
// is positioned just past '(' — returning positional args and
// `name=expr` kwargs up to and including the closing ')'. Shared by
// the filter-call and value-call postfix productions (the loops were
// duplicated verbatim); what names the construct in error messages.
func (p *parser) parseCallArgs(what string) ([]expr, []kwarg, error) {
	var args []expr
	var kw []kwarg
	for !p.at(")") {
		if p.tok(0).kind == tokName && p.tok(1).kind == tokOp && p.tok(1).val == "=" {
			kn := p.next().val
			p.next()
			ke, err := p.parseTernary()
			if err != nil {
				return nil, nil, err
			}
			kw = append(kw, kwarg{kn, ke})
		} else {
			a, err := p.parseTernary()
			if err != nil {
				return nil, nil, err
			}
			args = append(args, a)
		}
		if p.at(",") {
			p.next()
		} else if !p.at(")") {
			return nil, nil, fmt.Errorf("%s: expected ',' or ')' between arguments, got %q", what, p.peek().val)
		}
	}
	p.next()
	return args, kw, nil
}

func (p *parser) parsePrimary() (expr, error) {
	t := p.next()
	switch t.kind {
	case tokStr:
		return litExpr{t.val}, nil
	case tokNum:
		// Base-0 (0x/0o/0b prefixes) only for explicitly-prefixed
		// literals — a LEADING ZERO decimal like 08/09/010 must parse
		// base-10: base-0 reads the 0 as octal (010→8) and rejects
		// 08/09 outright, then the float fallback silently changed
		// the literal's type.
		base := 10
		if len(t.val) > 2 && t.val[0] == '0' &&
			(t.val[1] == 'x' || t.val[1] == 'X' ||
				t.val[1] == 'o' || t.val[1] == 'O' ||
				t.val[1] == 'b' || t.val[1] == 'B') {
			base = 0
		}
		if i, err := strconv.ParseInt(t.val, base, 64); err == nil {
			return litExpr{i}, nil
		}
		if f, err := strconv.ParseFloat(t.val, 64); err == nil {
			return litExpr{f}, nil
		}
		return nil, fmt.Errorf("bad number %q", t.val)
	case tokName:
		switch t.val {
		case "true", "True":
			return litExpr{true}, nil
		case "false", "False":
			return litExpr{false}, nil
		case "none", "None", "null", "Null":
			return litExpr{nil}, nil
		}
		return nameExpr{t.val}, nil
	case tokOp:
		switch t.val {
		case "(":
			e, err := p.parseTernary()
			if err != nil {
				return nil, err
			}
			if err := p.expect(")"); err != nil {
				return nil, err
			}
			return e, nil
		case "[":
			// jinja2 comma semantics: a comma is REQUIRED between
			// items (the old optional-comma loop silently accepted
			// `[1 2]` as `[1, 2]`), while a trailing comma is legal —
			// after a comma, `]` closes the list.
			var items []expr
			for !p.at("]") {
				a, err := p.parseTernary()
				if err != nil {
					return nil, err
				}
				items = append(items, a)
				if !p.at(",") {
					break
				}
				p.next()
			}
			if !p.at("]") {
				return nil, fmt.Errorf("list: expected ',' or ']' between items, got %q", p.peek().val)
			}
			p.next()
			return listExpr(items), nil
		case "{":
			var pairs [][2]expr
			for !p.at("}") {
				k, err := p.parseTernary()
				if err != nil {
					return nil, err
				}
				if err := p.expect(":"); err != nil {
					return nil, err
				}
				v, err := p.parseTernary()
				if err != nil {
					return nil, err
				}
				pairs = append(pairs, [2]expr{k, v})
				if !p.at(",") {
					break
				}
				p.next()
			}
			if !p.at("}") {
				return nil, fmt.Errorf("dict: expected ',' or '}' between items, got %q", p.peek().val)
			}
			p.next()
			return dictExpr(pairs), nil
		}
	}
	return nil, fmt.Errorf("unexpected token %q (%s)", t.val, t.kind)
}
