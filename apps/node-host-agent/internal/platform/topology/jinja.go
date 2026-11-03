// Mini-Jinja2 evaluator — just enough of jinja2 + the ansible filter
// set to evaluate the vars files (defaults.yaml / cluster.yaml) and to
// render the vendored .j2 templates byte-identically.
//
// Supported:
//
//	statements: {{ expr }}, {% set x = expr %}, {% for a[,b] in expr %},
//	            {% if expr %} {% elif %} {% else %} {% endif %}, {# c #}
//	whitespace control via {%-/-%} {{-/-}} {#-/-#}
//	expressions: literals (str/int/float/bool/none/list/dict), names,
//	             .attr ['key'] [idx] calls, methods (items/append/get/
//	             keys/values/endswith/startswith/split/strip),
//	             filters |f(a), + - ~ * / // %, == != < <= > >=
//	             in/not in, is [not] t, and/or/not, x if c else y
//	tests: defined undefined none mapping iterable sequence string
//	       number boolean bool search equalto eq sameas
//	filters: basename bool b64decode b64encode default dict2items
//	         difference eq equalto first flatten float format from_json
//	         from_yaml hash indent int items2dict join last length list
//	         lower map min max regex_escape regex_findall regex_replace
//	         regex_search reject rejectattr search select selectattr
//	         sort split string ternary to_json to_yaml to_nice_yaml
//	         trim unique upper zip
//	functions: lookup('file'|'ansible.builtin.file'|'pipe'|...)
//
// NOT supported (unused by the ported sources): namespace(), macros,
// imports, raw blocks, slices, **.
package topology

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	yaml3 "go.yaml.in/yaml/v3"
)

// Undefined is the jinja `undefined` — falsy, default()-able.
type Undefined struct{ name string }

func (u Undefined) String() string { return "Undefined(" + u.name + ")" }

// List wraps a slice so in-place mutation (append inside set/for)
// behaves like python lists across scope bindings.
type List struct{ V []any }

// Env carries render-time hooks.
type Env struct {
	// FileLookup resolves lookup('file'|'ansible.builtin.file', path).
	FileLookup func(path string) (string, error)
	// PipeLookup resolves lookup('pipe'|'ansible.builtin.pipe', cmd) —
	// only 'date +%s' is honoured (returns unix epoch string).
	PipeLookup func(cmd string) (string, error)
}

// Render evaluates template text against ctx (name → value).
func Render(text string, ctx map[string]any, env *Env) (string, error) {
	nodes, err := parseTemplate(text)
	if err != nil {
		return "", err
	}
	s := &scope{vars: map[string]any{}, env: env}
	for k, v := range ctx {
		s.vars[k] = v
	}
	var b strings.Builder
	if err := renderNodes(nodes, s, &b); err != nil {
		return "", err
	}
	return b.String(), nil
}

type scope struct {
	vars   map[string]any
	env    *Env
	lookup func(name string) any // external var resolver (checked first)
}

func (s *scope) get(name string) any {
	if s.lookup != nil {
		if v := s.lookup(name); v != nil {
			if _, u := v.(Undefined); !u {
				return v
			}
		}
	}
	if v, ok := s.vars[name]; ok {
		return v
	}
	switch name {
	case "lookup", "ansible.builtin.lookup":
		return builtinFunc(func(args []any, kw map[string]any, sc *scope) (any, error) {
			return doLookup(args, sc)
		})
	case "range":
		return builtinFunc(func(args []any, kw map[string]any, _ *scope) (any, error) {
			var lo, hi, step int64 = 0, 0, 1
			if len(args) == 1 {
				hi, _ = toInt(args[0])
			} else if len(args) >= 2 {
				lo, _ = toInt(args[0])
				hi, _ = toInt(args[1])
			}
			if len(args) > 2 {
				step, _ = toInt(args[2])
			}
			var out []any
			for i := lo; i < hi; i += step {
				out = append(out, i)
			}
			return &List{out}, nil
		})
	}
	return Undefined{name}
}

// ---------------- template parsing ----------------

type tnode interface {
	render(s *scope, b *strings.Builder) error
}

type textNode string

func (t textNode) render(_ *scope, b *strings.Builder) error {
	b.WriteString(string(t))
	return nil
}

type exprNode struct{ e expr }

func (n exprNode) render(s *scope, b *strings.Builder) error {
	v, err := n.e.eval(s)
	if err != nil {
		return err
	}
	b.WriteString(stringify(v))
	return nil
}

type setNode struct {
	name string
	e    expr
}

func (n setNode) render(s *scope, _ *strings.Builder) error {
	v, err := n.e.eval(s)
	if err != nil {
		return err
	}
	s.vars[n.name] = v
	return nil
}

type forNode struct {
	names []string
	list  expr
	conds []expr // {% for x in seq if cond [if cond2] %} filters
	body  []tnode
}

// bind assigns the loop variable(s) for one item.
func (n forNode) bind(s *scope, it any) {
	if len(n.names) == 2 {
		pair := toIter(it)
		if len(pair) >= 2 {
			s.vars[n.names[0]] = pair[0]
			s.vars[n.names[1]] = pair[1]
		} else {
			s.vars[n.names[0]] = it
			s.vars[n.names[1]] = Undefined{"loop-item"}
		}
	} else {
		s.vars[n.names[0]] = it
	}
}

func (n forNode) render(s *scope, b *strings.Builder) error {
	v, err := n.list.eval(s)
	if err != nil {
		return err
	}
	// Apply the `if` filters first: the loop var is bound for each
	// candidate and every condition must be truthy for the item to
	// iterate — loop.index/count then track the FILTERED sequence
	// (jinja semantics).
	var kept []any
	for _, it := range toIter(v) {
		n.bind(s, it)
		ok := true
		for _, ce := range n.conds {
			cv, err := ce.eval(s)
			if err != nil {
				return err
			}
			if !truthy(cv) {
				ok = false
				break
			}
		}
		if ok {
			kept = append(kept, it)
		}
	}
	ln := len(kept)
	for i, it := range kept {
		n.bind(s, it)
		loop := NewOMap()
		loop.Set("index", int64(i+1))
		loop.Set("index0", int64(i))
		loop.Set("revindex", int64(ln-i))
		loop.Set("revindex0", int64(ln-i-1))
		loop.Set("first", i == 0)
		loop.Set("last", i == ln-1)
		loop.Set("length", int64(ln))
		s.vars["loop"] = loop
		if err := renderNodes(n.body, s, b); err != nil {
			return err
		}
	}
	return nil
}

type ifArm struct {
	cond expr // nil = else
	body []tnode
}

type ifNode struct{ arms []ifArm }

func (n ifNode) render(s *scope, b *strings.Builder) error {
	for _, arm := range n.arms {
		if arm.cond == nil {
			return renderNodes(arm.body, s, b)
		}
		v, err := arm.cond.eval(s)
		if err != nil {
			return err
		}
		if truthy(v) {
			return renderNodes(arm.body, s, b)
		}
	}
	return nil
}

func renderNodes(nodes []tnode, s *scope, b *strings.Builder) error {
	for _, n := range nodes {
		if err := n.render(s, b); err != nil {
			return err
		}
	}
	return nil
}

type frame struct {
	kind string // "for" | "if"
	n    tnode
}

// parseTemplate tokenises {{ }} {% %} {# #} and builds the node tree.
func parseTemplate(text string) ([]tnode, error) {
	var containers []*[]tnode
	var frames []frame
	nodes := []tnode{}
	containers = append(containers, &nodes)
	cur := func() *[]tnode { return containers[len(containers)-1] }
	pushFrame := func(f frame, c *[]tnode) {
		frames = append(frames, f)
		containers = append(containers, c)
	}
	pop := func(kind string) error {
		if len(frames) == 0 || frames[len(frames)-1].kind != kind {
			return fmt.Errorf("end%s without open %s block", kind, kind)
		}
		frames = frames[:len(frames)-1]
		containers = containers[:len(containers)-1]
		return nil
	}

	i := 0
	for i < len(text) {
		j := len(text)
		tag := ""
		for _, t := range []string{"{{", "{%", "{#"} {
			if k := strings.Index(text[i:], t); k >= 0 && i+k < j {
				j = i + k
				tag = t
			}
		}
		end := ""
		switch tag {
		case "{{":
			end = "}}"
		case "{%":
			end = "%}"
		case "{#":
			end = "#}"
		}
		if j == len(text) {
			*cur() = append(*cur(), textNode(text[i:]))
			break
		}
		stripL := strings.HasPrefix(text[j:j+3], tag+"-")
		chunk := text[i:j]
		if stripL {
			chunk = strings.TrimRight(chunk, " \t\n\r")
		}
		if chunk != "" {
			*cur() = append(*cur(), textNode(chunk))
		}
		openLen := 2
		if stripL {
			openLen = 3
		}
		rest := text[j+openLen:]
		closeIdx := strings.Index(rest, end)
		if closeIdx < 0 {
			return nil, fmt.Errorf("unclosed %s tag", tag)
		}
		body := rest[:closeIdx]
		i = j + openLen + closeIdx + len(end)
		if strings.HasSuffix(body, "-") {
			body = body[:len(body)-1]
			// skip following whitespace
			for i < len(text) && (text[i] == ' ' || text[i] == '\t' || text[i] == '\n' || text[i] == '\r') {
				i++
			}
		}
		if tag == "{#" {
			continue
		}
		if tag == "{{" {
			e, err := parseExpr(body)
			if err != nil {
				return nil, err
			}
			*cur() = append(*cur(), exprNode{e})
			continue
		}
		stmt := strings.TrimSpace(body)
		fields := strings.Fields(stmt)
		kw := ""
		if len(fields) > 0 {
			kw = fields[0]
		}
		switch kw {
		case "set":
			restStmt := strings.TrimSpace(strings.TrimPrefix(stmt, "set"))
			eq := strings.Index(restStmt, "=")
			if eq < 0 {
				return nil, fmt.Errorf("set: missing = in %q", stmt)
			}
			e, err := parseExpr(restStmt[eq+1:])
			if err != nil {
				return nil, err
			}
			*cur() = append(*cur(), setNode{name: strings.TrimSpace(restStmt[:eq]), e: e})
		case "for":
			fn, err := parseFor(stmt)
			if err != nil {
				return nil, err
			}
			*cur() = append(*cur(), fn)
			pushFrame(frame{"for", fn}, &fn.body)
		case "endfor":
			if err := pop("for"); err != nil {
				return nil, err
			}
		case "if":
			e, err := parseExpr(strings.TrimSpace(strings.TrimPrefix(stmt, "if")))
			if err != nil {
				return nil, err
			}
			in := &ifNode{arms: []ifArm{{cond: e}}}
			*cur() = append(*cur(), in)
			pushFrame(frame{"if", in}, &in.arms[0].body)
		case "elif", "else":
			if len(frames) == 0 || frames[len(frames)-1].kind != "if" {
				return nil, fmt.Errorf("%s without if", kw)
			}
			in := frames[len(frames)-1].n.(*ifNode)
			containers = containers[:len(containers)-1] // pop previous arm body
			if kw == "elif" {
				e, err := parseExpr(strings.TrimSpace(strings.TrimPrefix(stmt, "elif")))
				if err != nil {
					return nil, err
				}
				in.arms = append(in.arms, ifArm{cond: e})
			} else {
				in.arms = append(in.arms, ifArm{})
			}
			containers = append(containers, &in.arms[len(in.arms)-1].body)
		case "endif":
			if len(frames) == 0 || frames[len(frames)-1].kind != "if" {
				return nil, fmt.Errorf("endif without if")
			}
			frames = frames[:len(frames)-1]
			containers = containers[:len(containers)-1]
		default:
			return nil, fmt.Errorf("unsupported tag %q", stmt)
		}
	}
	return nodes, nil
}

// parseFor parses `{% for a[,b] in seq [if cond [if cond2 ...]] %}`.
// The `in` separator and the `if` filter markers are only honoured at
// bracket-depth 0 outside string literals — a naive lastIndexOf("in")
// splits inside the filter's own `x in y` test and yields a garbage
// loop variable (silent misparse, haproxy.cfg incident class).
func parseFor(stmt string) (*forNode, error) {
	restStmt := strings.TrimSpace(strings.TrimPrefix(stmt, "for"))
	inIdxs := topLevelWords(restStmt, "in")
	if len(inIdxs) == 0 {
		return nil, fmt.Errorf("for: missing 'in' in %q", stmt)
	}
	inIdx := inIdxs[0]
	var names []string
	for _, nm := range strings.Split(restStmt[:inIdx], ",") {
		names = append(names, strings.TrimSpace(nm))
	}
	rest := restStmt[inIdx+2:]
	// Sequence expr runs up to the first top-level `if`; every further
	// top-level `if` starts another filter condition.
	ifIdxs := topLevelWords(rest, "if")
	iterSrc := rest
	var condSrcs []string
	if len(ifIdxs) > 0 {
		iterSrc = rest[:ifIdxs[0]]
		for i, ix := range ifIdxs {
			end := len(rest)
			if i+1 < len(ifIdxs) {
				end = ifIdxs[i+1]
			}
			condSrcs = append(condSrcs, rest[ix+2:end])
		}
	}
	e, err := parseExpr(iterSrc)
	if err != nil {
		return nil, fmt.Errorf("for: %w", err)
	}
	fn := &forNode{names: names, list: e}
	for _, cs := range condSrcs {
		ce, err := parseExpr(cs)
		if err != nil {
			return nil, fmt.Errorf("for: filter %q: %w", strings.TrimSpace(cs), err)
		}
		fn.conds = append(fn.conds, ce)
	}
	return fn, nil
}

// topLevelWords returns offsets of word w in s where it appears at
// bracket-depth 0, outside 'single'/"double" quotes, bounded by
// non-name characters.
func topLevelWords(s, w string) []int {
	var idxs []int
	depth := 0
	for off := 0; off < len(s); off++ {
		c := s[off]
		switch c {
		case '\'', '"':
			j := off + 1
			for j < len(s) && s[j] != c {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			off = j
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		default:
			if depth == 0 && off+len(w) <= len(s) && s[off:off+len(w)] == w {
				before := off == 0 || !isNameChar(s[off-1])
				after := off+len(w) == len(s) || !isNameChar(s[off+len(w)])
				if before && after {
					idxs = append(idxs, off)
					off += len(w) - 1
				}
			}
		}
	}
	return idxs
}

func isNameChar(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// ---------------- expression parser ----------------

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
		return !truthy(v), nil
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
		if err != nil || !truthy(l) {
			return l, err
		}
		return e.r.eval(s)
	case "or":
		l, err := e.l.eval(s)
		if err != nil || truthy(l) {
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
	r := runTest(e.name, v, args)
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
	if truthy(c) {
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
		m.Set(stringify(k), v)
	}
	return m, nil
}

// --- tokenizer ---

type tok struct {
	kind string // num str name op eof
	val  string
}

func lex(src string) ([]tok, error) {
	var out []tok
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '\'' || c == '"':
			j := i + 1
			var sb strings.Builder
			for j < len(src) && src[j] != c {
				if src[j] == '\\' && j+1 < len(src) {
					switch src[j+1] {
					case 'n':
						sb.WriteByte('\n')
					case 't':
						sb.WriteByte('\t')
					default:
						sb.WriteByte(src[j+1])
					}
					j += 2
					continue
				}
				sb.WriteByte(src[j])
				j++
			}
			if j >= len(src) {
				return nil, fmt.Errorf("unterminated string in %q", src)
			}
			out = append(out, tok{"str", sb.String()})
			i = j + 1
		case c >= '0' && c <= '9':
			j := i
			for j < len(src) && (src[j] >= '0' && src[j] <= '9' || src[j] == '.' || src[j] == 'x' || src[j] >= 'a' && src[j] <= 'f' || src[j] >= 'A' && src[j] <= 'F') {
				j++
			}
			out = append(out, tok{"num", src[i:j]})
			i = j
		case isNameChar(c):
			j := i
			for j < len(src) && isNameChar(src[j]) {
				j++
			}
			out = append(out, tok{"name", src[i:j]})
			i = j
		default:
			matched := false
			for _, op := range []string{"==", "!=", "<=", ">=", "//", "**", "~"} {
				if strings.HasPrefix(src[i:], op) {
					out = append(out, tok{"op", op})
					i += len(op)
					matched = true
					break
				}
			}
			if !matched {
				if strings.ContainsRune("()[]{},.:+-*/%|<>=!", rune(c)) {
					out = append(out, tok{"op", string(c)})
					i++
				} else {
					return nil, fmt.Errorf("lex: unexpected %q in %q", string(c), src)
				}
			}
		}
	}
	out = append(out, tok{"eof", ""})
	return out, nil
}

type parser struct {
	toks []tok
	pos  int
}

func (p *parser) peek() tok { return p.toks[p.pos] }
func (p *parser) next() tok { t := p.toks[p.pos]; p.pos++; return t }
func (p *parser) at(v string) bool {
	return p.toks[p.pos].kind == "op" && p.toks[p.pos].val == v
}
func (p *parser) atName(v string) bool {
	return p.toks[p.pos].kind == "name" && p.toks[p.pos].val == v
}
func (p *parser) atKind(k string) bool { return p.toks[p.pos].kind == k }
func (p *parser) expect(v string) error {
	if !p.at(v) {
		return fmt.Errorf("expected %q got %q (%s)", v, p.toks[p.pos].val, p.toks[p.pos].kind)
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
	if p.peek().kind != "eof" {
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
		if t.kind == "op" && (t.val == "==" || t.val == "!=" || t.val == "<" || t.val == "<=" || t.val == ">" || t.val == ">=") {
			p.next()
			r, err := p.parseConcat()
			if err != nil {
				return nil, err
			}
			l = binExpr{t.val, l, r}
			continue
		}
		if t.kind == "name" && t.val == "in" {
			p.next()
			r, err := p.parseConcat()
			if err != nil {
				return nil, err
			}
			l = binExpr{"in", l, r}
			continue
		}
		if t.kind == "name" && t.val == "not" && p.toks[p.pos+1].kind == "name" && p.toks[p.pos+1].val == "in" {
			p.next()
			p.next()
			r, err := p.parseConcat()
			if err != nil {
				return nil, err
			}
			l = unExpr{"not", binExpr{"in", l, r}}
			continue
		}
		if t.kind == "name" && t.val == "is" {
			p.next()
			neg := false
			if p.atName("not") {
				p.next()
				neg = true
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

func (p *parser) parseConcat() (expr, error) { return p.parseAdd() }

func (p *parser) parseAdd() (expr, error) {
	l, err := p.parseMul()
	if err != nil {
		return nil, err
	}
	for p.at("+") || p.at("-") || p.at("~") {
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
			name := p.next().val
			var args []expr
			var kw []kwarg
			if p.at("(") {
				p.next()
				for !p.at(")") {
					if p.toks[p.pos].kind == "name" && p.toks[p.pos+1].kind == "op" && p.toks[p.pos+1].val == "=" {
						kn := p.next().val
						p.next()
						ke, err := p.parseTernary()
						if err != nil {
							return nil, err
						}
						kw = append(kw, kwarg{kn, ke})
					} else {
						a, err := p.parseTernary()
						if err != nil {
							return nil, err
						}
						args = append(args, a)
					}
					if p.at(",") {
						p.next()
					}
				}
				p.next()
			}
			e = filterExpr{in: e, name: name, args: args, kw: kw}
		case p.at("."):
			p.next()
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
			for !p.at(")") {
				if p.toks[p.pos].kind == "name" && p.toks[p.pos+1].kind == "op" && p.toks[p.pos+1].val == "=" {
					kn := p.next().val
					p.next()
					ke, err := p.parseTernary()
					if err != nil {
						return nil, err
					}
					kw = append(kw, kwarg{kn, ke})
				} else {
					a, err := p.parseTernary()
					if err != nil {
						return nil, err
					}
					args = append(args, a)
				}
				if p.at(",") {
					p.next()
				}
			}
			p.next()
			e = callExpr{e, args, kw}
		default:
			return e, nil
		}
	}
}

func (p *parser) parsePrimary() (expr, error) {
	t := p.next()
	switch t.kind {
	case "str":
		return litExpr{t.val}, nil
	case "num":
		if i, err := strconv.ParseInt(t.val, 0, 64); err == nil {
			return litExpr{i}, nil
		}
		if f, err := strconv.ParseFloat(t.val, 64); err == nil {
			return litExpr{f}, nil
		}
		return nil, fmt.Errorf("bad number %q", t.val)
	case "name":
		switch t.val {
		case "true", "True":
			return litExpr{true}, nil
		case "false", "False":
			return litExpr{false}, nil
		case "none", "None", "null", "Null":
			return litExpr{nil}, nil
		}
		return nameExpr{t.val}, nil
	case "op":
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
			var items []expr
			for !p.at("]") {
				a, err := p.parseTernary()
				if err != nil {
					return nil, err
				}
				items = append(items, a)
				if p.at(",") {
					p.next()
				}
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
				if p.at(",") {
					p.next()
				}
			}
			p.next()
			return dictExpr(pairs), nil
		}
	}
	return nil, fmt.Errorf("unexpected token %q (%s)", t.val, t.kind)
}

// ---------------- value helpers ----------------

func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case Undefined:
		return false
	case bool:
		return t
	case int64:
		return t != 0
	case float64:
		return t != 0
	case string:
		return t != ""
	case []any:
		return len(t) > 0
	case *List:
		return len(t.V) > 0
	case *OMap:
		return t.Len() > 0
	}
	return true
}

func stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return "None"
	case Undefined:
		return ""
	case bool:
		if t {
			return "True"
		}
		return "False"
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'g', -1, 64)
	case string:
		return t
	case []any:
		parts := make([]string, len(t))
		for i, x := range t {
			parts[i] = stringify(x)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case *List:
		return stringify(t.V)
	case *OMap:
		parts := make([]string, 0, t.Len())
		for _, k := range t.Keys() {
			vv, _ := t.Get(k)
			parts = append(parts, "'"+k+"': "+stringify(vv))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return fmt.Sprint(v)
}

func toIter(v any) []any {
	switch t := v.(type) {
	case *List:
		return t.V
	case []any:
		return t
	case *OMap:
		out := make([]any, 0, t.Len())
		for _, k := range t.Keys() {
			out = append(out, k)
		}
		return out
	case string:
		out := make([]any, 0, len(t))
		for _, r := range t {
			out = append(out, string(r))
		}
		return out
	}
	return nil
}

// boundMethod wraps obj.method calls (items/append/endswith/...).
type boundMethod struct {
	obj  any
	name string
}

var methodNames = map[string]bool{
	"items": true, "append": true, "keys": true, "values": true,
	"get": true, "endswith": true, "startswith": true, "split": true,
	"strip": true, "index": true, "pop": true,
}

func getAttr(v any, key string) any {
	switch t := v.(type) {
	case *OMap:
		if val, ok := t.Get(key); ok {
			return val
		}
		if methodNames[key] {
			return boundMethod{v, key}
		}
		return Undefined{key}
	case *List, string:
		if methodNames[key] {
			return boundMethod{v, key}
		}
		return Undefined{key}
	case map[string]any:
		if val, ok := t[key]; ok {
			return val
		}
		return Undefined{key}
	case []any:
		if methodNames[key] {
			return boundMethod{v, key}
		}
		return Undefined{key}
	}
	return Undefined{key}
}

func getIndex(v any, k any) (any, error) {
	switch t := v.(type) {
	case *OMap:
		if val, ok := t.Get(stringify(k)); ok {
			return val, nil
		}
		return Undefined{stringify(k)}, nil
	case *List:
		return getIndex(t.V, k)
	case []any:
		i, ok := toInt(k)
		if !ok {
			return nil, fmt.Errorf("non-integer index %v", k)
		}
		if i < 0 {
			i += int64(len(t))
		}
		if i < 0 || i >= int64(len(t)) {
			return Undefined{"index"}, nil
		}
		return t[i], nil
	case string:
		i, ok := toInt(k)
		if !ok || i < 0 || i >= int64(len(t)) {
			return Undefined{"index"}, nil
		}
		return string(t[i]), nil
	}
	return Undefined{"index"}, nil
}

func toInt(v any) (int64, bool) {
	switch t := v.(type) {
	case int64:
		return t, true
	case float64:
		return int64(t), true
	case bool:
		if t {
			return 1, true
		}
		return 0, true
	case string:
		i, err := strconv.ParseInt(strings.TrimSpace(t), 0, 64)
		return i, err == nil
	}
	return 0, false
}

func toFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case int64:
		return float64(t), true
	case float64:
		return t, true
	case bool:
		if t {
			return 1, true
		}
		return 0, true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return f, err == nil
	}
	return 0, false
}

func numNeg(v any) (any, error) {
	switch t := v.(type) {
	case int64:
		return -t, nil
	case float64:
		return -t, nil
	}
	return nil, fmt.Errorf("cannot negate %v", v)
}

func numEq(l, r any) bool {
	lf, lok := toFloat(l)
	rf, rok := toFloat(r)
	if lok && rok {
		return lf == rf
	}
	return stringify(l) == stringify(r)
}

func deepEq(l, r any) bool {
	if lt, ok := l.(*List); ok {
		l = lt.V
	}
	if rt, ok := r.(*List); ok {
		r = rt.V
	}
	switch lt := l.(type) {
	case *OMap:
		rt, ok := r.(*OMap)
		if !ok || lt.Len() != rt.Len() {
			return false
		}
		for _, k := range lt.Keys() {
			lv, _ := lt.Get(k)
			rv, ok := rt.Get(k)
			if !ok || !deepEq(lv, rv) {
				return false
			}
		}
		return true
	case []any:
		rt, ok := r.([]any)
		if !ok || len(lt) != len(rt) {
			return false
		}
		for i := range lt {
			if !deepEq(lt[i], rt[i]) {
				return false
			}
		}
		return true
	}
	if l == nil || r == nil {
		return isNilOrUndef(l) && isNilOrUndef(r)
	}
	if _, ok := l.(Undefined); ok {
		_, uok := r.(Undefined)
		return uok
	}
	return numEq(l, r)
}

func isNilOrUndef(v any) bool {
	if v == nil {
		return true
	}
	_, u := v.(Undefined)
	return u
}

func binOp(op string, l, r any) (any, error) {
	switch op {
	case "~":
		return stringify(l) + stringify(r), nil
	case "+":
		if ls, ok := l.(*List); ok {
			if rs, ok := r.(*List); ok {
				return &List{append(append([]any{}, ls.V...), rs.V...)}, nil
			}
		}
		if ls, ok := l.([]any); ok {
			if rs, ok := r.([]any); ok {
				return append(append([]any{}, ls...), rs...), nil
			}
		}
		if lf, ok := toFloat(l); ok {
			if rf, ok := toFloat(r); ok && !isStr(l) && !isStr(r) {
				li, lInt := toInt(l)
				ri, rInt := toInt(r)
				if lInt && rInt && isNum(l) && isNum(r) {
					return li + ri, nil
				}
				return lf + rf, nil
			}
		}
		if ls, ok := l.(string); ok {
			if rs, ok := r.(string); ok {
				return ls + rs, nil
			}
		}
		return stringify(l) + stringify(r), nil
	case "-", "*", "/", "//", "%":
		lf, lok := toFloat(l)
		rf, rok := toFloat(r)
		if !lok || !rok {
			return nil, fmt.Errorf("non-numeric %s operands", op)
		}
		li, lInt := toInt(l)
		ri, rInt := toInt(r)
		if lInt && rInt && isNum(l) && isNum(r) && op != "/" {
			switch op {
			case "-":
				return li - ri, nil
			case "*":
				return li * ri, nil
			case "//":
				if ri == 0 {
					return nil, fmt.Errorf("division by zero")
				}
				return li / ri, nil
			case "%":
				if ri == 0 {
					return nil, fmt.Errorf("modulo by zero")
				}
				return li % ri, nil
			}
		}
		switch op {
		case "-":
			return lf - rf, nil
		case "*":
			return lf * rf, nil
		case "/", "//":
			if rf == 0 {
				return nil, fmt.Errorf("division by zero")
			}
			return lf / rf, nil
		case "%":
			if rf == 0 {
				return nil, fmt.Errorf("modulo by zero")
			}
			return float64(int64(lf) % int64(rf)), nil
		}
	case "==":
		return deepEq(l, r), nil
	case "!=":
		return !deepEq(l, r), nil
	case "<", "<=", ">", ">=":
		if isNum(l) && isNum(r) {
			lf, _ := toFloat(l)
			rf, _ := toFloat(r)
			switch op {
			case "<":
				return lf < rf, nil
			case "<=":
				return lf <= rf, nil
			case ">":
				return lf > rf, nil
			case ">=":
				return lf >= rf, nil
			}
		}
		ls, rs := stringify(l), stringify(r)
		switch op {
		case "<":
			return ls < rs, nil
		case "<=":
			return ls <= rs, nil
		case ">":
			return ls > rs, nil
		case ">=":
			return ls >= rs, nil
		}
	case "in":
		switch rt := r.(type) {
		case string:
			return strings.Contains(rt, stringify(l)), nil
		case *List:
			return binOp("in", l, rt.V)
		case []any:
			for _, it := range rt {
				if deepEq(it, l) {
					return true, nil
				}
			}
			return false, nil
		case *OMap:
			_, ok := rt.Get(stringify(l))
			return ok, nil
		}
		return false, nil
	}
	return nil, fmt.Errorf("unsupported op %q", op)
}

func isStr(v any) bool { _, ok := v.(string); return ok }

func isNum(v any) bool {
	switch v.(type) {
	case int64, float64:
		return true
	case bool:
		return true
	}
	return false
}

func callValue(fn any, args []any, kw map[string]any, s *scope) (any, error) {
	if m, ok := fn.(boundMethod); ok {
		return m.call(args, s)
	}
	if name, ok := fn.(builtinFunc); ok {
		return name(args, kw, s)
	}
	return nil, fmt.Errorf("not callable: %v (%T)", fn, fn)
}

type builtinFunc func(args []any, kw map[string]any, s *scope) (any, error)

func (m boundMethod) call(args []any, _ *scope) (any, error) {
	switch m.name {
	case "items":
		if om, ok := m.obj.(*OMap); ok {
			pairs := make([]any, 0, om.Len())
			for _, k := range om.Keys() {
				v, _ := om.Get(k)
				pairs = append(pairs, &List{[]any{k, v}})
			}
			return &List{pairs}, nil
		}
	case "append":
		if l, ok := m.obj.(*List); ok {
			l.V = append(l.V, args...)
			return nil, nil
		}
	case "keys":
		if om, ok := m.obj.(*OMap); ok {
			out := make([]any, 0, om.Len())
			for _, k := range om.Keys() {
				out = append(out, k)
			}
			return &List{out}, nil
		}
	case "values":
		if om, ok := m.obj.(*OMap); ok {
			out := make([]any, 0, om.Len())
			for _, k := range om.Keys() {
				v, _ := om.Get(k)
				out = append(out, v)
			}
			return &List{out}, nil
		}
	case "get":
		if om, ok := m.obj.(*OMap); ok {
			if v, ok := om.Get(stringify(args[0])); ok {
				return v, nil
			}
			if len(args) > 1 {
				return args[1], nil
			}
			return nil, nil
		}
	case "endswith", "startswith":
		str := stringify(m.obj)
		if len(args) == 0 {
			return false, nil
		}
		if m.name == "endswith" {
			return strings.HasSuffix(str, stringify(args[0])), nil
		}
		return strings.HasPrefix(str, stringify(args[0])), nil
	case "split":
		str := stringify(m.obj)
		if len(args) == 0 {
			return &List{splitWS(str)}, nil
		}
		return &List{splitAny(str, stringify(args[0]))}, nil
	case "strip":
		return strings.TrimSpace(stringify(m.obj)), nil
	case "index":
		for i, it := range toIter(m.obj) {
			if deepEq(it, args[0]) {
				return int64(i), nil
			}
		}
		return nil, fmt.Errorf("index: not found")
	case "pop":
		if l, ok := m.obj.(*List); ok && len(l.V) > 0 {
			i := len(l.V) - 1
			if len(args) > 0 {
				j, _ := toInt(args[0])
				i = int(j)
			}
			v := l.V[i]
			l.V = append(l.V[:i], l.V[i+1:]...)
			return v, nil
		}
	}
	return nil, fmt.Errorf("unknown method %q on %T", m.name, m.obj)
}

func splitWS(s string) []any {
	var out []any
	for _, f := range strings.Fields(s) {
		out = append(out, f)
	}
	return out
}

func splitAny(s, sep string) []any {
	parts := strings.Split(s, sep)
	out := make([]any, 0, len(parts))
	for _, p := range parts {
		out = append(out, p)
	}
	return out
}

// ---------------- tests ----------------

func runTest(name string, v any, args []any) bool {
	switch name {
	case "defined":
		return !isNilOrUndef(v)
	case "undefined":
		_, u := v.(Undefined)
		return u
	case "none":
		return v == nil
	case "mapping":
		_, ok := v.(*OMap)
		return ok
	case "iterable", "sequence":
		switch v.(type) {
		case []any, *List, *OMap, string:
			return true
		}
		return false
	case "string":
		_, ok := v.(string)
		return ok
	case "number":
		return isNum(v)
	case "boolean", "bool":
		_, ok := v.(bool)
		return ok
	case "search":
		if len(args) == 0 {
			return false
		}
		re, err := regexp.Compile(stringify(args[0]))
		if err != nil {
			return false
		}
		return re.MatchString(stringify(v))
	case "equalto", "eq":
		if len(args) == 0 {
			return false
		}
		return deepEq(v, args[0])
	case "sameas":
		if len(args) == 0 {
			return false
		}
		return deepEq(v, args[0])
	case "changed", "failed", "succeeded", "skipped":
		return false
	case "in":
		if len(args) == 0 {
			return false
		}
		r, _ := binOp("in", v, args[0])
		b, _ := r.(bool)
		return b
	}
	return truthy(v)
}

// ---------------- filters ----------------

func applyFilter(name string, v any, args []any, kw map[string]any, s *scope) (any, error) {
	switch name {
	case "default", "d":
		var def any
		if len(args) > 0 {
			def = args[0]
		}
		useBool := len(args) > 1 && truthy(args[1])
		_, undef := v.(Undefined)
		if undef {
			return def, nil
		}
		if v == nil {
			return def, nil
		}
		if useBool && !truthy(v) {
			return def, nil
		}
		return v, nil
	case "basename":
		sv := stringify(v)
		return sv[strings.LastIndex(sv, "/")+1:], nil
	case "join":
		sep := " "
		if len(args) > 0 {
			sep = stringify(args[0])
		}
		parts := []string{}
		for _, it := range toIter(v) {
			parts = append(parts, stringify(it))
		}
		return strings.Join(parts, sep), nil
	case "list":
		return &List{toIter(v)}, nil
	case "length", "count":
		switch t := v.(type) {
		case string:
			return int64(len(t)), nil
		case []any:
			return int64(len(t)), nil
		case *List:
			return int64(len(t.V)), nil
		case *OMap:
			return int64(t.Len()), nil
		}
		return int64(0), nil
	case "first":
		l := toIter(v)
		if len(l) == 0 {
			return Undefined{"first"}, nil
		}
		return l[0], nil
	case "last":
		l := toIter(v)
		if len(l) == 0 {
			return Undefined{"last"}, nil
		}
		return l[len(l)-1], nil
	case "sort":
		l := append([]any{}, toIter(v)...)
		sort.SliceStable(l, func(i, j int) bool {
			if isNum(l[i]) && isNum(l[j]) {
				fi, _ := toFloat(l[i])
				fj, _ := toFloat(l[j])
				return fi < fj
			}
			if lp, ok := l[i].(*List); ok {
				if rp, ok := l[j].(*List); ok && len(lp.V) > 0 && len(rp.V) > 0 {
					return stringify(lp.V[0]) < stringify(rp.V[0])
				}
			}
			return stringify(l[i]) < stringify(l[j])
		})
		return &List{l}, nil
	case "unique":
		seen := map[string]bool{}
		var out []any
		for _, it := range toIter(v) {
			k := stringify(it)
			if !seen[k] {
				seen[k] = true
				out = append(out, it)
			}
		}
		return &List{out}, nil
	case "difference":
		var excl []any
		if len(args) > 0 {
			excl = toIter(args[0])
		}
		var out []any
		for _, it := range toIter(v) {
			skip := false
			for _, e := range excl {
				if deepEq(it, e) {
					skip = true
					break
				}
			}
			if !skip {
				out = append(out, it)
			}
		}
		return &List{out}, nil
	case "union":
		var out []any
		out = append(out, toIter(v)...)
		for _, a := range args {
			out = append(out, toIter(a)...)
		}
		return &List{out}, nil
	case "dict2items":
		if om, ok := v.(*OMap); ok {
			return &List{om.Items()}, nil
		}
		return &List{}, nil
	case "items2dict":
		m := NewOMap()
		for _, it := range toIter(v) {
			if om, ok := it.(*OMap); ok {
				k, _ := om.Get("key")
				vv, _ := om.Get("value")
				m.Set(stringify(k), vv)
			}
		}
		return m, nil
	case "map":
		return filterMap(v, args, kw, s)
	case "selectattr":
		return filterSelectAttr(v, args, true)
	case "rejectattr":
		return filterSelectAttr(v, args, false)
	case "reject":
		return filterTest(v, args, false)
	case "select":
		return filterTest(v, args, true)
	case "bool":
		return truthy(v), nil
	case "int":
		def := int64(0)
		if len(args) > 0 {
			def, _ = toInt(args[0])
		}
		base := int64(10)
		if len(args) > 1 {
			base, _ = toInt(args[1])
		}
		switch t := v.(type) {
		case int64:
			return t, nil
		case float64:
			return int64(t), nil
		case bool:
			if t {
				return int64(1), nil
			}
			return int64(0), nil
		case string:
			i, err := strconv.ParseInt(strings.TrimSpace(t), int(base), 64)
			if err == nil {
				return i, nil
			}
			if f, err := strconv.ParseFloat(t, 64); err == nil {
				return int64(f), nil
			}
		}
		return def, nil
	case "float":
		f, _ := toFloat(v)
		return f, nil
	case "string":
		return stringify(v), nil
	case "trim":
		return strings.TrimSpace(stringify(v)), nil
	case "split":
		str := stringify(v)
		if len(args) == 0 {
			return &List{splitWS(str)}, nil
		}
		return &List{splitAny(str, stringify(args[0]))}, nil
	case "lower":
		return strings.ToLower(stringify(v)), nil
	case "upper":
		return strings.ToUpper(stringify(v)), nil
	case "regex_escape":
		return regexp.QuoteMeta(stringify(v)), nil
	case "regex_replace":
		if len(args) < 2 {
			return v, nil
		}
		re, err := regexp.Compile(stringify(args[0]))
		if err != nil {
			return nil, err
		}
		return re.ReplaceAllString(stringify(v), stringify(args[1])), nil
	case "regex_findall":
		if len(args) == 0 {
			return &List{}, nil
		}
		re, err := regexp.Compile(stringify(args[0]))
		if err != nil {
			return nil, err
		}
		matches := re.FindAllStringSubmatch(stringify(v), -1)
		out := make([]any, 0, len(matches))
		for _, m := range matches {
			if len(m) > 1 {
				out = append(out, m[1])
			} else {
				out = append(out, m[0])
			}
		}
		return &List{out}, nil
	case "regex_search":
		if len(args) == 0 {
			return Undefined{"regex_search"}, nil
		}
		re, err := regexp.Compile(stringify(args[0]))
		if err != nil {
			return nil, err
		}
		m := re.FindStringSubmatch(stringify(v))
		if len(m) > 1 {
			out := make([]any, 0, len(m)-1)
			for _, g := range m[1:] {
				out = append(out, g)
			}
			return &List{out}, nil
		}
		if m != nil {
			return m[0], nil
		}
		return Undefined{"regex_search"}, nil
	case "ternary":
		if truthy(v) && len(args) > 0 {
			return args[0], nil
		}
		if len(args) > 1 {
			return args[1], nil
		}
		return nil, nil
	case "to_json":
		b, err := json.Marshal(jsonValue(v))
		if err != nil {
			return nil, err
		}
		return string(b), nil
	case "from_json":
		var out any
		if err := json.Unmarshal([]byte(stringify(v)), &out); err != nil {
			return nil, err
		}
		return fromJSON(out), nil
	case "from_yaml":
		return DecodeYAML([]byte(stringify(v)))
	case "to_yaml", "to_nice_yaml":
		b, err := yaml3.Marshal(toPlain(v))
		if err != nil {
			return nil, err
		}
		return string(b), nil
	case "b64decode":
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(stringify(v)))
		if err != nil {
			return nil, err
		}
		return string(b), nil
	case "b64encode":
		return base64.StdEncoding.EncodeToString([]byte(stringify(v))), nil
	case "hash":
		h := sha256.Sum256([]byte(stringify(v)))
		return hex.EncodeToString(h[:]), nil
	case "min":
		l := toIter(v)
		if len(l) == 0 {
			return Undefined{"min"}, nil
		}
		best := l[0]
		for _, it := range l[1:] {
			if f, ok := toFloat(it); ok {
				if bf, ok := toFloat(best); ok && f < bf {
					best = it
				}
			}
		}
		return best, nil
	case "max":
		l := toIter(v)
		if len(l) == 0 {
			return Undefined{"max"}, nil
		}
		best := l[0]
		for _, it := range l[1:] {
			if f, ok := toFloat(it); ok {
				if bf, ok := toFloat(best); ok && f > bf {
					best = it
				}
			}
		}
		return best, nil
	case "format":
		return pyFormat(stringify(v), args), nil
	case "indent":
		n := int64(4)
		if len(args) > 0 {
			n, _ = toInt(args[0])
		}
		pad := strings.Repeat(" ", int(n))
		return pad + strings.ReplaceAll(stringify(v), "\n", "\n"+pad), nil
	case "flatten":
		var out []any
		var rec func(x any)
		rec = func(x any) {
			for _, it := range toIter(x) {
				rec(it)
			}
			if toIter(x) == nil {
				out = append(out, x)
			}
		}
		rec(v)
		return &List{out}, nil
	case "zip":
		var out []any
		lists := [][]any{toIter(v)}
		for _, a := range args {
			lists = append(lists, toIter(a))
		}
		minLen := -1
		for _, l := range lists {
			if minLen < 0 || len(l) < minLen {
				minLen = len(l)
			}
		}
		for i := 0; i < minLen; i++ {
			pair := make([]any, len(lists))
			for j, l := range lists {
				pair[j] = l[i]
			}
			out = append(out, &List{pair})
		}
		return &List{out}, nil
	case "equalto", "eq":
		if len(args) == 0 {
			return false, nil
		}
		return deepEq(v, args[0]), nil
	case "search":
		return runTest("search", v, args), nil
	case "mandatory":
		if isNilOrUndef(v) {
			return nil, fmt.Errorf("mandatory: value undefined")
		}
		return v, nil
	}
	return nil, fmt.Errorf("unsupported filter %q", name)
}

func pyFormat(format string, args []any) string {
	out := format
	argi := 0
	var b strings.Builder
	for i := 0; i < len(out); i++ {
		if out[i] != '%' || i+1 >= len(out) {
			b.WriteByte(out[i])
			continue
		}
		// %% literal
		if out[i+1] == '%' {
			b.WriteByte('%')
			i++
			continue
		}
		j := i + 1
		for j < len(out) && !strings.ContainsRune("sdvrxXfEgGc", rune(out[j])) {
			j++
		}
		if j >= len(out) || argi >= len(args) {
			b.WriteString(out[i:])
			break
		}
		spec := out[i+1 : j]
		conv := out[j]
		a := args[argi]
		argi++
		switch conv {
		case 'd':
			iv, _ := toInt(a)
			width := 0
			num := strings.TrimLeft(spec, "-+0")
			fmt.Sscanf(num, "%d", &width)
			if strings.Contains(spec, "-") {
				b.WriteString(fmt.Sprintf("%-"+strconv.Itoa(width)+"d", iv))
			} else {
				b.WriteString(fmt.Sprintf("%"+spec+"d", iv))
			}
		case 's', 'v', 'r':
			sv := stringify(a)
			num := strings.TrimLeft(spec, "-")
			width := 0
			fmt.Sscanf(num, "%d", &width)
			if strings.Contains(spec, "-") {
				b.WriteString(fmt.Sprintf("%-"+strconv.Itoa(width)+"s", sv))
			} else if width > 0 {
				b.WriteString(fmt.Sprintf("%"+strconv.Itoa(width)+"s", sv))
			} else {
				b.WriteString(sv)
			}
		default:
			b.WriteString(stringify(a))
		}
		i = j
	}
	return b.String()
}

func filterMap(v any, args []any, kw map[string]any, s *scope) (any, error) {
	// map(attribute='x'[, default=y])
	if attr, ok := kw["attribute"]; ok {
		var out []any
		for _, it := range toIter(v) {
			got := selectAttrKey(it, stringify(attr))
			if _, u := got.(Undefined); u && kw["default"] != nil {
				got = kw["default"]
			}
			out = append(out, got)
		}
		return &List{out}, nil
	}
	if len(args) == 0 {
		return &List{toIter(v)}, nil
	}
	name := stringify(args[0])
	// map('basename') / map('regex_replace', p, r) — filter by name
	var out []any
	for _, it := range toIter(v) {
		fv, err := applyFilter(name, it, args[1:], nil, s)
		if err != nil {
			out = append(out, getAttr(it, name))
			continue
		}
		out = append(out, fv)
	}
	return &List{out}, nil
}

func selectAttrKey(v any, path string) any {
	cur := v
	for _, seg := range strings.Split(path, ".") {
		if m, ok := cur.(boundMethod); ok {
			cur = m
			continue
		}
		cur = getAttr(cur, seg)
		if _, u := cur.(Undefined); u {
			return cur
		}
	}
	return cur
}

func filterSelectAttr(v any, args []any, keep bool) (any, error) {
	if len(args) == 0 {
		return &List{toIter(v)}, nil
	}
	path := stringify(args[0])
	testName := ""
	var testArgs []any
	if len(args) > 1 {
		testName = stringify(args[1])
		testArgs = args[2:]
	}
	var out []any
	for _, it := range toIter(v) {
		val := selectAttrKey(it, path)
		var ok bool
		if testName == "" {
			ok = truthy(val)
		} else {
			ok = runTest(testName, val, testArgs)
		}
		if ok == keep {
			out = append(out, it)
		}
	}
	return &List{out}, nil
}

func filterTest(v any, args []any, keep bool) (any, error) {
	if len(args) == 0 {
		return v, nil
	}
	testName := stringify(args[0])
	var out []any
	for _, it := range toIter(v) {
		ok := runTest(testName, it, args[1:])
		if ok == keep {
			out = append(out, it)
		}
	}
	return &List{out}, nil
}

// ---------------- conversions ----------------

func jsonValue(v any) any {
	switch t := v.(type) {
	case *OMap:
		m := map[string]any{}
		for _, k := range t.Keys() {
			vv, _ := t.Get(k)
			m[k] = jsonValue(vv)
		}
		return m
	case *List:
		out := make([]any, len(t.V))
		for i, x := range t.V {
			out[i] = jsonValue(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = jsonValue(x)
		}
		return out
	case Undefined:
		return nil
	default:
		return v
	}
}

func fromJSON(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := NewOMap()
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			m.Set(k, fromJSON(t[k]))
		}
		return m
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = fromJSON(x)
		}
		return &List{out}
	case float64:
		if t == float64(int64(t)) {
			return int64(t)
		}
		return t
	default:
		return v
	}
}

func toPlain(v any) any {
	switch t := v.(type) {
	case *OMap:
		m := map[string]any{}
		for _, k := range t.Keys() {
			vv, _ := t.Get(k)
			m[k] = toPlain(vv)
		}
		return m
	case *List:
		out := make([]any, len(t.V))
		for i, x := range t.V {
			out[i] = toPlain(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = toPlain(x)
		}
		return out
	case Undefined:
		return nil
	default:
		return v
	}
}

// ---------------- lookup ----------------

// doLookup mirrors ansible's lookup() — fail-loud: a lookup that
// cannot be honoured (unknown plugin, missing term, no env hook)
// errors the render instead of silently emitting "", which would let
// a missing file converge to an empty config value.
func doLookup(args []any, s *scope) (any, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("lookup: missing plugin name")
	}
	kind := stringify(args[0])
	switch kind {
	case "file", "ansible.builtin.file":
		if len(args) < 2 {
			return nil, fmt.Errorf("lookup(%q): missing file path", kind)
		}
		if s.env == nil || s.env.FileLookup == nil {
			return nil, fmt.Errorf("lookup(%q): no file lookup configured", kind)
		}
		return s.env.FileLookup(stringify(args[1]))
	case "pipe", "ansible.builtin.pipe":
		if len(args) < 2 {
			return nil, fmt.Errorf("lookup(%q): missing command", kind)
		}
		if s.env == nil || s.env.PipeLookup == nil {
			return nil, fmt.Errorf("lookup(%q): no pipe lookup configured", kind)
		}
		return s.env.PipeLookup(stringify(args[1]))
	}
	return nil, fmt.Errorf("lookup: unsupported plugin %q", kind)
}
