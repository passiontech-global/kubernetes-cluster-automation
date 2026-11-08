package jinja

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// ---------------- value helpers ----------------

func Truthy(v any) bool {
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

func Stringify(v any) string {
	steps := 0
	return stringifyAt(v, 0, &steps)
}

// walkMaxSteps bounds the TOTAL number of node visits in one
// top-level walk (stringify / json / plain / deepEq / yaml-decode),
// shared through a *int across the whole recursion. A depth cap
// alone can't stop an exponentially BRANCHING structure — a list
// containing two copies of itself doubles the work every level
// while staying shallow — so the walkers also burn a shared step
// budget and bail (or error) once it's gone. That same budget is
// what turns a YAML billion-laughs document into a decode error
// instead of a hang.
const walkMaxSteps = 100_000

// stepBudgetExhausted bumps the shared walk counter and reports
// whether the budget is spent — the walker must stop descending
// NOW. A nil counter (leaf-only helpers) is never exhausted.
func stepBudgetExhausted(steps *int) bool {
	if steps == nil {
		return false
	}
	*steps++
	return *steps > walkMaxSteps
}

// stringifyAt renders under the walkMaxDepth recursion budget AND
// the walkMaxSteps total-step budget — a cyclic *List is
// constructible in-template ({% set _ = l.append(l) %}) and
// unbounded recursion would burst the goroutine stack, while a
// branching cycle doubles the work per level without ever
// deepening. Past either cap a python-style "[...]" marks the
// elided tail (Stringify's signature is public API, so the step
// bail degrades instead of erroring).
func stringifyAt(v any, depth int, steps *int) string {
	if depth > walkMaxDepth || stepBudgetExhausted(steps) {
		return "[...]"
	}
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
			parts[i] = stringifyAt(x, depth+1, steps)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case *List:
		return stringifyAt(t.V, depth+1, steps)
	case *OMap:
		parts := make([]string, 0, t.Len())
		for _, k := range t.Keys() {
			vv, _ := t.Get(k)
			parts = append(parts, "'"+k+"': "+stringifyAt(vv, depth+1, steps))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return fmt.Sprint(v)
}

func ToIter(v any) []any {
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
		if val, ok := t.Get(Stringify(k)); ok {
			return val, nil
		}
		return Undefined{Stringify(k)}, nil
	case *List:
		return getIndex(t.V, k)
	case []any:
		i, ok := ToInt(k)
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
		i, ok := ToInt(k)
		if !ok {
			return Undefined{"index"}, nil
		}
		// Same negative-index semantics as the []any branch.
		if i < 0 {
			i += int64(len(t))
		}
		if i < 0 || i >= int64(len(t)) {
			return Undefined{"index"}, nil
		}
		return string(t[i]), nil
	}
	return Undefined{"index"}, nil
}

func ToInt(v any) (int64, bool) {
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
		// Base-10 only: ParseInt(s, 0, ...) reads a leading 0 as
		// OCTAL ("010"→8, "08"→error) — python's int('010') is 10.
		i, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
		return i, err == nil
	}
	return 0, false
}

func toFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case int64:
		return float64(t), true
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) {
			return 0, false
		}
		return t, true
	case bool:
		if t {
			return 1, true
		}
		return 0, true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		// NaN/±Inf (ParseFloat accepts "nan"/"inf") are rejected so
		// a numeric-looking string can never smuggle a non-finite
		// float into comparisons or int conversion.
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, false
		}
		return f, true
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

// numAsFloat converts only plain, finite numbers (int64/float64) —
// no strings, no bools. numEq uses it to keep bool==number numeric
// (python True == 1) while bool==string stays unequal.
func numAsFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case int64:
		return float64(t), true
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) {
			return 0, false
		}
		return t, true
	}
	return 0, false
}

// numEq compares two scalars for equality without cross-type
// surprises:
//
//   - bool == bool is identity; a bool pairs numerically ONLY with
//     a plain number (python True == 1) — never with a string, so
//     false == '0' is false.
//   - string == string is lexicographic, NEVER numeric: '0' and
//     '00', '1e2' and '100' parse to the same float but are
//     different strings.
//   - numeric pairs (int64/float64/numeric-string) compare as
//     floats — '1' == 1 stays true.
//   - a non-finite number (toFloat rejects NaN/±Inf) equals
//     nothing, not even itself (IEEE-754) — the Stringify
//     fallback must not resurrect NaN == NaN as "NaN" == "NaN".
func numEq(l, r any) bool {
	lb, lIsBool := l.(bool)
	rb, rIsBool := r.(bool)
	switch {
	case lIsBool && rIsBool:
		return lb == rb
	case lIsBool:
		rf, ok := numAsFloat(r)
		if !ok {
			return false
		}
		lf := 0.0
		if lb {
			lf = 1
		}
		return lf == rf
	case rIsBool:
		lf, ok := numAsFloat(l)
		if !ok {
			return false
		}
		rf := 0.0
		if rb {
			rf = 1
		}
		return lf == rf
	}
	if ls, ok := l.(string); ok {
		if rs, ok := r.(string); ok {
			return ls == rs
		}
	}
	lf, lok := toFloat(l)
	rf, rok := toFloat(r)
	if lok && rok {
		return lf == rf
	}
	// Exactly one side numeric (or a rejected NaN/Inf number): a
	// string form like "NaN" must not count as equality.
	if isNum(l) || isNum(r) {
		return false
	}
	return Stringify(l) == Stringify(r)
}

func deepEq(l, r any) bool {
	steps := 0
	return deepEqAt(l, r, 0, &steps)
}

// deepEqAt is deepEq under the walkMaxDepth recursion budget AND
// the walkMaxSteps total-step budget — cyclic structures can't be
// compared meaningfully and would overflow the stack (the deep
// tail answers false), while a branching cycle doubles the
// comparison work per level without ever deepening; the shared
// counter bails out in bounded time. Identical container pointers
// short-circuit true so `l == l` stays true even for a
// self-referential list.
func deepEqAt(l, r any, depth int, steps *int) bool {
	if depth > walkMaxDepth || stepBudgetExhausted(steps) {
		return false
	}
	switch lt := l.(type) {
	case *List:
		if lt == r {
			return true
		}
		l = lt.V
	case *OMap:
		if lt == r {
			return true
		}
	}
	switch rt := r.(type) {
	case *List:
		if rt == l {
			return true
		}
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
			if !ok || !deepEqAt(lv, rv, depth+1, steps) {
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
			if !deepEqAt(lt[i], rt[i], depth+1, steps) {
				return false
			}
		}
		return true
	}
	if l == nil || r == nil {
		return IsNilOrUndef(l) && IsNilOrUndef(r)
	}
	if _, ok := l.(Undefined); ok {
		_, uok := r.(Undefined)
		return uok
	}
	return numEq(l, r)
}

func IsNilOrUndef(v any) bool {
	if v == nil {
		return true
	}
	_, u := v.(Undefined)
	return u
}

func binOp(op string, l, r any) (any, error) {
	switch op {
	case "~":
		return Stringify(l) + Stringify(r), nil
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
		if isStr(l) || isStr(r) {
			// str+str concatenates; str+number silently producing
			// "53" for '5'+3 hides template bugs — python raises
			// TypeError (use ~ for concat-coercion).
			ls, lok := l.(string)
			rs, rok := r.(string)
			if lok && rok {
				return ls + rs, nil
			}
			// Name the NON-string operand — reporting r's type
			// blamed the string half when l was the offender.
			bad := r
			if !lok {
				bad = l
			}
			return nil, fmt.Errorf("cannot concatenate string and %T (use ~ for coercion)", bad)
		}
		if lf, ok := toFloat(l); ok {
			if rf, ok := toFloat(r); ok {
				li, lInt := ToInt(l)
				ri, rInt := ToInt(r)
				if lInt && rInt && isNum(l) && isNum(r) {
					return li + ri, nil
				}
				return lf + rf, nil
			}
		}
		// list+num, dict+num, none+num … used to fall through to
		// a silent Stringify-concat — same bug-hiding class as
		// str+num. Only num+num, str+str and seq+seq are legal.
		return nil, fmt.Errorf("unsupported operand types for +: %T and %T", l, r)
	case "-", "*", "/", "//", "%":
		lf, lok := toFloat(l)
		rf, rok := toFloat(r)
		if !lok || !rok {
			return nil, fmt.Errorf("non-numeric %s operands", op)
		}
		li, lInt := ToInt(l)
		ri, rInt := ToInt(r)
		if lInt && rInt && isNum(l) && isNum(r) && op != "/" {
			switch op {
			case "-":
				return li - ri, nil
			case "*":
				return li * ri, nil
			case "//":
				if ri == 0 {
					return nil, errors.New("division by zero")
				}
				// python // FLOORS: -7//2 = -4, 7//-2 = -4 — Go's
				// truncating division would give -3 for both.
				q := li / ri
				if li%ri != 0 && (li < 0) != (ri < 0) {
					q--
				}
				return q, nil
			case "%":
				if ri == 0 {
					return nil, errors.New("modulo by zero")
				}
				// python's % takes the DIVISOR's sign: -7%2 = 1,
				// 7%-2 = -1 — Go's remainder truncates toward zero.
				m := li % ri
				if m != 0 && (m < 0) != (ri < 0) {
					m += ri
				}
				return m, nil
			}
		}
		switch op {
		case "-":
			return lf - rf, nil
		case "*":
			return lf * rf, nil
		case "/", "//":
			if rf == 0 {
				return nil, errors.New("division by zero")
			}
			if op == "//" {
				// python's float // floors too: -7.0//2 = -4.0
				// (plain division truncates toward zero).
				return math.Floor(lf / rf), nil
			}
			return lf / rf, nil
		case "%":
			if rf == 0 {
				return nil, errors.New("modulo by zero")
			}
			// math.Mod, NOT int64(lf) % int64(rf): operands reaching
			// this branch aren't int-representable (a float-string
			// like "0.5"), and truncating a sub-1 divisor to
			// int64(rf)==0 was an integer divide-by-zero PANIC.
			// Python's % takes the DIVISOR's sign (floored modulo),
			// so shift an fmod result whose sign disagrees with rf.
			m := math.Mod(lf, rf)
			if m != 0 && (m < 0) != (rf < 0) {
				m += rf
			}
			return m, nil
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
		ls, rs := Stringify(l), Stringify(r)
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
			return strings.Contains(rt, Stringify(l)), nil
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
			_, ok := rt.Get(Stringify(l))
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

// minMaxLess is the min/max comparator: numeric when both operands
// are numbers, lexical on the string form otherwise — a non-numeric
// list used to keep the first element untouched (never comparing).
func minMaxLess(a, b any) bool {
	if isNum(a) && isNum(b) {
		af, _ := toFloat(a)
		bf, _ := toFloat(b)
		return af < bf
	}
	return Stringify(a) < Stringify(b)
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
			if len(args) == 0 {
				return nil, errors.New("get: missing key argument")
			}
			if v, ok := om.Get(Stringify(args[0])); ok {
				return v, nil
			}
			if len(args) > 1 {
				return args[1], nil
			}
			return nil, nil
		}
	case "endswith", "startswith":
		str := Stringify(m.obj)
		if len(args) == 0 {
			return false, nil
		}
		if m.name == "endswith" {
			return strings.HasSuffix(str, Stringify(args[0])), nil
		}
		return strings.HasPrefix(str, Stringify(args[0])), nil
	case "split":
		str := Stringify(m.obj)
		if len(args) == 0 {
			return &List{splitWS(str)}, nil
		}
		return &List{splitAny(str, Stringify(args[0]))}, nil
	case "strip":
		return strings.TrimSpace(Stringify(m.obj)), nil
	case "index":
		if len(args) == 0 {
			return nil, errors.New("index: missing argument")
		}
		for i, it := range ToIter(m.obj) {
			if deepEq(it, args[0]) {
				return int64(i), nil
			}
		}
		return nil, errors.New("index: not found")
	case "pop":
		if l, ok := m.obj.(*List); ok {
			if len(l.V) == 0 {
				return nil, errors.New("pop: empty list")
			}
			i := int64(len(l.V)) - 1
			if len(args) > 0 {
				j, _ := ToInt(args[0])
				i = j
				// python list.pop accepts negative indices.
				if i < 0 {
					i += int64(len(l.V))
				}
			}
			if i < 0 || i >= int64(len(l.V)) {
				return nil, fmt.Errorf("pop: index %d out of range", i)
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
