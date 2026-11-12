package jinja

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// ---------------- value helpers ----------------

// asInt64 normalizes every Go integer type to int64 — contexts feed
// the engine plain Go values (int, uint32, ...) that used to fall
// through every numeric branch and compare/stringify as garbage.
// uint64 (and uint on 64-bit) only converts while it fits int64;
// float64 is deliberately NOT here — it keeps its own (truncating,
// range-checked) path via floatToInt64.
func asInt64(v any) (int64, bool) {
	switch t := v.(type) {
	case int64:
		return t, true
	case int:
		return int64(t), true
	case int32:
		return int64(t), true
	case int16:
		return int64(t), true
	case int8:
		return int64(t), true
	case uint64:
		if t <= math.MaxInt64 {
			return int64(t), true
		}
	case uint:
		if uint64(t) <= math.MaxInt64 {
			return int64(t), true
		}
	case uint32:
		return int64(t), true
	case uint16:
		return int64(t), true
	case uint8:
		return int64(t), true
	}
	return 0, false
}

// asUint64 normalizes unsigned integer types for stringify — a
// uint64 above MaxInt64 still prints exactly.
func asUint64(v any) (uint64, bool) {
	switch t := v.(type) {
	case uint64:
		return t, true
	case uint:
		return uint64(t), true
	case uint32:
		return uint64(t), true
	case uint16:
		return uint64(t), true
	case uint8:
		return uint64(t), true
	}
	return 0, false
}

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
		// A typed-nil *List is an empty list, not a panic.
		return t != nil && len(t.V) > 0
	case *OMap:
		return t.Len() > 0
	case map[string]any:
		return len(t) > 0
	case map[string]string:
		return len(t) > 0
	}
	if i, ok := asInt64(v); ok {
		return i != 0
	}
	if u, ok := asUint64(v); ok {
		return u != 0
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
		// floatToInt64, not int64(t): NaN/±Inf/out-of-range used to
		// truncate into platform garbage (usually MinInt64).
		if i, ok := floatToInt64(t); ok && t == float64(i) {
			return strconv.FormatInt(i, 10)
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
		if t == nil {
			return "[]"
		}
		return stringifyAt(t.V, depth+1, steps)
	case *OMap:
		parts := make([]string, 0, t.Len())
		for _, k := range t.Keys() {
			vv, _ := t.Get(k)
			parts = append(parts, "'"+k+"': "+stringifyAt(vv, depth+1, steps))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	case map[string]any:
		return stringifyStringMap(t, depth, steps)
	case map[string]string:
		return stringifyStringMap(t, depth, steps)
	}
	if i, ok := asInt64(v); ok {
		return strconv.FormatInt(i, 10)
	}
	if u, ok := asUint64(v); ok {
		return strconv.FormatUint(u, 10)
	}
	return fmt.Sprint(v)
}

// stringifyStringMap renders a plain Go string map like an *OMap —
// keys sorted for deterministic output (Go map order is random).
func stringifyStringMap[V any](m map[string]V, depth int, steps *int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, "'"+k+"': "+stringifyAt(m[k], depth+1, steps))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func ToIter(v any) []any {
	switch t := v.(type) {
	case *List:
		if t == nil {
			return nil
		}
		return t.V
	case []any:
		return t
	case *OMap:
		if t == nil {
			return nil
		}
		out := make([]any, 0, t.Len())
		for _, k := range t.Keys() {
			out = append(out, k)
		}
		return out
	case map[string]any:
		return sortedMapKeys(t)
	case map[string]string:
		return sortedMapKeys(t)
	case string:
		out := make([]any, 0, len(t))
		for _, r := range t {
			out = append(out, string(r))
		}
		return out
	}
	return nil
}

// sortedMapKeys yields a plain Go map's keys in sorted order — jinja
// iterates a mapping's keys, and Go's random map order would make
// `for k in map` / `| join` / `| sort` output nondeterministic.
func sortedMapKeys[V any](m map[string]V) []any {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]any, len(keys))
	for i, k := range keys {
		out[i] = k
	}
	return out
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
		if methodNames[key] {
			return boundMethod{v, key}
		}
		return Undefined{key}
	case map[string]string:
		if val, ok := t[key]; ok {
			return val
		}
		if methodNames[key] {
			return boundMethod{v, key}
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
	case map[string]any:
		if val, ok := t[Stringify(k)]; ok {
			return val, nil
		}
		return Undefined{Stringify(k)}, nil
	case map[string]string:
		if val, ok := t[Stringify(k)]; ok {
			return val, nil
		}
		return Undefined{Stringify(k)}, nil
	case *List:
		if t == nil {
			return Undefined{"index"}, nil
		}
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
		// Same negative-index semantics as the []any branch, in runes.
		runes := []rune(t)
		if i < 0 {
			i += int64(len(runes))
		}
		if i < 0 || i >= int64(len(runes)) {
			return Undefined{"index"}, nil
		}
		return string(runes[i]), nil
	}
	return Undefined{"index"}, nil
}

func ToInt(v any) (int64, bool) {
	switch t := v.(type) {
	case int64:
		return t, true
	case float64:
		// floatToInt64, not int64(t): NaN/±Inf/out-of-range used to
		// return platform garbage (usually MinInt64) with ok=true.
		return floatToInt64(t)
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
	if i, ok := asInt64(v); ok {
		return i, true
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
	if i, ok := asInt64(v); ok {
		return float64(i), true
	}
	return 0, false
}

func numNeg(v any) (any, error) {
	switch t := v.(type) {
	case int64:
		// -MinInt64 wraps to itself in int64 — promote to float64
		// (exact: 2^63 is a power of two) like python's bignum.
		if t == math.MinInt64 {
			return -float64(t), nil
		}
		return -t, nil
	case float64:
		return -t, nil
	}
	if i, ok := asInt64(v); ok {
		if i == math.MinInt64 {
			return -float64(i), nil
		}
		return -i, nil
	}
	return nil, fmt.Errorf("cannot negate %v", v)
}

// addInt64/subInt64/mulInt64 are the exact int64 fast paths for
// binOp's arithmetic: ok=false means the true result does not fit
// int64 and the caller promotes to float64 — a silent wraparound
// would flip the sign and corrupt template math (python ints are
// arbitrary precision).
func addInt64(a, b int64) (int64, bool) {
	s := a + b
	if (b > 0 && s < a) || (b < 0 && s > a) {
		return 0, false
	}
	return s, true
}

func subInt64(a, b int64) (int64, bool) {
	d := a - b
	if (b < 0 && d < a) || (b > 0 && d > a) {
		return 0, false
	}
	return d, true
}

func mulInt64(a, b int64) (int64, bool) {
	if a == 0 || b == 0 {
		return 0, true
	}
	if a == -1 {
		// p/a below would be MinInt64/-1 → SIGFPE when b is
		// MinInt64; handle the sign flip directly.
		if b == math.MinInt64 {
			return 0, false
		}
		return -b, true
	}
	p := a * b
	// Two's-complement wrap makes p/a != b exactly when the true
	// product left int64 range (a == 0 and a == -1 excluded above,
	// so the division can never panic).
	if p/a != b {
		return 0, false
	}
	return p, true
}

// numAsFloat converts only plain, finite numbers — no strings, no
// bools. numEq uses it to keep bool==number numeric (python
// True == 1) while bool==string stays unequal.
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
	if i, ok := asInt64(v); ok {
		return float64(i), true
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
	// Integer-typed pairs compare on int64 — routing them through
	// float64 rounds both sides to the same value past 2^53
	// (9007199254740993 == 9007199254740992 used to be true).
	if ai, aok := asInt64(l); aok {
		if bi, bok := asInt64(r); bok {
			return ai == bi
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
		if lt == nil {
			// Typed-nil unwraps to an EMPTY slice — same shape
			// (*OMap)(nil) takes through asMapping — so it compares
			// equal to [] and unequal to None, like python's [].
			l = []any(nil)
		} else {
			if lt == r {
				return true
			}
			l = lt.V
		}
	case *OMap:
		if lt == r {
			return true
		}
	}
	switch rt := r.(type) {
	case *List:
		if rt == nil {
			r = []any(nil)
		} else {
			if rt == l {
				return true
			}
			r = rt.V
		}
	}
	// Mappings compare order-insensitively across *OMap,
	// map[string]any and map[string]string — a vars-file OMap and a
	// Go-native map with the same entries are the same value.
	if lm, lok := asMapping(l); lok {
		rm, rok := asMapping(r)
		if !rok || lm.n != rm.n {
			return false
		}
		for _, k := range lm.keys {
			lv, _ := lm.get(k)
			rv, ok := rm.get(k)
			if !ok || !deepEqAt(lv, rv, depth+1, steps) {
				return false
			}
		}
		return true
	}
	if _, rok := asMapping(r); rok {
		return false
	}
	switch lt := l.(type) {
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

// mappingView is the Len/Get surface shared by *OMap, map[string]any
// and map[string]string for order-insensitive deep equality.
type mappingView struct {
	n    int
	keys []string
	get  func(string) (any, bool)
}

// isMappingValue reports whether v is any mapping shape the engine
// understands (*OMap, map[string]any, map[string]string) — used by
// the for-loop unpack guards.
func isMappingValue(v any) bool {
	_, ok := asMapping(v)
	return ok
}

func asMapping(v any) (mappingView, bool) {
	switch t := v.(type) {
	case *OMap:
		return mappingView{n: t.Len(), keys: t.Keys(), get: t.Get}, true
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return mappingView{
			n:    len(t),
			keys: keys,
			get: func(k string) (any, bool) {
				x, ok := t[k]
				return x, ok
			},
		}, true
	case map[string]string:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return mappingView{
			n:    len(t),
			keys: keys,
			get: func(k string) (any, bool) {
				x, ok := t[k]
				return x, ok
			},
		}, true
	}
	return mappingView{}, false
}

func IsNilOrUndef(v any) bool {
	if v == nil {
		return true
	}
	_, u := v.(Undefined)
	return u
}

// seqElems unwraps either list representation the engine carries —
// *List (literals, filters) and []any (DecodeYAML, Go callers) —
// for the seq+seq concat in binOp.
func seqElems(v any) ([]any, bool) {
	switch t := v.(type) {
	case *List:
		if t == nil {
			return nil, true
		}
		return t.V, true
	case []any:
		return t, true
	}
	return nil, false
}

func binOp(op string, l, r any) (any, error) {
	switch op {
	case "~":
		return Stringify(l) + Stringify(r), nil
	case "+":
		// seq+seq concatenates across BOTH list representations:
		// DecodeYAML yields []any while list literals and filters
		// yield *List — `yaml_list + ['a']` used to fall through to
		// the unsupported-operands error.
		if ls, ok := seqElems(l); ok {
			if rs, ok := seqElems(r); ok {
				out := append(append([]any{}, ls...), rs...)
				if _, isList := l.(*List); isList {
					return &List{out}, nil
				}
				if _, isList := r.(*List); isList {
					return &List{out}, nil
				}
				return out, nil
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
				if lInt && rInt && isNum(l) && isNum(r) &&
					!isFloatNum(l) && !isFloatNum(r) {
					if s, ok := addInt64(li, ri); ok {
						return s, nil
					}
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
		// ToInt TRUNCATES every float64 (5.5 → 5, ok=true), so
		// lInt/rInt alone would route `5.5 * 2.0` through the
		// integer branch below and silently drop the fraction
		// (10 instead of 11). The fast-path is only for genuinely
		// integer-typed operands — any float64 takes the float
		// math further down.
		if lInt && rInt && isNum(l) && isNum(r) &&
			!isFloatNum(l) && !isFloatNum(r) && op != "/" {
			switch op {
			case "-":
				if d, ok := subInt64(li, ri); ok {
					return d, nil
				}
				return lf - rf, nil
			case "*":
				if p, ok := mulInt64(li, ri); ok {
					return p, nil
				}
				return lf * rf, nil
			case "//":
				if ri == 0 {
					return nil, errors.New("division by zero")
				}
				if li == math.MinInt64 && ri == -1 {
					// The only int64 divide whose quotient
					// overflows: the hardware divide would raise
					// SIGFPE. MinInt64 is exact as a float64 and
					// /-1 gives exactly 2^63, so the float path
					// answers exactly.
					return math.Floor(lf / rf), nil
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
				if li == math.MinInt64 && ri == -1 {
					// Same divide-overflow SIGFPE hazard; the
					// remainder never overflows and is exactly 0
					// (x % -1 == 0 in python for every x).
					return int64(0), nil
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
			c, ok := numCmp(l, r)
			if !ok {
				// A NaN/±Inf operand makes EVERY ordering
				// comparison false (IEEE-754 / python) — falling
				// through to the string branch would compare
				// "NaN" < "5" lexically and answer nonsense.
				return false, nil
			}
			switch op {
			case "<":
				return c < 0, nil
			case "<=":
				return c <= 0, nil
			case ">":
				return c > 0, nil
			case ">=":
				return c >= 0, nil
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
			var rv []any
			if rt != nil {
				rv = rt.V
			}
			return binOp("in", l, rv)
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
		// Plain Go maps get the same membership test *OMap has —
		// "k" in map[string]any was a silent false while deepEq
		// already treats all three mapping shapes equivalently.
		if mv, ok := asMapping(r); ok {
			_, found := mv.get(Stringify(l))
			return found, nil
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
	_, ok := asInt64(v)
	return ok
}

// isFloatNum reports whether v is a float64 — the one numeric type
// ToInt cannot convert losslessly (it truncates 5.5 to 5 and still
// reports ok). binOp's integer fast-paths must exclude it so float
// arithmetic keeps its fraction.
func isFloatNum(v any) bool {
	_, ok := v.(float64)
	return ok
}

// numCmp orders two numeric operands: integer-typed pairs compare on
// int64 (exact past 2^53), everything else on finite floats. ok=false
// means at least one side isn't a usable number (NaN/±Inf) — the
// caller falls back to string ordering instead of silently treating
// the rejected value as 0.0 (the old `lf, _ := toFloat(l)` did).
func numCmp(a, b any) (int, bool) {
	if ai, aok := asInt64(a); aok {
		if bi, bok := asInt64(b); bok {
			switch {
			case ai < bi:
				return -1, true
			case ai > bi:
				return 1, true
			}
			return 0, true
		}
	}
	af, aok := toFloat(a)
	bf, bok := toFloat(b)
	if !aok || !bok {
		return 0, false
	}
	switch {
	case af < bf:
		return -1, true
	case af > bf:
		return 1, true
	}
	return 0, true
}

// minMaxLess is the min/max comparator: numeric when both operands
// are numbers, lexical on the string form otherwise — a non-numeric
// list used to keep the first element untouched (never comparing).
func minMaxLess(a, b any) bool {
	if isNum(a) && isNum(b) {
		if c, ok := numCmp(a, b); ok {
			return c < 0
		}
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
		// asMapping covers *OMap (insertion order via Keys()) and the
		// plain map shapes DecodeYAML/Go callers produce (sorted keys)
		// — .items() on a map[string]any used to be uncallable.
		if mv, ok := asMapping(m.obj); ok {
			pairs := make([]any, 0, mv.n)
			for _, k := range mv.keys {
				v, _ := mv.get(k)
				pairs = append(pairs, &List{[]any{k, v}})
			}
			return &List{pairs}, nil
		}
	case "append":
		if l, ok := m.obj.(*List); ok && l != nil {
			l.V = append(l.V, args...)
			return nil, nil
		}
	case "keys":
		if mv, ok := asMapping(m.obj); ok {
			out := make([]any, 0, mv.n)
			for _, k := range mv.keys {
				out = append(out, k)
			}
			return &List{out}, nil
		}
	case "values":
		if mv, ok := asMapping(m.obj); ok {
			out := make([]any, 0, mv.n)
			for _, k := range mv.keys {
				v, _ := mv.get(k)
				out = append(out, v)
			}
			return &List{out}, nil
		}
	case "get":
		if mv, ok := asMapping(m.obj); ok {
			if len(args) == 0 {
				return nil, errors.New("get: missing key argument")
			}
			if v, ok := mv.get(Stringify(args[0])); ok {
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
		if l, ok := m.obj.(*List); ok && l != nil {
			if len(l.V) == 0 {
				return nil, errors.New("pop: empty list")
			}
			i := int64(len(l.V)) - 1
			if len(args) > 0 {
				j, ok := ToInt(args[0])
				if !ok {
					return nil, errors.New("pop: index must be an integer")
				}
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
