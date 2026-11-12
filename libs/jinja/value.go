package jinja

import (
	"fmt"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
)

// ---------------- value helpers ----------------
//
// Coercions (Truthy/ToInt/toFloat), iteration (ToIter), and the
// numeric comparison core (numEq/numCmp/minMaxLess) live here.
// Method/attribute dispatch is methods.go, python-repr and JSON
// writers are stringify.go, and the binary-operator evaluator
// (binOp) is in expr.go next to the AST nodes that call it.

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
	keys := slices.Sorted(maps.Keys(m))
	out := make([]any, len(keys))
	for i, k := range keys {
		out[i] = k
	}
	return out
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
