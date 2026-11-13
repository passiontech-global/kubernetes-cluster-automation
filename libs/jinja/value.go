// value.go — value coercions (Truthy/ToInt/toFloat), iteration
// (ToIter), the shared walk budgets and the list/map unwraps
// (seqElems). The numeric machinery — exact-magnitude compares,
// the int64 fast paths, numEq/numCmp/minMaxLess — lives in num.go.
// Method/attribute dispatch is methods.go, python-repr and JSON
// writers are stringify.go, and the binary-operator evaluator
// (binOp) is in binop.go next to the AST nodes that call it.
package jinja

import (
	"maps"
	"math"
	"slices"
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
	case uint64:
		// Values past MaxInt64 have no int64 form; the float64
		// conversion is the best representable answer (exact up to
		// 2^53, nearest above).
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
	if u, ok := asUint64(v); ok {
		return float64(u), true
	}
	return 0, false
}

func isStr(v any) bool { _, ok := v.(string); return ok }

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
