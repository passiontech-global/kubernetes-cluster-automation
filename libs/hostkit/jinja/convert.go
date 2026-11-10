// convert.go — jinja-value → marshal-friendly-plain conversions
// feeding to_json/from_json/from_yaml/to_yaml: OMap/List unwrap,
// YAML/JSON re-box, cyclic-input depth caps.
package jinja

import (
	"fmt"
	"sort"
)

// ---------------- conversions ----------------

func jsonValue(v any) (any, error) {
	steps := 0
	return jsonValueAt(v, 0, &steps)
}

// jsonValueAt converts under the walkMaxDepth recursion budget AND
// the walkMaxSteps total-step budget — a cyclic value can't be
// marshaled anyway, so past the depth cap a "[...]" string
// placeholder stands in (marshal-safe), while an exponentially
// BRANCHING structure (a list holding two copies of itself) stays
// shallow and instead burns the shared step budget, which errors.
func jsonValueAt(v any, depth int, steps *int) (any, error) {
	if depth > walkMaxDepth {
		return "[...]", nil
	}
	if stepBudgetExhausted(steps) {
		return nil, fmt.Errorf("json: value walk exceeds %d steps (exponentially branching value?)", walkMaxSteps)
	}
	switch t := v.(type) {
	case *OMap:
		m := map[string]any{}
		for _, k := range t.Keys() {
			vv, _ := t.Get(k)
			cv, err := jsonValueAt(vv, depth+1, steps)
			if err != nil {
				return nil, err
			}
			m[k] = cv
		}
		return m, nil
	case *List:
		out := make([]any, len(t.V))
		for i, x := range t.V {
			cv, err := jsonValueAt(x, depth+1, steps)
			if err != nil {
				return nil, err
			}
			out[i] = cv
		}
		return out, nil
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			cv, err := jsonValueAt(x, depth+1, steps)
			if err != nil {
				return nil, err
			}
			out[i] = cv
		}
		return out, nil
	case map[string]any:
		// Recurse: values may hold *OMap/*List/Undefined which
		// json.Marshal cannot represent — same reason *OMap is
		// unwrapped above.
		m := make(map[string]any, len(t))
		for k, vv := range t {
			cv, err := jsonValueAt(vv, depth+1, steps)
			if err != nil {
				return nil, err
			}
			m[k] = cv
		}
		return m, nil
	case map[string]string:
		return t, nil
	case Undefined:
		return nil, nil
	default:
		return v, nil
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
		// floatToInt64, not int64(t): NaN/±Inf/out-of-range floats
		// truncate into platform garbage (usually MinInt64).
		if i, ok := floatToInt64(t); ok && t == float64(i) {
			return i
		}
		return t
	default:
		return v
	}
}

func toPlain(v any) (any, error) {
	steps := 0
	return toPlainAt(v, 0, &steps)
}

// toPlainAt converts under the walkMaxDepth recursion budget AND
// the walkMaxSteps total-step budget — same guards as jsonValueAt:
// past the depth cap a "[...]" placeholder keeps the yaml.Marshal
// fed and acyclic, while an exponentially branching structure
// errors instead of exploding the walk.
func toPlainAt(v any, depth int, steps *int) (any, error) {
	if depth > walkMaxDepth {
		return "[...]", nil
	}
	if stepBudgetExhausted(steps) {
		return nil, fmt.Errorf("yaml: value walk exceeds %d steps (exponentially branching value?)", walkMaxSteps)
	}
	switch t := v.(type) {
	case *OMap:
		m := map[string]any{}
		for _, k := range t.Keys() {
			vv, _ := t.Get(k)
			pv, err := toPlainAt(vv, depth+1, steps)
			if err != nil {
				return nil, err
			}
			m[k] = pv
		}
		return m, nil
	case *List:
		out := make([]any, len(t.V))
		for i, x := range t.V {
			pv, err := toPlainAt(x, depth+1, steps)
			if err != nil {
				return nil, err
			}
			out[i] = pv
		}
		return out, nil
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			pv, err := toPlainAt(x, depth+1, steps)
			if err != nil {
				return nil, err
			}
			out[i] = pv
		}
		return out, nil
	case map[string]any:
		// Same recursion as jsonValueAt — nested *OMap/*List values
		// must unwrap before yaml.Marshal sees them.
		m := make(map[string]any, len(t))
		for k, vv := range t {
			pv, err := toPlainAt(vv, depth+1, steps)
			if err != nil {
				return nil, err
			}
			m[k] = pv
		}
		return m, nil
	case map[string]string:
		return t, nil
	case Undefined:
		return nil, nil
	default:
		return v, nil
	}
}
