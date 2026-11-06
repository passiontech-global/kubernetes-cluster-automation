// convert.go — jinja-value → marshal-friendly-plain conversions
// feeding to_json/from_json/from_yaml/to_yaml: OMap/List unwrap,
// YAML/JSON re-box, cyclic-input depth caps.
package jinja

import (
	"sort"
)

// ---------------- conversions ----------------

func jsonValue(v any) any { return jsonValueAt(v, 0) }

// jsonValueAt converts under the walkMaxDepth recursion budget —
// a cyclic value can't be marshaled anyway, so past the cap a
// "[...]" string placeholder stands in (marshal-safe).
func jsonValueAt(v any, depth int) any {
	if depth > walkMaxDepth {
		return "[...]"
	}
	switch t := v.(type) {
	case *OMap:
		m := map[string]any{}
		for _, k := range t.Keys() {
			vv, _ := t.Get(k)
			m[k] = jsonValueAt(vv, depth+1)
		}
		return m
	case *List:
		out := make([]any, len(t.V))
		for i, x := range t.V {
			out[i] = jsonValueAt(x, depth+1)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = jsonValueAt(x, depth+1)
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

func toPlain(v any) any { return toPlainAt(v, 0) }

// toPlainAt converts under the walkMaxDepth recursion budget —
// same cyclic-input guard as jsonValueAt; past the cap a "[...]"
// placeholder keeps the yaml.Marshal fed and acyclic.
func toPlainAt(v any, depth int) any {
	if depth > walkMaxDepth {
		return "[...]"
	}
	switch t := v.(type) {
	case *OMap:
		m := map[string]any{}
		for _, k := range t.Keys() {
			vv, _ := t.Get(k)
			m[k] = toPlainAt(vv, depth+1)
		}
		return m
	case *List:
		out := make([]any, len(t.V))
		for i, x := range t.V {
			out[i] = toPlainAt(x, depth+1)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = toPlainAt(x, depth+1)
		}
		return out
	case Undefined:
		return nil
	default:
		return v
	}
}
