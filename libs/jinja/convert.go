// convert.go — jinja-value → marshal-ready conversions feeding
// to_json/from_json/from_yaml/to_yaml/to_nice_yaml: OMap/List unwrap,
// YAML/JSON re-box, cyclic-input depth caps, and *OMap insertion-order
// preservation in the emitted documents (a plain map[string]any would
// sort keys and silently reorder the mappings these filters
// regenerate — see omap.go).
package jinja

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	yaml3 "go.yaml.in/yaml/v3"
)

// ---------------- to_json ----------------

// toJSON renders v as a JSON document. *OMap insertion order is
// preserved — routing through map[string]any + encoding/json would
// sort the keys and silently reorder the mappings the ansible-
// derived templates regenerate.
func toJSON(v any) ([]byte, error) {
	steps := 0
	return jsonValueAt(v, 0, &steps)
}

// jsonValueAt walks under the walkMaxDepth recursion budget AND the
// walkMaxSteps total-step budget — a cyclic value can't be marshaled
// anyway, so past the depth cap a "[...]" string placeholder stands
// in (marshal-safe), while an exponentially BRANCHING structure (a
// list holding two copies of itself) stays shallow and instead burns
// the shared step budget, which errors.
func jsonValueAt(v any, depth int, steps *int) ([]byte, error) {
	if depth > walkMaxDepth {
		return []byte(`"[...]"`), nil
	}
	if stepBudgetExhausted(steps) {
		return nil, fmt.Errorf("json: value walk exceeds %d steps (exponentially branching value?)", walkMaxSteps)
	}
	switch t := v.(type) {
	case *OMap:
		return jsonObjectAt(t.Keys(), func(k string) any {
			vv, _ := t.Get(k)
			return vv
		}, depth, steps)
	case *List:
		return jsonListAt(t.V, depth, steps)
	case []any:
		return jsonListAt(t, depth, steps)
	case map[string]any:
		// Plain Go maps carry no order — sort keys for deterministic
		// output, same as encoding/json did.
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return jsonObjectAt(keys, func(k string) any { return t[k] }, depth, steps)
	case map[string]string:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return jsonObjectAt(keys, func(k string) any { return t[k] }, depth, steps)
	case Undefined:
		return []byte("null"), nil
	default:
		// Scalars (and non-jinja container types) marshal exactly
		// as encoding/json handled them before — including HTML
		// escaping and json.Marshaler support.
		return json.Marshal(v)
	}
}

// jsonObjectAt emits {"k":v,...} walking keys in the given order.
func jsonObjectAt(keys []string, get func(string) any, depth int, steps *int) ([]byte, error) {
	var sb strings.Builder
	sb.WriteByte('{')
	for i, k := range keys {
		cv, err := jsonValueAt(get(k), depth+1, steps)
		if err != nil {
			return nil, err
		}
		if i > 0 {
			sb.WriteByte(',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		sb.Write(kb)
		sb.WriteByte(':')
		sb.Write(cv)
	}
	sb.WriteByte('}')
	return []byte(sb.String()), nil
}

func jsonListAt(items []any, depth int, steps *int) ([]byte, error) {
	var sb strings.Builder
	sb.WriteByte('[')
	for i, x := range items {
		cv, err := jsonValueAt(x, depth+1, steps)
		if err != nil {
			return nil, err
		}
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.Write(cv)
	}
	sb.WriteByte(']')
	return []byte(sb.String()), nil
}

// ---------------- to_yaml / to_nice_yaml ----------------

// toYAMLNode converts v into a yaml.Node tree for yaml3.Marshal.
// *OMap insertion order survives as MappingNode Content order —
// marshaling a plain map[string]any would sort the keys and
// silently reorder the mappings these filters regenerate.
func toYAMLNode(v any) (*yaml3.Node, error) {
	steps := 0
	return yamlValueAt(v, 0, &steps)
}

// yamlValueAt walks under the same walkMaxDepth / walkMaxSteps
// budgets as jsonValueAt: past the depth cap a "[...]" placeholder
// keeps the document acyclic and marshal-safe, while an
// exponentially branching structure errors the render.
func yamlValueAt(v any, depth int, steps *int) (*yaml3.Node, error) {
	if depth > walkMaxDepth {
		return yamlLeafNode("[...]")
	}
	if stepBudgetExhausted(steps) {
		return nil, fmt.Errorf("yaml: value walk exceeds %d steps (exponentially branching value?)", walkMaxSteps)
	}
	switch t := v.(type) {
	case *OMap:
		return yamlMapNode(t.Keys(), func(k string) any {
			vv, _ := t.Get(k)
			return vv
		}, depth, steps)
	case *List:
		return yamlSeqNode(t.V, depth, steps)
	case []any:
		return yamlSeqNode(t, depth, steps)
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return yamlMapNode(keys, func(k string) any { return t[k] }, depth, steps)
	case map[string]string:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return yamlMapNode(keys, func(k string) any { return t[k] }, depth, steps)
	case Undefined:
		return yamlLeafNode(nil)
	default:
		return yamlLeafNode(v)
	}
}

// yamlMapNode emits a block MappingNode whose Content alternates
// key,value in the given key order.
func yamlMapNode(keys []string, get func(string) any, depth int, steps *int) (*yaml3.Node, error) {
	n := &yaml3.Node{Kind: yaml3.MappingNode, Tag: "!!map"}
	for _, k := range keys {
		kn, err := yamlLeafNode(k)
		if err != nil {
			return nil, err
		}
		vn, err := yamlValueAt(get(k), depth+1, steps)
		if err != nil {
			return nil, err
		}
		n.Content = append(n.Content, kn, vn)
	}
	return n, nil
}

func yamlSeqNode(items []any, depth int, steps *int) (*yaml3.Node, error) {
	n := &yaml3.Node{Kind: yaml3.SequenceNode, Tag: "!!seq"}
	for _, x := range items {
		vn, err := yamlValueAt(x, depth+1, steps)
		if err != nil {
			return nil, err
		}
		n.Content = append(n.Content, vn)
	}
	return n, nil
}

// yamlLeafNode encodes a scalar through yaml's own marshaler and
// re-parses the result into a Node. Going through Encode (rather
// than hand-building a !!str node) preserves the emitter's quoting
// decisions byte-for-byte — YAML 1.1 bool spellings (yes/on/y),
// base-60 floats (1:20), multi-line literals — so to_yaml output is
// identical to the old map round-trip except for key order.
func yamlLeafNode(v any) (*yaml3.Node, error) {
	n := &yaml3.Node{}
	if err := n.Encode(v); err != nil {
		return nil, err
	}
	return n, nil
}

// ---------------- from_json ----------------

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
