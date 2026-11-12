// convert.go — jinja-value → marshal-ready conversions feeding
// to_json/from_json/from_yaml/to_yaml/to_nice_yaml: OMap/List unwrap,
// YAML/JSON re-box, cyclic-input depth caps, and *OMap insertion-order
// preservation in the emitted documents (a plain map[string]any would
// sort keys and silently reorder the mappings these filters
// regenerate — see omap.go).
package jinja

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	yaml3 "go.yaml.in/yaml/v3"
)

// ---------------- to_json ----------------

// toJSON renders v as a JSON document. *OMap insertion order is
// preserved — routing through map[string]any + encoding/json would
// sort the keys and silently reorder the mappings the ansible-
// derived templates regenerate. The document is written straight
// into one strings.Builder by writeJSONAt (stringify.go) instead of
// allocating a []byte per node.
func toJSON(v any) ([]byte, error) {
	var sb strings.Builder
	steps := 0
	if err := writeJSONAt(v, &sb, 0, &steps); err != nil {
		return nil, err
	}
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
		if t == nil {
			return yamlSeqNode(nil, depth, steps)
		}
		return yamlSeqNode(t.V, depth, steps)
	case []any:
		return yamlSeqNode(t, depth, steps)
	case map[string]any:
		return yamlMapNode(slices.Sorted(maps.Keys(t)), func(k string) any { return t[k] }, depth, steps)
	case map[string]string:
		return yamlMapNode(slices.Sorted(maps.Keys(t)), func(k string) any { return t[k] }, depth, steps)
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

// fromJSONMaxDepth bounds the re-boxing walk — json.Unmarshal
// already rejects documents nested past its own limit, but the
// decoded tree still deserves an explicit recursion budget so a
// hostile-but-parseable document can't stack the re-boxer.
const fromJSONMaxDepth = 64

// fromJSONChecked re-boxes a json.Unmarshal tree into OMap/List
// values. Unlike the old silent fromJSON it returns an explicit
// error when the document nests past fromJSONMaxDepth — a truncated
// nil would render as a WRONG value downstream (a vars file quietly
// losing a subtree), which is worse than a loud filter failure.
func fromJSONChecked(v any) (any, error) {
	return fromJSONAt(v, 0)
}

func fromJSONAt(v any, depth int) (any, error) {
	if depth > fromJSONMaxDepth {
		return nil, fmt.Errorf("from_json: document nests past %d levels", fromJSONMaxDepth)
	}
	switch t := v.(type) {
	case map[string]any:
		m := NewOMapCap(len(t))
		for _, k := range slices.Sorted(maps.Keys(t)) {
			cv, err := fromJSONAt(t[k], depth+1)
			if err != nil {
				return nil, err
			}
			m.Set(k, cv)
		}
		return m, nil
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			cv, err := fromJSONAt(x, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = cv
		}
		return &List{out}, nil
	case float64:
		// floatToInt64, not int64(t): NaN/±Inf/out-of-range floats
		// truncate into platform garbage (usually MinInt64).
		if i, ok := floatToInt64(t); ok && t == float64(i) {
			return i, nil
		}
		return t, nil
	default:
		return v, nil
	}
}
