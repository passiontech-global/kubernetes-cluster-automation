// convert.go — jinja-value → marshal-ready conversions feeding
// to_json/from_json/from_yaml/to_yaml/to_nice_yaml: OMap/List unwrap,
// YAML/JSON re-box, cyclic-input depth caps, and *OMap insertion-order
// preservation in the emitted documents (a plain map[string]any would
// sort keys and silently reorder the mappings these filters
// regenerate — see omap.go).
package jinja

import (
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
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
	// The step budget runs BEFORE the depth early-out: a wide
	// structure sitting exactly at the depth cap would otherwise
	// spawn unbounded "[...]" leaf encodes that never consume
	// budget — every recursive call must burn a step.
	if stepBudgetExhausted(steps) {
		return nil, fmt.Errorf("yaml: value walk exceeds %d steps (exponentially branching value?)", walkMaxSteps)
	}
	if depth > walkMaxDepth {
		// Build the elision leaf directly. yamlLeafNode would run a
		// full yaml Encode + re-parse for EVERY branch that sits at
		// the depth cap — a branching cycle (l.V=[l,l]) hits those
		// leaves ~walkMaxSteps times and spent 3–10s under -race.
		// This marker is a static scalar; no emitter round-trip is
		// needed for a value that is always exactly "[...]".
		return &yaml3.Node{
			Kind:  yaml3.ScalarNode,
			Tag:   "!!str",
			Value: "[...]",
		}, nil
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
	case []string:
		items := make([]any, len(t))
		for i, x := range t {
			items[i] = x
		}
		return yamlSeqNode(items, depth, steps)
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

// fromJSONMaxDepth bounds JSON container nesting so a hostile
// deeply nested document fails before overflowing the Go call stack.
const fromJSONMaxDepth = 64

// decodeJSON parses raw JSON directly into jinja values (*OMap in
// document key order, *List, int64/uint64/float64, bool, string, nil)
// via jsontext.NewDecoder, tolerating invalid UTF-8 and duplicate
// object keys (last-write-wins at first-insert position via OMap.Set).
func decodeJSON(raw string) (any, error) {
	dec := jsontext.NewDecoder(
		strings.NewReader(raw),
		jsontext.AllowInvalidUTF8(true),
		jsontext.AllowDuplicateNames(true),
	)
	v, err := decodeJSONValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.ReadToken(); err != io.EOF {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("from_json: unexpected trailing data")
	}
	return v, nil
}

func decodeJSONValue(dec *jsontext.Decoder, depth int) (any, error) {
	if depth > fromJSONMaxDepth {
		return nil, fmt.Errorf("from_json: document nests past %d levels", fromJSONMaxDepth)
	}
	tok, err := dec.ReadToken()
	if err != nil {
		return nil, err
	}
	switch tok.Kind() {
	case 'n':
		return nil, nil
	case 't', 'f':
		return tok.Bool(), nil
	case '"':
		return tok.String(), nil
	case '0':
		if i, err := tok.Int(); err == nil {
			return i, nil
		}
		if u, err := tok.Uint(); err == nil {
			return u, nil
		}
		f, err := tok.Float()
		if err != nil {
			return nil, err
		}
		return f, nil
	case '{':
		m := NewOMap()
		for dec.PeekKind() != '}' {
			ktok, err := dec.ReadToken()
			if err != nil {
				return nil, err
			}
			if ktok.Kind() != '"' {
				return nil, fmt.Errorf("from_json: expected object key string, got %v", ktok.Kind())
			}
			k := ktok.String()
			val, err := decodeJSONValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			m.Set(k, val)
		}
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		return m, nil
	case '[':
		var out []any
		for dec.PeekKind() != ']' {
			elem, err := decodeJSONValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, elem)
		}
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		return &List{out}, nil
	default:
		return nil, fmt.Errorf("from_json: unexpected token %v", tok.Kind())
	}
}
