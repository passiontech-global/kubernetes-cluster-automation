// Ordered map + YAML decoding helpers.
//
// The ansible sources iterate registries and dicts in FILE order
// (interdc_nodes.yaml is regenerated with to_nice_yaml — insertion
// order is meaningful for the derived probe/target lists which are
// NOT all sorted). Go's map[string]any loses that order, so every
// YAML mapping is decoded into *OMap which keeps key order while
// still offering map semantics to the jinja evaluator.
package topology

import (
	"bytes"
	"fmt"
	"io"
	"strconv"

	yaml3 "go.yaml.in/yaml/v3"
)

// OMap is an insertion-ordered string-keyed map.
type OMap struct {
	keys []string
	vals map[string]any
}

func NewOMap() *OMap { return &OMap{vals: map[string]any{}} }

// Keys returns the ordered key slice (live — do not mutate).
func (m *OMap) Keys() []string { return m.keys }

func (m *OMap) Len() int { return len(m.keys) }

// Get returns (value, present).
func (m *OMap) Get(k string) (any, bool) {
	v, ok := m.vals[k]
	return v, ok
}

// Set inserts or replaces, preserving first-insert order.
func (m *OMap) Set(k string, v any) {
	if _, ok := m.vals[k]; !ok {
		m.keys = append(m.keys, k)
	}
	m.vals[k] = v
}

// Del removes a key (keeps order of the rest).
func (m *OMap) Del(k string) {
	if _, ok := m.vals[k]; !ok {
		return
	}
	delete(m.vals, k)
	for i, kk := range m.keys {
		if kk == k {
			m.keys = append(m.keys[:i], m.keys[i+1:]...)
			return
		}
	}
}

// Items returns ordered [key,value] pairs (jinja dict2items shape).
func (m *OMap) Items() []any {
	out := make([]any, 0, len(m.keys))
	for _, k := range m.keys {
		p := NewOMap()
		p.Set("key", k)
		p.Set("value", m.vals[k])
		out = append(out, p)
	}
	return out
}

// DecodeYAML parses a YAML document into jinja values: mappings →
// *OMap (ordered), sequences → []any, ints stay int64. The vars
// files are single-document — extra documents that decode to real
// values error rather than being silently dropped (half-loaded
// vars, no error); ones decoding to nil (a trailing bare `---`
// separator) are legal YAML and accepted.
func DecodeYAML(data []byte) (any, error) {
	var node yaml3.Node
	dec := yaml3.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&node); err != nil {
		return nil, err
	}
	for {
		var extra yaml3.Node
		switch err := dec.Decode(&extra); err {
		case nil:
			v, verr := yamlNodeToValue(&extra)
			if verr != nil {
				return nil, verr
			}
			if v != nil {
				return nil, fmt.Errorf("unexpected second yaml document")
			}
			// nil-decoding doc (bare `---`) — keep scanning.
		case io.EOF:
			return yamlNodeToValue(&node)
		default:
			return nil, err
		}
	}
}

// yamlMaxDepth bounds yamlNodeToValue — a recursive anchor
// (&x {self: *x}) links the node graph into a cycle that would
// otherwise recurse until the stack burst.
const yamlMaxDepth = 100

func yamlNodeToValue(n *yaml3.Node) (any, error) { return yamlNodeAt(n, 0) }

func yamlNodeAt(n *yaml3.Node, depth int) (any, error) {
	if n == nil {
		return nil, nil
	}
	if depth > yamlMaxDepth {
		return nil, fmt.Errorf("yaml: nesting exceeds %d levels (anchor cycle?)", yamlMaxDepth)
	}
	if n.Kind == yaml3.DocumentNode {
		if len(n.Content) == 0 {
			return nil, nil
		}
		return yamlNodeAt(n.Content[0], depth+1)
	}
	switch n.Kind {
	case yaml3.MappingNode:
		m := NewOMap()
		for i := 0; i+1 < len(n.Content); i += 2 {
			kn, vn := n.Content[i], n.Content[i+1]
			v, err := yamlNodeAt(vn, depth+1)
			if err != nil {
				return nil, err
			}
			m.Set(kn.Value, v)
		}
		return m, nil
	case yaml3.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := yamlNodeAt(c, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml3.ScalarNode:
		switch n.Tag {
		case "!!int":
			if i, err := strconv.ParseInt(n.Value, 0, 64); err == nil {
				return i, nil
			}
			return n.Value, nil
		case "!!float":
			if f, err := strconv.ParseFloat(n.Value, 64); err == nil {
				return f, nil
			}
			return n.Value, nil
		case "!!bool":
			return n.Value == "true" || n.Value == "True" || n.Value == "TRUE", nil
		case "!!null", "":
			if n.Value == "" || n.Value == "null" || n.Value == "~" {
				return nil, nil
			}
			return n.Value, nil
		default:
			return n.Value, nil
		}
	case yaml3.AliasNode:
		return yamlNodeAt(n.Alias, depth+1)
	default:
		return nil, fmt.Errorf("unsupported yaml node kind %v", n.Kind)
	}
}
