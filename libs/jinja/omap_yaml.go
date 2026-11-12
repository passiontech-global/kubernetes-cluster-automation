package jinja

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"

	yaml3 "go.yaml.in/yaml/v3"
)

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
	// One shared step budget for the whole decode — alias
	// re-expansion (billion laughs) multiplies node visits without
	// adding depth, so only a total counter catches it.
	steps := 0
	for {
		var extra yaml3.Node
		switch err := dec.Decode(&extra); err {
		case nil:
			v, verr := yamlNodeToValue(&extra, &steps)
			if verr != nil {
				return nil, verr
			}
			if v != nil {
				return nil, errors.New("unexpected second yaml document")
			}
			// nil-decoding doc (bare `---`) — keep scanning.
		case io.EOF:
			return yamlNodeToValue(&node, &steps)
		default:
			return nil, err
		}
	}
}

// isDecimalInt reports whether s is an optionally-signed run of
// ASCII digits — used to re-classify yaml.v3's !!float-tagged
// leading-zero decimals ("08", "09") as the ints they are.
func isDecimalInt(s string) bool {
	i := 0
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		i++
	}
	if i == len(s) {
		return false
	}
	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// yamlMaxDepth bounds yamlNodeToValue — a recursive anchor
// (&x {self: *x}) links the node graph into a cycle that would
// otherwise recurse until the stack burst.
const yamlMaxDepth = 100

func yamlNodeToValue(n *yaml3.Node, steps *int) (any, error) {
	return yamlNodeAt(n, 0, steps)
}

func yamlNodeAt(n *yaml3.Node, depth int, steps *int) (any, error) {
	if n == nil {
		return nil, nil
	}
	if depth > yamlMaxDepth {
		return nil, fmt.Errorf("yaml: nesting exceeds %d levels (anchor cycle?)", yamlMaxDepth)
	}
	if stepBudgetExhausted(steps) {
		// Depth alone can't catch billion-laughs: every alias
		// re-walks its target, multiplying visits per level while
		// staying shallow. The shared counter errors the decode.
		return nil, fmt.Errorf("yaml: decode exceeds %d node steps (billion-laughs alias expansion?)", walkMaxSteps)
	}
	if n.Kind == yaml3.DocumentNode {
		if len(n.Content) == 0 {
			return nil, nil
		}
		return yamlNodeAt(n.Content[0], depth+1, steps)
	}
	switch n.Kind {
	case yaml3.MappingNode:
		m := NewOMapCap(len(n.Content) / 2)
		// Pass 1 (only when a merge key exists): collect every
		// EXPLICIT (non-merge) key so merge sources can skip them
		// no matter where `<<` sits in the document — an explicit
		// key always wins over a merged one. 99% of mappings carry
		// no `<<` at all, so a cheap pre-scan skips the explicit-set
		// alloc entirely on the common path (a nil map reads as
		// empty anyway, and yamlMergeInto is unreachable without a
		// merge key).
		hasMerge := false
		for i := 0; i+1 < len(n.Content); i += 2 {
			if isYAMLMergeKey(n.Content[i]) {
				hasMerge = true
				break
			}
		}
		var explicit map[string]bool
		if hasMerge {
			explicit = make(map[string]bool, len(n.Content)/2)
			for i := 0; i+1 < len(n.Content); i += 2 {
				if !isYAMLMergeKey(n.Content[i]) {
					explicit[n.Content[i].Value] = true
				}
			}
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			kn, vn := n.Content[i], n.Content[i+1]
			if isYAMLMergeKey(kn) {
				if err := yamlMergeInto(m, vn, explicit, depth+1, steps); err != nil {
					return nil, err
				}
				continue
			}
			v, err := yamlNodeAt(vn, depth+1, steps)
			if err != nil {
				return nil, err
			}
			m.Set(kn.Value, v)
		}
		return m, nil
	case yaml3.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := yamlNodeAt(c, depth+1, steps)
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
			// "08"/"09": base-0 reads the leading 0 as octal and
			// rejects them; YAML ints are decimal, so retry base-10
			// before degrading to the raw string.
			if i, err := strconv.ParseInt(n.Value, 10, 64); err == nil {
				return i, nil
			}
			return n.Value, nil
		case "!!float":
			if f, err := strconv.ParseFloat(n.Value, 64); err == nil {
				// yaml.v3 tags leading-zero decimals like "08"/"09"
				// as !!float (they match no YAML 1.1 int pattern) —
				// a digits-only scalar is an int in every practical
				// sense; keep it int64. "1.0"/"1e3" keep float.
				if isDecimalInt(n.Value) {
					if i, ierr := strconv.ParseInt(n.Value, 10, 64); ierr == nil {
						return i, nil
					}
				}
				return f, nil
			}
			return n.Value, nil
		case "!!bool":
			return n.Value == "true" || n.Value == "True" || n.Value == "TRUE", nil
		case "!!null":
			// Every YAML null spelling (~, null, Null, NULL, empty)
			// is nil — returning n.Value leaked the literal "Null"
			// string into templates.
			return nil, nil
		case "":
			if n.Value == "" || n.Value == "null" || n.Value == "~" {
				return nil, nil
			}
			return n.Value, nil
		default:
			return n.Value, nil
		}
	case yaml3.AliasNode:
		return yamlNodeAt(n.Alias, depth+1, steps)
	default:
		return nil, fmt.Errorf("unsupported yaml node kind %v", n.Kind)
	}
}

// isYAMLMergeKey reports whether kn is a `<<` merge key. yaml.v3 tags
// the unquoted form !!merge; a PLAIN (unquoted, untagged) scalar whose
// value is "<<" is the same key. A QUOTED "<<" (DoubleQuotedStyle /
// SingleQuotedStyle) is a literal string key, NOT a merge — checking
// Kind+Style keeps `"<<": 1` in a vars file from silently splicing.
func isYAMLMergeKey(kn *yaml3.Node) bool {
	if kn == nil || kn.Kind != yaml3.ScalarNode {
		return false
	}
	return kn.Tag == "!!merge" || (kn.Style == 0 && kn.Value == "<<")
}

// yamlMergeInto splices the mapping(s) referenced by a `<<` value
// into m. The value is an alias to a mapping (single merge) or a
// sequence of such aliases (multi-merge, earlier sources win per the
// YAML spec). Keys already explicit in the enclosing mapping — or
// already merged from an earlier source — are skipped.
func yamlMergeInto(m *OMap, n *yaml3.Node, explicit map[string]bool, depth int, steps *int) error {
	switch n.Kind {
	case yaml3.AliasNode, yaml3.MappingNode:
		v, err := yamlNodeAt(n, depth, steps)
		if err != nil {
			return err
		}
		om, ok := v.(*OMap)
		if !ok || om == nil {
			return errors.New("yaml: merge source is not a mapping")
		}
		for _, k := range om.Keys() {
			if explicit[k] {
				continue
			}
			if _, dup := m.Get(k); dup {
				continue
			}
			vv, _ := om.Get(k)
			m.Set(k, vv)
		}
		return nil
	case yaml3.SequenceNode:
		for _, c := range n.Content {
			if err := yamlMergeInto(m, c, explicit, depth, steps); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("yaml: unsupported merge source kind %v", n.Kind)
}
