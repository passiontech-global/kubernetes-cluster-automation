// convert.go — jinja-value → marshal-ready conversions feeding
// to_json/from_json/from_yaml/to_yaml/to_nice_yaml: OMap/List unwrap,
// YAML/JSON re-box, cyclic-input depth caps, and *OMap insertion-order
// preservation in the emitted documents (a plain map[string]any would
// sort keys and silently reorder the mappings these filters
// regenerate — see omap.go).
package jinja

import (
	"encoding/base64"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

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

var errYAMLSizeCap = errors.New("to_yaml: output size cap exceeded")

type yamlLimitWriter struct {
	b        strings.Builder
	max      int
	overflow bool
}

func (w *yamlLimitWriter) Write(p []byte) (int, error) {
	if w.b.Len()+len(p) > w.max {
		w.overflow = true
		return 0, errYAMLSizeCap
	}
	return w.b.Write(p)
}

// toYAMLNode converts v into a yaml.Node tree for yaml3.Marshal.
// *OMap insertion order survives as MappingNode Content order —
// marshaling a plain map[string]any would sort the keys and
// silently reorder the mappings these filters regenerate.
func toYAMLNode(v any) (*yaml3.Node, error) {
	steps := 0
	bytes := 1 // document trailing '\n'
	return yamlValueBudgetAt(v, 0, &steps, &bytes)
}

// yamlValueAt walks under the same walkMaxDepth / walkMaxSteps
// budgets as jsonValueAt: past the depth cap a "[...]" placeholder
// keeps the document acyclic and marshal-safe, while an
// exponentially branching structure errors the render.
func yamlValueAt(v any, depth int, steps *int) (*yaml3.Node, error) {
	bytes := 1
	return yamlValueBudgetAt(v, depth, steps, &bytes)
}

func addYAMLBudget(bytes *int, n int) error {
	if bytes == nil || n <= 0 {
		return nil
	}
	if n > maxStringBytes || *bytes > maxStringBytes-n {
		return fmt.Errorf("to_yaml: output exceeds %d bytes", maxStringBytes)
	}
	*bytes += n
	return nil
}

func yamlValueBudgetAt(v any, depth int, steps, bytes *int) (*yaml3.Node, error) {
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
		if err := addYAMLBudget(bytes, len("[...]")); err != nil {
			return nil, err
		}
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
		}, depth, steps, bytes)
	case *List:
		if t == nil {
			return yamlSeqNode(nil, depth, steps, bytes)
		}
		return yamlSeqNode(t.V, depth, steps, bytes)
	case []any:
		return yamlSeqNode(t, depth, steps, bytes)
	case []string:
		return yamlSeqNodeN(len(t), func(i int) any { return t[i] }, depth, steps, bytes)
	case map[string]any:
		if steps != nil && len(t) > walkMaxSteps-*steps {
			return nil, fmt.Errorf("yaml: value walk exceeds %d steps (exponentially branching value?)", walkMaxSteps)
		}
		return yamlMapNode(slices.Sorted(maps.Keys(t)), func(k string) any { return t[k] }, depth, steps, bytes)
	case map[string]string:
		if steps != nil && len(t) > walkMaxSteps-*steps {
			return nil, fmt.Errorf("yaml: value walk exceeds %d steps (exponentially branching value?)", walkMaxSteps)
		}
		return yamlMapNode(slices.Sorted(maps.Keys(t)), func(k string) any { return t[k] }, depth, steps, bytes)
	case Undefined:
		return yamlLeafNodeBudget(nil, bytes)
	default:
		return yamlLeafNodeBudget(v, bytes)
	}
}

// yamlMapNode emits a block MappingNode whose Content alternates
// key,value in the given key order.
func yamlMapNode(keys []string, get func(string) any, depth int, steps, bytes *int) (*yaml3.Node, error) {
	if len(keys) == 0 {
		if err := addYAMLBudget(bytes, 2); err != nil {
			return nil, err
		}
		return &yaml3.Node{Kind: yaml3.MappingNode, Tag: "!!map"}, nil
	}
	n := &yaml3.Node{
		Kind:    yaml3.MappingNode,
		Tag:     "!!map",
		Content: make([]*yaml3.Node, 0, min(len(keys), 1024)*2),
	}
	for i, k := range keys {
		if i > 0 {
			if err := addYAMLBudget(bytes, 1); err != nil {
				return nil, err
			}
		}
		if err := addYAMLBudget(bytes, 2); err != nil {
			return nil, err
		}
		kn, err := yamlStringNode(k, bytes)
		if err != nil {
			return nil, err
		}
		vn, err := yamlValueBudgetAt(get(k), depth+1, steps, bytes)
		if err != nil {
			return nil, err
		}
		n.Content = append(n.Content, kn, vn)
	}
	return n, nil
}

func yamlSeqNode(items []any, depth int, steps, bytes *int) (*yaml3.Node, error) {
	return yamlSeqNodeN(len(items), func(i int) any { return items[i] }, depth, steps, bytes)
}

func yamlSeqNodeN(count int, at func(int) any, depth int, steps, bytes *int) (*yaml3.Node, error) {
	if count == 0 {
		if err := addYAMLBudget(bytes, 2); err != nil {
			return nil, err
		}
		return &yaml3.Node{Kind: yaml3.SequenceNode, Tag: "!!seq"}, nil
	}
	n := &yaml3.Node{
		Kind:    yaml3.SequenceNode,
		Tag:     "!!seq",
		Content: make([]*yaml3.Node, 0, min(count, 1024)),
	}
	for i := range count {
		if i > 0 {
			if err := addYAMLBudget(bytes, 1); err != nil {
				return nil, err
			}
		}
		if err := addYAMLBudget(bytes, 2); err != nil {
			return nil, err
		}
		vn, err := yamlValueBudgetAt(at(i), depth+1, steps, bytes)
		if err != nil {
			return nil, err
		}
		n.Content = append(n.Content, vn)
	}
	return n, nil
}

// base60FloatRe matches YAML 1.1 base-60 floats (mirrors yaml/v3's encode.go).
var base60FloatRe = regexp.MustCompile(`^[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+(?:\.[0-9_]*)?$`)

func isYAMLBase60Float(s string) bool {
	if s == "" {
		return false
	}
	c := s[0]
	if !(c == '+' || c == '-' || c >= '0' && c <= '9') || strings.IndexByte(s, ':') < 0 {
		return false
	}
	return base60FloatRe.MatchString(s)
}

func isYAML11OldBool(s string) bool {
	switch s {
	case "y", "Y", "yes", "Yes", "YES", "on", "On", "ON",
		"n", "N", "no", "No", "NO", "off", "Off", "OFF":
		return true
	default:
		return false
	}
}

func yamlStringNode(s string, bytes *int) (*yaml3.Node, error) {
	if !utf8.ValidString(s) {
		encLen := base64.StdEncoding.EncodedLen(len(s))
		if err := addYAMLBudget(bytes, encLen); err != nil {
			return nil, err
		}
		n := &yaml3.Node{}
		n.SetString(s)
		return n, nil
	}
	minBytes := len(s)
	if minBytes == 0 {
		minBytes = 2 // ""
	}
	if err := addYAMLBudget(bytes, minBytes); err != nil {
		return nil, err
	}
	var style yaml3.Style
	if strings.Contains(s, "\n") {
		style = yaml3.LiteralStyle
	} else if isYAML11OldBool(s) || isYAMLBase60Float(s) {
		style = yaml3.DoubleQuotedStyle
	}
	return &yaml3.Node{
		Kind:  yaml3.ScalarNode,
		Tag:   "!!str",
		Value: s,
		Style: style,
	}, nil
}

func yamlIntNode(v int64, bytes *int) (*yaml3.Node, error) {
	s := strconv.FormatInt(v, 10)
	if err := addYAMLBudget(bytes, len(s)); err != nil {
		return nil, err
	}
	return &yaml3.Node{
		Kind:  yaml3.ScalarNode,
		Tag:   "!!int",
		Value: s,
	}, nil
}

func yamlUintNode(v uint64, bytes *int) (*yaml3.Node, error) {
	s := strconv.FormatUint(v, 10)
	if err := addYAMLBudget(bytes, len(s)); err != nil {
		return nil, err
	}
	return &yaml3.Node{
		Kind:  yaml3.ScalarNode,
		Tag:   "!!int",
		Value: s,
	}, nil
}

func yamlFloatNode(v float64, precision int, bytes *int) (*yaml3.Node, error) {
	s := strconv.FormatFloat(v, 'g', -1, precision)
	switch s {
	case "+Inf":
		s = ".inf"
	case "-Inf":
		s = "-.inf"
	case "NaN":
		s = ".nan"
	}
	if err := addYAMLBudget(bytes, len(s)); err != nil {
		return nil, err
	}
	// Leave Tag empty so integral floats (e.g. 1.0 -> "1") emit without
	// an explicit !!float tag, matching yaml3.Marshal / Node.Encode.
	return &yaml3.Node{
		Kind:  yaml3.ScalarNode,
		Value: s,
	}, nil
}

// yamlLeafNodeBudget constructs a *yaml3.Node for a scalar leaf without a
// full marshal+re-parse round-trip for common Go types, while
// preserving YAML 1.1 quoting parity and enforcing maxStringBytes.
func yamlLeafNodeBudget(v any, bytes *int) (*yaml3.Node, error) {
	switch t := v.(type) {
	case nil:
		if err := addYAMLBudget(bytes, len("null")); err != nil {
			return nil, err
		}
		return &yaml3.Node{
			Kind:  yaml3.ScalarNode,
			Tag:   "!!null",
			Value: "null",
		}, nil
	case string:
		return yamlStringNode(t, bytes)
	case bool:
		s := "false"
		if t {
			s = "true"
		}
		if err := addYAMLBudget(bytes, len(s)); err != nil {
			return nil, err
		}
		return &yaml3.Node{
			Kind:  yaml3.ScalarNode,
			Tag:   "!!bool",
			Value: s,
		}, nil
	case int:
		return yamlIntNode(int64(t), bytes)
	case int8:
		return yamlIntNode(int64(t), bytes)
	case int16:
		return yamlIntNode(int64(t), bytes)
	case int32:
		return yamlIntNode(int64(t), bytes)
	case int64:
		return yamlIntNode(t, bytes)
	case uint:
		return yamlUintNode(uint64(t), bytes)
	case uint8:
		return yamlUintNode(uint64(t), bytes)
	case uint16:
		return yamlUintNode(uint64(t), bytes)
	case uint32:
		return yamlUintNode(uint64(t), bytes)
	case uint64:
		return yamlUintNode(t, bytes)
	case uintptr:
		return yamlUintNode(uint64(t), bytes)
	case float32:
		return yamlFloatNode(float64(t), 32, bytes)
	case float64:
		return yamlFloatNode(t, 64, bytes)
	case time.Time:
		s := t.Format(time.RFC3339Nano)
		if err := addYAMLBudget(bytes, len(s)); err != nil {
			return nil, err
		}
		return &yaml3.Node{
			Kind:  yaml3.ScalarNode,
			Value: s,
		}, nil
	case *time.Time:
		if t == nil {
			return yamlLeafNodeBudget(nil, bytes)
		}
		s := t.Format(time.RFC3339Nano)
		if err := addYAMLBudget(bytes, len(s)); err != nil {
			return nil, err
		}
		return &yaml3.Node{
			Kind:  yaml3.ScalarNode,
			Value: s,
		}, nil
	case time.Duration:
		return yamlStringNode(t.String(), bytes)
	case []byte:
		if len(t) == 0 {
			if err := addYAMLBudget(bytes, 2); err != nil {
				return nil, err
			}
			return &yaml3.Node{Kind: yaml3.SequenceNode, Tag: "!!seq"}, nil
		}
		if len(t) > maxStringBytes/4 {
			return nil, fmt.Errorf("to_yaml: output exceeds %d bytes", maxStringBytes)
		}
	}

	// Bounded fallback for exotic Go types: stream through yamlLimitWriter
	// so oversized structs/slices/marshalers fail without unbounded allocation.
	remaining := maxStringBytes
	if bytes != nil {
		remaining = maxStringBytes - *bytes + 1
	}
	if remaining < 1 {
		return nil, fmt.Errorf("to_yaml: output exceeds %d bytes", maxStringBytes)
	}
	lw := yamlLimitWriter{max: remaining}
	enc := yaml3.NewEncoder(&lw)
	err := enc.Encode(v)
	if err == nil {
		err = enc.Close()
	}
	if lw.overflow {
		return nil, fmt.Errorf("to_yaml: output exceeds %d bytes", maxStringBytes)
	}
	if err != nil {
		return nil, err
	}
	if bytes != nil {
		if err := addYAMLBudget(bytes, max(lw.b.Len()-1, 0)); err != nil {
			return nil, err
		}
	}
	var doc yaml3.Node
	if err := yaml3.Unmarshal([]byte(lw.b.String()), &doc); err != nil {
		return nil, err
	}
	if doc.Kind == yaml3.DocumentNode && len(doc.Content) > 0 {
		return doc.Content[0], nil
	}
	if doc.Kind != 0 {
		return &doc, nil
	}
	return &yaml3.Node{}, nil
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
