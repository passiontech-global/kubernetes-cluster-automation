// Ordered map + YAML decoding helpers.
//
// The ansible sources iterate registries and dicts in FILE order
// (interdc_nodes.yaml is regenerated with to_nice_yaml — insertion
// order is meaningful for the derived probe/target lists which are
// NOT all sorted). Go's map[string]any loses that order, so every
// YAML mapping is decoded into *OMap which keeps key order while
// still offering map semantics to the jinja evaluator.
package jinja

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"

	yaml3 "go.yaml.in/yaml/v3"
)

// OMap is an insertion-ordered string-keyed map.
type OMap struct {
	keys []string
	vals map[string]any
}

func NewOMap() *OMap { return &OMap{vals: map[string]any{}} }

// NewOMapCap is NewOMap with both storages pre-sized — the hot
// decode/render paths that know the entry count up front (YAML
// mappings, from_json objects, dict literals, the for-loop var
// OMap, dict2items/items2dict) skip the grow-realloc chain.
func NewOMapCap(n int) *OMap {
	return &OMap{keys: make([]string, 0, n), vals: make(map[string]any, n)}
}

// Keys returns the ordered key slice (live — do not mutate).
func (m *OMap) Keys() []string {
	if m == nil {
		return nil
	}
	return m.keys
}

func (m *OMap) Len() int {
	if m == nil {
		return 0
	}
	return len(m.keys)
}

// Get returns (value, present).
func (m *OMap) Get(k string) (any, bool) {
	if m == nil {
		return nil, false
	}
	v, ok := m.vals[k]
	return v, ok
}

// Set inserts or replaces, preserving first-insert order. A typed-nil
// *OMap has no storage — Set is a no-op rather than a panic (same
// nil-safety contract as the typed getters below).
func (m *OMap) Set(k string, v any) {
	if m == nil {
		return
	}
	if m.vals == nil {
		// &OMap{} literals carry no storage — lazily allocate so a
		// zero-value OMap behaves like NewOMap (the typed getters
		// are already nil-map safe; Set must be too).
		m.vals = map[string]any{}
	}
	if _, ok := m.vals[k]; !ok {
		m.keys = append(m.keys, k)
	}
	m.vals[k] = v
}

// Del removes a key (keeps order of the rest).
func (m *OMap) Del(k string) {
	if m == nil {
		return
	}
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

// --- typed getters ---
//
// Every consumer of an *OMap grew the same private accessor family
// over Get (mapStr/mapBool in topology, omStr/omList/jstrMap in
// nebulasign, omBool/strOf/strMap in hubsync, strOf in hostconfig).
// These typed getters are that family's single home, so a read site
// becomes om.Str("ip") instead of a three-line switch. All are
// nil-receiver safe: a missing registry entry type-asserts to a nil
// *OMap, and a typed nil must answer like an empty map, not panic.
// A missing key and a stored nil are deliberately indistinguishable
// here — every coercion below maps both to the same zero.

// Str returns the value at k in scalar string form. Missing key, nil,
// Undefined, or any container → "". Scalars: string verbatim, ints
// decimal, floats 'f'-formatted, bool "true"/"" — the YAML/registry
// spellings, NOT jinja's python-style Stringify ("True"/"None"/
// container repr). One exception to "container → ”": a CONCRETE
// typed slice (Go []string stored via Set) coerces element-wise and
// joins with ',' — its elements already ARE the scalar form, unlike
// a decoded []any which Str never repr-prints.
func (m *OMap) Str(k string) string {
	if m == nil {
		return ""
	}
	return scalarStr(m.vals[k])
}

// scalarStr coerces one jinja value to the scalar string form the
// registry helpers expect. Shared by Str and StrMap.
func scalarStr(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case Undefined:
		// Undefined reads like a missing key ("", not the repr
		// Undefined's String() would print) — Str's contract already
		// promises this, but the value arrived via a concrete case
		// only after the container cases ran.
		return ""
	case string:
		return t
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "true"
		}
		return ""
	case []any, *List, *OMap, map[string]any, map[string]string:
		return ""
	case []byte:
		// A byte slice is a byte string, not a list of scalars —
		// element-wise treatment would print "110,111" for "no".
		return string(t)
	case []string:
		// Fast path ahead of the reflect fallback: a Go-native
		// string slice coerces element-wise like []any (','-joined)
		// but its elements are already scalar — no per-element
		// scalarStr call needed. map[string]string needs no twin:
		// it stays a container in the "" group above.
		return strings.Join(t, ",")
	}
	// Integer types beyond int64 (int, int32, uint, ...) stringify
	// decimal BEFORE the reflect walk — an int can never have
	// Slice/Map kind, so checking them first costs nothing and
	// spares the common Go-native-int case the reflection.
	if i, ok := asInt64(v); ok {
		return strconv.FormatInt(i, 10)
	}
	if u, ok := asUint64(v); ok {
		return strconv.FormatUint(u, 10)
	}
	// ONE reflect.ValueOf feeds both container probes — the
	// previous code called it once for Slice and again for Map.
	if rv := reflect.ValueOf(v); rv.Kind() == reflect.Slice {
		// Concrete typed slices ([]int, []MyType, …) used to fall
		// through to fmt.Sprint's "[a b]" repr. Coerce element-wise —
		// the same scalar treatment []any elements get — joined
		// with ',' like the registry list spellings (join(',')).
		parts := make([]string, rv.Len())
		for i := range parts {
			parts[i] = scalarStr(rv.Index(i).Interface())
		}
		return strings.Join(parts, ",")
	} else if rv.Kind() == reflect.Map {
		// Any other map shape (map[string]int, map[int]string, …)
		// has no faithful scalar form: keys would be lost, values
		// mis-keyed — drop to "" like the container cases above.
		return ""
	}
	return fmt.Sprint(v)
}

// Bool reports Truthy(value at k); missing/nil/undefined → false.
func (m *OMap) Bool(k string) bool {
	if m == nil {
		return false
	}
	return Truthy(m.vals[k])
}

// BoolDef coerces the ansible/YAML truthy SCALAR spellings —
// true/yes/1/on and false/no/0/off, case-insensitive, whitespace-
// trimmed (a quoted YAML `True` decodes as a string, not a bool) —
// with bool and int64 handled directly, non-zero float64/float32
// true (NaN excluded: NaN != 0 is TRUE in Go and must not leak
// through as truthy), and every other Go integer width via
// asInt64/asUint64 (contexts feed plain Go ints, not just int64).
// Anything unrecognized, missing, or nil → def. This is NOT jinja's
// Truthy: an unrecognized non-empty string ("maybe") falls back to
// def instead of truthing.
func (m *OMap) BoolDef(k string, def bool) bool {
	if m == nil {
		return def
	}
	v := m.vals[k]
	switch t := v.(type) {
	case bool:
		return t
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "true", "yes", "1", "on":
			return true
		case "false", "no", "0", "off":
			return false
		}
	case int64:
		return t != 0
	case float64:
		return !math.IsNaN(t) && t != 0
	case float32:
		return !math.IsNaN(float64(t)) && t != 0
	}
	if i, ok := asInt64(v); ok {
		return i != 0
	}
	if u, ok := asUint64(v); ok {
		return u != 0
	}
	return def
}

// Int returns ToInt(value at k) — ints verbatim, bools 0/1, numeric
// strings base-10, in-range floats truncated; missing or
// unconvertible → 0.
func (m *OMap) Int(k string) int64 {
	if m == nil {
		return 0
	}
	i, _ := ToInt(m.vals[k])
	return i
}

// Slice returns the raw sequence at k: []any as stored, *List
// unwrapped. Missing or non-sequence → nil. The slice is LIVE, like
// Keys — appending mutates the stored value.
func (m *OMap) Slice(k string) []any {
	if m == nil {
		return nil
	}
	switch t := m.vals[k].(type) {
	case []any:
		return t
	case *List:
		if t == nil {
			return nil
		}
		return t.V
	}
	return nil
}

// StrMap flattens the *OMap stored at k into a plain string map,
// coercing each value like Str (the nested-registry-mapping case).
// Missing, nil, or non-OMap → an empty NON-nil map, so the result is
// always lookup-safe without a nil check at the call site.
func (m *OMap) StrMap(k string) map[string]string {
	out := map[string]string{}
	if m == nil {
		return out
	}
	om, ok := m.vals[k].(*OMap)
	if !ok || om == nil {
		return out
	}
	for _, kk := range om.Keys() {
		out[kk] = scalarStr(om.vals[kk])
	}
	return out
}

// omFromStringMap boxes a plain Go string map into an *OMap with
// sorted keys — dict2items needs the OMap item shape, and Go's
// random map order would make the output nondeterministic.
func omFromStringMap[V any](m map[string]V) *OMap {
	// slices.Sorted(maps.Keys) — the collect-then-sort.Strings dance
	// every map-key walk used to spell out by hand.
	keys := slices.Sorted(maps.Keys(m))
	om := NewOMapCap(len(m))
	for _, k := range keys {
		om.Set(k, m[k])
	}
	return om
}

// Items returns ordered [key,value] pairs (jinja dict2items shape).
func (m *OMap) Items() []any {
	if m == nil {
		return nil
	}
	out := make([]any, 0, len(m.keys))
	for _, k := range m.keys {
		p := NewOMapCap(2)
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
