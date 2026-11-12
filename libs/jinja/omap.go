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
	"fmt"
	"maps"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
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
