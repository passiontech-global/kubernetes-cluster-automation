// methods.go — attribute/index lookup and bound-method dispatch
// (obj.items(), obj.append(), ...) over the string/list/dict value
// shapes, plus the deep-equality walker and mapping view those
// dispatchers share.
package jinja

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// boundMethod wraps obj.method calls (items/append/endswith/...).
type boundMethod struct {
	obj  any
	name string
}

var methodNames = map[string]bool{
	"items": true, "append": true, "keys": true, "values": true,
	"get": true, "endswith": true, "startswith": true, "split": true,
	"strip": true, "index": true, "pop": true,
}

func getAttr(v any, key string) any {
	switch t := v.(type) {
	case *OMap:
		if val, ok := t.Get(key); ok {
			return val
		}
		if methodNames[key] {
			return boundMethod{v, key}
		}
		return Undefined{key}
	case *List, string:
		if methodNames[key] {
			return boundMethod{v, key}
		}
		return Undefined{key}
	case map[string]any:
		if val, ok := t[key]; ok {
			return val
		}
		if methodNames[key] {
			return boundMethod{v, key}
		}
		return Undefined{key}
	case map[string]string:
		if val, ok := t[key]; ok {
			return val
		}
		if methodNames[key] {
			return boundMethod{v, key}
		}
		return Undefined{key}
	case []any:
		if methodNames[key] {
			return boundMethod{v, key}
		}
		return Undefined{key}
	}
	return Undefined{key}
}

func getIndex(v any, k any) (any, error) {
	switch t := v.(type) {
	case *OMap:
		if val, ok := t.Get(Stringify(k)); ok {
			return val, nil
		}
		return Undefined{Stringify(k)}, nil
	case map[string]any:
		if val, ok := t[Stringify(k)]; ok {
			return val, nil
		}
		return Undefined{Stringify(k)}, nil
	case map[string]string:
		if val, ok := t[Stringify(k)]; ok {
			return val, nil
		}
		return Undefined{Stringify(k)}, nil
	case *List:
		if t == nil {
			return Undefined{"index"}, nil
		}
		return getIndex(t.V, k)
	case []any:
		i, ok := ToInt(k)
		if !ok {
			return nil, fmt.Errorf("non-integer index %v", k)
		}
		if i < 0 {
			i += int64(len(t))
		}
		if i < 0 || i >= int64(len(t)) {
			return Undefined{"index"}, nil
		}
		return t[i], nil
	case string:
		i, ok := ToInt(k)
		if !ok {
			return Undefined{"index"}, nil
		}
		// Same negative-index semantics as the []any branch, in runes.
		runes := []rune(t)
		if i < 0 {
			i += int64(len(runes))
		}
		if i < 0 || i >= int64(len(runes)) {
			return Undefined{"index"}, nil
		}
		return string(runes[i]), nil
	}
	return Undefined{"index"}, nil
}

func callValue(fn any, args []any, kw map[string]any, s *scope) (any, error) {
	if m, ok := fn.(boundMethod); ok {
		return m.call(args, s)
	}
	if name, ok := fn.(builtinFunc); ok {
		return name(args, kw, s)
	}
	return nil, fmt.Errorf("not callable: %v (%T)", fn, fn)
}

type builtinFunc func(args []any, kw map[string]any, s *scope) (any, error)

func (m boundMethod) call(args []any, _ *scope) (any, error) {
	switch m.name {
	case "items":
		// asMapping covers *OMap (insertion order via Keys()) and the
		// plain map shapes DecodeYAML/Go callers produce (sorted keys)
		// — .items() on a map[string]any used to be uncallable.
		if mv, ok := asMapping(m.obj); ok {
			pairs := make([]any, 0, mv.n)
			for _, k := range mv.keys {
				v, _ := mv.get(k)
				pairs = append(pairs, &List{[]any{k, v}})
			}
			return &List{pairs}, nil
		}
	case "append":
		if l, ok := m.obj.(*List); ok && l != nil {
			l.V = append(l.V, args...)
			return nil, nil
		}
	case "keys":
		if mv, ok := asMapping(m.obj); ok {
			out := make([]any, 0, mv.n)
			for _, k := range mv.keys {
				out = append(out, k)
			}
			return &List{out}, nil
		}
	case "values":
		if mv, ok := asMapping(m.obj); ok {
			out := make([]any, 0, mv.n)
			for _, k := range mv.keys {
				v, _ := mv.get(k)
				out = append(out, v)
			}
			return &List{out}, nil
		}
	case "get":
		if isMappingValue(m.obj) {
			if len(args) == 0 {
				return nil, errors.New("get: missing key argument")
			}
			if v, ok := mapLookup(m.obj, Stringify(args[0])); ok {
				return v, nil
			}
			if len(args) > 1 {
				return args[1], nil
			}
			return nil, nil
		}
	case "endswith", "startswith":
		str := Stringify(m.obj)
		if len(args) == 0 {
			return false, nil
		}
		if m.name == "endswith" {
			return strings.HasSuffix(str, Stringify(args[0])), nil
		}
		return strings.HasPrefix(str, Stringify(args[0])), nil
	case "split":
		str := Stringify(m.obj)
		if len(args) == 0 {
			return &List{splitWS(str)}, nil
		}
		return &List{splitAny(str, Stringify(args[0]))}, nil
	case "strip":
		return strings.TrimSpace(Stringify(m.obj)), nil
	case "index":
		if len(args) == 0 {
			return nil, errors.New("index: missing argument")
		}
		for i, it := range ToIter(m.obj) {
			if deepEq(it, args[0]) {
				return int64(i), nil
			}
		}
		return nil, errors.New("index: not found")
	case "pop":
		if l, ok := m.obj.(*List); ok && l != nil {
			if len(l.V) == 0 {
				return nil, errors.New("pop: empty list")
			}
			i := int64(len(l.V)) - 1
			if len(args) > 0 {
				j, ok := ToInt(args[0])
				if !ok {
					return nil, errors.New("pop: index must be an integer")
				}
				i = j
				// python list.pop accepts negative indices.
				if i < 0 {
					i += int64(len(l.V))
				}
			}
			if i < 0 || i >= int64(len(l.V)) {
				return nil, fmt.Errorf("pop: index %d out of range", i)
			}
			v := l.V[i]
			l.V = append(l.V[:i], l.V[i+1:]...)
			return v, nil
		}
	}
	return nil, fmt.Errorf("unknown method %q on %T", m.name, m.obj)
}

func splitWS(s string) []any {
	var out []any
	for f := range strings.FieldsSeq(s) {
		out = append(out, f)
	}
	return out
}

func splitAny(s, sep string) []any {
	parts := strings.Split(s, sep)
	out := make([]any, 0, len(parts))
	for _, p := range parts {
		out = append(out, p)
	}
	return out
}

// ---------------- deep equality ----------------

func deepEq(l, r any) bool {
	steps := 0
	return deepEqAt(l, r, 0, &steps)
}

// deepEqAt is deepEq under the walkMaxDepth recursion budget AND
// the walkMaxSteps total-step budget — cyclic structures can't be
// compared meaningfully and would overflow the stack (the deep
// tail answers false), while a branching cycle doubles the
// comparison work per level without ever deepening; the shared
// counter bails out in bounded time. Identical container pointers
// short-circuit true so `l == l` stays true even for a
// self-referential list.
func deepEqAt(l, r any, depth int, steps *int) bool {
	if depth > walkMaxDepth || stepBudgetExhausted(steps) {
		return false
	}
	switch lt := l.(type) {
	case *List:
		if lt == nil {
			// Typed-nil unwraps to an EMPTY slice — same shape
			// (*OMap)(nil) takes through asMapping — so it compares
			// equal to [] and unequal to None, like python's [].
			l = []any(nil)
		} else {
			if lt == r {
				return true
			}
			l = lt.V
		}
	case *OMap:
		if lt == r {
			return true
		}
	}
	switch rt := r.(type) {
	case *List:
		if rt == nil {
			r = []any(nil)
		} else {
			if rt == l {
				return true
			}
			r = rt.V
		}
	}
	// Mappings compare order-insensitively across *OMap,
	// map[string]any and map[string]string — a vars-file OMap and a
	// Go-native map with the same entries are the same value.
	if lm, lok := asMapping(l); lok {
		// The right side only answers per-key lookups — mapLookup
		// skips the sorted view asMapping would build for it.
		rn, rok := mappingLen(r)
		if !rok || lm.n != rn {
			return false
		}
		for _, k := range lm.keys {
			lv, _ := lm.get(k)
			rv, ok := mapLookup(r, k)
			if !ok || !deepEqAt(lv, rv, depth+1, steps) {
				return false
			}
		}
		return true
	}
	if isMappingValue(r) {
		return false
	}
	switch lt := l.(type) {
	case []any:
		rt, ok := r.([]any)
		if !ok || len(lt) != len(rt) {
			return false
		}
		for i := range lt {
			if !deepEqAt(lt[i], rt[i], depth+1, steps) {
				return false
			}
		}
		return true
	}
	if l == nil || r == nil {
		return IsNilOrUndef(l) && IsNilOrUndef(r)
	}
	if _, ok := l.(Undefined); ok {
		_, uok := r.(Undefined)
		return uok
	}
	return numEq(l, r)
}

// mappingView is the Len/Get surface shared by *OMap, map[string]any
// and map[string]string for order-insensitive deep equality.
type mappingView struct {
	n    int
	keys []string
	get  func(string) (any, bool)
}

// isMappingValue reports whether v is any mapping shape the engine
// understands (*OMap, map[string]any, map[string]string) — used by
// the for-loop unpack guards. A plain type switch: the predicate
// must not build asMapping's sorted-key view just to say "yes".
func isMappingValue(v any) bool {
	switch v.(type) {
	case *OMap, map[string]any, map[string]string:
		return true
	}
	return false
}

// mapLookup resolves one key on any mapping shape WITHOUT the
// sorted-keys view asMapping builds — direct indexing sorts nothing
// and allocates nothing on a hit, so single-key reads (`key in dict`,
// .get(key)) stay O(1) however large the mapping. Typed-nil *OMap
// reads as an empty map (Get is nil-receiver safe), matching
// asMapping. The three shapes are exactly asMapping's.
func mapLookup(v any, key string) (any, bool) {
	switch t := v.(type) {
	case *OMap:
		return t.Get(key)
	case map[string]any:
		x, ok := t[key]
		return x, ok
	case map[string]string:
		x, ok := t[key]
		return x, ok
	}
	return nil, false
}

// mappingLen reports the entry count for any mapping shape — the
// size half of mappingView, without building the sorted-key view.
// False for every non-mapping.
func mappingLen(v any) (int, bool) {
	switch t := v.(type) {
	case *OMap:
		return t.Len(), true
	case map[string]any:
		return len(t), true
	case map[string]string:
		return len(t), true
	}
	return 0, false
}

func asMapping(v any) (mappingView, bool) {
	switch t := v.(type) {
	case *OMap:
		return mappingView{n: t.Len(), keys: t.Keys(), get: t.Get}, true
	case map[string]any:
		keys := slices.Sorted(maps.Keys(t))
		return mappingView{
			n:    len(t),
			keys: keys,
			get: func(k string) (any, bool) {
				x, ok := t[k]
				return x, ok
			},
		}, true
	case map[string]string:
		keys := slices.Sorted(maps.Keys(t))
		return mappingView{
			n:    len(t),
			keys: keys,
			get: func(k string) (any, bool) {
				x, ok := t[k]
				return x, ok
			},
		}, true
	}
	return mappingView{}, false
}
