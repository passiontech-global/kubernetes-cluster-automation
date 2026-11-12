// filters_seq.go — the sequence/set/dict filter family: unique,
// difference, union, flatten, min, max, zip, dict2items, items2dict.
package jinja

import "fmt"

// filterUnique keeps the first occurrence of each element —
// membership is deepEq (whose scalar arm is numEq), so 1 and 1.0
// dedupe together.
func filterUnique(v any) (any, error) {
	return &List{appendUnique(nil, ToIter(v))}, nil
}

// filterDifference drops every element that deep-equals a member of
// the exclusion list (args[0]).
func filterDifference(v any, args []any) (any, error) {
	var excl []any
	if len(args) > 0 {
		excl = ToIter(args[0])
	}
	var out []any
	for _, it := range ToIter(v) {
		if !containsDeepEq(excl, it) {
			out = append(out, it)
		}
	}
	return &List{out}, nil
}

// filterUnion is the ansible set union: unique elements across ALL
// operands — the seed operand's own duplicates collapse too,
// keeping the first occurrence of each value.
func filterUnion(v any, args []any) (any, error) {
	out := appendUnique(nil, ToIter(v))
	for _, a := range args {
		out = appendUnique(out, ToIter(a))
	}
	return &List{out}, nil
}

// appendUnique appends every item of items not already present in
// out, preserving first-occurrence order — the shared core of
// unique/union (the three filters used to spell the same nested
// deepEq loop out three times).
func appendUnique(out, items []any) []any {
	for _, it := range items {
		if !containsDeepEq(out, it) {
			out = append(out, it)
		}
	}
	return out
}

// containsDeepEq reports whether v deep-equals any element of list.
func containsDeepEq(list []any, v any) bool {
	for _, e := range list {
		if deepEq(v, e) {
			return true
		}
	}
	return false
}

// filterDict2Items renders a mapping as [key,value] pair items —
// *OMap in insertion order, plain Go maps sorted (deterministic).
func filterDict2Items(v any) (any, error) {
	switch t := v.(type) {
	case *OMap:
		return &List{t.Items()}, nil
	case map[string]any:
		return &List{omFromStringMap(t).Items()}, nil
	case map[string]string:
		return &List{omFromStringMap(t).Items()}, nil
	}
	return &List{}, nil
}

// filterItems2Dict is ansible items2dict(items, key_name='key',
// value_name='value') — the kwargs pick which pair fields become
// dict key/value; positionals follow the ansible signature.
// Non-mapping items are skipped (asMapping below).
func filterItems2Dict(v any, args []any, kw map[string]any) (any, error) {
	keyName, valueName := "key", "value"
	if len(args) > 0 {
		keyName = Stringify(args[0])
	}
	if len(args) > 1 {
		valueName = Stringify(args[1])
	}
	if kv, ok := kw["key_name"]; ok {
		keyName = Stringify(kv)
	}
	if vv, ok := kw["value_name"]; ok {
		valueName = Stringify(vv)
	}
	items := ToIter(v)
	m := NewOMapCap(len(items))
	for _, it := range items {
		// asMapping accepts *OMap AND the Go-native maps a
		// vars-file decode produces — items2dict over YAML data
		// must not silently drop plain-map entries.
		om, ok := asMapping(it)
		if !ok {
			continue
		}
		k, _ := om.get(keyName)
		val, _ := om.get(valueName)
		m.Set(Stringify(k), val)
	}
	return m, nil
}

// filterFlatten recursively expands nested lists into one flat list.
func filterFlatten(v any) (any, error) {
	var out []any
	var rec func(x any, depth int) error
	rec = func(x any, depth int) error {
		// Only real lists nest. ToIter char-splits strings and
		// dumps map keys, so routing everything through it
		// turned ["ab","cd"] into [a b c d]; a dict is an atom.
		var items []any
		switch t := x.(type) {
		case *List:
			if t == nil {
				// A typed-nil *List is an EMPTY list — it
				// contributes no elements, not a nil atom.
				return nil
			}
			items = t.V
		case []any:
			items = t
		default:
			out = append(out, x)
			return nil
		}
		if depth >= flattenMaxDepth {
			// Depth cap keeps a self-referential list from
			// recursing forever — keep the tail unexpanded.
			out = append(out, items...)
			return nil
		}
		for _, it := range items {
			if err := rec(it, depth+1); err != nil {
				return err
			}
			if len(out) > flattenMaxOut {
				// A BRANCHING cycle (l.V=[l,l]) never nears
				// the depth cap yet doubles output per level —
				// budget total elements, not just depth.
				return fmt.Errorf("flatten: output exceeds %d elements", flattenMaxOut)
			}
		}
		return nil
	}
	if err := rec(v, 0); err != nil {
		return nil, err
	}
	return &List{out}, nil
}

// filterMinMax is min (wantMax=false) / max (wantMax=true): the
// extreme element under minMaxLess — numeric when both operands are
// numbers, lexical on the string form otherwise. Empty input yields
// the named Undefined like jinja2's undefined-on-empty.
func filterMinMax(v any, name string, wantMax bool) (any, error) {
	l := ToIter(v)
	if len(l) == 0 {
		return Undefined{name}, nil
	}
	best := l[0]
	for _, it := range l[1:] {
		if wantMax {
			if minMaxLess(best, it) {
				best = it
			}
		} else if minMaxLess(it, best) {
			best = it
		}
	}
	return best, nil
}

// filterZip pairs the i-th element of every operand into a tuple —
// length is the SHORTEST input (python zip parity).
func filterZip(v any, args []any) (any, error) {
	var out []any
	lists := [][]any{ToIter(v)}
	for _, a := range args {
		lists = append(lists, ToIter(a))
	}
	minLen := -1
	for _, l := range lists {
		if minLen < 0 || len(l) < minLen {
			minLen = len(l)
		}
	}
	for i := 0; i < minLen; i++ {
		pair := make([]any, len(lists))
		for j, l := range lists {
			pair[j] = l[i]
		}
		out = append(out, &List{pair})
	}
	return &List{out}, nil
}
