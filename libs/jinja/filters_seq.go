// filters_seq.go — the sequence/set/dict filter family: unique,
// difference, union, flatten, min, max, zip, dict2items, items2dict.
package jinja

import "fmt"

// filterUnique keeps the first occurrence of each element —
// membership is deepEq (whose scalar arm is numEq), so 1 and 1.0
// dedupe together. All-plain-string inputs take the O(N) hash-set
// path: deepEq on two plain strings is plain equality, so first-seen
// dedupe through a set is semantics-free — anything else (1 vs 1.0,
// mixed shapes) stays on the deepEq scan.
func filterUnique(v any) (any, error) {
	items := ToIter(v)
	if allPlainStrings(items) {
		seen := make(map[string]struct{}, len(items))
		var out []any
		for _, it := range items {
			s := it.(string)
			if _, dup := seen[s]; !dup {
				seen[s] = struct{}{}
				out = append(out, it)
			}
		}
		return &List{out}, nil
	}
	return &List{appendUnique(nil, items)}, nil
}

// filterDifference drops every element that deep-equals a member of
// the exclusion list (args[0]). Both operands all-plain-string →
// hash-set membership (equality, like deepEq's string arm); the
// deepEq scan would be O(len(v)×len(excl)).
func filterDifference(v any, args []any) (any, error) {
	var excl []any
	if len(args) > 0 {
		excl = ToIter(args[0])
	}
	items := ToIter(v)
	if allPlainStrings(items) && allPlainStrings(excl) {
		drop := make(map[string]struct{}, len(excl))
		for _, e := range excl {
			drop[e.(string)] = struct{}{}
		}
		var out []any
		for _, it := range items {
			if _, hit := drop[it.(string)]; !hit {
				out = append(out, it)
			}
		}
		return &List{out}, nil
	}
	var out []any
	for _, it := range items {
		if !containsDeepEq(excl, it) {
			out = append(out, it)
		}
	}
	return &List{out}, nil
}

// filterUnion is the ansible set union: unique elements across ALL
// operands — the seed operand's own duplicates collapse too,
// keeping the first occurrence of each value. Every operand
// all-plain-string → one shared hash set across the sweep.
func filterUnion(v any, args []any) (any, error) {
	seed := ToIter(v)
	rest := make([][]any, len(args))
	allStrings := allPlainStrings(seed)
	for i, a := range args {
		rest[i] = ToIter(a)
		if allStrings && !allPlainStrings(rest[i]) {
			allStrings = false
		}
	}
	if allStrings {
		seen := make(map[string]struct{}, len(seed))
		var out []any
		add := func(items []any) {
			for _, it := range items {
				s := it.(string)
				if _, dup := seen[s]; !dup {
					seen[s] = struct{}{}
					out = append(out, it)
				}
			}
		}
		add(seed)
		for _, items := range rest {
			add(items)
		}
		return &List{out}, nil
	}
	out := appendUnique(nil, seed)
	for _, items := range rest {
		out = appendUnique(out, items)
	}
	return &List{out}, nil
}

// allPlainStrings reports whether every element is exactly the
// string type — the gate for the O(N) hash-set dedupe fast paths.
// A named string type (or any non-string) disqualifies the input so
// membership keeps running through deepEq, byte-for-byte the old
// semantics.
func allPlainStrings(items []any) bool {
	for _, it := range items {
		if _, ok := it.(string); !ok {
			return false
		}
	}
	return true
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
		// mapLookup accepts *OMap AND the Go-native maps a vars-file
		// decode produces — items2dict over YAML data must not
		// silently drop plain-map entries. Two single-key probes, so
		// the sorted view asMapping builds per item is pure waste.
		if !isMappingValue(it) {
			continue
		}
		k, _ := mapLookup(it, keyName)
		val, _ := mapLookup(it, valueName)
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
