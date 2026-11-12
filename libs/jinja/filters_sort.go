// filters_sort.go — the |sort filter and its key machinery:
// attribute-path resolution (sortKeyOf), the precomputed sortKey
// decoration, and the strict-weak-ordering comparator.
package jinja

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
)

// filterSort implements jinja2 do_sort(value, reverse=False,
// case_sensitive=False, attribute=None): strings sort
// case-INSENSITIVELY unless case_sensitive is set, attribute walks
// dotted paths ("address.city") and comma-separated key lists
// ("age,name"), digit segments index sequences, and a missing
// attribute errors (jinja2 raises UndefinedError — a silently-wrong
// sort order is worse than a loud one). Positional args follow the
// jinja2 signature; kwargs win.
func filterSort(v any, args []any, kw map[string]any) (any, error) {
	reverse := boolArg(args, kw, "reverse", 0, false)
	caseSensitive := boolArg(args, kw, "case_sensitive", 1, false)
	attribute := ""
	if av, ok := kw["attribute"]; ok {
		attribute = Stringify(av)
	} else if len(args) > 2 {
		attribute = Stringify(args[2])
	}
	elems := append([]any{}, ToIter(v)...)
	// Schwartzian transform — decorate once, sort, undecorate.
	// The old comparator re-resolved attribute paths and
	// re-stringified operands on EVERY comparison, O(n log n)
	// times per element; the key is now computed exactly once.
	type keyed struct {
		skey sortKey // precomputed rank/num/str — compare is O(1)
		elem any
	}
	pairs := make([]keyed, len(elems))
	for i, el := range elems {
		k, err := sortKeyOf(el, attribute, caseSensitive)
		if err != nil {
			return nil, err
		}
		pairs[i] = keyed{skey: newSortKey(k), elem: el}
	}
	// Stable, like python's sorted — equal keys keep relative
	// order (the chaining idiom in the jinja2 docstring relies
	// on it). reverse=True is an INVERTED comparator, not a
	// post-hoc slice reversal: python keeps equal elements in
	// original order with reverse=True, and reversing a stable
	// ascending result would swap them. sortKeyCompare is a
	// strict weak ordering on MIXED key types (rank buckets),
	// so SortStableFunc can never see an intransitive less.
	less := func(a, b keyed) int { return sortKeyCompare(a.skey, b.skey) }
	if reverse {
		less = func(a, b keyed) int { return sortKeyCompare(b.skey, a.skey) }
	}
	slices.SortStableFunc(pairs, less)
	out := make([]any, len(pairs))
	for i, p := range pairs {
		out[i] = p.elem
	}
	return &List{out}, nil
}

// sortTuple is the multi-attribute sort key ("age,name") — a
// dedicated type so sortKeyLess can tell a tuple key apart from a
// plain []any element (a YAML-decoded sequence sorts on its first
// item, it is NOT a tuple). Without the distinct type the two
// shared []any: tuple comparison recursed element-wise into real
// sequences (unbounded on cyclic values) and the sequence branch
// was dead code.
type sortTuple []any

// sortKeyOf resolves ONE element's sort key: the element itself, or
// the attribute path(s) the jinja2 `attribute` kwarg names. Multi-key
// paths ("age,name") resolve to a sortTuple compared element-wise;
// digit segments index sequences (sort(attribute='0') on pairs).
// String keys are case-folded HERE (jinja2's ignore_case
// postprocess) so the comparator never re-folds per comparison —
// with case_sensitive the raw value is kept.
func sortKeyOf(el any, attribute string, caseSensitive bool) (any, error) {
	if attribute == "" {
		if s, ok := el.(string); ok && !caseSensitive {
			return strings.ToLower(s), nil
		}
		return el, nil
	}
	var keys []any
	for _, attr := range strings.Split(attribute, ",") {
		cur := el
		for _, seg := range strings.Split(attr, ".") {
			var next any
			if allDigits(seg) {
				i, _ := strconv.ParseInt(seg, 10, 64)
				v, err := getIndex(cur, i)
				if err != nil {
					return nil, fmt.Errorf("sort: bad index %q in attribute %q: %w", seg, attr, err)
				}
				next = v
			} else {
				next = getAttr(cur, seg)
			}
			if IsNilOrUndef(next) {
				// jinja2 raises UndefinedError ("'dict object' has
				// no attribute ...") — fail loud, not silent-wrong.
				return nil, fmt.Errorf("sort: element has no attribute %q", attr)
			}
			cur = next
		}
		if s, ok := cur.(string); ok && !caseSensitive {
			cur = strings.ToLower(s)
		}
		keys = append(keys, cur)
	}
	if len(keys) == 1 {
		return keys[0], nil
	}
	return sortTuple(keys), nil
}

// allDigits reports whether s is a bare ASCII digit run — python's
// str.isdigit for the attribute-segment check (no sign: "-1" stays a
// mapping key, matching jinja2).
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// numSortKind tags which exact numeric representation a rank-0
// sortKey carries — float64(num), int64(i64) or uint64(u64). The
// int/uint kinds exist because float64(num) cannot represent every
// integer: an int64 past 2^53 rounds, and a uint64 past MaxInt64 has
// no int64 form at all.
type numSortKind uint8

const (
	numFloat numSortKind = iota
	numInt64
	numUint64
)

// sortKey is the precomputed decoration the |sort comparator works
// on — resolving attribute paths and stringifying operands once per
// ELEMENT (not once per comparison) keeps the sort O(n log n)
// stringify-free, and bucketing every key into a rank makes the
// comparator a strict weak ordering on MIXED types.
type sortKey struct {
	rank    int
	numKind numSortKind
	i64     int64     // numInt64: exact integer value — float64(num) loses >2^53
	u64     uint64    // numUint64: exact integer value past MaxInt64
	num     float64   // rank 0: numeric approximation (NaN/±Inf mapped to ±Inf sentinels)
	str     string    // rank 0/1/2/3 secondary (or sole) key — sentinel tiebreak
	tup     []sortKey // rank 4 only — multi-attribute key, PRE-DECORATED per element
}

// sortKeyRank buckets a resolved sort key so cross-type pairs never
// reach a value comparison: the OLD comparator compared numbers
// numerically but everything else via Stringify, which is
// intransitive on mixed input ([10, "2", 3] could cycle 10<"2"<3<10)
// — an intransitive less is exactly what slices.SortFunc must never
// see. Ranks make every cross-type pair decided by rank alone.
func sortKeyRank(v any) int {
	switch {
	case isNum(v):
		return 0
	}
	if _, ok := asUint64(v); ok {
		// A uint64 (or uint on 64-bit) past MaxInt64 fails asInt64,
		// so isNum calls it a non-number — but it IS one and must
		// sort in the numeric rank, not with the Stringify-compared
		// "other" bucket where it misordered against ints.
		return 0
	}
	if _, ok := v.(string); ok {
		return 1
	}
	switch v.(type) {
	case *List, []any:
		return 2
	}
	return 3
}

// newSortKey decorates one resolved sort key. String keys arrive
// already case-folded by sortKeyOf (jinja2 ignore_case).
func newSortKey(v any) sortKey {
	if t, ok := v.(sortTuple); ok {
		// Decorate tuple elements ONCE here — the comparator then
		// compares sortKey-to-sortKey directly instead of re-running
		// newSortKey per comparison (O(n log n) re-decoration).
		tup := make([]sortKey, len(t))
		for i, e := range t {
			tup[i] = newSortKey(e)
		}
		return sortKey{rank: 4, tup: tup}
	}
	switch sortKeyRank(v) {
	case 0:
		k := sortKey{rank: 0, str: Stringify(v)}
		// Exact integer kinds first: int64 magnitudes past 2^53 do
		// not fit float64(num), and a uint64 past MaxInt64 has no
		// int64 form — keep the exact value so the comparator can
		// order them losslessly instead of collapsing on the float.
		if i, isInt := asInt64(v); isInt {
			k.numKind, k.i64, k.num = numInt64, i, float64(i)
			return k
		}
		if u, isUint := asUint64(v); isUint {
			k.numKind, k.u64, k.num = numUint64, u, float64(u)
			return k
		}
		f, ok := toFloat(v)
		if !ok {
			// NaN/±Inf have no float order — map them to sentinels
			// so the (num, str) pair stays a total preorder; the
			// string half still distinguishes NaN from +Inf.
			if fv, isF := v.(float64); isF && math.IsInf(fv, -1) {
				f = math.Inf(-1)
			} else {
				f = math.Inf(1)
			}
		}
		k.numKind, k.num = numFloat, f
		return k
	case 1:
		s, _ := v.(string)
		return sortKey{rank: 1, str: s}
	case 2:
		// Sequence elements compare on their first item — *List
		// (template literals/filters) and []any (YAML-decoded vars)
		// are the same value in two representations.
		if first, ok := seqSortFirst(v); ok {
			return sortKey{rank: 2, str: Stringify(first)}
		}
		return sortKey{rank: 2, str: Stringify(v)}
	default:
		return sortKey{rank: 3, str: Stringify(v)}
	}
}

// seqSortFirst returns the first element of a sequence sort key, or
// ok=false for an empty one.
func seqSortFirst(v any) (any, bool) {
	switch t := v.(type) {
	case *List:
		if t != nil && len(t.V) > 0 {
			return t.V[0], true
		}
	case []any:
		if len(t) > 0 {
			return t[0], true
		}
	}
	return nil, false
}

// sortKeyCompare is a strict weak ordering: rank decides cross-type
// pairs; within a rank the numeric or str pair is lexicographic —
// a total preorder by construction, so SortStableFunc stays safe on
// any mixture of ints, floats, bools, strings, sequences and maps.
func sortKeyCompare(a, b sortKey) int {
	if a.rank != b.rank {
		return cmp.Compare(a.rank, b.rank)
	}
	if a.rank == 4 {
		// Both multi-attribute tuples: element-wise like python
		// tuple ordering — first non-equal pair decides, the
		// shorter tuple is smaller on a shared prefix. Elements are
		// already sortKeys (decorated once in newSortKey).
		for i := 0; i < min(len(a.tup), len(b.tup)); i++ {
			if c := sortKeyCompare(a.tup[i], b.tup[i]); c != 0 {
				return c
			}
		}
		return cmp.Compare(len(a.tup), len(b.tup))
	}
	if a.rank == 0 {
		return sortKeyNumCompare(a, b)
	}
	return strings.Compare(a.str, b.str)
}

// sortKeyNumCompare orders two rank-0 (numeric) keys. Same-kind
// pairs compare on their exact representation; cross-kind pairs go
// through float64(num) first — float64 conversion is monotonic, so a
// STRICT float compare is always decisive — and only a float TIE
// falls through to the exact-integer tiebreak, which is what keeps
// 9007199254740993 sorting above 9007199254740992.0 (and a negative
// int64 below -2^53 from collapsing onto its float64 rounding).
func sortKeyNumCompare(a, b sortKey) int {
	if a.numKind == b.numKind {
		switch a.numKind {
		case numInt64:
			return cmp.Compare(a.i64, b.i64)
		case numUint64:
			return cmp.Compare(a.u64, b.u64)
		}
		// numFloat == numFloat: identical float64 values are equal
		// keys — return 0 so SortStableFunc keeps input order like
		// python's sorted() (1 vs 1.0 style ties included). The
		// NaN/±Inf sentinel pairs share num=±Inf but are NOT equal
		// values, so they fall through to the string half which
		// still orders "NaN" vs "+Inf" vs "-Inf".
		if a.num != b.num {
			return cmp.Compare(a.num, b.num)
		}
		if !math.IsInf(a.num, 0) {
			return 0
		}
		return strings.Compare(a.str, b.str)
	}
	if a.num < b.num {
		return -1
	}
	if a.num > b.num {
		return 1
	}
	// num tie — the exact values are within float64 rounding of
	// each other; resolve both to integers where possible.
	if c, ok := sortKeyExactCmp(a, b); ok {
		return c
	}
	return strings.Compare(a.str, b.str)
}

// sortKeyExactCmp compares two rank-0 keys on their EXACT integer
// values when both sides have one: int64/uint64 carry it directly,
// a finite integral float64 inside range converts losslessly (a
// float64 that big is always integral — fraction bits don't exist
// past 2^52). ok=false means at least one side has no exact integer
// form (non-integral float, out-of-range, or a NaN/±Inf sentinel) —
// the caller falls back to the string half, which still totally
// orders the remaining sentinel ties.
func sortKeyExactCmp(a, b sortKey) (int, bool) {
	if ai, aok := sortKeyAsInt64(a); aok {
		if bi, bok := sortKeyAsInt64(b); bok {
			return cmp.Compare(ai, bi), true
		}
	}
	if au, aok := sortKeyAsUint64(a); aok {
		if bu, bok := sortKeyAsUint64(b); bok {
			return cmp.Compare(au, bu), true
		}
	}
	return 0, false
}

// sortKeyAsInt64 resolves a rank-0 key to an exact int64 when
// possible — the int64 domain covers every signed integer and every
// non-negative uint64 up to MaxInt64.
func sortKeyAsInt64(k sortKey) (int64, bool) {
	switch k.numKind {
	case numInt64:
		return k.i64, true
	case numUint64:
		if k.u64 <= math.MaxInt64 {
			return int64(k.u64), true
		}
	case numFloat:
		f := k.num
		if !math.IsInf(f, 0) && f == math.Trunc(f) &&
			f >= -9223372036854775808.0 && f < 9223372036854775808.0 {
			return int64(f), true
		}
	}
	return 0, false
}

// sortKeyAsUint64 resolves a rank-0 key to an exact uint64 when
// possible — the domain for non-negative integers past MaxInt64.
func sortKeyAsUint64(k sortKey) (uint64, bool) {
	switch k.numKind {
	case numUint64:
		return k.u64, true
	case numInt64:
		if k.i64 >= 0 {
			return uint64(k.i64), true
		}
	case numFloat:
		f := k.num
		if !math.IsInf(f, 0) && f == math.Trunc(f) &&
			f >= 0 && f < 18446744073709551616.0 {
			return uint64(f), true
		}
	}
	return 0, false
}
