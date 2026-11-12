package jinja

import (
	"cmp"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	yaml3 "go.yaml.in/yaml/v3"
)

// ---------------- filters ----------------

// errUnknownFilter marks an UNREGISTERED filter name. filterMap's
// getAttr fallback keys on it via errors.Is, so a known filter's
// runtime error (bad regex, bad JSON, divide by zero) surfaces
// instead of being swallowed into an Undefined attribute read.
var errUnknownFilter = errors.New("unsupported filter")

// maxIndentWidth caps the |indent width — strings.Repeat with a
// huge count allocates without bound (OOM). 10k spaces per line is
// already far past any sane template.
const maxIndentWidth = 10_000

// fromJSONMaxBytes caps |from_json input — json.Unmarshal on a
// hostile multi-MB string is an unbounded CPU/memory sink.
const fromJSONMaxBytes = 4 << 20 // 4 MiB

// floatToInt64 converts only finite, int64-range floats — Go's
// int64() on NaN/±Inf or an out-of-range value yields platform
// garbage (typically MinInt64), which |int must never return:
// callers fall back to the filter's default instead.
func floatToInt64(f float64) (int64, bool) {
	if math.IsNaN(f) || math.IsInf(f, 0) || f < math.MinInt64 || f >= math.MaxInt64 {
		return 0, false
	}
	return int64(f), true
}

func applyFilter(name string, v any, args []any, kw map[string]any, s *scope) (any, error) {
	switch name {
	case "default", "d":
		// jinja2 do_default(value, default_value='', boolean=False) —
		// the kwargs carry the same parameters the positional args do
		// (kwargs win, as the python call they mirror would enforce).
		var def any
		if len(args) > 0 {
			def = args[0]
		}
		useBool := len(args) > 1 && Truthy(args[1])
		if dv, ok := kw["default_value"]; ok {
			def = dv
		}
		if bv, ok := kw["boolean"]; ok {
			useBool = Truthy(bv)
		}
		_, undef := v.(Undefined)
		if undef {
			return def, nil
		}
		if v == nil {
			return def, nil
		}
		if useBool && !Truthy(v) {
			return def, nil
		}
		return v, nil
	case "basename":
		sv := Stringify(v)
		return sv[strings.LastIndex(sv, "/")+1:], nil
	case "join":
		sep := " "
		if len(args) > 0 {
			sep = Stringify(args[0])
		}
		parts := []string{}
		for _, it := range ToIter(v) {
			parts = append(parts, Stringify(it))
		}
		return strings.Join(parts, sep), nil
	case "list":
		// Clone: ToIter hands back the LIVE backing slice of a
		// *List/[]any — wrapping it unchecked let .pop()/.append()
		// on the result mutate the caller's original value.
		return &List{slices.Clone(ToIter(v))}, nil
	case "length", "count":
		switch t := v.(type) {
		case string:
			// Rune count, not bytes — s[i] indexing and for-loops
			// already operate in runes, so len() must agree or a
			// multibyte string reports ~3x its real length.
			return int64(utf8.RuneCountInString(t)), nil
		case []any:
			return int64(len(t)), nil
		case *List:
			if t == nil {
				return int64(0), nil
			}
			return int64(len(t.V)), nil
		case *OMap:
			return int64(t.Len()), nil
		case map[string]any:
			return int64(len(t)), nil
		case map[string]string:
			return int64(len(t)), nil
		}
		return int64(0), nil
	case "first":
		l := ToIter(v)
		if len(l) == 0 {
			return Undefined{"first"}, nil
		}
		return l[0], nil
	case "last":
		l := ToIter(v)
		if len(l) == 0 {
			return Undefined{"last"}, nil
		}
		return l[len(l)-1], nil
	case "sort":
		// jinja2 do_sort(value, reverse=False, case_sensitive=False,
		// attribute=None): strings sort case-INSENSITIVELY unless
		// case_sensitive is set, attribute walks dotted paths
		// ("address.city") and comma-separated key lists
		// ("age,name"), digit segments index sequences, and a
		// missing attribute errors (jinja2 raises UndefinedError —
		// a silently-wrong sort order is worse than a loud one).
		// Positional args follow the jinja2 signature; kwargs win.
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
	case "unique":
		var out []any
		for _, it := range ToIter(v) {
			dup := false
			for _, e := range out {
				if deepEq(it, e) {
					dup = true
					break
				}
			}
			if !dup {
				out = append(out, it)
			}
		}
		return &List{out}, nil
	case "difference":
		var excl []any
		if len(args) > 0 {
			excl = ToIter(args[0])
		}
		var out []any
		for _, it := range ToIter(v) {
			skip := false
			for _, e := range excl {
				if deepEq(it, e) {
					skip = true
					break
				}
			}
			if !skip {
				out = append(out, it)
			}
		}
		return &List{out}, nil
	case "union":
		// Ansible set union: unique elements across ALL operands —
		// the seed operand's own duplicates collapse too, keeping the
		// first occurrence of each value.
		var out []any
		for _, it := range ToIter(v) {
			dup := false
			for _, e := range out {
				if deepEq(it, e) {
					dup = true
					break
				}
			}
			if !dup {
				out = append(out, it)
			}
		}
		for _, a := range args {
			for _, it := range ToIter(a) {
				dup := false
				for _, e := range out {
					if deepEq(it, e) {
						dup = true
						break
					}
				}
				if !dup {
					out = append(out, it)
				}
			}
		}
		return &List{out}, nil
	case "dict2items":
		switch t := v.(type) {
		case *OMap:
			return &List{t.Items()}, nil
		case map[string]any:
			return &List{omFromStringMap(t).Items()}, nil
		case map[string]string:
			return &List{omFromStringMap(t).Items()}, nil
		}
		return &List{}, nil
	case "items2dict":
		// ansible items2dict(items, key_name='key', value_name='value')
		// — the kwargs pick which pair fields become dict key/value;
		// positionals follow the ansible signature. Non-mapping items
		// are skipped (asMapping below).
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
		m := NewOMap()
		for _, it := range ToIter(v) {
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
	case "map":
		return filterMap(v, args, kw, s)
	case "selectattr":
		return filterSelectAttr(v, args, true)
	case "rejectattr":
		return filterSelectAttr(v, args, false)
	case "reject":
		return filterTest(v, args, false)
	case "select":
		return filterTest(v, args, true)
	case "bool":
		return Truthy(v), nil
	case "int":
		// Python parity: the default is returned VERBATIM when
		// conversion fails — x|int(default="abc") yields "abc",
		// not ToInt("abc")==0. Keep it untyped so a non-numeric
		// default survives to the return.
		var def any = int64(0)
		if len(args) > 0 {
			def = args[0]
		}
		if dv, ok := kw["default"]; ok {
			def = dv
		}
		base := int64(10)
		if len(args) > 1 {
			base, _ = ToInt(args[1])
		}
		if bv, ok := kw["base"]; ok {
			base, _ = ToInt(bv)
		}
		switch t := v.(type) {
		case int64:
			return t, nil
		case float64:
			if i, ok := floatToInt64(t); ok {
				return i, nil
			}
		case bool:
			if t {
				return int64(1), nil
			}
			return int64(0), nil
		case string:
			i, err := strconv.ParseInt(strings.TrimSpace(t), int(base), 64)
			if err == nil {
				return i, nil
			}
			if f, err := strconv.ParseFloat(t, 64); err == nil {
				// NaN/±Inf/out-of-int64-range floats used to
				// truncate into platform garbage (usually
				// MinInt64) — the default is the honest answer.
				if i, ok := floatToInt64(f); ok {
					return i, nil
				}
			}
		default:
			// Every other Go integer type (int, int32, uint, ...).
			if i, ok := asInt64(v); ok {
				return i, nil
			}
		}
		return def, nil
	case "float":
		// jinja2 do_float(value, default=0.0): the default is
		// returned VERBATIM on a failed conversion — the same
		// untyped-default quirk as |int, so x|float('n/a') yields
		// the string, not 0.
		var def any = float64(0)
		if len(args) > 0 {
			def = args[0]
		}
		if dv, ok := kw["default"]; ok {
			def = dv
		}
		if f, ok := toFloat(v); ok {
			return f, nil
		}
		return def, nil
	case "string":
		return Stringify(v), nil
	case "trim":
		return strings.TrimSpace(Stringify(v)), nil
	case "split":
		str := Stringify(v)
		if len(args) == 0 {
			return &List{splitWS(str)}, nil
		}
		return &List{splitAny(str, Stringify(args[0]))}, nil
	case "lower":
		return strings.ToLower(Stringify(v)), nil
	case "upper":
		return strings.ToUpper(Stringify(v)), nil
	case "regex_escape":
		return regexp.QuoteMeta(Stringify(v)), nil
	case "regex_replace":
		if len(args) < 2 {
			return v, nil
		}
		re, err := cachedRegexp(Stringify(args[0]))
		if err != nil {
			return nil, err
		}
		return re.ReplaceAllString(Stringify(v), Stringify(args[1])), nil
	case "regex_findall":
		if len(args) == 0 {
			return &List{}, nil
		}
		re, err := cachedRegexp(Stringify(args[0]))
		if err != nil {
			return nil, err
		}
		matches := re.FindAllStringSubmatch(Stringify(v), -1)
		out := make([]any, 0, len(matches))
		for _, m := range matches {
			switch {
			case len(m) > 2:
				// Multiple capture groups — python findall yields a
				// tuple of ALL groups per match, not just group 1.
				grps := make([]any, 0, len(m)-1)
				for _, g := range m[1:] {
					grps = append(grps, g)
				}
				out = append(out, &List{grps})
			case len(m) == 2:
				out = append(out, m[1])
			default:
				out = append(out, m[0])
			}
		}
		return &List{out}, nil
	case "regex_search":
		if len(args) == 0 {
			return Undefined{"regex_search"}, nil
		}
		re, err := cachedRegexp(Stringify(args[0]))
		if err != nil {
			return nil, err
		}
		m := re.FindStringSubmatch(Stringify(v))
		if len(m) > 1 {
			out := make([]any, 0, len(m)-1)
			for _, g := range m[1:] {
				out = append(out, g)
			}
			return &List{out}, nil
		}
		if m != nil {
			return m[0], nil
		}
		return Undefined{"regex_search"}, nil
	case "ternary":
		if Truthy(v) && len(args) > 0 {
			return args[0], nil
		}
		if len(args) > 1 {
			return args[1], nil
		}
		return nil, nil
	case "to_json":
		b, err := toJSON(v)
		if err != nil {
			return nil, err
		}
		return string(b), nil
	case "from_json":
		raw := Stringify(v)
		if len(raw) > fromJSONMaxBytes {
			return nil, fmt.Errorf("from_json: input exceeds %d bytes", fromJSONMaxBytes)
		}
		var out any
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			return nil, err
		}
		return fromJSONChecked(out)
	case "from_yaml":
		return DecodeYAML([]byte(Stringify(v)))
	case "to_yaml", "to_nice_yaml":
		node, err := toYAMLNode(v)
		if err != nil {
			return nil, err
		}
		b, err := yaml3.Marshal(node)
		if err != nil {
			return nil, err
		}
		return string(b), nil
	case "b64decode":
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(Stringify(v)))
		if err != nil {
			return nil, err
		}
		return string(b), nil
	case "b64encode":
		return base64.StdEncoding.EncodeToString([]byte(Stringify(v))), nil
	case "hash":
		h := sha256.Sum256([]byte(Stringify(v)))
		return hex.EncodeToString(h[:]), nil
	case "min":
		l := ToIter(v)
		if len(l) == 0 {
			return Undefined{"min"}, nil
		}
		best := l[0]
		for _, it := range l[1:] {
			if minMaxLess(it, best) {
				best = it
			}
		}
		return best, nil
	case "max":
		l := ToIter(v)
		if len(l) == 0 {
			return Undefined{"max"}, nil
		}
		best := l[0]
		for _, it := range l[1:] {
			if minMaxLess(best, it) {
				best = it
			}
		}
		return best, nil
	case "format":
		return pyFormat(Stringify(v), args)
	case "indent":
		n := int64(4)
		if len(args) > 0 {
			n, _ = ToInt(args[0])
		}
		// A negative width is no indentation at all (python's
		// ' ' * -n is '') — and strings.Repeat PANICS on a negative
		// count, so clamp instead of passing it through.
		if n < 0 {
			n = 0
		}
		// Same for a huge width: strings.Repeat would allocate
		// width×lines bytes without bound (OOM) — cap it.
		if n > maxIndentWidth {
			n = maxIndentWidth
		}
		pad := strings.Repeat(" ", int(n))
		// jinja2 (2.10+) leaves EMPTY lines unindented unless
		// blank=true opts in; whitespace-only lines still count as
		// content (python `line` truthiness). This port keeps the
		// historical first-line indent the vendored templates are
		// rendered with — jinja2's own default is first=False.
		blank := Truthy(kw["blank"])
		lines := strings.Split(Stringify(v), "\n")
		var sb strings.Builder
		sb.Grow(len(lines[0]) + len(pad) + (len(lines)-1)*(len(pad)+1))
		sb.WriteString(pad)
		sb.WriteString(lines[0])
		for _, ln := range lines[1:] {
			sb.WriteByte('\n')
			if ln != "" || blank {
				sb.WriteString(pad)
			}
			sb.WriteString(ln)
		}
		return sb.String(), nil
	case "flatten":
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
	case "zip":
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
	case "equalto", "eq":
		if len(args) == 0 {
			return false, nil
		}
		return deepEq(v, args[0]), nil
	case "search":
		return runTest("search", v, args)
	case "mandatory":
		if IsNilOrUndef(v) {
			return nil, errors.New("mandatory: value undefined")
		}
		return v, nil
	}
	return nil, fmt.Errorf("%w: %q", errUnknownFilter, name)
}

// boolArg resolves a boolean filter parameter: kwargs win, then
// positional args at the jinja2 signature position, else def.
// Truthy (not a strict bool) mirrors python's `if x:` — a "yes"
// string or 1 is on.
func boolArg(args []any, kw map[string]any, name string, pos int, def bool) bool {
	if bv, ok := kw[name]; ok {
		return Truthy(bv)
	}
	if pos < len(args) {
		return Truthy(args[pos])
	}
	return def
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

// sortKey is the precomputed decoration the |sort comparator works
// on — resolving attribute paths and stringifying operands once per
// ELEMENT (not once per comparison) keeps the sort O(n log n)
// stringify-free, and bucketing every key into a rank makes the
// comparator a strict weak ordering on MIXED types.
type sortKey struct {
	rank   int
	num    float64   // rank 0 primary (NaN/±Inf mapped to ±Inf sentinels)
	str    string    // rank 0/1/2/3 secondary (or sole) key
	tup    []sortKey // rank 4 only — multi-attribute key, PRE-DECORATED per element
	hasInt bool      // rank 0: the key is an exact integer (i64 is authoritative)
	i64    int64     // rank 0: exact integer value — float64(num) loses >2^53
	finite bool      // rank 0: num came from a real finite number, not a NaN/±Inf sentinel
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
		f, ok := toFloat(v)
		var k sortKey
		if !ok {
			// NaN/±Inf have no float order — map them to sentinels
			// so the (num, str) pair stays a total preorder; the
			// string half still distinguishes NaN from +Inf.
			if fv, isF := v.(float64); isF && math.IsInf(fv, -1) {
				f = math.Inf(-1)
			} else {
				f = math.Inf(1)
			}
		} else {
			k.finite = true
		}
		k.rank, k.num, k.str = 0, f, Stringify(v)
		// Exact integer path: int64 magnitudes past 2^53 do not fit
		// float64(num) — keep the int64 so the comparator can order
		// them exactly instead of collapsing to the float rounding.
		if i, isInt := asInt64(v); isInt {
			k.hasInt, k.i64 = true, i
		}
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
// pairs; within a rank the (num, str) or str pair is lexicographic —
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
		// Exact integer comparison when BOTH sides resolve to an
		// int64 — an int64 past 2^53 and an integral float64 in
		// range both land here, so 9007199254740993 sorts above
		// 9007199254740992.0 instead of collapsing on the float.
		if ai, aok := sortKeyInt64(a); aok {
			if bi, bok := sortKeyInt64(b); bok {
				return cmp.Compare(ai, bi)
			}
		}
		if a.num != b.num {
			return cmp.Compare(a.num, b.num)
		}
		if a.finite && b.finite {
			// Numerically equal FINITE values (1 vs 1.0, True vs 1)
			// are equal keys — return 0 so SortStableFunc keeps
			// input order like python's sorted(). The str fallback
			// stays for the NaN/±Inf sentinels, which share a num
			// but are NOT equal values.
			return 0
		}
	}
	return strings.Compare(a.str, b.str)
}

// sortKeyInt64 resolves a rank-0 sort key to an exact int64 when
// possible: hasInt keys carry it directly; finite integral floats
// inside int64 range convert losslessly (a float64 that big is
// always integral — fraction bits don't exist past 2^52).
func sortKeyInt64(k sortKey) (int64, bool) {
	if k.hasInt {
		return k.i64, true
	}
	if k.finite && k.num == math.Trunc(k.num) &&
		k.num >= -9223372036854775808.0 && k.num < 9223372036854775808.0 {
		return int64(k.num), true
	}
	return 0, false
}
