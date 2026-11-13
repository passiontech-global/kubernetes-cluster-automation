// filters.go — applyFilter dispatch plus the scalar/string/codec/
// regex filter cases. The sequence/set family lives in
// filters_seq.go, |sort and its key machinery in filters_sort.go,
// printf-style format in filters_format.go, and the
// map/select/reject family in filters_select.go.
package jinja

import (
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

// parseMaxBytes caps |from_json AND |from_yaml input — decoding a
// hostile multi-MB string through json.Unmarshal/yaml is an
// unbounded CPU/memory sink.
const parseMaxBytes = 4 << 20 // 4 MiB

// hexish reports whether s looks like a hex number (0x/0X prefix,
// after python's sign/whitespace conventions): strconv.ParseFloat
// accepts "0x1p-2"-style hex floats python's float() rejects, so the
// |int decimal fallback must skip them.
func hexish(s string) bool {
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(s), "+"), "-"))
	return len(s) > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')
}

// floatToInt64 converts NaN/±Inf-free floats into int64: Go's
// int64() on NaN/±Inf or an out-of-range value yields platform
// garbage (typically MinInt64), which |int must never return.
// Finite underflow below MinInt64 clamps to MinInt64 (python
// int(-1e300) is a huge negative int, not a failure); overflow above
// MaxInt64 and the non-finites report false — callers fall back to
// the filter's default instead.
func floatToInt64(f float64) (int64, bool) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	if f <= math.MinInt64 {
		return math.MinInt64, true
	}
	if f >= math.MaxInt64 {
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
		// attribute=None) — see filters_sort.go for the key machinery.
		return filterSort(v, args, kw)
	case "unique":
		return filterUnique(v)
	case "difference":
		return filterDifference(v, args)
	case "union":
		return filterUnion(v, args)
	case "dict2items":
		return filterDict2Items(v)
	case "items2dict":
		return filterItems2Dict(v, args, kw)
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
			// The float fallback is a base-10 decimal convenience:
			// int("1.5") → 1. With base != 10 (int("1.5", 16) is a
			// ValueError in python), and never for a hex string —
			// Go's ParseFloat accepts "0x1p-2"-style hex floats
			// python's float() rejects, and int("0x10", 16) parses
			// the digits via ParseInt above anyway.
			if base == 10 && !hexish(t) {
				if f, err := strconv.ParseFloat(t, 64); err == nil {
					// NaN/±Inf/out-of-int64-range floats used to
					// truncate into platform garbage — the
					// default is the honest answer for those,
					// while finite underflow clamps (see
					// floatToInt64).
					if i, ok := floatToInt64(f); ok {
						return i, nil
					}
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
		if len(raw) > parseMaxBytes {
			return nil, fmt.Errorf("from_json: input exceeds %d bytes", parseMaxBytes)
		}
		var out any
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			return nil, err
		}
		return fromJSONChecked(out)
	case "from_yaml":
		// Same input cap as |from_json — a hostile multi-MB YAML
		// string is the same unbounded decode sink.
		raw := Stringify(v)
		if len(raw) > parseMaxBytes {
			return nil, fmt.Errorf("from_yaml: input exceeds %d bytes", parseMaxBytes)
		}
		return DecodeYAML([]byte(raw))
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
		return filterMinMax(v, "min", false)
	case "max":
		return filterMinMax(v, "max", true)
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
		return filterFlatten(v)
	case "zip":
		return filterZip(v, args)
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
