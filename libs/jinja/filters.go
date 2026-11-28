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
	"errors"
	"fmt"
	"math"
	"regexp"
	"regexp/syntax"
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

// outputSizeCap is the post-serialization byte ceiling shared by
// the codec/format filters: a value that walked inside its step
// budget can still marshal to an unbounded document (YAML quotes,
// indentation and line breaks amplify every node). Kept as a tiny
// helper so the cap branch is testable without building a 16 MiB
// document under -race.
func outputSizeCap(n int, filter string) error {
	if n > maxStringBytes {
		return fmt.Errorf("%s: output exceeds %d bytes", filter, maxStringBytes)
	}
	return nil
}

// hexish reports whether s looks like a hex number (0x/0X prefix,
// after python's sign/whitespace conventions): strconv.ParseFloat
// accepts "0x1p-2"-style hex floats python's float() rejects, so the
// |int decimal fallback must skip them.
func hexish(s string) bool {
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(s), "+"), "-"))
	return len(s) > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')
}

// parseIntBase parses s in the given base with Python 3 int(s, base)
// semantics: optional +/- followed by 0x/0X (base 16), 0o/0O (base 8),
// or 0b/0B (base 2), rejecting empty bodies ("0x"), inner signs
// ("0x-10", "0x+10"), and underscores ("1_000", "0x_10"). For base == 0,
// all-zero strings ("0", "000") parse as 0 while other leading-zero
// numbers without a base prefix ("010") are rejected.
func parseIntBase(s string, base int) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" || base < 0 || base == 1 || base > 36 {
		return 0, strconv.ErrSyntax
	}
	if strings.ContainsRune(s, '_') {
		return 0, strconv.ErrSyntax
	}
	sign := ""
	rest := s
	if rest[0] == '+' || rest[0] == '-' {
		sign = rest[:1]
		rest = rest[1:]
		if rest == "" {
			return 0, strconv.ErrSyntax
		}
	}
	if base == 0 {
		switch {
		case len(rest) >= 2 && rest[0] == '0' && (rest[1] == 'x' || rest[1] == 'X'):
			base = 16
			rest = rest[2:]
		case len(rest) >= 2 && rest[0] == '0' && (rest[1] == 'o' || rest[1] == 'O'):
			base = 8
			rest = rest[2:]
		case len(rest) >= 2 && rest[0] == '0' && (rest[1] == 'b' || rest[1] == 'B'):
			base = 2
			rest = rest[2:]
		case rest[0] == '0':
			for i := 1; i < len(rest); i++ {
				if rest[i] != '0' {
					return 0, strconv.ErrSyntax
				}
			}
			return 0, nil
		default:
			base = 10
		}
		if rest == "" || rest[0] == '+' || rest[0] == '-' {
			return 0, strconv.ErrSyntax
		}
		return strconv.ParseInt(sign+rest, base, 64)
	}
	if base == 2 || base == 8 || base == 16 {
		var p0, p1 byte
		switch base {
		case 2:
			p0, p1 = 'b', 'B'
		case 8:
			p0, p1 = 'o', 'O'
		case 16:
			p0, p1 = 'x', 'X'
		}
		if len(rest) >= 2 && rest[0] == '0' && (rest[1] == p0 || rest[1] == p1) {
			rest = rest[2:]
			if rest == "" || rest[0] == '+' || rest[0] == '-' {
				return 0, strconv.ErrSyntax
			}
		}
	}
	return strconv.ParseInt(sign+rest, base, 64)
}

// floatToInt64 converts NaN/±Inf-free floats into int64: Go's
// int64() on NaN/±Inf or an out-of-range value yields platform
// garbage (typically MinInt64), which |int must never return.
// Out-of-range on EITHER end reports false — callers fall back to
// the filter's default instead of a clamped lie (python's bignum
// has no int64 form here, so the default is the honest answer).
func floatToInt64(f float64) (int64, bool) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	// float64(math.MinInt64) is exactly -2^63 and float64(math.MaxInt64)
	// rounds UP to 2^63 — both bounds are exact powers of two, so a
	// strict compare keeps every in-range float (f == -2^63 still
	// yields MinInt64) and rejects genuine overflow on BOTH ends.
	// The old `f <= MinInt64` clamp reported MinInt64 for -1e300 —
	// a value no int64 holds; the filter's default is the honest
	// answer, same as positive overflow.
	if f < float64(math.MinInt64) || f >= float64(math.MaxInt64) {
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
		items := ToIter(v)
		if len(items) > maxSeqElems {
			return nil, fmt.Errorf("join: %d elements exceeds cap %d", len(items), maxSeqElems)
		}
		parts := make([]string, 0, len(items))
		total := 0
		for _, it := range items {
			p := Stringify(it)
			total += len(p)
			if total > maxStringBytes {
				return nil, fmt.Errorf("join: output exceeds %d bytes", maxStringBytes)
			}
			parts = append(parts, p)
		}
		// The separator bytes count toward the output too —
		// range(1e6) | join(sep_1MiB) passed the per-item check
		// while strings.Join allocated ~1 TiB. Guard len(sep) >
		// maxStringBytes before multiplying so large counts cannot
		// overflow int.
		if len(parts) > 1 && len(sep) > 0 {
			if len(sep) > maxStringBytes || len(parts)-1 > (maxStringBytes-total)/len(sep) {
				return nil, fmt.Errorf("join: output exceeds %d bytes", maxStringBytes)
			}
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
		case []string:
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
		if bv, ok := kw["base"]; ok {
			b, ok := ToInt(bv)
			if !ok {
				return def, nil
			}
			base = b
		} else if len(args) > 1 {
			b, ok := ToInt(args[1])
			if !ok {
				return def, nil
			}
			base = b
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
			if base < 0 || base == 1 || base > 36 {
				return def, nil
			}
			i, err := parseIntBase(t, int(base))
			if err == nil {
				return i, nil
			}
			// The float fallback is a base-10 decimal convenience:
			// int("1.5") → 1. With base != 10 (int("1.5", 16) is a
			// ValueError in python), and never for a hex string or
			// underscore-separated string — Go's ParseFloat accepts
			// "0x1p-2" and "1_000", which must not bypass base rules.
			if base == 10 && !hexish(t) && !strings.ContainsRune(t, '_') {
				// TrimSpace like the ParseInt above — " 1.5 " | int
				// must not fail the decimal fallback on padding
				// python's float() tolerates.
				if f, err := strconv.ParseFloat(strings.TrimSpace(t), 64); err == nil {
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
			parts, err := splitWSBounded(str)
			if err != nil {
				return nil, err
			}
			return &List{parts}, nil
		}
		parts, err := splitAnyBounded(str, Stringify(args[0]))
		if err != nil {
			return nil, err
		}
		return &List{parts}, nil
	case "lower":
		return strings.ToLower(Stringify(v)), nil
	case "upper":
		return strings.ToUpper(Stringify(v)), nil
	case "regex_escape":
		s := Stringify(v)
		if err := outputSizeCap(len(s), "regex_escape"); err != nil {
			return nil, err
		}
		if len(s) > maxStringBytes/2 {
			extra := 0
			for i := 0; i < len(s); i++ {
				switch s[i] {
				case '\\', '.', '+', '*', '?', '(', ')', '|', '[', ']', '{', '}', '^', '$':
					extra++
				}
			}
			if err := outputSizeCap(len(s)+extra, "regex_escape"); err != nil {
				return nil, err
			}
		}
		out := regexp.QuoteMeta(s)
		if err := outputSizeCap(len(out), "regex_escape"); err != nil {
			return nil, err
		}
		return out, nil
	case "regex_replace":
		if len(args) < 2 {
			return v, nil
		}
		entry, err := cachedRegexpEntry(Stringify(args[0]))
		if err != nil {
			return nil, err
		}
		s := Stringify(v)
		repl := Stringify(args[1])
		if len(s) > maxStringBytes {
			return nil, fmt.Errorf("regex_replace: input exceeds %d bytes", maxStringBytes)
		}
		return regexReplaceBounded(entry, s, repl)
	case "regex_findall":
		if len(args) == 0 {
			return &List{}, nil
		}
		entry, err := cachedRegexpEntry(Stringify(args[0]))
		if err != nil {
			return nil, err
		}
		return regexFindallBounded(entry, Stringify(v))
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
		return decodeJSON(raw)
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
		lw := yamlLimitWriter{max: maxStringBytes}
		enc := yaml3.NewEncoder(&lw)
		err = enc.Encode(node)
		if err == nil {
			err = enc.Close()
		}
		if lw.overflow {
			return nil, fmt.Errorf("to_yaml: output exceeds %d bytes", maxStringBytes)
		}
		if err != nil {
			return nil, err
		}
		// Marshal can amplify a wide-but-in-budget value well past
		// the string cap (quotes, indentation, line breaks). Fail
		// instead of returning an unbounded document — the same
		// contract |join / |regex_replace / ~ already honor.
		if err := outputSizeCap(lw.b.Len(), "to_yaml"); err != nil {
			return nil, err
		}
		return lw.b.String(), nil
	case "b64decode":
		raw := strings.TrimSpace(Stringify(v))
		maxEnc := base64.StdEncoding.EncodedLen(maxStringBytes)
		if len(raw) > maxEnc*2 || (len(raw) > maxEnc && !strings.ContainsAny(raw, "\r\n")) {
			return nil, fmt.Errorf("b64decode: output exceeds %d bytes", maxStringBytes)
		}
		b, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, err
		}
		if err := outputSizeCap(len(b), "b64decode"); err != nil {
			return nil, err
		}
		return string(b), nil
	case "b64encode":
		s := Stringify(v)
		if len(s) > maxStringBytes {
			return nil, fmt.Errorf("b64encode: output exceeds %d bytes", maxStringBytes)
		}
		encLen := base64.StdEncoding.EncodedLen(len(s))
		if err := outputSizeCap(encLen, "b64encode"); err != nil {
			return nil, err
		}
		var sb strings.Builder
		sb.Grow(encLen)
		var inBuf [49152]byte // multiple of 3 -> no mid-stream padding
		var outBuf [65536]byte
		for off := 0; off < len(s); {
			n := copy(inBuf[:], s[off:])
			m := base64.StdEncoding.EncodedLen(n)
			base64.StdEncoding.Encode(outBuf[:m], inBuf[:n])
			sb.Write(outBuf[:m])
			off += n
		}
		return sb.String(), nil
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
		s := Stringify(v)
		if len(s) > maxStringBytes {
			return nil, fmt.Errorf("indent: output exceeds %d bytes", maxStringBytes)
		}
		// Output ≈ input + pad per indented line — a 16MiB input of
		// short lines (or newlines) under a 10KB indent is GiB-scale.
		// Count padded lines via strings.Count/scan BEFORE any split
		// or builder allocation so a 16 MiB string of '\n' cannot
		// allocate ~268 MiB before failing maxStringBytes.
		padded := 1 // first line is always indented
		if len(pad) > 0 {
			if blank {
				padded += strings.Count(s, "\n")
			} else {
				for i := 0; i < len(s); {
					nl := strings.IndexByte(s[i:], '\n')
					if nl < 0 {
						break
					}
					idx := i + nl
					if idx+1 < len(s) && s[idx+1] != '\n' {
						padded++
					}
					i = idx + 1
				}
			}
			if padded > (maxStringBytes-len(s))/len(pad) {
				return nil, fmt.Errorf("indent: output exceeds %d bytes", maxStringBytes)
			}
		}
		var sb strings.Builder
		sb.Grow(len(s) + padded*len(pad))
		sb.WriteString(pad)
		first := true
		for i := 0; ; {
			nl := strings.IndexByte(s[i:], '\n')
			if nl < 0 {
				ln := s[i:]
				if !first && (ln != "" || blank) {
					sb.WriteString(pad)
				}
				sb.WriteString(ln)
				break
			}
			ln := s[i : i+nl]
			if !first && (ln != "" || blank) {
				sb.WriteString(pad)
			}
			sb.WriteString(ln)
			sb.WriteByte('\n')
			first = false
			i += nl + 1
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

const (
	regexLeftFree  = 0 // no ^ / \A / (?m)^ / \b / \B anywhere: safe for incremental s[pos:]
	regexLeftBegin = 1 // must start at text begin (pos == 0): at most one match via FindStringSubmatchIndex(s)
	regexLeftFull  = 2 // general left-context assertion ((?m)^, \b, \B, a|^b): bounded FindAll
)

func hasLeftAnchor(r *syntax.Regexp) bool {
	switch r.Op {
	case syntax.OpBeginText, syntax.OpBeginLine, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return true
	}
	for _, sub := range r.Sub {
		if hasLeftAnchor(sub) {
			return true
		}
	}
	return false
}

func mustStartAtTextBegin(r *syntax.Regexp) bool {
	switch r.Op {
	case syntax.OpBeginText:
		return true
	case syntax.OpCapture, syntax.OpPlus:
		return len(r.Sub) > 0 && mustStartAtTextBegin(r.Sub[0])
	case syntax.OpRepeat:
		return r.Min >= 1 && len(r.Sub) > 0 && mustStartAtTextBegin(r.Sub[0])
	case syntax.OpConcat:
		return len(r.Sub) > 0 && mustStartAtTextBegin(r.Sub[0])
	case syntax.OpAlternate:
		if len(r.Sub) == 0 {
			return false
		}
		for _, sub := range r.Sub {
			if !mustStartAtTextBegin(sub) {
				return false
			}
		}
		return true
	}
	return false
}

func classifyRegexReplace(pat string, hasExpand bool) (mode int, lit string, isLit, isEmpty, isLinePrefix bool) {
	if !hasExpand && !strings.ContainsAny(pat, `^$\.*+?()[]{}|`) {
		if !strings.ContainsRune(pat, utf8.RuneError) && pat != "" {
			return regexLeftFree, pat, true, false, false
		}
	}
	ast, err := syntax.Parse(pat, syntax.Perl)
	if err != nil {
		return regexLeftFull, "", false, false, false
	}
	if ast.Op == syntax.OpEmptyMatch {
		return regexLeftFree, "", false, true, false
	}
	if !hasExpand {
		litNode := ast
		if litNode.Op == syntax.OpCapture && len(litNode.Sub) == 1 {
			litNode = litNode.Sub[0]
		}
		if litNode.Op == syntax.OpLiteral && (litNode.Flags&syntax.FoldCase) == 0 && len(litNode.Rune) > 0 {
			s := string(litNode.Rune)
			if !strings.ContainsRune(s, utf8.RuneError) {
				return regexLeftFree, s, true, false, false
			}
		}
		if ast.Op == syntax.OpConcat && len(ast.Sub) == 2 && ast.Sub[0].Op == syntax.OpBeginLine {
			sub := ast.Sub[1]
			if sub.Op == syntax.OpCapture && len(sub.Sub) == 1 {
				sub = sub.Sub[0]
			}
			if sub.Op == syntax.OpLiteral && (sub.Flags&syntax.FoldCase) == 0 && len(sub.Rune) > 0 {
				s := string(sub.Rune)
				if !strings.ContainsRune(s, utf8.RuneError) && !strings.ContainsRune(s, '\n') {
					return regexLeftFull, s, false, false, true
				}
			}
		}
	}
	if !hasLeftAnchor(ast) {
		return regexLeftFree, "", false, false, false
	}
	if mustStartAtTextBegin(ast) {
		return regexLeftBegin, "", false, false, false
	}
	return regexLeftFull, "", false, false, false
}

func singleLiteralCapture(pat string) (string, bool) {
	ast, err := syntax.Parse(pat, syntax.Perl)
	if err != nil || ast.Op != syntax.OpCapture || len(ast.Sub) != 1 {
		return "", false
	}
	sub := ast.Sub[0]
	if sub.Op != syntax.OpLiteral || (sub.Flags&syntax.FoldCase) != 0 || len(sub.Rune) == 0 {
		return "", false
	}
	s := string(sub.Rune)
	if strings.ContainsRune(s, utf8.RuneError) {
		return "", false
	}
	return s, true
}

func replaceLiteralBounded(s, lit, repl string) (string, error) {
	n := strings.Count(s, lit)
	if n == 0 {
		return s, nil
	}
	diff := len(repl) - len(lit)
	if diff > 0 {
		if n > (maxStringBytes-len(s))/diff {
			return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
		}
	} else if len(s)+n*diff > maxStringBytes {
		return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
	}
	return strings.ReplaceAll(s, lit, repl), nil
}

func replaceEmptyBounded(s, repl string) (string, error) {
	nMatches := utf8.RuneCountInString(s) + 1
	if nMatches > maxSeqElems {
		return "", fmt.Errorf("regex_replace: match count exceeds %d", maxSeqElems)
	}
	if len(repl) > 0 && nMatches > (maxStringBytes-len(s))/len(repl) {
		return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
	}
	var b strings.Builder
	b.Grow(len(s) + nMatches*len(repl))
	for i := 0; i < len(s); {
		b.WriteString(repl)
		_, w := utf8.DecodeRuneInString(s[i:])
		if w <= 0 {
			w = 1
		}
		b.WriteString(s[i : i+w])
		i += w
	}
	b.WriteString(repl)
	return b.String(), nil
}

func replaceLinePrefixLiteralBounded(s, lit, repl string) (string, error) {
	var b strings.Builder
	last := 0
	pos := 0
	matches := 0
	for pos <= len(s) {
		if strings.HasPrefix(s[pos:], lit) {
			matches++
			if matches > maxSeqElems {
				return "", fmt.Errorf("regex_replace: match count exceeds %d", maxSeqElems)
			}
			if b.Len()+(pos-last)+len(repl) > maxStringBytes {
				return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
			}
			if matches == 1 {
				b.Grow(min(len(s)+64, maxStringBytes))
			}
			b.WriteString(s[last:pos])
			b.WriteString(repl)
			last = pos + len(lit)
			pos = last
		}
		nl := strings.IndexByte(s[pos:], '\n')
		if nl < 0 {
			break
		}
		pos += nl + 1
	}
	if matches == 0 {
		return s, nil
	}
	if b.Len()+(len(s)-last) > maxStringBytes {
		return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
	}
	b.WriteString(s[last:])
	return b.String(), nil
}

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

// regexReplaceBounded replaces matches incrementally without materializing an
// unbounded [][]int match slice, enforcing maxStringBytes before writes.
func regexReplaceBounded(entry *regexEntry, s, repl string) (string, error) {
	re := entry.re
	hasExpand := strings.ContainsRune(repl, '$')
	cls := entry.noExpand
	if hasExpand {
		cls = entry.withExpand
	}
	mode, lit, isLit, isEmpty, isLinePrefix := cls.mode, cls.lit, cls.isLit, cls.isEmpty, cls.isLinePrefix
	if isLit {
		return replaceLiteralBounded(s, lit, repl)
	}
	if isEmpty && !hasExpand {
		return replaceEmptyBounded(s, repl)
	}
	if isLinePrefix {
		return replaceLinePrefixLiteralBounded(s, lit, repl)
	}

	const batchSize = 4096
	var b strings.Builder
	last := 0
	var exp []byte
	totalMatches := 0

	switch mode {
	case regexLeftFree:
		b.Grow(min(len(s)+64, 64<<10))
		pos := 0
		prevMatchEnd := -1
		for pos <= len(s) {
			var batch [][]int
			if hasExpand {
				batch = re.FindAllStringSubmatchIndex(s[pos:], batchSize)
			} else {
				batch = re.FindAllStringIndex(s[pos:], batchSize)
			}
			if len(batch) == 0 {
				break
			}
			startPos := pos
			for i, m := range batch {
				for k := range m {
					if m[k] >= 0 {
						m[k] += startPos
					}
				}
				if i == 0 && m[1] == startPos && m[0] == prevMatchEnd {
					continue
				}
				totalMatches++
				if totalMatches > maxSeqElems {
					return "", fmt.Errorf("regex_replace: match count exceeds %d", maxSeqElems)
				}
				if b.Len()+(m[0]-last) > maxStringBytes {
					return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
				}
				b.WriteString(s[last:m[0]])
				if !hasExpand {
					if b.Len()+len(repl) > maxStringBytes {
						return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
					}
					b.WriteString(repl)
				} else {
					exp = re.ExpandString(exp[:0], repl, s, m)
					if b.Len()+len(exp) > maxStringBytes {
						return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
					}
					b.Write(exp)
				}
				last = m[1]
			}
			if len(batch) < batchSize {
				break
			}
			lastM := batch[len(batch)-1]
			prevMatchEnd = lastM[1]
			if lastM[0] == lastM[1] {
				if lastM[1] == len(s) {
					pos = len(s) + 1
				} else {
					_, w := utf8.DecodeRuneInString(s[lastM[1]:])
					if w <= 0 {
						w = 1
					}
					pos = lastM[1] + w
				}
			} else {
				pos = lastM[1]
			}
		}
	case regexLeftBegin:
		b.Grow(min(len(s)+64, maxStringBytes))
		var m []int
		if hasExpand {
			m = re.FindStringSubmatchIndex(s)
		} else {
			m = re.FindStringIndex(s)
		}
		if m != nil {
			if b.Len()+(m[0]-last) > maxStringBytes {
				return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
			}
			b.WriteString(s[last:m[0]])
			if !hasExpand {
				if b.Len()+len(repl) > maxStringBytes {
					return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
				}
				b.WriteString(repl)
			} else {
				exp = re.ExpandString(exp[:0], repl, s, m)
				if b.Len()+len(exp) > maxStringBytes {
					return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
				}
				b.Write(exp)
			}
			last = m[1]
		}
	default:
		var matches [][]int
		if hasExpand {
			matches = re.FindAllStringSubmatchIndex(s, maxSeqElems+1)
		} else {
			matches = re.FindAllStringIndex(s, maxSeqElems+1)
		}
		if len(matches) > maxSeqElems {
			return "", fmt.Errorf("regex_replace: match count exceeds %d", maxSeqElems)
		}
		b.Grow(min(len(s)+64, maxStringBytes))
		for _, m := range matches {
			if b.Len()+(m[0]-last) > maxStringBytes {
				return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
			}
			b.WriteString(s[last:m[0]])
			if !hasExpand {
				if b.Len()+len(repl) > maxStringBytes {
					return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
				}
				b.WriteString(repl)
			} else {
				exp = re.ExpandString(exp[:0], repl, s, m)
				if b.Len()+len(exp) > maxStringBytes {
					return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
				}
				b.Write(exp)
			}
			last = m[1]
		}
	}

	if b.Len()+(len(s)-last) > maxStringBytes {
		return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
	}
	b.WriteString(s[last:])
	return b.String(), nil
}

// regexFindallBounded evaluates |regex_findall while rejecting match counts >
// maxSeqElems without allocating 1,000,001 per-match []string submatch slices.
func regexFindallBounded(entry *regexEntry, s string) (*List, error) {
	re := entry.re
	mode, lit, isLit, isEmpty := entry.noExpand.mode, entry.noExpand.lit, entry.noExpand.isLit, entry.noExpand.isEmpty
	if re.NumSubexp() == 0 {
		if isLit {
			n := strings.Count(s, lit)
			if n > maxSeqElems {
				return nil, fmt.Errorf("regex_findall: match count exceeds %d", maxSeqElems)
			}
			if n == 0 {
				return &List{}, nil
			}
			out := make([]any, n)
			for i := range out {
				out[i] = lit
			}
			return &List{out}, nil
		}
		if mode == regexLeftFree && !isEmpty {
			const batchSize = 4096
			var out []any
			pos := 0
			prevMatchEnd := -1
			for pos <= len(s) {
				batch := re.FindAllStringIndex(s[pos:], batchSize)
				if len(batch) == 0 {
					break
				}
				startPos := pos
				for i, m := range batch {
					m0, m1 := m[0]+startPos, m[1]+startPos
					if i == 0 && m1 == startPos && m0 == prevMatchEnd {
						continue
					}
					if len(out) >= maxSeqElems {
						return nil, fmt.Errorf("regex_findall: match count exceeds %d", maxSeqElems)
					}
					out = append(out, s[m0:m1])
				}
				if len(batch) < batchSize {
					break
				}
				lastM := batch[len(batch)-1]
				prevMatchEnd = lastM[1] + startPos
				if lastM[0] == lastM[1] {
					if prevMatchEnd == len(s) {
						pos = len(s) + 1
					} else {
						_, w := utf8.DecodeRuneInString(s[prevMatchEnd:])
						if w <= 0 {
							w = 1
						}
						pos = prevMatchEnd + w
					}
				} else {
					pos = prevMatchEnd
				}
			}
			if len(out) == 0 {
				return &List{}, nil
			}
			return &List{out}, nil
		}
		strs := re.FindAllString(s, maxSeqElems+1)
		if len(strs) > maxSeqElems {
			return nil, fmt.Errorf("regex_findall: match count exceeds %d", maxSeqElems)
		}
		if len(strs) == 0 {
			return &List{}, nil
		}
		out := make([]any, len(strs))
		for i, m := range strs {
			out[i] = m
		}
		return &List{out}, nil
	}

	if re.NumSubexp() == 1 {
		if entry.hasLitCap {
			lit := entry.litCapture
			n := strings.Count(s, lit)
			if n > maxSeqElems {
				return nil, fmt.Errorf("regex_findall: match count exceeds %d", maxSeqElems)
			}
			if n == 0 {
				return &List{}, nil
			}
			out := make([]any, n)
			for i := range out {
				out[i] = lit
			}
			return &List{out}, nil
		}
	}

	if mode == regexLeftFree && !isEmpty {
		const batchSize = 4096
		var out []any
		pos := 0
		prevMatchEnd := -1
		for pos <= len(s) {
			batch := re.FindAllStringSubmatchIndex(s[pos:], batchSize)
			if len(batch) == 0 {
				break
			}
			startPos := pos
			for i, m := range batch {
				m0, m1 := m[0]+startPos, m[1]+startPos
				if i == 0 && m1 == startPos && m0 == prevMatchEnd {
					continue
				}
				if len(out) >= maxSeqElems {
					return nil, fmt.Errorf("regex_findall: match count exceeds %d", maxSeqElems)
				}
				switch {
				case len(m) > 4:
					grps := make([]any, 0, len(m)/2-1)
					for k := 2; k < len(m); k += 2 {
						if m[k] >= 0 {
							grps = append(grps, s[m[k]+startPos:m[k+1]+startPos])
						} else {
							grps = append(grps, "")
						}
					}
					out = append(out, &List{grps})
				case len(m) == 4:
					if m[2] >= 0 {
						out = append(out, s[m[2]+startPos:m[3]+startPos])
					} else {
						out = append(out, "")
					}
				default:
					out = append(out, s[m0:m1])
				}
			}
			if len(batch) < batchSize {
				break
			}
			lastM := batch[len(batch)-1]
			prevMatchEnd = lastM[1] + startPos
			if lastM[0] == lastM[1] {
				if prevMatchEnd == len(s) {
					pos = len(s) + 1
				} else {
					_, w := utf8.DecodeRuneInString(s[prevMatchEnd:])
					if w <= 0 {
						w = 1
					}
					pos = prevMatchEnd + w
				}
			} else {
				pos = prevMatchEnd
			}
		}
		if len(out) == 0 {
			return &List{}, nil
		}
		return &List{out}, nil
	}

	// Capture groups present with left anchor: count matches with FindAllString first
	// so inputs exceeding maxSeqElems fail without allocating 1,000,001 []string slices.
	strs := re.FindAllString(s, maxSeqElems+1)
	if len(strs) > maxSeqElems {
		return nil, fmt.Errorf("regex_findall: match count exceeds %d", maxSeqElems)
	}
	if len(strs) == 0 {
		return &List{}, nil
	}
	matches := re.FindAllStringSubmatch(s, len(strs))
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
}
