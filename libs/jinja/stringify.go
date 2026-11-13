// stringify.go — the value→text writers: Stringify's python-repr
// (writeStringify/writeStringifyAt) and the JSON document writer
// (writeJSONAt) behind to_json. Both thread ONE *strings.Builder
// through the whole recursion so a {{ }} render or a to_json call
// never materializes a string/[]byte per node only to copy it into
// the output.
package jinja

import (
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Stringify renders v in python repr style: True/False/None,
// "[a, b]" lists, "{'k': v}" mappings (OMap insertion order, plain
// maps sorted). Depth- and step-budgeted against cyclic values —
// past either cap a "[...]" marks the elided tail.
func Stringify(v any) string {
	// Scalar fast path — the dominant render shapes (string, bool,
	// int64, float64, nil/Undefined) stringify without touching the
	// Builder at all; containers still take the budgeted writer.
	switch t := v.(type) {
	case nil:
		return "None"
	case Undefined:
		return ""
	case string:
		return t
	case bool:
		if t {
			return "True"
		}
		return "False"
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		// Mirrors writeStringifyAt's float64 arm exactly.
		if i, ok := floatToInt64(t); ok && t == float64(i) {
			return strconv.FormatInt(i, 10)
		}
		return strconv.FormatFloat(t, 'g', -1, 64)
	}
	var b strings.Builder
	writeStringify(v, &b)
	return b.String()
}

// writeStringify is Stringify's builder-threaded form —
// exprNode.render calls it directly so a {{ }} never pays an
// intermediate string alloc + copy.
func writeStringify(v any, b *strings.Builder) {
	steps := 0
	writeStringifyAt(v, b, 0, &steps)
}

// writeStringifyAt is stringifyAt's builder-threaded form, under the
// same walkMaxDepth recursion budget AND walkMaxSteps total-step
// budget — a cyclic *List is constructible in-template ({% set _ =
// l.append(l) %}) and unbounded recursion would burst the goroutine
// stack, while a branching cycle doubles the work per level without
// ever deepening. Past either cap a python-style "[...]" marks the
// elided tail (the budget bail degrades instead of erroring —
// Stringify's signature is public API).
func writeStringifyAt(v any, b *strings.Builder, depth int, steps *int) {
	if depth > walkMaxDepth || stepBudgetExhausted(steps) {
		b.WriteString("[...]")
		return
	}
	switch t := v.(type) {
	case nil:
		b.WriteString("None")
		return
	case Undefined:
		return // renders ""
	case bool:
		if t {
			b.WriteString("True")
		} else {
			b.WriteString("False")
		}
		return
	case int64:
		b.WriteString(strconv.FormatInt(t, 10))
		return
	case float64:
		// floatToInt64, not int64(t): NaN/±Inf/out-of-range used to
		// truncate into platform garbage (usually MinInt64).
		if i, ok := floatToInt64(t); ok && t == float64(i) {
			b.WriteString(strconv.FormatInt(i, 10))
		} else {
			b.WriteString(strconv.FormatFloat(t, 'g', -1, 64))
		}
		return
	case string:
		b.WriteString(t)
		return
	case []string:
		// Fast path ahead of the generic fallthrough: a Go-native
		// string slice renders exactly like []any of strings
		// (verbatim elements, ", " joined) — previously it fell to
		// fmt.Sprint's "[a b]" repr, inconsistent with every other
		// sequence shape.
		b.WriteByte('[')
		for i, x := range t {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(x)
		}
		b.WriteByte(']')
		return
	case []any:
		b.WriteByte('[')
		for i, x := range t {
			if i > 0 {
				b.WriteString(", ")
			}
			writeStringifyAt(x, b, depth+1, steps)
		}
		b.WriteByte(']')
		return
	case *List:
		if t == nil {
			b.WriteString("[]")
			return
		}
		writeStringifyAt(t.V, b, depth+1, steps)
		return
	case *OMap:
		b.WriteByte('{')
		for i, k := range t.Keys() {
			if i > 0 {
				b.WriteString(", ")
			}
			vv, _ := t.Get(k)
			b.WriteByte('\'')
			b.WriteString(k)
			b.WriteString("': ")
			writeStringifyAt(vv, b, depth+1, steps)
		}
		b.WriteByte('}')
		return
	case map[string]any:
		writeStringifyMap(t, b, depth, steps)
		return
	case map[string]string:
		writeStringifyMap(t, b, depth, steps)
		return
	}
	if i, ok := asInt64(v); ok {
		b.WriteString(strconv.FormatInt(i, 10))
		return
	}
	if u, ok := asUint64(v); ok {
		b.WriteString(strconv.FormatUint(u, 10))
		return
	}
	b.WriteString(fmt.Sprint(v))
}

// writeStringifyMap renders a plain Go string map like an *OMap —
// keys sorted for deterministic output (Go map order is random).
func writeStringifyMap[V any](m map[string]V, b *strings.Builder, depth int, steps *int) {
	keys := slices.Sorted(maps.Keys(m))
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteByte('\'')
		b.WriteString(k)
		b.WriteString("': ")
		writeStringifyAt(m[k], b, depth+1, steps)
	}
	b.WriteByte('}')
}

// ---------------- to_json writer ----------------

// writeJSONAt renders v as a JSON document directly into b — the
// builder-threaded form of the old jsonValueAt/jsonObjectAt/
// jsonListAt chain, which allocated a []byte (and a Builder) per
// node. *OMap insertion order is preserved — routing through
// map[string]any + encoding/json would sort the keys and silently
// reorder the mappings these filters regenerate.
func writeJSONAt(v any, b *strings.Builder, depth int, steps *int) error {
	if depth > walkMaxDepth {
		// A cyclic value can't be marshaled anyway — a "[...]"
		// string placeholder keeps the document marshal-safe.
		b.WriteString(`"[...]"`)
		return nil
	}
	if stepBudgetExhausted(steps) {
		return fmt.Errorf("json: value walk exceeds %d steps (exponentially branching value?)", walkMaxSteps)
	}
	switch t := v.(type) {
	case *OMap:
		return writeJSONMap(t.Keys(), func(k string) any {
			vv, _ := t.Get(k)
			return vv
		}, b, depth, steps)
	case *List:
		if t == nil {
			return writeJSONList(nil, b, depth, steps)
		}
		return writeJSONList(t.V, b, depth, steps)
	case []any:
		return writeJSONList(t, b, depth, steps)
	case map[string]any:
		// Plain Go maps carry no order — sort keys for deterministic
		// output, same as encoding/json did.
		return writeJSONMap(slices.Sorted(maps.Keys(t)), func(k string) any { return t[k] }, b, depth, steps)
	case map[string]string:
		return writeJSONMap(slices.Sorted(maps.Keys(t)), func(k string) any { return t[k] }, b, depth, steps)
	case Undefined:
		b.WriteString("null")
		return nil
	}

	// Scalar fast path — the engine's scalar shapes written straight
	// into b, byte-identical to what json.Marshal emits for them but
	// with no intermediate []byte (and no reflect walk) per node.
	switch s := v.(type) {
	case nil:
		b.WriteString("null")
		return nil
	case bool:
		if s {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
		return nil
	case string:
		writeJSONString(s, b)
		return nil
	case int64:
		b.WriteString(strconv.FormatInt(s, 10))
		return nil
	case float64:
		if writeJSONFloat(b, s) {
			return nil
		}
		// NaN/±Inf defer to the generic encoder below so its exact
		// UnsupportedValueError stays the observable failure.
	case int, int8, int16, int32, uint, uint8, uint16, uint32, uint64:
		// Every Go integer width marshals as plain decimal, exactly
		// what json.Marshal prints for these kinds.
		if i, ok := asInt64(s); ok {
			b.WriteString(strconv.FormatInt(i, 10))
			return nil
		}
		if u, ok := asUint64(s); ok {
			b.WriteString(strconv.FormatUint(u, 10))
			return nil
		}
	}
	// Non-jinja container types (and the scalars the fast path
	// defers) marshal exactly as encoding/json handled them before —
	// including HTML escaping and json.Marshaler support.
	bb, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b.Write(bb)
	return nil
}

// writeJSONMap emits {"k":v,...} walking keys in the given order.
func writeJSONMap(keys []string, get func(string) any, b *strings.Builder, depth int, steps *int) error {
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		writeJSONString(k, b)
		b.WriteByte(':')
		if err := writeJSONAt(get(k), b, depth+1, steps); err != nil {
			return err
		}
	}
	b.WriteByte('}')
	return nil
}

func writeJSONList(items []any, b *strings.Builder, depth int, steps *int) error {
	b.WriteByte('[')
	for i, x := range items {
		if i > 0 {
			b.WriteByte(',')
		}
		if err := writeJSONAt(x, b, depth+1, steps); err != nil {
			return err
		}
	}
	b.WriteByte(']')
	return nil
}

// jsonHTMLSafe marks the ASCII bytes json.Marshal's HTML-escaped
// string encoder passes through verbatim: 0x20–0x7F minus `"`, `&`,
// `<`, `>` and `\` (encoding/json's htmlSafeSet under its default
// escapeHTML=true). Bytes ≥ 0x80 never index it — they go through
// the UTF-8 decode path.
var jsonHTMLSafe = func() [utf8.RuneSelf]bool {
	var set [utf8.RuneSelf]bool
	for c := 0x20; c < utf8.RuneSelf; c++ {
		set[c] = true
	}
	for _, c := range []byte{'"', '&', '<', '>', '\\'} {
		set[c] = false
	}
	return set
}()

const jsonHexDigits = "0123456789abcdef"

// writeJSONString writes s as a JSON string exactly as
// encoding/json's default (HTML-escaping) encoder does — `<`/`>`/`&`
// as \u003c/\u003e/\u0026, \u2028/\u2029 escaped for JSONP safety,
// control chars short-escaped (\n \r \t \b \f) or \u00XX, invalid
// UTF-8 bytes as \ufffd, everything else verbatim. Straight into b:
// no intermediate []byte per string.
func writeJSONString(s string, b *strings.Builder) {
	b.WriteByte('"')
	start := 0
	for i := 0; i < len(s); {
		if c := s[i]; c < utf8.RuneSelf {
			if jsonHTMLSafe[c] {
				i++
				continue
			}
			if start < i {
				b.WriteString(s[start:i])
			}
			b.WriteByte('\\')
			switch c {
			case '\\', '"':
				b.WriteByte(c)
			case '\b':
				b.WriteByte('b')
			case '\f':
				b.WriteByte('f')
			case '\n':
				b.WriteByte('n')
			case '\r':
				b.WriteByte('r')
			case '\t':
				b.WriteByte('t')
			default:
				b.WriteString(`u00`)
				b.WriteByte(jsonHexDigits[c>>4])
				b.WriteByte(jsonHexDigits[c&0xF])
			}
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			if start < i {
				b.WriteString(s[start:i])
			}
			// The invalid byte becomes the replacement CHARACTER in
			// raw UTF-8 (ef bf bd) — this toolchain's encoder writes
			// the rune itself, not the old \\ufffd escape.
			b.WriteRune(utf8.RuneError)
			i += size
			start = i
			continue
		}
		// U+2028 (LINE SEPARATOR) and U+2029 (PARAGRAPH SEPARATOR)
		// are valid JSON but break JSONP — escaped unconditionally,
		// like encoding/json.
		if r == '\u2028' || r == '\u2029' {
			if start < i {
				b.WriteString(s[start:i])
			}
			b.WriteString(`\u202`)
			b.WriteByte(jsonHexDigits[r&0xF])
			i += size
			start = i
		} else {
			i += size
		}
	}
	if start < len(s) {
		b.WriteString(s[start:])
	}
	b.WriteByte('"')
}

// writeJSONFloat writes f exactly as encoding/json's floatEncoder
// does: shortest round-trip form, 'f' while |f| ∈ [1e-6, 1e21),
// shortest 'e' outside that window with the exponent's leading zero
// stripped (e-09 → e-9). Reports false for NaN/±Inf — those have no
// JSON form and defer to the generic encoder for its exact
// UnsupportedValueError.
func writeJSONFloat(b *strings.Builder, f float64) bool {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return false
	}
	format := byte('f')
	if abs := math.Abs(f); abs != 0 && (abs < 1e-6 || abs >= 1e21) {
		format = 'e'
	}
	var scratch [32]byte
	out := strconv.AppendFloat(scratch[:0], f, format, -1, 64)
	if format == 'e' {
		// clean up e-09 to e-9
		n := len(out)
		if n >= 4 && out[n-4] == 'e' && out[n-3] == '-' && out[n-2] == '0' {
			out[n-2] = out[n-1]
			out = out[:n-1]
		}
	}
	b.Write(out)
	return true
}
