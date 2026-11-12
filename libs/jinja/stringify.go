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
	"slices"
	"strconv"
	"strings"
)

// Stringify renders v in python repr style: True/False/None,
// "[a, b]" lists, "{'k': v}" mappings (OMap insertion order, plain
// maps sorted). Depth- and step-budgeted against cyclic values —
// past either cap a "[...]" marks the elided tail.
func Stringify(v any) string {
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
	default:
		// Scalars (and non-jinja container types) marshal exactly
		// as encoding/json handled them before — including HTML
		// escaping and json.Marshaler support.
		bb, err := json.Marshal(v)
		if err != nil {
			return err
		}
		b.Write(bb)
		return nil
	}
}

// writeJSONMap emits {"k":v,...} walking keys in the given order.
func writeJSONMap(keys []string, get func(string) any, b *strings.Builder, depth int, steps *int) error {
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return err
		}
		b.Write(kb)
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
