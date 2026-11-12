// filters_select.go — the map/select/reject filter family:
// attribute-path walking (selectAttrKey) plus per-item
// filter/test application over an iterable.
package jinja

import (
	"errors"
	"slices"
	"strings"
)

func filterMap(v any, args []any, kw map[string]any, s *scope) (any, error) {
	// map(attribute='x'[, default=y]) — presence decides, not
	// nil-ness: default=none maps missing attributes to a literal
	// None, which the old kw["default"] != nil check dropped.
	if attr, ok := kw["attribute"]; ok {
		_, hasDefault := kw["default"]
		var out []any
		for _, it := range ToIter(v) {
			got := selectAttrKey(it, Stringify(attr))
			if _, u := got.(Undefined); u && hasDefault {
				got = kw["default"]
			}
			out = append(out, got)
		}
		return &List{out}, nil
	}
	if len(args) == 0 {
		// Clone like `|list` — ToIter hands back the LIVE backing
		// slice; wrapping it unchecked aliases the caller's value.
		return &List{slices.Clone(ToIter(v))}, nil
	}
	name := Stringify(args[0])
	// map('basename') / map('regex_replace', p, r) — filter by name.
	// kw travels with the call so keyword-taking filters (e.g.
	// map('default', x, default=none)) keep working. Only an
	// UNKNOWN filter falls back to the attribute/method read: a
	// runtime error inside a known filter (bad regex, bad JSON,
	// divide by zero) must surface, not degrade to Undefined.
	var out []any
	for _, it := range ToIter(v) {
		fv, err := applyFilter(name, it, args[1:], kw, s)
		if err != nil {
			if errors.Is(err, errUnknownFilter) {
				out = append(out, getAttr(it, name))
				continue
			}
			return nil, err
		}
		out = append(out, fv)
	}
	return &List{out}, nil
}

func selectAttrKey(v any, path string) any {
	cur := v
	for _, seg := range strings.Split(path, ".") {
		cur = getAttr(cur, seg)
		if _, u := cur.(Undefined); u {
			return cur
		}
	}
	return cur
}

func filterSelectAttr(v any, args []any, keep bool) (any, error) {
	if len(args) == 0 {
		return &List{slices.Clone(ToIter(v))}, nil
	}
	path := Stringify(args[0])
	testName := ""
	var testArgs []any
	if len(args) > 1 {
		testName = Stringify(args[1])
		testArgs = args[2:]
	}
	var out []any
	for _, it := range ToIter(v) {
		val := selectAttrKey(it, path)
		var ok bool
		if testName == "" {
			ok = Truthy(val)
		} else {
			var err error
			ok, err = runTest(testName, val, testArgs)
			if err != nil {
				return nil, err
			}
		}
		if ok == keep {
			out = append(out, it)
		}
	}
	return &List{out}, nil
}

func filterTest(v any, args []any, keep bool) (any, error) {
	var out []any
	if len(args) == 0 {
		// select/reject with no test filters on truthiness —
		// `x | select` keeps Truthy items, `| reject` drops them
		// (previously the whole list passed through unchanged).
		for _, it := range ToIter(v) {
			if Truthy(it) == keep {
				out = append(out, it)
			}
		}
		return &List{out}, nil
	}
	testName := Stringify(args[0])
	for _, it := range ToIter(v) {
		ok, err := runTest(testName, it, args[1:])
		if err != nil {
			return nil, err
		}
		if ok == keep {
			out = append(out, it)
		}
	}
	return &List{out}, nil
}
