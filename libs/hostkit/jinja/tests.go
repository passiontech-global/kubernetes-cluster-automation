// tests.go — the `is <test>` predicate dispatch (runTest), the
// engine's ansible test-plugin surface.
package jinja

import (
	"fmt"
	"log/slog"
	"regexp"
)

// ---------------- tests ----------------

func runTest(name string, v any, args []any) (bool, error) {
	switch name {
	case "defined":
		return !IsNilOrUndef(v), nil
	case "undefined":
		_, u := v.(Undefined)
		return u, nil
	case "none":
		return v == nil, nil
	case "mapping":
		_, ok := v.(*OMap)
		return ok, nil
	case "iterable", "sequence":
		switch v.(type) {
		case []any, *List, *OMap, string:
			return true, nil
		}
		return false, nil
	case "string":
		_, ok := v.(string)
		return ok, nil
	case "number":
		return isNum(v), nil
	case "boolean", "bool":
		_, ok := v.(bool)
		return ok, nil
	case "search":
		if len(args) == 0 {
			return false, nil
		}
		re, err := regexp.Compile(Stringify(args[0]))
		if err != nil {
			// an unparseable pattern is no match, not a template error
			slog.Debug("jinja: search pattern does not compile — no match",
				"pattern", Stringify(args[0]), "error", err)
			return false, nil
		}
		return re.MatchString(Stringify(v)), nil
	case "equalto", "eq":
		if len(args) == 0 {
			return false, nil
		}
		return deepEq(v, args[0]), nil
	case "sameas":
		if len(args) == 0 {
			return false, nil
		}
		return deepEq(v, args[0]), nil
	case "changed", "failed", "succeeded", "skipped":
		return false, nil
	case "in":
		if len(args) == 0 {
			return false, nil
		}
		r, _ := binOp("in", v, args[0])
		b, _ := r.(bool)
		return b, nil
	}
	// Unknown test name — almost always a typo (is defind), and
	// evaluating it was actively dangerous: false + `is not`
	// negated to TRUE and silently opened the gate. Jinja raises
	// "no test named"; do the same.
	return false, fmt.Errorf("no test named %q", name)
}
