package jinja

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	yaml3 "go.yaml.in/yaml/v3"
)

// ---------------- filters ----------------

func applyFilter(name string, v any, args []any, kw map[string]any, s *scope) (any, error) {
	switch name {
	case "default", "d":
		var def any
		if len(args) > 0 {
			def = args[0]
		}
		useBool := len(args) > 1 && Truthy(args[1])
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
		return &List{ToIter(v)}, nil
	case "length", "count":
		switch t := v.(type) {
		case string:
			return int64(len(t)), nil
		case []any:
			return int64(len(t)), nil
		case *List:
			return int64(len(t.V)), nil
		case *OMap:
			return int64(t.Len()), nil
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
		l := append([]any{}, ToIter(v)...)
		sort.SliceStable(l, func(i, j int) bool {
			if isNum(l[i]) && isNum(l[j]) {
				fi, _ := toFloat(l[i])
				fj, _ := toFloat(l[j])
				return fi < fj
			}
			if lp, ok := l[i].(*List); ok {
				if rp, ok := l[j].(*List); ok && len(lp.V) > 0 && len(rp.V) > 0 {
					return Stringify(lp.V[0]) < Stringify(rp.V[0])
				}
			}
			return Stringify(l[i]) < Stringify(l[j])
		})
		return &List{l}, nil
	case "unique":
		seen := map[string]bool{}
		var out []any
		for _, it := range ToIter(v) {
			k := Stringify(it)
			if !seen[k] {
				seen[k] = true
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
		var out []any
		out = append(out, ToIter(v)...)
		for _, a := range args {
			out = append(out, ToIter(a)...)
		}
		return &List{out}, nil
	case "dict2items":
		if om, ok := v.(*OMap); ok {
			return &List{om.Items()}, nil
		}
		return &List{}, nil
	case "items2dict":
		m := NewOMap()
		for _, it := range ToIter(v) {
			if om, ok := it.(*OMap); ok {
				k, _ := om.Get("key")
				vv, _ := om.Get("value")
				m.Set(Stringify(k), vv)
			}
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
		def := int64(0)
		if len(args) > 0 {
			def, _ = ToInt(args[0])
		}
		base := int64(10)
		if len(args) > 1 {
			base, _ = ToInt(args[1])
		}
		switch t := v.(type) {
		case int64:
			return t, nil
		case float64:
			return int64(t), nil
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
				return int64(f), nil
			}
		}
		return def, nil
	case "float":
		f, _ := toFloat(v)
		return f, nil
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
		re, err := regexp.Compile(Stringify(args[0]))
		if err != nil {
			return nil, err
		}
		return re.ReplaceAllString(Stringify(v), Stringify(args[1])), nil
	case "regex_findall":
		if len(args) == 0 {
			return &List{}, nil
		}
		re, err := regexp.Compile(Stringify(args[0]))
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
		re, err := regexp.Compile(Stringify(args[0]))
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
		b, err := json.Marshal(jsonValue(v))
		if err != nil {
			return nil, err
		}
		return string(b), nil
	case "from_json":
		var out any
		if err := json.Unmarshal([]byte(Stringify(v)), &out); err != nil {
			return nil, err
		}
		return fromJSON(out), nil
	case "from_yaml":
		return DecodeYAML([]byte(Stringify(v)))
	case "to_yaml", "to_nice_yaml":
		b, err := yaml3.Marshal(toPlain(v))
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
		pad := strings.Repeat(" ", int(n))
		return pad + strings.ReplaceAll(Stringify(v), "\n", "\n"+pad), nil
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
	return nil, fmt.Errorf("unsupported filter %q", name)
}
