package jinja

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"

	yaml3 "go.yaml.in/yaml/v3"
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

// pyFormat implements the python printf-style subset used by the
// format filter: %s/%r/%v, %d, %x/%X, %f/%e/%g (+upper) with
// flags/width/precision, %c, %%. A conversion we cannot honour
// errors rather than emitting silently wrong output.
func pyFormat(format string, args []any) (string, error) {
	out := format
	argi := 0
	var b strings.Builder
	for i := 0; i < len(out); i++ {
		if out[i] != '%' || i+1 >= len(out) {
			b.WriteByte(out[i])
			continue
		}
		// %% literal
		if out[i+1] == '%' {
			b.WriteByte('%')
			i++
			continue
		}
		j := i + 1
		// A spec is flags/width/precision then ONE conversion
		// letter — the first non-spec byte terminates it. Scanning
		// for "a letter we handle" let %o/%u/%p pass through
		// literally (or eat across text to the next real spec) and
		// left %F a dead case.
		for j < len(out) && strings.ContainsRune("0123456789-+. #", rune(out[j])) {
			j++
		}
		if j >= len(out) {
			// Trailing incomplete spec ("%5" at EOF) — emit as-is.
			b.WriteString(out[i:])
			break
		}
		spec := out[i+1 : j]
		conv := out[j]
		switch conv {
		case 's', 'd', 'v', 'r', 'x', 'X', 'f', 'F', 'e', 'E', 'g', 'G', 'c':
		default:
			return "", fmt.Errorf("format: unsupported conversion %%%c", conv)
		}
		if argi >= len(args) {
			return "", fmt.Errorf("format: not enough args for %%%s%c", spec, conv)
		}
		a := args[argi]
		argi++
		switch conv {
		case 'd':
			iv, ok := ToInt(a)
			if !ok {
				return "", fmt.Errorf("format: %%%sd arg %v is not a number", spec, a)
			}
			if !validFmtSpec(spec, false) {
				return "", fmt.Errorf("format: unsupported %%%s%c spec", spec, conv)
			}
			if strings.Contains(spec, "-") {
				width := 0
				_, _ = fmt.Sscanf(strings.TrimLeft(spec, "-+0"), "%d", &width)
				b.WriteString(fmt.Sprintf("%-"+strconv.Itoa(width)+"d", iv))
			} else {
				b.WriteString(fmt.Sprintf("%"+spec+"d", iv))
			}
		case 'x', 'X':
			iv, ok := ToInt(a)
			if !ok {
				return "", fmt.Errorf("format: %%%s%c arg %v is not a number", spec, conv, a)
			}
			if !validFmtSpec(spec, true) {
				return "", fmt.Errorf("format: unsupported %%%s%c spec", spec, conv)
			}
			b.WriteString(fmt.Sprintf("%"+spec+string(conv), iv))
		case 'f', 'F', 'e', 'E', 'g', 'G':
			fv, ok := toFloat(a)
			if !ok {
				return "", fmt.Errorf("format: %%%s%c arg %v is not a number", spec, conv, a)
			}
			if !validFmtSpec(spec, true) {
				return "", fmt.Errorf("format: unsupported %%%s%c spec", spec, conv)
			}
			b.WriteString(fmt.Sprintf("%"+spec+string(conv), fv))
		case 'c':
			if iv, ok := ToInt(a); ok {
				b.WriteString(string(rune(iv)))
			} else if sv := Stringify(a); sv != "" {
				// First RUNE, not first byte — sv[:1] split a
				// multi-byte UTF-8 character.
				for _, r := range sv {
					b.WriteRune(r)
					break
				}
			}
		case 's', 'v', 'r':
			sv := Stringify(a)
			// %.Ns truncates the string form (python precision
			// semantics on %s).
			if dot := strings.IndexByte(spec, '.'); dot >= 0 {
				if n, err := strconv.Atoi(spec[dot+1:]); err == nil && n >= 0 {
					if rs := []rune(sv); len(rs) > n {
						sv = string(rs[:n])
					}
				}
			}
			num := strings.TrimLeft(spec, "-")
			width := 0
			_, _ = fmt.Sscanf(num, "%d", &width)
			if strings.Contains(spec, "-") {
				b.WriteString(fmt.Sprintf("%-"+strconv.Itoa(width)+"s", sv))
			} else if width > 0 {
				b.WriteString(fmt.Sprintf("%"+strconv.Itoa(width)+"s", sv))
			} else {
				b.WriteString(sv)
			}
		}
		i = j
	}
	if argi < len(args) {
		return "", fmt.Errorf("format: not all arguments converted (%d given)", len(args))
	}
	return b.String(), nil
}

// validFmtSpec reports whether spec (between % and the conversion
// letter) is flags → width → .precision IN ORDER — the flat
// char-set check used to accept "%5-2f", whose mid-spec '-' then
// rendered as Go's %!f(BAD) noise. precision requires dot.
func validFmtSpec(spec string, dot bool) bool {
	i := 0
	for i < len(spec) && strings.ContainsRune("-+ #0", rune(spec[i])) {
		i++ // flags
	}
	for i < len(spec) && spec[i] >= '0' && spec[i] <= '9' {
		i++ // width
	}
	if i < len(spec) && spec[i] == '.' {
		if !dot {
			return false
		}
		i++
		for i < len(spec) && spec[i] >= '0' && spec[i] <= '9' {
			i++ // precision
		}
	}
	return i == len(spec)
}

func filterMap(v any, args []any, kw map[string]any, s *scope) (any, error) {
	// map(attribute='x'[, default=y])
	if attr, ok := kw["attribute"]; ok {
		var out []any
		for _, it := range ToIter(v) {
			got := selectAttrKey(it, Stringify(attr))
			if _, u := got.(Undefined); u && kw["default"] != nil {
				got = kw["default"]
			}
			out = append(out, got)
		}
		return &List{out}, nil
	}
	if len(args) == 0 {
		return &List{ToIter(v)}, nil
	}
	name := Stringify(args[0])
	// map('basename') / map('regex_replace', p, r) — filter by name
	var out []any
	for _, it := range ToIter(v) {
		fv, err := applyFilter(name, it, args[1:], nil, s)
		if err != nil {
			out = append(out, getAttr(it, name))
			continue
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
		return &List{ToIter(v)}, nil
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

// ---------------- conversions ----------------

func jsonValue(v any) any { return jsonValueAt(v, 0) }

// jsonValueAt converts under the walkMaxDepth recursion budget —
// a cyclic value can't be marshaled anyway, so past the cap a
// "[...]" string placeholder stands in (marshal-safe).
func jsonValueAt(v any, depth int) any {
	if depth > walkMaxDepth {
		return "[...]"
	}
	switch t := v.(type) {
	case *OMap:
		m := map[string]any{}
		for _, k := range t.Keys() {
			vv, _ := t.Get(k)
			m[k] = jsonValueAt(vv, depth+1)
		}
		return m
	case *List:
		out := make([]any, len(t.V))
		for i, x := range t.V {
			out[i] = jsonValueAt(x, depth+1)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = jsonValueAt(x, depth+1)
		}
		return out
	case Undefined:
		return nil
	default:
		return v
	}
}

func fromJSON(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := NewOMap()
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			m.Set(k, fromJSON(t[k]))
		}
		return m
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = fromJSON(x)
		}
		return &List{out}
	case float64:
		if t == float64(int64(t)) {
			return int64(t)
		}
		return t
	default:
		return v
	}
}

func toPlain(v any) any { return toPlainAt(v, 0) }

// toPlainAt converts under the walkMaxDepth recursion budget —
// same cyclic-input guard as jsonValueAt; past the cap a "[...]"
// placeholder keeps the yaml.Marshal fed and acyclic.
func toPlainAt(v any, depth int) any {
	if depth > walkMaxDepth {
		return "[...]"
	}
	switch t := v.(type) {
	case *OMap:
		m := map[string]any{}
		for _, k := range t.Keys() {
			vv, _ := t.Get(k)
			m[k] = toPlainAt(vv, depth+1)
		}
		return m
	case *List:
		out := make([]any, len(t.V))
		for i, x := range t.V {
			out[i] = toPlainAt(x, depth+1)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = toPlainAt(x, depth+1)
		}
		return out
	case Undefined:
		return nil
	default:
		return v
	}
}

// ---------------- lookup ----------------

// doLookup mirrors ansible's lookup() — fail-loud: a lookup that
// cannot be honoured (unknown plugin, missing term, no env hook)
// errors the render instead of silently emitting "", which would let
// a missing file converge to an empty config value.
func doLookup(args []any, s *scope) (any, error) {
	if len(args) == 0 {
		return nil, errors.New("lookup: missing plugin name")
	}
	kind := Stringify(args[0])
	switch kind {
	case "file", "ansible.builtin.file":
		if len(args) < 2 {
			return nil, fmt.Errorf("lookup(%q): missing file path", kind)
		}
		if s.env == nil || s.env.FileLookup == nil {
			return nil, fmt.Errorf("lookup(%q): no file lookup configured", kind)
		}
		return s.env.FileLookup(Stringify(args[1]))
	case "pipe", "ansible.builtin.pipe":
		if len(args) < 2 {
			return nil, fmt.Errorf("lookup(%q): missing command", kind)
		}
		if s.env == nil || s.env.PipeLookup == nil {
			return nil, fmt.Errorf("lookup(%q): no pipe lookup configured", kind)
		}
		return s.env.PipeLookup(Stringify(args[1]))
	}
	return nil, fmt.Errorf("lookup: unsupported plugin %q", kind)
}
