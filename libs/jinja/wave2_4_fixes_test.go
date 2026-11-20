// wave2_4_fixes_test.go — comprehensive unit, regression, and edge-case
// coverage for Milestone M1b (Waves 2–4): M1-F6..M1-F13.
package jinja

import (
	"encoding/base64"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

// M1-F6: Undefined equality/inequality/membership symmetry while keeping
// nil == Undefined true and "" == Undefined false.
func TestUndefinedEqualitySymmetry(t *testing.T) {
	u := NewUndefined("missing")
	u2 := NewUndefined("other")

	// Direct deepEq and numEq symmetry checks.
	eqCases := []struct {
		name string
		l, r any
		want bool
	}{
		{"empty_vs_undef", "", u, false},
		{"undef_vs_empty", u, "", false},
		{"nil_vs_undef", nil, u, true},
		{"undef_vs_nil", u, nil, true},
		{"undef_vs_undef", u, u2, true},
		{"zero_vs_undef", int64(0), u, false},
		{"undef_vs_zero", u, int64(0), false},
		{"false_vs_undef", false, u, false},
		{"undef_vs_false", u, false, false},
		{"slice_vs_undef", []any{}, u, false},
		{"undef_vs_slice", u, []any{}, false},
		{"nil_list_vs_undef", (*List)(nil), u, false},
		{"undef_vs_nil_list", u, (*List)(nil), false},
		{"nil_omap_vs_undef", (*OMap)(nil), u, false},
		{"undef_vs_nil_omap", u, (*OMap)(nil), false},
	}
	for _, tc := range eqCases {
		t.Run("deepEq/"+tc.name, func(t *testing.T) {
			if got := deepEq(tc.l, tc.r); got != tc.want {
				t.Fatalf("deepEq(%#v, %#v) = %v, want %v", tc.l, tc.r, got, tc.want)
			}
		})
	}

	numEqCases := []struct {
		name string
		l, r any
		want bool
	}{
		{"empty_vs_undef", "", u, false},
		{"undef_vs_empty", u, "", false},
		{"nil_vs_None_str", nil, "None", false},
		{"None_str_vs_nil", "None", nil, false},
		{"nil_vs_undef", nil, u, true},
		{"undef_vs_nil", u, nil, true},
	}
	for _, tc := range numEqCases {
		t.Run("numEq/"+tc.name, func(t *testing.T) {
			if got := numEq(tc.l, tc.r); got != tc.want {
				t.Fatalf("numEq(%#v, %#v) = %v, want %v", tc.l, tc.r, got, tc.want)
			}
		})
	}

	// Template-level ==, !=, in, not in, is in, equalto, unique symmetry.
	ctx := map[string]any{
		"u":         u,
		"emptyAny":  map[string]any{"": 1, "a": 2},
		"emptyStrM": map[string]string{"": "v", "a": "w"},
		"nilOMap":   (*OMap)(nil),
	}
	tplCases := []struct {
		tpl  string
		want string
	}{
		{`{{ [''] == [u] }}|{{ [u] == [''] }}`, "False|False"},
		{`{{ {'k': ''} == {'k': u} }}|{{ {'k': u} == {'k': ''} }}`, "False|False"},
		{`{{ '' != u }}|{{ u != '' }}|{{ none != u }}|{{ u != none }}`, "True|True|False|False"},
		{`{{ '' in [u] }}|{{ u in [''] }}|{{ u in [none] }}|{{ none in [u] }}`, "False|False|True|True"},
		{`{{ '' is equalto(u) }}|{{ u is equalto('') }}`, "False|False"},
		{`{{ [u, ''] | unique | length }}`, "2"},
		// Undefined membership on strings, *OMap, and plain Go maps must be False.
		{`{{ undef in 'abc' }}|{{ undef in '' }}|{{ u in 'abc' }}|{{ u in '' }}`, "False|False|False|False"},
		{`{{ undef not in 'abc' }}|{{ undef not in '' }}|{{ undef is in('abc') }}|{{ undef is not in('abc') }}`, "True|True|False|True"},
		{`{{ '' in 'abc' }}|{{ '' in '' }}`, "True|True"},
		{`{{ undef in {'': 1} }}|{{ undef in emptyAny }}|{{ undef in emptyStrM }}|{{ undef in nilOMap }}`, "False|False|False|False"},
		{`{{ undef not in {'': 1} }}|{{ undef not in emptyAny }}|{{ undef is in({'': 1}) }}|{{ undef is in(emptyAny) }}`, "True|True|False|False"},
		{`{{ '' in {'': 1} }}|{{ '' in emptyAny }}|{{ '' in emptyStrM }}`, "True|True|True"},
		{`{{ 1 < 2 and undef not in 'abc' }}|{{ (undef in 'abc') == false }}|{{ [undef, 'a'] | select('in', 'abc') | join(',') }}`, "True|True|a"},
	}
	for _, tc := range tplCases {
		got, err := renderBounded(t, tc.tpl, ctx)
		if err != nil {
			t.Fatalf("render %q: %v", tc.tpl, err)
		}
		if got != tc.want {
			t.Fatalf("render %q = %q, want %q", tc.tpl, got, tc.want)
		}
	}
}

// M1-F7: Chained comparisons, single intermediate evaluation, short-circuit,
// and `is` test precedence separation.
func TestChainedComparisonsAndTestPrecedence(t *testing.T) {
	ctx := map[string]any{
		"nan": math.NaN(),
	}
	cases := []struct {
		name string
		tpl  string
		want string
	}{
		{"false_chain", `{{ 5 < 10 < 3 }}`, "False"},
		{"true_chain", `{{ 1 < 2 < 3 }}`, "True"},
		{"eq_chain", `{{ 2 == 2 == 2 }}`, "True"},
		{"ne_chain", `{{ 1 != 2 != 1 }}`, "True"},
		{"mixed_le_lt", `{{ 1 <= 2 <= 2 < 3 }}`, "True"},
		{"lt_in", `{{ 1 < 2 in [2, 3] }}`, "True"},
		{"lt_not_in_true", `{{ 1 < 2 not in [3, 4] }}`, "True"},
		{"lt_not_in_false", `{{ 1 < 2 not in [2, 3] }}`, "False"},
		{"in_eq_bool", `{{ 1 in [1, 2] == true }}`, "False"},
		{"lt_eq_bool", `{{ 1 < 2 == true }}`, "False"},
		{"eval_once", `{% set l = [1, 2] %}{{ 0 < l.pop() < 3 }}:{{ l | length }}`, "True:1"},
		{"short_circuit_lookup", `{{ 5 < 3 < lookup('file', 'nonexistent') }}`, "False"},
		{"short_circuit_div0", `{{ 1 > 2 < (1 // 0) }}`, "False"},
		{"is_lhs_eq", `{{ x is defined == false }}`, "True"},
		{"eq_is_rhs", `{{ true == x is undefined }}`, "True"},
		{"not_chain", `{{ not 5 < 10 < 3 }}`, "True"},
		{"and_chain", `{{ 1 < 2 and 3 < 4 < 5 }}`, "True"},
		{"nan_first", `{{ nan < 5 < 10 }}`, "False"},
		{"nan_mid", `{{ 1 < nan < 5 }}`, "False"},
		{"undef_chain", `{{ '' == missing == '' }}`, "False"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := renderBounded(t, tc.tpl, ctx)
			if err != nil {
				t.Fatalf("render %q: %v", tc.tpl, err)
			}
			if got != tc.want {
				t.Fatalf("render %q = %q, want %q", tc.tpl, got, tc.want)
			}
		})
	}
}

// M1-F8: DoS / CPU / RAM caps across flatten, regex_escape, b64encode,
// b64decode, split, regex_findall, regex_replace, parseExpr, and parseTemplate.
func TestWave2CapsAndBounds(t *testing.T) {
	t.Run("flatten_empty_dag_steps", func(t *testing.T) {
		l := &List{}
		for range 30 {
			l = &List{V: []any{l, l}}
		}
		_, err := renderBounded(t, `{{ l | flatten }}`, map[string]any{"l": l})
		if err == nil || !strings.Contains(err.Error(), "steps") {
			t.Fatalf("expected step-budget error for flatten DAG, got %v", err)
		}
	})

	t.Run("flatten_depth_tail_over_max_out", func(t *testing.T) {
		big := make([]any, flattenMaxOut+1)
		cur := any(&List{V: big})
		for range flattenMaxDepth {
			cur = &List{V: []any{cur}}
		}
		_, err := renderBounded(t, `{{ l | flatten }}`, map[string]any{"l": cur})
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("expected flatten output cap error at depth tail, got %v", err)
		}
	})

	t.Run("regex_escape_caps", func(t *testing.T) {
		tooManyDots := strings.Repeat(".", maxStringBytes/2+1)
		if _, err := renderBounded(t, `{{ s | regex_escape | length }}`, map[string]any{"s": tooManyDots}); err == nil {
			t.Fatal("expected regex_escape metachar expansion > maxStringBytes to fail")
		}
		exactPlain := strings.Repeat("a", maxStringBytes)
		got, err := renderBounded(t, `{{ s | regex_escape | length }}`, map[string]any{"s": exactPlain})
		if err != nil {
			t.Fatalf("plain maxStringBytes regex_escape failed: %v", err)
		}
		if got != fmt.Sprintf("%d", maxStringBytes) {
			t.Fatalf("got %q, want %d", got, maxStringBytes)
		}
	})

	t.Run("b64encode_caps", func(t *testing.T) {
		maxIn := (maxStringBytes / 4) * 3
		overIn := strings.Repeat("a", maxIn+1)
		if _, err := renderBounded(t, `{{ s | b64encode | length }}`, map[string]any{"s": overIn}); err == nil {
			t.Fatal("expected b64encode > maxStringBytes output to fail")
		}
		exactIn := strings.Repeat("a", maxIn)
		got, err := renderBounded(t, `{{ s | b64encode | length }}`, map[string]any{"s": exactIn})
		if err != nil {
			t.Fatalf("exact b64encode failed: %v", err)
		}
		if got != fmt.Sprintf("%d", base64.StdEncoding.EncodedLen(maxIn)) {
			t.Fatalf("b64encode len = %q", got)
		}
	})

	t.Run("b64decode_cap", func(t *testing.T) {
		overB64 := strings.Repeat("AAAA", maxStringBytes/3+4)
		if _, err := renderBounded(t, `{{ s | b64decode | length }}`, map[string]any{"s": overB64}); err == nil {
			t.Fatal("expected oversized b64decode to fail")
		}
	})

	t.Run("split_caps", func(t *testing.T) {
		manyCommas := strings.Repeat("a,", maxSeqElems)
		if _, err := renderBounded(t, `{{ s | split(',') | length }}`, map[string]any{"s": manyCommas}); err == nil {
			t.Fatal("expected split(',') > maxSeqElems to fail")
		}
		manyChars := strings.Repeat("a", maxSeqElems+1)
		if _, err := renderBounded(t, `{{ s | split('') | length }}`, map[string]any{"s": manyChars}); err == nil {
			t.Fatal("expected split('') > maxSeqElems to fail")
		}
		manyFields := strings.Repeat("a ", maxSeqElems+1)
		if _, err := renderBounded(t, `{{ s.split() | length }}`, map[string]any{"s": manyFields}); err == nil {
			t.Fatal("expected method s.split() > maxSeqElems to fail")
		}
	})

	t.Run("regex_findall_cap", func(t *testing.T) {
		manyMatches := strings.Repeat("a", maxSeqElems+1)
		if _, err := renderBounded(t, `{{ s | regex_findall('a') | length }}`, map[string]any{"s": manyMatches}); err == nil {
			t.Fatal("expected regex_findall > maxSeqElems to fail")
		}
	})

	t.Run("regex_replace_semantics_and_caps", func(t *testing.T) {
		bigA := strings.Repeat("a", maxStringBytes)
		if _, err := renderBounded(t, `{{ s | regex_replace('a', 'bb') | length }}`, map[string]any{"s": bigA}); err == nil {
			t.Fatal("expected regex_replace expansion > maxStringBytes to fail")
		}
		// Non-literal regex mid-stream output cap (must error without full match slice alloc).
		if _, err := renderBounded(t, `{{ s | regex_replace('[a]', repl) | length }}`, map[string]any{
			"s":    strings.Repeat("a", 1024),
			"repl": strings.Repeat("b", 32768),
		}); err == nil || !strings.Contains(err.Error(), "output exceeds") {
			t.Fatalf("expected non-literal regex_replace output cap error, got %v", err)
		}
		if _, err := renderBounded(t, `{{ s | regex_replace('', 'x') | length }}`, map[string]any{"s": bigA}); err == nil {
			t.Fatal("expected regex_replace empty-pattern expansion > maxStringBytes to fail")
		}
		// Large input + large repl with NO match should succeed cleanly.
		bigRepl := strings.Repeat("r", maxStringBytes)
		got, err := renderBounded(t, `{{ s | regex_replace('zzz', repl) | length }}`, map[string]any{"s": bigA, "repl": bigRepl})
		if err != nil {
			t.Fatalf("no-match regex_replace failed: %v", err)
		}
		if got != fmt.Sprintf("%d", maxStringBytes) {
			t.Fatalf("no-match regex_replace len = %q", got)
		}

		cases := []struct {
			tpl  string
			want string
		}{
			{`{{ 'aba' | regex_replace('a*', 'X') }}`, "XbX"},
			{`{{ 'b' | regex_replace('a*', 'X') }}`, "XbX"},
			{`{{ 'aéb' | regex_replace('', 'X') }}`, "XaXéXbX"},
			{`{{ 'aa' | regex_replace('^a', 'X') }}`, "Xa"},
			{`{{ 'aa' | regex_replace('\Aa', 'X') }}`, "Xa"},
			{`{{ 'foo' | regex_replace('\b\w', 'X') }}`, "Xoo"},
			{`{{ s | regex_replace('(?m)^[a-z]', 'X') }}`, "Xb\nXd"},
			{`{{ 'a1' | regex_replace('([a-z])(\d)', '$2-$1') }}`, "1-a"},
		}
		for _, tc := range cases {
			out, err := renderBounded(t, tc.tpl, map[string]any{"s": "ab\ncd"})
			if err != nil {
				t.Fatalf("%s failed: %v", tc.tpl, err)
			}
			if out != tc.want {
				t.Fatalf("%s = %q, want %q", tc.tpl, out, tc.want)
			}
		}

		// Path C match cap (> maxSeqElems matches with \b).
		manyWords := strings.Repeat("a ", maxSeqElems+1)
		if _, err := renderBounded(t, `{{ s | regex_replace('\b\w', 'X') | length }}`, map[string]any{"s": manyWords}); err == nil {
			t.Fatal("expected Path C regex_replace > maxSeqElems matches to fail")
		}
	})

	t.Run("expr_depth_cap", func(t *testing.T) {
		over := exprMaxDepth + 1
		overExprs := []string{
			"{{ " + strings.Repeat("(", over) + "1" + strings.Repeat(")", over) + " }}",
			"{{ " + strings.Repeat("[", over) + "1" + strings.Repeat("]", over) + " }}",
			"{{ " + strings.Repeat("{'a':", over) + "1" + strings.Repeat("}", over) + " }}",
			"{{ " + strings.Repeat("not ", over) + "true }}",
			"{{ " + strings.Repeat("-", over) + "1 }}",
			"{{ " + strings.Repeat("+-", over/2+1) + "1 }}",
			"{{ " + strings.Repeat("1 if true else ", over) + "2 }}",
			"{{ " + strings.Repeat("f(", over) + "1" + strings.Repeat(")", over) + " }}",
			"{{ a" + strings.Repeat("[b", over) + strings.Repeat("]", over) + " }}",
			"{{ " + strings.Repeat("1 | default(", over) + "2" + strings.Repeat(")", over) + " }}",
		}
		for _, tpl := range overExprs {
			if _, err := renderBounded(t, tpl, nil); err == nil {
				t.Fatalf("expected depth error for %q", tpl[:min(len(tpl), 40)])
			}
		}

		// Right at cap passes (exprMaxDepth - 1 parens => depth == exprMaxDepth).
		atCap := "{{ " + strings.Repeat("(", exprMaxDepth-1) + "1" + strings.Repeat(")", exprMaxDepth-1) + " }}"
		if out, err := renderBounded(t, atCap, nil); err != nil || out != "1" {
			t.Fatalf("at-cap parens got (%q, %v), want (\"1\", nil)", out, err)
		}

		// Wide flat chains stay unbounded in length.
		flatAdd := "{{ " + strings.Repeat("1 + ", 500) + "1 }}"
		if out, err := renderBounded(t, flatAdd, nil); err != nil || out != "501" {
			t.Fatalf("flat add got (%q, %v), want (\"501\", nil)", out, err)
		}
		flatFilter := "{{ ' x '" + strings.Repeat(" | trim", 500) + " }}"
		if out, err := renderBounded(t, flatFilter, nil); err != nil || out != "x" {
			t.Fatalf("flat filter got (%q, %v), want (\"x\", nil)", out, err)
		}
	})

	t.Run("template_depth_cap", func(t *testing.T) {
		atCap := strings.Repeat("{% if true %}", templateMaxDepth) + "ok" + strings.Repeat("{% endif %}", templateMaxDepth)
		if out, err := renderBounded(t, atCap, nil); err != nil || out != "ok" {
			t.Fatalf("at templateMaxDepth got (%q, %v), want (\"ok\", nil)", out, err)
		}
		withElif := strings.Repeat("{% if false %}x{% elif true %}", templateMaxDepth) + "ok" + strings.Repeat("{% endif %}", templateMaxDepth)
		if out, err := renderBounded(t, withElif, nil); err != nil || out != "ok" {
			t.Fatalf("at templateMaxDepth with elif got (%q, %v), want (\"ok\", nil)", out, err)
		}
		overIf := strings.Repeat("{% if true %}", templateMaxDepth+1) + "ok" + strings.Repeat("{% endif %}", templateMaxDepth+1)
		if _, err := renderBounded(t, overIf, nil); err == nil {
			t.Fatal("expected templateMaxDepth+1 if blocks to fail")
		}
		overFor := strings.Repeat("{% for x in [1] %}", templateMaxDepth+1) + "ok" + strings.Repeat("{% endfor %}", templateMaxDepth+1)
		if _, err := renderBounded(t, overFor, nil); err == nil {
			t.Fatal("expected templateMaxDepth+1 for blocks to fail")
		}
	})
}

// M1-F9 + M1-F13c: RenderScoped precedence, parent-pointer scope, nil preservation.
func TestRenderScopedParentChainAndNil(t *testing.T) {
	lookup := func(name string) any {
		switch name {
		case "a":
			return "ext"
		case "loop":
			return "ext_loop"
		case "n":
			return nil
		default:
			return NewUndefined(name)
		}
	}
	cases := []struct {
		name string
		tpl  string
		want string
	}{
		{"set_shadows_lookup", `{% set a = 'local' %}{{ a }}`, "local"},
		{"for_shadows_lookup_then_restores", `{% for a in [1,2] %}{{ a }}{% endfor %}{{ a }}`, "12ext"},
		{"outer_set_shadows_lookup_in_for", `{% set a = 'outer' %}{% for i in [1] %}{{ a }}{% endfor %}`, "outer"},
		{"loop_var_shadows_lookup", `{% for i in [1] %}{{ loop.index }}{% endfor %}`, "1"},
		{"nil_preserved_as_none", `{{ n is none }}|{{ n is undefined }}|{{ n }}|{{ n | to_json }}|{{ n | default('d') }}`, "True|False|None|null|d"},
		{"undef_falls_through", `{{ missing is undefined }}|{{ range(2) | join(',') }}`, "True|0,1"},
		{"empty_and_filtered_loops", `{% for x in [] %}{{ x }}{% endfor %}|{% for x in [1,2] if x > 5 %}{{ x }}{% endfor %}`, "|"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RenderScoped(tc.tpl, nil, lookup)
			if err != nil {
				t.Fatalf("RenderScoped(%q): %v", tc.tpl, err)
			}
			if got != tc.want {
				t.Fatalf("RenderScoped(%q) = %q, want %q", tc.tpl, got, tc.want)
			}
		})
	}
	// Nil lookup func does not panic.
	if got, err := RenderScoped(`{% set x = 'ok' %}{{ x }}|{{ missing is undefined }}`, nil, nil); err != nil || got != "ok|True" {
		t.Fatalf("RenderScoped nil lookup = (%q, %v), want (\"ok|True\", nil)", got, err)
	}
}

// M1-F10a: Lexer preserves backslashes on unrecognized escapes while keeping standard ones.
func TestLexerEscapePreservation(t *testing.T) {
	cases := []struct {
		tpl  string
		want string
	}{
		{`{{ '\d+' }}`, `\d+`},
		{`{{ '\.' }}`, `\.`},
		{`{{ '\s\w\b' }}`, `\s\w\b`},
		{`{{ 'a1b2' | regex_findall('\d+') | join(',') }}`, "1,2"},
		{`{{ 'a.b' | regex_replace('\.', '-') }}`, "a-b"},
		{`{{ 'a\nb\tc\rd' }}`, "a\nb\tc\rd"},
		{`{{ 'it\'s' }}`, "it's"},
		{`{{ "a\"b" }}`, `a"b`},
		{`{{ 'a\\b' }}`, `a\b`},
		{`{{ '\\d' }}`, `\d`},
		{`{{ '\\\\d' }}`, `\\d`},
		{`{{ 'abc\\' }}`, `abc\`},
	}
	for _, tc := range cases {
		got, err := renderBounded(t, tc.tpl, nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.tpl, err)
		}
		if got != tc.want {
			t.Fatalf("%s = %q, want %q", tc.tpl, got, tc.want)
		}
	}
}

// M1-F10b: |int(default, base) base-prefix, base validation, and base=0 edge cases.
func TestFilterIntBasePrefixes(t *testing.T) {
	cases := []struct {
		tpl  string
		want string
	}{
		{`{{ '0x10' | int(0, 16) }}`, "16"},
		{`{{ '0X1f' | int(0, 16) }}`, "31"},
		{`{{ '-0x10' | int(0, 16) }}`, "-16"},
		{`{{ '+0x10' | int(0, 16) }}`, "16"},
		{`{{ '  -0X10  ' | int(0, 16) }}`, "-16"},
		{`{{ '-0x8000000000000000' | int(0, 16) }}`, fmt.Sprintf("%d", int64(math.MinInt64))},
		{`{{ '0x' | int(7, 16) }}`, "7"},
		{`{{ '-0x' | int(7, 16) }}`, "7"},
		{`{{ '0x-10' | int(7, 16) }}`, "7"},
		{`{{ '0x+10' | int(7, 16) }}`, "7"},
		{`{{ '0x10' | int(7) }}`, "7"},
		{`{{ '0x10' | int(7, 0) }}`, "16"},
		{`{{ '-0X1f' | int(7, 0) }}`, "-31"},
		{`{{ '+0x10' | int(7, 0) }}`, "16"},
		{`{{ '0o17' | int(7, 0) }}`, "15"},
		{`{{ '-0O17' | int(7, 0) }}`, "-15"},
		{`{{ '0b101' | int(7, 0) }}`, "5"},
		{`{{ '-0B101' | int(7, 0) }}`, "-5"},
		{`{{ '0x' | int(7, 0) }}`, "7"},
		{`{{ '0x-10' | int(7, 0) }}`, "7"},
		{`{{ '0o' | int(7, 0) }}`, "7"},
		{`{{ '0b' | int(7, 0) }}`, "7"},
		{`{{ '0b101' | int(0, 2) }}`, "5"},
		{`{{ '-0b101' | int(0, 2) }}`, "-5"},
		{`{{ '0b' | int(7, 2) }}`, "7"},
		{`{{ '0o17' | int(0, 8) }}`, "15"},
		{`{{ '-0o17' | int(0, 8) }}`, "-15"},
		{`{{ '010' | int(0, 8) }}`, "8"},
		// Python 3 int(s, 0) leading-zero & all-zero rules.
		{`{{ '0' | int(-1, 0) }}`, "0"},
		{`{{ '000' | int(-1, 0) }}`, "0"},
		{`{{ '-000' | int(-1, 0) }}`, "0"},
		{`{{ '+0' | int(-1, 0) }}`, "0"},
		{`{{ '010' | int(-1, 0) }}`, "-1"},
		{`{{ '-010' | int(-1, 0) }}`, "-1"},
		{`{{ '08' | int(-1, 0) }}`, "-1"},
		// Underscores rejected consistently across bases 0, 2, 8, 10, 16.
		{`{{ '0x_10' | int(-1, 0) }}`, "-1"},
		{`{{ '0x_10' | int(-1, 16) }}`, "-1"},
		{`{{ '1_000' | int(-1, 0) }}`, "-1"},
		{`{{ '1_000' | int(-1, 10) }}`, "-1"},
		{`{{ '1_000' | int(-1) }}`, "-1"},
		{`{{ '0b_10' | int(-1, 0) }}`, "-1"},
		{`{{ '0b_10' | int(-1, 2) }}`, "-1"},
		{`{{ '0o_10' | int(-1, 0) }}`, "-1"},
		{`{{ '0o_10' | int(-1, 8) }}`, "-1"},
		// Invalid/undefined/nil base arguments must NOT silently coerce to base=0.
		{`{{ '0x10' | int(-1, 'notabase') }}`, "-1"},
		{`{{ '0x10' | int(-1, undef) }}`, "-1"},
		{`{{ '0x10' | int(-1, none) }}`, "-1"},
		{`{{ '0x10' | int(-1, []) }}`, "-1"},
		{`{{ '0x10' | int(-1, base='notabase') }}`, "-1"},
		{`{{ '0x10' | int(-1, base=undef) }}`, "-1"},
		{`{{ '0x10' | int(-1, base=none) }}`, "-1"},
		{`{{ '0x10' | int(-1, base=16) }}`, "16"},
		{`{{ '0x10' | int(-1, 'notabase', base=16) }}`, "16"},
		{`{{ '0x10' | int(-1, 16, base='notabase') }}`, "-1"},
		{`{{ 42 | int(-1, 'notabase') }}`, "-1"},
		{`{{ '10' | int(-1, 1) }}`, "-1"},
		{`{{ '10' | int(-1, 37) }}`, "-1"},
		{`{{ '10' | int(-1, -1) }}`, "-1"},
		{`{{ '10' | int(-1, '16') }}`, "16"},
		{`{{ '10' | int(-1, true) }}`, "-1"},
		{`{{ '0x10' | int(-1, false) }}`, "16"},
	}
	for _, tc := range cases {
		got, err := renderBounded(t, tc.tpl, nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.tpl, err)
		}
		if got != tc.want {
			t.Fatalf("%s = %q, want %q", tc.tpl, got, tc.want)
		}
	}
}

// M1-F10c: Exact MinInt64 & uint64 arithmetic + float64 fallback beyond uint64.
func TestExactMinInt64AndUint64Math(t *testing.T) {
	// Direct numNeg type verification.
	if v, err := numNeg(int64(math.MinInt64)); err != nil || v != uint64(1<<63) {
		t.Fatalf("numNeg(MinInt64) = (%T(%#v), %v), want uint64(1<<63)", v, v, err)
	}
	if v, err := numNeg(uint64(1 << 63)); err != nil || v != int64(math.MinInt64) {
		t.Fatalf("numNeg(2^63) = (%T(%#v), %v), want int64(MinInt64)", v, v, err)
	}
	if v, err := numNeg(uint64(1<<63) + 1); err != nil || v != -float64(uint64(1<<63)+1) {
		t.Fatalf("numNeg(2^63+1) = (%T(%#v), %v), want -float64", v, v, err)
	}
	if v, err := binOp("+", uint64(1<<63), int64(-1)); err != nil || v != int64(math.MaxInt64) {
		t.Fatalf("2^63 + (-1) = (%T(%#v), %v), want int64(MaxInt64)", v, v, err)
	}

	ctx := map[string]any{"min64": int64(math.MinInt64)}
	cases := []struct {
		tpl  string
		want string
	}{
		{`{{ -(-9223372036854775808) }}`, "9223372036854775808"},
		{`{{ (-min64) + 1 }}`, "9223372036854775809"},
		{`{{ (-min64) - 1 }}`, "9223372036854775807"},
		{`{{ -9223372036854775808 + 1 }}`, "-9223372036854775807"},
		{`{{ 9223372036854775807 + 9223372036854775807 }}`, "18446744073709551614"},
		{`{{ 9223372036854775807 - (-1) }}`, "9223372036854775808"},
		{`{{ 0 - (-9223372036854775808) }}`, "9223372036854775808"},
		{`{{ 9223372036854775807 - (-9223372036854775808) }}`, "18446744073709551615"},
		{`{{ 9223372036854775807 * 2 }}`, "18446744073709551614"},
		{`{{ -9223372036854775808 * -1 }}`, "9223372036854775808"},
		{`{{ 18446744073709551615 + 1 }}`, "1.8446744073709552e+19"},
		{`{{ 9223372036854775807 * 3 }}`, "2.7670116110564327e+19"},
		{`{{ -9223372036854775809 }}`, "-9223372036854775808"},
		{`{{ -9223372036854777856 }}`, "-9.223372036854778e+18"},
	}
	for _, tc := range cases {
		got, err := renderBounded(t, tc.tpl, ctx)
		if err != nil {
			t.Fatalf("%s: %v", tc.tpl, err)
		}
		if got != tc.want {
			t.Fatalf("%s = %q, want %q", tc.tpl, got, tc.want)
		}
	}
}

// M1-F11: YAML merge <<= *alias_to_seq, chained aliases, empty seq, and step/depth budgets.
func TestYAMLMergeAliasToSeqAndBudgets(t *testing.T) {
	v, err := DecodeYAML([]byte(`
a: &a
  k1: 1
  k2: 2
b: &b
  k2: 99
  k3: 3
c: &c
  k4: 4
seq1: &s1 [*a, *b]
seq2: &s2 [*s1]
empty_seq: &es []
merged_chain:
  <<: *s2
  k3: 30
merged_mixed:
  <<: [*s1, *c]
merged_empty:
  <<: *es
  only: 1
`))
	if err != nil {
		t.Fatalf("DecodeYAML: %v", err)
	}
	root := v.(*OMap)
	mc, _ := root.Get("merged_chain")
	mcm := mc.(*OMap)
	if mcm.Int("k1") != 1 || mcm.Int("k2") != 2 || mcm.Int("k3") != 30 {
		t.Fatalf("merged_chain mismatch: k1=%d k2=%d k3=%d", mcm.Int("k1"), mcm.Int("k2"), mcm.Int("k3"))
	}
	mm, _ := root.Get("merged_mixed")
	mmm := mm.(*OMap)
	if mmm.Int("k1") != 1 || mmm.Int("k4") != 4 {
		t.Fatalf("merged_mixed mismatch: k1=%d k4=%d", mmm.Int("k1"), mmm.Int("k4"))
	}
	me, _ := root.Get("merged_empty")
	mem := me.(*OMap)
	if mem.Int("only") != 1 || mem.Len() != 1 {
		t.Fatalf("merged_empty = %#v", mem)
	}

	// Scalar inside aliased sequence errors cleanly.
	if _, err := DecodeYAML([]byte("sc: &sc 1\ns: &s [*sc]\ntop:\n  <<: *s\n")); err == nil {
		t.Fatal("expected error for scalar inside aliased merge sequence")
	}
	// Null inside aliased sequence errors cleanly.
	if _, err := DecodeYAML([]byte("n: &n null\ns: &s [*n]\ntop:\n  <<: *s\n")); err == nil {
		t.Fatal("expected error for null inside aliased merge sequence")
	}

	// Self-referential merge anchor errors via depth/steps instead of stack overflow.
	if _, err := DecodeYAML([]byte("x: &x\n  <<: *x\n  a: 1\n")); err == nil {
		t.Fatal("expected error for self-referential merge mapping")
	}
	if _, err := DecodeYAML([]byte("s: &s [*s]\ntop:\n  <<: *s\n")); err == nil {
		t.Fatal("expected error for self-referential merge sequence")
	}

	// Billion-laughs empty-sequence merge DAG caught by stepBudgetExhausted.
	var sb strings.Builder
	sb.WriteString("l0: &l0 []\n")
	for i := 1; i <= 25; i++ {
		fmt.Fprintf(&sb, "l%d: &l%d [*l%d, *l%d]\n", i, i, i-1, i-1)
	}
	sb.WriteString("top:\n  <<: *l25\n")
	if _, err := DecodeYAML([]byte(sb.String())); err == nil || !strings.Contains(err.Error(), "steps") {
		t.Fatalf("expected step-budget error for billion-laughs merge sequence, got %v", err)
	}
}

// M1-F12 + M1-F13d: encoding/json/v2 v1 fallback options and direct jsontext.NewDecoder.
func TestJSONv2AndDirectFromJSON(t *testing.T) {
	t.Run("to_json_v1_semantics", func(t *testing.T) {
		type v1Payload struct {
			Dur     time.Duration
			Flag    bool `json:"flag,omitempty"`
			Zero    int  `json:"zero,omitempty"`
			NilList []string
			NilMap  map[string]string
			Sep     string
			BadUTF8 string
		}
		p := v1Payload{
			Dur:     5 * time.Second,
			Sep:     "a\u2028b\u2029c",
			BadUTF8: "a\xffb",
		}
		got, err := renderBounded(t, `{{ p | to_json }}`, map[string]any{"p": p})
		if err != nil {
			t.Fatalf("to_json struct failed: %v", err)
		}
		if !strings.Contains(got, `"Dur":5000000000`) {
			t.Fatalf("expected Duration ns, got %s", got)
		}
		if strings.Contains(got, `"flag"`) || strings.Contains(got, `"zero"`) {
			t.Fatalf("expected omitempty zero bool/int omitted, got %s", got)
		}
		if !strings.Contains(got, `"NilList":null`) || !strings.Contains(got, `"NilMap":null`) {
			t.Fatalf("expected nil slice/map as null, got %s", got)
		}
		if !strings.Contains(got, `"Sep":"a\u2028b\u2029c"`) {
			t.Fatalf("expected escaped U+2028/U+2029, got %s", got)
		}
		if !strings.Contains(got, `"BadUTF8":"a`+"\ufffd"+`b"`) {
			t.Fatalf("expected raw U+FFFD replacement matching writeJSONString, got %q", got)
		}
		// NaN / +Inf still error.
		if _, err := renderBounded(t, `{{ x | to_json }}`, map[string]any{"x": math.NaN()}); err == nil {
			t.Fatal("expected NaN | to_json to error")
		}
		if _, err := renderBounded(t, `{{ x | to_json }}`, map[string]any{"x": math.Inf(1)}); err == nil {
			t.Fatal("expected +Inf | to_json to error")
		}
	})

	t.Run("from_json_direct_decoder", func(t *testing.T) {
		// Preserves document key order.
		got, err := renderBounded(t, `{{ '{"z":1,"a":2,"m":3}' | from_json | to_json }}`, nil)
		if err != nil || got != `{"z":1,"a":2,"m":3}` {
			t.Fatalf("key order got (%q, %v)", got, err)
		}
		// Duplicate keys keep first-insert position and last value.
		got, err = renderBounded(t, `{{ '{"b":1,"a":2,"b":3}' | from_json | to_json }}`, nil)
		if err != nil || got != `{"b":3,"a":2}` {
			t.Fatalf("duplicate keys got (%q, %v)", got, err)
		}
		// Lone surrogate and raw invalid UTF-8 tolerated.
		v, err := decodeJSON(`{"k":"a\uD800b","raw":"x` + "\xff" + `y"}`)
		if err != nil {
			t.Fatalf("invalid UTF-8/surrogate decodeJSON failed: %v", err)
		}
		m := v.(*OMap)
		if kv, _ := m.Get("k"); kv != "a\ufffdb" {
			t.Fatalf("surrogate value = %q", kv)
		}
		if rv, _ := m.Get("raw"); rv != "x\ufffdy" {
			t.Fatalf("raw invalid UTF-8 value = %q", rv)
		}

		// Numeric precision / types.
		numVal, err := decodeJSON(`{"i64":9007199254740993,"min":-9223372036854775808,"u64":9223372036854775808,"f1":1.5,"f2":1.0,"f3":1e5,"negbig":-9223372036854775809,"bigf":1e100}`)
		if err != nil {
			t.Fatalf("numbers decodeJSON failed: %v", err)
		}
		nm := numVal.(*OMap)
		if v, _ := nm.Get("i64"); v != int64(9007199254740993) {
			t.Fatalf("i64 = %T(%#v)", v, v)
		}
		if v, _ := nm.Get("min"); v != int64(math.MinInt64) {
			t.Fatalf("min = %T(%#v)", v, v)
		}
		if v, _ := nm.Get("u64"); v != uint64(1<<63) {
			t.Fatalf("u64 = %T(%#v)", v, v)
		}
		for _, k := range []string{"f1", "f2", "f3", "negbig", "bigf"} {
			v, _ := nm.Get(k)
			if _, ok := v.(float64); !ok {
				t.Fatalf("%s = %T(%#v), want float64", k, v, v)
			}
		}

		// Float overflow (1e1000) errors instead of returning +Inf.
		if _, err := decodeJSON(`1e1000`); err == nil {
			t.Fatal("expected 1e1000 to error")
		}

		// Object depth parity with TestFromJSONDepthLimitErrors.
		atCapObj := strings.Repeat(`{"a":`, fromJSONMaxDepth) + `{}` + strings.Repeat(`}`, fromJSONMaxDepth)
		if _, err := decodeJSON(atCapObj); err != nil {
			t.Fatalf("at-cap object errored: %v", err)
		}
		overCapObj := strings.Repeat(`{"a":`, fromJSONMaxDepth+1) + `{}` + strings.Repeat(`}`, fromJSONMaxDepth+1)
		if _, err := decodeJSON(overCapObj); err == nil {
			t.Fatal("over-cap object must error")
		}

		// Empty / whitespace / trailing tokens.
		for _, bad := range []string{"", "   ", `{"a":1} 2`, `1,`, `{"a":1`} {
			if _, err := decodeJSON(bad); err == nil {
				t.Fatalf("expected decodeJSON(%q) to fail", bad)
			}
		}
		if v, err := decodeJSON("{\"a\":1} \n\t"); err != nil || v.(*OMap).Int("a") != 1 {
			t.Fatalf("trailing whitespace failed: (%v, %v)", v, err)
		}
	})
}

// M1-F13a + M1-F13b: clockCache.get concurrent cold-to-warm + eviction under -race,
// and single-pass template tag scanner edge cases.
func TestClockCacheHammerAndSinglePassTagScan(t *testing.T) {
	c := newClockCache[int](8)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := range 200 {
				key := fmt.Sprintf("k-%d", (id*7+i)%24)
				if _, ok := c.get(key); !ok {
					c.putIfAbsent(key, i)
				}
			}
		}(g)
	}
	wg.Wait()

	cases := []struct {
		tpl  string
		want string
	}{
		{`{'k': 1} {{ x }}`, `{'k': 1} ok`},
		{`{ {{ x }}`, `{ ok`},
		{`{a{{ x }}`, `{aok`},
		{`{ {% if x %}1{% endif %}`, `{ 1`},
		{`a{`, `a{`},
		{`{%- if x -%}ok{%- endif -%}`, `ok`},
		{`{# comment { {{ {% #}{{ x }}`, `ok`},
	}
	for _, tc := range cases {
		got, err := renderBounded(t, tc.tpl, map[string]any{"x": "ok"})
		if err != nil {
			t.Fatalf("render %q: %v", tc.tpl, err)
		}
		if got != tc.want {
			t.Fatalf("render %q = %q, want %q", tc.tpl, got, tc.want)
		}
	}
	if _, err := Render(`a{{`, nil, nil); err == nil {
		t.Fatal("expected unclosed {{ at EOF to error")
	}
}

func TestRegexFindallNonLiteralAndCaptureCaps(t *testing.T) {
	manyMatches := strings.Repeat("a", maxSeqElems+1)
	for _, pat := range []string{`[a]`, `(a)`} {
		tpl := fmt.Sprintf(`{{ s | regex_findall(%q) | length }}`, pat)
		if _, err := renderBounded(t, tpl, map[string]any{"s": manyMatches}); err == nil {
			t.Fatalf("expected regex_findall(%q) > maxSeqElems to fail", pat)
		}
	}

	cases := []struct {
		tpl  string
		ctx  map[string]any
		want string
	}{
		{`{{ 'xyz' | regex_findall('a') | length }}`, nil, "0"},
		{`{{ 'xyz' | regex_findall('(a)') | length }}`, nil, "0"},
		{`{{ 'a1b2' | regex_findall('[a-z]\\d') | join(',') }}`, nil, "a1,b2"},
		{`{{ 'a1b2' | regex_findall('(\\d)') | join(',') }}`, nil, "1,2"},
		{`{{ 'a1b2' | regex_findall('([a-z])(\\d)') | first | join('-') }}`, nil, "a-1"},
		{`{{ 'ab\ncd' | regex_findall('(?m)^[a-z]') | join(',') }}`, nil, "a,c"},
		{`{{ 'aba' | regex_findall('a*') | join('|') }}`, nil, "a|a"},
		{`{{ 'b' | regex_findall('a*') | join('|') }}`, nil, "|"},
	}
	for _, tc := range cases {
		got, err := renderBounded(t, tc.tpl, tc.ctx)
		if err != nil {
			t.Fatalf("%s failed: %v", tc.tpl, err)
		}
		if got != tc.want {
			t.Fatalf("%s = %q, want %q", tc.tpl, got, tc.want)
		}
	}
}
