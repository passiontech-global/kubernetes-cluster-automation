// filters_kw_test.go — jinja2/ansible keyword-argument parity for the
// filters that grew kw support, plus the jinja2 blank-line semantics
// for |indent and the \r string escape. Expectations were pinned
// against jinja2 3.1.6 (indent blank/first behavior, sort
// case-insensitivity, reverse stability, attribute resolution) and
// the ansible items2dict signature.
package jinja

import (
	"fmt"
	"strings"
	"testing"
)

func TestSortKwargs(t *testing.T) {
	cases := []struct {
		name string
		tpl  string
		ctx  map[string]any
		want string
	}{
		{
			// jinja2 default: strings compare case-insensitively,
			// equal keys keep original order (stable).
			name: "case-insensitive default",
			tpl:  "{{ ['b','A','B','a'] | sort }}",
			want: "[A, a, b, B]",
		},
		{
			name: "case_sensitive kw",
			tpl:  "{{ ['b','A','B','a'] | sort(case_sensitive=true) }}",
			want: "[A, B, a, b]",
		},
		{
			name: "case_sensitive positional",
			tpl:  "{{ ['b','A','B','a'] | sort(false, true) }}",
			want: "[A, B, a, b]",
		},
		{
			// reverse=true is an inverted STABLE comparator: the two
			// b-keys keep their original order (b before B).
			name: "reverse stable",
			tpl:  "{{ ['b','A','B','a'] | sort(reverse=true) }}",
			want: "[b, B, A, a]",
		},
		{
			name: "reverse numbers",
			tpl:  "{{ [3,1,2] | sort(reverse=true) | join(',') }}",
			want: "3,2,1",
		},
		{
			name: "attribute kw",
			tpl:  "{{ xs | sort(attribute='age') | map(attribute='n') | join(',') }}",
			ctx: map[string]any{"xs": []any{
				map[string]any{"n": "x", "age": int64(30)},
				map[string]any{"n": "y", "age": int64(20)},
			}},
			want: "y,x",
		},
		{
			name: "attribute positional",
			tpl:  "{{ xs | sort(false, false, 'age') | map(attribute='n') | join(',') }}",
			ctx: map[string]any{"xs": []any{
				map[string]any{"n": "x", "age": int64(30)},
				map[string]any{"n": "y", "age": int64(20)},
			}},
			want: "y,x",
		},
		{
			name: "attribute dotted path",
			tpl:  "{{ xs | sort(attribute='cfg.user') | map(attribute='cfg.user') | join(',') }}",
			ctx: map[string]any{"xs": []any{
				map[string]any{"cfg": map[string]any{"user": "bob"}},
				map[string]any{"cfg": map[string]any{"user": "ann"}},
			}},
			want: "ann,bob",
		},
		{
			// Multi-key: tuple compare, (1,1) < (1,9) < (2,1).
			name: "attribute comma list",
			tpl:  "{{ xs | sort(attribute='a,b') | map(attribute='b') | join(',') }}",
			ctx: map[string]any{"xs": []any{
				map[string]any{"a": int64(2), "b": int64(1)},
				map[string]any{"a": int64(1), "b": int64(9)},
				map[string]any{"a": int64(1), "b": int64(1)},
			}},
			want: "1,9,1",
		},
		{
			// Digit segments are sequence indexes, python isdigit rule.
			name: "attribute digit segment",
			tpl:  "{{ pairs | sort(attribute='0') | first | last }}",
			ctx: map[string]any{"pairs": []any{
				[]any{int64(10), "x"},
				[]any{int64(9), "y"},
			}},
			want: "y",
		},
		{
			// Attribute folding only reorders; equal keys stay stable.
			name: "attribute case-insensitive",
			tpl:  "{{ xs | sort(attribute='k') | map(attribute='v') | join(',') }}",
			ctx: map[string]any{"xs": []any{
				map[string]any{"k": "b", "v": 1},
				map[string]any{"k": "A", "v": 2},
				map[string]any{"k": "B", "v": 3},
				map[string]any{"k": "a", "v": 4},
			}},
			want: "2,4,1,3",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := renderBounded(t, c.tpl, c.ctx)
			if err != nil {
				t.Fatal(err)
			}
			if out != c.want {
				t.Fatalf("sort = %q want %q", out, c.want)
			}
		})
	}
}

// A missing attribute must ERROR (jinja2 raises UndefinedError) —
// the old silent behavior sorted by garbage.
func TestSortAttributeMissingErrors(t *testing.T) {
	_, err := Render("{{ [{'a':1},{}] | sort(attribute='a') }}", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "no attribute") {
		t.Fatalf("missing sort attribute must error, got %v", err)
	}
}

// Schwartzian regression: a 100-element sort must come out fully
// ordered (decorated keys travel WITH their elements — an index mixup
// scrambles exactly here).
func TestSortSchwartzianLarge(t *testing.T) {
	var items []any
	for i := range 100 {
		items = append(items, fmt.Sprintf("%02d", (i*37)%100))
	}
	out, err := Render("{{ xs | sort | join('') }}", map[string]any{"xs": items}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var want strings.Builder
	for i := range 100 {
		fmt.Fprintf(&want, "%02d", i)
	}
	if out != want.String() {
		t.Fatalf("large sort mismatch")
	}
}

func TestIntFloatDefaultKwargs(t *testing.T) {
	cases := []struct {
		tpl  string
		want string
	}{
		{"{{ 'zz' | int(default=7) }}", "7"},
		{"{{ 'zz' | int(7) }}", "7"},        // positional unchanged
		{"{{ 'zz' | int }}", "0"},           // default default
		{"{{ '12' | int(base=16) }}", "18"}, // 0x12
		{"{{ '12' | int(0, 16) }}", "18"},   // positional base unchanged
		{"{{ 'zz' | float(default=1.5) }}", "1.5"},
		{"{{ 'zz' | float }}", "0"},
		{"{{ '1.5' | float }}", "1.5"},
		{"{{ '' | default(default_value='dv', boolean=true) }}", "dv"},
		{"{{ 0 | default(default_value='dv') }}", "0"}, // defined → kept
		{"{{ '' | default('x', true) }}", "x"},         // positional unchanged
		// base != 10 never takes the decimal-float fallback.
		{"{{ '1.5' | int(0, 16) }}", "0"},
		{"{{ 'ff' | int(0, 16) }}", "255"},
		// Hex-float strings (Go ParseFloat accepts "0x1p-2",
		// python float() does not) don't convert via the fallback.
		{"{{ '0x1p-2' | int }}", "0"},
		{"{{ '0x10' | int }}", "0"}, // no implicit base-0 parsing
		// Underflow below MinInt64 clamps instead of using default.
		{"{{ '-1e300' | int }}", "-9223372036854775808"},
		{"{{ (0 - 1e300) | int }}", "-9223372036854775808"},
		// Overflow above MaxInt64 stays a failure → default.
		{"{{ 1e300 | int(default=7) }}", "7"},
	}
	for _, c := range cases {
		out, err := Render(c.tpl, nil, nil)
		if err != nil {
			t.Fatalf("%s: %v", c.tpl, err)
		}
		if out != c.want {
			t.Fatalf("%s = %q want %q", c.tpl, out, c.want)
		}
	}
}

func TestItems2DictKwargs(t *testing.T) {
	tpl := "{{ items | items2dict(key_name='name', value_name='id') | to_json }}"
	out, err := Render(tpl, map[string]any{"items": []any{
		map[string]any{"name": "a", "id": int64(1)},
		map[string]any{"name": "b", "id": int64(2)},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out != `{"a":1,"b":2}` {
		t.Fatalf("items2dict kw = %q", out)
	}
	// Positional args follow the ansible signature.
	out, err = Render("{{ items | items2dict('name', 'id') | to_json }}", map[string]any{"items": []any{
		map[string]any{"name": "a", "id": int64(1)},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out != `{"a":1}` {
		t.Fatalf("items2dict positional = %q", out)
	}
	// Defaults unchanged.
	out, err = Render("{{ items | items2dict | to_json }}", map[string]any{"items": []any{
		map[string]any{"key": "a", "value": int64(9)},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out != `{"a":9}` {
		t.Fatalf("items2dict defaults = %q", out)
	}
}

// jinja2 (2.10+): EMPTY lines are not indented unless blank=true;
// whitespace-only lines still count as content (python truthiness).
// This port keeps its historical first-line indent.
func TestIndentBlankLines(t *testing.T) {
	cases := []struct {
		tpl  string
		want string
	}{
		{"{{ 'a\\nb' | indent(2) }}", "  a\n  b"},
		{"{{ 'a\\n\\nb' | indent(2) }}", "  a\n\n  b"}, // blank line untouched
		{"{{ 'a\\n\\nb' | indent(2, blank=true) }}", "  a\n  \n  b"},
		{"{{ 'a\\n \\nb' | indent(2) }}", "  a\n   \n  b"}, // ws-only line IS indented
		{"{{ 'a\\n' | indent(2) }}", "  a\n"},              // trailing empty line: no pad
		{"{{ 'a\\n\\nb' | indent }}", "    a\n\n    b"},
	}
	for _, c := range cases {
		out, err := Render(c.tpl, nil, nil)
		if err != nil {
			t.Fatalf("%s: %v", c.tpl, err)
		}
		if out != c.want {
			t.Fatalf("%s = %q want %q", c.tpl, out, c.want)
		}
	}
}

// The lexer's escape set: \r joins \n and \t.
func TestLexCarriageReturnEscape(t *testing.T) {
	out, err := Render(`{{ "a\rb" | length }}`, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out != "3" {
		t.Fatalf(`"a\rb" length = %q want 3`, out)
	}
	out, err = Render(`{{ "x\ry" | regex_replace('\r', 'R') }}`, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out != "xRy" {
		t.Fatalf("escaped CR = %q want xRy", out)
	}
}
