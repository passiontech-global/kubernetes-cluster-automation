// gaps_test.go — coverage for helpers jinja_test.go doesn't exercise:
// NewUndefined/String, RenderScoped, doLookup, OMap.Del, the
// {% if %} statement node, fromJSON re-boxing, and the split
// helpers behind |split.
package jinja

import (
	"reflect"
	"strings"
	"testing"
)

// NewUndefined is the missing-name marker: falsy, undef-tested, and
// it renders as "" (while Undefined.String — the debug form — keeps
// the name).
func TestUndefinedValue(t *testing.T) {
	u := NewUndefined("missing")
	if got := u.String(); got != "Undefined(missing)" {
		t.Fatalf("String() = %q want %q", got, "Undefined(missing)")
	}
	if Truthy(u) {
		t.Fatalf("undefined must be falsy")
	}
	if !IsNilOrUndef(u) {
		t.Fatalf("undefined must satisfy IsNilOrUndef")
	}
	if got := Stringify(u); got != "" {
		t.Fatalf("Stringify(undefined) = %q want \"\"", got)
	}
}

// RenderScoped resolves names through the lookup BEFORE the scope
// vars; a lookup hit shadows a {% set %}, and a nil/Undefined miss
// falls through to the vars the template set itself.
func TestRenderScopedLookupResolver(t *testing.T) {
	lookup := func(name string) any {
		switch name {
		case "a":
			return "A"
		case "b":
			return NewUndefined("b") // miss → scope var
		}
		return nil // miss → scope var
	}
	tpl := `{% set b = 9 %}{% set c = 8 %}{{ a }}{{ b }}{{ c }}`
	got, err := RenderScoped(tpl, nil, lookup)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if got != "A98" {
		t.Fatalf("RenderScoped = %q want %q", got, "A98")
	}
}

// RenderScoped shares the render pipeline: a parse error errors the
// render instead of emitting partial output — and so does an eval
// failure (lookup() with no env hook fails loud).
func TestRenderScopedParseError(t *testing.T) {
	if _, err := RenderScoped("{{ oops", nil, func(string) any { return nil }); err == nil {
		t.Fatalf("unparseable template must error")
	}
	_, err := RenderScoped("{{ lookup('file', 'x') }}", nil, func(string) any { return nil })
	if err == nil || !strings.Contains(err.Error(), "no file lookup configured") {
		t.Fatalf("eval failure must error, got %v", err)
	}
}

// doLookup is the lookup() plugin dispatch: fail-loud on missing
// plugin/term, no env hook, or an unsupported plugin name; 'file' and
// 'pipe' (plus their ansible.builtin aliases) route to the Env hook
// with the term Stringified.
func TestDoLookupDispatch(t *testing.T) {
	hooks := &Env{
		FileLookup: func(path string) (string, error) { return "contents-of-" + path, nil },
		PipeLookup: func(cmd string) (string, error) { return "out:" + cmd, nil },
	}
	hooked := &scope{vars: map[string]any{}, env: hooks}
	unhooked := &scope{vars: map[string]any{}, env: &Env{}}
	noEnv := &scope{vars: map[string]any{}}

	cases := []struct {
		name    string
		s       *scope
		args    []any
		want    any
		wantErr string
	}{
		{"missing plugin", hooked, nil, nil, "lookup: missing plugin name"},
		{"file missing path", hooked, []any{"file"}, nil, `lookup("file"): missing file path`},
		{"file no env", noEnv, []any{"file", "/etc/f"}, nil, `lookup("file"): no file lookup configured`},
		{"file hook nil", unhooked, []any{"file", "/etc/f"}, nil, `lookup("file"): no file lookup configured`},
		{"file ok", hooked, []any{"file", "/etc/f"}, "contents-of-/etc/f", ""},
		{"builtin file alias", hooked, []any{"ansible.builtin.file", "x.txt"}, "contents-of-x.txt", ""},
		{"pipe missing command", hooked, []any{"pipe"}, nil, `lookup("pipe"): missing command`},
		{"pipe no hook", unhooked, []any{"pipe", "date +%s"}, nil, `lookup("pipe"): no pipe lookup configured`},
		{"pipe ok", hooked, []any{"pipe", "date +%s"}, "out:date +%s", ""},
		{"builtin pipe alias", hooked, []any{"ansible.builtin.pipe", "date"}, "out:date", ""},
		{"unsupported plugin", hooked, []any{"url", "http://x"}, nil, `lookup: unsupported plugin "url"`},
	}
	for _, tc := range cases {
		got, err := doLookup(tc.args, tc.s)
		if tc.wantErr != "" {
			if err == nil || err.Error() != tc.wantErr {
				t.Fatalf("%s: err = %v want %q", tc.name, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got != tc.want {
			t.Fatalf("%s = %v want %v", tc.name, got, tc.want)
		}
	}
}

// Del must remove a key while preserving the order of the rest, and
// a miss must be a no-op (no phantom key, no reordering).
func TestOMapDel(t *testing.T) {
	m := NewOMap()
	m.Set("a", 1)
	m.Set("b", 2)
	m.Set("c", 3)

	m.Del("b")
	if got := m.Keys(); !reflect.DeepEqual(got, []string{"a", "c"}) {
		t.Fatalf("Keys after Del = %v want [a c]", got)
	}
	if _, ok := m.Get("b"); ok {
		t.Fatalf("deleted key still present")
	}
	if m.Len() != 2 {
		t.Fatalf("Len = %d want 2", m.Len())
	}

	m.Del("zz")
	if got := m.Keys(); !reflect.DeepEqual(got, []string{"a", "c"}) {
		t.Fatalf("Del of absent key mutated keys: %v", got)
	}

	m.Del("a")
	m.Del("c")
	if m.Len() != 0 {
		t.Fatalf("Len = %d want 0", m.Len())
	}
}

// The {% if/elif/else %} STATEMENT node: first truthy arm renders,
// the nil-cond else arm is the fallback, and no match at all renders
// nothing (distinct from the `x if c else y` expression the engine
// test already covers).
func TestIfStatementRender(t *testing.T) {
	cases := []struct {
		x    string
		want string
	}{
		{"1", "one"},
		{"2", "two"},
		{"3", "other"},
	}
	tpl := `{% if x == 1 %}one{% elif x == 2 %}two{% else %}other{% endif %}`
	for _, tc := range cases {
		got, err := Render(tpl, map[string]any{"x": tc.x}, nil)
		if err != nil {
			t.Fatalf("x=%s: %v", tc.x, err)
		}
		if got != tc.want {
			t.Fatalf("x=%s: got %q want %q", tc.x, got, tc.want)
		}
	}

	got, err := Render(`{% if x == 1 %}one{% endif %}`, map[string]any{"x": "9"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("no matching arm rendered %q want \"\"", got)
	}
}

// fromJSON re-boxes decoded JSON for the evaluator: maps become
// insertion-ordered *OMap with SORTED keys (Go map order), lists
// become *List, integral floats collapse to int64 — non-integral
// floats, strings and bools pass through.
func TestFromJSONReboxing(t *testing.T) {
	out := fromJSON(map[string]any{
		"zeta":  2.0,
		"alpha": []any{1.5, "s", true},
		"mid":   map[string]any{"k": nil},
	})
	m, ok := out.(*OMap)
	if !ok {
		t.Fatalf("fromJSON(map) = %T want *OMap", out)
	}
	if got := strings.Join(m.Keys(), ","); got != "alpha,mid,zeta" {
		t.Fatalf("keys = %q want alpha,mid,zeta", got)
	}
	lst, ok := m.Get("alpha")
	if !ok {
		t.Fatal("alpha missing")
	}
	al, ok := lst.(*List)
	if !ok {
		t.Fatalf("alpha = %T want *List", lst)
	}
	if !reflect.DeepEqual(al.V, []any{1.5, "s", true}) {
		t.Fatalf("alpha = %v", al.V)
	}
	midV, _ := m.Get("mid")
	mid, ok := midV.(*OMap)
	if !ok || mid.Len() != 1 {
		t.Fatalf("mid = %#v want 1-entry *OMap", midV)
	}
	if k, _ := mid.Get("k"); k != nil {
		t.Fatalf("mid.k = %v want nil", k)
	}
	if zeta, _ := m.Get("zeta"); zeta != int64(2) {
		t.Fatalf("zeta = %#v want int64(2)", zeta)
	}

	if got := fromJSON(3.5); got != 3.5 {
		t.Fatalf("fromJSON(3.5) = %v want 3.5", got)
	}
	if got := fromJSON("x"); got != "x" {
		t.Fatalf("fromJSON scalar = %v want x", got)
	}
	if got := fromJSON(nil); got != nil {
		t.Fatalf("fromJSON(nil) = %v want nil", got)
	}
}

// splitWS fields on any whitespace and yields [] (nil) for blanks;
// splitAny keeps empty segments exactly like strings.Split — both
// back the |split filter's argless vs sep forms.
func TestSplitHelpers(t *testing.T) {
	cases := []struct {
		name string
		got  []any
		want []any
	}{
		{"ws fields", splitWS("  a  b\tc\nd "), []any{"a", "b", "c", "d"}},
		{"ws blank", splitWS("   "), nil},
		{"sep segments", splitAny("a,b,,c", ","), []any{"a", "b", "", "c"}},
		{"sep no match", splitAny("x", ","), []any{"x"}},
	}
	for _, tc := range cases {
		if len(tc.got) != len(tc.want) {
			t.Fatalf("%s: len = %d want %d (%v)", tc.name, len(tc.got), len(tc.want), tc.got)
		}
		for i := range tc.got {
			if tc.got[i] != tc.want[i] {
				t.Fatalf("%s[%d] = %v want %v", tc.name, i, tc.got[i], tc.want[i])
			}
		}
	}
}

// union is a set union: unique elements across all operands (Jinja2/Ansible).
func TestUnionDedupes(t *testing.T) {
	tpl := `{{ [1, 2] | union([2, 3]) }}|{{ [true, 'x'] | union([true]) }}|{{ [1, 1, 2] | union([3]) }}`
	got, err := Render(tpl, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := "[1, 2, 3]|[True, x]|[1, 2, 3]"; got != want {
		t.Fatalf("union = %q want %q", got, want)
	}
}

// unique dedupes by value equality, not stringified form.
func TestUniqueDeepEq(t *testing.T) {
	tpl := `{{ [true, 'True'] | unique | length }}|{{ [[1], [1]] | unique | length }}|{{ [1, 1.0] | unique | length }}|{{ ['a', 'a', 'b'] | unique | length }}`
	got, err := Render(tpl, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := "2|1|1|2"; got != want {
		t.Fatalf("unique = %q want %q", got, want)
	}
}

// String indexing counts runes, matching iteration and Python semantics.
func TestStringIndexRune(t *testing.T) {
	tpl := `{{ s[1] }}|{{ s[-4] }}`
	got, err := Render(tpl, map[string]any{"s": "héllo"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := "é|é"; got != want {
		t.Fatalf("index = %q want %q", got, want)
	}
}
