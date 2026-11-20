package jinja_test

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/jinja"
)

const (
	e2eMaxStringBytes = 16 << 20 // 16 MiB (F12 DoS bound)
	e2eRenderTimeout  = 3 * time.Second
)

func e2eRenderBounded(t *testing.T, tpl string, ctx map[string]any, env *jinja.Env, timeout time.Duration) (string, error) {
	t.Helper()
	type res struct {
		out string
		err error
	}
	ch := make(chan res, 1)
	go func() {
		out, err := jinja.Render(tpl, ctx, env)
		ch <- res{out: out, err: err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.out, r.err
	case <-timer.C:
		t.Fatalf("jinja.Render timed out after %v (tpl prefix: %q)", timeout, truncatePrefix(tpl, 80))
		return "", nil
	}
}

func e2eRenderScopedBounded(t *testing.T, tpl string, env *jinja.Env, lookup func(string) any, timeout time.Duration) (string, error) {
	t.Helper()
	type res struct {
		out string
		err error
	}
	ch := make(chan res, 1)
	go func() {
		out, err := jinja.RenderScoped(tpl, env, lookup)
		ch <- res{out: out, err: err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.out, r.err
	case <-timer.C:
		t.Fatalf("jinja.RenderScoped timed out after %v (tpl prefix: %q)", timeout, truncatePrefix(tpl, 80))
		return "", nil
	}
}

func e2eDecodeYAMLBounded(t *testing.T, data []byte, timeout time.Duration) (any, error) {
	t.Helper()
	type res struct {
		val any
		err error
	}
	ch := make(chan res, 1)
	go func() {
		v, err := jinja.DecodeYAML(data)
		ch <- res{val: v, err: err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.val, r.err
	case <-timer.C:
		t.Fatalf("jinja.DecodeYAML timed out after %v", timeout)
		return nil, nil
	}
}

func truncatePrefix(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func TestE2ETier1_CoreRendering(t *testing.T) {
	tpl := `{# header comment -#}
{{- name | upper }}:
{%- if enabled %}
  port={{ port | default(8080) }}
{%- elif fallback %}
  port=9090
{%- else %}
  port=0
{%- endif %}
items=[{% for it in items %}{{ it }}{% if it != items[-1] %},{% endif %}{% endfor %}]
pair={% for k, v in mapping.items() %}{{ k }}={{ v }};{% endfor %}
file={{ lookup('file', 'cfg') }} pipe={{ lookup('pipe', 'date +%s') }}`

	om := jinja.NewOMap()
	om.Set("z", 1)
	om.Set("a", 2)

	env := &jinja.Env{
		FileLookup: func(path string) (string, error) { return "loaded:" + path, nil },
		PipeLookup: func(cmd string) (string, error) { return "1700000000:" + cmd, nil },
	}
	ctx := map[string]any{
		"name":     "edge",
		"enabled":  true,
		"fallback": false,
		"port":     int64(8443),
		"items":    &jinja.List{V: []any{"n1", "n2", "n3"}},
		"mapping":  om,
	}

	got, err := e2eRenderBounded(t, tpl, ctx, env, e2eRenderTimeout)
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}
	want := "EDGE:\n  port=8443\nitems=[n1,n2,n3]\npair=z=1;a=2;\nfile=loaded:cfg pipe=1700000000:date +%s"
	if got != want {
		t.Fatalf("Render mismatch:\ngot:  %q\nwant: %q", got, want)
	}

	// Exported value helpers.
	u := jinja.NewUndefined("missing")
	if !jinja.IsNilOrUndef(u) || !jinja.IsNilOrUndef(nil) || jinja.IsNilOrUndef("x") {
		t.Fatalf("IsNilOrUndef contract failed")
	}
	if jinja.Truthy(u) || jinja.Truthy(false) || jinja.Truthy("") || !jinja.Truthy("ok") {
		t.Fatalf("Truthy contract failed")
	}
	if jinja.Stringify(u) != "" || u.String() != "Undefined(missing)" {
		t.Fatalf("Undefined stringify/String contract failed: %q %q", jinja.Stringify(u), u.String())
	}
	if n, ok := jinja.ToInt("42"); !ok || n != 42 {
		t.Fatalf("ToInt(\"42\") = (%d, %v), want (42, true)", n, ok)
	}
	if iter := jinja.ToIter(&jinja.List{V: []any{"a", "b"}}); len(iter) != 2 {
		t.Fatalf("ToIter length = %d, want 2", len(iter))
	}
}

func TestE2ETier1_SerializationAndOMap(t *testing.T) {
	om := jinja.NewOMapCap(3)
	om.Set("zeta", "last")
	om.Set("alpha", int64(10))
	om.Set("middle", true)
	om.Set("drop", "bye")
	om.Del("drop")

	if om.Len() != 3 {
		t.Fatalf("OMap.Len() = %d, want 3", om.Len())
	}
	if gotKeys := strings.Join(om.Keys(), ","); gotKeys != "zeta,alpha,middle" {
		t.Fatalf("OMap.Keys() = %q, want %q", gotKeys, "zeta,alpha,middle")
	}
	if om.Str("zeta") != "last" || om.Int("alpha") != 10 || !om.Bool("middle") || !om.BoolDef("missing", true) {
		t.Fatalf("OMap typed accessors mismatch")
	}
	if v, ok := om.Get("drop"); ok || v != nil {
		t.Fatalf("deleted key returned (%v, %v)", v, ok)
	}

	gotJSON, err := e2eRenderBounded(t, `{{ m | to_json }}`, map[string]any{"m": om}, nil, e2eRenderTimeout)
	if err != nil {
		t.Fatalf("to_json failed: %v", err)
	}
	wantJSON := `{"zeta":"last","alpha":10,"middle":true}`
	if gotJSON != wantJSON {
		t.Fatalf("to_json did not preserve *OMap insertion order: got %s want %s", gotJSON, wantJSON)
	}

	gotRoundTrip, err := e2eRenderBounded(t, `{% set parsed = raw | from_json %}{{ parsed.k }}:{{ parsed.nums[1] }}`, map[string]any{
		"raw": `{"k":"v","nums":[10,20]}`,
	}, nil, e2eRenderTimeout)
	if err != nil {
		t.Fatalf("from_json failed: %v", err)
	}
	if gotRoundTrip != "v:20" {
		t.Fatalf("from_json got %q, want %q", gotRoundTrip, "v:20")
	}

	gotYAML, err := e2eRenderBounded(t, "{{ m | to_yaml }}---\n{{ m | to_nice_yaml }}", map[string]any{"m": om}, nil, e2eRenderTimeout)
	if err != nil {
		t.Fatalf("to_yaml/to_nice_yaml failed: %v", err)
	}
	if !strings.Contains(gotYAML, "zeta: last\nalpha: 10\nmiddle: true") {
		t.Fatalf("to_yaml lost *OMap key order:\n%s", gotYAML)
	}

	fromYAML, err := e2eRenderBounded(t, `{% set y = doc | from_yaml %}{{ y.z }}/{{ y.a }}`, map[string]any{
		"doc": "z: 1\na: 2\n",
	}, nil, e2eRenderTimeout)
	if err != nil {
		t.Fatalf("from_yaml failed: %v", err)
	}
	if fromYAML != "1/2" {
		t.Fatalf("from_yaml got %q, want %q", fromYAML, "1/2")
	}

	// DecodeYAML with anchors and << merge.
	yamlDoc := []byte(`
base: &base
  timeout: 30
  retries: 3
extra: &extra
  region: us-east
  retries: 99
svc:
  <<: [*base, *extra]
  retries: 5
  port: 08
`)
	decoded, err := e2eDecodeYAMLBounded(t, yamlDoc, e2eRenderTimeout)
	if err != nil {
		t.Fatalf("DecodeYAML failed: %v", err)
	}
	root, ok := decoded.(*jinja.OMap)
	if !ok {
		t.Fatalf("DecodeYAML root = %T, want *jinja.OMap", decoded)
	}
	svcVal, _ := root.Get("svc")
	svc, ok := svcVal.(*jinja.OMap)
	if !ok {
		t.Fatalf("svc = %T, want *jinja.OMap", svcVal)
	}
	if svc.Int("timeout") != 30 || svc.Int("retries") != 5 || svc.Str("region") != "us-east" || svc.Int("port") != 8 {
		t.Fatalf("DecodeYAML merge/int values unexpected: timeout=%d retries=%d region=%q port=%d",
			svc.Int("timeout"), svc.Int("retries"), svc.Str("region"), svc.Int("port"))
	}
}

func TestE2ETier1_Filters(t *testing.T) {
	ctx := map[string]any{
		"nums":  &jinja.List{V: []any{int64(3), int64(1), int64(2), int64(2)}},
		"other": &jinja.List{V: []any{int64(2), int64(4)}},
		"objs": &jinja.List{V: []any{
			map[string]any{"name": "b", "active": true},
			map[string]any{"name": "a", "active": false},
			map[string]any{"name": "c", "active": true},
		}},
		"dict": func() *jinja.OMap {
			m := jinja.NewOMap()
			m.Set("k1", "v1")
			m.Set("k2", "v2")
			return m
		}(),
	}

	cases := []struct {
		name string
		tpl  string
		want string
	}{
		{"int_float", `{{ '7' | int }}|{{ 'bad' | int(9) }}|{{ '2.5' | float }}`, "7|9|2.5"},
		{"default_d", `{{ missing | d('fb') }}|{{ '' | default('empty', boolean=true) }}`, "fb|empty"},
		{"join_indent", `{{ nums | unique | join(',') }}|{{ "a\n\nb" | indent(2) }}`, "3,1,2|  a\n\n  b"},
		{"set_ops", `{{ nums | unique | difference(other) | join(',') }}|{{ nums | union(other) | join(',') }}`, "3,1|3,1,2,4"},
		{"dict_items", `{% set items = dict | dict2items %}{% set back = items | items2dict %}{{ items | length }}:{{ back.k2 }}`, "2:v2"},
		{"min_max_zip", `{{ nums | min }}:{{ nums | max }}:{{ ['a','b'] | zip([1,2]) | map('join', '=') | join(',') }}`, "1:3:a=1,b=2"},
		{"sort_map_select", `{{ objs | selectattr('active') | sort(attribute='name', reverse=true) | map(attribute='name') | join(',') }}`, "c,b"},
		{"reject_rejectattr", `{{ nums | unique | reject('equalto', 2) | join(',') }}|{{ objs | rejectattr('active') | map(attribute='name') | join(',') }}`, "3,1|a"},
		{"select_eq", `{{ nums | select('eq', 2) | length }}`, "2"},
		{"format_ternary_hash", `{{ '%s-%d' | format('n', 4) }}|{{ true | ternary('Y', 'N') }}|{{ 'abc' | hash | length }}`, "n-4|Y|64"},
		{"regex_b64", `{{ 'a.b+c' | regex_escape }}|{{ 'foobar' | regex_replace('bar', 'baz') }}|{{ 'hi' | b64encode | b64decode }}`, `a\.b\+c|foobaz|hi`},
		{"flatten", `{{ [[1, [2]], [3]] | flatten | join(',') }}`, "1,2,3"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := e2eRenderBounded(t, tc.tpl, ctx, nil, e2eRenderTimeout)
			if err != nil {
				t.Fatalf("Render(%s) failed: %v", tc.name, err)
			}
			if got != tc.want {
				t.Fatalf("%s: got %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

func TestE2ETier1_RenderScopedBasic(t *testing.T) {
	lookup := func(name string) any {
		switch name {
		case "host":
			return "node-01"
		case "port":
			return int64(9000)
		case "undef":
			return jinja.NewUndefined("undef")
		default:
			return jinja.NewUndefined(name)
		}
	}
	tpl := `{{ host }}:{{ port }}|{{ undef | default('def') }}|{{ range(3) | join(',') }}`
	got, err := e2eRenderScopedBounded(t, tpl, nil, lookup, e2eRenderTimeout)
	if err != nil {
		t.Fatalf("RenderScoped failed: %v", err)
	}
	if got != "node-01:9000|def|0,1,2" {
		t.Fatalf("RenderScoped got %q, want %q", got, "node-01:9000|def|0,1,2")
	}
}

func TestE2ETier2_UndefinedEqualitySymmetry(t *testing.T) {
	u := jinja.NewUndefined("missing")
	omUndef := jinja.NewOMap()
	omUndef.Set("a", u)
	omEmpty := jinja.NewOMap()
	omEmpty.Set("a", "")

	ctx := map[string]any{
		"u":           u,
		"empty":       "",
		"om_u":        omUndef,
		"om_empty":    omEmpty,
		"map_nil":     map[string]any{"a": nil},
		"map_empty":   map[string]any{"a": ""},
		"list_u":      &jinja.List{V: []any{u}},
		"slice_nil":   []any{nil},
		"slice_empty": []any{""},
	}

	cases := []struct {
		name string
		tpl  string
		want string
	}{
		{"undef_eq_empty", `{{ u == "" }}`, "False"},
		{"empty_eq_undef", `{{ "" == u }}`, "False"},
		{"missing_eq_empty", `{{ nope == empty }}`, "False"},
		{"empty_eq_missing", `{{ empty == nope }}`, "False"},
		{"undef_ne_empty", `{{ u != "" }}`, "True"},
		{"empty_ne_undef", `{{ "" != u }}`, "True"},
		{"undef_eq_none", `{{ u == none }}`, "True"},
		{"none_eq_undef", `{{ none == u }}`, "True"},
		{"undef_eq_undef", `{{ u == nope }}`, "True"},
		// Nested *OMap / map[string]any / *List / []any symmetry.
		{"omap_undef_eq_map_nil", `{{ om_u == map_nil }}`, "True"},
		{"map_nil_eq_omap_undef", `{{ map_nil == om_u }}`, "True"},
		{"omap_undef_ne_map_empty", `{{ om_u == map_empty }}`, "False"},
		{"map_empty_ne_omap_undef", `{{ map_empty == om_u }}`, "False"},
		{"omap_empty_ne_map_nil", `{{ om_empty == map_nil }}`, "False"},
		{"list_undef_eq_slice_nil", `{{ list_u == slice_nil }}`, "True"},
		{"slice_nil_eq_list_undef", `{{ slice_nil == list_u }}`, "True"},
		{"list_undef_ne_slice_empty", `{{ list_u == slice_empty }}`, "False"},
		{"slice_empty_ne_list_undef", `{{ slice_empty == list_u }}`, "False"},
		// Membership (`in`) and `equalto` test/filter symmetry.
		{"undef_in_list_with_none", `{{ u in [none, 'a'] }}`, "True"},
		{"undef_not_in_list_with_empty", `{{ u in ['', 'a'] }}`, "False"},
		{"none_in_list_with_undef", `{{ none in [u] }}`, "True"},
		{"empty_not_in_list_with_undef", `{{ '' in [u] }}`, "False"},
		{"undef_is_equalto_none", `{{ u is equalto(none) }}`, "True"},
		{"none_is_equalto_undef", `{{ none is equalto(u) }}`, "True"},
		{"undef_is_not_equalto_empty", `{{ u is equalto('') }}`, "False"},
		{"empty_is_not_equalto_undef", `{{ '' is equalto(u) }}`, "False"},
		{"filter_equalto_sym", `{{ u | equalto(none) }}|{{ '' | equalto(u) }}`, "True|False"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := e2eRenderBounded(t, tc.tpl, ctx, nil, e2eRenderTimeout)
			if err != nil {
				t.Fatalf("Render failed: %v", err)
			}
			if got != tc.want {
				t.Fatalf("%s: got %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

func TestE2ETier2_ChainedComparisons(t *testing.T) {
	cases := []struct {
		tpl  string
		want string
	}{
		{`{{ 5 < 10 < 3 }}`, "False"},
		{`{{ 2 == 2 == 2 }}`, "True"},
		{`{{ 1 < 2 < 3 }}`, "True"},
		{`{{ 1 < 5 < 3 }}`, "False"},
		{`{{ 1 <= 2 <= 2 < 3 }}`, "True"},
		{`{{ 3 > 2 > 1 }}`, "True"},
		{`{{ 3 > 2 > 5 }}`, "False"},
		{`{{ 'a' in 'ab' == 'ab' }}`, "True"},
	}
	for _, tc := range cases {
		got, err := e2eRenderBounded(t, tc.tpl, nil, nil, e2eRenderTimeout)
		if err != nil {
			t.Fatalf("Render(%s) failed: %v", tc.tpl, err)
		}
		if got != tc.want {
			t.Fatalf("Render(%s) = %q, want %q", tc.tpl, got, tc.want)
		}
	}
}

func TestE2ETier2_FlattenEmptyDAGCap(t *testing.T) {
	// 20-level branching DAG of empty lists: 2^21 - 1 > 2,000,000 node visits
	// with zero leaf elements, exercising the flatten step cap cleanly.
	cur := &jinja.List{}
	for range 20 {
		cur = &jinja.List{V: []any{cur, cur}}
	}
	got, err := e2eRenderBounded(t, `{{ dag | flatten }}`, map[string]any{"dag": cur}, nil, e2eRenderTimeout)
	if err == nil {
		t.Fatalf("expected flatten empty-DAG DoS cap error, got nil error and output %q", got)
	}
}

func TestE2ETier2_SizeBoundsAndParseDepthCap(t *testing.T) {
	oversized := strings.Repeat("a", e2eMaxStringBytes+1)
	exact16MiB := strings.Repeat("a", e2eMaxStringBytes)
	exact12MiB := strings.Repeat("a", 12<<20)
	over12MiB := strings.Repeat("a", (12<<20)+1)
	exact8MiBDots := strings.Repeat(".", e2eMaxStringBytes/2)
	over8MiBDots := strings.Repeat(".", (e2eMaxStringBytes/2)+1)
	exact8MiBA := strings.Repeat("a", e2eMaxStringBytes/2)
	over8MiBA := strings.Repeat("a", (e2eMaxStringBytes/2)+1)

	t.Run("regex_escape_16MiB_plain_pass", func(t *testing.T) {
		got, err := e2eRenderBounded(t, `{{ s | regex_escape | length }}`, map[string]any{"s": exact16MiB}, nil, e2eRenderTimeout)
		if err != nil {
			t.Fatalf("expected regex_escape exact 16MiB plain to pass, got %v", err)
		}
		if got != "16777216" {
			t.Fatalf("regex_escape 16MiB len = %q, want 16777216", got)
		}
	})

	t.Run("regex_escape_16MiB_plus1_fail", func(t *testing.T) {
		got, err := e2eRenderBounded(t, `{{ s | regex_escape | length }}`, map[string]any{"s": oversized}, nil, e2eRenderTimeout)
		if err == nil {
			t.Fatalf("expected regex_escape >16MiB to fail, got %q", got)
		}
	})

	t.Run("regex_escape_8MiB_dots_output_cap", func(t *testing.T) {
		got, err := e2eRenderBounded(t, `{{ s | regex_escape | length }}`, map[string]any{"s": exact8MiBDots}, nil, e2eRenderTimeout)
		if err != nil {
			t.Fatalf("expected regex_escape 8MiB dots (-> 16MiB) to pass, got %v", err)
		}
		if got != "16777216" {
			t.Fatalf("regex_escape 8MiB dots len = %q, want 16777216", got)
		}
		gotOver, err := e2eRenderBounded(t, `{{ s | regex_escape | length }}`, map[string]any{"s": over8MiBDots}, nil, e2eRenderTimeout)
		if err == nil {
			t.Fatalf("expected regex_escape 8MiB+1 dots (>16MiB output) to fail, got %q", gotOver)
		}
	})

	t.Run("b64encode_12MiB_output_cap", func(t *testing.T) {
		got, err := e2eRenderBounded(t, `{{ s | b64encode | length }}`, map[string]any{"s": exact12MiB}, nil, e2eRenderTimeout)
		if err != nil {
			t.Fatalf("expected b64encode 12MiB (-> 16MiB) to pass, got %v", err)
		}
		if got != "16777216" {
			t.Fatalf("b64encode 12MiB len = %q, want 16777216", got)
		}
		gotOver, err := e2eRenderBounded(t, `{{ s | b64encode | length }}`, map[string]any{"s": over12MiB}, nil, e2eRenderTimeout)
		if err == nil {
			t.Fatalf("expected b64encode 12MiB+1 (>16MiB encoded) to fail, got %q", gotOver)
		}
	})

	t.Run("regex_replace_16MiB_and_amplification_caps", func(t *testing.T) {
		const bigTimeout = 20 * time.Second
		got, err := e2eRenderBounded(t, `{{ s | regex_replace('a', 'b') | length }}`, map[string]any{"s": exact16MiB}, nil, bigTimeout)
		if err != nil {
			t.Fatalf("expected regex_replace 16MiB a->b to pass, got %v", err)
		}
		if got != "16777216" {
			t.Fatalf("regex_replace 16MiB len = %q, want 16777216", got)
		}

		gotOver, err := e2eRenderBounded(t, `{{ s | regex_replace('a', 'b') | length }}`, map[string]any{"s": oversized}, nil, e2eRenderTimeout)
		if err == nil {
			t.Fatalf("expected regex_replace >16MiB input to fail, got %q", gotOver)
		}

		gotExp, err := e2eRenderBounded(t, `{{ s | regex_replace('a', 'bb') | length }}`, map[string]any{"s": exact8MiBA}, nil, bigTimeout)
		if err != nil {
			t.Fatalf("expected regex_replace 8MiB a->bb (->16MiB) to pass, got %v", err)
		}
		if gotExp != "16777216" {
			t.Fatalf("regex_replace 8MiB expand len = %q, want 16777216", gotExp)
		}

		gotExpOver, err := e2eRenderBounded(t, `{{ s | regex_replace('a', 'bb') | length }}`, map[string]any{"s": over8MiBA}, nil, bigTimeout)
		if err == nil {
			t.Fatalf("expected regex_replace 8MiB+1 a->bb (>16MiB output) to fail, got %q", gotExpOver)
		}

		manyLines := strings.Repeat("a\n", 1_000_001)
		gotMatchOver, err := e2eRenderBounded(t, `{{ s | regex_replace('(?m)^a', 'b') | length }}`, map[string]any{"s": manyLines}, nil, bigTimeout)
		if err == nil {
			t.Fatalf("expected regex_replace >1,000,000 matches to fail match-count cap, got %q", gotMatchOver)
		}
	})

	t.Run("deep_expr_nesting_cap", func(t *testing.T) {
		deep := "{{ " + strings.Repeat("(", 1500) + "1" + strings.Repeat(")", 1500) + " }}"
		got, err := e2eRenderBounded(t, deep, nil, nil, e2eRenderTimeout)
		if err == nil {
			t.Fatalf("expected deep expression nesting to fail parse-depth cap, got %q", got)
		}
	})

	t.Run("deep_block_nesting_cap", func(t *testing.T) {
		deep := strings.Repeat("{% if true %}", 1500) + "ok" + strings.Repeat("{% endif %}", 1500)
		got, err := e2eRenderBounded(t, deep, nil, nil, e2eRenderTimeout)
		if err == nil {
			t.Fatalf("expected deep block nesting to fail parse-depth cap, got %q", got)
		}
	})

	t.Run("yaml_billion_laughs_alias_cap", func(t *testing.T) {
		var sb strings.Builder
		sb.WriteString("l0: &l0 []\n")
		for i := 1; i <= 25; i++ {
			fmt.Fprintf(&sb, "l%d: &l%d [*l%d, *l%d]\n", i, i, i-1, i-1)
		}
		sb.WriteString("top:\n  <<: *l25\n")
		val, err := e2eDecodeYAMLBounded(t, []byte(sb.String()), e2eRenderTimeout)
		if err == nil {
			t.Fatalf("expected YAML billion-laughs alias expansion to fail cap, got %#v", val)
		}
	})
}

func TestE2ETier2_RenderScopedPrecedenceAndNil(t *testing.T) {
	lookup := func(name string) any {
		switch name {
		case "x":
			return "from_lookup"
		case "item":
			return "lookup_item"
		case "nilval":
			return nil
		case "undefval":
			return jinja.NewUndefined("undefval")
		default:
			return nil
		}
	}

	t.Run("set_overrides_lookup", func(t *testing.T) {
		tpl := `before={{ x }}|{% set x = 'from_set' %}after={{ x }}`
		got, err := e2eRenderScopedBounded(t, tpl, nil, lookup, e2eRenderTimeout)
		if err != nil {
			t.Fatalf("RenderScoped failed: %v", err)
		}
		if got != "before=from_lookup|after=from_set" {
			t.Fatalf("RenderScoped set precedence got %q, want %q", got, "before=from_lookup|after=from_set")
		}
	})

	t.Run("for_loop_overrides_lookup", func(t *testing.T) {
		tpl := `{% for item in ['a', 'b'] %}{{ item }}{% endfor %}|outside={{ item }}`
		got, err := e2eRenderScopedBounded(t, tpl, nil, lookup, e2eRenderTimeout)
		if err != nil {
			t.Fatalf("RenderScoped failed: %v", err)
		}
		if got != "ab|outside=lookup_item" {
			t.Fatalf("RenderScoped for precedence got %q, want %q", got, "ab|outside=lookup_item")
		}
	})

	t.Run("nil_and_undef_lookup", func(t *testing.T) {
		tpl := `{{ nilval is none }}|{{ nilval | default('d') }}|{{ undefval is undefined }}|{% set nilval = 'local' %}{{ nilval }}`
		got, err := e2eRenderScopedBounded(t, tpl, nil, lookup, e2eRenderTimeout)
		if err != nil {
			t.Fatalf("RenderScoped failed: %v", err)
		}
		if got != "True|d|True|local" {
			t.Fatalf("RenderScoped nil/undef got %q, want %q", got, "True|d|True|local")
		}
	})
}

func TestE2ETier2_LexEscapesAndHexInt(t *testing.T) {
	cases := []struct {
		name string
		tpl  string
		want string
	}{
		{"single_quote_regex_d", `{{ '\d+' }}`, `\d+`},
		{"double_quote_regex_s", `{{ "\s+\w+" }}`, `\s+\w+`},
		{"standard_escapes", `{{ 'a\nb\tc\\d\'e' }}`, "a\nb\tc\\d'e"},
		{"hex_int_0x10_base16", `{{ '0x10' | int(0, 16) }}`, "16"},
		{"hex_int_0Xff_base16", `{{ '0Xff' | int(0, 16) }}`, "255"},
		{"hex_int_neg_base16", `{{ '-0x10' | int(0, 16) }}`, "-16"},
		{"hex_int_base0", `{{ '0x10' | int(0, 0) }}`, "16"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := e2eRenderBounded(t, tc.tpl, nil, nil, e2eRenderTimeout)
			if err != nil {
				t.Fatalf("Render(%s) failed: %v", tc.name, err)
			}
			if got != tc.want {
				t.Fatalf("%s: got %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

func TestE2ETier2_MinInt64AndUint64Arithmetic(t *testing.T) {
	ctx := map[string]any{
		"min64": int64(math.MinInt64),
		"max64": int64(math.MaxInt64),
		"u_big": uint64(math.MaxInt64) + 2, // 2^63 + 1
		"u_max": uint64(math.MaxUint64),
		"u_m1":  uint64(math.MaxUint64) - 1,
	}

	cases := []struct {
		name string
		tpl  string
		want string
	}{
		{"min64_plus_ubig", `{{ min64 + u_big }}`, "1"},
		{"ubig_plus_neg5", `{{ u_big + (-5) }}`, "9223372036854775804"},
		{"min64_floordiv_neg1", `{{ min64 // -1 }}`, "9.223372036854776e+18"},
		{"min64_floordiv_neg1_eq_2pow63", `{{ (min64 // -1) == (max64 + 1) }}`, "True"},
		{"min64_mod_neg1", `{{ min64 % -1 }}`, "0"},
		{"min64_negate_unary", `{{ -min64 }}`, "9223372036854775808"},
		{"umax_gt_um1", `{{ u_max > u_m1 }}`, "True"},
		{"umax_ne_um1", `{{ u_max == u_m1 }}`, "False"},
		{"min64_lt_ubig", `{{ min64 < u_big }}`, "True"},
		{"max64_plus_1_mul_neg1", `{{ (max64 + 1) * -1 }}`, "-9223372036854775808"},
		{"ubig_mul_neg1", `{{ u_big * -1 }}`, "-9223372036854775808"},
		{"neg_literal_overflow", `{{ -9223372036854775809 }}`, "-9223372036854775808"},
		{"ubig_mod_2", `{{ u_big % 2 }}`, "1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := e2eRenderBounded(t, tc.tpl, ctx, nil, e2eRenderTimeout)
			if err != nil {
				t.Fatalf("Render(%s) failed: %v", tc.name, err)
			}
			if got != tc.want {
				t.Fatalf("%s: got %q, want %q", tc.name, got, tc.want)
			}
		})
	}

	// Verify (u_big) - (u_big + 3) = -3 accurately without float rounding.
	ctx["u_bigger"] = uint64(math.MaxInt64) + 5
	gotSub, err := e2eRenderBounded(t, `{{ u_big - u_bigger }}`, ctx, nil, e2eRenderTimeout)
	if err != nil {
		t.Fatalf("Render uint64 sub failed: %v", err)
	}
	if gotSub != "-3" {
		t.Fatalf("u_big - u_bigger = %q, want %q", gotSub, "-3")
	}
}

func TestE2ETier2_YAMLSequenceAliasMerge(t *testing.T) {
	doc := []byte(`
defaults: &seq_defaults
  - &a
    x: 1
    y: 2
  - &b
    y: 99
    z: 3
merged:
  <<: *seq_defaults
  z: 42
`)
	val, err := e2eDecodeYAMLBounded(t, doc, e2eRenderTimeout)
	if err != nil {
		t.Fatalf("DecodeYAML with <<: *seq_defaults failed: %v", err)
	}
	root, ok := val.(*jinja.OMap)
	if !ok {
		t.Fatalf("root = %T, want *jinja.OMap", val)
	}
	mv, _ := root.Get("merged")
	merged, ok := mv.(*jinja.OMap)
	if !ok {
		t.Fatalf("merged = %T, want *jinja.OMap", mv)
	}
	if merged.Int("x") != 1 || merged.Int("y") != 2 || merged.Int("z") != 42 {
		t.Fatalf("<<: *seq_defaults values wrong: x=%d y=%d z=%d (want 1, 2, 42)",
			merged.Int("x"), merged.Int("y"), merged.Int("z"))
	}
}

func TestE2ETier2_JSONv2Compatibility(t *testing.T) {
	t.Run("to_json_duration_u2028_u2029_invalid_utf8", func(t *testing.T) {
		type payload struct {
			Timeout time.Duration
			Sep     string
			Invalid string
		}
		p := payload{
			Timeout: 5 * time.Second,
			Sep:     "a\u2028b\u2029c",
			Invalid: "bad-\xff-utf8",
		}
		got, err := e2eRenderBounded(t, `{{ p | to_json }}`, map[string]any{"p": p}, nil, e2eRenderTimeout)
		if err != nil {
			t.Fatalf("to_json on struct with Duration/U+2028/invalid UTF-8 failed: %v", err)
		}
		if !strings.Contains(got, `"Timeout":5000000000`) {
			t.Fatalf("expected time.Duration marshaled as int64 nanoseconds (5000000000), got %s", got)
		}
		if !strings.Contains(got, `\u2028`) || !strings.Contains(got, `\u2029`) {
			t.Fatalf("expected U+2028 and U+2029 escaped as \\u2028/\\u2029, got %s", got)
		}
		if !strings.Contains(got, `"Invalid":"bad-`+"\ufffd"+`-utf8"`) {
			t.Fatalf("expected invalid UTF-8 scrubbed to U+FFFD in Invalid field, got %q", got)
		}
		if !json.Valid([]byte(got)) {
			t.Fatalf("to_json emitted invalid JSON: %s", got)
		}
		var decoded payload
		if err := json.Unmarshal([]byte(got), &decoded); err != nil {
			t.Fatalf("json.Unmarshal(to_json output) failed: %v", err)
		}
		if decoded.Invalid != "bad-\ufffd-utf8" || decoded.Timeout != 5*time.Second {
			t.Fatalf("decoded struct mismatch: %+v", decoded)
		}
	})

	t.Run("to_json_standalone_invalid_utf8", func(t *testing.T) {
		got, err := e2eRenderBounded(t, `{{ s | to_json }}`, map[string]any{"s": "x\xffy"}, nil, e2eRenderTimeout)
		if err != nil {
			t.Fatalf("to_json on standalone invalid UTF-8 failed: %v", err)
		}
		if got != `"x`+"\ufffd"+`y"` {
			t.Fatalf("standalone invalid UTF-8 | to_json = %q, want %q", got, `"x`+"\ufffd"+`y"`)
		}
	})

	t.Run("to_json_plain_duration", func(t *testing.T) {
		got, err := e2eRenderBounded(t, `{{ d | to_json }}`, map[string]any{"d": 1500 * time.Millisecond}, nil, e2eRenderTimeout)
		if err != nil {
			t.Fatalf("to_json on time.Duration failed: %v", err)
		}
		if got != "1500000000" {
			t.Fatalf("time.Duration | to_json = %q, want %q", got, "1500000000")
		}
	})

	t.Run("from_json_duplicate_keys_and_lone_surrogate", func(t *testing.T) {
		raw := `{"k":"first","k":"second","emoji":"bad \uD83D text"}`
		got, err := e2eRenderBounded(t, `{% set d = raw | from_json %}{{ d.k }}|{{ d.emoji | length > 0 }}`, map[string]any{
			"raw": raw,
		}, nil, e2eRenderTimeout)
		if err != nil {
			t.Fatalf("from_json with duplicate keys + lone UTF-16 surrogate failed: %v", err)
		}
		if got != "second|True" {
			t.Fatalf("from_json got %q, want %q", got, "second|True")
		}
	})

	t.Run("from_json_raw_invalid_utf8_and_dup_keys", func(t *testing.T) {
		raw := `{"k":"first","k":"win","raw":"x` + "\xff" + `y"}`
		got, err := e2eRenderBounded(t, `{% set d = raw | from_json %}{{ d.k }}|{{ d.raw }}`, map[string]any{
			"raw": raw,
		}, nil, e2eRenderTimeout)
		if err != nil {
			t.Fatalf("from_json with raw \\xff + duplicate keys failed: %v", err)
		}
		if got != "win|x\ufffdy" {
			t.Fatalf("from_json raw \\xff got %q, want %q", got, "win|x\ufffdy")
		}
	})

	t.Run("from_json_depth_cap", func(t *testing.T) {
		atCap := strings.Repeat(`{"a":`, 64) + `{}` + strings.Repeat(`}`, 64)
		if _, err := e2eRenderBounded(t, `{{ raw | from_json | to_json | length > 0 }}`, map[string]any{"raw": atCap}, nil, e2eRenderTimeout); err != nil {
			t.Fatalf("from_json at depth 64 should succeed, got %v", err)
		}
		overCap := strings.Repeat(`{"a":`, 70) + `{}` + strings.Repeat(`}`, 70)
		got, err := e2eRenderBounded(t, `{{ raw | from_json }}`, map[string]any{"raw": overCap}, nil, e2eRenderTimeout)
		if err == nil {
			t.Fatalf("expected from_json depth 70 (>64) to fail, got %q", got)
		}
	})
}

func TestE2ETier3_TopologyPipeline(t *testing.T) {
	yamlCfg := []byte(`
base_layers: &layers
  - &net
    cidr: "10.42.0.0/16"
    mtu: 1420
  - &dns
    mtu: 1500
    domain: "cluster.local"
cluster:
  <<: *layers
  name: prod-eu
  timeout: 1500
`)
	decoded, err := e2eDecodeYAMLBounded(t, yamlCfg, e2eRenderTimeout)
	if err != nil {
		t.Fatalf("DecodeYAML failed: %v", err)
	}
	root := decoded.(*jinja.OMap)
	clusterVal, _ := root.Get("cluster")
	cluster := clusterVal.(*jinja.OMap)
	cluster.Set("extra_json", `{"mode":"fast","mode":"strict","note":"line\u2028sep"}`)

	lookup := func(name string) any {
		if name == "cluster" {
			return cluster
		}
		if v, ok := cluster.Get(name); ok {
			return v
		}
		return jinja.NewUndefined(name)
	}

	tpl := `{%- set parsed = extra_json | from_json -%}
{%- set out = {'cluster': name, 'cidr': cidr, 'mtu': mtu, 'mode': parsed.mode} -%}
name={{ name }}
regex={{ cidr | regex_replace('\.', '_') }}
json={{ out | to_json }}
yaml:
{{ cluster | to_nice_yaml | indent(2) }}`

	got, err := e2eRenderScopedBounded(t, tpl, nil, lookup, e2eRenderTimeout)
	if err != nil {
		t.Fatalf("Tier3/4 pipeline RenderScoped failed: %v", err)
	}
	if !strings.Contains(got, "name=prod-eu\nregex=10_42_0_0/16\n") {
		t.Fatalf("unexpected pipeline header output:\n%s", got)
	}
	if !strings.Contains(got, `"mode":"strict"`) || !strings.Contains(got, `"mtu":1420`) {
		t.Fatalf("unexpected JSON output in pipeline:\n%s", got)
	}
	if !strings.Contains(got, "yaml:\n  cidr: 10.42.0.0/16\n  mtu: 1420\n  domain: cluster.local\n  name: prod-eu") {
		t.Fatalf("unexpected YAML key order in pipeline:\n%s", got)
	}
}
