package jinja_test

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/jinja"
)

const (
	e2eReqRenderTimeout  = 10 * time.Second
	e2eReqBigTimeout     = 45 * time.Second
	e2eReqMaxStringBytes = 16 << 20
	e2eReqMaxSeqElems    = 1_000_000
)

func e2eReqTruncatePrefix(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func e2eReqRenderBounded(t *testing.T, tpl string, ctx map[string]any, env *jinja.Env, timeout time.Duration) (string, error) {
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
		t.Fatalf("jinja.Render timed out after %v (tpl prefix: %q)", timeout, e2eReqTruncatePrefix(tpl, 80))
		return "", nil
	}
}

func e2eReqRenderScopedBounded(t *testing.T, tpl string, env *jinja.Env, lookup func(string) any, timeout time.Duration) (string, error) {
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
		t.Fatalf("jinja.RenderScoped timed out after %v (tpl prefix: %q)", timeout, e2eReqTruncatePrefix(tpl, 80))
		return "", nil
	}
}

func e2eReqDecodeYAMLBounded(t *testing.T, data []byte, timeout time.Duration) (any, error) {
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

func TestE2EReqTier1_F1_CoreAPIAndOMapContracts(t *testing.T) {
	t.Run("RenderScoped_ShadowingAndBuiltins", func(t *testing.T) {
		lookup := func(name string) any {
			switch name {
			case "item":
				return "outer-item"
			case "x":
				return "lookup-x"
			default:
				return jinja.NewUndefined(name)
			}
		}
		env := &jinja.Env{
			FileLookup: func(p string) (string, error) { return "file:" + p, nil },
		}
		tpl := `{{ x }}|{% set x = 'set-x' %}{{ x }}|{% for item in range(3) %}{{ item }}{% endfor %}|{{ item }}|{{ lookup('file', 'a.conf') }}`
		got, err := e2eReqRenderScopedBounded(t, tpl, env, lookup, e2eReqRenderTimeout)
		if err != nil {
			t.Fatalf("RenderScoped failed: %v", err)
		}
		if got != "lookup-x|set-x|012|outer-item|file:a.conf" {
			t.Fatalf("RenderScoped = %q, want %q", got, "lookup-x|set-x|012|outer-item|file:a.conf")
		}
	})

	t.Run("OMap_OrderThroughJSONAndYAML", func(t *testing.T) {
		om := jinja.NewOMapCap(4)
		om.Set("zeta", "1")
		om.Set("alpha", int64(2))
		om.Set("drop", "gone")
		om.Set("beta", true)
		om.Del("drop")
		if got := strings.Join(om.Keys(), ","); got != "zeta,alpha,beta" {
			t.Fatalf("Keys() = %q, want %q", got, "zeta,alpha,beta")
		}
		got, err := e2eReqRenderBounded(t, `{{ m | to_json }}|{{ m | to_yaml }}|{{ m | to_nice_yaml }}`, map[string]any{"m": om}, nil, e2eReqRenderTimeout)
		if err != nil {
			t.Fatalf("Render failed: %v", err)
		}
		parts := strings.SplitN(got, "|", 3)
		if len(parts) != 3 {
			t.Fatalf("unexpected parts: %q", got)
		}
		if parts[0] != `{"zeta":"1","alpha":2,"beta":true}` {
			t.Fatalf("to_json = %q", parts[0])
		}
		wantYAML := "zeta: \"1\"\nalpha: 2\nbeta: true\n"
		if parts[1] != wantYAML || parts[2] != wantYAML {
			t.Fatalf("YAML order/content mismatch:\nto_yaml:\n%s\nto_nice_yaml:\n%s", parts[1], parts[2])
		}
	})

	t.Run("WhitespaceAndFlooredDivMod", func(t *testing.T) {
		tpl := `{# ignored -#}
  {{- 'hi' ~ '-' ~ 'there' -}}|
{%- if true -%}
  {{ 7 // 2 }},{{ -7 // 2 }},{{ -7 % 2 }}
{%- endif -%}`
		got, err := e2eReqRenderBounded(t, tpl, nil, nil, e2eReqRenderTimeout)
		if err != nil {
			t.Fatalf("Render failed: %v", err)
		}
		if got != "hi-there|3,-4,1" {
			t.Fatalf("got %q, want %q", got, "hi-there|3,-4,1")
		}
	})

	t.Run("FilterPipeline_SortSelectMapFlattenZip", func(t *testing.T) {
		ctx := map[string]any{
			"nodes": &jinja.List{V: []any{
				map[string]any{"name": "n2", "role": "worker", "ok": true},
				map[string]any{"name": "n1", "role": "control", "ok": true},
				map[string]any{"name": "n3", "role": "worker", "ok": false},
			}},
			"nested": &jinja.List{V: []any{[]any{"a", "b"}, []any{"c"}}},
		}
		tpl := `{{ nodes | selectattr('ok') | sort(attribute='name', reverse=true) | map(attribute='name') | join(',') }}` +
			`|{{ nested | flatten | join('') }}` +
			`|{{ ['x','y'] | zip([1,2]) | map('join', ':') | join(',') }}` +
			`|{% set d = [{'key':'k1','value':'v1'},{'key':'k2','value':'v2'}] | items2dict %}{{ (d | dict2items) | length }}:{{ d.k2 }}`
		got, err := e2eReqRenderBounded(t, tpl, ctx, nil, e2eReqRenderTimeout)
		if err != nil {
			t.Fatalf("Render failed: %v", err)
		}
		if got != "n2,n1|abc|x:1,y:2|2:v2" {
			t.Fatalf("got %q, want %q", got, "n2,n1|abc|x:1,y:2|2:v2")
		}
	})

	t.Run("DecodeYAML_AnchorsMergeAndOctal", func(t *testing.T) {
		doc := []byte(`
base: &base
  replicas: 2
  mode: "0755"
svc:
  <<: *base
  port: 08
  oct: 0o10
`)
		val, err := e2eReqDecodeYAMLBounded(t, doc, e2eReqRenderTimeout)
		if err != nil {
			t.Fatalf("DecodeYAML failed: %v", err)
		}
		root, ok := val.(*jinja.OMap)
		if !ok {
			t.Fatalf("root = %T, want *jinja.OMap", val)
		}
		svcAny, _ := root.Get("svc")
		svc, ok := svcAny.(*jinja.OMap)
		if !ok {
			t.Fatalf("svc = %T, want *jinja.OMap", svcAny)
		}
		if svc.Int("replicas") != 2 || svc.Str("mode") != "0755" || svc.Int("port") != 8 || svc.Int("oct") != 8 {
			t.Fatalf("decoded svc mismatch: replicas=%d mode=%q port=%d oct=%d",
				svc.Int("replicas"), svc.Str("mode"), svc.Int("port"), svc.Int("oct"))
		}
	})
}

func TestE2EReqTier1_F15_BudgetsAndStreamingPass(t *testing.T) {
	t.Run("LoopStepBudget_NormalNestedLoopPasses", func(t *testing.T) {
		tpl := `{% for a in range(50) %}{% for b in range(50) %}{% set x = a + b %}{% endfor %}{% endfor %}ok`
		got, err := e2eReqRenderBounded(t, tpl, nil, nil, e2eReqRenderTimeout)
		if err != nil {
			t.Fatalf("Render failed: %v", err)
		}
		if got != "ok" {
			t.Fatalf("got %q, want %q", got, "ok")
		}
	})

	t.Run("FilterUnion_AllInts_ExactCapPasses", func(t *testing.T) {
		tpl := `{{ range(0, 500000) | union(range(500000, 1000000)) | length }}`
		got, err := e2eReqRenderBounded(t, tpl, nil, nil, e2eReqBigTimeout)
		if err != nil {
			t.Fatalf("union 1,000,000 ints failed: %v", err)
		}
		if got != "1000000" {
			t.Fatalf("got %q, want 1000000", got)
		}
	})

	t.Run("FilterUnion_AllStrings_ExactCapPasses", func(t *testing.T) {
		s1 := make([]string, 500_000)
		s2 := make([]string, 500_000)
		for i := range 500_000 {
			num := strconv.Itoa(i)
			s1[i] = "a-" + num
			s2[i] = "b-" + num
		}
		got, err := e2eReqRenderBounded(t, `{{ s1 | union(s2) | length }}`, map[string]any{"s1": s1, "s2": s2}, nil, e2eReqBigTimeout)
		if err != nil {
			t.Fatalf("union 1,000,000 strings failed: %v", err)
		}
		if got != "1000000" {
			t.Fatalf("got %q, want 1000000", got)
		}
	})

	t.Run("FilterUnion_MixedSmallAndDeduplicatingPasses", func(t *testing.T) {
		got, err := e2eReqRenderBounded(t, `{{ [1, 'a', 1.0, none] | union([2, 'a', 2.0]) | length }}`, nil, nil, e2eReqRenderTimeout)
		if err != nil {
			t.Fatalf("mixed union failed: %v", err)
		}
		if got != "4" {
			t.Fatalf("mixed union len = %q, want 4", got)
		}

		gotDedup, err := e2eReqRenderBounded(t, `{{ range(0, 60000) | union(range(20000, 80000)) | length }}`, nil, nil, e2eReqRenderTimeout)
		if err != nil {
			t.Fatalf("dedup int union failed: %v", err)
		}
		if gotDedup != "80000" {
			t.Fatalf("dedup int union len = %q, want 80000", gotDedup)
		}
	})

	t.Run("ToYAML_And_ToNiceYAML_Under16MiB_PreservesOMapOrder", func(t *testing.T) {
		om := jinja.NewOMapCap(16)
		val := strings.Repeat("a", 32<<10) // 16 * 32 KiB = 512 KiB (< 16 MiB)
		for i := range 16 {
			om.Set(fmt.Sprintf("k%02d", i), val)
		}
		for _, filt := range []string{"to_yaml", "to_nice_yaml"} {
			got, err := e2eReqRenderBounded(t, fmt.Sprintf("{{ m | %s }}", filt), map[string]any{"m": om}, nil, e2eReqBigTimeout)
			if err != nil {
				t.Fatalf("%s under 16MiB failed: %v", filt, err)
			}
			if len(got) > e2eReqMaxStringBytes {
				t.Fatalf("%s len = %d > %d", filt, len(got), e2eReqMaxStringBytes)
			}
			prevIdx := -1
			for i := range 16 {
				needle := fmt.Sprintf("k%02d:", i)
				idx := strings.Index(got, needle)
				if idx <= prevIdx {
					t.Fatalf("%s lost key order at %q (idx=%d, prev=%d)", filt, needle, idx, prevIdx)
				}
				prevIdx = idx
			}
		}
	})
}

func TestE2EReqTier1_F18_RegexClassifierBranches(t *testing.T) {
	t.Run("RegexReplace_LiteralFastPaths", func(t *testing.T) {
		cases := []struct {
			tpl, want string
		}{
			{`{{ 'foo-foo' | regex_replace('foo', 'bar') }}`, "bar-bar"},
			{`{{ 'a.b.c' | regex_replace('\.', '_') }}`, "a_b_c"},
			{`{{ 'x-foo-y' | regex_replace('(foo)', 'baz') }}`, "x-baz-y"},
			{`{{ 'unchanged' | regex_replace('zzz', 'bar') }}`, "unchanged"},
		}
		for _, tc := range cases {
			got, err := e2eReqRenderBounded(t, tc.tpl, nil, nil, e2eReqRenderTimeout)
			if err != nil {
				t.Fatalf("Render(%s): %v", tc.tpl, err)
			}
			if got != tc.want {
				t.Fatalf("Render(%s) = %q, want %q", tc.tpl, got, tc.want)
			}
		}
	})

	t.Run("RegexReplace_EmptyAndLinePrefix", func(t *testing.T) {
		ctx := map[string]any{
			"lf":   "a\nb\na",
			"crlf": "a\r\nb\r\na",
		}
		cases := []struct {
			tpl, want string
		}{
			{`{{ 'ab' | regex_replace('', '-') }}`, "-a-b-"},
			{`{{ 'a' | regex_replace('', '$$') }}`, "$a$"},
			{`{{ lf | regex_replace('(?m)^a', 'X') }}`, "X\nb\nX"},
			{`{{ crlf | regex_replace('(?m)^a', 'X') }}`, "X\r\nb\r\nX"},
			{`{{ lf | regex_replace('(?m)^[ab]', 'X') }}`, "X\nX\nX"},
		}
		for _, tc := range cases {
			got, err := e2eReqRenderBounded(t, tc.tpl, ctx, nil, e2eReqRenderTimeout)
			if err != nil {
				t.Fatalf("Render(%s): %v", tc.tpl, err)
			}
			if got != tc.want {
				t.Fatalf("Render(%s) = %q, want %q", tc.tpl, got, tc.want)
			}
		}
	})

	t.Run("RegexReplace_AnchorsAndExpand", func(t *testing.T) {
		cases := []struct {
			tpl, want string
		}{
			{`{{ 'abc-abc' | regex_replace('\Aa', 'Z') }}`, "Zbc-abc"},
			{`{{ 'foofoo-foo' | regex_replace('\A(?:foo)+', 'X') }}`, "X-foo"},
			{`{{ 'alpha beta' | regex_replace('\ba', 'X') }}`, "Xlpha beta"},
			{`{{ 'bar' | regex_replace('\Ba', 'O') }}`, "bOr"},
			{`{{ 'a-b' | regex_replace('a|^b', 'X') }}`, "X-b"},
			{`{{ 'ab' | regex_replace('(a)(b)', '$2-$1') }}`, "b-a"},
		}
		for _, tc := range cases {
			got, err := e2eReqRenderBounded(t, tc.tpl, nil, nil, e2eReqRenderTimeout)
			if err != nil {
				t.Fatalf("Render(%s): %v", tc.tpl, err)
			}
			if got != tc.want {
				t.Fatalf("Render(%s) = %q, want %q", tc.tpl, got, tc.want)
			}
		}
	})

	t.Run("RegexFindall_SingleLiteralCaptureAndGeneral", func(t *testing.T) {
		cases := []struct {
			tpl, want string
		}{
			{`{{ 'foo-bar-foo' | regex_findall('(foo)') | join(',') }}`, "foo,foo"},
			{`{{ 'a.b.c' | regex_findall('(\.)') | join(',') }}`, ".,."},
			{`{{ 'FOO foo Foo' | regex_findall('(?i)(foo)') | join(',') }}`, "FOO,foo,Foo"},
			{`{{ 'abac' | regex_findall('([ab])') | join(',') }}`, "a,b,a"},
			{`{{ 'ab1 ab2' | regex_findall('(a)(b)') | length }}`, "2"},
			{`{{ 'aa b aaa' | regex_findall('a+') | join(',') }}`, "aa,aaa"},
		}
		for _, tc := range cases {
			got, err := e2eReqRenderBounded(t, tc.tpl, nil, nil, e2eReqRenderTimeout)
			if err != nil {
				t.Fatalf("Render(%s): %v", tc.tpl, err)
			}
			if got != tc.want {
				t.Fatalf("Render(%s) = %q, want %q", tc.tpl, got, tc.want)
			}
		}
	})

	t.Run("RegexSearch_FilterAndTestParity", func(t *testing.T) {
		tpl := `{{ 'node-42' | regex_search('node-\d+') }}|{{ 'node-42' | regex_search('node-(\d+)') }}|{{ ('node-42' | regex_search('missing')) is undefined }}|{{ 'node-42' is search('node-\d+') }}|{{ 'node-42' is search('missing') }}`
		got, err := e2eReqRenderBounded(t, tpl, nil, nil, e2eReqRenderTimeout)
		if err != nil {
			t.Fatalf("Render failed: %v", err)
		}
		if got != "node-42|[42]|True|True|False" {
			t.Fatalf("got %q, want %q", got, "node-42|[42]|True|True|False")
		}
	})
}

func TestE2EReqTier2_F1_BoundaryAndErrorContracts(t *testing.T) {
	t.Run("UnparseableTemplate_ErrorsEveryRender", func(t *testing.T) {
		for _, bad := range []string{`{{ unclosed`, `{% if true %}no-endif`} {
			for range 2 {
				if out, err := e2eReqRenderBounded(t, bad, nil, nil, e2eReqRenderTimeout); err == nil {
					t.Fatalf("expected parse error for %q, got %q", bad, out)
				}
			}
		}
	})

	t.Run("CyclicListAndOMap_TerminatesInWalkBudget", func(t *testing.T) {
		cl := &jinja.List{}
		cl.V = []any{cl}
		cm := jinja.NewOMap()
		cm.Set("self", cm)
		got, err := e2eReqRenderBounded(t, `{{ cl | to_json | length > 0 }}|{{ cm | to_yaml | length > 0 }}`, map[string]any{
			"cl": cl,
			"cm": cm,
		}, nil, e2eReqRenderTimeout)
		if err != nil {
			t.Fatalf("cyclic render failed: %v", err)
		}
		if got != "True|True" {
			t.Fatalf("cyclic output = %q, want True|True", got)
		}
	})

	t.Run("Undefined_And_MandatoryFilter", func(t *testing.T) {
		got, err := e2eReqRenderBounded(t, `{{ missing | default('fallback') }}`, nil, nil, e2eReqRenderTimeout)
		if err != nil || got != "fallback" {
			t.Fatalf("default on missing = (%q, %v), want (%q, nil)", got, err, "fallback")
		}
		if out, err := e2eReqRenderBounded(t, `{{ missing | mandatory }}`, nil, nil, e2eReqRenderTimeout); err == nil {
			t.Fatalf("expected mandatory error on missing var, got %q", out)
		}
	})

	t.Run("FromJSON_FromYAML_4MiBInputCap", func(t *testing.T) {
		const fourMiB = 4 << 20
		okJSON := `"` + strings.Repeat("a", fourMiB-2) + `"`
		if _, err := e2eReqRenderBounded(t, `{{ s | from_json | length }}`, map[string]any{"s": okJSON}, nil, e2eReqBigTimeout); err != nil {
			t.Fatalf("from_json at 4MiB failed: %v", err)
		}
		overJSON := `"` + strings.Repeat("a", fourMiB) + `"`
		if out, err := e2eReqRenderBounded(t, `{{ s | from_json }}`, map[string]any{"s": overJSON}, nil, e2eReqBigTimeout); err == nil {
			t.Fatalf("expected from_json >4MiB error, got %q", out)
		}

		okYAML := "k: " + strings.Repeat("b", fourMiB-3)
		if _, err := e2eReqRenderBounded(t, `{{ (s | from_yaml).k | length }}`, map[string]any{"s": okYAML}, nil, e2eReqBigTimeout); err != nil {
			t.Fatalf("from_yaml at 4MiB failed: %v", err)
		}
		overYAML := "k: " + strings.Repeat("b", fourMiB)
		if out, err := e2eReqRenderBounded(t, `{{ s | from_yaml }}`, map[string]any{"s": overYAML}, nil, e2eReqBigTimeout); err == nil {
			t.Fatalf("expected from_yaml >4MiB error, got %q", out)
		}
	})

	t.Run("Range_ZeroStep_And_MaxOutCap", func(t *testing.T) {
		if out, err := e2eReqRenderBounded(t, `{{ range(0, 10, 0) }}`, nil, nil, e2eReqRenderTimeout); err == nil {
			t.Fatalf("expected range zero-step error, got %q", out)
		}
		if out, err := e2eReqRenderBounded(t, `{{ range(1000001) | length }}`, nil, nil, e2eReqRenderTimeout); err == nil {
			t.Fatalf("expected range >1,000,000 error, got %q", out)
		}
	})
}

func TestE2EReqTier2_F15_DoSBudgetBoundaries(t *testing.T) {
	t.Run("LoopStepBudget_ExactBoundary999999PassVs1001000Fail", func(t *testing.T) {
		// Outer 999 steps + inner 999*1000 steps = 999,999 <= 1,000,000 -> PASS.
		passTpl := `{% for a in range(999) %}{% for b in range(1000) %}{% endfor %}{% endfor %}ok`
		got, err := e2eReqRenderBounded(t, passTpl, nil, nil, e2eReqBigTimeout)
		if err != nil {
			t.Fatalf("999,999-step loop failed: %v", err)
		}
		if got != "ok" {
			t.Fatalf("999,999-step loop = %q, want %q", got, "ok")
		}

		// Outer 1000 steps + inner 1000*1000 steps = 1,001,000 > 1,000,000 -> FAIL.
		failTpl := `{% for a in range(1000) %}{% for b in range(1000) %}{% endfor %}{% endfor %}ok`
		if out, err := e2eReqRenderBounded(t, failTpl, nil, nil, e2eReqBigTimeout); err == nil {
			t.Fatalf("expected 1,001,000-step loop to fail budget, got %q", out)
		}
	})

	t.Run("LoopStepBudget_ZeroOutputNestedDoS_ErrorsWithinBudget", func(t *testing.T) {
		dosTpl := `{% for a in range(1000) %}{% for b in range(1000) %}{% for c in range(1000) %}{% set x = 1 %}{% endfor %}{% endfor %}{% endfor %}`
		if out, err := e2eReqRenderBounded(t, dosTpl, nil, nil, e2eReqBigTimeout); err == nil {
			t.Fatalf("expected Render zero-output 1000^3 loop DoS error, got %q", out)
		}
		scopedDoS := `{% for a in range(1000) %}{% for b in range(1001) %}{% endfor %}{% endfor %}`
		if out, err := e2eReqRenderScopedBounded(t, scopedDoS, nil, func(string) any { return nil }, e2eReqBigTimeout); err == nil {
			t.Fatalf("expected RenderScoped zero-output nested loop DoS error, got %q", out)
		}
	})

	t.Run("LoopStepBudget_FilteredIfConditionDoS_ErrorsWithinBudget", func(t *testing.T) {
		filteredDoS := `{% for a in range(1000) %}{% for b in range(1000) %}{% for c in range(1000) if c < 0 %}{{ c }}{% endfor %}{% endfor %}{% endfor %}`
		if out, err := e2eReqRenderBounded(t, filteredDoS, nil, nil, e2eReqBigTimeout); err == nil {
			t.Fatalf("expected filtered if-condition DoS loop to error, got %q", out)
		}

		// Budget must be render-local; subsequent normal loop render succeeds.
		got, err := e2eReqRenderBounded(t, `{% for i in range(4) %}{{ i }}{% endfor %}`, nil, nil, e2eReqRenderTimeout)
		if err != nil || got != "0123" {
			t.Fatalf("subsequent render after loop budget failure = (%q, %v), want (%q, nil)", got, err, "0123")
		}
	})

	t.Run("FilterUnion_AllInts_OverCapErrors", func(t *testing.T) {
		if out, err := e2eReqRenderBounded(t, `{{ range(0, 500000) | union(range(500000, 1000001)) | length }}`, nil, nil, e2eReqBigTimeout); err == nil {
			t.Fatalf("expected 1,000,001-int union to fail, got %q", out)
		}
		if out, err := e2eReqRenderBounded(t, `{{ range(0, 400000) | union(range(400000, 800000), range(800000, 1000001)) | length }}`, nil, nil, e2eReqBigTimeout); err == nil {
			t.Fatalf("expected 3-operand 1,000,001-int union to fail, got %q", out)
		}
	})

	t.Run("FilterUnion_AllStrings_OverCapErrors", func(t *testing.T) {
		s1 := make([]string, 500_000)
		s2 := make([]string, 500_001)
		for i := range 500_000 {
			num := strconv.Itoa(i)
			s1[i] = "s1-" + num
			s2[i] = "s2-" + num
		}
		s2[500_000] = "s2-500000"
		if out, err := e2eReqRenderBounded(t, `{{ s1 | union(s2) | length }}`, map[string]any{"s1": s1, "s2": s2}, nil, e2eReqBigTimeout); err == nil {
			t.Fatalf("expected 1,000,001-string union to fail, got %q", out)
		}
	})

	t.Run("ToYAML_And_ToNiceYAML_Over16MiB_StreamingCapErrorsFast", func(t *testing.T) {
		// 17 keys x 1 MiB = 17 MiB with only 35 walk steps (well below walkMaxSteps = 100,000).
		over17 := jinja.NewOMapCap(17)
		oneMiB := strings.Repeat("x", 1<<20)
		for i := range 17 {
			over17.Set(fmt.Sprintf("k%02d", i), oneMiB)
		}
		for _, filt := range []string{"to_yaml", "to_nice_yaml"} {
			if out, err := e2eReqRenderBounded(t, fmt.Sprintf("{{ m | %s }}", filt), map[string]any{"m": over17}, nil, e2eReqBigTimeout); err == nil {
				t.Fatalf("expected %s 17MiB to fail streaming cap, got %d bytes", filt, len(out))
			}
		}
	})
}

func TestE2EReqTier2_F18_RegexCacheEvictionAndRace(t *testing.T) {
	t.Run("InvalidRegex_NeverPoisonsCache", func(t *testing.T) {
		for range 3 {
			if out, err := e2eReqRenderBounded(t, `{{ 'abc' | regex_replace('(', 'x') }}`, nil, nil, e2eReqRenderTimeout); err == nil {
				t.Fatalf("expected invalid regex_replace error, got %q", out)
			}
			if out, err := e2eReqRenderBounded(t, `{{ 'abc' | regex_findall('[') }}`, nil, nil, e2eReqRenderTimeout); err == nil {
				t.Fatalf("expected invalid regex_findall error, got %q", out)
			}
			if out, err := e2eReqRenderBounded(t, `{{ 'abc' | regex_search('(') }}`, nil, nil, e2eReqRenderTimeout); err == nil {
				t.Fatalf("expected invalid regex_search error, got %q", out)
			}
			got, err := e2eReqRenderBounded(t, `{{ 'abc' is search('(') }}`, nil, nil, e2eReqRenderTimeout)
			if err != nil || got != "False" {
				t.Fatalf("is search('(') = (%q, %v), want (\"False\", nil)", got, err)
			}
		}
	})

	t.Run("EvictionPast512Patterns_PreservesCorrectness", func(t *testing.T) {
		const total = 640
		for i := range total {
			pat := fmt.Sprintf("pat_%03d", i)
			tpl := fmt.Sprintf(`{{ '%s_val' | regex_replace('%s', 'hit') }}|{{ '%s' | regex_findall('(%s)') | join(',') }}|{{ '%s' is search('%s') }}`,
				pat, pat, pat, pat, pat, pat)
			got, err := e2eReqRenderBounded(t, tpl, nil, nil, e2eReqRenderTimeout)
			if err != nil {
				t.Fatalf("render %d failed: %v", i, err)
			}
			want := fmt.Sprintf("hit_val|%s|True", pat)
			if got != want {
				t.Fatalf("render %d = %q, want %q", i, got, want)
			}
		}
		// Re-render early evicted patterns (0..20) and verify exact results after eviction.
		for i := range 21 {
			pat := fmt.Sprintf("pat_%03d", i)
			tpl := fmt.Sprintf(`{{ '%s_val' | regex_replace('%s', 'ok') }}|{{ '%s' | regex_findall('(%s)') | join(',') }}`, pat, pat, pat, pat)
			got, err := e2eReqRenderBounded(t, tpl, nil, nil, e2eReqRenderTimeout)
			if err != nil {
				t.Fatalf("re-render evicted %d failed: %v", i, err)
			}
			want := fmt.Sprintf("ok_val|%s", pat)
			if got != want {
				t.Fatalf("re-render evicted %d = %q, want %q", i, got, want)
			}
		}
	})

	t.Run("PatternEdgeCases_CaseFoldAndCaptureOptional", func(t *testing.T) {
		cases := []struct {
			tpl, want string
		}{
			{`{{ 'FOO foo' | regex_replace('(?i)foo', 'x') }}`, "x x"},
			{`{{ 'FOO foo' | regex_findall('(?i)(foo)') | join(',') }}`, "FOO,foo"},
			{`{{ 'a ab' | regex_replace('(a)(b)?', '[$1:$2]') }}`, "[a:] [a:b]"},
			{`{{ '' | regex_replace('foo', 'bar') }}`, ""},
			{`{{ '' | regex_replace('', 'x') }}`, "x"},
			{`{{ '' | regex_replace('\Aa', 'x') }}`, ""},
		}
		for _, tc := range cases {
			got, err := e2eReqRenderBounded(t, tc.tpl, nil, nil, e2eReqRenderTimeout)
			if err != nil {
				t.Fatalf("Render(%s): %v", tc.tpl, err)
			}
			if got != tc.want {
				t.Fatalf("Render(%s) = %q, want %q", tc.tpl, got, tc.want)
			}
		}
	})

	t.Run("LiteralMetacharAndDollarExpandDistinction", func(t *testing.T) {
		cases := []struct {
			tpl, want string
		}{
			{`{{ 'a' | regex_replace('a', '$$') }}`, "$"},
			{`{{ 'a' | regex_replace('a', '$1') }}`, ""},
			{`{{ 'a' | regex_replace('a', 'b') }}`, "b"},
			{`{{ 'foo' | regex_replace('(foo)', 'X') }}`, "X"},
			{`{{ 'foo' | regex_replace('(foo)', '[$1]') }}`, "[foo]"},
		}
		for _, tc := range cases {
			got, err := e2eReqRenderBounded(t, tc.tpl, nil, nil, e2eReqRenderTimeout)
			if err != nil {
				t.Fatalf("Render(%s): %v", tc.tpl, err)
			}
			if got != tc.want {
				t.Fatalf("Render(%s) = %q, want %q", tc.tpl, got, tc.want)
			}
		}
	})

	t.Run("ConcurrentStress_600Patterns_Race", func(t *testing.T) {
		const workers = 8
		const iters = 150
		var wg sync.WaitGroup
		errs := make(chan error, workers)
		for g := range workers {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for i := range iters {
					idx := (id*iters + i) % 600
					pat := fmt.Sprintf("p_%03d", idx)
					// 1. Hot shared literal/anchor/capture patterns across workers.
					out1, err := jinja.Render(`{{ 'a.b' | regex_replace('\.', '_') }}|{{ 'FOO' | regex_findall('(?i)(foo)') | join(',') }}|{{ 'ab' | regex_replace('(a)(b)', '$2$1') }}`, nil, nil)
					if err != nil || out1 != "a_b|FOO|ba" {
						errs <- fmt.Errorf("shared render = (%q, %w)", out1, err)
						return
					}
					// 2. Rotating >512 distinct patterns triggering eviction under -race.
					tpl2 := fmt.Sprintf(`{{ '%s' | regex_replace('(%s)', '[$1]') }}|{{ '%s' is search('^p_') }}`, pat, pat, pat)
					out2, err := jinja.Render(tpl2, nil, nil)
					if err != nil || out2 != fmt.Sprintf("[%s]|True", pat) {
						errs <- fmt.Errorf("rotating render %d = (%q, %w)", idx, out2, err)
						return
					}
					// 3. Invalid pattern must never poison cache or race.
					if _, err := jinja.Render(`{{ 'x' | regex_replace('(', 'y') }}`, nil, nil); err == nil {
						errs <- fmt.Errorf("invalid regex unexpectedly succeeded")
						return
					}
				}
			}(g)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}
	})
}

func TestE2EReqTier3_PairwiseInteractions(t *testing.T) {
	t.Run("F1_RenderScoped_X_F15_LoopAndUnion", func(t *testing.T) {
		om := jinja.NewOMap()
		om.Set("first", "alpha")
		om.Set("second", "beta")
		lookup := func(name string) any {
			switch name {
			case "nodes":
				return om
			case "a":
				return []any{"alpha", "gamma"}
			case "b":
				return []any{"beta", "gamma"}
			default:
				return jinja.NewUndefined(name)
			}
		}
		tpl := `{% for k in nodes %}{% for r in (a | union(b)) %}{% if r == nodes[k] %}{{ k }}={{ r }};{% endif %}{% endfor %}{% endfor %}`
		got, err := e2eReqRenderScopedBounded(t, tpl, nil, lookup, e2eReqRenderTimeout)
		if err != nil {
			t.Fatalf("RenderScoped failed: %v", err)
		}
		if got != "first=alpha;second=beta;" {
			t.Fatalf("got %q, want %q", got, "first=alpha;second=beta;")
		}

		// Oversized loop in RenderScoped fails without affecting subsequent RenderScoped calls.
		bad := `{% for i in range(1000) %}{% for j in range(1001) %}{% endfor %}{% endfor %}`
		if out, err := e2eReqRenderScopedBounded(t, bad, nil, lookup, e2eReqBigTimeout); err == nil {
			t.Fatalf("expected RenderScoped loop budget error, got %q", out)
		}
		got2, err := e2eReqRenderScopedBounded(t, `{{ a | union(b) | join(',') }}`, nil, lookup, e2eReqRenderTimeout)
		if err != nil || got2 != "alpha,gamma,beta" {
			t.Fatalf("post-error RenderScoped = (%q, %v), want (%q, nil)", got2, err, "alpha,gamma,beta")
		}
	})

	t.Run("F1_OMapOrder_X_F15_StreamingToYAML", func(t *testing.T) {
		om := jinja.NewOMapCap(10)
		chunk := strings.Repeat("m", 64<<10) // 64 KiB * 10 = 640 KiB
		for i := 9; i >= 0; i-- {
			om.Set(fmt.Sprintf("z%02d", i), chunk)
		}
		got, err := e2eReqRenderBounded(t, `{{ m | to_yaml }}`, map[string]any{"m": om}, nil, e2eReqBigTimeout)
		if err != nil {
			t.Fatalf("640KiB to_yaml failed: %v", err)
		}
		prev := -1
		for i := 9; i >= 0; i-- {
			idx := strings.Index(got, fmt.Sprintf("z%02d:", i))
			if idx <= prev {
				t.Fatalf("to_yaml order broken at z%02d", i)
			}
			prev = idx
		}

		om.Set("overflow", strings.Repeat("n", 16<<20)) // total > 16 MiB
		if out, err := e2eReqRenderBounded(t, `{{ m | to_json }}`, map[string]any{"m": om}, nil, e2eReqBigTimeout); err == nil {
			t.Fatalf("expected >16MiB to_json error, got %d bytes", len(out))
		}
	})

	t.Run("F15_OutputCaps_X_F18_RegexFiltersInLoop", func(t *testing.T) {
		// Inside bounded loop: regex_replace hitting maxStringBytes fails cleanly without poisoning regexCache.
		ctx := map[string]any{"big": strings.Repeat("a", 1<<20)}
		badTpl := `{% set s = '' %}{% for i in range(17) %}{% set s = s ~ (big | regex_replace('a', 'b')) %}{% endfor %}{{ s | length }}`
		if out, err := e2eReqRenderBounded(t, badTpl, ctx, nil, e2eReqBigTimeout); err == nil {
			t.Fatalf("expected string cap error in loop with regex_replace, got %q", out)
		}

		// Subsequent loop using the exact same pattern succeeds.
		okTpl := `{% set items = [] %}{% for i in range(4) %}{% set _ = items.append('ab' | regex_replace('a', 'b')) %}{% endfor %}{{ items | join('') | length }}`
		got, err := e2eReqRenderBounded(t, okTpl, nil, nil, e2eReqRenderTimeout)
		if err != nil || got != "8" {
			t.Fatalf("recovery loop = (%q, %v), want (%q, nil)", got, err, "8")
		}
	})

	t.Run("F15_FilterUnion_X_F18_RegexFindall", func(t *testing.T) {
		// regex_findall returns a list of strings; piped into union deduplicates cleanly and respects maxSeqElems (1M+1 fail).
		got, err := e2eReqRenderBounded(t, `{{ ('tok1 tok2 tok1' | regex_findall('(tok\d)')) | union(['tok2', 'tok3']) | join(',') }}`, nil, nil, e2eReqRenderTimeout)
		if err != nil || got != "tok1,tok2,tok3" {
			t.Fatalf("findall|union dedup = (%q, %v), want (\"tok1,tok2,tok3\", nil)", got, err)
		}

		sOver := make([]string, 999_999)
		for i := range sOver {
			sOver[i] = "u-" + strconv.Itoa(i)
		}
		if out, err := e2eReqRenderBounded(t, `{{ ('tok1 tok2' | regex_findall('(tok\d)')) | union(sOver) | length }}`, map[string]any{"sOver": sOver}, nil, e2eReqBigTimeout); err == nil {
			t.Fatalf("expected findall|union 1,000,001 to fail, got %q", out)
		}
	})
}

func TestE2EReqTier4_Scenario2_ProductionHostconfigPipeline(t *testing.T) {
	varsDoc := []byte(`
defaults: &node_defaults
  zone: eu-central-1
  roles:
    - worker
    - storage
interdc_nodes:
  - name: node-alpha
    <<: *node_defaults
    endpoint: "10.10.1.10"
    banner: "line1\nline2"
    tags:
      - ingress
      - worker
  - name: node-beta
    <<: *node_defaults
    endpoint: "10.10.2.20"
    banner: "lineA\nlineB"
    tags:
      - control
`)
	decoded, err := e2eReqDecodeYAMLBounded(t, varsDoc, e2eReqRenderTimeout)
	if err != nil {
		t.Fatalf("DecodeYAML failed: %v", err)
	}
	root, ok := decoded.(*jinja.OMap)
	if !ok {
		t.Fatalf("DecodeYAML root = %T, want *jinja.OMap", decoded)
	}

	lookup := func(name string) any {
		if v, exists := root.Get(name); exists {
			return v
		}
		return jinja.NewUndefined(name)
	}

	tpl := `{%- set out = [] -%}
{%- for n in interdc_nodes -%}
  {%- set merged_roles = n.roles | union(n.tags) -%}
  {%- set host_prefix = n.name | regex_replace('\Anode-', 'dc-') -%}
  {%- set octets = n.endpoint | regex_findall('(\d+)') -%}
  {%- set norm_banner = n.banner | regex_replace('(?m)^line', 'row-') -%}
  {%- set entry = {'host': host_prefix, 'zone': n.zone, 'roles': merged_roles, 'octets': octets, 'banner': norm_banner} -%}
  {%- set _ = out.append(entry) -%}
{%- endfor -%}
{{ out | to_nice_yaml }}`

	got, err := e2eReqRenderScopedBounded(t, tpl, nil, lookup, e2eReqRenderTimeout)
	if err != nil {
		t.Fatalf("production pipeline render failed: %v", err)
	}
	for _, wantSubstr := range []string{
		"host: dc-alpha",
		"host: dc-beta",
		"zone: eu-central-1",
		"- worker",
		"- storage",
		"- ingress",
		"- control",
		"row-1",
		"row-B",
	} {
		if !strings.Contains(got, wantSubstr) {
			t.Fatalf("pipeline output missing %q:\n%s", wantSubstr, got)
		}
	}

	// Preserve exact *OMap key order when serialized directly through to_yaml.
	ordered := jinja.NewOMapCap(3)
	ordered.Set("cluster", "prod-eu")
	ordered.Set("nodes", func() any { v, _ := root.Get("interdc_nodes"); return v }())
	ordered.Set("checksum", "ok")
	orderedOut, err := e2eReqRenderBounded(t, `{{ cfg | to_yaml }}`, map[string]any{"cfg": ordered}, nil, e2eReqRenderTimeout)
	if err != nil {
		t.Fatalf("ordered to_yaml failed: %v", err)
	}
	idxCluster := strings.Index(orderedOut, "cluster:")
	idxNodes := strings.Index(orderedOut, "nodes:")
	idxChecksum := strings.Index(orderedOut, "checksum:")
	if !(idxCluster >= 0 && idxCluster < idxNodes && idxNodes < idxChecksum) {
		t.Fatalf("to_yaml lost *OMap key order (%d, %d, %d):\n%s", idxCluster, idxNodes, idxChecksum, orderedOut)
	}

	// Adversarial subtests against the same pipeline surface + clean recovery.
	t.Run("AdversarialGuardsAndRecovery", func(t *testing.T) {
		if out, err := e2eReqRenderScopedBounded(t, `{% for a in range(1000) %}{% for b in range(1000) %}{% for c in range(1000) if c < 0 %}{{ c }}{% endfor %}{% endfor %}{% endfor %}`, nil, lookup, e2eReqBigTimeout); err == nil {
			t.Fatalf("expected loop DoS error, got %q", out)
		}

		if out, err := e2eReqRenderBounded(t, `{{ range(0, 500000) | union(range(500000, 1000001)) | length }}`, nil, nil, e2eReqBigTimeout); err == nil {
			t.Fatalf("expected union >1M error, got %q", out)
		}

		overYAML := "k: " + strings.Repeat("z", 4<<20)
		if out, err := e2eReqRenderBounded(t, `{{ y | from_yaml }}`, map[string]any{"y": overYAML}, nil, e2eReqBigTimeout); err == nil {
			t.Fatalf("expected >4MiB from_yaml error, got %q", out)
		}

		if out, err := e2eReqRenderBounded(t, `{{ 'node-1' | regex_replace('[', 'x') }}`, nil, nil, e2eReqRenderTimeout); err == nil {
			t.Fatalf("expected invalid regex error, got %q", out)
		}

		// Clean recovery render of the real production pipeline.
		recovered, err := e2eReqRenderScopedBounded(t, tpl, nil, lookup, e2eReqRenderTimeout)
		if err != nil || recovered != got {
			t.Fatalf("recovery pipeline mismatch: err=%v same=%v", err, recovered == got)
		}
	})
}
