package jinja

import (
	"errors"
	"fmt"
	"math"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	yaml3 "go.yaml.in/yaml/v3"
)

func TestLoopStepBudget(t *testing.T) {
	t.Run("nested_and_sequential_limits", func(t *testing.T) {
		cases := []struct {
			name    string
			tpl     string
			want    string
			wantErr bool
		}{
			{
				name:    "nested_empty_loops",
				tpl:     `{% for a in range(2000) %}{% for b in range(2000) %}{% endfor %}{% endfor %}`,
				wantErr: true,
			},
			{
				name:    "nested_filtered_out_loops",
				tpl:     `{% for a in range(2000) %}{% for b in range(2000) if false %}{% endfor %}{% endfor %}`,
				wantErr: true,
			},
			{
				name:    "sequential_loops_exceed_cumulative",
				tpl:     `{% for a in range(600000) %}{% endfor %}{% for b in range(600000) %}{% endfor %}`,
				wantErr: true,
			},
			{
				name:    "filtered_large_loop_exceeds",
				tpl:     `{% for a in range(600000) if a >= 0 %}{% endfor %}`,
				wantErr: true,
			},
			{
				name: "within_budget_ok",
				tpl:  `{% for a in range(1000) %}{% if a == 999 %}ok{% endif %}{% endfor %}`,
				want: "ok",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got, err := renderBounded(t, tc.tpl, nil)
				if tc.wantErr {
					if err == nil {
						t.Fatalf("expected loop budget error, got output %q", got)
					}
					if !strings.Contains(err.Error(), "exceed") {
						t.Fatalf("unexpected error: %v", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != tc.want {
					t.Fatalf("got %q, want %q", got, tc.want)
				}
			})
		}
	})

	t.Run("render_scoped_enforces_budget", func(t *testing.T) {
		_, err := RenderScoped(
			`{% for a in range(2000) %}{% for b in range(2000) %}{% endfor %}{% endfor %}`,
			nil,
			func(string) any { return Undefined{} },
		)
		if err == nil || !strings.Contains(err.Error(), "exceed") {
			t.Fatalf("RenderScoped err = %v, want loop budget error", err)
		}
	})

	t.Run("concurrent_shared_ast_race_free", func(t *testing.T) {
		tpl := `{% for a in xs %}{% for b in ys %}{{ a }}-{{ b }};{% endfor %}{% endfor %}`
		var wg sync.WaitGroup
		errs := make(chan error, 16)
		for g := range 8 {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for range 20 {
					ctx := map[string]any{
						"xs": []any{int64(id), int64(id + 1)},
						"ys": []any{"x", "y"},
					}
					out, err := Render(tpl, ctx, nil)
					if err != nil {
						errs <- err
						return
					}
					want := fmt.Sprintf("%d-x;%d-y;%d-x;%d-y;", id, id, id+1, id+1)
					if out != want {
						errs <- fmt.Errorf("got %q, want %q", out, want)
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

func TestFilterUnionMaxSeqElems(t *testing.T) {
	t.Run("all_ints_exceeds", func(t *testing.T) {
		a := make([]any, 500_001)
		for i := range a {
			a[i] = int64(i)
		}
		b := make([]any, 500_000)
		for i := range b {
			b[i] = int64(500_001 + i)
		}
		_, err := filterUnion(&List{a}, []any{&List{b}})
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("allInts union err = %v, want exceeds error", err)
		}
	})

	t.Run("all_strings_exceeds", func(t *testing.T) {
		a := make([]any, 500_001)
		for i := range a {
			a[i] = "a-" + strconv.Itoa(i)
		}
		b := make([]any, 500_000)
		for i := range b {
			b[i] = "b-" + strconv.Itoa(i)
		}
		_, err := filterUnion(&List{a}, []any{&List{b}})
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("allStrings union err = %v, want exceeds error", err)
		}
	})

	t.Run("append_unique_cap_boundary", func(t *testing.T) {
		items := []any{int64(1), "a", "b", 2.5, &List{}, nil}
		out, err := appendUnique(nil, items[:5], 5, "union")
		if err != nil || len(out) != 5 {
			t.Fatalf("at limit: out=%d err=%v, want len=5 nil", len(out), err)
		}
		if _, err := appendUnique(nil, items, 5, "union"); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("over limit: err=%v, want exceeds error", err)
		}
	})

	t.Run("duplicates_collapse_within_cap", func(t *testing.T) {
		out, err := renderBounded(t, `{{ range(600000) | union(range(600000)) | length }}`, nil)
		if err != nil {
			t.Fatalf("duplicate-heavy union err: %v", err)
		}
		if out != "600000" {
			t.Fatalf("got %q, want 600000", out)
		}
	})
}

func TestFilterToYAMLStreamingCap(t *testing.T) {
	t.Run("limit_writer_exact_boundary", func(t *testing.T) {
		lw := yamlLimitWriter{max: 10}
		if n, err := lw.Write([]byte("1234567890")); err != nil || n != 10 || lw.overflow {
			t.Fatalf("exact max write: n=%d err=%v overflow=%v", n, err, lw.overflow)
		}
		if _, err := lw.Write([]byte("x")); !errors.Is(err, errYAMLSizeCap) || !lw.overflow {
			t.Fatalf("overflow write: err=%v overflow=%v", err, lw.overflow)
		}
	})

	t.Run("oversized_to_yaml_and_to_nice_yaml_fail_fast", func(t *testing.T) {
		chunk := strings.Repeat("a", 1<<20)
		items := make([]any, 17)
		for i := range items {
			items[i] = chunk
		}
		ctx := map[string]any{"big": &List{items}}
		for _, filt := range []string{"to_yaml", "to_nice_yaml"} {
			_, err := renderBounded(t, "{{ big | "+filt+" }}", ctx)
			if err == nil || !strings.Contains(err.Error(), "exceeds") {
				t.Fatalf("%s err = %v, want output exceeds error", filt, err)
			}
		}
	})

	t.Run("matches_yaml_marshal_byte_for_byte", func(t *testing.T) {
		om := NewOMap()
		om.Set("z_first", "yes")
		om.Set("a_second", "0123")
		om.Set("flag", true)
		om.Set("nested", &List{[]any{int64(1), "two"}})

		node, err := toYAMLNode(om)
		if err != nil {
			t.Fatal(err)
		}
		wantBytes, err := yaml3.Marshal(node)
		if err != nil {
			t.Fatal(err)
		}
		for _, filt := range []string{"to_yaml", "to_nice_yaml"} {
			got, err := renderBounded(t, "{{ m | "+filt+" }}", map[string]any{"m": om})
			if err != nil {
				t.Fatalf("%s error: %v", filt, err)
			}
			if got != string(wantBytes) {
				t.Fatalf("%s mismatch:\ngot:\n%s\nwant:\n%s", filt, got, string(wantBytes))
			}
		}
	})

	t.Run("exact_16MiB_boundary_and_yaml11_parity", func(t *testing.T) {
		// Exact maxStringBytes boundary (16,777,215-byte plain scalar + "\n" == maxStringBytes).
		exactStr := strings.Repeat("a", maxStringBytes-1)
		gotExact, err := renderBounded(t, "{{ s | to_yaml }}", map[string]any{"s": exactStr})
		if err != nil {
			t.Fatalf("exact boundary to_yaml failed: %v", err)
		}
		if len(gotExact) != maxStringBytes {
			t.Fatalf("exact boundary len = %d, want %d", len(gotExact), maxStringBytes)
		}
		overStr := strings.Repeat("a", maxStringBytes)
		if _, err := renderBounded(t, "{{ s | to_yaml }}", map[string]any{"s": overStr}); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("over-boundary scalar err = %v, want exceeds error", err)
		}

		// Every scalar & YAML 1.1/1.2 edge case must match yaml3.Node.Encode + yaml3.Marshal byte-for-byte.
		type customStruct struct {
			Name  string
			Count int
		}
		scalars := []struct {
			name string
			val  any
		}{
			{"nil", nil},
			{"empty_str", ""},
			{"bool_true", true},
			{"bool_false", false},
			{"int_zero", int64(0)},
			{"int_neg", int64(-42)},
			{"int_min", int64(math.MinInt64)},
			{"uint_max", uint64(math.MaxUint64)},
			{"int8", int8(-7)},
			{"uint16", uint16(512)},
			{"float_zero", 0.0},
			{"float_integral", 1.0},
			{"float_frac", 1.5},
			{"float32", float32(2.25)},
			{"float_pos_inf", math.Inf(1)},
			{"float_neg_inf", math.Inf(-1)},
			{"float_nan", math.NaN()},
			{"y", "y"},
			{"Y", "Y"},
			{"yes", "yes"},
			{"Yes", "Yes"},
			{"YES", "YES"},
			{"on", "on"},
			{"On", "On"},
			{"ON", "ON"},
			{"n", "n"},
			{"N", "N"},
			{"no", "no"},
			{"No", "No"},
			{"NO", "NO"},
			{"off", "off"},
			{"Off", "Off"},
			{"OFF", "OFF"},
			{"str_true", "true"},
			{"str_True", "True"},
			{"str_false", "false"},
			{"str_null", "null"},
			{"str_Null", "Null"},
			{"str_tilde", "~"},
			{"str_merge", "<<"},
			{"str_octal_0123", "0123"},
			{"str_int_123", "123"},
			{"str_float_1_5", "1.5"},
			{"str_hex", "0x10"},
			{"str_oct", "0o10"},
			{"str_bin", "0b10"},
			{"str_underscore", "1_000"},
			{"str_inf", ".inf"},
			{"str_nan", ".nan"},
			{"str_timestamp", "2020-01-01"},
			{"base60_1_20", "1:20"},
			{"base60_signed", "+1:20"},
			{"base60_non_base60", "1:60"},
			{"multiline_trailing_nl", "line1\nline2\n"},
			{"multiline_no_trailing_nl", "line1\nline2"},
			{"multiline_only_nl", "\n"},
			{"multiline_blank_line", "a\n\nb"},
			{"multiline_yes", "yes\n"},
			{"multiline_trailing_space", "a\nb "},
			{"colon_space", "a: b"},
			{"leading_space", " lead"},
			{"trailing_space", "trail "},
			{"hash_comment", "#comment"},
			{"dash_item", "- item"},
			{"doc_sep", "---"},
			{"doc_end", "..."},
			{"braces", "{a: 1}"},
			{"brackets", "[1, 2]"},
			{"single_quotes", "'quoted'"},
			{"double_quotes", `"double"`},
			{"tab_char", "a\tb"},
			{"nul_char", "a\x00b"},
			{"bell_char", "a\x07b"},
			{"invalid_utf8_short", "\xff"},
			{"invalid_utf8_long", strings.Repeat("\xff", 100)},
			{"time_val", time.Date(2026, 11, 22, 9, 30, 0, 123, time.UTC)},
			{"duration_val", 5 * time.Second},
			{"bytes_slice", []byte("abc")},
			{"struct_val", customStruct{Name: "yes", Count: 3}},
		}

		for _, sc := range scalars {
			t.Run("scalar_"+sc.name, func(t *testing.T) {
				var legacyNode yaml3.Node
				if err := legacyNode.Encode(sc.val); err != nil {
					t.Fatalf("legacy Node.Encode: %v", err)
				}
				wantBytes, err := yaml3.Marshal(&legacyNode)
				if err != nil {
					t.Fatalf("legacy Marshal: %v", err)
				}
				for _, filt := range []string{"to_yaml", "to_nice_yaml"} {
					got, err := renderBounded(t, "{{ v | "+filt+" }}", map[string]any{"v": sc.val})
					if err != nil {
						t.Fatalf("%s error: %v", filt, err)
					}
					if got != string(wantBytes) {
						t.Fatalf("%s mismatch for %q (%T):\ngot:  %q\nwant: %q", filt, sc.name, sc.val, got, string(wantBytes))
					}
				}
			})
		}

		// Verify string keys (including YAML 1.1 bools, numeric strings, multiline keys, colons, spaces)
		// and empty containers + Undefined match legacy Node.Encode byte-for-byte.
		keyed := NewOMap()
		keyed.Set("yes", "no")
		keyed.Set("true", "false")
		keyed.Set("null", "0123")
		keyed.Set("1:20", "")
		keyed.Set("a: b", " lead")
		keyed.Set("line1\nline2", "trail ")
		keyed.Set("", "empty-key")
		keyed.Set("undef", Undefined{"missing"})
		keyed.Set("empty_list", &List{})
		keyed.Set("empty_map", NewOMap())
		keyed.Set("str_slice", []string{"yes", "0123", "plain"})

		legacyMap := &yaml3.Node{Kind: yaml3.MappingNode, Tag: "!!map"}
		for _, k := range keyed.Keys() {
			kn := &yaml3.Node{}
			if err := kn.Encode(k); err != nil {
				t.Fatal(err)
			}
			v, _ := keyed.Get(k)
			var vn *yaml3.Node
			switch tv := v.(type) {
			case Undefined:
				vn = &yaml3.Node{}
				_ = vn.Encode(nil)
			case *List:
				vn = &yaml3.Node{Kind: yaml3.SequenceNode, Tag: "!!seq"}
			case *OMap:
				vn = &yaml3.Node{Kind: yaml3.MappingNode, Tag: "!!map"}
			case []string:
				vn = &yaml3.Node{Kind: yaml3.SequenceNode, Tag: "!!seq"}
				for _, s := range tv {
					sn := &yaml3.Node{}
					_ = sn.Encode(s)
					vn.Content = append(vn.Content, sn)
				}
			default:
				vn = &yaml3.Node{}
				if err := vn.Encode(v); err != nil {
					t.Fatal(err)
				}
			}
			legacyMap.Content = append(legacyMap.Content, kn, vn)
		}
		wantMapBytes, err := yaml3.Marshal(legacyMap)
		if err != nil {
			t.Fatal(err)
		}
		gotMap, err := renderBounded(t, "{{ m | to_yaml }}", map[string]any{"m": keyed})
		if err != nil {
			t.Fatalf("keyed OMap to_yaml failed: %v", err)
		}
		if gotMap != string(wantMapBytes) {
			t.Fatalf("keyed OMap mismatch:\ngot:\n%s\nwant:\n%s", gotMap, string(wantMapBytes))
		}
	})

	t.Run("huge_inputs_fail_fast_with_bounded_alloc", func(t *testing.T) {
		measure := func(name string, fn func() error, maxAlloc uint64, maxElapsed time.Duration) {
			t.Helper()
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			start := time.Now()
			err := fn()
			elapsed := time.Since(start)
			runtime.ReadMemStats(&after)
			if err == nil {
				t.Fatalf("%s unexpectedly succeeded", name)
			}
			allocDelta := after.TotalAlloc - before.TotalAlloc
			if allocDelta > maxAlloc {
				t.Fatalf("%s TotalAlloc delta = %d MiB, want <= %d MiB (err=%v)",
					name, allocDelta>>20, maxAlloc>>20, err)
			}
			if elapsed > maxElapsed {
				t.Fatalf("%s elapsed = %v, want <= %v (err=%v)", name, elapsed, maxElapsed, err)
			}
		}

		// 64 MiB & 128 MiB scalar strings must fail immediately with near-zero allocs.
		for _, sizeMiB := range []int{64, 128} {
			s := strings.Repeat("A", sizeMiB<<20)
			for _, filt := range []string{"to_yaml", "to_nice_yaml"} {
				measure(fmt.Sprintf("%dMiB_scalar_%s", sizeMiB, filt), func() error {
					_, err := Render("{{ s | "+filt+" }}", map[string]any{"s": s}, nil)
					if err != nil && !strings.Contains(err.Error(), "exceeds") {
						return fmt.Errorf("unexpected error: %v", err)
					}
					return err
				}, 8<<20, 2*time.Second)
			}
		}

		// 14 MiB invalid UTF-8 string (base64 expands > 16 MiB) must fail pre-encode.
		badUTF8 := strings.Repeat("\xff", 14<<20)
		measure("14MiB_invalid_utf8_to_yaml", func() error {
			_, err := Render("{{ s | to_yaml }}", map[string]any{"s": badUTF8}, nil)
			return err
		}, 8<<20, 2*time.Second)

		// 4,000 x 8 KiB *OMap (32 MiB) must fail mid-walk without encoding/parsing all entries.
		bigMap := NewOMapCap(4000)
		chunk8K := strings.Repeat("B", 8<<10)
		for i := range 4000 {
			bigMap.Set(fmt.Sprintf("k-%04d", i), chunk8K)
		}
		measure("4000x8KiB_OMap_to_yaml", func() error {
			_, err := Render("{{ m | to_yaml }}", map[string]any{"m": bigMap}, nil)
			if err != nil && !strings.Contains(err.Error(), "exceeds") {
				return fmt.Errorf("unexpected error: %v", err)
			}
			return err
		}, 16<<20, 2*time.Second)

		// 2M-element []any / *List / []string must hit walkMaxSteps without 1+ GiB Node.Encode churn.
		hugeAny := make([]any, 2_000_000)
		hugeStr := make([]string, 2_000_000)
		for i := range hugeAny {
			hugeAny[i] = "hello"
			hugeStr[i] = "hello"
		}
		measure("2M_list_to_nice_yaml", func() error {
			_, err := Render("{{ l | to_nice_yaml }}", map[string]any{"l": &List{hugeAny}}, nil)
			if err != nil && !strings.Contains(err.Error(), "steps") {
				return fmt.Errorf("unexpected error: %v", err)
			}
			return err
		}, 64<<20, 2*time.Second)
		measure("2M_strings_to_yaml", func() error {
			_, err := Render("{{ l | to_yaml }}", map[string]any{"l": hugeStr}, nil)
			if err != nil && !strings.Contains(err.Error(), "steps") {
				return fmt.Errorf("unexpected error: %v", err)
			}
			return err
		}, 64<<20, 2*time.Second)

		// 64 MiB []byte exotic slice fallback must fail fast with minimal allocs.
		hugeBytes := make([]byte, 64<<20)
		measure("64MiB_bytes_fallback_to_yaml", func() error {
			_, err := Render("{{ b | to_yaml }}", map[string]any{"b": hugeBytes}, nil)
			return err
		}, 8<<20, 2*time.Second)
	})
}

func TestRegexCachePrecomputedClassifications(t *testing.T) {
	t.Run("entry_populates_all_classifications", func(t *testing.T) {
		eLit, err := cachedRegexpEntry("foo")
		if err != nil {
			t.Fatal(err)
		}
		if !eLit.noExpand.isLit || eLit.noExpand.lit != "foo" || eLit.noExpand.mode != regexLeftFree {
			t.Fatalf("unexpected literal classification: %+v", eLit.noExpand)
		}

		ePrefix, err := cachedRegexpEntry("(?m)^bar")
		if err != nil {
			t.Fatal(err)
		}
		if !ePrefix.noExpand.isLinePrefix || ePrefix.noExpand.lit != "bar" {
			t.Fatalf("unexpected line-prefix classification: %+v", ePrefix.noExpand)
		}
		if ePrefix.withExpand.isLinePrefix {
			t.Fatalf("withExpand should not mark isLinePrefix: %+v", ePrefix.withExpand)
		}

		eCap, err := cachedRegexpEntry("(baz)")
		if err != nil {
			t.Fatal(err)
		}
		if !eCap.hasLitCap || eCap.litCapture != "baz" {
			t.Fatalf("expected singleLiteralCapture baz, got (%q, %v)", eCap.litCapture, eCap.hasLitCap)
		}
	})

	t.Run("concurrent_regex_filters_and_tests", func(t *testing.T) {
		ctx := map[string]any{"s": "a1 b2 c3 a1"}
		var wg sync.WaitGroup
		errs := make(chan error, 32)
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 25 {
					if out, err := Render(`{{ s | regex_replace('([a-z])([0-9])', '$1=$2') }}`, ctx, nil); err != nil || out != "a=1 b=2 c=3 a=1" {
						errs <- fmt.Errorf("expand regex_replace = (%q, %v)", out, err)
						return
					}
					if out, err := Render(`{{ s | regex_replace('a1', 'X') }}`, ctx, nil); err != nil || out != "X b2 c3 X" {
						errs <- fmt.Errorf("lit regex_replace = (%q, %v)", out, err)
						return
					}
					if out, err := Render(`{{ s | regex_findall('(a1)') }}`, ctx, nil); err != nil || out != "[a1, a1]" {
						errs <- fmt.Errorf("litcap regex_findall = (%q, %v)", out, err)
						return
					}
					if out, err := Render(`{{ s | regex_search('b([0-9])') }}`, ctx, nil); err != nil || out != "[2]" {
						errs <- fmt.Errorf("regex_search = (%q, %v)", out, err)
						return
					}
					if out, err := Render(`{{ s is search('c[0-9]') }}`, ctx, nil); err != nil || out != "True" {
						errs <- fmt.Errorf("is search = (%q, %v)", out, err)
						return
					}
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}
	})
}
