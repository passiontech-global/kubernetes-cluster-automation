package jinja

import (
	"math"
	"strings"
	"testing"
)

func TestTruthyAllTypes(t *testing.T) {
	var nilList *List
	var nilMap *OMap
	omEmpty := NewOMap()
	omNonEmpty := NewOMap()
	omNonEmpty.Set("a", 1)

	cases := []struct {
		name string
		val  any
		want bool
	}{
		{"nil", nil, false},
		{"undefined", Undefined{}, false},
		{"bool_true", true, true},
		{"bool_false", false, false},
		{"int64_zero", int64(0), false},
		{"int64_nonzero", int64(-3), true},
		{"float64_zero", float64(0), false},
		{"float64_nonzero", float64(1.5), true},
		{"string_empty", "", false},
		{"string_nonempty", "0", true},
		{"slice_any_empty", []any{}, false},
		{"slice_any_nonempty", []any{1}, true},
		{"slice_str_empty", []string{}, false},
		{"slice_str_nonempty", []string{"a"}, true},
		{"list_nil", nilList, false},
		{"list_empty", &List{}, false},
		{"list_nonempty", &List{V: []any{1}}, true},
		{"omap_nil", nilMap, false},
		{"omap_empty", omEmpty, false},
		{"omap_nonempty", omNonEmpty, true},
		{"map_any_empty", map[string]any{}, false},
		{"map_any_nonempty", map[string]any{"k": 1}, true},
		{"map_str_empty", map[string]string{}, false},
		{"map_str_nonempty", map[string]string{"k": "v"}, true},
		{"int_zero", 0, false},
		{"int_nonzero", 7, true},
		{"uint64_zero", uint64(0), false},
		{"uint64_large", uint64(math.MaxUint64), true},
		{"struct", struct{}{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Truthy(tc.val); got != tc.want {
				t.Fatalf("Truthy(%T %v) = %v, want %v", tc.val, tc.val, got, tc.want)
			}
		})
	}
}

func TestRunTestPredicates(t *testing.T) {
	cases := []struct {
		name    string
		test    string
		val     any
		args    []any
		want    bool
		wantErr bool
	}{
		{"defined_val", "defined", "x", nil, true, false},
		{"defined_undef", "defined", Undefined{}, nil, false, false},
		{"undefined_true", "undefined", Undefined{}, nil, true, false},
		{"undefined_false", "undefined", 1, nil, false, false},
		{"none_true", "none", nil, nil, true, false},
		{"none_false", "none", "", nil, false, false},
		{"mapping_omap", "mapping", NewOMap(), nil, true, false},
		{"mapping_false", "mapping", []any{}, nil, false, false},
		{"iterable_list", "iterable", []string{"a"}, nil, true, false},
		{"sequence_str", "sequence", "abc", nil, true, false},
		{"iterable_int", "iterable", 42, nil, false, false},
		{"string_true", "string", "hi", nil, true, false},
		{"string_false", "string", 123, nil, false, false},
		{"number_int", "number", 10, nil, true, false},
		{"number_str", "number", "10", nil, false, false},
		{"boolean_true", "boolean", true, nil, true, false},
		{"bool_false", "bool", 1, nil, false, false},
		{"search_noargs", "search", "abc", nil, false, false},
		{"search_bad_regex", "search", "abc", []any{"["}, false, false},
		{"search_match", "search", "hello-123", []any{`\d+`}, true, false},
		{"search_nomatch", "search", "hello", []any{`\d+`}, false, false},
		{"equalto_noargs", "equalto", 1, nil, false, false},
		{"eq_match", "eq", 42, []any{int64(42)}, true, false},
		{"sameas_noargs", "sameas", 1, nil, false, false},
		{"sameas_match", "sameas", "a", []any{"a"}, true, false},
		{"changed", "changed", true, nil, false, false},
		{"failed", "failed", true, nil, false, false},
		{"succeeded", "succeeded", true, nil, false, false},
		{"skipped", "skipped", true, nil, false, false},
		{"in_noargs", "in", "a", nil, false, false},
		{"in_match", "in", "a", []any{[]any{"a", "b"}}, true, false},
		{"unknown_err", "nosuchtest", "a", nil, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := runTest(tc.test, tc.val, tc.args)
			if (err != nil) != tc.wantErr {
				t.Fatalf("runTest(%q) err=%v, wantErr=%v", tc.test, err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("runTest(%q) = %v, want %v", tc.test, got, tc.want)
			}
		})
	}
}

func TestWriteJSONStringEscapes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "hello", `"hello"`},
		{"quotes_slash", `a\b"c`, `"a\\b\"c"`},
		{"controls", "\b\f\n\r\t\x01", `"\b\f\n\r\t\u0001"`},
		{"html", "<script>&</script>", `"\u003cscript\u003e\u0026\u003c/script\u003e"`},
		{"jsonp_seps", "a\u2028b\u2029c", `"a\u2028b\u2029c"`},
		{"invalid_utf8", "a\xffb", "\"a\ufffdb\""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b strings.Builder
			writeJSONString(tc.in, &b)
			if got := b.String(); got != tc.want {
				t.Fatalf("writeJSONString(%q) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

func TestSortKeyExactCmp(t *testing.T) {
	bigFloat := sortKey{numKind: numFloat, num: 1e20}
	u64Big := sortKey{numKind: numUint64, u64: math.MaxUint64}
	u64Small := sortKey{numKind: numUint64, u64: math.MaxInt64 + 10}
	i64Val := sortKey{numKind: numInt64, i64: 42}
	nanKey := sortKey{numKind: numFloat, num: math.NaN()}

	cases := []struct {
		name   string
		a, b   sortKey
		want   int
		wantOK bool
	}{
		{"int64_cmp", i64Val, sortKey{numKind: numInt64, i64: 100}, -1, true},
		{"uint64_cmp", u64Small, u64Big, -1, true},
		{"bigfloat_gt_uint64", bigFloat, u64Big, 1, true},
		{"bigfloat_gt_int64", bigFloat, i64Val, 1, true},
		{"uint64_lt_bigfloat", u64Big, bigFloat, -1, true},
		{"int64_lt_bigfloat", i64Val, bigFloat, -1, true},
		{"nan_not_exact", nanKey, i64Val, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := sortKeyExactCmp(tc.a, tc.b)
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("sortKeyExactCmp = (%d, %v), want (%d, %v)", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}
