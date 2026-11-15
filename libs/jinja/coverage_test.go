package jinja

import (
	"math"
	"strings"
	"testing"
)

func TestFilterDifferenceAndZip(t *testing.T) {
	cases := []struct {
		name string
		tmpl string
		ctx  map[string]any
		want string
	}{
		{
			name: "difference_strings",
			tmpl: `{{ items | difference(excl) | to_json }}`,
			ctx:  map[string]any{"items": []any{"a", "b", "c", "a"}, "excl": []any{"b"}},
			want: `["a","c","a"]`,
		},
		{
			name: "difference_ints",
			tmpl: `{{ items | difference(excl) | to_json }}`,
			ctx:  map[string]any{"items": []any{int64(1), int64(2), int64(3)}, "excl": []any{int64(2)}},
			want: `[1,3]`,
		},
		{
			name: "difference_mixed_deepeq",
			tmpl: `{{ items | difference(excl) | to_json }}`,
			ctx: map[string]any{
				"items": []any{int64(1), "a", map[string]any{"k": int64(1)}},
				"excl":  []any{map[string]any{"k": int64(1)}, "b"},
			},
			want: `[1,"a"]`,
		},
		{
			name: "difference_no_args",
			tmpl: `{{ [1, 2] | difference | to_json }}`,
			want: `[1,2]`,
		},
		{
			name: "zip_equal_and_unequal",
			tmpl: `{{ [1, 2, 3] | zip(["a", "b"]) | to_json }}`,
			want: `[[1,"a"],[2,"b"]]`,
		},
		{
			name: "zip_three_lists",
			tmpl: `{{ [1, 2] | zip(["x", "y", "z"], [true, false]) | to_json }}`,
			want: `[[1,"x",true],[2,"y",false]]`,
		},
		{
			name: "zip_empty",
			tmpl: `{{ [] | zip([1, 2]) | to_json }}`,
			want: `[]`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Render(tc.tmpl, tc.ctx, &Env{})
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSortKeyAsUint64AndSortingLargeUints(t *testing.T) {
	big1 := uint64(math.MaxInt64) + 5
	big2 := uint64(math.MaxInt64) + 1
	got, err := Render(`{{ xs | sort | to_json }}`, map[string]any{
		"xs": []any{big1, int64(10), float64(3.0), big2},
	}, &Env{})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	want := `[3,10,9223372036854775808,9223372036854775812]`
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}

	// Direct unit tests for sortKeyAsUint64 branches.
	if u, ok := sortKeyAsUint64(sortKey{numKind: numUint64, u64: 42}); !ok || u != 42 {
		t.Fatalf("numUint64: got (%d,%v)", u, ok)
	}
	if u, ok := sortKeyAsUint64(sortKey{numKind: numInt64, i64: 7}); !ok || u != 7 {
		t.Fatalf("numInt64>=0: got (%d,%v)", u, ok)
	}
	if _, ok := sortKeyAsUint64(sortKey{numKind: numInt64, i64: -1}); ok {
		t.Fatal("numInt64<0 should be false")
	}
	if u, ok := sortKeyAsUint64(sortKey{numKind: numFloat, num: 12.0}); !ok || u != 12 {
		t.Fatalf("numFloat int: got (%d,%v)", u, ok)
	}
	if _, ok := sortKeyAsUint64(sortKey{numKind: numFloat, num: 1.5}); ok {
		t.Fatal("numFloat fractional should be false")
	}
	if _, ok := sortKeyAsUint64(sortKey{numKind: numFloat, num: math.Inf(1)}); ok {
		t.Fatal("numFloat Inf should be false")
	}
}

func TestMappingLenAndStringifyMap(t *testing.T) {
	om := NewOMap()
	om.Set("z", 1)
	om.Set("a", 2)

	if n, ok := mappingLen(om); !ok || n != 2 {
		t.Fatalf("OMap len = (%d,%v), want (2,true)", n, ok)
	}
	if n, ok := mappingLen(map[string]any{"k": 1}); !ok || n != 1 {
		t.Fatalf("map[string]any len = (%d,%v), want (1,true)", n, ok)
	}
	if n, ok := mappingLen(map[string]string{"a": "1", "b": "2", "c": "3"}); !ok || n != 3 {
		t.Fatalf("map[string]string len = (%d,%v), want (3,true)", n, ok)
	}
	if _, ok := mappingLen(123); ok {
		t.Fatal("non-mapping reported ok")
	}

	got, err := Render(`{{ m }}|{{ m | length }}|{{ s }}|{{ s | length }}`, map[string]any{
		"m": map[string]any{"b": 2, "a": 1},
		"s": map[string]string{"y": "2", "x": "1"},
	}, &Env{})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	want := `{'a': 1, 'b': 2}|2|{'x': 1, 'y': 2}|2`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestExactFloorDivMod(t *testing.T) {
	// (MaxInt64 + 2) % 2 == 1 (float64 would round and return 0).
	big := uint64(math.MaxInt64) + 2
	got, err := Render(`{{ x % 2 }}|{{ x // 2 }}`, map[string]any{"x": big}, &Env{})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if got != "1|4611686018427387904" {
		t.Fatalf("got %q, want 1|4611686018427387904", got)
	}

	// Exercise remaining branches of exactFloorDivMod.
	if v, ok := exactFloorDivMod("%", false, 10, false, 2); !ok || v != int64(0) {
		t.Fatalf("10%%2 = (%v,%v), want (0,true)", v, ok)
	}
	if v, ok := exactFloorDivMod("%", true, 7, false, 3); !ok || v != int64(2) {
		t.Fatalf("-7%%3 = (%v,%v), want (2,true)", v, ok)
	}
	if v, ok := exactFloorDivMod("%", false, 7, false, 3); !ok || v != int64(1) {
		t.Fatalf("7%%3 = (%v,%v), want (1,true)", v, ok)
	}
	if v, ok := exactFloorDivMod("//", true, 7, false, 2); !ok || v != int64(-4) {
		t.Fatalf("-7//2 = (%v,%v), want (-4,true)", v, ok)
	}
}

func TestWriteJSONFloat(t *testing.T) {
	got, err := Render(`{{ [0.0, 1.5, 1e-9, 1e22] | to_json }}`, nil, &Env{})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if got != `[0,1.5,1e-9,1e+22]` {
		t.Fatalf("got %q, want [0,1.5,1e-9,1e+22]", got)
	}

	var b strings.Builder
	if writeJSONFloat(&b, math.NaN()) {
		t.Fatal("NaN should return false")
	}
	if writeJSONFloat(&b, math.Inf(1)) {
		t.Fatal("+Inf should return false")
	}
	if _, err := Render(`{{ x | to_json }}`, map[string]any{"x": math.NaN()}, &Env{}); err == nil {
		t.Fatal("expected error encoding NaN to JSON")
	}
}
