// wave26_test.go — Phase-1 (wave 26-28 plan) leaf-library
// regressions: YAML merge keys (`<<`), strict-weak-ordering |sort
// on mixed types, |list/map/selectattr clone non-aliasing, typed-nil
// *List/*OMap safety, int64 overflow promotion, |from_json input
// cap, and the bounded regex cache.
package jinja

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

// DecodeYAML must honor YAML merge keys: `<<: *anchor` splices the
// anchored mapping's pairs in, explicit keys always win regardless
// of position, and a sequence of anchors merges earlier-wins.
func TestYAMLMergeKeys(t *testing.T) {
	v, err := DecodeYAML([]byte(`
base: &b
  a: 1
  b: 2
extra: &extra
  c: 4
  a: 9
top:
  <<: *b
  b: 3
multi:
  <<: [*b, *extra]
`))
	if err != nil {
		t.Fatal(err)
	}
	root, ok := v.(*OMap)
	if !ok {
		t.Fatalf("root = %T, want *OMap", v)
	}

	top, _ := root.Get("top")
	topm, ok := top.(*OMap)
	if !ok {
		t.Fatalf("top = %T, want *OMap", top)
	}
	// Merged `a` lands first (merge pass runs in document order
	// before the explicit `b` overwrites the merged value).
	if got := topm.Keys(); strings.Join(got, ",") != "a,b" {
		t.Fatalf("top keys = %v, want [a b]", got)
	}
	if av, _ := topm.Get("a"); av != int64(1) {
		t.Fatalf("top.a = %v, want 1", av)
	}
	if bv, _ := topm.Get("b"); bv != int64(3) {
		t.Fatalf("top.b = %v, want 3 (explicit wins over merge)", bv)
	}

	multi, _ := root.Get("multi")
	mm, ok := multi.(*OMap)
	if !ok {
		t.Fatalf("multi = %T, want *OMap", multi)
	}
	// *b merges first: a=1, b=2; *extra then adds c=4 and its a=9
	// is skipped (earlier source wins) — plus explicit? none here.
	for k, want := range map[string]int64{"a": 1, "b": 2, "c": 4} {
		if got, _ := mm.Get(k); got != want {
			t.Fatalf("multi.%s = %v, want %d", k, got, want)
		}
	}
	if _, dup := mm.Get("a"); !dup {
		t.Fatal("multi.a missing")
	}
}

// A merge source that isn't a mapping must error, not silently
// produce a partial map.
func TestYAMLMergeKeyNonMapping(t *testing.T) {
	_, err := DecodeYAML([]byte(`
scalar: &s 5
top:
  <<: *s
`))
	if err == nil {
		t.Fatal("merge of scalar source did not error")
	}
}

// |sort on MIXED types must be a strict weak ordering: the old
// comparator stringified non-numeric keys, which is intransitive
// (10 < "2" < 3 < 10 could cycle). Rank-bucketed keys make every
// cross-type pair decidable — this input used to be able to hang
// or scramble slices.SortStableFunc.
func TestSortMixedTypes(t *testing.T) {
	out, err := renderBounded(t, `{{ [3, "10", 1, true, none, [2], "a"] | sort | join("|") }}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Rank order: numbers first — true is numeric 1.0 (bool==number
	// parity with numEq), tying with int 1 and sorting after it on
	// the string half ("1" < "True") — then strings ("10","a"),
	// sequences ([2]), and everything else (none→"None") last.
	if want := "1|True|3|10|a|[2]|None"; out != want {
		t.Fatalf("sort output = %q, want %q", out, want)
	}
}

// |sort reverse=True keeps equal elements in ORIGINAL order (python
// parity) — it inverts the comparator, it does not reverse the
// result.
func TestSortReverseStability(t *testing.T) {
	out, err := renderBounded(t, `{{ [{"k": 1, "v": "a"}, {"k": 1, "v": "b"}, {"k": 0, "v": "c"}] | sort(attribute="k", reverse=true) | map(attribute="v") | join(",") }}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	// k=1 pair stays a-before-b (stable), k=0 sinks last under
	// reverse.
	if want := "a,b,c"; out != want {
		t.Fatalf("reverse sort = %q, want %q", out, want)
	}
}

// |list, bare |map, and bare |selectattr|rejectattr must CLONE the
// iterable: ToIter hands back the live backing slice, and wrapping
// it unchecked let .pop()/.append() mutate the caller's value.
func TestListFiltersClone(t *testing.T) {
	ctx := map[string]any{
		"x": &List{V: []any{int64(1), int64(2), int64(3)}},
	}
	out, err := renderBounded(t, `{% set y = x | list %}{{ y.pop() }};{{ x | length }}`, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := "3;3"; out != want {
		t.Fatalf("list clone = %q, want %q (x mutated through alias)", out, want)
	}

	out, err = renderBounded(t, `{% set y = x | map %}{{ y.pop() }};{{ x | length }}`, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := "3;3"; out != want {
		t.Fatalf("map clone = %q, want %q", out, want)
	}

	out, err = renderBounded(t, `{% set y = x | selectattr %}{{ y.pop() }};{{ x | length }}`, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := "3;3"; out != want {
		t.Fatalf("selectattr clone = %q, want %q", out, want)
	}
}

// A typed-nil *List/*OMap arriving from a Go caller must behave as
// an empty container everywhere the engine touches it — never panic.
func TestTypedNilContainers(t *testing.T) {
	ctx := map[string]any{
		"nl": (*List)(nil),
		"nm": (*OMap)(nil),
	}
	out, err := renderBounded(t,
		`{{ nl | length }}|{{ nl | list | length }}|{{ nl | join(",") }}|{{ nm | length }}|{{ nm | dict2items | length }}`,
		ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := "0|0||0|0"; out != want {
		t.Fatalf("typed-nil render = %q, want %q", out, want)
	}
}

// int64 arithmetic that would wrap must promote to float64 (python
// bignum parity) — a silent wrap flips the sign.
func TestInt64OverflowPromotes(t *testing.T) {
	out, err := renderBounded(t, `{{ 9223372036854775807 + 1 }}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := "9.223372036854776e+18"; out != want {
		t.Fatalf("max+1 = %q, want %q", out, want)
	}

	ctx := map[string]any{"x": int64(math.MinInt64)}
	out, err = renderBounded(t, `{{ x - 1 }}|{{ -x }}|{{ x * -1 }}`, ctx)
	if err != nil {
		t.Fatal(err)
	}
	// All three are -2^63, +2^63 (float), +2^63 (float) — none may
	// wrap back to a wrong value or panic on MinInt64/-1. -2^63 is
	// exactly representable so it renders through the int64 fast
	// path; +2^63 overflows int64 and renders as float.
	if want := "-9223372036854775808|9.223372036854776e+18|9.223372036854776e+18"; out != want {
		t.Fatalf("min-int64 ops = %q, want %q", out, want)
	}
}

// |from_json rejects oversized input before json.Unmarshal — a
// hostile multi-MB string is an unbounded CPU/memory sink.
func TestFromJSONSizeCap(t *testing.T) {
	big := `"` + strings.Repeat("x", fromJSONMaxBytes) + `"`
	_, err := renderBounded(t, `{{ j | from_json }}`, map[string]any{"j": big})
	if err == nil {
		t.Fatal("oversized from_json input did not error")
	}
	out, err := renderBounded(t, `{{ j | from_json }}`, map[string]any{"j": `{"a": 1}`})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"a": 1`) && !strings.Contains(out, "a") {
		t.Fatalf("small from_json = %q", out)
	}
}

// The regex cache is bounded: past regexCacheCap distinct patterns
// compile per call instead of growing the map without limit.
func TestRegexCacheBounded(t *testing.T) {
	for i := 0; i < regexCacheCap+10; i++ {
		pat := fmt.Sprintf("pat-%d", i)
		if _, err := cachedRegexp(pat); err != nil {
			t.Fatalf("pattern %d: %v", i, err)
		}
	}
	regexCache.RLock()
	n := len(regexCache.m)
	regexCache.RUnlock()
	if n > regexCacheCap {
		t.Fatalf("regexCache holds %d entries, cap %d", n, regexCacheCap)
	}
	// Over-cap patterns still compile correctly, just uncached.
	re, err := cachedRegexp("pat-overflow-check")
	if err != nil || re == nil {
		t.Fatalf("overflow pattern: %v", err)
	}
}
