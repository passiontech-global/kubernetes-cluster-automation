// bench_hot_paths_test.go — Wave 6.2 benchmarks for the jinja hot
// paths: Stringify over a mixed map/scalar document, mapLookup hit
// and miss, the O(N) all-strings unique path (1k / 10k), and a
// representative full template eval through the public Render entry.
// All inputs are built once per benchmark and never mutated, so
// every iteration is deterministic.
package jinja

import (
	"fmt"
	"strings"
	"testing"
)

// benchDoc builds a mixed map/scalar document shaped like a decoded
// vars file: an ordered map of scalar and nested-list values.
func benchDoc(n int) *OMap {
	m := NewOMapCap(n)
	for i := range n {
		m.Set(fmt.Sprintf("key_%03d", i), fmt.Sprintf("value-%d", i))
		m.Set(fmt.Sprintf("num_%03d", i), i)
		m.Set(fmt.Sprintf("flag_%03d", i), i%2 == 0)
	}
	return m
}

func BenchmarkStringifyMixedDoc(b *testing.B) {
	doc := &List{[]any{
		benchDoc(50),
		[]any{"a", "b", 1, 2.5, true, nil},
		"top-level scalar",
	}}
	want := Stringify(doc) // pin the output once — must be identical every iteration
	b.ReportAllocs()
	for b.Loop() {
		if got := Stringify(doc); got != want {
			b.Fatalf("Stringify mismatch")
		}
	}
}

func BenchmarkMapLookupHit(b *testing.B) {
	m := benchDoc(100)
	const key = "key_050"
	if _, ok := mapLookup(m, key); !ok {
		b.Fatalf("missing %q", key)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, ok := mapLookup(m, key); !ok {
			b.Fatal("hit became a miss")
		}
	}
}

func BenchmarkMapLookupMiss(b *testing.B) {
	m := benchDoc(100)
	b.ReportAllocs()
	for b.Loop() {
		if v, ok := mapLookup(m, "absent_key"); ok || v != nil {
			b.Fatal("miss returned a hit")
		}
	}
}

func benchStrings(n int) *List {
	items := make([]any, n)
	for i := range items {
		items[i] = fmt.Sprintf("host-%04d.example.internal", i%(n/2)) // 50% dups to exercise dedupe
	}
	return &List{items}
}

func BenchmarkFilterUniqueStrings1k(b *testing.B) {
	l := benchStrings(1000)
	want, err := filterUnique(l)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		got, err := filterUnique(l)
		if err != nil {
			b.Fatal(err)
		}
		if got.(*List).V[0].(string) != want.(*List).V[0].(string) {
			b.Fatal("unique mismatch")
		}
	}
}

func BenchmarkFilterUniqueStrings10k(b *testing.B) {
	l := benchStrings(10000)
	want, err := filterUnique(l)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		got, err := filterUnique(l)
		if err != nil {
			b.Fatal(err)
		}
		if got.(*List).V[0].(string) != want.(*List).V[0].(string) {
			b.Fatal("unique mismatch")
		}
	}
}

func BenchmarkRenderTemplateEval(b *testing.B) {
	ctx := map[string]any{
		"nodes": benchStrings(50).V,
		"cfg":   benchDoc(20),
	}
	tpl := "{{ nodes | unique | sort | join(',') }} {{ cfg.key_005 | upper }} {{ nodes | length }}"
	want, err := Render(tpl, ctx, nil)
	if err != nil {
		b.Fatal(err)
	}
	if !strings.Contains(want, "VALUE-5") {
		b.Fatalf("unexpected render: %q", want)
	}
	b.ReportAllocs()
	for b.Loop() {
		got, err := Render(tpl, ctx, nil)
		if err != nil {
			b.Fatal(err)
		}
		if got != want {
			b.Fatal("render mismatch across iterations")
		}
	}
}
