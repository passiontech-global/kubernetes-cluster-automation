// filters_seq_budget_test.go — Tier 5 adversarial tests verifying O(N^2)
// comparison-budget enforcement in unique, difference, and union for
// non-hashable inputs while preserving moderate/fast-path behavior.
package jinja

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSeqFilterComparisonBudget(t *testing.T) {
	makeMaps := func(offset, n int) *List {
		items := make([]any, n)
		for i := range n {
			items[i] = map[string]any{"id": int64(offset + i), "nested": []any{int64(offset + i)}}
		}
		return &List{items}
	}

	t.Run("unique_large_distinct_maps_fails_bounded", func(t *testing.T) {
		ctx := map[string]any{"items": makeMaps(0, 2500)}
		start := time.Now()
		_, err := renderBounded(t, "{{ items | unique | length }}", ctx)
		elapsed := time.Since(start)
		if err == nil || !strings.Contains(err.Error(), "budget exceeded") {
			t.Fatalf("unique(2500 maps) err = %v, want comparison budget exceeded", err)
		}
		if elapsed > time.Second {
			t.Fatalf("unique(2500 maps) took %s, expected bounded bailout (<1s)", elapsed)
		}
		t.Logf("unique(2500 maps) bailed in %s: %v", elapsed, err)
	})

	t.Run("difference_large_distinct_maps_fails_bounded", func(t *testing.T) {
		ctx := map[string]any{
			"a": makeMaps(0, 2500),
			"b": makeMaps(10000, 2500),
		}
		start := time.Now()
		_, err := renderBounded(t, "{{ a | difference(b) | length }}", ctx)
		elapsed := time.Since(start)
		if err == nil || !strings.Contains(err.Error(), "budget exceeded") {
			t.Fatalf("difference(2500x2500 maps) err = %v, want comparison budget exceeded", err)
		}
		if elapsed > time.Second {
			t.Fatalf("difference(2500x2500 maps) took %s, expected bounded bailout (<1s)", elapsed)
		}
		t.Logf("difference(2500x2500 maps) bailed in %s: %v", elapsed, err)
	})

	t.Run("union_large_distinct_maps_fails_bounded", func(t *testing.T) {
		ctx := map[string]any{
			"a": makeMaps(0, 1500),
			"b": makeMaps(1500, 1500),
		}
		start := time.Now()
		_, err := renderBounded(t, "{{ a | union(b) | length }}", ctx)
		elapsed := time.Since(start)
		if err == nil || !strings.Contains(err.Error(), "budget exceeded") {
			t.Fatalf("union(1500+1500 maps) err = %v, want comparison budget exceeded", err)
		}
		if elapsed > time.Second {
			t.Fatalf("union(1500+1500 maps) took %s, expected bounded bailout (<1s)", elapsed)
		}
		t.Logf("union(1500+1500 maps) bailed in %s: %v", elapsed, err)
	})

	t.Run("moderate_non_string_int_inputs_succeed", func(t *testing.T) {
		ctx := map[string]any{
			"a": makeMaps(0, 200),
			"b": makeMaps(100, 200),
		}
		out, err := renderBounded(t, "{{ a | unique | length }}", ctx)
		if err != nil || out != "200" {
			t.Fatalf("moderate unique = (%q, %v), want (\"200\", nil)", out, err)
		}
		out, err = renderBounded(t, "{{ a | difference(b) | length }}", ctx)
		if err != nil || out != "100" {
			t.Fatalf("moderate difference = (%q, %v), want (\"100\", nil)", out, err)
		}
		out, err = renderBounded(t, "{{ a | union(b) | length }}", ctx)
		if err != nil || out != "300" {
			t.Fatalf("moderate union = (%q, %v), want (\"300\", nil)", out, err)
		}

		// Preserve mixed int/float numeric dedupe semantics (1 == 1.0).
		mixCtx := map[string]any{"mix": &List{[]any{int64(1), float64(1.0), int64(2)}}}
		out, err = renderBounded(t, "{{ mix | unique | length }}", mixCtx)
		if err != nil || out != "2" {
			t.Fatalf("mixed numeric unique = (%q, %v), want (\"2\", nil)", out, err)
		}
	})

	t.Run("difference_max_seq_elems_enforced", func(t *testing.T) {
		a := make([]any, maxSeqElems+1)
		for i := range a {
			a[i] = int64(i)
		}
		_, err := filterDifference(&List{a}, []any{&List{[]any{int64(-1)}}})
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("filterDifference > maxSeqElems err = %v, want exceeds error", err)
		}
	})

	t.Run("string_slices_500x50k_distinct_bounded_no_oom", func(t *testing.T) {
		const nSlices = 500
		const sliceLen = 50_000
		makeStrSlices := func(prefix string) *List {
			items := make([]any, nSlices)
			for i := range nSlices {
				s := make([]string, sliceLen)
				s[0] = fmt.Sprintf("%s-%d", prefix, i)
				for j := 1; j < sliceLen; j++ {
					s[j] = "pad"
				}
				items[i] = s
			}
			return &List{items}
		}

		itemsA := makeStrSlices("a")
		itemsB := makeStrSlices("b")

		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		start := time.Now()
		out, err := renderBounded(t, "{{ items | unique | length }}", map[string]any{"items": itemsA})
		elapsed := time.Since(start)
		runtime.ReadMemStats(&after)
		allocMiB := float64(after.TotalAlloc-before.TotalAlloc) / (1024 * 1024)
		if err != nil || out != "500" {
			t.Fatalf("unique(500x50k []string) = (%q, %v), want (\"500\", nil)", out, err)
		}
		if elapsed > time.Second {
			t.Fatalf("unique(500x50k []string) took %s, expected <1s", elapsed)
		}
		if allocMiB > 32 {
			t.Fatalf("unique(500x50k []string) allocated %.2f MiB, expected low allocation (<32 MiB)", allocMiB)
		}

		start = time.Now()
		out, err = renderBounded(t, "{{ a | difference(b) | length }}", map[string]any{"a": itemsA, "b": itemsB})
		if err != nil || out != "500" {
			t.Fatalf("difference(500x50k []string) = (%q, %v), want (\"500\", nil)", out, err)
		}
		if time.Since(start) > time.Second {
			t.Fatalf("difference(500x50k []string) took >1s")
		}

		start = time.Now()
		out, err = renderBounded(t, "{{ a | union(b) | length }}", map[string]any{"a": itemsA, "b": itemsB})
		if err == nil || !strings.Contains(err.Error(), "budget exceeded") {
			t.Fatalf("union(500+500x50k []string) = (%q, %v), want comparison budget exceeded", out, err)
		}
		if time.Since(start) > time.Second {
			t.Fatalf("union(500+500x50k []string) took >1s")
		}
	})

	t.Run("string_slices_500x50k_shared_prefix_hits_budget_promptly", func(t *testing.T) {
		const nSlices = 500
		const sliceLen = 50_000
		makePrefixSlices := func(prefix string) *List {
			items := make([]any, nSlices)
			for i := range nSlices {
				s := make([]string, sliceLen)
				for j := range sliceLen - 1 {
					s[j] = "same"
				}
				s[sliceLen-1] = fmt.Sprintf("%s-%d", prefix, i)
				items[i] = s
			}
			return &List{items}
		}

		itemsA := makePrefixSlices("a")
		itemsB := makePrefixSlices("b")
		for _, tc := range []struct {
			name string
			tpl  string
			ctx  map[string]any
		}{
			{"unique", "{{ a | unique | length }}", map[string]any{"a": itemsA}},
			{"difference", "{{ a | difference(b) | length }}", map[string]any{"a": itemsA, "b": itemsB}},
			{"union", "{{ a | union(b) | length }}", map[string]any{"a": itemsA, "b": itemsB}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var before, after runtime.MemStats
				runtime.GC()
				runtime.ReadMemStats(&before)
				start := time.Now()
				_, err := renderBounded(t, tc.tpl, tc.ctx)
				elapsed := time.Since(start)
				runtime.ReadMemStats(&after)
				allocMiB := float64(after.TotalAlloc-before.TotalAlloc) / (1024 * 1024)
				if err == nil || !strings.Contains(err.Error(), "budget exceeded") {
					t.Fatalf("%s shared-prefix 500x50k err = %v, want budget exceeded", tc.name, err)
				}
				if elapsed > time.Second {
					t.Fatalf("%s shared-prefix 500x50k took %s, expected <1s", tc.name, elapsed)
				}
				if allocMiB > 32 {
					t.Fatalf("%s shared-prefix 500x50k allocated %.2f MiB, expected <32 MiB", tc.name, allocMiB)
				}
			})
		}
	})

	t.Run("mixed_string_slice_and_any_slice_equality_and_budget", func(t *testing.T) {
		ctx := map[string]any{
			"a": &List{[]any{[]string{"a", "b"}, []any{"a", "b"}, []string{"c"}}},
			"b": &List{[]any{[]any{"c"}, []string{"d"}}},
			"c": &List{[]any{[]any{"a", "b"}}},
		}
		out, err := renderBounded(t, "{{ a | unique | length }}", ctx)
		if err != nil || out != "2" {
			t.Fatalf("mixed unique = (%q, %v), want (\"2\", nil)", out, err)
		}
		out, err = renderBounded(t, "{{ a | difference(b) | length }}", ctx)
		if err != nil || out != "2" {
			t.Fatalf("mixed difference(b) = (%q, %v), want (\"2\", nil)", out, err)
		}
		out, err = renderBounded(t, "{{ a | difference(c) | length }}", ctx)
		if err != nil || out != "1" {
			t.Fatalf("mixed difference(c) = (%q, %v), want (\"1\", nil)", out, err)
		}
		out, err = renderBounded(t, "{{ a | union(b) | length }}", ctx)
		if err != nil || out != "3" {
			t.Fatalf("mixed union = (%q, %v), want (\"3\", nil)", out, err)
		}
		// Symmetry check: scalar string must never equal a sequence.
		if deepEq("[]", []string{}) || deepEq([]string{}, "[]") || deepEq("[]", []any{}) || deepEq([]any{}, "[]") {
			t.Fatal("scalar \"[]\" compared equal to empty slice")
		}

		// Large mixed []string vs []any with shared prefix must hit budget promptly.
		const nSlices = 100
		const sliceLen = 50_000
		mixed := make([]any, nSlices)
		for i := range nSlices {
			if i%2 == 0 {
				s := make([]string, sliceLen)
				for j := range sliceLen - 1 {
					s[j] = "same"
				}
				s[sliceLen-1] = fmt.Sprintf("m-%d", i)
				mixed[i] = s
			} else {
				s := make([]any, sliceLen)
				for j := range sliceLen - 1 {
					s[j] = "same"
				}
				s[sliceLen-1] = fmt.Sprintf("m-%d", i)
				mixed[i] = s
			}
		}
		start := time.Now()
		_, err = renderBounded(t, "{{ items | unique | length }}", map[string]any{"items": &List{mixed}})
		if err == nil || !strings.Contains(err.Error(), "budget exceeded") {
			t.Fatalf("mixed large unique err = %v, want budget exceeded", err)
		}
		if time.Since(start) > time.Second {
			t.Fatalf("mixed large unique took >1s")
		}
	})
}
