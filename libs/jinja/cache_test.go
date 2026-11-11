// cache_test.go — the compiled-AST LRU (parsedTemplate) and the
// regex compile cache. The AST cache's load-bearing property is that
// sharing one parsed tree across renders is invisible: identical
// output, no cross-talk under concurrent renders (this suite is the
// -race exercise for the immutability argument in cache.go), bounded
// memory, and parse errors never cached.
package jinja

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

// Render twice through the cache with different contexts — the
// shared tree must produce context-faithful output both times.
func TestTemplateCacheRoundTrip(t *testing.T) {
	tpl := "node-{{ n }}-{{ role | upper }}"
	first, err := Render(tpl, map[string]any{"n": int64(1), "role": "ctrl"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first != "node-1-CTRL" {
		t.Fatalf("first render = %q", first)
	}
	second, err := Render(tpl, map[string]any{"n": int64(2), "role": "wrk"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if second != "node-2-WRK" {
		t.Fatalf("second render = %q — cache cross-talk", second)
	}
}

// The loop OMap reuse (one alloc per for-render) must behave exactly
// like a fresh map per iteration: loop.* correct on every iteration,
// nested loops restore the outer loop binding, and a {% set loop %}
// inside the body cannot leak into the next iteration.
func TestForLoopVarAcrossIterations(t *testing.T) {
	out, err := Render(
		"{% for i in range(3) %}{{ loop.index }}:{{ loop.last }};{% endfor %}|"+
			"{% for i in range(2) %}{% for j in range(2) %}{{ loop.index }}{% endfor %}[{{ loop.index }}]{% endfor %}|"+
			"{% for i in range(2) %}{% set loop = 'x' %}{{ i }}{% endfor %}",
		nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "1:False;2:False;3:True;|12[1]12[2]|01"
	if out != want {
		t.Fatalf("loop var render = %q want %q", out, want)
	}
}

// Eviction: rendering more distinct sources than the cap leaves the
// cache at exactly the cap, and an evicted template still renders
// correctly (transparent reparse).
func TestTemplateCacheEviction(t *testing.T) {
	total := templateCacheCap + 16
	for i := range total {
		tpl := fmt.Sprintf("t{{ %d }}", i)
		out, err := Render(tpl, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if want := fmt.Sprintf("t%d", i); out != want {
			t.Fatalf("render %d = %q want %q", i, out, want)
		}
	}
	templateCache.mu.Lock()
	n := templateCache.lru.Len()
	templateCache.mu.Unlock()
	if n != templateCacheCap {
		t.Fatalf("cache len = %d want cap %d", n, templateCacheCap)
	}
	// An early (long-evicted) source re-renders fine.
	out, err := Render("t{{ 0 }}", nil, nil)
	if err != nil || out != "t0" {
		t.Fatalf("post-eviction render = %q err %v", out, err)
	}
}

// Concurrent renders of SHARED sources — the race-detector exercise
// for sharing one []tnode across goroutines (see cache.go's
// immutability argument). Every output must match the serial render.
func TestTemplateCacheConcurrent(t *testing.T) {
	shared := []string{
		"{% for x in xs %}{{ x }}-{{ loop.index }};{% endfor %}",
		"{{ d.k }}|{{ d | dict2items | sort(attribute='key') | map(attribute='value') | join(',') }}",
		"{% if flag %}yes{% else %}no{% endif %}{{ missing | default('dv') }}",
	}
	want := make([]string, len(shared))
	for i, tpl := range shared {
		out, err := Render(tpl, sharedCtx(), nil)
		if err != nil {
			t.Fatal(err)
		}
		want[i] = out
	}
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// One goroutine-private dynamic source churns the LRU
			// while the shared sources stay hot.
			for j := range 20 {
				if _, err := Render(fmt.Sprintf("private{{ %d*%d }}", j, j), nil, nil); err != nil {
					errs <- err
					return
				}
			}
			for i, tpl := range shared {
				for range 25 {
					out, err := Render(tpl, sharedCtx(), nil)
					if err != nil {
						errs <- err
						return
					}
					if out != want[i] {
						errs <- fmt.Errorf("concurrent render %d = %q want %q", i, out, want[i])
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func sharedCtx() map[string]any {
	d := NewOMap()
	d.Set("k", "kv")
	d.Set("a", int64(1))
	d.Set("b", int64(2))
	return map[string]any{
		"xs":   []any{"a", "b", "c"},
		"d":    d,
		"flag": true,
	}
}

// Parse errors are not cache entries: an unparseable source must
// error on EVERY render (no poisoned empty-tree entry), and a source
// that parses but fails at eval time still comes back with the eval
// error, not a parse artifact.
func TestTemplateCacheErrorsNotCached(t *testing.T) {
	for range 2 {
		if _, err := Render("{% for x in", nil, nil); err == nil {
			t.Fatalf("unparseable template must error every render")
		}
	}
	for range 2 {
		_, err := Render("{{ lookup('file', 'nope') }}", nil, nil)
		if err == nil || !strings.Contains(err.Error(), "no file lookup configured") {
			t.Fatalf("eval failure must error every render, got %v", err)
		}
	}
}

// The regex cache serves regex_*/search: a repeated pattern renders
// identically across calls, and a compile failure errors every time
// (failures are not cached).
func TestRegexCache(t *testing.T) {
	ctx := map[string]any{"s": "a1b2c3"}
	for range 3 {
		out, err := Render("{{ s | regex_replace('[0-9]', '#') }}", ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if out != "a#b#c#" {
			t.Fatalf("cached regex_replace = %q", out)
		}
	}
	if _, err := Render("{{ s | regex_replace('(', 'x') }}", ctx, nil); err == nil {
		t.Fatalf("bad pattern must error")
	}
	if _, err := Render("{{ s | regex_replace('(', 'x') }}", ctx, nil); err == nil {
		t.Fatalf("bad pattern must keep erroring (failures uncached)")
	}
	if _, err := Render("{{ s is search('(') }}", ctx, nil); err != nil {
		// `is search` degrades a bad pattern to no-match, not an error.
		t.Fatalf("is search must not error on a bad pattern: %v", err)
	}
}
