// wave4_caps_test.go — regression coverage for the Wave-4 hardening
// caps: exponential concat growth, oversized join separators, and
// the range→unique worst case must all terminate inside the budgets
// instead of hanging or OOMing the render. renderBounded (shared
// with audit_fixes_test.go) turns a hang regression into a deadline
// failure.
package jinja

import (
	"strings"
	"testing"
	"time"
)

// Exponential string growth: each ~ doubles the payload. The
// maxStringBytes/maxSeqElems caps must cut the loop long before the
// result approaches memory exhaustion — the render errors instead
// of hanging or producing an unbounded string. renderBounded turns
// a hang regression into a deadline failure.
func TestConcatDoublingBounded(t *testing.T) {
	// Both templates must hit a hard budget (maxStringBytes /
	// maxSeqElems) and return an error — a silent truncation or a
	// short-but-valid render would mean the cap is not wired.
	for _, tpl := range []string{
		`{% set s = 'x' %}{% for i in range(64) %}{% set s = s ~ s %}{% endfor %}{{ s | length }}`,
		`{% set l = [1] %}{% for i in range(24) %}{% set l = l + l %}{% endfor %}{{ l | length }}`,
	} {
		if _, err := renderBounded(t, tpl, nil); err == nil {
			t.Fatalf("concat doubling completed without budget error\ntpl: %s", tpl)
		}
	}
}

// A huge join separator is one giant string allocation — capped by
// maxStringBytes, so the render errors instead of allocating
// unboundedly.
func TestJoinHugeSeparatorBounded(t *testing.T) {
	sep := strings.Repeat("s", maxStringBytes+1)
	_, err := renderBounded(t,
		`{{ ['a','b','c'] | join(sep) }}`,
		map[string]any{"sep": sep})
	if err == nil {
		t.Fatal("join with >maxStringBytes separator succeeded — cap missing")
	}
}

// range(200000) | unique exercises the all-ints fast path at scale:
// the dedup must stay O(N) and the render must finish quickly even
// though the naive quadratic path would take minutes.
func TestRangeUniqueLargeBounded(t *testing.T) {
	start := time.Now()
	out, err := renderBounded(t,
		`{{ range(200000) | unique | length }}`, nil)
	if err != nil {
		t.Fatalf("range|unique errored: %v", err)
	}
	if out != "200000" {
		t.Fatalf("range(200000)|unique|length = %q, want 200000", out)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("range|unique took %v — quadratic dedup regression?", elapsed)
	}
}
